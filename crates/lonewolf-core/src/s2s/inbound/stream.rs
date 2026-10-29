// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::pin;
use std::time::{Duration, Instant, SystemTime};

use compio::net::TcpStream;
use futures_util::future::{Either, select};
use futures_util::io::AsyncWrite;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stanza::StanzaNamespace;
use lonewolf_xmpp::stream::StreamErrorCondition;
use tokio::io::AsyncBufRead;

use super::negotiate::Authenticated;
use super::{Settings, ShutdownSignal};
use crate::delivery::WorkGroup;
use crate::router::RoutedStanza;
use crate::s2s::ingress::{self, InboundPeer, IngressContext, IngressFailure};
use crate::s2s::log_domain;
use crate::s2s::metrics::{Direction, S2sMetrics, StreamClose};
use crate::s2s::stream::{S2sError, S2sReader, S2sWriter};

const CLOSE_BUDGET: Duration = Duration::from_secs(6);
const FOOTER_GRACE: Duration = Duration::from_secs(5);

struct Terminal<'a> {
    metrics: &'a S2sMetrics,
    outcome: StreamClose,
}

impl Drop for Terminal<'_> {
    fn drop(&mut self) {
        self.metrics.stream_closed(Direction::Inbound, self.outcome);
    }
}

#[derive(Clone, Copy)]
enum WireClose {
    Footer { peer_closed: bool },
    Error(StreamErrorCondition),
    Abort,
}

#[derive(Clone, Copy)]
struct Closed {
    outcome: StreamClose,
    wire: WireClose,
}

impl Closed {
    fn error(condition: StreamErrorCondition) -> Self {
        let outcome = match condition {
            StreamErrorCondition::Reset => StreamClose::CertificateExpired,
            StreamErrorCondition::SystemShutdown => StreamClose::Shutdown,
            StreamErrorCondition::Conflict => StreamClose::Conflict,
            StreamErrorCondition::ImproperAddressing => StreamClose::ImproperAddressing,
            StreamErrorCondition::HostUnknown => StreamClose::HostUnknown,
            StreamErrorCondition::InvalidFrom => StreamClose::InvalidFrom,
            StreamErrorCondition::InvalidNamespace => StreamClose::InvalidNamespace,
            StreamErrorCondition::UnsupportedStanzaType => StreamClose::UnsupportedStanzaType,
            StreamErrorCondition::InternalServerError => StreamClose::InternalError,
            _ => StreamClose::ProtocolError,
        };
        Self {
            outcome,
            wire: WireClose::Error(condition),
        }
    }

    fn footer(outcome: StreamClose, peer_closed: bool) -> Self {
        Self {
            outcome,
            wire: WireClose::Footer { peer_closed },
        }
    }

    fn reader_error(error: S2sError) -> Self {
        match error {
            S2sError::Stream(condition) => Self {
                outcome: match condition {
                    StreamErrorCondition::InvalidNamespace => StreamClose::InvalidNamespace,
                    StreamErrorCondition::UnsupportedStanzaType => {
                        StreamClose::UnsupportedStanzaType
                    }
                    _ => StreamClose::ProtocolError,
                },
                wire: WireClose::Error(condition),
            },
            S2sError::Internal => Self::error(StreamErrorCondition::InternalServerError),
            S2sError::PeerError(_) => Self {
                outcome: StreamClose::PeerError,
                wire: WireClose::Abort,
            },
            S2sError::Eof | S2sError::Io | S2sError::Timeout => Self {
                outcome: StreamClose::TransportError,
                wire: WireClose::Abort,
            },
        }
    }
}

fn validate(
    namespace: StanzaNamespace,
    from: Option<JidRef<'_>>,
    to: Option<JidRef<'_>>,
    peer: &InboundPeer,
) -> Result<(), StreamErrorCondition> {
    if namespace != StanzaNamespace::Server {
        return Err(StreamErrorCondition::InvalidNamespace);
    }
    let (Some(from), Some(to)) = (from, to) else {
        return Err(StreamErrorCondition::ImproperAddressing);
    };
    if to.domainpart() != peer.local.as_ref() {
        return Err(StreamErrorCondition::HostUnknown);
    }
    if from.domainpart() != peer.remote.as_ref() {
        return Err(StreamErrorCondition::InvalidFrom);
    }
    Ok(())
}

fn rejection(peer: &InboundPeer, stanza_kind: &'static str, closed: Closed) -> Closed {
    if matches!(closed.wire, WireClose::Error(_)) {
        tracing::debug!(remote_domain = %log_domain(&peer.remote), stanza_kind, outcome = closed.outcome.as_str(), "s2s stanza rejected");
    }
    closed
}

async fn expired(until: SystemTime) {
    if let Ok(delay) = until.duration_since(SystemTime::now())
        && !delay.is_zero()
    {
        compio::time::sleep(delay).await;
    }
}

async fn interrupt<T>(
    shutdown: ShutdownSignal,
    valid_until: SystemTime,
    operation: impl Future<Output = T>,
) -> Result<T, StreamErrorCondition> {
    match select(
        pin!(shutdown),
        pin!(select(pin!(expired(valid_until)), pin!(operation))),
    )
    .await
    {
        Either::Left(_) => Err(StreamErrorCondition::SystemShutdown),
        Either::Right((Either::Left(_), _)) => Err(StreamErrorCondition::Reset),
        Either::Right((Either::Right((result, _)), _)) => Ok(result),
    }
}

pub(super) async fn serve<A: ChunkAllocator + Clone + 'static>(
    mut authenticated: Authenticated<A>,
    tcp: &TcpStream,
    settings: &Settings<A>,
    shutdown: ShutdownSignal,
) -> StreamClose {
    let peer = InboundPeer {
        local: authenticated.local,
        remote: authenticated.remote,
        connection_id: authenticated.connection_id,
    };
    tracing::info!(connection_id = peer.connection_id, local_domain = %log_domain(&peer.local), remote_domain = %log_domain(&peer.remote), direction = "inbound", "s2s connection authenticated");
    run(
        &mut authenticated.reader,
        &mut authenticated.writer,
        Parameters {
            peer: &peer,
            valid_until: authenticated.valid_until,
            settings,
            shutdown,
        },
        || {
            let _ = socket2::SockRef::from(tcp).shutdown(std::net::Shutdown::Both);
        },
        ingress::dispatch,
    )
    .await
}

struct Parameters<'a, A: ChunkAllocator> {
    peer: &'a InboundPeer,
    valid_until: SystemTime,
    settings: &'a Settings<A>,
    shutdown: ShutdownSignal,
}

async fn run<A, R, W, D>(
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    parameters: Parameters<'_, A>,
    abort: impl FnOnce(),
    mut dispatch: D,
) -> StreamClose
where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
    D: for<'a> AsyncFnMut(
        &'a IngressContext<A>,
        &'a InboundPeer,
        RoutedStanza<A>,
    ) -> Result<(), IngressFailure>,
{
    let Parameters {
        peer,
        valid_until,
        settings,
        shutdown,
    } = parameters;
    let mut terminal = Terminal {
        metrics: &settings.metrics,
        outcome: StreamClose::Shutdown,
    };
    let permit = settings
        .streams
        .acquire(&peer.local, &peer.remote, settings.max_streams);
    let gauge = permit
        .as_ref()
        .map(|_| settings.metrics.stream_opened(Direction::Inbound));
    let mut group = WorkGroup::new();
    let context = IngressContext {
        router: settings.services.router.clone(),
        storage: settings.services.storage.clone(),
        allocator: settings.services.allocator.clone(),
        work: group.handle(),
    };
    let closed = if permit.is_none() {
        rejection(
            peer,
            "stream",
            Closed::error(StreamErrorCondition::Conflict),
        )
    } else {
        receive(
            reader,
            peer,
            valid_until,
            settings,
            shutdown.clone(),
            &context,
            &mut dispatch,
        )
        .await
    };
    terminal.outcome = closed.outcome;
    close(reader, writer, closed, valid_until, shutdown).await;
    abort();
    drop(context);
    group.drain().await;
    drop((permit, gauge));
    closed.outcome
}

async fn receive<A, R, D>(
    reader: &mut S2sReader<A, R>,
    peer: &InboundPeer,
    valid_until: SystemTime,
    settings: &Settings<A>,
    shutdown: ShutdownSignal,
    context: &IngressContext<A>,
    dispatch: &mut D,
) -> Closed
where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    D: for<'a> AsyncFnMut(
        &'a IngressContext<A>,
        &'a InboundPeer,
        RoutedStanza<A>,
    ) -> Result<(), IngressFailure>,
{
    let mut last_input = Instant::now();
    loop {
        let remaining = settings.idle_timeout.saturating_sub(last_input.elapsed());
        let event = interrupt(shutdown.clone(), valid_until, async {
            if remaining.is_zero() {
                return Err(Closed::footer(StreamClose::Idle, false));
            }
            compio::time::timeout(remaining, reader.next_event())
                .await
                .map_err(|_| Closed::footer(StreamClose::Idle, false))?
                .map_err(Closed::reader_error)
        })
        .await;
        let event = match event {
            Ok(Ok(Some(StreamEvent::StreamEnd))) => {
                return Closed::footer(StreamClose::StreamEnd, true);
            }
            Ok(Ok(Some(event))) => event,
            Ok(Ok(None)) => return Closed::reader_error(S2sError::Eof),
            Ok(Err(closed)) => return rejection(peer, "stream", closed),
            Err(condition) => return rejection(peer, "stream", Closed::error(condition)),
        };
        let stanza_kind = match &event {
            StreamEvent::Stanza(parsed) => parsed
                .value()
                .resolve(parsed.arena())
                .map(|view| view.kind().as_str())
                .unwrap_or("stanza"),
            StreamEvent::RejectedStanza(parsed) => parsed.value().kind().as_str(),
            StreamEvent::Element(_) => "element",
            _ => "stream",
        };
        let result = async {
            match event {
                StreamEvent::Stanza(parsed) => {
                    last_input = Instant::now();
                    let view = parsed
                        .value()
                        .resolve(parsed.arena())
                        .map_err(|_| StreamErrorCondition::InternalServerError)?;
                    validate(
                        view.namespace(),
                        view.from()
                            .map_err(|_| StreamErrorCondition::InternalServerError)?,
                        view.to()
                            .map_err(|_| StreamErrorCondition::InternalServerError)?,
                        peer,
                    )?;
                    settings.metrics.stanza_received(view.kind());
                    let mut arena =
                        Arena::try_new_in(Default::default(), context.allocator.clone())
                            .map_err(|_| StreamErrorCondition::InternalServerError)?;
                    let stanza = view
                        .rescope_in(StanzaNamespace::Client, &mut arena)
                        .map_err(|_| StreamErrorCondition::InternalServerError)?;
                    interrupt(
                        shutdown.clone(),
                        valid_until,
                        dispatch(context, peer, RoutedStanza::from_parts(stanza, arena)),
                    )
                    .await?
                    .map_err(|_| StreamErrorCondition::InternalServerError)
                }
                StreamEvent::RejectedStanza(parsed) => {
                    last_input = Instant::now();
                    let rejected = parsed.value();
                    if rejected.namespace() != StanzaNamespace::Server {
                        return Err(StreamErrorCondition::InvalidNamespace);
                    }
                    if rejected.invalid_from() || rejected.invalid_to() {
                        return Err(StreamErrorCondition::ImproperAddressing);
                    }
                    validate(
                        rejected.namespace(),
                        rejected
                            .from(parsed.arena())
                            .map_err(|_| StreamErrorCondition::InternalServerError)?,
                        rejected
                            .to(parsed.arena())
                            .map_err(|_| StreamErrorCondition::InternalServerError)?,
                        peer,
                    )?;
                    settings.metrics.stanza_received(rejected.kind());
                    if rejected.can_reply() {
                        let mut output =
                            Arena::try_new_in(Default::default(), context.allocator.clone())
                                .map_err(|_| StreamErrorCondition::InternalServerError)?;
                        let sender = rejected
                            .from(parsed.arena())
                            .map_err(|_| StreamErrorCondition::InternalServerError)?
                            .ok_or(StreamErrorCondition::ImproperAddressing)?
                            .clone_in(&mut output)
                            .map_err(|_| StreamErrorCondition::InternalServerError)?;
                        let target = rejected
                            .to(parsed.arena())
                            .map_err(|_| StreamErrorCondition::InternalServerError)?
                            .ok_or(StreamErrorCondition::ImproperAddressing)?
                            .clone_in(&mut output)
                            .map_err(|_| StreamErrorCondition::InternalServerError)?;
                        let (rejected, mut arena) = parsed.into_parts();
                        let sender = sender
                            .resolve(&output)
                            .map_err(|_| StreamErrorCondition::InternalServerError)?
                            .clone_in(&mut arena)
                            .map_err(|_| StreamErrorCondition::InternalServerError)?;
                        let target = target
                            .resolve(&output)
                            .map_err(|_| StreamErrorCondition::InternalServerError)?
                            .clone_in(&mut arena)
                            .map_err(|_| StreamErrorCondition::InternalServerError)?;
                        let reply = rejected
                            .error_in(sender, target, &mut arena)
                            .map_err(|_| StreamErrorCondition::InternalServerError)?;
                        let reply = reply
                            .resolve(&arena)
                            .map_err(|_| StreamErrorCondition::InternalServerError)?;
                        let reply = reply
                            .rescope_in(StanzaNamespace::Client, &mut output)
                            .map_err(|_| StreamErrorCondition::InternalServerError)?;
                        let _ = context
                            .router
                            .route_remote(RoutedStanza::from_parts(reply, output));
                    }
                    Ok(())
                }
                StreamEvent::Element(parsed) => {
                    let element = parsed
                        .value()
                        .resolve(parsed.arena())
                        .map_err(|_| StreamErrorCondition::InternalServerError)?;
                    if matches!(element.name(), "message" | "iq" | "presence")
                        && element.namespace() != "jabber:server"
                    {
                        Err(StreamErrorCondition::InvalidNamespace)
                    } else {
                        Err(StreamErrorCondition::UnsupportedStanzaType)
                    }
                }
                _ => Err(StreamErrorCondition::UnsupportedStanzaType),
            }
        }
        .await;
        if let Err(condition) = result {
            return rejection(peer, stanza_kind, Closed::error(condition));
        }
    }
}

async fn close<A, R, W>(
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    closed: Closed,
    valid_until: SystemTime,
    shutdown: ShutdownSignal,
) where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
{
    let (condition, peer_closed) = match closed.wire {
        WireClose::Footer { peer_closed } => (None, peer_closed),
        WireClose::Error(condition) => (Some(condition), false),
        WireClose::Abort => return,
    };
    let mut deadline = Instant::now() + CLOSE_BUDGET;
    let known_shutdown = shutdown.peek().copied();
    if let Some(until) = known_shutdown {
        deadline = deadline.min(until);
    }
    let operation = async {
        writer.close(condition).await?;
        if !peer_closed {
            let _ = compio::time::timeout(FOOTER_GRACE, async {
                while let Some(event) = reader.next_event().await? {
                    if matches!(event, StreamEvent::StreamEnd) {
                        break;
                    }
                }
                Ok::<_, S2sError>(())
            })
            .await;
        }
        writer.shutdown().await
    };
    let mut operation = pin!(operation);
    let controls = async {
        if matches!(condition, Some(StreamErrorCondition::Reset)) {
            std::future::pending().await
        } else {
            expired(valid_until).await
        }
    };
    let mut expiry = pin!(controls);
    let mut stopped = known_shutdown.is_some();
    loop {
        let signal = shutdown.clone();
        let stop = async move {
            if stopped {
                std::future::pending().await
            } else {
                signal.await
            }
        };
        match select(
            pin!(stop),
            pin!(select(
                expiry.as_mut(),
                pin!(compio::time::timeout_at(deadline, operation.as_mut()))
            )),
        )
        .await
        {
            Either::Left((until, _)) => {
                deadline = deadline.min(until);
                stopped = true;
            }
            Either::Right(_) => return,
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
