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

fn condition(outcome: StreamClose) -> Option<StreamErrorCondition> {
    Some(match outcome {
        StreamClose::CertificateExpired => StreamErrorCondition::Reset,
        StreamClose::Shutdown => StreamErrorCondition::SystemShutdown,
        StreamClose::Conflict => StreamErrorCondition::Conflict,
        StreamClose::ImproperAddressing => StreamErrorCondition::ImproperAddressing,
        StreamClose::HostUnknown => StreamErrorCondition::HostUnknown,
        StreamClose::InvalidFrom => StreamErrorCondition::InvalidFrom,
        StreamClose::InvalidNamespace => StreamErrorCondition::InvalidNamespace,
        StreamClose::UnsupportedStanzaType => StreamErrorCondition::UnsupportedStanzaType,
        StreamClose::InternalError => StreamErrorCondition::InternalServerError,
        _ => return None,
    })
}

fn validate(
    namespace: StanzaNamespace,
    from: Option<JidRef<'_>>,
    to: Option<JidRef<'_>>,
    peer: &InboundPeer,
) -> Result<(), StreamClose> {
    if namespace != StanzaNamespace::Server {
        return Err(StreamClose::InvalidNamespace);
    }
    let (Some(from), Some(to)) = (from, to) else {
        return Err(StreamClose::ImproperAddressing);
    };
    if to.domainpart() != peer.local.as_ref() {
        return Err(StreamClose::HostUnknown);
    }
    if from.domainpart() != peer.remote.as_ref() {
        return Err(StreamClose::InvalidFrom);
    }
    Ok(())
}

fn rejection(peer: &InboundPeer, stanza_kind: &'static str, outcome: StreamClose) -> StreamClose {
    if condition(outcome).is_some() {
        tracing::debug!(remote_domain = %log_domain(&peer.remote), stanza_kind, outcome = outcome.as_str(), "s2s stanza rejected");
    }
    outcome
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
) -> Result<T, StreamClose> {
    match select(
        pin!(shutdown),
        pin!(select(pin!(expired(valid_until)), pin!(operation))),
    )
    .await
    {
        Either::Left(_) => Err(StreamClose::Shutdown),
        Either::Right((Either::Left(_), _)) => Err(StreamClose::CertificateExpired),
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
    let outcome = if permit.is_none() {
        rejection(peer, "stream", StreamClose::Conflict)
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
    terminal.outcome = outcome;
    close(reader, writer, outcome, valid_until, shutdown).await;
    abort();
    drop(context);
    group.drain().await;
    drop((permit, gauge));
    outcome
}

async fn receive<A, R, D>(
    reader: &mut S2sReader<A, R>,
    peer: &InboundPeer,
    valid_until: SystemTime,
    settings: &Settings<A>,
    shutdown: ShutdownSignal,
    context: &IngressContext<A>,
    dispatch: &mut D,
) -> StreamClose
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
                return Err(StreamClose::Idle);
            }
            compio::time::timeout(remaining, reader.next_event())
                .await
                .map_err(|_| StreamClose::Idle)?
                .map_err(|error| match error {
                    S2sError::PeerError(_) => StreamClose::PeerError,
                    S2sError::Stream(StreamErrorCondition::InvalidNamespace) => {
                        StreamClose::InvalidNamespace
                    }
                    S2sError::Stream(StreamErrorCondition::UnsupportedStanzaType) => {
                        StreamClose::UnsupportedStanzaType
                    }
                    S2sError::Stream(_) => StreamClose::InternalError,
                    _ => StreamClose::TransportError,
                })
        })
        .await;
        let event = match event {
            Ok(Ok(Some(event))) => event,
            Ok(Ok(None)) => return StreamClose::TransportError,
            Ok(Err(outcome)) | Err(outcome) => return rejection(peer, "stream", outcome),
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
                        .map_err(|_| StreamClose::InternalError)?;
                    validate(
                        view.namespace(),
                        view.from().map_err(|_| StreamClose::InternalError)?,
                        view.to().map_err(|_| StreamClose::InternalError)?,
                        peer,
                    )?;
                    settings.metrics.stanza_received(view.kind());
                    let mut arena =
                        Arena::try_new_in(Default::default(), context.allocator.clone())
                            .map_err(|_| StreamClose::InternalError)?;
                    let stanza = view
                        .rescope_in(StanzaNamespace::Client, &mut arena)
                        .map_err(|_| StreamClose::InternalError)?;
                    interrupt(
                        shutdown.clone(),
                        valid_until,
                        dispatch(context, peer, RoutedStanza::from_parts(stanza, arena)),
                    )
                    .await?
                    .map_err(|_| StreamClose::InternalError)
                }
                StreamEvent::RejectedStanza(parsed) => {
                    last_input = Instant::now();
                    let rejected = parsed.value();
                    if rejected.namespace() != StanzaNamespace::Server {
                        return Err(StreamClose::InvalidNamespace);
                    }
                    if rejected.invalid_from() || rejected.invalid_to() {
                        return Err(StreamClose::ImproperAddressing);
                    }
                    validate(
                        rejected.namespace(),
                        rejected
                            .from(parsed.arena())
                            .map_err(|_| StreamClose::InternalError)?,
                        rejected
                            .to(parsed.arena())
                            .map_err(|_| StreamClose::InternalError)?,
                        peer,
                    )?;
                    settings.metrics.stanza_received(rejected.kind());
                    if rejected.can_reply() {
                        let mut output =
                            Arena::try_new_in(Default::default(), context.allocator.clone())
                                .map_err(|_| StreamClose::InternalError)?;
                        let sender = rejected
                            .from(parsed.arena())
                            .map_err(|_| StreamClose::InternalError)?
                            .ok_or(StreamClose::ImproperAddressing)?
                            .clone_in(&mut output)
                            .map_err(|_| StreamClose::InternalError)?;
                        let target = rejected
                            .to(parsed.arena())
                            .map_err(|_| StreamClose::InternalError)?
                            .ok_or(StreamClose::ImproperAddressing)?
                            .clone_in(&mut output)
                            .map_err(|_| StreamClose::InternalError)?;
                        let (rejected, mut arena) = parsed.into_parts();
                        let sender = sender
                            .resolve(&output)
                            .map_err(|_| StreamClose::InternalError)?
                            .clone_in(&mut arena)
                            .map_err(|_| StreamClose::InternalError)?;
                        let target = target
                            .resolve(&output)
                            .map_err(|_| StreamClose::InternalError)?
                            .clone_in(&mut arena)
                            .map_err(|_| StreamClose::InternalError)?;
                        let reply = rejected
                            .error_in(sender, target, &mut arena)
                            .map_err(|_| StreamClose::InternalError)?;
                        let reply = reply
                            .resolve(&arena)
                            .map_err(|_| StreamClose::InternalError)?;
                        let reply = reply
                            .rescope_in(StanzaNamespace::Client, &mut output)
                            .map_err(|_| StreamClose::InternalError)?;
                        let _ = context
                            .router
                            .route_remote(RoutedStanza::from_parts(reply, output));
                    }
                    Ok(())
                }
                StreamEvent::StreamEnd => Err(StreamClose::StreamEnd),
                StreamEvent::Element(parsed) => {
                    let element = parsed
                        .value()
                        .resolve(parsed.arena())
                        .map_err(|_| StreamClose::InternalError)?;
                    if matches!(element.name(), "message" | "iq" | "presence")
                        && element.namespace() != "jabber:server"
                    {
                        Err(StreamClose::InvalidNamespace)
                    } else {
                        Err(StreamClose::UnsupportedStanzaType)
                    }
                }
                _ => Err(StreamClose::UnsupportedStanzaType),
            }
        }
        .await;
        if let Err(outcome) = result {
            return rejection(peer, stanza_kind, outcome);
        }
    }
}

async fn close<A, R, W>(
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    outcome: StreamClose,
    valid_until: SystemTime,
    shutdown: ShutdownSignal,
) where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
{
    if matches!(
        outcome,
        StreamClose::TransportError | StreamClose::PeerError
    ) {
        return;
    }
    let mut deadline = Instant::now() + CLOSE_BUDGET;
    let known_shutdown = shutdown.peek().copied();
    if let Some(until) = known_shutdown {
        deadline = deadline.min(until);
    }
    let operation = async {
        writer.close(condition(outcome)).await?;
        if !matches!(outcome, StreamClose::StreamEnd) {
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
        if matches!(outcome, StreamClose::CertificateExpired) {
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
