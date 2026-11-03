// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::pin;
use std::time::{Duration, Instant};

use compio::net::TcpStream;
use futures_util::FutureExt;
use futures_util::future::{Either, select};
use futures_util::io::AsyncWrite;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::parser::StreamEvent;
#[cfg(test)]
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
use crate::s2s::revocation::CheckPhase;
use crate::s2s::stream::{S2sError, S2sReader, S2sWriter};
use crate::s2s::validity::{LinkValidity, MonitorLog, supervise};

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
    fn interrupted(condition: StreamErrorCondition, validity: &LinkValidity) -> Self {
        if matches!(condition, StreamErrorCondition::Reset) {
            Self {
                outcome: validity.reason().unwrap_or(StreamClose::CertificateExpired),
                wire: WireClose::Error(StreamErrorCondition::Reset),
            }
        } else {
            Self::error(condition)
        }
    }

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

fn rejection(peer: &InboundPeer, stanza_kind: &'static str, closed: Closed) -> Closed {
    if matches!(closed.wire, WireClose::Error(_)) {
        tracing::debug!(remote_domain = %log_domain(&peer.remote), stanza_kind, outcome = closed.outcome.as_str(), "s2s stanza rejected");
    }
    closed
}

async fn interrupt<T>(
    shutdown: ShutdownSignal,
    validity: &LinkValidity,
    operation: impl Future<Output = T>,
) -> Result<T, StreamErrorCondition> {
    match select(
        pin!(shutdown),
        pin!(select(pin!(validity.wait()), pin!(operation))),
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
    let (validity, monitor) = match authenticated.revocation {
        Some(verdict) if verdict.needs_rechecks() => {
            let revocation = std::sync::Arc::clone(&settings.revocation);
            let chain = authenticated.chain;
            let revalidate = Box::new(move || {
                let revocation = std::sync::Arc::clone(&revocation);
                let chain = std::sync::Arc::clone(&chain);
                async move {
                    revocation
                        .check(chain, Direction::Inbound, CheckPhase::Recheck)
                        .await
                }
                .boxed_local()
            });
            let (validity, monitor) = LinkValidity::monitored(
                authenticated.valid_until,
                verdict,
                settings.revocation.recheck_interval(),
                revalidate,
            );
            (validity, Some(monitor))
        }
        _ => (LinkValidity::fixed(authenticated.valid_until), None),
    };
    let work = run(
        &mut authenticated.reader,
        &mut authenticated.writer,
        Parameters {
            peer: &peer,
            validity: &validity,
            settings,
            shutdown,
        },
        || {
            let _ = socket2::SockRef::from(tcp).shutdown(std::net::Shutdown::Both);
        },
        ingress::dispatch,
    );
    supervise(
        monitor,
        MonitorLog {
            direction: Direction::Inbound,
            connection_id: peer.connection_id,
            local: &peer.local,
            remote: &peer.remote,
        },
        settings.timeout,
        work,
    )
    .await
}

struct Parameters<'a, A: ChunkAllocator> {
    peer: &'a InboundPeer,
    validity: &'a LinkValidity,
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
        validity,
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
            validity,
            settings,
            shutdown.clone(),
            &context,
            &mut dispatch,
        )
        .await
    };
    terminal.outcome = closed.outcome;
    close(reader, writer, closed, validity, shutdown).await;
    abort();
    drop(context);
    group.drain().await;
    drop((permit, gauge));
    closed.outcome
}

async fn receive<A, R, D>(
    reader: &mut S2sReader<A, R>,
    peer: &InboundPeer,
    validity: &LinkValidity,
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
        let event = interrupt(shutdown.clone(), validity, async {
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
            Err(condition) => {
                return rejection(peer, "stream", Closed::interrupted(condition, validity));
            }
        };
        let stanza_kind = ingress::receive::stanza_kind(&event);
        if matches!(
            event,
            StreamEvent::Stanza(_) | StreamEvent::RejectedStanza(_)
        ) {
            last_input = Instant::now();
        }
        let result =
            ingress::receive::process(event, peer, &settings.metrics, context, async |stanza| {
                interrupt(shutdown.clone(), validity, dispatch(context, peer, stanza))
                    .await?
                    .map_err(|_| StreamErrorCondition::InternalServerError)
            })
            .await;
        if let Err(condition) = result {
            return rejection(peer, stanza_kind, Closed::interrupted(condition, validity));
        }
    }
}

async fn close<A, R, W>(
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    closed: Closed,
    validity: &LinkValidity,
    shutdown: ShutdownSignal,
) where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
{
    let (condition, mut peer_closed) = match closed.wire {
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
                        peer_closed = true;
                        break;
                    }
                }
                Ok::<_, S2sError>(())
            })
            .await;
        }
        writer.shutdown().await?;
        if peer_closed {
            reader.read_transport_end().await
        } else {
            Ok(())
        }
    };
    let mut operation = pin!(operation);
    let controls = async {
        if matches!(condition, Some(StreamErrorCondition::Reset)) {
            std::future::pending().await
        } else {
            validity.wait().await;
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
