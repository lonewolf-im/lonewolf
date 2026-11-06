// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::time::{Duration, Instant, SystemTime};

use futures_util::future::{Either, select};
use futures_util::io::AsyncWrite;
use lonewolf_util::arena::Arena;
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stanza::{StanzaErrorCondition, StanzaKind, StanzaNamespace};
use lonewolf_xmpp::stream::StreamErrorCondition;
use tokio::io::AsyncBufRead;

use super::duplex::{self, DuplexParameters};
use super::*;
use crate::s2s::ingress::{self, InboundPeer, IngressContext};
use crate::s2s::metrics::{Direction, StreamClose};
use crate::s2s::revocation::CheckPhase;
use crate::s2s::stream::S2sError;
use crate::s2s::stream::traffic::{IdleClock, SystemIdleClock};
use crate::s2s::validity::{LinkValidity, MonitorLog, ValidityMonitor, supervise};

const CLOSE_BUDGET: Duration = Duration::from_secs(6);
const FOOTER_GRACE: Duration = Duration::from_secs(5);

async fn watch<T>(
    stop: Option<Stop>,
    validity: Option<&LinkValidity>,
    timeout: Duration,
    timeout_reason: StreamClose,
    work: impl Future<Output = Result<T, S2sError>>,
) -> Result<T, StreamClose> {
    let work = async {
        compio::time::timeout(timeout, work)
            .await
            .map_err(|_| timeout_reason)?
            .map_err(|error| match error {
                S2sError::PeerError(_) => StreamClose::PeerError,
                S2sError::Timeout => StreamClose::StalledWrite,
                _ => StreamClose::TransportError,
            })
    };
    watch_control(stop, validity, work).await
}

async fn watch_control<T>(
    stop: Option<Stop>,
    validity: Option<&LinkValidity>,
    work: impl Future<Output = Result<T, StreamClose>>,
) -> Result<T, StreamClose> {
    let stop = async {
        match stop {
            Some(stop) => stop.await,
            None => std::future::pending().await,
        }
    };
    let expiry = async {
        match validity {
            Some(validity) => validity.wait().await,
            None => std::future::pending().await,
        }
    };
    match select(pin!(stop), pin!(select(pin!(expiry), pin!(work)))).await {
        Either::Left(_) => Err(StreamClose::Shutdown),
        Either::Right((Either::Left((reason, _)), _)) => Err(reason),
        Either::Right((Either::Right((result, _)), _)) => result,
    }
}

pub(super) enum WriteOutcome {
    Written { at: Instant, kind: StanzaKind },
    Discarded,
    PeerSizeRejected,
}

fn discard<A: ChunkAllocator>(
    inner: &Inner<A>,
    queued: &mut Queued<A>,
    validity: &LinkValidity,
) -> Result<WriteOutcome, StreamClose> {
    let state = inner.state.lock();
    if state.stopped {
        return Err(StreamClose::Shutdown);
    }
    if let Err(reason) = validity.check(SystemTime::now()) {
        return Err(validity.record_invalidation(reason));
    }
    drop(queued.reservation.take());
    inner.metrics.dropped(DropReason::InternalError, 1);
    queued.write_outcome_recorded = true;
    Ok(WriteOutcome::Discarded)
}

pub(super) async fn write<A: ChunkAllocator + Clone, W: AsyncWrite + Unpin>(
    writer: &mut S2sWriter<W>,
    queued: &mut Queued<A>,
    inner: &Inner<A>,
    validity: &LinkValidity,
    flush: bool,
    buffered: &mut bool,
) -> Result<WriteOutcome, StreamClose> {
    let prepared = (|| {
        let mut arena =
            Arena::try_new_in(Default::default(), inner.allocator.clone()).map_err(|_| ())?;
        let source = queued.stanza.resolve().map_err(|_| ())?;
        let copy = source
            .rescope_in(StanzaNamespace::Server, &mut arena)
            .map_err(|_| ())?;
        Ok::<_, ()>((arena, copy))
    })();
    let prepared = prepared.ok();
    let view = prepared
        .as_ref()
        .and_then(|(arena, copy)| copy.resolve(arena).ok());
    let Some(view) = view else {
        let outcome = discard(inner, queued, validity)?;
        if flush {
            flush_buffered(writer, inner, validity, buffered).await?;
        }
        return Ok(outcome);
    };
    if let Some(maximum) = writer.peer_limits().max_bytes {
        match crate::s2s::stream::limits::stanza_fits(&view, maximum).await {
            Ok(false) => {
                let state = inner.state.lock();
                if state.stopped {
                    return Err(StreamClose::Shutdown);
                }
                if let Err(reason) = validity.check(SystemTime::now()) {
                    return Err(validity.record_invalidation(reason));
                }
                drop(queued.reservation.take());
                queued.write_outcome_recorded = true;
                inner.metrics.peer_size_rejected();
                return Ok(WriteOutcome::PeerSizeRejected);
            }
            Err(_) => {
                let outcome = discard(inner, queued, validity)?;
                if flush {
                    flush_buffered(writer, inner, validity, buffered).await?;
                }
                return Ok(outcome);
            }
            Ok(true) => {}
        }
    }
    let kind = view.kind();
    let timeout = Duration::from_secs(inner.limits.stalled_write_timeout_secs.get());
    let result = {
        let mut operation = pin!(writer.write_stanza(&view));
        watch(
            Some(inner.stopped.clone()),
            Some(validity),
            timeout,
            StreamClose::StalledWrite,
            poll_fn(|cx| {
                drop(queued.reservation.take());
                operation.as_mut().poll(cx)
            }),
        )
        .await
    };
    if let Err(reason) = result {
        if queued.reservation.is_none() {
            inner.metrics.dropped(DropReason::ConnectionLost, 1);
            queued.write_outcome_recorded = true;
            tracing::debug!(
                stanza_kind = kind.as_str(),
                "s2s in-flight stanza discarded"
            );
        }
        return Err(reason);
    }
    let written_at = Instant::now();
    inner.metrics.stanza_sent(kind);
    queued.write_outcome_recorded = true;
    *buffered = true;
    if flush {
        flush_buffered(writer, inner, validity, buffered).await?;
    }
    Ok(WriteOutcome::Written {
        at: written_at,
        kind,
    })
}

pub(super) fn reject_peer_size<A: ChunkAllocator + Clone + 'static>(
    router: &RouterHandle<A>,
    current: &mut Option<Queued<A>>,
) {
    if let Some(queued) = current.take()
        && let Some(remote) = router.remote_router()
    {
        let _ = remote.bounce(
            router,
            queued.into_stanza(),
            StanzaErrorCondition::PolicyViolation,
        );
    }
}

pub(super) async fn flush_buffered<A: ChunkAllocator, W: AsyncWrite + Unpin>(
    writer: &mut S2sWriter<W>,
    inner: &Inner<A>,
    validity: &LinkValidity,
    buffered: &mut bool,
) -> Result<(), StreamClose> {
    if *buffered {
        watch(
            Some(inner.stopped.clone()),
            Some(validity),
            Duration::from_secs(inner.limits.stalled_write_timeout_secs.get()),
            StreamClose::StalledWrite,
            writer.flush(),
        )
        .await?;
        *buffered = false;
    }
    Ok(())
}

fn close_condition(reason: StreamClose) -> Option<StreamErrorCondition> {
    match reason {
        reason if reason.certificate_invalid() => Some(StreamErrorCondition::Reset),
        StreamClose::NotAuthorized => Some(StreamErrorCondition::NotAuthorized),
        _ => None,
    }
}

async fn graceful<
    A: ChunkAllocator + Clone,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
>(
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    reason: StreamClose,
    condition: Option<StreamErrorCondition>,
    stop: Stop,
    validity: &LinkValidity,
    write_timeout: Duration,
) -> Result<(), StreamClose> {
    let stopped = (!matches!(reason, StreamClose::Shutdown)).then_some(stop);
    let validity = (!reason.certificate_invalid()).then_some(validity);
    watch(
        stopped,
        validity,
        CLOSE_BUDGET,
        StreamClose::StalledWrite,
        async {
            compio::time::timeout(write_timeout, writer.close(condition))
                .await
                .map_err(|_| S2sError::Timeout)??;
            let mut peer_footer = matches!(reason, StreamClose::StreamEnd);
            if !peer_footer {
                let _ = compio::time::timeout(FOOTER_GRACE, async {
                    while let Ok(Some(event)) = reader.next_event().await {
                        if matches!(event, StreamEvent::StreamEnd) {
                            peer_footer = true;
                            break;
                        }
                    }
                })
                .await;
            }
            writer.shutdown().await?;
            if peer_footer {
                reader.read_transport_end().await
            } else {
                Ok(())
            }
        },
    )
    .await
}

enum Next<A: ChunkAllocator> {
    Queued,
    Peer(Option<StreamEvent<A>>),
}

struct Closed {
    reason: StreamClose,
    abort: bool,
}

async fn serve<
    A: ChunkAllocator + Clone,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
>(
    inner: &Inner<A>,
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    validity: &LinkValidity,
    receiver: &Receiver<Queued<A>>,
    current: &mut Option<Queued<A>>,
    router: &RouterHandle<A>,
) -> Closed {
    serve_with_clock(
        inner,
        reader,
        writer,
        validity,
        (receiver, current),
        router,
        &SystemIdleClock,
    )
    .await
}

async fn serve_with_clock<
    A: ChunkAllocator + Clone,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
>(
    inner: &Inner<A>,
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    validity: &LinkValidity,
    queue: (&Receiver<Queued<A>>, &mut Option<Queued<A>>),
    router: &RouterHandle<A>,
    clock: &impl IdleClock,
) -> Closed {
    let (receiver, current) = queue;
    let mut last_written = clock.now();
    let physical = reader.activity();
    let mut buffered = false;
    loop {
        let next = async {
            let queued = async {
                if current.is_none() {
                    *current = Some(receiver.recv().await.map_err(|_| S2sError::Internal)?);
                }
                Ok(Next::Queued)
            };
            match select(pin!(reader.next_event()), pin!(queued)).await {
                Either::Left((result, _)) => result.map(Next::Peer),
                Either::Right((result, _)) => result,
            }
        };
        let last_activity = physical
            .as_ref()
            .map_or(last_written, |physical| physical.last().max(last_written));
        let deadline = last_activity + Duration::from_secs(inner.limits.idle_timeout_secs.get());
        let next = async {
            match select(pin!(clock.sleep_until(deadline)), pin!(next)).await {
                Either::Left(_) => Err(StreamClose::Idle),
                Either::Right((result, _)) => result.map_err(|error| match error {
                    S2sError::PeerError(_) => StreamClose::PeerError,
                    S2sError::Timeout => StreamClose::StalledWrite,
                    _ => StreamClose::TransportError,
                }),
            }
        };
        match watch_control(Some(inner.stopped.clone()), Some(validity), next).await {
            Ok(Next::Queued) => {
                let Some(queued) = current.as_mut() else {
                    return Closed {
                        reason: StreamClose::InternalError,
                        abort: true,
                    };
                };
                match write(
                    writer,
                    queued,
                    inner,
                    validity,
                    receiver.is_empty(),
                    &mut buffered,
                )
                .await
                {
                    Ok(WriteOutcome::Written { at: written_at, .. }) => {
                        last_written = written_at;
                        *current = None;
                    }
                    Ok(WriteOutcome::PeerSizeRejected) => {
                        reject_peer_size(router, current);
                        if let Err(reason) =
                            flush_buffered(writer, inner, validity, &mut buffered).await
                        {
                            return Closed {
                                reason,
                                abort: true,
                            };
                        }
                    }
                    Ok(WriteOutcome::Discarded) => {
                        *current = None;
                    }
                    Err(reason) => {
                        let started = queued.reservation.is_none();
                        if started {
                            *current = None;
                        }
                        return Closed {
                            reason,
                            abort: started
                                || !(matches!(reason, StreamClose::Shutdown)
                                    || reason.certificate_invalid()),
                        };
                    }
                }
            }
            Ok(Next::Peer(Some(StreamEvent::StreamEnd))) => {
                return Closed {
                    reason: StreamClose::StreamEnd,
                    abort: false,
                };
            }
            Ok(Next::Peer(None)) => {
                return Closed {
                    reason: StreamClose::TransportError,
                    abort: true,
                };
            }
            Ok(Next::Peer(Some(_))) => {
                return Closed {
                    reason: StreamClose::NotAuthorized,
                    abort: false,
                };
            }
            Err(StreamClose::Idle)
                if physical.as_ref().is_some_and(|physical| {
                    clock.now().saturating_duration_since(physical.last())
                        < Duration::from_secs(inner.limits.idle_timeout_secs.get())
                }) =>
            {
                continue;
            }
            Err(reason) => {
                let abort = matches!(
                    reason,
                    StreamClose::TransportError
                        | StreamClose::StalledWrite
                        | StreamClose::PeerError
                );
                return Closed { reason, abort };
            }
        }
    }
}

struct LiveValidity<'a> {
    validity: &'a LinkValidity,
    monitor: Option<ValidityMonitor>,
    connection_id: u64,
}

async fn connected<A, R, W>(
    inner: &Inner<A>,
    router: &RouterHandle<A>,
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    live: LiveValidity<'_>,
    queue: &mut LinkQueue<A>,
    bidi: bool,
) -> StreamClose
where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
{
    let LiveValidity {
        validity,
        monitor,
        connection_id,
    } = live;
    let write_timeout = Duration::from_secs(inner.limits.stalled_write_timeout_secs.get());
    let timeout = Duration::from_secs(inner.limits.negotiation_timeout_secs.get());
    let (reason, pending_ingress) = if bidi {
        if let Some(ingress) = &inner.bidi {
            let gauge = inner.metrics.bidi_stream_opened(Direction::Outbound);
            let group = WorkGroup::new();
            let context = IngressContext {
                router: router.clone(),
                storage: ingress.storage.clone(),
                allocator: inner.allocator.clone(),
                work: group.handle(),
            };
            let peer = InboundPeer {
                local: queue.pair.0.clone(),
                remote: queue.pair.1.clone(),
                connection_id,
            };
            let work = async {
                let end = duplex::run_outbound(
                    inner,
                    queue,
                    reader,
                    writer,
                    DuplexParameters {
                        peer: &peer,
                        context: &context,
                        validity,
                        idle_timeout: Duration::from_secs(inner.limits.idle_timeout_secs.get()),
                    },
                    ingress::dispatch,
                )
                .await;
                if end.abort {
                    end.reason
                } else {
                    match graceful(
                        reader,
                        writer,
                        end.reason,
                        end.violation.or_else(|| close_condition(end.reason)),
                        inner.stopped.clone(),
                        validity,
                        write_timeout,
                    )
                    .await
                    {
                        Ok(()) => end.reason,
                        Err(reason) => reason,
                    }
                }
            };
            let reason = supervise(
                monitor,
                MonitorLog {
                    direction: Direction::Outbound,
                    connection_id,
                    local: &peer.local,
                    remote: &peer.remote,
                },
                timeout,
                work,
            )
            .await;
            (reason, Some((context, group, gauge)))
        } else {
            (StreamClose::InternalError, None)
        }
    } else {
        let LinkQueue {
            pair,
            receiver,
            current,
            ..
        } = queue;
        let work = async {
            let closed = serve(inner, reader, writer, validity, receiver, current, router).await;
            if closed.abort {
                closed.reason
            } else {
                match graceful(
                    reader,
                    writer,
                    closed.reason,
                    close_condition(closed.reason),
                    inner.stopped.clone(),
                    validity,
                    write_timeout,
                )
                .await
                {
                    Ok(()) => closed.reason,
                    Err(reason) => reason,
                }
            }
        };
        let reason = supervise(
            monitor,
            MonitorLog {
                direction: Direction::Outbound,
                connection_id,
                local: &pair.0,
                remote: &pair.1,
            },
            timeout,
            work,
        )
        .await;
        (reason, None)
    };
    inner.metrics.stream_closed(Direction::Outbound, reason);
    if let Some((context, mut group, _gauge)) = pending_ingress {
        drop(context);
        group.drain().await;
    }
    reason
}

/// Builds the detached task that drives one outbound link.
///
/// The link state is boxed so spawning moves only a pointer. Unoptimized builds copy a spawned
/// future through many frames, and the inline state overflows a worker stack.
pub(super) fn task<A: ChunkAllocator + Clone + 'static>(
    guard: WorkGuard,
    inner: Arc<Inner<A>>,
    router: RouterHandle<A>,
    queue: LinkQueue<A>,
    failures: u32,
) -> impl Future<Output = ()> + 'static {
    guard.run(Box::pin(run(inner, router, queue, failures)))
}

async fn run<A: ChunkAllocator + Clone + 'static>(
    inner: Arc<Inner<A>>,
    router: RouterHandle<A>,
    mut queue: LinkQueue<A>,
    mut failures: u32,
) {
    loop {
        if inner.state.lock().stopped {
            break;
        }
        queue = match inner.offer_standby(queue) {
            Ok(()) => return,
            Err(queue) => queue,
        };
        let context = connect::ConnectContext {
            bidirectional: inner.bidi.is_some(),
            hosts: &inner.hosts,
            trust: &inner.trust,
            revocation: &inner.revocation,
            resolver: &inner.resolver,
            limits: &inner.limits,
            metrics: Arc::clone(&inner.metrics),
        };
        let result = stopping(
            inner.stopped.clone(),
            connect::establish(
                &queue.pair.0,
                &queue.pair.1,
                &context,
                inner.allocator.clone(),
            ),
        )
        .await;
        let mut stream = match result {
            None => break,
            Some(Err(error)) => {
                let condition = match error.condition() {
                    lonewolf_xmpp::stanza::StanzaErrorCondition::RemoteServerNotFound => {
                        RemoteFailure::NotFound
                    }
                    _ => RemoteFailure::Timeout,
                };
                queue = match inner.failed(queue, failures, condition, Instant::now(), jitter()) {
                    FailureDisposition::HandedOff => return,
                    FailureDisposition::Bounce(queue) => queue,
                    FailureDisposition::Shutdown(returned) => {
                        queue = returned;
                        break;
                    }
                };
                queue.receiver.close();
                while let Some(queued) = queue
                    .current
                    .take()
                    .or_else(|| queue.receiver.try_recv().ok())
                {
                    let stanza = queued.into_stanza();
                    if stopping(
                        inner.stopped.clone(),
                        bounce(&router, &stanza, error.condition()),
                    )
                    .await
                    .is_none()
                    {
                        inner.metrics.dropped(DropReason::Shutdown, 1);
                        break;
                    }
                }
                break;
            }
            Some(Ok(stream)) => stream,
        };
        let (validity, monitor) = match stream.revocation.take() {
            Some(verdict) if verdict.needs_rechecks() => {
                let revocation = Arc::clone(&inner.revocation);
                let chain = Arc::clone(&stream.chain);
                let revalidate = Box::new(move || {
                    let revocation = Arc::clone(&revocation);
                    let chain = Arc::clone(&chain);
                    async move {
                        revocation
                            .check(chain, Direction::Outbound, CheckPhase::Recheck)
                            .await
                    }
                    .boxed_local()
                });
                let (validity, monitor) = LinkValidity::monitored(
                    stream.valid_until,
                    verdict,
                    inner.revocation.recheck_interval(),
                    revalidate,
                );
                (validity, Some(monitor))
            }
            _ => (LinkValidity::fixed(stream.valid_until), None),
        };
        ready(&queue.counters, &mut failures);
        let gauge = inner.metrics.stream_opened(Direction::Outbound);
        connected(
            &inner,
            &router,
            &mut stream.reader,
            &mut stream.writer,
            LiveValidity {
                validity: &validity,
                monitor,
                connection_id: stream.connection_id,
            },
            &mut queue,
            stream.bidi,
        )
        .await;
        drop(stream);
        drop(gauge);
        queue.counters.ready.store(false, Ordering::Relaxed);
        let mut state = inner.state.lock();
        if state.stopped || queue.is_drained() || !state.owns(&queue.pair, &queue.counters) {
            if state.owns(&queue.pair, &queue.counters) {
                state.entries.remove(&queue.pair);
            }
            break;
        }
        drop(state);
    }
    queue.receiver.close();
    shutdown_queue(&inner, &queue.receiver, &queue.pair, &mut queue.current);
    inner.remove(&queue.pair, &queue.counters);
}

pub(super) fn shutdown_queue<A: ChunkAllocator>(
    inner: &Inner<A>,
    receiver: &Receiver<Queued<A>>,
    pair: &Pair,
    current: &mut Option<Queued<A>>,
) {
    let dropped = u64::from(current.take().is_some()) + drain(receiver);
    if dropped > 0 {
        inner.metrics.dropped(DropReason::Shutdown, dropped);
        tracing::warn!(local_domain = %log_domain(&pair.0), remote_domain = %log_domain(&pair.1), dropped, "s2s link stopped with queued stanzas");
    }
}

fn drain<A: ChunkAllocator>(receiver: &Receiver<Queued<A>>) -> u64 {
    let mut dropped = 0;
    while let Ok(queued) = receiver.try_recv() {
        drop(queued);
        dropped += 1;
    }
    dropped
}

fn log_domain(domain: &str) -> Cow<'_, str> {
    let literal = domain.trim_start_matches('[').trim_end_matches(']');
    if literal.parse::<std::net::IpAddr>().is_ok() {
        Cow::Borrowed("<literal>")
    } else if domain.len() <= 253 && !domain.chars().any(char::is_control) {
        Cow::Borrowed(domain)
    } else {
        Cow::Owned(
            domain
                .chars()
                .take(253)
                .map(|ch| if ch.is_control() { '?' } else { ch })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures_util::poll;
    use lonewolf_util::arena::GlobalChunkAllocator;

    use super::super::manager_tests::{manager, message, render, run, stanza};
    use super::*;
    use crate::s2s::stream::S2sReaderLimits;

    #[derive(Default)]
    struct Calls {
        writes: usize,
        flushes: usize,
        closes: usize,
        accepts: bool,
        output: Vec<u8>,
    }

    struct ControlledWriter(Arc<PlMutex<Calls>>);

    impl AsyncWrite for ControlledWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut calls = self.0.lock();
            calls.writes += 1;
            if calls.accepts {
                calls.output.extend_from_slice(bytes);
                Poll::Ready(Ok(bytes.len()))
            } else {
                Poll::Pending
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.0.lock().flushes += 1;
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.0.lock().closes += 1;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn interrupted_write_drops_only_in_flight_and_shutdown_releases_the_tail()
    -> Result<(), Box<dyn std::error::Error>> {
        run(async {
            let manager = manager(S2sLimits::default())?;
            let source = stanza(&format!("<message from='alice@localhost/desk' to='bob@remote.test'><body>{}</body></message>", "x".repeat(8192))).await?;
            let task = manager
                .admit("localhost", "remote.test", source)
                .map_err(|error| format!("{error:?}"))?
                .ok_or("launch")?;
            assert!(
                manager
                    .admit("localhost", "remote.test", message().await?)
                    .map_err(|error| format!("{error:?}"))?
                    .is_none()
            );
            let mut current = task.queue.receiver.recv().await?;
            assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 2);
            let calls = Arc::new(PlMutex::new(Calls::default()));
            let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
            let expiry = rcgen::CertificateParams::default().not_after;
            let valid = LinkValidity::fixed(
                SystemTime::UNIX_EPOCH + Duration::from_secs(expiry.unix_timestamp().try_into()?),
            );
            let mut buffered = false;
            {
                let mut writing = pin!(write(
                    &mut writer,
                    &mut current,
                    &manager.inner,
                    &valid,
                    true,
                    &mut buffered
                ));
                assert!(poll!(writing.as_mut()).is_pending());
                assert!(calls.lock().writes > 0);
                manager.stop();
                assert!(matches!(writing.await, Err(StreamClose::Shutdown)));
            }
            let output = render(&manager.inner.metrics)?;
            assert!(output.contains("s2s_dropped_stanzas_total{reason=\"connection_lost\"} 1"));
            assert!(!output.contains("s2s_stanzas_sent_total{kind=\"message\"} 1"));
            let writes = calls.lock().writes;
            drop(writer);
            assert_eq!(calls.lock().writes, writes);
            assert_eq!(calls.lock().flushes, 0);
            assert_eq!(calls.lock().closes, 0);
            assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 1);
            shutdown_queue(
                &manager.inner,
                &task.queue.receiver,
                &task.queue.pair,
                &mut None,
            );
            assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 0);
            assert_eq!(task.queue.counters.bytes.load(Ordering::Relaxed), 0);
            assert!(
                render(&manager.inner.metrics)?
                    .contains("s2s_dropped_stanzas_total{reason=\"shutdown\"} 1")
            );
            drop(task);
            manager
                .join(Instant::now() + Duration::from_secs(5))
                .await?;
            Ok(())
        })
    }

    #[test]
    fn successful_write_then_interrupted_flush_keeps_sent_count_without_a_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        run(async {
            let manager = manager(S2sLimits::default())?;
            let calls = Arc::new(PlMutex::new(Calls::default()));
            let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
            let task = manager
                .admit("localhost", "remote.test", message().await?)
                .map_err(|error| format!("{error:?}"))?
                .ok_or("launch")?;
            let mut source = task.queue.receiver.recv().await?;
            let mut buffered = false;
            {
                let validity = LinkValidity::fixed(SystemTime::now() + Duration::from_secs(60));
                let mut writing = pin!(write(
                    &mut writer,
                    &mut source,
                    &manager.inner,
                    &validity,
                    true,
                    &mut buffered
                ));
                assert!(poll!(writing.as_mut()).is_pending());
                assert!(calls.lock().writes > 0);
                assert!(
                    render(&manager.inner.metrics)?
                        .contains("s2s_stanzas_sent_total{kind=\"message\"} 1")
                );
                manager.stop();
                assert!(matches!(writing.await, Err(StreamClose::Shutdown)));
            }
            drop(writer);
            assert_eq!(calls.lock().closes, 0);
            assert_eq!(calls.lock().flushes, 0);
            assert!(
                !render(&manager.inner.metrics)?
                    .contains("s2s_dropped_stanzas_total{reason=\"connection_lost\"} 1")
            );
            drop(task);
            manager
                .join(Instant::now() + Duration::from_secs(5))
                .await?;
            Ok(())
        })
    }

    #[test]
    fn output_not_polled_keeps_the_head_reserved_without_a_connection_loss()
    -> Result<(), Box<dyn std::error::Error>> {
        run(async {
            for stopped in [false, true] {
                let manager = manager(S2sLimits {
                    max_queued_stanzas_per_link: std::num::NonZeroUsize::new(2).ok_or("count")?,
                    ..Default::default()
                })?;
                let task = manager
                    .admit("localhost", "remote.test", message().await?)
                    .map_err(|error| format!("{error:?}"))?
                    .ok_or("launch")?;
                manager
                    .admit("localhost", "remote.test", message().await?)
                    .map_err(|error| format!("{error:?}"))?;
                let mut current = Some(task.queue.receiver.recv().await?);
                let calls = Arc::new(PlMutex::new(Calls::default()));
                let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
                if stopped {
                    manager.stop();
                }
                let mut buffered = false;
                let outcome = write(
                    &mut writer,
                    current.as_mut().ok_or("head")?,
                    &manager.inner,
                    &LinkValidity::fixed(SystemTime::UNIX_EPOCH),
                    true,
                    &mut buffered,
                )
                .await;
                if stopped {
                    assert!(matches!(outcome, Err(StreamClose::Shutdown)));
                } else {
                    assert!(matches!(outcome, Err(StreamClose::CertificateExpired)));
                    assert!(matches!(
                        manager.admit("localhost", "remote.test", message().await?),
                        Err(RemoteError::Busy)
                    ));
                }
                assert_eq!(calls.lock().writes, 0);
                assert!(current.as_ref().ok_or("head")?.reservation.is_some());
                assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 2);
                assert!(
                    !render(&manager.inner.metrics)?
                        .contains("s2s_dropped_stanzas_total{reason=\"connection_lost\"} 1")
                );
                assert!(
                    !render(&manager.inner.metrics)?
                        .contains("s2s_stanzas_sent_total{kind=\"message\"} 1")
                );
                manager.stop();
                shutdown_queue(
                    &manager.inner,
                    &task.queue.receiver,
                    &task.queue.pair,
                    &mut current,
                );
                assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 0);
                assert_eq!(task.queue.counters.bytes.load(Ordering::Relaxed), 0);
                assert!(
                    render(&manager.inner.metrics)?
                        .contains("s2s_dropped_stanzas_total{reason=\"shutdown\"} 2")
                );
                drop(task);
                manager
                    .join(Instant::now() + Duration::from_secs(5))
                    .await?;
            }
            Ok(())
        })
    }

    #[derive(Clone, Default)]
    struct ControlledAllocator {
        exhausted: Arc<AtomicBool>,
        live: Arc<AtomicUsize>,
    }

    // Successful allocations keep the global allocator's ownership and layout.
    unsafe impl ChunkAllocator for ControlledAllocator {
        fn allocate(
            &self,
            layout: std::alloc::Layout,
        ) -> Result<lonewolf_util::arena::Chunk, lonewolf_util::arena::AllocationError> {
            if self.exhausted.load(Ordering::Relaxed) {
                return Err(lonewolf_util::arena::AllocationError::Exhausted);
            }
            let chunk = GlobalChunkAllocator.allocate(layout)?;
            self.live.fetch_add(1, Ordering::Relaxed);
            Ok(chunk)
        }
        unsafe fn deallocate(&self, chunk: lonewolf_util::arena::Chunk) {
            unsafe {
                GlobalChunkAllocator.deallocate(chunk);
            }
            self.live.fetch_sub(1, Ordering::Relaxed);
        }
    }

    async fn controlled_stanza(
        id: &str,
        allocator: ControlledAllocator,
    ) -> Result<RoutedStanza<ControlledAllocator>, Box<dyn std::error::Error>> {
        super::super::manager_tests::stanza_in(&format!("<message from='alice@localhost/desk' to='bob@remote.test' id='{id}'><body>{id}</body></message>"), allocator).await
    }

    #[test]
    fn preparation_failure_discards_once_and_the_fifo_tail_uses_the_same_writer()
    -> Result<(), Box<dyn std::error::Error>> {
        run(async {
            let allocator = ControlledAllocator::default();
            let manager = super::super::manager_tests::manager_with_allocator(
                S2sLimits::default(),
                allocator.clone(),
            )?;
            let task = manager
                .admit(
                    "localhost",
                    "remote.test",
                    controlled_stanza("failed-head", allocator.clone()).await?,
                )
                .map_err(|error| format!("{error:?}"))?
                .ok_or("launch")?;
            for id in ["first-tail", "second-tail"] {
                manager
                    .admit(
                        "localhost",
                        "remote.test",
                        controlled_stanza(id, allocator.clone()).await?,
                    )
                    .map_err(|error| format!("{error:?}"))?;
            }
            let calls = Arc::new(PlMutex::new(Calls {
                accepts: true,
                ..Default::default()
            }));
            let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
            let mut buffered = false;
            let valid = LinkValidity::fixed(SystemTime::now() + Duration::from_secs(60));
            let mut head = task.queue.receiver.recv().await?;
            allocator.exhausted.store(true, Ordering::Relaxed);
            assert!(matches!(
                write(
                    &mut writer,
                    &mut head,
                    &manager.inner,
                    &valid,
                    false,
                    &mut buffered
                )
                .await,
                Ok(WriteOutcome::Discarded)
            ));
            assert!(head.reservation.is_none());
            assert_eq!(calls.lock().writes, 0);
            assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 2);
            drop(head);
            allocator.exhausted.store(false, Ordering::Relaxed);
            for id in ["first-tail", "second-tail"] {
                let mut queued = task.queue.receiver.recv().await?;
                assert_eq!(queued.stanza.resolve()?.id()?, Some(id));
                assert!(matches!(
                    write(
                        &mut writer,
                        &mut queued,
                        &manager.inner,
                        &valid,
                        task.queue.receiver.is_empty(),
                        &mut buffered
                    )
                    .await,
                    Ok(WriteOutcome::Written { .. })
                ));
            }
            assert!(task.queue.receiver.is_empty());
            assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 0);
            assert_eq!(task.queue.counters.bytes.load(Ordering::Relaxed), 0);
            assert_eq!(allocator.live.load(Ordering::Relaxed), 0);
            {
                let calls = calls.lock();
                let output = std::str::from_utf8(&calls.output)?;
                assert!(!output.contains("failed-head"));
                let first = output.find("first-tail").ok_or("first tail missing")?;
                let second = output.find("second-tail").ok_or("second tail missing")?;
                assert!(first < second);
            }
            let output = render(&manager.inner.metrics)?;
            assert!(output.contains("s2s_dropped_stanzas_total{reason=\"internal_error\"} 1"));
            assert!(output.contains("s2s_stanzas_sent_total{kind=\"message\"} 2"));
            for reason in ["connection_lost", "not_bounceable", "shutdown"] {
                assert!(!output.contains(&format!(
                    "s2s_dropped_stanzas_total{{reason=\"{reason}\"}} 1"
                )));
            }
            assert!(!output.contains("s2s_streams_closed_total{"));
            assert!(
                manager
                    .inner
                    .state
                    .lock()
                    .owns(&task.queue.pair, &task.queue.counters)
            );
            drop(task);
            manager
                .join(Instant::now() + Duration::from_secs(5))
                .await?;
            Ok(())
        })
    }

    #[test]
    fn discarding_the_last_head_flushes_previously_written_output()
    -> Result<(), Box<dyn std::error::Error>> {
        run(async {
            let allocator = ControlledAllocator::default();
            let manager = super::super::manager_tests::manager_with_allocator(
                S2sLimits::default(),
                allocator.clone(),
            )?;
            let task = manager
                .admit(
                    "localhost",
                    "remote.test",
                    controlled_stanza("buffered", allocator.clone()).await?,
                )
                .map_err(|error| format!("{error:?}"))?
                .ok_or("launch")?;
            manager
                .admit(
                    "localhost",
                    "remote.test",
                    controlled_stanza("failed-last", allocator.clone()).await?,
                )
                .map_err(|error| format!("{error:?}"))?;
            let calls = Arc::new(PlMutex::new(Calls {
                accepts: true,
                ..Default::default()
            }));
            let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
            let mut buffered = false;
            let valid = LinkValidity::fixed(SystemTime::now() + Duration::from_secs(60));
            let mut first = task.queue.receiver.recv().await?;
            assert!(matches!(
                write(
                    &mut writer,
                    &mut first,
                    &manager.inner,
                    &valid,
                    false,
                    &mut buffered
                )
                .await,
                Ok(WriteOutcome::Written { .. })
            ));
            drop(first);
            assert!(buffered);
            assert_eq!(calls.lock().writes, 0);
            let mut last = task.queue.receiver.recv().await?;
            allocator.exhausted.store(true, Ordering::Relaxed);
            assert!(matches!(
                write(
                    &mut writer,
                    &mut last,
                    &manager.inner,
                    &valid,
                    true,
                    &mut buffered
                )
                .await,
                Ok(WriteOutcome::Discarded)
            ));
            drop(last);
            assert!(!buffered);
            assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 0);
            assert_eq!(task.queue.counters.bytes.load(Ordering::Relaxed), 0);
            assert_eq!(allocator.live.load(Ordering::Relaxed), 0);
            {
                let calls = calls.lock();
                let output = std::str::from_utf8(&calls.output)?;
                assert!(output.contains("buffered"));
                assert!(!output.contains("failed-last"));
                assert_eq!(calls.flushes, 1);
            }
            let output = render(&manager.inner.metrics)?;
            assert!(output.contains("s2s_dropped_stanzas_total{reason=\"internal_error\"} 1"));
            assert!(output.contains("s2s_stanzas_sent_total{kind=\"message\"} 1"));
            drop(task);
            manager
                .join(Instant::now() + Duration::from_secs(5))
                .await?;
            Ok(())
        })
    }

    #[test]
    fn stop_and_expiry_at_preparation_discard_assign_each_head_once()
    -> Result<(), Box<dyn std::error::Error>> {
        run(async {
            for (stopped_first, expired) in
                [(false, false), (true, false), (false, true), (true, true)]
            {
                let allocator = ControlledAllocator::default();
                let manager = super::super::manager_tests::manager_with_allocator(
                    S2sLimits::default(),
                    allocator.clone(),
                )?;
                let task = manager
                    .admit(
                        "localhost",
                        "remote.test",
                        controlled_stanza("failed-head", allocator.clone()).await?,
                    )
                    .map_err(|error| format!("{error:?}"))?
                    .ok_or("launch")?;
                manager
                    .admit(
                        "localhost",
                        "remote.test",
                        controlled_stanza("tail", allocator.clone()).await?,
                    )
                    .map_err(|error| format!("{error:?}"))?;
                let mut current = Some(task.queue.receiver.recv().await?);
                let calls = Arc::new(PlMutex::new(Calls::default()));
                let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
                let mut buffered = false;
                allocator.exhausted.store(true, Ordering::Relaxed);
                if stopped_first {
                    manager.stop();
                }
                let outcome = write(
                    &mut writer,
                    current.as_mut().ok_or("head")?,
                    &manager.inner,
                    &LinkValidity::fixed(if expired {
                        SystemTime::UNIX_EPOCH
                    } else {
                        SystemTime::now() + Duration::from_secs(60)
                    }),
                    false,
                    &mut buffered,
                )
                .await;
                if stopped_first {
                    assert!(matches!(outcome, Err(StreamClose::Shutdown)));
                } else if expired {
                    assert!(matches!(outcome, Err(StreamClose::CertificateExpired)));
                } else {
                    assert!(matches!(outcome, Ok(WriteOutcome::Discarded)));
                    current = None;
                }
                manager.stop();
                shutdown_queue(
                    &manager.inner,
                    &task.queue.receiver,
                    &task.queue.pair,
                    &mut current,
                );
                let output = render(&manager.inner.metrics)?;
                let committed = !stopped_first && !expired;
                let shutdown = if committed { 1 } else { 2 };
                assert!(output.contains(&format!(
                    "s2s_dropped_stanzas_total{{reason=\"shutdown\"}} {shutdown}"
                )));
                assert_eq!(
                    output.contains("s2s_dropped_stanzas_total{reason=\"internal_error\"} 1"),
                    committed
                );
                assert!(
                    !output.contains("s2s_dropped_stanzas_total{reason=\"connection_lost\"} 1")
                );
                assert_eq!(calls.lock().writes, 0);
                assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 0);
                assert_eq!(task.queue.counters.bytes.load(Ordering::Relaxed), 0);
                assert_eq!(allocator.live.load(Ordering::Relaxed), 0);
                drop(task);
                manager
                    .join(Instant::now() + Duration::from_secs(5))
                    .await?;
            }
            Ok(())
        })
    }

    #[test]
    fn ready_peer_termination_precedes_queued_output_and_a_retained_head()
    -> Result<(), Box<dyn std::error::Error>> {
        run(async {
            for retained in [false, true] {
                for (event, expected) in [
                    ("</stream:stream>", StreamClose::StreamEnd),
                    (
                        "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>",
                        StreamClose::PeerError,
                    ),
                    (
                        "<message from='bob@remote.test' to='alice@localhost'/>",
                        StreamClose::NotAuthorized,
                    ),
                ] {
                    let manager = manager(S2sLimits::default())?;
                    let task = manager
                        .admit("localhost", "remote.test", message().await?)
                        .map_err(|error| format!("{error:?}"))?
                        .ok_or("launch")?;
                    manager
                        .admit("localhost", "remote.test", message().await?)
                        .map_err(|error| format!("{error:?}"))?;
                    let mut current = if retained {
                        Some(task.queue.receiver.recv().await?)
                    } else {
                        None
                    };
                    let queued_bytes = task.queue.counters.bytes.load(Ordering::Relaxed);
                    let xml = format!(
                        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0'>{event}"
                    );
                    let limits = &manager.inner.limits;
                    let mut reader = S2sReader::new(
                        tokio::io::BufReader::new(std::io::Cursor::new(xml.into_bytes())),
                        &S2sReaderLimits {
                            max_stanza_bytes: limits.max_stanza_bytes,
                            stanzas: limits.incoming_stanzas_per_connection.clone(),
                            xml: limits.incoming_xml_per_connection.clone(),
                        },
                        GlobalChunkAllocator,
                        None,
                    );
                    assert!(matches!(
                        reader
                            .next_event()
                            .await
                            .map_err(|error| format!("{error:?}"))?,
                        Some(StreamEvent::StreamStart { .. })
                    ));
                    let calls = Arc::new(PlMutex::new(Calls {
                        accepts: true,
                        ..Default::default()
                    }));
                    let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
                    let closed = serve(
                        &manager.inner,
                        &mut reader,
                        &mut writer,
                        &LinkValidity::fixed(SystemTime::now() + Duration::from_secs(60)),
                        &task.queue.receiver,
                        &mut current,
                        &crate::router::Router::new(
                            manager.inner.hosts.clone(),
                            crate::router::local::LocalRouter::new(GlobalChunkAllocator),
                        )
                        .handle(),
                    )
                    .await;
                    assert_eq!(closed.reason.as_str(), expected.as_str());
                    assert_eq!(calls.lock().writes, 0);
                    assert_eq!(calls.lock().flushes, 0);
                    assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 2);
                    assert_eq!(
                        task.queue.counters.bytes.load(Ordering::Relaxed),
                        queued_bytes
                    );
                    assert_eq!(current.is_some(), retained);
                    assert!(
                        !render(&manager.inner.metrics)?
                            .contains("s2s_stanzas_sent_total{kind=\"message\"} 1")
                    );
                    assert!(
                        !render(&manager.inner.metrics)?
                            .contains("s2s_stanzas_sent_total{kind=\"message\"} 2")
                    );
                    drop(current);
                    drop(task);
                    manager
                        .join(Instant::now() + Duration::from_secs(5))
                        .await?;
                }
            }
            Ok(())
        })
    }

    #[test]
    fn interrupted_graceful_close_does_not_restart_or_emit_another_footer()
    -> Result<(), Box<dyn std::error::Error>> {
        struct PendingInput {
            bytes: std::io::Cursor<Vec<u8>>,
            polls: Arc<PlMutex<usize>>,
            dropped: Arc<std::sync::atomic::AtomicBool>,
        }
        impl tokio::io::AsyncRead for PendingInput {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                output: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let position = self.bytes.position() as usize;
                if position < self.bytes.get_ref().len() {
                    let count = output
                        .remaining()
                        .min(self.bytes.get_ref().len() - position);
                    output.put_slice(&self.bytes.get_ref()[position..position + count]);
                    self.bytes.set_position((position + count) as u64);
                    Poll::Ready(Ok(()))
                } else {
                    *self.polls.lock() += 1;
                    Poll::Pending
                }
            }
        }
        impl Drop for PendingInput {
            fn drop(&mut self) {
                self.dropped
                    .store(true, std::sync::atomic::Ordering::Release);
            }
        }
        run(async {
            for (accepts, expiry) in [(false, false), (true, false), (true, true)] {
                let manager = manager(S2sLimits::default())?;
                let limits = &manager.inner.limits;
                let polls = Arc::new(PlMutex::new(0));
                let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let mut reader = S2sReader::new(tokio::io::BufReader::new(PendingInput {
                    bytes: std::io::Cursor::new(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server'></stream:stream>".to_vec()),
                    polls: Arc::clone(&polls), dropped: Arc::clone(&dropped),
                }), &S2sReaderLimits { max_stanza_bytes: limits.max_stanza_bytes, stanzas: limits.incoming_stanzas_per_connection.clone(), xml: limits.incoming_xml_per_connection.clone() }, GlobalChunkAllocator, None);
                assert!(matches!(
                    reader.next_event().await,
                    Ok(Some(StreamEvent::StreamStart { .. }))
                ));
                assert!(matches!(
                    reader.next_event().await,
                    Ok(Some(StreamEvent::StreamEnd))
                ));
                let calls = Arc::new(PlMutex::new(Calls {
                    accepts,
                    ..Calls::default()
                }));
                let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
                {
                    let validity = LinkValidity::fixed(
                        SystemTime::now() + Duration::from_secs(if expiry { 1 } else { 60 }),
                    );
                    let mut closing = pin!(graceful(
                        &mut reader,
                        &mut writer,
                        StreamClose::StreamEnd,
                        close_condition(StreamClose::StreamEnd),
                        manager.inner.stopped.clone(),
                        &validity,
                        Duration::from_secs(60)
                    ));
                    assert!(poll!(closing.as_mut()).is_pending());
                    assert!(calls.lock().writes > 0);
                    assert_eq!(calls.lock().closes, usize::from(accepts));
                    assert_eq!(*polls.lock(), usize::from(accepts));
                    assert!(!dropped.load(std::sync::atomic::Ordering::Acquire));
                    if !expiry {
                        manager.stop();
                    }
                    let result = closing.await;
                    assert!(matches!(
                        (expiry, result),
                        (false, Err(StreamClose::Shutdown))
                            | (true, Err(StreamClose::CertificateExpired))
                    ));
                }
                let writes = calls.lock().writes;
                drop(writer);
                assert_eq!(calls.lock().writes, writes);
                assert_eq!(calls.lock().closes, usize::from(accepts));
                assert_eq!(dropped.load(std::sync::atomic::Ordering::Acquire), accepts);
                if accepts {
                    assert_eq!(calls.lock().output.as_slice(), b"</stream:stream>");
                }
                manager.stop();
                manager
                    .join(Instant::now() + Duration::from_secs(5))
                    .await?;
            }
            Ok(())
        })
    }

    #[test]
    fn monitored_revocation_resets_the_link_and_keeps_unstarted_output_queued()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::s2s::revocation::{RevocationSource, RevocationStatus, RevocationVerdict};
        use std::cell::Cell;
        use std::rc::Rc;
        const HEADER: &[u8] = b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server'>";
        struct PeerInput {
            position: usize,
            ready: Rc<Cell<bool>>,
        }
        impl tokio::io::AsyncRead for PeerInput {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                output: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let bytes = if self.position < HEADER.len() {
                    &HEADER[self.position..]
                } else if !self.ready.get() {
                    return Poll::Pending;
                } else {
                    &b"</stream:stream>"[self.position - HEADER.len()..]
                };
                let count = bytes.len().min(output.remaining());
                output.put_slice(&bytes[..count]);
                self.position += count;
                Poll::Ready(Ok(()))
            }
        }
        run(async {
            let manager = manager(S2sLimits::default())?;
            let router = crate::router::Router::new(
                manager.inner.hosts.clone(),
                crate::router::local::LocalRouter::new(GlobalChunkAllocator),
            )
            .handle();
            let mut task = manager
                .admit("localhost", "remote.test", message().await?)
                .map_err(|error| format!("{error:?}"))?
                .ok_or("launch")?;
            drop(task.queue.receiver.recv().await?);
            let peer_ready = Rc::new(Cell::new(false));
            let mut reader = S2sReader::new(
                tokio::io::BufReader::new(PeerInput {
                    position: 0,
                    ready: Rc::clone(&peer_ready),
                }),
                &S2sReaderLimits {
                    max_stanza_bytes: manager.inner.limits.max_stanza_bytes,
                    stanzas: manager.inner.limits.incoming_stanzas_per_connection.clone(),
                    xml: manager.inner.limits.incoming_xml_per_connection.clone(),
                },
                GlobalChunkAllocator,
                None,
            );
            assert!(matches!(
                reader.next_event().await,
                Ok(Some(StreamEvent::StreamStart { .. }))
            ));
            let calls = Arc::new(PlMutex::new(Calls {
                accepts: true,
                ..Default::default()
            }));
            let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
            let initial = RevocationVerdict {
                source: RevocationSource::Fetched,
                status: RevocationStatus::Good,
                next_update: None,
                refresh_at: None,
                pending: vec![async {}.boxed().shared()],
                leases: Vec::new(),
                recheckable: true,
            };
            let revalidate = Box::new(move || {
                peer_ready.set(true);
                async {
                    Some(RevocationVerdict {
                        source: RevocationSource::Fetched,
                        status: RevocationStatus::Revoked,
                        next_update: None,
                        refresh_at: None,
                        pending: Vec::new(),
                        leases: Vec::new(),
                        recheckable: true,
                    })
                }
                .boxed_local()
            });
            let (validity, monitor) = LinkValidity::monitored(
                SystemTime::now() + Duration::from_secs(60),
                initial,
                Duration::from_secs(60),
                revalidate,
            );
            let mut serving = Box::pin(connected(
                &manager.inner,
                &router,
                &mut reader,
                &mut writer,
                LiveValidity {
                    validity: &validity,
                    monitor: Some(monitor),
                    connection_id: 1,
                },
                &mut task.queue,
                false,
            ));
            assert!(poll!(serving.as_mut()).is_pending());
            assert!(matches!(
                validity.reason(),
                Some(StreamClose::CertificateRevoked)
            ));
            assert!(
                manager
                    .admit("localhost", "remote.test", message().await?)
                    .map_err(|error| format!("{error:?}"))?
                    .is_none()
            );
            assert!(matches!(serving.await, StreamClose::CertificateRevoked));
            assert!(task.queue.current.is_none());
            assert_eq!(task.queue.receiver.len(), 1);
            assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 1);
            let xml = std::str::from_utf8(&calls.lock().output)?.to_owned();
            assert!(xml.contains("reset"));
            assert_eq!(xml.matches("</stream:stream>").count(), 1);
            assert!(!xml.contains("<message"));
            let mut registry = prometheus_client::registry::Registry::default();
            manager
                .inner
                .metrics
                .register(registry.sub_registry_with_prefix("lonewolf"));
            let mut metrics = String::new();
            prometheus_client::encoding::text::encode(&mut metrics, &registry)?;
            assert!(metrics.lines().any(|line| line == "lonewolf_s2s_streams_closed_total{direction=\"outbound\",outcome=\"certificate_revoked\"} 1"));
            assert!(!metrics.contains("s2s_dropped_stanzas_total{reason=\"connection_lost\"}"));
            manager.stop();
            shutdown_queue(
                &manager.inner,
                &task.queue.receiver,
                &task.queue.pair,
                &mut task.queue.current,
            );
            drop(task);
            manager
                .join(Instant::now() + Duration::from_secs(5))
                .await?;
            Ok(())
        })
    }

    #[test]
    fn preparation_expiry_records_the_first_reason_before_supervisor_completion_or_cancellation()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::s2s::revocation::{
            CrlLease, RevocationSource, RevocationStatus, RevocationVerdict,
        };
        run(async {
            for complete in [false, true] {
                let allocator = ControlledAllocator::default();
                let manager = super::super::manager_tests::manager_with_allocator(
                    S2sLimits::default(),
                    allocator.clone(),
                )?;
                let task = manager
                    .admit(
                        "localhost",
                        "remote.test",
                        controlled_stanza("retained-head", allocator.clone()).await?,
                    )
                    .map_err(|error| format!("{error:?}"))?
                    .ok_or("launch")?;
                let mut head = task.queue.receiver.recv().await?;
                let token = Arc::new(());
                let initial = RevocationVerdict {
                    source: RevocationSource::File,
                    status: RevocationStatus::Good,
                    next_update: Some(SystemTime::now() - Duration::from_secs(1)),
                    refresh_at: None,
                    pending: Vec::new(),
                    leases: vec![CrlLease(Arc::clone(&token))],
                    recheckable: true,
                };
                let (validity, monitor) = LinkValidity::monitored(
                    SystemTime::now() + Duration::from_secs(60),
                    initial,
                    Duration::from_secs(60),
                    Box::new(|| {
                        async { panic!("expired links must not revalidate") }.boxed_local()
                    }),
                );
                let signal = validity.invalidated();
                let calls = Arc::new(PlMutex::new(Calls::default()));
                let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
                let mut buffered = false;
                allocator.exhausted.store(true, Ordering::Relaxed);
                let work = async {
                    let outcome = write(
                        &mut writer,
                        &mut head,
                        &manager.inner,
                        &validity,
                        false,
                        &mut buffered,
                    )
                    .await;
                    assert!(matches!(outcome, Err(StreamClose::RevocationStale)));
                    assert!(matches!(
                        validity.reason(),
                        Some(StreamClose::RevocationStale)
                    ));
                    if complete {
                        StreamClose::RevocationStale
                    } else {
                        std::future::pending().await
                    }
                };
                let mut supervised = Box::pin(supervise(
                    Some(monitor),
                    MonitorLog {
                        direction: Direction::Outbound,
                        connection_id: 1,
                        local: "localhost",
                        remote: "remote.test",
                    },
                    Duration::from_secs(5),
                    work,
                ));
                if complete {
                    assert!(matches!(supervised.await, StreamClose::RevocationStale));
                } else {
                    assert!(poll!(supervised.as_mut()).is_pending());
                    assert_eq!(Arc::strong_count(&token), 2);
                    drop(supervised);
                }
                assert!(matches!(signal.await, StreamClose::RevocationStale));
                assert!(matches!(
                    validity.check(SystemTime::UNIX_EPOCH),
                    Err(StreamClose::RevocationStale)
                ));
                assert_eq!(Arc::strong_count(&token), 1);
                assert!(head.reservation.is_some());
                assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 1);
                assert_eq!(calls.lock().writes, 0);
                let metrics = render(&manager.inner.metrics)?;
                assert!(!metrics.contains("s2s_dropped_stanzas_total{reason=\"connection_lost\"}"));
                assert!(!metrics.contains("s2s_dropped_stanzas_total{reason=\"internal_error\"}"));
                manager.stop();
                shutdown_queue(
                    &manager.inner,
                    &task.queue.receiver,
                    &task.queue.pair,
                    &mut Some(head),
                );
                drop(task);
                manager
                    .join(Instant::now() + Duration::from_secs(5))
                    .await?;
            }
            Ok(())
        })
    }
    #[test]
    fn physical_whitespace_and_partial_xml_extend_outbound_idle_until_silence()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::s2s::stream::traffic::{
            CountingIo,
            test_support::{Clock, Fragments},
        };
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        run(async {
            let manager = manager(S2sLimits {
                idle_timeout_secs: std::num::NonZeroU64::new(1).ok_or("timeout")?,
                ..Default::default()
            })?;
            let task = manager
                .admit("localhost", "remote.test", message().await?)
                .map_err(|error| format!("{error:?}"))?
                .ok_or("launch")?;
            drop(task.queue.receiver.recv().await?);
            let input = Fragments::default();
            input.push(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0'>");
            let counted = CountingIo::new(
                input.clone(),
                Arc::clone(&manager.inner.metrics),
                Direction::Outbound,
            );
            let activity = counted.activity();
            let mut reader = S2sReader::new(
                tokio::io::BufReader::new(counted.compat()),
                &S2sReaderLimits {
                    max_stanza_bytes: manager.inner.limits.max_stanza_bytes,
                    stanzas: manager.inner.limits.incoming_stanzas_per_connection.clone(),
                    xml: manager.inner.limits.incoming_xml_per_connection.clone(),
                },
                GlobalChunkAllocator,
                None,
            )
            .with_activity(activity.clone());
            assert!(matches!(
                reader.next_event().await,
                Ok(Some(StreamEvent::StreamStart { .. }))
            ));
            let router = crate::router::Router::new(
                manager.inner.hosts.clone(),
                crate::router::local::LocalRouter::new(GlobalChunkAllocator),
            )
            .handle();
            let validity = LinkValidity::fixed(SystemTime::now() + Duration::from_secs(60));
            let clock = Clock::new();
            let mut current = None;
            let mut writer = S2sWriter::new(Vec::new());
            let end = {
                let mut running = pin!(serve_with_clock(
                    &manager.inner,
                    &mut reader,
                    &mut writer,
                    &validity,
                    (&task.queue.receiver, &mut current),
                    &router,
                    &clock
                ));
                assert!(futures_util::poll!(running.as_mut()).is_pending());
                assert!(futures_util::poll!(running.as_mut()).is_pending());
                for fragment in [b" \n".as_slice(), b"<message", b" from='"] {
                    clock.advance(Duration::from_millis(500));
                    let before = input.polls();
                    input.push(fragment);
                    assert!(futures_util::poll!(running.as_mut()).is_pending());
                    assert!(input.polls() > before);
                    activity.record(clock.now());
                }
                clock.advance(Duration::from_millis(999));
                assert!(futures_util::poll!(running.as_mut()).is_pending());
                clock.advance(Duration::from_millis(1));
                running.await
            };
            assert!(matches!(end.reason, StreamClose::Idle));
            assert!(!end.abort);
            assert!(current.is_none());
            assert_eq!(task.queue.counters.count.load(Ordering::Relaxed), 0);
            manager.stop();
            manager.inner.remove(&task.queue.pair, &task.queue.counters);
            drop(task);
            manager
                .join(Instant::now() + Duration::from_secs(5))
                .await?;
            Ok(())
        })
    }
    #[test]
    fn routed_preflight_preserves_exact_boundary_and_control_accounting()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::s2s::stream::limits::StreamLimits;
        run(async {
            for (fits, stopped, expired) in [
                (true, false, false),
                (false, false, false),
                (false, true, false),
                (false, false, true),
            ] {
                let manager = manager(S2sLimits::default())?;
                let task = manager
                    .admit("localhost", "remote.test", message().await?)
                    .map_err(|error| format!("{error:?}"))?
                    .ok_or("launch")?;
                let mut head = task.queue.receiver.recv().await?;
                let mut arena = Arena::try_new(Default::default())?;
                let scoped = head
                    .stanza
                    .resolve()?
                    .rescope_in(StanzaNamespace::Server, &mut arena)?;
                let mut exact = Vec::new();
                scoped
                    .resolve(&arena)?
                    .write_xml_async(&mut exact)
                    .await
                    .map_err(|error| format!("{error:?}"))?;
                let maximum: u32 = (exact.len() - usize::from(!fits)).try_into()?;
                let calls = Arc::new(PlMutex::new(Calls {
                    accepts: true,
                    ..Default::default()
                }));
                let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
                writer.update_peer_limits(Some(StreamLimits {
                    max_bytes: Some(maximum),
                    idle_seconds: None,
                }));
                if stopped {
                    manager.stop();
                }
                let valid_until = if expired {
                    SystemTime::now() - Duration::from_secs(1)
                } else {
                    SystemTime::now() + Duration::from_secs(60)
                };
                let validity = LinkValidity::fixed(valid_until);
                let mut buffered = !fits;
                let result = write(
                    &mut writer,
                    &mut head,
                    &manager.inner,
                    &validity,
                    true,
                    &mut buffered,
                )
                .await;
                if stopped {
                    assert!(matches!(result, Err(StreamClose::Shutdown)));
                } else if expired {
                    assert!(matches!(result, Err(StreamClose::CertificateExpired)));
                } else if fits {
                    assert!(matches!(result, Ok(WriteOutcome::Written { .. })));
                    assert_eq!(calls.lock().output, exact);
                } else {
                    assert!(matches!(result, Ok(WriteOutcome::PeerSizeRejected)));
                    assert_eq!(calls.lock().flushes, 0);
                }
                if !fits {
                    assert_eq!(calls.lock().writes, 0);
                }
                assert_eq!(head.reservation.is_some(), stopped || expired);
                assert_eq!(
                    task.queue.counters.count.load(Ordering::Relaxed),
                    usize::from(stopped || expired)
                );
                let metrics = render(&manager.inner.metrics)?;
                assert_eq!(
                    metrics.contains("s2s_peer_size_rejections_total 1"),
                    !fits && !stopped && !expired
                );
                assert!(!metrics.contains("reason=\"connection_lost\""));
                assert!(!metrics.contains("reason=\"internal_error\""));
                drop(head);
                manager.stop();
                manager.inner.remove(&task.queue.pair, &task.queue.counters);
                drop(task);
                manager
                    .join(Instant::now() + Duration::from_secs(5))
                    .await?;
            }
            Ok(())
        })
    }
}
