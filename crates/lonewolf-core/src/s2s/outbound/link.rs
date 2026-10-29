// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::time::{Duration, Instant, SystemTime};

use futures_util::future::{Either, select};
use futures_util::io::AsyncWrite;
use lonewolf_util::arena::Arena;
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stanza::StanzaNamespace;
use lonewolf_xmpp::stream::StreamErrorCondition;
use tokio::io::AsyncBufRead;

use super::*;
use crate::s2s::metrics::{Direction, StreamClose};
use crate::s2s::stream::S2sError;

const CLOSE_BUDGET: Duration = Duration::from_secs(6);
const FOOTER_GRACE: Duration = Duration::from_secs(5);

async fn watch<T>(
    stop: Option<Stop>,
    validity: Option<SystemTime>,
    timeout: Duration,
    timeout_reason: StreamClose,
    work: impl Future<Output = Result<T, S2sError>>,
) -> Result<T, StreamClose> {
    let stop = async {
        match stop {
            Some(stop) => stop.await,
            None => std::future::pending().await,
        }
    };
    let expiry = async {
        match validity {
            Some(until) => {
                if let Ok(delay) = until.duration_since(SystemTime::now())
                    && !delay.is_zero()
                {
                    compio::time::sleep(delay).await;
                }
            }
            None => std::future::pending().await,
        }
    };
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
    match select(pin!(stop), pin!(select(pin!(expiry), pin!(work)))).await {
        Either::Left(_) => Err(StreamClose::Shutdown),
        Either::Right((Either::Left(_), _)) => Err(StreamClose::CertificateExpired),
        Either::Right((Either::Right((result, _)), _)) => result,
    }
}

enum WriteOutcome {
    Written(Instant),
    Discarded,
}

fn discard<A: ChunkAllocator>(
    inner: &Inner<A>,
    queued: &mut Queued<A>,
    valid_until: SystemTime,
) -> Result<WriteOutcome, StreamClose> {
    let state = inner.state.lock();
    if state.stopped {
        return Err(StreamClose::Shutdown);
    }
    if SystemTime::now() >= valid_until {
        return Err(StreamClose::CertificateExpired);
    }
    drop(queued.reservation.take());
    inner.metrics.dropped(DropReason::InternalError, 1);
    Ok(WriteOutcome::Discarded)
}

async fn write<A: ChunkAllocator + Clone, W: AsyncWrite + Unpin>(
    writer: &mut S2sWriter<W>,
    queued: &mut Queued<A>,
    inner: &Inner<A>,
    valid_until: SystemTime,
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
        let outcome = discard(inner, queued, valid_until)?;
        if flush && *buffered {
            watch(
                Some(inner.stopped.clone()),
                Some(valid_until),
                Duration::from_secs(inner.limits.stalled_write_timeout_secs.get()),
                StreamClose::StalledWrite,
                writer.flush(),
            )
            .await?;
            *buffered = false;
        }
        return Ok(outcome);
    };
    let kind = view.kind();
    let timeout = Duration::from_secs(inner.limits.stalled_write_timeout_secs.get());
    let result = {
        let mut operation = pin!(writer.write_stanza(&view));
        watch(
            Some(inner.stopped.clone()),
            Some(valid_until),
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
            tracing::debug!(
                stanza_kind = kind.as_str(),
                "s2s in-flight stanza discarded"
            );
        }
        return Err(reason);
    }
    let written_at = Instant::now();
    inner.metrics.stanza_sent(kind);
    *buffered = true;
    if flush {
        watch(
            Some(inner.stopped.clone()),
            Some(valid_until),
            timeout,
            StreamClose::StalledWrite,
            writer.flush(),
        )
        .await?;
        *buffered = false;
    }
    Ok(WriteOutcome::Written(written_at))
}

async fn graceful<
    A: ChunkAllocator + Clone,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
>(
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    reason: StreamClose,
    stop: Stop,
    valid_until: SystemTime,
    write_timeout: Duration,
) -> Result<(), StreamClose> {
    let condition = match reason {
        StreamClose::CertificateExpired => Some(StreamErrorCondition::Reset),
        StreamClose::NotAuthorized => Some(StreamErrorCondition::NotAuthorized),
        _ => None,
    };
    let stopped = (!matches!(reason, StreamClose::Shutdown)).then_some(stop);
    let validity = (!matches!(reason, StreamClose::CertificateExpired)).then_some(valid_until);
    watch(
        stopped,
        validity,
        CLOSE_BUDGET,
        StreamClose::StalledWrite,
        async {
            compio::time::timeout(write_timeout, writer.close(condition))
                .await
                .map_err(|_| S2sError::Timeout)??;
            if !matches!(reason, StreamClose::StreamEnd) {
                let _ = compio::time::timeout(FOOTER_GRACE, async {
                    while let Ok(Some(event)) = reader.next_event().await {
                        if matches!(event, StreamEvent::StreamEnd) {
                            break;
                        }
                    }
                })
                .await;
            }
            writer.shutdown().await
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
    valid_until: SystemTime,
    receiver: &Receiver<Queued<A>>,
    current: &mut Option<Queued<A>>,
) -> Closed {
    let mut last_written = Instant::now();
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
        let idle = Duration::from_secs(inner.limits.idle_timeout_secs.get())
            .saturating_sub(last_written.elapsed());
        match watch(
            Some(inner.stopped.clone()),
            Some(valid_until),
            idle,
            StreamClose::Idle,
            next,
        )
        .await
        {
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
                    valid_until,
                    receiver.is_empty(),
                    &mut buffered,
                )
                .await
                {
                    Ok(WriteOutcome::Written(written_at)) => {
                        last_written = written_at;
                        *current = None;
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
                                || !matches!(
                                    reason,
                                    StreamClose::Shutdown | StreamClose::CertificateExpired
                                ),
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

pub(super) async fn run<A: ChunkAllocator + Clone>(
    inner: Arc<Inner<A>>,
    router: RouterHandle<A>,
    pair: Pair,
    counters: Arc<QueueCounters>,
    receiver: QueueReceiver<A>,
    mut failures: u32,
) {
    let mut current = None;
    loop {
        if inner.state.lock().stopped {
            break;
        }
        let context = connect::ConnectContext {
            hosts: &inner.hosts,
            trust: &inner.trust,
            resolver: &inner.resolver,
            limits: &inner.limits,
            metrics: Arc::clone(&inner.metrics),
        };
        let result = stopping(
            inner.stopped.clone(),
            connect::establish(&pair.0, &pair.1, &context, inner.allocator.clone()),
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
                if !inner.failed(
                    &pair,
                    &counters,
                    failures,
                    condition,
                    Instant::now(),
                    jitter(),
                ) {
                    break;
                }
                receiver.close();
                while let Some(queued) = current.take().or_else(|| receiver.try_recv().ok()) {
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
        ready(&counters, &mut failures);
        let gauge = inner.metrics.stream_opened(Direction::Outbound);
        let closed = serve(
            &inner,
            &mut stream.reader,
            &mut stream.writer,
            stream.valid_until,
            &receiver,
            &mut current,
        )
        .await;
        let reason = if closed.abort {
            closed.reason
        } else {
            match graceful(
                &mut stream.reader,
                &mut stream.writer,
                closed.reason,
                inner.stopped.clone(),
                stream.valid_until,
                Duration::from_secs(inner.limits.stalled_write_timeout_secs.get()),
            )
            .await
            {
                Ok(()) => closed.reason,
                Err(reason) => reason,
            }
        };
        inner.metrics.stream_closed(Direction::Outbound, reason);
        drop(stream);
        drop(gauge);
        counters.ready.store(false, Ordering::Relaxed);
        let mut state = inner.state.lock();
        if state.stopped
            || (receiver.is_empty() && current.is_none())
            || !state.owns(&pair, &counters)
        {
            if state.owns(&pair, &counters) {
                state.entries.remove(&pair);
            }
            break;
        }
        drop(state);
    }
    receiver.close();
    shutdown_queue(&inner, &receiver, &pair, &mut current);
    inner.remove(&pair, &counters);
}

fn shutdown_queue<A: ChunkAllocator>(
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
            let mut current = task.receiver.recv().await?;
            assert_eq!(task.counters.count.load(Ordering::Relaxed), 2);
            let calls = Arc::new(PlMutex::new(Calls::default()));
            let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
            let valid = SystemTime::now() + Duration::from_secs(60);
            let mut buffered = false;
            {
                let mut writing = pin!(write(
                    &mut writer,
                    &mut current,
                    &manager.inner,
                    valid,
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
            assert_eq!(task.counters.count.load(Ordering::Relaxed), 1);
            shutdown_queue(&manager.inner, &task.receiver, &task.pair, &mut None);
            assert_eq!(task.counters.count.load(Ordering::Relaxed), 0);
            assert_eq!(task.counters.bytes.load(Ordering::Relaxed), 0);
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
            let mut source = task.receiver.recv().await?;
            let mut buffered = false;
            {
                let mut writing = pin!(write(
                    &mut writer,
                    &mut source,
                    &manager.inner,
                    SystemTime::now() + Duration::from_secs(60),
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
                let mut current = Some(task.receiver.recv().await?);
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
                    SystemTime::UNIX_EPOCH,
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
                assert_eq!(task.counters.count.load(Ordering::Relaxed), 2);
                assert!(
                    !render(&manager.inner.metrics)?
                        .contains("s2s_dropped_stanzas_total{reason=\"connection_lost\"} 1")
                );
                assert!(
                    !render(&manager.inner.metrics)?
                        .contains("s2s_stanzas_sent_total{kind=\"message\"} 1")
                );
                manager.stop();
                shutdown_queue(&manager.inner, &task.receiver, &task.pair, &mut current);
                assert_eq!(task.counters.count.load(Ordering::Relaxed), 0);
                assert_eq!(task.counters.bytes.load(Ordering::Relaxed), 0);
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
            let valid = SystemTime::now() + Duration::from_secs(60);
            let mut head = task.receiver.recv().await?;
            allocator.exhausted.store(true, Ordering::Relaxed);
            assert!(matches!(
                write(
                    &mut writer,
                    &mut head,
                    &manager.inner,
                    valid,
                    false,
                    &mut buffered
                )
                .await,
                Ok(WriteOutcome::Discarded)
            ));
            assert!(head.reservation.is_none());
            assert_eq!(calls.lock().writes, 0);
            assert_eq!(task.counters.count.load(Ordering::Relaxed), 2);
            drop(head);
            allocator.exhausted.store(false, Ordering::Relaxed);
            for id in ["first-tail", "second-tail"] {
                let mut queued = task.receiver.recv().await?;
                assert_eq!(queued.stanza.resolve()?.id()?, Some(id));
                assert!(matches!(
                    write(
                        &mut writer,
                        &mut queued,
                        &manager.inner,
                        valid,
                        task.receiver.is_empty(),
                        &mut buffered
                    )
                    .await,
                    Ok(WriteOutcome::Written(_))
                ));
            }
            assert!(task.receiver.is_empty());
            assert_eq!(task.counters.count.load(Ordering::Relaxed), 0);
            assert_eq!(task.counters.bytes.load(Ordering::Relaxed), 0);
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
            assert!(manager.inner.state.lock().owns(&task.pair, &task.counters));
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
            let valid = SystemTime::now() + Duration::from_secs(60);
            let mut first = task.receiver.recv().await?;
            assert!(matches!(
                write(
                    &mut writer,
                    &mut first,
                    &manager.inner,
                    valid,
                    false,
                    &mut buffered
                )
                .await,
                Ok(WriteOutcome::Written(_))
            ));
            drop(first);
            assert!(buffered);
            assert_eq!(calls.lock().writes, 0);
            let mut last = task.receiver.recv().await?;
            allocator.exhausted.store(true, Ordering::Relaxed);
            assert!(matches!(
                write(
                    &mut writer,
                    &mut last,
                    &manager.inner,
                    valid,
                    true,
                    &mut buffered
                )
                .await,
                Ok(WriteOutcome::Discarded)
            ));
            drop(last);
            assert!(!buffered);
            assert_eq!(task.counters.count.load(Ordering::Relaxed), 0);
            assert_eq!(task.counters.bytes.load(Ordering::Relaxed), 0);
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
            for (stopped_first, expired) in [(false, false), (true, false), (false, true)] {
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
                let mut current = Some(task.receiver.recv().await?);
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
                    if expired {
                        SystemTime::UNIX_EPOCH
                    } else {
                        SystemTime::now() + Duration::from_secs(60)
                    },
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
                shutdown_queue(&manager.inner, &task.receiver, &task.pair, &mut current);
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
                assert_eq!(task.counters.count.load(Ordering::Relaxed), 0);
                assert_eq!(task.counters.bytes.load(Ordering::Relaxed), 0);
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
                        Some(task.receiver.recv().await?)
                    } else {
                        None
                    };
                    let queued_bytes = task.counters.bytes.load(Ordering::Relaxed);
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
                        SystemTime::now() + Duration::from_secs(60),
                        &task.receiver,
                        &mut current,
                    )
                    .await;
                    assert_eq!(closed.reason.as_str(), expected.as_str());
                    assert_eq!(calls.lock().writes, 0);
                    assert_eq!(calls.lock().flushes, 0);
                    assert_eq!(task.counters.count.load(Ordering::Relaxed), 2);
                    assert_eq!(task.counters.bytes.load(Ordering::Relaxed), queued_bytes);
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
        run(async {
            let manager = manager(S2sLimits::default())?;
            let limits = &manager.inner.limits;
            let mut reader = S2sReader::new(
                tokio::io::BufReader::new(&b""[..]),
                &S2sReaderLimits {
                    max_stanza_bytes: limits.max_stanza_bytes,
                    stanzas: limits.incoming_stanzas_per_connection.clone(),
                    xml: limits.incoming_xml_per_connection.clone(),
                },
                GlobalChunkAllocator,
                None,
            );
            let calls = Arc::new(PlMutex::new(Calls::default()));
            let mut writer = S2sWriter::new(ControlledWriter(Arc::clone(&calls)));
            {
                let mut closing = pin!(graceful(
                    &mut reader,
                    &mut writer,
                    StreamClose::Idle,
                    manager.inner.stopped.clone(),
                    SystemTime::now() + Duration::from_secs(60),
                    Duration::from_secs(60)
                ));
                assert!(poll!(closing.as_mut()).is_pending());
                assert!(calls.lock().writes > 0);
                manager.stop();
                assert!(matches!(closing.await, Err(StreamClose::Shutdown)));
            }
            let writes = calls.lock().writes;
            drop(writer);
            assert_eq!(calls.lock().writes, writes);
            assert_eq!(calls.lock().closes, 0);
            manager
                .join(Instant::now() + Duration::from_secs(5))
                .await?;
            Ok(())
        })
    }
}
