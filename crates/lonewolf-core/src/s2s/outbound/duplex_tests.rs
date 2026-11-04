// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Waker};
use std::time::SystemTime;

use futures_channel::mpsc;
use futures_util::{Stream, poll, ready};
use lonewolf_util::arena::{AllocationError, Chunk, GlobalChunkAllocator};
use tokio::io::{AsyncRead, ReadBuf};

use super::*;
use crate::config::Config;
use crate::router::{Router, local::LocalRouter};
use crate::s2s::metrics::Direction;
use crate::s2s::outbound::manager_tests::{run as test, stanza_in};
use crate::s2s::revocation::{RevocationSource, RevocationStatus, RevocationVerdict};
use crate::s2s::stream::S2sReaderLimits;
use crate::s2s::validity::ValidityMonitor;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const HEADER: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0'>";
const INPUT: &str = "<message from='u@remote.test/r' to='v@localhost'><body>in</body></message>";

struct InputSender(mpsc::UnboundedSender<io::Result<Vec<u8>>>);
impl InputSender {
    fn unbounded_send(
        &self,
        bytes: Vec<u8>,
    ) -> Result<(), mpsc::TrySendError<io::Result<Vec<u8>>>> {
        self.0.unbounded_send(Ok(bytes))
    }
    fn fail(&self) -> Result<(), mpsc::TrySendError<io::Result<Vec<u8>>>> {
        self.0
            .unbounded_send(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
    }
}

struct Input {
    receiver: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    buffer: Vec<u8>,
    offset: usize,
}
impl AsyncBufRead for Input {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        while this.offset == this.buffer.len() {
            match ready!(Pin::new(&mut this.receiver).poll_next(cx)) {
                Some(Ok(bytes)) => {
                    this.buffer = bytes;
                    this.offset = 0;
                }
                Some(Err(error)) => return Poll::Ready(Err(error)),
                None => return Poll::Ready(Ok(&[])),
            }
        }
        Poll::Ready(Ok(&this.buffer[this.offset..]))
    }
    fn consume(self: Pin<&mut Self>, amount: usize) {
        self.get_mut().offset += amount;
    }
}
impl AsyncRead for Input {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let bytes = ready!(self.as_mut().poll_fill_buf(cx))?;
        let count = bytes.len().min(output.remaining());
        output.put_slice(&bytes[..count]);
        self.consume(count);
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct Written {
    bytes: Vec<u8>,
    pause_at: Option<usize>,
    paused_flush: bool,
    blocked_write: bool,
    blocked_flush: bool,
    flushes: usize,
    waker: Option<Waker>,
    flushed: Option<oneshot::Sender<()>>,
}
#[derive(Clone, Default)]
struct Output(Rc<RefCell<Written>>);
impl Output {
    fn pause_write(&self) {
        self.0.borrow_mut().pause_at = Some(8);
    }
    fn resume(&self) {
        let mut state = self.0.borrow_mut();
        state.pause_at = None;
        state.paused_flush = false;
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
    fn resume_write(&self) {
        let mut state = self.0.borrow_mut();
        state.pause_at = None;
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
    fn text(&self) -> TestResult<String> {
        Ok(String::from_utf8(self.0.borrow().bytes.clone())?)
    }
}
impl AsyncWrite for Output {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.borrow_mut();
        let count = state.pause_at.map_or(bytes.len(), |at| {
            at.saturating_sub(state.bytes.len()).min(bytes.len())
        });
        if count == 0 {
            state.blocked_write = true;
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            state.bytes.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.borrow_mut();
        if state.paused_flush {
            state.blocked_flush = true;
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            state.flushes += 1;
            if let Some(flushed) = state.flushed.take() {
                let _ = flushed.send(());
            }
            Poll::Ready(Ok(()))
        }
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Clock {
    now: Cell<Instant>,
    deadline: Cell<Option<Instant>>,
    waker: RefCell<Option<Waker>>,
}
impl Clock {
    fn new() -> Self {
        Self {
            now: Cell::new(Instant::now()),
            deadline: Cell::new(None),
            waker: RefCell::new(None),
        }
    }
    fn advance(&self, duration: Duration) {
        self.now.set(self.now.get() + duration);
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }
}
impl IdleClock for Clock {
    fn now(&self) -> Instant {
        self.now.get()
    }
    async fn sleep_until(&self, deadline: Instant) {
        poll_fn(|cx| {
            self.deadline.set(Some(deadline));
            if self.now.get() >= deadline {
                Poll::Ready(())
            } else {
                *self.waker.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await;
    }
}

struct Fixture<A: ChunkAllocator + Clone> {
    remote: RemoteRouter<A>,
    router: Router<A>,
    context: IngressContext<A>,
    _directory: tempfile::TempDir,
}
impl<A: ChunkAllocator + Clone + 'static> Fixture<A> {
    fn new(allocator: A) -> TestResult<Self> {
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, None)?;
        let trust = PeerTrust::load(&config.s2s.tls, hosts.crypto_provider())?;
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("state.redb"))?;
        let remote = RemoteRouter::new(
            hosts.clone(),
            PeerVerification {
                trust,
                revocation: PeerRevocation::disabled(),
            },
            Arc::new(Resolver::new(&config.s2s)?),
            &config.limits.s2s,
            allocator.clone(),
            S2sMetrics::new(0),
            Some(BidiIngress {
                storage: storage.clone(),
            }),
        );
        let router =
            Router::new(hosts, LocalRouter::new(allocator.clone())).with_remote(remote.clone());
        let context = IngressContext {
            router: router.handle(),
            storage,
            allocator,
            work: WorkGroup::new().handle(),
        };
        Ok(Self {
            remote,
            router,
            context,
            _directory: directory,
        })
    }
    async fn queue(&self, count: usize) -> TestResult<LinkQueue<A>> {
        let (sender, receiver) = async_channel::bounded(count.max(1));
        let counters = Arc::new(QueueCounters::default());
        let handle = LinkHandle {
            sender,
            counters: Arc::clone(&counters),
        };
        // The payload must exceed the writer buffer to pause stanza serialization.
        let body = "x".repeat(8192);
        for index in 0..count {
            let source = stanza_in(&format!("<message from='v@localhost' to='u@remote.test/r' id='{index}'><body>{}</body></message>", body), self.context.allocator.clone()).await?;
            let bytes = stanza_bytes(&source).ok_or("stanza size")?;
            handle
                .enqueue(source, bytes, &self.remote.inner.limits)
                .map_err(|error| format!("{error:?}"))?;
        }
        let pair: Pair = ("localhost".into(), "remote.test".into());
        self.remote
            .inner
            .state
            .lock()
            .entries
            .insert(pair.clone(), Entry::Link(handle));
        Ok(LinkQueue {
            pair,
            counters,
            receiver: QueueReceiver(receiver),
            current: None,
        })
    }
    async fn reader(&self) -> TestResult<(InputSender, S2sReader<A, Input>)> {
        let (sender, receiver) = mpsc::unbounded();
        let sender = InputSender(sender);
        sender.unbounded_send(HEADER.as_bytes().to_vec())?;
        let mut reader = S2sReader::new(
            Input {
                receiver,
                buffer: Vec::new(),
                offset: 0,
            },
            &S2sReaderLimits {
                max_stanza_bytes: self.remote.inner.limits.max_stanza_bytes,
                stanzas: self
                    .remote
                    .inner
                    .limits
                    .incoming_stanzas_per_connection
                    .clone(),
                xml: self.remote.inner.limits.incoming_xml_per_connection.clone(),
            },
            self.context.allocator.clone(),
            None,
        );
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::StreamStart { .. }))
        ));
        Ok((sender, reader))
    }
    fn cleanup(&self, mut queue: LinkQueue<A>) {
        queue.receiver.close();
        link::shutdown_queue(
            &self.remote.inner,
            &queue.receiver,
            &queue.pair,
            &mut queue.current,
        );
        self.remote.inner.remove(&queue.pair, &queue.counters);
    }
    async fn finish(self) -> TestResult {
        self.remote
            .join(Instant::now() + Duration::from_secs(5))
            .await?;
        self.router.shutdown().await?;
        Ok(())
    }
    fn metrics(&self) -> TestResult<String> {
        let mut registry = prometheus_client::registry::Registry::default();
        self.remote
            .inner
            .metrics
            .register(registry.sub_registry_with_prefix("lonewolf"));
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &registry)?;
        Ok(output)
    }
}
fn peer() -> InboundPeer {
    InboundPeer {
        local: "localhost".into(),
        remote: "remote.test".into(),
        connection_id: 1,
    }
}
fn valid() -> LinkValidity {
    LinkValidity::fixed(SystemTime::now() + Duration::from_secs(3600))
}
fn parameters<'a, A: ChunkAllocator>(
    peer: &'a InboundPeer,
    context: &'a IngressContext<A>,
    validity: &'a LinkValidity,
) -> DuplexParameters<'a, A> {
    DuplexParameters {
        peer,
        context,
        validity,
        idle_timeout: Duration::from_secs(60),
    }
}
async fn dispatch<A: ChunkAllocator>(
    _: &IngressContext<A>,
    _: &InboundPeer,
    _: RoutedStanza<A>,
) -> Result<(), IngressFailure> {
    Ok(())
}
fn sample(output: &str, text: &str) {
    assert!(
        output.lines().any(|line| line == text),
        "missing {text} in {output}"
    );
}
fn expire_later() -> (LinkValidity, ValidityMonitor) {
    LinkValidity::monitored(
        SystemTime::now() + Duration::from_secs(3600),
        RevocationVerdict {
            source: RevocationSource::Fetched,
            status: RevocationStatus::Good,
            next_update: None,
            refresh_at: None,
            pending: Vec::new(),
            leases: Vec::new(),
            recheckable: false,
        },
        Duration::from_secs(60),
        Box::new(|| async { None }.boxed_local()),
    )
}

#[test]
fn writes_continue_while_a_dispatch_is_pending() -> TestResult {
    test(async {
        let f = Fixture::new(GlobalChunkAllocator)?;
        let mut queue = f.queue(1).await?;
        let (input, mut reader) = f.reader().await?;
        input.unbounded_send(INPUT.as_bytes().to_vec())?;
        let output = Output::default();
        let mut writer = S2sWriter::new(output.clone());
        let (release, wait) = oneshot::channel();
        let mut wait = Some(wait);
        let entered = Cell::new(false);
        let p = peer();
        let v = valid();
        let end = {
            let mut running = pin!(run_outbound(
                &f.remote.inner,
                &mut queue,
                &mut reader,
                &mut writer,
                parameters(&p, &f.context, &v),
                async |_, _, _| {
                    entered.set(true);
                    if let Some(wait) = wait.take() {
                        wait.await.map_err(|_| IngressFailure)?;
                    }
                    Ok(())
                }
            ));
            assert!(poll!(running.as_mut()).is_pending());
            assert!(entered.get());
            assert!(output.text()?.ends_with("</message>"));
            assert_eq!(output.0.borrow().flushes, 1);
            release.send(()).map_err(|_| "dispatch release")?;
            input.unbounded_send(b"</stream:stream>".to_vec())?;
            running.await
        };
        assert!(matches!(end.reason, StreamClose::StreamEnd));
        f.cleanup(queue);
        f.finish().await
    })
}

#[test]
fn reads_continue_while_a_write_is_blocked() -> TestResult {
    test(async {
        let f = Fixture::new(GlobalChunkAllocator)?;
        let mut queue = f.queue(1).await?;
        let (input, mut reader) = f.reader().await?;
        let output = Output::default();
        output.pause_write();
        let mut writer = S2sWriter::new(output.clone());
        let entered = Cell::new(false);
        let p = peer();
        let v = valid();
        let end = {
            let mut running = pin!(run_outbound(
                &f.remote.inner,
                &mut queue,
                &mut reader,
                &mut writer,
                parameters(&p, &f.context, &v),
                async |_, _, _| {
                    entered.set(true);
                    Ok(())
                }
            ));
            assert!(poll!(running.as_mut()).is_pending());
            assert!(output.0.borrow().blocked_write);
            input.unbounded_send(INPUT.as_bytes().to_vec())?;
            assert!(poll!(running.as_mut()).is_pending());
            assert!(entered.get());
            output.resume();
            input.unbounded_send(b"</stream:stream>".to_vec())?;
            running.await
        };
        assert!(end.peer_closed);
        f.cleanup(queue);
        f.finish().await
    })
}

#[test]
fn peer_closing_tag_lets_the_current_write_finish_and_keeps_the_rest_queued() -> TestResult {
    test(async {
        let f = Fixture::new(GlobalChunkAllocator)?;
        let mut queue = f.queue(3).await?;
        let (input, mut reader) = f.reader().await?;
        let output = Output::default();
        output.pause_write();
        let mut writer = S2sWriter::new(output.clone());
        let p = peer();
        let v = valid();
        let end = {
            let mut running = pin!(run_outbound(
                &f.remote.inner,
                &mut queue,
                &mut reader,
                &mut writer,
                parameters(&p, &f.context, &v),
                dispatch
            ));
            assert!(poll!(running.as_mut()).is_pending());
            assert!(output.0.borrow().blocked_write);
            input.unbounded_send(b"</stream:stream>".to_vec())?;
            assert!(poll!(running.as_mut()).is_pending());
            output.resume();
            running.await
        };
        assert!(end.peer_closed);
        assert!(matches!(end.reason, StreamClose::StreamEnd));
        assert!(!end.abort);
        writer.flush().await.map_err(|error| format!("{error:?}"))?;
        assert_eq!(output.text()?.matches("<message").count(), 1);
        assert!(output.text()?.ends_with("</message>"));
        assert_eq!(queue.receiver.len(), 2);
        assert_eq!(queue.counters.count.load(Ordering::Relaxed), 2);
        f.cleanup(queue);
        f.finish().await
    })
}

#[test]
fn address_violation_stops_sending_at_a_boundary() -> TestResult {
    test(async {
        let f = Fixture::new(GlobalChunkAllocator)?;
        let mut queue = f.queue(2).await?;
        let (input, mut reader) = f.reader().await?;
        let output = Output::default();
        output.pause_write();
        let mut writer = S2sWriter::new(output.clone());
        let p = peer();
        let v = valid();
        let end = {
            let mut running = pin!(run_outbound(
                &f.remote.inner,
                &mut queue,
                &mut reader,
                &mut writer,
                parameters(&p, &f.context, &v),
                dispatch
            ));
            assert!(poll!(running.as_mut()).is_pending());
            input.unbounded_send(b"<message from='u@foreign.test' to='v@localhost'/>".to_vec())?;
            assert!(poll!(running.as_mut()).is_pending());
            output.resume();
            running.await
        };
        assert_eq!(end.violation, Some(StreamErrorCondition::InvalidFrom));
        assert!(matches!(end.reason, StreamClose::InvalidFrom));
        assert!(!end.abort);
        writer.flush().await.map_err(|error| format!("{error:?}"))?;
        assert!(output.text()?.ends_with("</message>"));
        assert_eq!(queue.receiver.len(), 1);
        f.cleanup(queue);
        f.finish().await
    })
}

#[test]
fn transport_failure_during_a_write_aborts_and_counts_the_lost_stanza() -> TestResult {
    test(async {
        for paused_flush in [false, true] {
            let f = Fixture::new(GlobalChunkAllocator)?;
            let mut queue = f.queue(1).await?;
            let (input, mut reader) = f.reader().await?;
            let output = Output::default();
            if paused_flush {
                output.0.borrow_mut().paused_flush = true;
            } else {
                output.pause_write();
            }
            let mut writer = S2sWriter::new(output.clone());
            let p = peer();
            let v = valid();
            let end = {
                let mut running = pin!(run_outbound(
                    &f.remote.inner,
                    &mut queue,
                    &mut reader,
                    &mut writer,
                    parameters(&p, &f.context, &v),
                    dispatch
                ));
                assert!(poll!(running.as_mut()).is_pending());
                if paused_flush {
                    assert!(output.0.borrow().blocked_flush);
                } else {
                    assert!(output.0.borrow().blocked_write);
                }
                input.fail()?;
                running.await
            };
            assert!(end.abort);
            assert!(matches!(end.reason, StreamClose::TransportError));
            let metrics = f.metrics()?;
            if paused_flush {
                sample(
                    &metrics,
                    "lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 1",
                );
                assert!(!metrics.contains("lonewolf_s2s_dropped_stanzas_total"));
            } else {
                sample(
                    &metrics,
                    "lonewolf_s2s_dropped_stanzas_total{reason=\"connection_lost\"} 1",
                );
            }
            assert!(queue.current.is_none());
            f.cleanup(queue);
            f.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn shutdown_ends_the_session() -> TestResult {
    test(async {
        let f = Fixture::new(GlobalChunkAllocator)?;
        let mut queue = f.queue(0).await?;
        let (_input, mut reader) = f.reader().await?;
        let mut writer = S2sWriter::new(Output::default());
        let p = peer();
        let v = valid();
        let end = {
            let mut running = pin!(run_outbound(
                &f.remote.inner,
                &mut queue,
                &mut reader,
                &mut writer,
                parameters(&p, &f.context, &v),
                dispatch
            ));
            assert!(poll!(running.as_mut()).is_pending());
            f.remote.stop();
            running.await
        };
        assert!(matches!(end.reason, StreamClose::Shutdown));
        assert!(!end.abort);
        f.cleanup(queue);
        f.finish().await
    })
}

#[test]
fn validity_expiry_waits_for_the_current_write() -> TestResult {
    test(async {
        for writing in [false, true] {
            let f = Fixture::new(GlobalChunkAllocator)?;
            let mut queue = f.queue(usize::from(writing)).await?;
            let (_input, mut reader) = f.reader().await?;
            let output = Output::default();
            output.pause_write();
            let mut writer = S2sWriter::new(output.clone());
            let p = peer();
            let (v, monitor) = expire_later();
            let end = {
                let mut running = pin!(run_outbound(
                    &f.remote.inner,
                    &mut queue,
                    &mut reader,
                    &mut writer,
                    parameters(&p, &f.context, &v),
                    dispatch
                ));
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(output.0.borrow().blocked_write, writing);
                v.record_invalidation(StreamClose::CertificateExpired);
                drop(monitor);
                running.await
            };
            assert!(matches!(end.reason, StreamClose::CertificateExpired));
            assert_eq!(end.abort, writing);
            f.cleanup(queue);
            f.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn idle_requires_silence_in_both_directions() -> TestResult {
    test(async {
        for outbound_traffic in [false, true] {
            let f = Fixture::new(GlobalChunkAllocator)?;
            let mut queue = f.queue(0).await?;
            let (input, mut reader) = f.reader().await?;
            let output = Output::default();
            let mut writer = S2sWriter::new(output.clone());
            let p = peer();
            let v = valid();
            let clock = Clock::new();
            let received = Cell::new(0);
            let end = {
                let mut parameters = parameters(&p, &f.context, &v);
                parameters.idle_timeout = Duration::from_millis(200);
                let mut running = pin!(run(
                    Session {
                        inner: &f.remote.inner,
                        source: QueueSource::Owned(&mut queue),
                        outbound: true
                    },
                    &mut reader,
                    &mut writer,
                    parameters,
                    f.remote.inner.stopped.clone(),
                    async |_, _, _| {
                        received.set(received.get() + 1);
                        Ok(())
                    },
                    &clock
                ));
                assert!(poll!(running.as_mut()).is_pending());
                for count in 1..=3 {
                    clock.advance(Duration::from_millis(100));
                    if outbound_traffic {
                        let source = stanza_in("<message from='v@localhost' to='u@remote.test/r'><body>out</body></message>", GlobalChunkAllocator).await?;
                        assert!(
                            f.remote
                                .admit("localhost", "remote.test", source)
                                .map_err(|error| format!("{error:?}"))?
                                .is_none()
                        );
                    } else {
                        input.unbounded_send(INPUT.as_bytes().to_vec())?;
                    }
                    assert!(poll!(running.as_mut()).is_pending());
                    if outbound_traffic {
                        assert_eq!(output.0.borrow().flushes, count);
                    } else {
                        assert_eq!(received.get(), count);
                    }
                }
                clock.advance(Duration::from_millis(199));
                assert!(poll!(running.as_mut()).is_pending());
                clock.advance(Duration::from_millis(1));
                running.await
            };
            assert!(matches!(end.reason, StreamClose::Idle));
            assert!(!end.abort);
            f.cleanup(queue);
            f.finish().await?;
        }
        for busy_write in [false, true] {
            let f = Fixture::new(GlobalChunkAllocator)?;
            let mut queue = f.queue(usize::from(busy_write)).await?;
            let (input, mut reader) = f.reader().await?;
            if !busy_write {
                input.unbounded_send(INPUT.as_bytes().to_vec())?;
            }
            let output = Output::default();
            output.pause_write();
            let mut writer = S2sWriter::new(output.clone());
            let p = peer();
            let v = valid();
            let clock = Clock::new();
            let (release, waiting) = oneshot::channel();
            let mut waiting = Some(waiting);
            let (stop, stopped) = oneshot::channel();
            let entered = Cell::new(false);
            let end = {
                let mut parameters = parameters(&p, &f.context, &v);
                parameters.idle_timeout = Duration::from_millis(200);
                let mut running = pin!(run(
                    Session {
                        inner: &f.remote.inner,
                        source: QueueSource::Owned(&mut queue),
                        outbound: true
                    },
                    &mut reader,
                    &mut writer,
                    parameters,
                    async {
                        let _ = stopped.await;
                    },
                    async |_, _, _| {
                        entered.set(true);
                        if let Some(waiting) = waiting.take() {
                            waiting.await.map_err(|_| IngressFailure)?;
                        }
                        Ok(())
                    },
                    &clock
                ));
                assert!(poll!(running.as_mut()).is_pending());
                if busy_write {
                    assert!(output.0.borrow().blocked_write);
                } else {
                    assert!(entered.get());
                }
                clock.advance(Duration::from_millis(300));
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(
                    clock.deadline.get(),
                    Some(clock.now() + Duration::from_millis(200))
                );
                if busy_write {
                    output.resume();
                } else {
                    release.send(()).map_err(|_| "dispatch release")?;
                }
                assert!(poll!(running.as_mut()).is_pending());
                if busy_write {
                    assert!(output.text()?.ends_with("</message>"));
                }
                stop.send(()).map_err(|_| "shutdown signal")?;
                running.await
            };
            assert!(matches!(end.reason, StreamClose::Shutdown));
            assert!(!end.abort);
            f.cleanup(queue);
            f.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn assigned_queue_starts_sending_and_marks_the_link_ready() -> TestResult {
    test(async {
        let f = Fixture::new(GlobalChunkAllocator)?;
        let registration = f
            .remote
            .register_bidi(&f.router.handle(), "localhost", "remote.test")
            .ok_or("registration")?;
        let mut queue = None;
        let (input, mut reader) = f.reader().await?;
        input.unbounded_send(INPUT.as_bytes().to_vec())?;
        let output = Output::default();
        let mut writer = S2sWriter::new(output.clone());
        let (flushed, flushing) = oneshot::channel();
        output.0.borrow_mut().flushed = Some(flushed);
        let (stop, stopped) = oneshot::channel();
        let received = Cell::new(0);
        let p = peer();
        let v = valid();
        let end = {
            let mut running = pin!(run_inbound(
                &registration,
                &mut queue,
                &mut reader,
                &mut writer,
                parameters(&p, &f.context, &v),
                async {
                    let _ = stopped.await;
                },
                async |_, _, _| {
                    received.set(received.get() + 1);
                    Ok(())
                }
            ));
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(received.get(), 1);
            assert!(output.0.borrow().bytes.is_empty());
            let source = stanza_in(
                "<message from='v@localhost' to='u@remote.test/r'><body>out</body></message>",
                GlobalChunkAllocator,
            )
            .await?;
            f.remote
                .route(&f.router.handle(), "localhost", "remote.test", source)
                .map_err(|error| format!("{error:?}"))?;
            match select(running.as_mut(), pin!(flushing)).await {
                Either::Left(_) => return Err("driver ended before assignment was written".into()),
                Either::Right((result, _)) => result?,
            }
            sample(
                &f.metrics()?,
                "lonewolf_s2s_outbound_links{state=\"ready\"} 1",
            );
            assert!(output.text()?.ends_with("</message>"));
            stop.send(()).map_err(|_| "shutdown signal")?;
            running.await
        };
        assert!(matches!(end.reason, StreamClose::Shutdown));
        assert!(!end.abort);
        assert!(queue.is_some());
        f.remote.stop();
        registration.release(queue.take());
        f.finish().await
    })
}

#[test]
fn bidirectional_stanza_counters_follow_the_direction() -> TestResult {
    test(async {
        for inbound in [false, true] {
            let f = Fixture::new(GlobalChunkAllocator)?;
            let (input, mut reader) = f.reader().await?;
            input.unbounded_send(INPUT.as_bytes().to_vec())?;
            let mut writer = S2sWriter::new(Output::default());
            let p = peer();
            let v = valid();
            if inbound {
                let registration = f
                    .remote
                    .register_bidi(&f.router.handle(), "localhost", "remote.test")
                    .ok_or("registration")?;
                let source = stanza_in(
                    "<message from='v@localhost' to='u@remote.test/r'><body>out</body></message>",
                    GlobalChunkAllocator,
                )
                .await?;
                let task = f
                    .remote
                    .admit("localhost", "remote.test", source)
                    .map_err(|error| format!("{error:?}"))?
                    .ok_or("launch")?;
                assert!(f.remote.inner.offer_standby(task.queue).is_ok());
                drop(task.guard);
                let mut queue = None;
                {
                    let mut running = pin!(run_inbound(
                        &registration,
                        &mut queue,
                        &mut reader,
                        &mut writer,
                        parameters(&p, &f.context, &v),
                        f.remote.inner.stopped.clone(),
                        dispatch
                    ));
                    assert!(poll!(running.as_mut()).is_pending());
                    input.unbounded_send(b"</stream:stream>".to_vec())?;
                    assert!(running.await.peer_closed);
                }
                let metrics = f.metrics()?;
                sample(
                    &metrics,
                    "lonewolf_s2s_bidi_stanzas_sent_total{kind=\"message\"} 1",
                );
                assert!(!metrics.contains("lonewolf_s2s_bidi_stanzas_received_total"));
                f.remote.stop();
                registration.release(queue.take());
            } else {
                let mut queue = f.queue(1).await?;
                {
                    let mut running = pin!(run_outbound(
                        &f.remote.inner,
                        &mut queue,
                        &mut reader,
                        &mut writer,
                        parameters(&p, &f.context, &v),
                        dispatch
                    ));
                    assert!(poll!(running.as_mut()).is_pending());
                    input.unbounded_send(b"</stream:stream>".to_vec())?;
                    assert!(running.await.peer_closed);
                }
                let metrics = f.metrics()?;
                sample(
                    &metrics,
                    "lonewolf_s2s_bidi_stanzas_received_total{kind=\"message\"} 1",
                );
                assert!(!metrics.contains("lonewolf_s2s_bidi_stanzas_sent_total"));
                f.cleanup(queue);
            }
            let metrics = f.metrics()?;
            sample(
                &metrics,
                "lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 1",
            );
            sample(
                &metrics,
                "lonewolf_s2s_stanzas_received_total{kind=\"message\"} 1",
            );
            f.finish().await?;
        }
        Ok(())
    })
}

#[derive(Clone, Default)]
struct ControlledAllocator(Arc<AtomicBool>);

// Successful allocations keep the global allocator's ownership and layout.
unsafe impl ChunkAllocator for ControlledAllocator {
    fn allocate(&self, layout: std::alloc::Layout) -> Result<Chunk, AllocationError> {
        if self.0.load(Ordering::Relaxed) {
            Err(AllocationError::Exhausted)
        } else {
            GlobalChunkAllocator.allocate(layout)
        }
    }
    unsafe fn deallocate(&self, chunk: Chunk) {
        unsafe {
            GlobalChunkAllocator.deallocate(chunk);
        }
    }
}

#[test]
fn transport_failure_during_discard_flush_preserves_terminal_accounting() -> TestResult {
    test(async {
        let allocator = ControlledAllocator::default();
        let f = Fixture::new(allocator.clone())?;
        let mut queue = f.queue(2).await?;
        let (input, mut reader) = f.reader().await?;
        let output = Output::default();
        output.pause_write();
        output.0.borrow_mut().paused_flush = true;
        let mut writer = S2sWriter::new(output.clone());
        let p = peer();
        let v = valid();
        let end = {
            let mut running = pin!(run_outbound(
                &f.remote.inner,
                &mut queue,
                &mut reader,
                &mut writer,
                parameters(&p, &f.context, &v),
                dispatch
            ));
            assert!(poll!(running.as_mut()).is_pending());
            assert!(output.0.borrow().blocked_write);
            allocator.0.store(true, Ordering::Relaxed);
            output.resume_write();
            assert!(poll!(running.as_mut()).is_pending());
            sample(
                &f.metrics()?,
                "lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 1",
            );
            assert!(poll!(running.as_mut()).is_pending());
            assert!(output.0.borrow().blocked_flush);
            input.fail()?;
            running.await
        };
        assert!(end.abort);
        assert!(matches!(end.reason, StreamClose::TransportError));
        let metrics = f.metrics()?;
        sample(
            &metrics,
            "lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 1",
        );
        sample(
            &metrics,
            "lonewolf_s2s_dropped_stanzas_total{reason=\"internal_error\"} 1",
        );
        assert!(!metrics.contains("reason=\"connection_lost\""));
        assert!(queue.current.is_none());
        f.cleanup(queue);
        f.finish().await
    })
}

#[test]
fn expired_validity_prevents_ready_traffic() -> TestResult {
    test(async {
        let f = Fixture::new(GlobalChunkAllocator)?;
        let mut queue = f.queue(1).await?;
        let (input, mut reader) = f.reader().await?;
        input.unbounded_send(INPUT.as_bytes().to_vec())?;
        let output = Output::default();
        let mut writer = S2sWriter::new(output.clone());
        let p = peer();
        let v = LinkValidity::fixed(SystemTime::now() - Duration::from_secs(1));
        let received = Cell::new(0);
        let end = run_outbound(
            &f.remote.inner,
            &mut queue,
            &mut reader,
            &mut writer,
            parameters(&p, &f.context, &v),
            async |_, _, _| {
                received.set(received.get() + 1);
                Ok(())
            },
        )
        .await;
        assert!(matches!(end.reason, StreamClose::CertificateExpired));
        assert!(!end.abort);
        assert_eq!(received.get(), 0);
        assert!(output.0.borrow().bytes.is_empty());
        assert!(queue.current.is_none());
        assert_eq!(queue.receiver.len(), 1);
        queue.current = Some(queue.receiver.try_recv()?);
        assert!(queue.current.as_ref().ok_or("head")?.reservation.is_some());
        assert!(!f.metrics()?.contains("lonewolf_s2s_stanzas_"));
        f.cleanup(queue);
        f.finish().await
    })
}

#[test]
fn ready_shutdown_precedes_expiry_and_ready_traffic() -> TestResult {
    test(async {
        let f = Fixture::new(GlobalChunkAllocator)?;
        let mut queue = f.queue(1).await?;
        let (input, mut reader) = f.reader().await?;
        input.unbounded_send(INPUT.as_bytes().to_vec())?;
        let output = Output::default();
        let mut writer = S2sWriter::new(output.clone());
        let p = peer();
        let v = LinkValidity::fixed(SystemTime::now() - Duration::from_secs(1));
        let received = Cell::new(0);
        f.remote.stop();
        let end = run_outbound(
            &f.remote.inner,
            &mut queue,
            &mut reader,
            &mut writer,
            parameters(&p, &f.context, &v),
            async |_, _, _| {
                received.set(received.get() + 1);
                Ok(())
            },
        )
        .await;
        assert!(matches!(end.reason, StreamClose::Shutdown));
        assert!(!end.abort);
        assert_eq!(received.get(), 0);
        assert!(output.0.borrow().bytes.is_empty());
        assert!(queue.current.is_none());
        assert_eq!(queue.receiver.len(), 1);
        queue.current = Some(queue.receiver.try_recv()?);
        assert!(queue.current.as_ref().ok_or("head")?.reservation.is_some());
        assert!(!f.metrics()?.contains("lonewolf_s2s_stanzas_"));
        f.cleanup(queue);
        f.finish().await
    })
}

#[test]
fn ready_batches_cooperate_with_shutdown_and_invalidation() -> TestResult {
    test(async {
        for invalidate in [false, true] {
            let f = Fixture::new(GlobalChunkAllocator)?;
            let mut queue = f.queue(3).await?;
            let counters = Arc::clone(&queue.counters);
            let (input, mut reader) = f.reader().await?;
            input.unbounded_send(INPUT.repeat(3).into_bytes())?;
            let output = Output::default();
            let mut writer = S2sWriter::new(output.clone());
            let p = peer();
            let (v, monitor) = expire_later();
            let received = Cell::new(0);
            let end = {
                let mut running = pin!(run_outbound(
                    &f.remote.inner,
                    &mut queue,
                    &mut reader,
                    &mut writer,
                    parameters(&p, &f.context, &v),
                    async |_, _, _| {
                        received.set(received.get() + 1);
                        Ok(())
                    }
                ));
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(received.get(), 1);
                assert_eq!(counters.count.load(Ordering::Relaxed), 2);
                sample(
                    &f.metrics()?,
                    "lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 1",
                );
                if invalidate {
                    v.record_invalidation(StreamClose::CertificateExpired);
                } else {
                    f.remote.stop();
                }
                drop(monitor);
                running.await
            };
            if invalidate {
                assert!(matches!(end.reason, StreamClose::CertificateExpired));
            } else {
                assert!(matches!(end.reason, StreamClose::Shutdown));
            }
            assert!(!end.abort);
            assert_eq!(received.get(), 1);
            assert_eq!(queue.receiver.len(), 2);
            assert!(queue.current.is_none());
            assert_eq!(counters.count.load(Ordering::Relaxed), 2);
            sample(
                &f.metrics()?,
                "lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 1",
            );
            sample(
                &f.metrics()?,
                "lonewolf_s2s_stanzas_received_total{kind=\"message\"} 1",
            );
            writer.flush().await.map_err(|error| format!("{error:?}"))?;
            assert_eq!(output.text()?.matches("<message").count(), 1);
            f.cleanup(queue);
            f.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn physical_whitespace_and_partial_xml_extend_duplex_idle_until_silence() -> TestResult {
    use crate::s2s::stream::traffic::{CountingIo, test_support::Fragments};
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    test(async {
        for outbound in [false, true] {
            let f = Fixture::new(GlobalChunkAllocator)?;
            let mut queue = f.queue(0).await?;
            let input = Fragments::default();
            input.push(HEADER.as_bytes());
            let counted = CountingIo::new(
                input.clone(),
                Arc::clone(&f.remote.inner.metrics),
                Direction::Outbound,
            );
            let activity = counted.activity();
            let mut reader = S2sReader::new(
                tokio::io::BufReader::new(counted.compat()),
                &S2sReaderLimits {
                    max_stanza_bytes: f.remote.inner.limits.max_stanza_bytes,
                    stanzas: f
                        .remote
                        .inner
                        .limits
                        .incoming_stanzas_per_connection
                        .clone(),
                    xml: f.remote.inner.limits.incoming_xml_per_connection.clone(),
                },
                GlobalChunkAllocator,
                None,
            )
            .with_activity(activity.clone());
            assert!(matches!(
                reader.next_event().await,
                Ok(Some(StreamEvent::StreamStart { .. }))
            ));
            let clock = Clock::new();
            let p = peer();
            let v = valid();
            let mut writer = S2sWriter::new(Output::default());
            let received = Cell::new(0);
            let end = {
                let mut parameters = parameters(&p, &f.context, &v);
                parameters.idle_timeout = Duration::from_millis(200);
                let mut running = pin!(run(
                    Session {
                        inner: &f.remote.inner,
                        source: QueueSource::Owned(&mut queue),
                        outbound
                    },
                    &mut reader,
                    &mut writer,
                    parameters,
                    f.remote.inner.stopped.clone(),
                    async |_, _, _| {
                        received.set(received.get() + 1);
                        Ok(())
                    },
                    &clock
                ));
                assert!(poll!(running.as_mut()).is_pending());
                assert!(poll!(running.as_mut()).is_pending());
                for fragment in [b" \n".as_slice(), b"<message", b" from='"] {
                    clock.advance(Duration::from_millis(100));
                    let before = input.polls();
                    input.push(fragment);
                    assert!(poll!(running.as_mut()).is_pending());
                    assert!(input.polls() > before);
                    activity.record(clock.now());
                }
                assert_eq!(received.get(), 0);
                clock.advance(Duration::from_millis(199));
                assert!(poll!(running.as_mut()).is_pending());
                clock.advance(Duration::from_millis(1));
                running.await
            };
            assert!(matches!(end.reason, StreamClose::Idle));
            assert!(!end.abort);
            f.cleanup(queue);
            f.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn incomplete_ready_reads_cooperate_before_shutdown_or_invalidation() -> TestResult {
    use crate::s2s::stream::traffic::{CountingIo, test_support::Fragments};
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    test(async {
        for invalidate in [false, true] {
            let f = Fixture::new(GlobalChunkAllocator)?;
            let mut queue = f.queue(0).await?;
            let input = Fragments::default();
            input.push(HEADER.as_bytes());
            let counted = CountingIo::new(
                input.clone(),
                Arc::clone(&f.remote.inner.metrics),
                Direction::Outbound,
            );
            let activity = counted.activity();
            let mut reader = S2sReader::new(
                tokio::io::BufReader::new(counted.compat()),
                &S2sReaderLimits {
                    max_stanza_bytes: f.remote.inner.limits.max_stanza_bytes,
                    stanzas: f
                        .remote
                        .inner
                        .limits
                        .incoming_stanzas_per_connection
                        .clone(),
                    xml: f.remote.inner.limits.incoming_xml_per_connection.clone(),
                },
                GlobalChunkAllocator,
                None,
            )
            .with_activity(activity);
            assert!(matches!(
                reader.next_event().await,
                Ok(Some(StreamEvent::StreamStart { .. }))
            ));
            input.push(b"<message");
            input.push(b" from='u@remote.test/r' to='v@localhost'/>");
            let p = peer();
            let (v, monitor) = expire_later();
            let mut monitor = Some(monitor);
            let mut writer = S2sWriter::new(Output::default());
            let received = Cell::new(0);
            let (stop, stopped) = oneshot::channel();
            let end = {
                let mut running = pin!(run(
                    Session {
                        inner: &f.remote.inner,
                        source: QueueSource::Owned(&mut queue),
                        outbound: true
                    },
                    &mut reader,
                    &mut writer,
                    parameters(&p, &f.context, &v),
                    async {
                        let _ = stopped.await;
                    },
                    async |_, _, _| {
                        received.set(received.get() + 1);
                        Ok(())
                    },
                    &SystemIdleClock
                ));
                assert!(poll!(running.as_mut()).is_pending());
                let before = input.polls();
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(input.polls(), before + 1);
                assert_eq!(received.get(), 0);
                if invalidate {
                    v.record_invalidation(StreamClose::CertificateExpired);
                    drop(monitor.take());
                } else {
                    stop.send(()).map_err(|_| "shutdown")?;
                }
                let end = running.await;
                assert_eq!(input.polls(), before + 1);
                end
            };
            assert!(matches!(end.reason, StreamClose::CertificateExpired) == invalidate);
            assert!(matches!(end.reason, StreamClose::Shutdown) != invalidate);
            assert_eq!(received.get(), 0);
            f.cleanup(queue);
            f.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn peer_size_rejection_transfers_ownership_before_prior_flush_can_be_aborted() -> TestResult {
    use crate::s2s::stream::limits::StreamLimits;
    test(async {
        for shutdown in [false, true] {
            let f = Fixture::new(GlobalChunkAllocator)?;
            let mut queue = f.queue(0).await?;
            let first = stanza_in("<message from='v@localhost' to='u@remote.test/r' id='first'><body>ok</body></message>", GlobalChunkAllocator).await?;
            assert!(
                f.remote
                    .admit("localhost", "remote.test", first)
                    .map_err(|error| format!("{error:?}"))?
                    .is_none()
            );
            queue.current = Some(queue.receiver.recv().await?);
            let rejected = stanza_in(&format!("<message type='error' from='v@localhost' to='u@remote.test/r' id='second'><body>{}</body><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>", "x".repeat(1024)), GlobalChunkAllocator).await?;
            assert!(
                f.remote
                    .admit("localhost", "remote.test", rejected)
                    .map_err(|error| format!("{error:?}"))?
                    .is_none()
            );
            let (input, mut reader) = f.reader().await?;
            let output = Output::default();
            output.0.borrow_mut().paused_flush = true;
            let mut writer = S2sWriter::new(output.clone());
            writer.update_peer_limits(Some(StreamLimits {
                max_bytes: Some(300),
                idle_seconds: None,
            }));
            let p = peer();
            let v = valid();
            let end = {
                let mut running = pin!(run_outbound(
                    &f.remote.inner,
                    &mut queue,
                    &mut reader,
                    &mut writer,
                    parameters(&p, &f.context, &v),
                    dispatch
                ));
                assert!(poll!(running.as_mut()).is_pending());
                assert!(!output.0.borrow().blocked_flush);
                assert!(poll!(running.as_mut()).is_pending());
                assert!(output.0.borrow().blocked_flush);
                sample(&f.metrics()?, "lonewolf_s2s_peer_size_rejections_total 1");
                sample(&f.metrics()?, "lonewolf_s2s_outbound_queued_stanzas 0");
                if shutdown {
                    f.remote.stop();
                } else {
                    input.fail()?;
                }
                running.await
            };
            assert!(matches!(end.reason, StreamClose::Shutdown) == shutdown);
            assert!(matches!(end.reason, StreamClose::TransportError) != shutdown);
            assert!(end.abort);
            assert!(queue.current.is_none());
            assert_eq!(queue.counters.count.load(Ordering::Relaxed), 0);
            assert_eq!(queue.counters.bytes.load(Ordering::Relaxed), 0);
            f.cleanup(queue);
            let remote = f.remote.clone();
            f.finish().await?;
            let mut registry = prometheus_client::registry::Registry::default();
            remote
                .inner
                .metrics
                .register(registry.sub_registry_with_prefix("lonewolf"));
            let mut metrics = String::new();
            prometheus_client::encoding::text::encode(&mut metrics, &registry)?;
            sample(&metrics, "lonewolf_s2s_peer_size_rejections_total 1");
            sample(
                &metrics,
                "lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 1",
            );
            sample(
                &metrics,
                "lonewolf_s2s_dropped_stanzas_total{reason=\"not_bounceable\"} 1",
            );
            assert!(!metrics.contains("reason=\"connection_lost\""));
            assert!(!output.text()?.contains("second"));
            assert!(output.text()?.contains("first"));
        }
        Ok(())
    })
}
