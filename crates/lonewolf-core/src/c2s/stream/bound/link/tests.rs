// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command as Process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

use compio::runtime::Runtime;
use futures_channel::oneshot;
use futures_util::future::join;
use futures_util::{FutureExt, poll};
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_util::pool::PooledChunkAllocator;
use lonewolf_xmpp::parser::{ParserConfig, XmppParser};
use lonewolf_xmpp::stanza::PresenceType;

use super::super::tests::{ControlledWriter, routed_presence};
use super::*;
use crate::c2s::stream::stanza_rate::StanzaLimiter;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn presence() -> TestResult<Outgoing<GlobalChunkAllocator>> {
    Ok(Outgoing::Routed(routed_presence(
        "alice@localhost/desk",
        Some("bob@localhost/phone"),
        PresenceType::Available,
    )?))
}

async fn reader(input: &'static [u8]) -> TestResult<Reader<GlobalChunkAllocator, &'static [u8]>> {
    let mut reader = Reader::new(
        XmppParser::new(
            input,
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(10_000).ok_or("invalid stanza size")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        ),
        StanzaLimiter::new(
            NonZeroUsize::MIN,
            NonZeroUsize::new(8).ok_or("invalid burst")?,
        ),
    );
    assert!(matches!(
        reader.next_event().await,
        Ok(Some(StreamEvent::StreamStart { .. }))
    ));
    Ok(reader)
}

#[test]
fn transport_forwards_the_next_stanza_only_after_the_session_accepts() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut reader = reader(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><message/><message/></stream:stream>").await?;
        let (link, incoming, transport) = link();
        let mut reading = pin!(transport.read(&mut reader, None));
        assert!(poll!(reading.as_mut()).is_pending());
        assert!(matches!(incoming.recv().await, Ok(Incoming::Stanza(_))));
        assert!(poll!(reading.as_mut()).is_pending());
        assert!(poll!(pin!(incoming.recv())).is_pending());
        link.accept();
        assert!(poll!(reading.as_mut()).is_pending());
        assert!(matches!(incoming.recv().await, Ok(Incoming::Stanza(_))));
        assert!(poll!(reading.as_mut()).is_pending());
        assert!(poll!(pin!(incoming.recv())).is_pending());
        link.accept();
        assert!(poll!(reading.as_mut()).is_ready());
        assert!(matches!(incoming.recv().await, Ok(Incoming::Ended(CloseOutcome::StreamEnd))));
        Ok(())
    })
}

#[test]
fn transport_forwards_the_next_rejected_stanza_only_after_the_session_accepts() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut reader = reader(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><iq type='unknown'/><iq type='unknown'/></stream:stream>").await?;
        let (link, incoming, transport) = link();
        let mut reading = pin!(transport.read(&mut reader, None));
        assert!(poll!(reading.as_mut()).is_pending());
        assert!(matches!(incoming.recv().await, Ok(Incoming::Rejected(_))));
        assert!(poll!(reading.as_mut()).is_pending());
        assert!(poll!(pin!(incoming.recv())).is_pending());
        link.accept();
        assert!(poll!(reading.as_mut()).is_pending());
        assert!(matches!(incoming.recv().await, Ok(Incoming::Rejected(_))));
        assert!(poll!(reading.as_mut()).is_pending());
        assert!(poll!(pin!(incoming.recv())).is_pending());
        link.accept();
        assert!(poll!(reading.as_mut()).is_ready());
        assert!(matches!(incoming.recv().await, Ok(Incoming::Ended(CloseOutcome::StreamEnd))));
        Ok(())
    })
}

#[test]
fn transport_stops_reading_when_the_session_stops() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut reader = reader(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><message/></stream:stream>").await?;
        let (link, incoming, transport) = link();
        link.stop();
        transport.read(&mut reader, None).await;
        assert!(incoming.is_empty());
        Ok(())
    })
}

#[test]
fn write_returns_the_close_outcome_and_drops_writes_after_stop() -> TestResult {
    Runtime::new()?.block_on(async {
        for failed in [false, true] {
            let (mut link, _incoming, transport) = link();
            let mut controlled = ControlledWriter::default();
            assert_eq!(link.write(presence()?).await, Ok(()));
            link.commands
                .send(Command::Flush {
                    through: OutputSequence::new(1),
                    request: 1,
                })
                .await?;
            link.stop();
            if failed {
                transport.fail(CloseOutcome::TransportError);
            }
            link.close(CloseOutcome::StreamEnd).await;
            drop(link);
            assert_eq!(
                transport.write(&mut controlled, None).await,
                CloseOutcome::StreamEnd
            );
            assert!(controlled.written.is_empty());
            assert!(controlled.flushed.is_empty());
            let progress = transport.state.progress.lock();
            assert_eq!(progress.flushed, OutputSequence::default());
            assert_eq!(progress.completed_flush, 0);
        }
        Ok(())
    })
}

#[test]
fn dropping_the_link_writer_stops_the_transport() -> TestResult {
    Runtime::new()?.block_on(async {
        let (mut link, _incoming, transport) = link();
        let mut controlled = ControlledWriter::default();
        assert_eq!(link.write(presence()?).await, Ok(()));
        link.commands
            .send(Command::Flush {
                through: OutputSequence::new(1),
                request: 1,
            })
            .await?;
        let mut stopped = pin!(transport.stopped());
        assert!(poll!(stopped.as_mut()).is_pending());
        drop(link);
        assert!(poll!(stopped.as_mut()).is_ready());
        assert_eq!(
            transport.write(&mut controlled, None).await,
            CloseOutcome::InternalError
        );
        assert!(controlled.written.is_empty());
        assert!(controlled.flushed.is_empty());
        let progress = transport.state.progress.lock();
        assert_eq!(progress.flushed, OutputSequence::default());
        assert_eq!(progress.completed_flush, 0);
        Ok(())
    })
}

#[test]
fn link_failure_wakes_the_session_watch() {
    let (link, _incoming, transport) = link::<GlobalChunkAllocator>();
    let watch = link.watch();
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    let mut context = Context::from_waker(&waker);
    let mut failed = pin!(watch.failed());
    assert!(failed.as_mut().poll(&mut context).is_pending());
    transport.fail(CloseOutcome::CertificateInvalid);
    assert_eq!(count.0.load(Ordering::Relaxed), 1);
    assert_eq!(
        failed.as_mut().poll(&mut context),
        Poll::Ready(CloseOutcome::CertificateInvalid)
    );
}

#[test]
fn flush_returns_after_the_transport_flushes_through_the_sequence() -> TestResult {
    Runtime::new()?.block_on(async {
        let (mut link, _incoming, transport) = link();
        let mut controlled = ControlledWriter::default();
        let session = async move {
            assert_eq!(link.write(presence()?).await, Ok(()));
            let flushed = link.flush(OutputSequence::new(1)).await;
            link.close(CloseOutcome::StreamEnd).await;
            drop(link);
            Ok::<_, Box<dyn Error>>(flushed)
        };
        let (flushed, outcome) = join(session, transport.write(&mut controlled, None)).await;
        assert_eq!(flushed?, Ok(()));
        assert_eq!(outcome, CloseOutcome::StreamEnd);
        assert_eq!(controlled.written.len(), 1);
        assert_eq!(controlled.flushed, [OutputSequence::new(1)]);
        Ok(())
    })
}

#[test]
fn write_failure_fails_the_next_flush_with_the_writer_outcome() -> TestResult {
    Runtime::new()?.block_on(async {
        let (mut link, _incoming, transport) = link();
        let mut controlled = ControlledWriter::default();
        controlled.fail_write = true;
        let session = async move {
            assert_eq!(link.write(presence()?).await, Ok(()));
            assert_eq!(
                link.flush(OutputSequence::new(1)).await,
                Err(CloseOutcome::TransportError)
            );
            let queued = link.commands.len();
            assert_eq!(
                link.write(presence()?).await,
                Err(CloseOutcome::TransportError)
            );
            assert_eq!(link.commands.len(), queued);
            link.close(CloseOutcome::StreamEnd).await;
            Ok::<_, Box<dyn Error>>(())
        };
        let (result, outcome) = join(session, transport.write(&mut controlled, None)).await;
        result?;
        assert_eq!(outcome, CloseOutcome::StreamEnd);
        assert!(controlled.written.is_empty());
        assert!(controlled.flushed.is_empty());
        Ok(())
    })
}

#[test]
fn stopped_link_drops_queued_writes_and_flushes() -> TestResult {
    Runtime::new()?.block_on(async {
        let (mut link, _incoming, transport) = link();
        let mut controlled = ControlledWriter::default();
        assert_eq!(link.write(presence()?).await, Ok(()));
        assert_eq!(link.write(presence()?).await, Ok(()));
        link.commands
            .send(Command::Flush {
                through: OutputSequence::new(2),
                request: 1,
            })
            .await?;
        link.stop();
        link.close(CloseOutcome::StreamEnd).await;
        drop(link);
        assert_eq!(
            transport.write(&mut controlled, None).await,
            CloseOutcome::StreamEnd
        );
        assert!(controlled.written.is_empty());
        assert!(controlled.flushed.is_empty());
        Ok(())
    })
}

#[test]
fn link_items_are_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Command<Arc<PooledChunkAllocator>>>();
    assert_send::<Incoming<Arc<PooledChunkAllocator>>>();
    assert_send::<LinkWatch>();
    assert_send::<LinkWriter<Arc<PooledChunkAllocator>>>();
    assert_send::<LinkTransport<Arc<PooledChunkAllocator>>>();
}

struct GatedWriter {
    writer: ControlledWriter,
    entered: async_channel::Sender<OutputSequence>,
    releases: async_channel::Receiver<Result<(), CloseOutcome>>,
}

impl GatedWriter {
    fn new() -> (
        Self,
        async_channel::Receiver<OutputSequence>,
        async_channel::Sender<Result<(), CloseOutcome>>,
    ) {
        let (notice, entered) = async_channel::bounded(1);
        let (release, blocked) = async_channel::bounded(1);
        (
            Self {
                writer: ControlledWriter::default(),
                entered: notice,
                releases: blocked,
            },
            entered,
            release,
        )
    }
}

impl OutboxWriter<GlobalChunkAllocator> for GatedWriter {
    async fn write(&mut self, output: Outgoing<GlobalChunkAllocator>) -> Result<(), CloseOutcome> {
        self.writer.write(output).await
    }

    async fn flush(&mut self, through: OutputSequence) -> Result<(), CloseOutcome> {
        self.entered
            .send(through)
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        self.releases
            .recv()
            .await
            .map_err(|_| CloseOutcome::InternalError)??;
        <ControlledWriter as OutboxWriter<GlobalChunkAllocator>>::flush(&mut self.writer, through)
            .await
    }
}

#[derive(Clone, Copy)]
enum FlushOutcome {
    Complete,
    Fail,
    Stop,
}

async fn verify_flush_completion(outcome: FlushOutcome) -> TestResult {
    for through in [OutputSequence::default(), OutputSequence::new(1)] {
        let (mut link, _incoming, transport) = link();
        let state = Arc::clone(&link.state);
        let (mut writer, entered, release) = GatedWriter::new();
        let mut completed = 0;
        {
            let mut running = pin!(transport.write(&mut writer, None));
            if through != OutputSequence::default() {
                assert_eq!(link.write(presence()?).await, Ok(()));
                let mut first = pin!(link.flush(through));
                assert!(poll!(first.as_mut()).is_pending());
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(entered.try_recv()?, through);
                release.try_send(Ok(()))?;
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(poll!(first.as_mut()), Poll::Ready(Ok(())));
                completed = 1;
            }
            {
                let mut current = pin!(link.flush(through));
                assert!(poll!(current.as_mut()).is_pending());
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(entered.try_recv()?, through);
                assert!(poll!(current.as_mut()).is_pending());
                assert_eq!(state.progress.lock().completed_flush, completed);
                match outcome {
                    FlushOutcome::Complete => {
                        release.try_send(Ok(()))?;
                        assert!(poll!(running.as_mut()).is_pending());
                        assert_eq!(poll!(current.as_mut()), Poll::Ready(Ok(())));
                        completed += 1;
                    }
                    FlushOutcome::Fail => {
                        release.try_send(Err(CloseOutcome::TransportError))?;
                        assert!(poll!(running.as_mut()).is_pending());
                        assert_eq!(
                            poll!(current.as_mut()),
                            Poll::Ready(Err(CloseOutcome::TransportError))
                        );
                    }
                    FlushOutcome::Stop => {}
                }
            }
            if matches!(outcome, FlushOutcome::Stop) {
                link.stop();
                assert!(poll!(running.as_mut()).is_pending());
            }
            {
                let progress = state.progress.lock();
                assert_eq!(progress.completed_flush, completed);
                assert_eq!(progress.flushed, through);
                assert_eq!(
                    progress.failure,
                    matches!(outcome, FlushOutcome::Fail).then_some(CloseOutcome::TransportError)
                );
            }
            link.close(CloseOutcome::StreamEnd).await;
            drop(link);
            assert!(poll!(running.as_mut()).is_ready());
        }
        assert_eq!(writer.writer.flushed.len(), completed as usize);
    }
    Ok(())
}

#[test]
fn zero_and_repeated_sequences_wait_for_their_own_flush() -> TestResult {
    Runtime::new()?.block_on(verify_flush_completion(FlushOutcome::Complete))
}

#[test]
fn zero_and_repeated_sequence_flush_failures_do_not_publish_completion() -> TestResult {
    Runtime::new()?.block_on(verify_flush_completion(FlushOutcome::Fail))
}

#[test]
fn stopping_zero_and_repeated_sequence_flushes_does_not_publish_completion() -> TestResult {
    Runtime::new()?.block_on(verify_flush_completion(FlushOutcome::Stop))
}

#[test]
fn a_cancelled_waiters_late_flush_does_not_complete_the_next_request() -> TestResult {
    Runtime::new()?.block_on(async {
        let (mut link, _incoming, transport) = link::<GlobalChunkAllocator>();
        let state = Arc::clone(&link.state);
        let (mut writer, entered, release) = GatedWriter::new();
        {
            let mut first = pin!(link.flush(OutputSequence::default()));
            assert!(poll!(first.as_mut()).is_pending());
        }
        {
            let mut running = pin!(transport.write(&mut writer, None));
            {
                let mut second = pin!(link.flush(OutputSequence::default()));
                assert!(poll!(second.as_mut()).is_pending());
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(entered.try_recv()?, OutputSequence::default());
                release.try_send(Ok(()))?;
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(entered.try_recv()?, OutputSequence::default());
                assert_eq!(state.progress.lock().completed_flush, 1);
                assert!(poll!(second.as_mut()).is_pending());
                release.try_send(Ok(()))?;
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(poll!(second.as_mut()), Poll::Ready(Ok(())));
            }
            assert_eq!(state.progress.lock().completed_flush, 2);
            link.close(CloseOutcome::StreamEnd).await;
            drop(link);
            assert!(poll!(running.as_mut()).is_ready());
        }
        assert_eq!(writer.writer.flushed, [OutputSequence::default(); 2]);
        Ok(())
    })
}

#[test]
fn exhausted_flush_requests_fail_without_enqueuing_a_command() -> TestResult {
    Runtime::new()?.block_on(async {
        let (mut link, _incoming, transport) = link::<GlobalChunkAllocator>();
        link.requested_flush = u64::MAX;
        assert_eq!(
            link.flush(OutputSequence::default()).await,
            Err(CloseOutcome::InternalError)
        );
        assert!(transport.commands.is_empty());
        assert_eq!(link.requested_flush, u64::MAX);
        assert_eq!(link.state.progress.lock().completed_flush, 0);
        Ok(())
    })
}

#[test]
fn stopping_cancels_a_pending_write_and_drops_queued_output() -> TestResult {
    Runtime::new()?.block_on(async {
        let (mut link, _incoming, transport) = link();
        let commands = transport.commands.clone();
        let state = Arc::clone(&link.state);
        let (notice, entered) = oneshot::channel();
        let (release, blocked) = oneshot::channel();
        let mut controlled = ControlledWriter::default();
        controlled.partial_entered = Some(notice);
        controlled.partial_release = Some(blocked);
        assert_eq!(link.write(presence()?).await, Ok(()));
        assert_eq!(link.write(presence()?).await, Ok(()));
        link.commands
            .send(Command::Flush {
                through: OutputSequence::new(2),
                request: 1,
            })
            .await?;
        {
            let mut running = pin!(transport.write(&mut controlled, None));
            assert!(poll!(running.as_mut()).is_pending());
            entered.await?;
            link.stop();
            assert!(poll!(running.as_mut()).is_pending());
            assert!(release.send(()).is_err());
            assert!(commands.is_empty());
            link.close(CloseOutcome::StreamEnd).await;
            drop(link);
            assert!(poll!(running.as_mut()).is_ready());
        }
        assert!(!controlled.bytes.is_empty());
        assert!(controlled.written.is_empty());
        assert!(controlled.flushed.is_empty());
        let progress = state.progress.lock();
        assert_eq!(progress.flushed, OutputSequence::default());
        assert_eq!(progress.completed_flush, 0);
        assert_eq!(progress.failure, None);
        Ok(())
    })
}

#[test]
fn stopping_cancels_a_pending_flush_without_advancing_the_watermark() -> TestResult {
    Runtime::new()?.block_on(async {
        let (mut link, _incoming, transport) = link();
        let commands = transport.commands.clone();
        let state = Arc::clone(&link.state);
        let (notice, entered) = oneshot::channel();
        let (release, blocked) = oneshot::channel();
        let mut controlled = ControlledWriter::default();
        controlled.flush_entered = Some(notice);
        controlled.flush_release = Some(blocked);
        assert_eq!(link.write(presence()?).await, Ok(()));
        link.commands
            .send(Command::Flush {
                through: OutputSequence::new(1),
                request: 1,
            })
            .await?;
        assert_eq!(link.write(presence()?).await, Ok(()));
        link.commands
            .send(Command::Flush {
                through: OutputSequence::new(2),
                request: 2,
            })
            .await?;
        {
            let mut running = pin!(transport.write(&mut controlled, None));
            assert!(poll!(running.as_mut()).is_pending());
            entered.await?;
            link.stop();
            assert!(poll!(running.as_mut()).is_pending());
            assert!(release.send(()).is_err());
            assert!(commands.is_empty());
            link.close(CloseOutcome::StreamEnd).await;
            drop(link);
            assert!(poll!(running.as_mut()).is_ready());
        }
        assert_eq!(controlled.written.len(), 1);
        assert!(controlled.flushed.is_empty());
        let progress = state.progress.lock();
        assert_eq!(progress.flushed, OutputSequence::default());
        assert_eq!(progress.completed_flush, 0);
        assert_eq!(progress.failure, None);
        Ok(())
    })
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn dropping_the_writer_while_unwinding_does_not_wake_the_transport() -> TestResult {
    let (link, incoming, transport) = link::<GlobalChunkAllocator>();
    let state = Arc::downgrade(&link.state);
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    let mut context = Context::from_waker(&waker);
    let mut controlled = ControlledWriter::default();
    {
        transport
            .incoming
            .try_send(Incoming::Ended(CloseOutcome::StreamEnd))?;
        let mut sending = pin!(
            transport
                .incoming
                .send(Incoming::Ended(CloseOutcome::StreamEnd))
        );
        assert!(sending.as_mut().poll(&mut context).is_pending());
        let mut writing = pin!(transport.write(&mut controlled, None));
        assert!(writing.as_mut().poll(&mut context).is_pending());
        let mut stopped = pin!(transport.stopped());
        assert!(stopped.as_mut().poll(&mut context).is_pending());
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _link = link;
            let _incoming = incoming;
            panic!("session panic");
        }));
        assert!(result.is_err());
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
    }
    drop(transport);
    assert!(state.upgrade().is_none());
    Ok(())
}

fn run_panic_process(test: &str) -> TestResult {
    let output = Process::new(std::env::current_exe()?)
        .args([test, "--exact", "--ignored", "--nocapture"])
        .env("LONEWOLF_LINK_PANIC_TEST", "1")
        .output()?;
    assert!(
        output.status.success(),
        "status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn a_hosted_session_panic_cleans_up_without_aborting() -> TestResult {
    run_panic_process("c2s::stream::bound::link::tests::hosted_session_panic_process")
}

#[test]
fn a_hosted_transport_panic_cleans_up_a_blocked_sender_without_aborting() -> TestResult {
    run_panic_process("c2s::stream::bound::link::tests::hosted_transport_panic_process")
}

#[test]
fn a_hosted_transport_panic_cleans_up_a_waiting_session_without_aborting() -> TestResult {
    run_panic_process(
        "c2s::stream::bound::link::tests::hosted_transport_panic_with_waiting_session_process",
    )
}

#[test]
#[ignore = "subprocess entry point for the link panic fixture"]
fn hosted_session_panic_process() -> TestResult {
    if std::env::var_os("LONEWOLF_LINK_PANIC_TEST").is_none() {
        return Ok(());
    }
    Runtime::new()?.block_on(async {
        compio::runtime::spawn(async {
            let (link, _incoming, transport) = link::<GlobalChunkAllocator>();
            let state = Arc::downgrade(&link.state);
            let (release, entered) = oneshot::channel();
            let mut controlled = ControlledWriter::default();
            {
                let serve = async move {
                    let _link = link;
                    let _ = entered.await;
                    panic!("hosted session panic");
                };
                let joined = AssertUnwindSafe(join(serve, transport.write(&mut controlled, None)))
                    .catch_unwind();
                let mut joined = pin!(joined);
                assert!(poll!(joined.as_mut()).is_pending());
                assert!(release.send(()).is_ok());
                assert!(joined.await.is_err());
            }
            drop(transport);
            assert!(state.upgrade().is_none());
        })
        .await
        .map_err(|_| "hosted task panicked")?;
        let value = compio::runtime::spawn(async { 42 })
            .await
            .map_err(|_| "recovery task panicked")?;
        assert_eq!(value, 42);
        Ok(())
    })
}

struct PanickingWriter;

impl OutboxWriter<GlobalChunkAllocator> for PanickingWriter {
    async fn write(&mut self, _: Outgoing<GlobalChunkAllocator>) -> Result<(), CloseOutcome> {
        panic!("transport write panic");
    }

    async fn flush(&mut self, _: OutputSequence) -> Result<(), CloseOutcome> {
        panic!("unexpected transport flush");
    }
}

#[test]
#[ignore = "subprocess entry point for the transport panic fixture"]
fn hosted_transport_panic_process() -> TestResult {
    if std::env::var_os("LONEWOLF_LINK_PANIC_TEST").is_none() {
        return Ok(());
    }
    Runtime::new()?.block_on(async {
        let outputs = (0..=COMMAND_CAPACITY)
            .map(|_| presence())
            .collect::<TestResult<Vec<_>>>()?;
        compio::runtime::spawn(async {
            let (mut link, _incoming, transport) = link();
            let state = Arc::downgrade(&link.state);
            let mut writer = PanickingWriter;
            {
                let serve = async move {
                    for output in outputs {
                        assert_eq!(link.write(output).await, Ok(()));
                    }
                };
                let mut serve = pin!(serve);
                assert!(poll!(serve.as_mut()).is_pending());
                assert_eq!(transport.commands.len(), COMMAND_CAPACITY);
                let result = AssertUnwindSafe(join(serve, transport.write(&mut writer, None)))
                    .catch_unwind()
                    .await;
                assert!(result.is_err());
            }
            drop(transport);
            assert!(state.upgrade().is_none());
        })
        .await
        .map_err(|_| "hosted task panicked")?;
        let value = compio::runtime::spawn(async { 42 })
            .await
            .map_err(|_| "recovery task panicked")?;
        assert_eq!(value, 42);
        Ok(())
    })
}

#[test]
#[ignore = "subprocess entry point for the incoming channel panic fixture"]
fn hosted_transport_panic_with_waiting_session_process() -> TestResult {
    if std::env::var_os("LONEWOLF_LINK_PANIC_TEST").is_none() {
        return Ok(());
    }
    Runtime::new()?.block_on(async {
        let output = presence()?;
        compio::runtime::spawn(async {
            let (mut link, incoming, transport) = link();
            let state = Arc::downgrade(&link.state);
            let mut writer = PanickingWriter;
            assert_eq!(link.write(output).await, Ok(()));
            {
                let serve = async move {
                    let _link = link;
                    let _ = incoming.recv().await;
                };
                let mut serve = pin!(serve);
                assert!(poll!(serve.as_mut()).is_pending());
                let result = AssertUnwindSafe(join(serve, transport.write(&mut writer, None)))
                    .catch_unwind()
                    .await;
                assert!(result.is_err());
            }
            drop(transport);
            assert!(state.upgrade().is_none());
        })
        .await
        .map_err(|_| "hosted task panicked")?;
        let value = compio::runtime::spawn(async { 42 })
            .await
            .map_err(|_| "recovery task panicked")?;
        assert_eq!(value, 42);
        Ok(())
    })
}

#[test]
fn renegotiation_aborts_and_wakes_failure_watch_while_output_is_blocked() -> TestResult {
    use crate::c2s::stream::renegotiation::RecordGuard;
    use std::io::Cursor;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdTcpStream};
    use tokio::io::AsyncReadExt as _;
    use tokio_util::compat::FuturesAsyncReadCompatExt as _;
    Runtime::new()?.block_on(async {
        let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let mut peer = StdTcpStream::connect(listener.local_addr()?)?;
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        let (socket, _) = listener.accept().await?;
        let mut guard = RecordGuard::new(futures_util::io::Cursor::new(vec![22]), socket);
        guard.handshake_complete(Some(rustls::ProtocolVersion::TLSv1_2));
        let input = Cursor::new(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>")
            .chain(guard.compat());
        let mut reader = Reader::new(XmppParser::new(
            tokio::io::BufReader::new(input),
            ParserConfig { max_stanza_bytes: NonZeroUsize::new(10_000).ok_or("invalid size")?, arena: ArenaConfig::default() },
            GlobalChunkAllocator,
        ), StanzaLimiter::new(NonZeroUsize::MIN, NonZeroUsize::MIN));
        assert!(matches!(reader.next_event().await, Ok(Some(StreamEvent::StreamStart { .. }))));
        let (mut link, incoming, transport) = link();
        let watch = link.watch();
        let mut failure = pin!(watch.failed());
        assert!(poll!(failure.as_mut()).is_pending());
        let (notice, entered) = oneshot::channel();
        let (release, blocked) = oneshot::channel();
        let mut controlled = ControlledWriter::default();
        controlled.partial_entered = Some(notice);
        controlled.partial_release = Some(blocked);
        assert_eq!(link.write(presence()?).await, Ok(()));
        {
            let mut writing = pin!(transport.write(&mut controlled, None));
            assert!(poll!(writing.as_mut()).is_pending());
            entered.await?;
            transport.read(&mut reader, None).await;
            assert_eq!(poll!(failure.as_mut()), Poll::Ready(CloseOutcome::TlsFailure));
            assert!(incoming.is_empty());
            assert_eq!(std::io::Read::read(&mut peer, &mut [0; 1])?, 0);
            assert_eq!(link.write(presence()?).await, Err(CloseOutcome::TlsFailure));
            link.stop();
            assert!(poll!(writing.as_mut()).is_pending());
            assert!(release.send(()).is_err());
            link.close(CloseOutcome::AccountDeleted).await;
            assert_eq!(writing.await, CloseOutcome::AccountDeleted);
        }
        assert!(!controlled.bytes.is_empty());
        assert!(controlled.written.is_empty());
        assert!(controlled.flushed.is_empty());
        assert_eq!(transport.state.progress.lock().failure, Some(CloseOutcome::TlsFailure));
        Ok(())
    })
}

#[test]
fn pending_input_does_not_bypass_acceptance_after_a_successful_write() -> TestResult {
    use std::cell::Cell;
    use std::io;
    use std::pin::Pin;
    use std::rc::Rc;

    use tokio::io::{AsyncRead, ReadBuf};

    #[derive(Clone, Copy)]
    enum PendingInput {
        Pending,
        Reset,
        Eof,
        Stanza,
    }

    struct ControlledInput {
        bytes: &'static [u8],
        next: Rc<Cell<PendingInput>>,
        polls: Rc<Cell<usize>>,
    }

    impl AsyncRead for ControlledInput {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let bytes = std::task::ready!(self.as_mut().poll_fill_buf(context))?;
            let length = bytes.len().min(output.remaining());
            output.put_slice(&bytes[..length]);
            self.consume(length);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncBufRead for ControlledInput {
        fn poll_fill_buf(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
            let this = self.get_mut();
            this.polls.set(this.polls.get() + 1);
            if !this.bytes.is_empty() {
                return Poll::Ready(Ok(this.bytes));
            }
            match this.next.get() {
                PendingInput::Reset => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
                PendingInput::Eof => Poll::Ready(Ok(&[])),
                PendingInput::Stanza => {
                    this.bytes = b"<message/>";
                    this.next.set(PendingInput::Pending);
                    Poll::Ready(Ok(this.bytes))
                }
                PendingInput::Pending => Poll::Pending,
            }
        }

        fn consume(self: Pin<&mut Self>, length: usize) {
            let this = self.get_mut();
            this.bytes = &this.bytes[length..];
        }
    }

    Runtime::new()?.block_on(async {
        for pending in [PendingInput::Reset, PendingInput::Eof, PendingInput::Stanza] {
            let state = Rc::new(Cell::new(PendingInput::Pending));
            let reads = Rc::new(Cell::new(0));
            let input = ControlledInput {
                bytes: b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><presence/>",
                next: Rc::clone(&state),
                polls: Rc::clone(&reads),
            };
            let mut reader = Reader::new(
                XmppParser::new(
                    input,
                    ParserConfig {
                        max_stanza_bytes: NonZeroUsize::new(10_000).ok_or("stanza size")?,
                        arena: ArenaConfig::default(),
                    },
                    GlobalChunkAllocator,
                ),
                StanzaLimiter::new(
                    NonZeroUsize::MIN,
                    NonZeroUsize::new(8).ok_or("stanza burst")?,
                ),
            );
            assert!(matches!(
                reader.next_event().await,
                Ok(Some(StreamEvent::StreamStart { .. }))
            ));
            let (mut link, incoming, transport) = link();
            let watch = link.watch();
            let mut reading = pin!(transport.read(&mut reader, None));
            assert_eq!(poll!(reading.as_mut()), Poll::Pending);
            assert!(matches!(incoming.recv().await?, Incoming::Stanza(_)));
            let before = reads.get();
            state.set(pending);
            let mut controlled = ControlledWriter::default();
            {
                let mut writing = pin!(transport.write(&mut controlled, None));
                link.write(presence()?).await.map_err(|_| "write")?;
                let mut flushing = pin!(link.flush(OutputSequence::new(1)));
                assert_eq!(poll!(flushing.as_mut()), Poll::Pending);
                assert!(poll!(writing.as_mut()).is_pending());
                assert_eq!(poll!(flushing.as_mut()), Poll::Ready(Ok(())));
            }
            assert_eq!(controlled.flushed, [OutputSequence::new(1)]);
            assert!(poll!(pin!(watch.failed())).is_pending());
            assert_eq!(poll!(reading.as_mut()), Poll::Pending);
            assert!(incoming.is_empty());
            assert_eq!(reads.get(), before);
            link.accept();
            let done = poll!(reading.as_mut());
            match pending {
                PendingInput::Reset => {
                    assert_eq!(done, Poll::Ready(()));
                    assert!(matches!(
                        incoming.recv().await?,
                        Incoming::Ended(CloseOutcome::TransportError)
                    ));
                }
                PendingInput::Eof => {
                    assert_eq!(done, Poll::Ready(()));
                    assert!(matches!(
                        incoming.recv().await?,
                        Incoming::Ended(CloseOutcome::Eof)
                    ));
                }
                PendingInput::Stanza => {
                    assert_eq!(done, Poll::Pending);
                    assert!(matches!(incoming.recv().await?, Incoming::Stanza(_)));
                }
                PendingInput::Pending => unreachable!("a ready input was selected"),
            }
            assert!(reads.get() > before);
        }
        Ok(())
    })
}
