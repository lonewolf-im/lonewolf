// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command as Process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

use compio::runtime::Runtime;
use futures_channel::oneshot;
use futures_util::future::join;
use futures_util::{FutureExt, poll};
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_util::pool::PooledChunkAllocator;
use lonewolf_xmpp::stanza::PresenceType;

use super::super::tests::{ControlledWriter, routed_presence};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn presence() -> TestResult<Outgoing<GlobalChunkAllocator>> {
    Ok(Outgoing::Routed(routed_presence(
        "alice@localhost/desk",
        Some("bob@localhost/phone"),
        PresenceType::Available,
    )?))
}

#[test]
fn flush_returns_after_the_transport_flushes_through_the_sequence() -> TestResult {
    Runtime::new()?.block_on(async {
        let (mut link, transport) = link();
        let mut controlled = ControlledWriter::default();
        let session = async move {
            assert_eq!(link.write(presence()?).await, Ok(()));
            let flushed = link.flush(OutputSequence::new(1)).await;
            drop(link);
            Ok::<_, Box<dyn Error>>(flushed)
        };
        let (flushed, ()) = join(session, transport.run(&mut controlled, None)).await;
        assert_eq!(flushed?, Ok(()));
        assert_eq!(controlled.written.len(), 1);
        assert_eq!(controlled.flushed, [OutputSequence::new(1)]);
        Ok(())
    })
}

#[test]
fn write_failure_fails_the_next_flush_with_the_writer_outcome() -> TestResult {
    Runtime::new()?.block_on(async {
        let (mut link, transport) = link();
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
            Ok::<_, Box<dyn Error>>(())
        };
        let (result, ()) = join(session, transport.run(&mut controlled, None)).await;
        result?;
        assert!(controlled.written.is_empty());
        assert!(controlled.flushed.is_empty());
        Ok(())
    })
}

#[test]
fn stopped_link_drops_queued_writes_and_flushes() -> TestResult {
    Runtime::new()?.block_on(async {
        let (mut link, transport) = link();
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
        drop(link);
        transport.run(&mut controlled, None).await;
        assert!(controlled.written.is_empty());
        assert!(controlled.flushed.is_empty());
        Ok(())
    })
}

#[test]
fn link_items_are_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Command<Arc<PooledChunkAllocator>>>();
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
        let (mut link, transport) = link();
        let state = Arc::clone(&link.state);
        let (mut writer, entered, release) = GatedWriter::new();
        let mut completed = 0;
        {
            let mut running = pin!(transport.run(&mut writer, None));
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
        let (mut link, transport) = link::<GlobalChunkAllocator>();
        let state = Arc::clone(&link.state);
        let (mut writer, entered, release) = GatedWriter::new();
        {
            let mut first = pin!(link.flush(OutputSequence::default()));
            assert!(poll!(first.as_mut()).is_pending());
        }
        {
            let mut running = pin!(transport.run(&mut writer, None));
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
        let (mut link, transport) = link::<GlobalChunkAllocator>();
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
        let (mut link, transport) = link();
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
            let mut running = pin!(transport.run(&mut controlled, None));
            assert!(poll!(running.as_mut()).is_pending());
            entered.await?;
            link.stop();
            assert!(poll!(running.as_mut()).is_pending());
            assert!(release.send(()).is_err());
            assert!(commands.is_empty());
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
        let (mut link, transport) = link();
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
            let mut running = pin!(transport.run(&mut controlled, None));
            assert!(poll!(running.as_mut()).is_pending());
            entered.await?;
            link.stop();
            assert!(poll!(running.as_mut()).is_pending());
            assert!(release.send(()).is_err());
            assert!(commands.is_empty());
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
fn dropping_the_writer_while_unwinding_does_not_wake_the_transport() {
    let (link, transport) = link::<GlobalChunkAllocator>();
    let state = Arc::downgrade(&link.state);
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    let mut context = Context::from_waker(&waker);
    let mut controlled = ControlledWriter::default();
    {
        let mut transport = pin!(transport.run(&mut controlled, None));
        assert!(transport.as_mut().poll(&mut context).is_pending());
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _link = link;
            panic!("session panic");
        }));
        assert!(result.is_err());
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
    }
    assert!(state.upgrade().is_none());
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
#[ignore = "subprocess entry point for the link panic fixture"]
fn hosted_session_panic_process() -> TestResult {
    if std::env::var_os("LONEWOLF_LINK_PANIC_TEST").is_none() {
        return Ok(());
    }
    Runtime::new()?.block_on(async {
        compio::runtime::spawn(async {
            let (link, transport) = link::<GlobalChunkAllocator>();
            let state = Arc::downgrade(&link.state);
            let (release, entered) = oneshot::channel();
            let mut controlled = ControlledWriter::default();
            {
                let serve = async move {
                    let _link = link;
                    let _ = entered.await;
                    panic!("hosted session panic");
                };
                let joined = AssertUnwindSafe(join(serve, transport.run(&mut controlled, None)))
                    .catch_unwind();
                let mut joined = pin!(joined);
                assert!(poll!(joined.as_mut()).is_pending());
                assert!(release.send(()).is_ok());
                assert!(joined.await.is_err());
            }
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
            let (mut link, transport) = link();
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
                let result = AssertUnwindSafe(join(serve, transport.run(&mut writer, None)))
                    .catch_unwind()
                    .await;
                assert!(result.is_err());
            }
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
