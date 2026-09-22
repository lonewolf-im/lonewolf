// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use compio::runtime::Runtime;
use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::poll_fn;

use super::{CoreDispatcher, Inbox, Job, WorkerContext, WorkerInfo, run_worker};

type TestResult = Result<(), Box<dyn Error>>;

static STARTED_WORKERS: AtomicUsize = AtomicUsize::new(0);
static EXITED_WORKERS: AtomicUsize = AtomicUsize::new(0);

struct WorkerExit;

impl Drop for WorkerExit {
    fn drop(&mut self) {
        EXITED_WORKERS.fetch_add(1, Ordering::SeqCst);
    }
}

thread_local! {
    static WORKER_EXIT: WorkerExit = {
        STARTED_WORKERS.fetch_add(1, Ordering::SeqCst);
        WorkerExit
    };
}

#[test]
fn partial_startup_failure_joins_previously_started_workers() -> TestResult {
    fn initialize(worker: WorkerInfo) -> io::Result<Runtime> {
        if worker.index == 1 {
            return Err(io::Error::other("injected startup failure"));
        }
        WORKER_EXIT.with(|_| {});
        Runtime::new()
    }

    let result = CoreDispatcher::start(
        vec![
            WorkerInfo {
                index: 0,
                cpu_id: None,
            },
            WorkerInfo {
                index: 1,
                cpu_id: None,
            },
        ],
        NonZeroUsize::MIN,
        initialize,
    );
    let error = result.err().ok_or("startup succeeded")?;
    assert_eq!(error.to_string(), "injected startup failure");
    assert_eq!(STARTED_WORKERS.load(Ordering::SeqCst), 1);
    assert_eq!(EXITED_WORKERS.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn closed_queue_preserves_shutdown_grace_period() -> TestResult {
    Runtime::new()?.block_on(async {
        let (sender, jobs) = async_channel::bounded::<Job>(1);
        let (release, cleanup) = oneshot::channel();
        let mut release = Some(release);
        sender.try_send(Box::new(move |_| {
            compio::runtime::spawn(async move {
                assert!(cleanup.await.is_ok());
                false
            })
        }))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let stop = poll_fn(move |context| {
            if sender.is_closed() {
                if let Some(release) = release.take() {
                    let _ = release.send(());
                }
                return Poll::Ready(deadline);
            }
            if sender.is_empty() {
                sender.close();
                context.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .boxed()
        .shared();
        let context = WorkerContext {
            worker: WorkerInfo {
                index: 0,
                cpu_id: None,
            },
            stop,
        };
        run_worker(context, Inbox(jobs)).await?;
        Ok(())
    })
}
