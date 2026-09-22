// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};

use compio::runtime::Runtime;

use super::{CoreDispatcher, WorkerInfo};

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
