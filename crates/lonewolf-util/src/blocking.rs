// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::sync::Arc;

use async_lock::Semaphore;

/// Clones share the limit on jobs submitted to the process-wide blocking pool.
#[derive(Clone)]
pub struct BlockingExecutor {
    capacity: Arc<Semaphore>,
}

impl BlockingExecutor {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity: Arc::new(Semaphore::new(capacity.get())),
        }
    }

    /// Waits for capacity before submitting work. A started operation retains its
    /// capacity until it finishes, even if the caller drops the future.
    /// Operation panics propagate to the caller.
    pub async fn run<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let permit = self.capacity.acquire_arc().await;
        ::blocking::unblock(move || {
            let _permit = permit;
            operation()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::future::Future;
    use std::num::NonZeroUsize;
    use std::pin::Pin;
    use std::sync::mpsc;
    use std::task::{Context, Poll, Waker};
    use std::thread;
    use std::time::Duration;

    use futures_executor::block_on;

    use super::BlockingExecutor;

    type TestResult = Result<(), Box<dyn Error>>;
    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn clones_share_capacity_and_allow_concurrent_operations() -> TestResult {
        let executor = BlockingExecutor::new(const { NonZeroUsize::new(2).unwrap() });
        let cloned = executor.clone();
        let (entered, started) = mpsc::channel();
        let (release_first, first_gate) = mpsc::channel();
        let (release_second, second_gate) = mpsc::channel();
        let first_entered = entered.clone();
        let mut first = Box::pin(executor.run(move || {
            let _ = first_entered.send(thread::current().id());
            first_gate.recv_timeout(TIMEOUT)
        }));
        assert!(poll(first.as_mut()).is_pending());
        let first_worker = started.recv_timeout(TIMEOUT)?;
        let mut second = Box::pin(cloned.run(move || {
            let _ = entered.send(thread::current().id());
            second_gate.recv_timeout(TIMEOUT)
        }));
        assert!(poll(second.as_mut()).is_pending());
        let second_worker = started.recv_timeout(TIMEOUT)?;
        assert_ne!(first_worker, second_worker);
        assert_ne!(first_worker, thread::current().id());
        assert_ne!(second_worker, thread::current().id());
        assert!(executor.capacity.try_acquire_arc().is_none());

        let mut third = Box::pin(executor.run(|| 42));
        assert!(poll(third.as_mut()).is_pending());
        release_first.send(())?;
        block_on(first)?;
        assert_eq!(block_on(third), 42);
        release_second.send(())?;
        block_on(second)?;
        Ok(())
    }

    #[test]
    fn cancelling_a_running_operation_does_not_release_capacity() -> TestResult {
        let executor = BlockingExecutor::new(NonZeroUsize::MIN);
        let (entered, started) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let (finished, completed) = mpsc::channel();
        let mut first = Box::pin(executor.run(move || {
            let _ = entered.send(());
            let outcome = gate.recv_timeout(TIMEOUT);
            let _ = finished.send(outcome);
        }));
        assert!(poll(first.as_mut()).is_pending());
        started.recv_timeout(TIMEOUT)?;
        drop(first);
        assert!(executor.capacity.try_acquire_arc().is_none());

        let mut second = Box::pin(executor.run(|| 42));
        assert!(poll(second.as_mut()).is_pending());
        release.send(())?;
        assert_eq!(block_on(second), 42);
        completed.recv_timeout(TIMEOUT)??;
        assert!(executor.capacity.try_acquire_arc().is_some());
        Ok(())
    }

    #[test]
    fn cancelling_while_waiting_does_not_submit_work() -> TestResult {
        let executor = BlockingExecutor::new(NonZeroUsize::MIN);
        let permit = executor
            .capacity
            .try_acquire_arc()
            .ok_or("missing permit")?;
        let (entered, started) = mpsc::channel();
        let mut waiting = Box::pin(executor.run(move || {
            let _ = entered.send(());
        }));
        assert!(poll(waiting.as_mut()).is_pending());
        drop(waiting);
        assert!(matches!(
            started.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
        drop(permit);
        assert_eq!(block_on(executor.run(|| 42)), 42);
        Ok(())
    }

    #[test]
    fn a_panicking_operation_releases_capacity() {
        let executor = BlockingExecutor::new(NonZeroUsize::MIN);
        let outcome = std::panic::catch_unwind(|| {
            block_on(executor.run(|| panic!("injected panic")));
        });
        assert!(outcome.is_err());
        assert!(executor.capacity.try_acquire_arc().is_some());
        assert_eq!(block_on(executor.run(|| 42)), 42);
    }

    fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }
}
