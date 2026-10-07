// SPDX-License-Identifier: Apache-2.0

//! Limits submitted blocking work across clones of one executor.

use std::num::NonZeroUsize;
use std::sync::Arc;

use async_lock::Semaphore;

use crate::capacity::{Capacity, Histogram};

/// Clones share the limit on jobs submitted to the process-wide blocking pool.
#[derive(Clone)]
pub struct BlockingExecutor {
    capacity: Arc<Semaphore>,
    observation: Option<(Arc<Capacity>, Histogram, Histogram)>,
}

impl BlockingExecutor {
    /// Creates an independent limit on queued and running blocking operations.
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity: Arc::new(Semaphore::new(capacity.get())),
            observation: None,
        }
    }

    pub fn with_observation(
        mut self,
        capacity: Arc<Capacity>,
        queue: Histogram,
        service: Histogram,
    ) -> Self {
        self.observation = Some((capacity, queue, service));
        self
    }

    /// Waits for capacity before submitting work to the process-wide pool.
    ///
    /// Dropping the future while it waits for capacity does not submit work.
    /// Submitted work retains its capacity until it finishes, even if the
    /// caller drops the future.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `operation` when the result is awaited.
    pub async fn run<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let timing = self
            .observation
            .as_ref()
            .map(|(_, queue, service)| (*queue, *service));
        self.run_timed(operation, timing).await
    }
    pub async fn run_with_histograms<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> T + Send + 'static,
        queue: Histogram,
        service: Histogram,
    ) -> T {
        self.run_timed(operation, Some((queue, service))).await
    }

    async fn run_timed<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> T + Send + 'static,
        timing: Option<(Histogram, Histogram)>,
    ) -> T {
        let observed = self
            .observation
            .as_ref()
            .zip(timing)
            .map(|((capacity, _, _), (queue, service))| (capacity.observe(queue), service));
        let permit = self.capacity.acquire_arc().await;
        ::blocking::unblock(move || {
            let _permit = permit;
            let service = observed.map(|(queue, service)| queue.transition(service));
            let result = operation();
            if let Some(service) = service {
                service.complete();
            }
            result
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
        let observations = std::sync::Arc::new(crate::capacity::Capacity::new());
        let executor = BlockingExecutor::new(NonZeroUsize::MIN).with_observation(
            std::sync::Arc::clone(&observations),
            crate::capacity::Histogram::StorageWriteQueueWait,
            crate::capacity::Histogram::StorageWriteService,
        );
        let outcome = std::panic::catch_unwind(|| {
            block_on(executor.run(|| panic!("injected panic")));
        });
        assert!(outcome.is_err());
        assert!(executor.capacity.try_acquire_arc().is_some());
        assert_eq!(
            observations
                .histogram(crate::capacity::Histogram::StorageWriteQueueWait)
                .count,
            1
        );
        assert_eq!(
            observations
                .histogram(crate::capacity::Histogram::StorageWriteService)
                .abandoned_total,
            1
        );
        assert_eq!(
            observations
                .histogram(crate::capacity::Histogram::StorageWriteService)
                .in_flight,
            0
        );
        assert_eq!(block_on(executor.run(|| 42)), 42);
        assert_eq!(
            observations
                .histogram(crate::capacity::Histogram::StorageWriteService)
                .count,
            1
        );
    }

    #[test]
    fn observations_start_on_poll_and_submitted_service_survives_cancellation() -> TestResult {
        use crate::capacity::{Capacity, Histogram};
        use std::sync::Arc;
        let capacity = Arc::new(Capacity::new());
        let executor = BlockingExecutor::new(NonZeroUsize::MIN).with_observation(
            Arc::clone(&capacity),
            Histogram::StorageReadQueueWait,
            Histogram::StorageReadService,
        );
        let unpolled = executor.run(|| ());
        drop(unpolled);
        assert_eq!(
            capacity
                .histogram(Histogram::StorageReadQueueWait)
                .in_flight,
            0
        );
        let permit = executor.capacity.try_acquire_arc().ok_or("no permit")?;
        let mut waiting = Box::pin(executor.run(|| ()));
        assert!(poll(waiting.as_mut()).is_pending());
        assert_eq!(
            capacity
                .histogram(Histogram::StorageReadQueueWait)
                .in_flight,
            1
        );
        drop(waiting);
        assert_eq!(
            capacity
                .histogram(Histogram::StorageReadQueueWait)
                .abandoned_total,
            1
        );
        drop(permit);
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let mut submitted = Box::pin(executor.run(move || {
            let _ = entered.send(());
            released.recv_timeout(TIMEOUT)
        }));
        assert!(poll(submitted.as_mut()).is_pending());
        entering.recv_timeout(TIMEOUT)?;
        assert_eq!(capacity.histogram(Histogram::StorageReadQueueWait).count, 1);
        assert_eq!(
            capacity.histogram(Histogram::StorageReadService).in_flight,
            1
        );
        drop(submitted);
        assert_eq!(
            capacity.histogram(Histogram::StorageReadService).in_flight,
            1
        );
        release.send(())?;
        let _ = block_on(executor.run(|| Err::<(), _>("classified failure")));
        let service = capacity.histogram(Histogram::StorageReadService);
        assert_eq!(service.count, 2);
        assert_eq!(service.abandoned_total, 0);
        assert_eq!(service.in_flight, 0);
        assert_eq!(capacity.histogram(Histogram::StorageReadQueueWait).count, 2);
        Ok(())
    }

    fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }
}
