// SPDX-License-Identifier: Apache-2.0

use async_lock::Semaphore;

static CAPACITY: Semaphore = Semaphore::new(16);

pub(crate) async fn run<T: Send + 'static>(operation: impl FnOnce() -> T + Send + 'static) -> T {
    run_with_capacity(&CAPACITY, operation).await
}

async fn run_with_capacity<T: Send + 'static>(
    capacity: &'static Semaphore,
    operation: impl FnOnce() -> T + Send + 'static,
) -> T {
    let permit = capacity.acquire().await;
    ::blocking::unblock(move || {
        // A cancelled caller must not release capacity while the operation still runs.
        let _permit = permit;
        operation()
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::mpsc;
    use std::task::{Context, Poll, Waker};
    use std::thread;
    use std::time::Duration;

    use async_lock::Semaphore;
    use futures_executor::block_on;

    use super::run_with_capacity;

    type TestResult = Result<(), Box<dyn Error>>;
    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn operations_overlap_up_to_the_capacity() -> TestResult {
        static CAPACITY: Semaphore = Semaphore::new(2);
        let (entered, started) = mpsc::channel();
        let (release_first, first_gate) = mpsc::channel();
        let (release_second, second_gate) = mpsc::channel();
        let first_entered = entered.clone();
        let mut first = Box::pin(run_with_capacity(&CAPACITY, move || {
            let _ = first_entered.send(thread::current().id());
            first_gate.recv_timeout(TIMEOUT)
        }));
        assert!(poll(first.as_mut()).is_pending());
        let first_worker = started.recv_timeout(TIMEOUT)?;
        let mut second = Box::pin(run_with_capacity(&CAPACITY, move || {
            let _ = entered.send(thread::current().id());
            second_gate.recv_timeout(TIMEOUT)
        }));
        assert!(poll(second.as_mut()).is_pending());
        let second_worker = started.recv_timeout(TIMEOUT)?;
        assert_ne!(first_worker, second_worker);
        assert_ne!(first_worker, thread::current().id());
        assert_ne!(second_worker, thread::current().id());
        assert!(CAPACITY.try_acquire().is_none());

        let mut third = Box::pin(run_with_capacity(&CAPACITY, || 42));
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
        static CAPACITY: Semaphore = Semaphore::new(1);
        let (entered, started) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let (finished, completed) = mpsc::channel();
        let mut first = Box::pin(run_with_capacity(&CAPACITY, move || {
            let _ = entered.send(());
            let outcome = gate.recv_timeout(TIMEOUT);
            let _ = finished.send(outcome);
        }));
        assert!(poll(first.as_mut()).is_pending());
        started.recv_timeout(TIMEOUT)?;
        drop(first);
        assert!(CAPACITY.try_acquire().is_none());

        let mut second = Box::pin(run_with_capacity(&CAPACITY, || 42));
        assert!(poll(second.as_mut()).is_pending());
        release.send(())?;
        assert_eq!(block_on(second), 42);
        completed.recv_timeout(TIMEOUT)??;
        assert!(CAPACITY.try_acquire().is_some());
        Ok(())
    }

    #[test]
    fn cancelling_while_waiting_does_not_submit_work() -> TestResult {
        static CAPACITY: Semaphore = Semaphore::new(1);
        let permit = CAPACITY.try_acquire().ok_or("missing permit")?;
        let (entered, started) = mpsc::channel();
        let mut waiting = Box::pin(run_with_capacity(&CAPACITY, move || {
            let _ = entered.send(());
        }));
        assert!(poll(waiting.as_mut()).is_pending());
        drop(waiting);
        assert!(matches!(
            started.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
        drop(permit);
        assert_eq!(block_on(run_with_capacity(&CAPACITY, || 42)), 42);
        Ok(())
    }

    #[test]
    fn a_panicking_operation_releases_capacity() {
        static CAPACITY: Semaphore = Semaphore::new(1);
        let outcome = std::panic::catch_unwind(|| {
            block_on(run_with_capacity(&CAPACITY, || panic!("injected panic")));
        });
        assert!(outcome.is_err());
        assert!(CAPACITY.try_acquire().is_some());
        assert_eq!(block_on(run_with_capacity(&CAPACITY, || 42)), 42);
    }

    fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }
}
