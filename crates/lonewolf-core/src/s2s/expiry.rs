// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::time::{Duration, SystemTime};

// Darwin rejects kevent timeouts above INT32_MAX seconds.
const MAX_WAIT: Duration = Duration::from_secs(i32::MAX as u64);

pub(super) async fn wait(until: SystemTime) {
    wait_with(until, SystemTime::now, compio::time::sleep).await;
}

async fn wait_with<N, S, F>(until: SystemTime, mut now: N, mut sleep: S)
where
    N: FnMut() -> SystemTime,
    S: FnMut(Duration) -> F,
    F: Future<Output = ()>,
{
    loop {
        let Ok(remaining) = until.duration_since(now()) else {
            return;
        };
        if remaining.is_zero() {
            return;
        }
        sleep(remaining.min(MAX_WAIT)).await;
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::pin::pin;

    use compio::runtime::Runtime;
    use futures_channel::oneshot;
    use futures_util::future::{Either, select};
    use futures_util::poll;

    use super::*;

    struct Clock {
        now: Cell<SystemTime>,
        waits: RefCell<Vec<Duration>>,
        release: RefCell<Option<oneshot::Sender<()>>>,
    }

    impl Clock {
        fn sleep(&self, duration: Duration) -> impl Future<Output = ()> {
            let (release, held) = oneshot::channel();
            assert!(self.release.borrow_mut().replace(release).is_none());
            self.waits.borrow_mut().push(duration);
            async move {
                assert!(held.await.is_ok());
            }
        }

        fn advance(&self, now: SystemTime) {
            self.now.set(now);
            let Some(release) = self.release.borrow_mut().take() else {
                panic!("no wait to release");
            };
            assert!(release.send(()).is_ok());
        }
    }

    #[test]
    fn past_and_equal_deadlines_finish_without_sleeping() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
            for until in [now - Duration::from_nanos(1), now] {
                wait_with(
                    until,
                    || now,
                    |_| async { panic!("deadline already passed") },
                )
                .await;
            }
        });
        Ok(())
    }

    #[test]
    fn bounded_wakes_keep_the_operation_and_original_deadline_through_clock_changes()
    -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
            let until = start + MAX_WAIT + MAX_WAIT + Duration::from_millis(1250);
            let clock = Clock {
                now: Cell::new(start),
                waits: RefCell::new(Vec::new()),
                release: RefCell::new(None),
            };
            let entered = Cell::new(0);
            let (_release, held) = oneshot::channel::<()>();
            let operation = async {
                entered.set(entered.get() + 1);
                let _ = held.await;
            };
            let expiry = wait_with(until, || clock.now.get(), |duration| clock.sleep(duration));
            let expiry = pin!(expiry);
            let operation = pin!(operation);
            let mut interrupted = pin!(select(expiry, operation));
            assert!(poll!(interrupted.as_mut()).is_pending());
            assert_eq!(entered.get(), 1);
            assert_eq!(*clock.waits.borrow(), [MAX_WAIT]);

            clock.advance(start + MAX_WAIT);
            assert!(poll!(interrupted.as_mut()).is_pending());
            assert_eq!(entered.get(), 1);
            assert_eq!(*clock.waits.borrow(), [MAX_WAIT, MAX_WAIT]);

            clock.advance(start + MAX_WAIT - Duration::from_secs(2));
            assert!(poll!(interrupted.as_mut()).is_pending());
            assert_eq!(entered.get(), 1);
            assert_eq!(*clock.waits.borrow(), [MAX_WAIT, MAX_WAIT, MAX_WAIT]);

            clock.advance(until - Duration::from_millis(250));
            assert!(poll!(interrupted.as_mut()).is_pending());
            assert_eq!(entered.get(), 1);
            assert_eq!(
                *clock.waits.borrow(),
                [MAX_WAIT, MAX_WAIT, MAX_WAIT, Duration::from_millis(250)]
            );

            clock.advance(until);
            assert!(matches!(interrupted.await, Either::Left(((), _))));
            assert_eq!(entered.get(), 1);
            assert!(clock.release.borrow().is_none());
            assert_eq!(clock.waits.borrow().len(), 4);
        });
        Ok(())
    }
}
