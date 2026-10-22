// SPDX-License-Identifier: Apache-2.0

use std::future::{pending, ready};

use compio::runtime::Runtime;
use futures_util::FutureExt;

use super::*;

pub(super) struct ManualClock {
    now: Cell<SystemTime>,
    waiters: std::cell::RefCell<Vec<std::task::Waker>>,
}

impl ManualClock {
    pub(super) fn new() -> Self {
        Self {
            now: Cell::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)),
            waiters: Default::default(),
        }
    }

    pub(super) fn now(&self) -> SystemTime {
        self.now.get()
    }

    pub(super) fn advance(&self, elapsed: Duration) {
        self.now.set(self.now() + elapsed);
        let waiters = std::mem::take(&mut *self.waiters.borrow_mut());
        for waiter in waiters {
            waiter.wake();
        }
    }

    pub(super) async fn wait_until(&self, deadline: SystemTime) {
        poll_fn(|context| {
            if self.now() >= deadline {
                Poll::Ready(())
            } else {
                let mut waiters = self.waiters.borrow_mut();
                if !waiters
                    .iter()
                    .any(|waiter| waiter.will_wake(context.waker()))
                {
                    waiters.push(context.waker().clone());
                }
                Poll::Pending
            }
        })
        .await;
    }
}

#[derive(Default)]
struct WakeCount(std::sync::atomic::AtomicUsize);

impl std::task::Wake for WakeCount {
    fn wake(self: std::sync::Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn monitor(recheck: Duration, expiry: Duration) -> ValidityMonitor {
    let clock = Clock::manual();
    let now = clock.now();
    ValidityMonitor {
        clock,
        validity: Cell::new(ClientValidity {
            recheck_at: now + recheck,
            valid_until: now + expiry,
        }),
    }
}

#[test]
fn expired_validity_does_not_poll_session_work() -> TestResult {
    Runtime::new()?.block_on(async {
        let monitor = monitor(Duration::ZERO, Duration::ZERO);
        let polled = Cell::new(false);
        let result = monitor
            .interrupt(
                async {
                    polled.set(true);
                    Ok(())
                },
                |_| ready(Err(CloseOutcome::CertificateInvalid)),
            )
            .await;
        assert_eq!(result, Err(CloseOutcome::CertificateInvalid));
        assert!(!polled.get());
    });
    Ok(())
}

#[test]
fn pending_revalidation_cannot_extend_expired_authority() -> TestResult {
    Runtime::new()?.block_on(async {
        let monitor = monitor(Duration::ZERO, Duration::from_millis(30));
        let mut operation =
            Box::pin(monitor.interrupt(pending::<Result<(), CloseOutcome>>(), |_| pending()));
        let wakes = std::sync::Arc::new(WakeCount::default());
        let waker = std::task::Waker::from(wakes.clone());
        let mut context = std::task::Context::from_waker(&waker);
        assert!(operation.as_mut().poll(&mut context).is_pending());
        monitor.clock.advance(Duration::from_millis(29));
        assert!(operation.as_mut().poll(&mut context).is_pending());
        wakes.0.store(0, std::sync::atomic::Ordering::Relaxed);
        monitor.clock.advance(Duration::from_millis(1));
        assert_eq!(wakes.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(operation.await, Err(CloseOutcome::CertificateInvalid));
    });
    Ok(())
}

#[test]
fn slow_revalidation_keeps_session_work_polling() -> TestResult {
    Runtime::new()?.block_on(async {
        let monitor = monitor(Duration::ZERO, Duration::from_secs(1));
        let revalidating = Cell::new(false);
        let polled = Cell::new(false);
        let complete = Cell::new(false);
        let mut operation = Box::pin(monitor.interrupt(
            poll_fn(|_| {
                polled.set(true);
                if complete.get() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }),
            |_| {
                revalidating.set(true);
                pending()
            },
        ));
        assert!(futures_util::poll!(operation.as_mut()).is_pending());
        assert!(revalidating.get());
        assert!(polled.get());
        complete.set(true);
        let result = operation.await;
        assert_eq!(result, Ok(()));
    });
    Ok(())
}

#[test]
fn revoked_certificate_stops_a_pending_session() -> TestResult {
    Runtime::new()?.block_on(async {
        let monitor = monitor(Duration::ZERO, Duration::from_secs(1));
        let result = monitor
            .interrupt(pending::<Result<(), CloseOutcome>>(), |_| {
                ready(Err(CloseOutcome::CertificateInvalid))
            })
            .await;
        assert_eq!(result, Err(CloseOutcome::CertificateInvalid));
    });
    Ok(())
}

#[test]
fn renewed_validity_survives_transition_between_operations() -> TestResult {
    Runtime::new()?.block_on(async {
        let monitor = monitor(Duration::ZERO, Duration::from_millis(30));
        let renewed = ClientValidity {
            recheck_at: monitor.clock.now() + Duration::from_secs(1),
            valid_until: monitor.clock.now() + Duration::from_secs(2),
        };
        assert_eq!(
            monitor
                .interrupt(ready(Ok(())), |_| ready(Ok(renewed)))
                .await,
            Ok(())
        );
        assert_eq!(monitor.validity.get(), renewed);
        monitor.clock.advance(Duration::from_millis(40));
        assert_eq!(
            monitor.interrupt(ready(Ok(())), |_| pending()).await,
            Ok(())
        );
    });
    Ok(())
}

#[test]
fn cancellation_drops_monitor_without_session_effects() -> TestResult {
    Runtime::new()?.block_on(async {
        let old = monitor(Duration::ZERO, Duration::from_secs(1));
        let current = monitor(Duration::from_secs(1), Duration::from_secs(2));
        let revalidating = Cell::new(false);
        let operation = old.interrupt(pending::<Result<(), CloseOutcome>>(), |_| {
            revalidating.set(true);
            pending()
        });
        let mut operation = Box::pin(operation);
        assert!(operation.as_mut().now_or_never().is_none());
        assert!(revalidating.get());
        drop(operation);
        assert_eq!(
            current.interrupt(ready(Ok(())), |_| pending()).await,
            Ok(())
        );
    });
    Ok(())
}
