// SPDX-License-Identifier: Apache-2.0

use std::future::{pending, ready};

use compio::runtime::Runtime;
use futures_util::FutureExt;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn monitor(recheck: Duration, expiry: Duration) -> ValidityMonitor {
    let now = SystemTime::now();
    ValidityMonitor {
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
        let result = monitor
            .interrupt(pending::<Result<(), CloseOutcome>>(), |_| pending())
            .await;
        assert_eq!(result, Err(CloseOutcome::CertificateInvalid));
    });
    Ok(())
}

#[test]
fn slow_revalidation_keeps_session_work_polling() -> TestResult {
    Runtime::new()?.block_on(async {
        let monitor = monitor(Duration::ZERO, Duration::from_secs(1));
        let revalidating = Cell::new(false);
        let result = monitor
            .interrupt(
                async {
                    compio::time::sleep(Duration::from_millis(10)).await;
                    assert!(revalidating.get());
                    Ok(())
                },
                |_| {
                    revalidating.set(true);
                    pending()
                },
            )
            .await;
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
            recheck_at: SystemTime::now() + Duration::from_secs(1),
            valid_until: SystemTime::now() + Duration::from_secs(2),
        };
        assert_eq!(
            monitor
                .interrupt(ready(Ok(())), |_| ready(Ok(renewed)))
                .await,
            Ok(())
        );
        assert_eq!(monitor.validity.get(), renewed);
        compio::time::sleep(Duration::from_millis(40)).await;
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
