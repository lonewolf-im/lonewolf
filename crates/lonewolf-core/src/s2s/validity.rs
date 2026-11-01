// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::rc::Rc;
use std::time::SystemTime;

use futures_util::FutureExt;
use futures_util::future::{LocalBoxFuture, Shared};

use super::metrics::StreamClose;

pub(super) struct LinkValidity {
    state: Rc<State>,
}

struct State {
    valid_until: Cell<SystemTime>,
    deadline_reason: Cell<StreamClose>,
    invalidated: Cell<Option<StreamClose>>,
    signal: Shared<LocalBoxFuture<'static, StreamClose>>,
}

impl LinkValidity {
    pub(super) fn fixed(valid_until: SystemTime) -> Self {
        Self {
            state: Rc::new(State {
                valid_until: Cell::new(valid_until),
                deadline_reason: Cell::new(StreamClose::CertificateExpired),
                invalidated: Cell::new(None),
                signal: async move {
                    super::expiry::wait(valid_until).await;
                    StreamClose::CertificateExpired
                }
                .boxed_local()
                .shared(),
            }),
        }
    }

    pub(super) fn invalidated(&self) -> Shared<LocalBoxFuture<'static, StreamClose>> {
        self.state.signal.clone()
    }

    pub(super) async fn wait(&self) -> StreamClose {
        self.wait_with(SystemTime::now).await
    }

    async fn wait_with(&self, now: impl FnOnce() -> SystemTime) -> StreamClose {
        let observed = match self.check(now()) {
            Err(reason) => reason,
            Ok(()) => self.invalidated().await,
        };
        let reason = self.state.invalidated.get().unwrap_or(observed);
        self.state.invalidated.set(Some(reason));
        reason
    }

    pub(super) fn reason(&self) -> Option<StreamClose> {
        self.state
            .invalidated
            .get()
            .or_else(|| self.state.signal.peek().copied())
    }

    pub(super) fn check(&self, now: SystemTime) -> Result<(), StreamClose> {
        if let Some(reason) = self.reason() {
            Err(reason)
        } else if now >= self.state.valid_until.get() {
            Err(self.state.deadline_reason.get())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::pin;
    use std::time::Duration;

    use compio::runtime::Runtime;
    use futures_util::future::join;
    use futures_util::poll;

    use super::*;

    #[test]
    fn fixed_deadline_resolves_all_waiters_and_retains_its_reason() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let now = SystemTime::now();
            let validity = LinkValidity::fixed(now + Duration::from_millis(200));
            assert!(validity.check(now).is_ok());
            assert!(validity.reason().is_none());
            let signal = validity.invalidated();
            let (first, second) = join(signal.clone(), signal).await;
            assert!(matches!(first, StreamClose::CertificateExpired));
            assert!(matches!(second, StreamClose::CertificateExpired));
            assert!(matches!(
                validity.reason(),
                Some(StreamClose::CertificateExpired)
            ));
            assert!(matches!(
                validity.check(now),
                Err(StreamClose::CertificateExpired)
            ));
        });
        Ok(())
    }

    #[test]
    fn each_wait_checks_wall_time_and_keeps_the_first_observed_reason() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            for reason in [
                StreamClose::CertificateExpired,
                StreamClose::RevocationStale,
            ] {
                let now = Cell::new(SystemTime::now());
                let deadline = now.get() + Duration::from_secs(3600);
                let validity = LinkValidity::fixed(deadline);
                validity.state.deadline_reason.set(reason);
                {
                    let mut first = pin!(validity.wait_with(|| now.get()));
                    assert!(poll!(first.as_mut()).is_pending());
                }
                now.set(deadline + Duration::from_nanos(1));
                assert!(validity.invalidated().now_or_never().is_none());
                let observed = validity.wait_with(|| now.get()).now_or_never();
                assert_eq!(observed.map(StreamClose::as_str), Some(reason.as_str()));
                assert_eq!(
                    validity.reason().map(StreamClose::as_str),
                    Some(reason.as_str())
                );
                assert_eq!(
                    validity
                        .check(deadline - Duration::from_secs(1))
                        .err()
                        .map(StreamClose::as_str),
                    Some(reason.as_str()),
                );
            }
        });
        Ok(())
    }

    #[test]
    fn past_deadline_fails_before_polling_and_resolves_at_once() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let now = SystemTime::now();
            let validity = LinkValidity::fixed(now - Duration::from_millis(200));
            assert!(validity.reason().is_none());
            assert!(matches!(
                validity.check(now),
                Err(StreamClose::CertificateExpired)
            ));
            assert!(matches!(
                validity.invalidated().now_or_never(),
                Some(StreamClose::CertificateExpired)
            ));
        });
        Ok(())
    }
}
