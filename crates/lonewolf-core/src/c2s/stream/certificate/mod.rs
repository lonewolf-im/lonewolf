// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::future::Future;
use std::pin::pin;
use std::task::Poll;
use std::time::{Duration, SystemTime};

use futures_util::future::{Either, poll_fn, select};

use super::outcome::CloseOutcome;
use crate::hosts::client_identity::{ClientValidity, VerifiedClient};

pub(super) struct CertificateMonitor {
    client: VerifiedClient,
    state: ValidityMonitor,
}

impl CertificateMonitor {
    pub(super) fn new(client: VerifiedClient, validity: ClientValidity) -> Self {
        Self {
            client,
            state: ValidityMonitor {
                validity: Cell::new(validity),
                clock: Clock::default(),
            },
        }
    }

    pub(super) fn check(&self) -> Result<(), CloseOutcome> {
        self.state.check()
    }

    pub(super) async fn interrupt<T>(
        &self,
        operation: impl Future<Output = Result<T, CloseOutcome>>,
    ) -> Result<T, CloseOutcome> {
        self.state
            .interrupt(operation, |validity| revalidate(&self.client, validity))
            .await
    }
}

pub(super) struct ValidityMonitor {
    pub(super) validity: Cell<ClientValidity>,
    pub(super) clock: Clock,
}

impl ValidityMonitor {
    fn check(&self) -> Result<(), CloseOutcome> {
        if self.clock.now() >= self.validity.get().valid_until {
            Err(CloseOutcome::CertificateInvalid)
        } else {
            Ok(())
        }
    }

    pub(super) async fn interrupt<T, F>(
        &self,
        operation: impl Future<Output = Result<T, CloseOutcome>>,
        revalidate: impl Fn(ClientValidity) -> F,
    ) -> Result<T, CloseOutcome>
    where
        F: Future<Output = Result<ClientValidity, CloseOutcome>>,
    {
        let mut operation = pin!(operation);
        let guarded = poll_fn(|context| match self.check() {
            Err(outcome) => Poll::Ready(Err(outcome)),
            Ok(()) => operation.as_mut().poll(context),
        });
        match select(pin!(self.invalid(revalidate)), pin!(guarded)).await {
            Either::Left(_) => Err(CloseOutcome::CertificateInvalid),
            Either::Right((result, _)) => result,
        }
    }

    async fn invalid<F>(&self, revalidate: impl Fn(ClientValidity) -> F)
    where
        F: Future<Output = Result<ClientValidity, CloseOutcome>>,
    {
        loop {
            let validity = self.validity.get();
            self.clock
                .wait_until(validity.recheck_at.min(validity.valid_until))
                .await;
            match self
                .clock
                .before_expiry(validity.valid_until, revalidate(validity))
                .await
            {
                Ok(validity) => self.validity.set(validity),
                Err(_) => return,
            }
        }
    }
}

pub(super) async fn revalidate(
    client: &VerifiedClient,
    validity: ClientValidity,
) -> Result<ClientValidity, CloseOutcome> {
    before_expiry(validity.valid_until, async {
        client
            .policy()
            .revalidate_client(client)
            .await
            .map_err(|_| CloseOutcome::CertificateInvalid)
    })
    .await
}

pub(super) async fn before_expiry<T>(
    deadline: SystemTime,
    operation: impl Future<Output = Result<T, CloseOutcome>>,
) -> Result<T, CloseOutcome> {
    Clock::default().before_expiry(deadline, operation).await
}

#[derive(Default)]
pub(super) struct Clock {
    #[cfg(test)]
    manual: Option<tests::ManualClock>,
}

impl Clock {
    pub(super) fn now(&self) -> SystemTime {
        #[cfg(test)]
        if let Some(clock) = &self.manual {
            return clock.now();
        }
        SystemTime::now()
    }

    #[cfg(test)]
    pub(super) fn manual() -> Self {
        Self {
            manual: Some(tests::ManualClock::new()),
        }
    }

    #[cfg(test)]
    pub(super) fn advance(&self, elapsed: Duration) {
        self.manual
            .as_ref()
            .expect("manual clock required")
            .advance(elapsed);
    }

    async fn before_expiry<T>(
        &self,
        deadline: SystemTime,
        operation: impl Future<Output = Result<T, CloseOutcome>>,
    ) -> Result<T, CloseOutcome> {
        let mut operation = pin!(operation);
        let guarded = poll_fn(|context| {
            if self.now() >= deadline {
                Poll::Ready(Err(CloseOutcome::CertificateInvalid))
            } else {
                operation.as_mut().poll(context)
            }
        });
        match select(pin!(self.wait_until(deadline)), pin!(guarded)).await {
            Either::Left(_) => Err(CloseOutcome::CertificateInvalid),
            Either::Right((result, _)) => result,
        }
    }

    async fn wait_until(&self, deadline: SystemTime) {
        #[cfg(test)]
        if let Some(clock) = &self.manual {
            return clock.wait_until(deadline).await;
        }
        loop {
            let remaining = deadline.duration_since(self.now()).unwrap_or_default();
            if remaining.is_zero() {
                return;
            }
            compio::time::sleep(remaining.min(Duration::from_secs(1))).await;
        }
    }
}

#[cfg(test)]
mod tests;
