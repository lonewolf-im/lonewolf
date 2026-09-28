// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use async_lock::Mutex;

use super::rejection_report::RejectionReport;

pub(super) struct UnauthenticatedLimiter {
    max: usize,
    active: AtomicUsize,
    report: Mutex<RejectionReport>,
}

pub(super) enum Admission {
    Allowed(UnauthenticatedPermit),
    Denied { report_count: Option<u64> },
}

pub(super) struct UnauthenticatedPermit {
    limiter: Arc<UnauthenticatedLimiter>,
}

impl UnauthenticatedLimiter {
    pub(super) fn new(max: NonZeroUsize) -> Self {
        Self {
            max: max.get(),
            active: AtomicUsize::new(0),
            report: Mutex::new(RejectionReport::default()),
        }
    }

    pub(super) async fn reserve(self: &Arc<Self>, now: Instant) -> Admission {
        if self
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                if active < self.max {
                    Some(active + 1)
                } else {
                    None
                }
            })
            .is_ok()
        {
            return Admission::Allowed(UnauthenticatedPermit {
                limiter: Arc::clone(self),
            });
        }
        let mut report = self.report.lock().await;
        let report_count = report.record(now);
        Admission::Denied { report_count }
    }

    #[cfg(test)]
    pub(super) fn active_count(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

impl Drop for UnauthenticatedPermit {
    fn drop(&mut self) {
        let previous = self.limiter.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

#[cfg(test)]
#[path = "tests/unauthenticated_limit.rs"]
mod tests;
