// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_lock::Mutex;

const REPORT_INTERVAL: Duration = Duration::from_secs(1);

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

struct RejectionReport {
    last_report_at: Option<Instant>,
    unreported_rejections: u64,
}

impl UnauthenticatedLimiter {
    pub(super) fn new(max: NonZeroUsize) -> Self {
        Self {
            max: max.get(),
            active: AtomicUsize::new(0),
            report: Mutex::new(RejectionReport {
                last_report_at: None,
                unreported_rejections: 0,
            }),
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
        report.unreported_rejections = report.unreported_rejections.saturating_add(1);
        let report_count = if report
            .last_report_at
            .is_none_or(|last| now.saturating_duration_since(last) >= REPORT_INTERVAL)
        {
            report.last_report_at = Some(now);
            Some(std::mem::take(&mut report.unreported_rejections))
        } else {
            None
        };
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
#[path = "../../tests/c2s/unauthenticated_limit.rs"]
mod tests;
