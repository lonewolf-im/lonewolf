// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

const REPORT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Default)]
pub(super) struct RejectionReport {
    last_report_at: Option<Instant>,
    unreported_rejections: u64,
}

impl RejectionReport {
    pub(super) fn record(&mut self, now: Instant) -> Option<u64> {
        self.unreported_rejections = self.unreported_rejections.saturating_add(1);
        if self
            .last_report_at
            .is_none_or(|last| now.saturating_duration_since(last) >= REPORT_INTERVAL)
        {
            self.last_report_at = Some(now);
            Some(std::mem::take(&mut self.unreported_rejections))
        } else {
            None
        }
    }
}

#[cfg(test)]
#[path = "tests/rejection_report.rs"]
mod tests;
