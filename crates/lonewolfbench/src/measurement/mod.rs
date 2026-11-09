// SPDX-License-Identifier: Apache-2.0

mod histogram;
mod ledger;
mod schedule;

pub use histogram::LatencyHistogram;
pub use ledger::*;
pub use schedule::{DispatchPolicy, DueSlots, RateSchedule, ScheduledSlot};

use crate::{
    error::{BenchError, BenchResult, ErrorCode},
    report::{
        CounterReport, HistogramReport, LatencyKind, RateReport, RunReason, RunStatus, status_of,
    },
};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug)]
pub struct MeasurementResult {
    pub counters: CounterReport,
    pub latencies: BTreeMap<LatencyKind, HistogramReport>,
    pub reasons: Vec<RunReason>,
}

impl MeasurementResult {
    pub fn status(&self) -> RunStatus {
        status_of(&self.reasons)
    }

    pub fn rates(
        &self,
        window: Duration,
        offered_rate: u32,
        topology: LedgerTopology,
    ) -> RateReport {
        let seconds = window.as_secs_f64();
        let rate = |count| (seconds > 0.0).then(|| count as f64 / seconds);
        let c = &self.counters;
        let messages = matches!(topology, LedgerTopology::Messages { .. });
        RateReport {
            planned_per_second: rate(c.planned),
            dispatched_in_window_per_second: rate(c.dispatched_in_window),
            write_succeeded_in_window_per_second: messages
                .then(|| rate(c.write_succeeded_in_window))
                .flatten(),
            received_in_window_per_second: messages.then(|| rate(c.received_in_window)).flatten(),
            cohort_receipts_per_second: messages.then(|| rate(c.received_on_time)).flatten(),
            login_in_window_per_second: (!messages).then(|| rate(c.login_in_window)).flatten(),
            cohort_logins_per_second: (!messages).then(|| rate(c.login_succeeded)).flatten(),
            closed_cycles_per_second: (!messages).then(|| rate(c.closed_cleanly)).flatten(),
            offered_rate_per_second: Some(offered_rate),
            window_seconds: (seconds > 0.0).then_some(seconds),
        }
    }
}

fn invalid(context: &'static str) -> BenchError {
    BenchError::new(ErrorCode::Runtime, context)
}

fn increment(value: &mut u64, amount: u64) -> BenchResult<()> {
    *value = value
        .checked_add(amount)
        .ok_or_else(|| invalid("counter overflow"))?;
    Ok(())
}
