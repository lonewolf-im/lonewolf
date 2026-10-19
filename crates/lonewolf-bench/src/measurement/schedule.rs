// SPDX-License-Identifier: Apache-2.0

use std::{num::NonZeroU32, ops::Range, time::Duration};
use tokio::time::Instant;

use super::invalid;
use crate::{config::MAX_PHASE_OPERATIONS, error::BenchResult, report::DispatchPolicyMetadata};

#[derive(Clone, Copy, Debug)]
pub struct DispatchPolicy {
    pub quantum: Duration,
    pub max_batch: u32,
    pub lag_allowance: Duration,
}

impl Default for DispatchPolicy {
    fn default() -> Self {
        Self {
            quantum: Duration::from_micros(1000),
            max_batch: 256,
            lag_allowance: Duration::from_millis(100),
        }
    }
}

impl DispatchPolicy {
    pub fn metadata(self) -> DispatchPolicyMetadata {
        DispatchPolicyMetadata {
            dispatch_quantum_us: self.quantum.as_micros() as u64,
            max_dispatch_batch: self.max_batch.into(),
            max_schedule_lag_ms: self.lag_allowance.as_millis() as u64,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ScheduledSlot {
    pub sequence: u64,
    pub scheduled_at: Instant,
}

#[derive(Debug)]
pub struct DueSlots {
    pub skipped: Range<u64>,
    pub dispatch: Range<u64>,
    pub next_deadline: Option<Instant>,
}

pub struct RateSchedule {
    start: Instant,
    end: Instant,
    tail_end: Instant,
    rate: NonZeroU32,
    policy: DispatchPolicy,
    planned: u64,
    cursor: u64,
    next_tick: Instant,
}

impl RateSchedule {
    pub fn new(
        start: Instant,
        duration: Duration,
        rate: NonZeroU32,
        policy: DispatchPolicy,
    ) -> BenchResult<Self> {
        let quantum = policy.quantum.as_nanos();
        if !quantum.is_multiple_of(1000)
            || !policy.lag_allowance.as_nanos().is_multiple_of(1_000_000)
            || !(1_000_000..=100_000_000).contains(&quantum)
            || !(1..=4096).contains(&policy.max_batch)
            || !(Duration::from_millis(1)..=Duration::from_secs(1)).contains(&policy.lag_allowance)
            || policy.lag_allowance < policy.quantum
            || rate.get() > 1_000_000
            || (u128::from(rate.get()) * quantum).div_ceil(1_000_000_000)
                > u128::from(policy.max_batch)
        {
            return Err(invalid("invalid dispatch policy"));
        }
        let planned = duration
            .as_nanos()
            .checked_mul(rate.get().into())
            .ok_or_else(|| invalid("schedule count overflow"))?
            .div_ceil(1_000_000_000);
        if planned > MAX_PHASE_OPERATIONS.into() {
            return Err(invalid("phase operation limit exceeded"));
        }
        let end = start
            .checked_add(duration)
            .ok_or_else(|| invalid("schedule end overflow"))?;
        let tail_end = end
            .checked_add(policy.lag_allowance)
            .ok_or_else(|| invalid("schedule tail overflow"))?;
        Ok(Self {
            start,
            end,
            tail_end,
            rate,
            policy,
            planned: planned as u64,
            cursor: 0,
            next_tick: start,
        })
    }

    pub fn planned(&self) -> u64 {
        self.planned
    }
    pub fn end(&self) -> Instant {
        self.end
    }
    pub fn tail_end(&self) -> Instant {
        self.tail_end
    }

    /// `sequence` must be less than the planned cohort size.
    pub fn slot(&self, sequence: u64) -> ScheduledSlot {
        assert!(sequence < self.planned, "sequence outside schedule cohort");
        let nanos = u128::from(sequence) * 1_000_000_000 / u128::from(self.rate.get());
        ScheduledSlot {
            sequence,
            scheduled_at: self.start + Duration::from_nanos(nanos as u64),
        }
    }

    pub fn poll_due(&mut self, now: Instant) -> DueSlots {
        let original = self.cursor;
        if self.cursor == self.planned {
            return DueSlots {
                skipped: original..original,
                dispatch: original..original,
                next_deadline: None,
            };
        }
        if now < self.next_tick {
            return DueSlots {
                skipped: original..original,
                dispatch: original..original,
                next_deadline: Some(self.next_tick),
            };
        }
        if now >= self.tail_end {
            self.cursor = self.planned;
            return DueSlots {
                skipped: original..self.planned,
                dispatch: self.planned..self.planned,
                next_deadline: None,
            };
        }
        let mut low = self.cursor;
        let mut high = self.planned;
        while low < high {
            let mid = low + (high - low) / 2;
            if now.saturating_duration_since(self.slot(mid).scheduled_at)
                > self.policy.lag_allowance
            {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        self.cursor = low;
        let dispatch_start = low;
        let limit = self.planned.min(low + u64::from(self.policy.max_batch));
        while self.cursor < limit && self.slot(self.cursor).scheduled_at <= now {
            self.cursor += 1;
        }
        let ticks = now.duration_since(self.start).as_nanos() / self.policy.quantum.as_nanos() + 1;
        let next_ns = ticks * self.policy.quantum.as_nanos();
        self.next_tick = self.start + Duration::from_nanos(next_ns as u64);
        self.next_tick = self.next_tick.min(self.tail_end);
        DueSlots {
            skipped: original..dispatch_start,
            dispatch: dispatch_start..self.cursor,
            next_deadline: (self.cursor < self.planned).then_some(self.next_tick),
        }
    }
}
