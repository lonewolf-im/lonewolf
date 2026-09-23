// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_lock::Mutex;

use crate::config::limits::EventRate;

const MAX_TRACKED_SOURCES: usize = 16_384;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

pub(super) struct AttemptLimiter {
    per_second: usize,
    burst: usize,
    state: Mutex<State>,
}

pub(super) enum Admission {
    Allowed,
    Denied {
        outcome: &'static str,
        report_count: Option<u64>,
    },
}

impl Admission {
    #[cfg(test)]
    fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

struct State {
    sources: HashMap<IpAddr, Bucket>,
    next_cleanup: Instant,
    last_report_at: Option<Instant>,
    unreported_rejections: u64,
}

struct Bucket {
    tokens: usize,
    remainder: u128,
    updated_at: Instant,
}

impl AttemptLimiter {
    pub(super) fn new(rate: &EventRate) -> Self {
        Self {
            per_second: rate.per_second.get(),
            burst: rate.burst.get(),
            state: Mutex::new(State {
                sources: HashMap::new(),
                next_cleanup: Instant::now(),
                last_report_at: None,
                unreported_rejections: 0,
            }),
        }
    }

    pub(super) async fn admit(&self, source: IpAddr, now: Instant) -> Admission {
        let mut state = self.state.lock().await;
        if !state.sources.contains_key(&source) && state.sources.len() >= MAX_TRACKED_SOURCES {
            if now >= state.next_cleanup {
                state.sources.retain(|_, bucket| {
                    bucket.replenish(self.per_second, self.burst, now);
                    bucket.tokens < self.burst
                });
                state.next_cleanup = now.checked_add(CLEANUP_INTERVAL).unwrap_or(now);
            }
            if state.sources.len() >= MAX_TRACKED_SOURCES {
                return state.deny(now, "source_tracking_full");
            }
        }
        let bucket = state.sources.entry(source).or_insert(Bucket {
            tokens: self.burst,
            remainder: 0,
            updated_at: now,
        });
        bucket.replenish(self.per_second, self.burst, now);
        if bucket.tokens == 0 {
            return state.deny(now, "rate_limited");
        }
        bucket.tokens -= 1;
        Admission::Allowed
    }
}

impl State {
    fn deny(&mut self, now: Instant, outcome: &'static str) -> Admission {
        self.unreported_rejections = self.unreported_rejections.saturating_add(1);
        let report_count = if self
            .last_report_at
            .is_none_or(|last| now.saturating_duration_since(last) >= CLEANUP_INTERVAL)
        {
            self.last_report_at = Some(now);
            Some(std::mem::take(&mut self.unreported_rejections))
        } else {
            None
        };
        Admission::Denied {
            outcome,
            report_count,
        }
    }
}

impl Bucket {
    fn replenish(&mut self, per_second: usize, burst: usize, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated_at);
        let credit = elapsed
            .as_nanos()
            .saturating_mul(per_second as u128)
            .saturating_add(self.remainder);
        let replenished = (credit / 1_000_000_000).min(burst as u128) as usize;
        self.tokens = self.tokens.saturating_add(replenished).min(burst);
        self.remainder = if self.tokens == burst {
            0
        } else {
            credit % 1_000_000_000
        };
        self.updated_at = self.updated_at.max(now);
    }
}

#[cfg(test)]
#[path = "../../tests/c2s/attempt_limit.rs"]
mod tests;
