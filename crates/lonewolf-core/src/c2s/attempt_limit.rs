// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use async_lock::Mutex;
use lonewolf_util::token_bucket::TokenBucket;

use crate::config::limits::EventRate;

use super::rejection_report::RejectionReport;

const MAX_TRACKED_SOURCES: usize = 16_384;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

pub(super) struct AttemptLimiter {
    per_second: NonZeroUsize,
    burst: NonZeroUsize,
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
    sources: HashMap<IpAddr, TokenBucket>,
    next_cleanup: Instant,
    report: RejectionReport,
}

impl AttemptLimiter {
    pub(super) fn new(rate: &EventRate) -> Self {
        Self {
            per_second: rate.per_second,
            burst: rate.burst,
            state: Mutex::new(State {
                sources: HashMap::new(),
                next_cleanup: Instant::now(),
                report: RejectionReport::default(),
            }),
        }
    }

    pub(super) async fn admit(&self, source: IpAddr, now: Instant) -> Admission {
        let mut state = self.state.lock().await;
        if !state.sources.contains_key(&source) && state.sources.len() >= MAX_TRACKED_SOURCES {
            if now >= state.next_cleanup {
                state.sources.retain(|_, bucket| {
                    bucket.replenish(self.per_second, self.burst, now);
                    bucket.available() < self.burst.get()
                });
                state.next_cleanup = now.checked_add(CLEANUP_INTERVAL).unwrap_or(now);
            }
            if state.sources.len() >= MAX_TRACKED_SOURCES {
                return state.deny(now, "source_tracking_full");
            }
        }
        let bucket = state
            .sources
            .entry(source)
            .or_insert(TokenBucket::new(self.burst, now));
        bucket.replenish(self.per_second, self.burst, now);
        if bucket.available() == 0 {
            return state.deny(now, "rate_limited");
        }
        bucket.consume(1);
        Admission::Allowed
    }
}

impl State {
    fn deny(&mut self, now: Instant, outcome: &'static str) -> Admission {
        Admission::Denied {
            outcome,
            report_count: self.report.record(now),
        }
    }
}

#[cfg(test)]
#[path = "tests/attempt_limit.rs"]
mod tests;
