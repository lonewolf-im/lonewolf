// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_lock::Mutex;

use super::rejection_report::RejectionReport;

const MAX_TRACKED_SOURCES: usize = 16_384;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

pub(super) struct ConnectionLimiter {
    max_per_ip: usize,
    state: Mutex<State>,
}

pub(super) enum ConnectionAdmission {
    Allowed(ConnectionPermit),
    Denied {
        outcome: &'static str,
        report_count: Option<u64>,
    },
}

pub(super) struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

struct State {
    sources: HashMap<IpAddr, Arc<AtomicUsize>>,
    next_cleanup: Instant,
    report: RejectionReport,
}

impl ConnectionLimiter {
    pub(super) fn new(max_per_ip: usize) -> Self {
        Self {
            max_per_ip,
            state: Mutex::new(State {
                sources: HashMap::new(),
                next_cleanup: Instant::now(),
                report: RejectionReport::default(),
            }),
        }
    }

    pub(super) async fn reserve(&self, source: IpAddr, now: Instant) -> ConnectionAdmission {
        let mut state = self.state.lock().await;
        if !state.sources.contains_key(&source) && state.sources.len() >= MAX_TRACKED_SOURCES {
            if now >= state.next_cleanup {
                state
                    .sources
                    .retain(|_, active| active.load(Ordering::Acquire) != 0);
                state.next_cleanup = now.checked_add(CLEANUP_INTERVAL).unwrap_or(now);
            }
            if state.sources.len() >= MAX_TRACKED_SOURCES {
                return state.deny(now, "source_tracking_full");
            }
        }
        let active = state
            .sources
            .entry(source)
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)));
        if active.load(Ordering::Acquire) >= self.max_per_ip {
            return state.deny(now, "connection_limit");
        }
        active.fetch_add(1, Ordering::AcqRel);
        ConnectionAdmission::Allowed(ConnectionPermit {
            active: Arc::clone(active),
        })
    }
}

impl State {
    fn deny(&mut self, now: Instant, outcome: &'static str) -> ConnectionAdmission {
        ConnectionAdmission::Denied {
            outcome,
            report_count: self.report.record(now),
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let previous = self.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

#[cfg(test)]
#[path = "tests/connection_limit.rs"]
mod tests;
