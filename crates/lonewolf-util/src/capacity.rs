// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub const UPPER_BOUNDS_US: [u64; 12] = [
    10, 50, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000, 5_000_000,
];

macro_rules! indices {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(usize)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $label),+ }
            }
        }
    };
}

indices!(Counter {
    ConnectionsAccepted => "connections_accepted_total",
    ConnectionsClosed => "connections_closed_total",
    MailboxAccepted => "mailbox_accepted_total",
    MailboxFull => "mailbox_full_total",
    MailboxClosed => "mailbox_closed_total",
    RetirementsEvicted => "retirements_evicted_total",
    RetirementsAccountDeleted => "retirements_account_deleted_total",
    RetirementsRouterStopped => "retirements_router_stopped_total",
    ReplaySubscriptionsFlushedStoredBytes => "replay_subscriptions_flushed_stored_bytes_total",
    ReplayOfflineFlushedStoredBytes => "replay_offline_flushed_stored_bytes_total",
    ReplayInvalidRecords => "replay_invalid_records_total",
});
indices!(Gauge {
    ConnectionsActive => "connections_active",
    ConnectionsEstablishing => "connections_establishing",
    ConnectionsAuthenticating => "connections_authenticating",
    ConnectionsBinding => "connections_binding",
    ConnectionsBound => "connections_bound",
});
indices!(Histogram {
    ConnectionEstablishment => "connection_establishment_us",
    ConnectionAuthentication => "connection_authentication_us",
    ConnectionBinding => "connection_binding_us",
    ConnectionBound => "connection_bound_us",
    OrderFixWait => "order_fix_wait_us",
    OrderTicketWait => "order_ticket_wait_us",
    StorageWriterAdmissionWait => "storage_writer_admission_wait_us",
    StorageReadQueueWait => "storage_read_queue_wait_us",
    StorageWriteQueueWait => "storage_write_queue_wait_us",
    StorageCommitQueueWait => "storage_commit_queue_wait_us",
    StorageReadService => "storage_read_service_us",
    StorageWriteService => "storage_write_service_us",
    StorageCommitService => "storage_commit_service_us",
});

pub struct Capacity {
    created: Instant,
    counters: [AtomicU64; Counter::ALL.len()],
    gauges: [AtomicU64; Gauge::ALL.len()],
    histograms: [Distribution; Histogram::ALL.len()],
}

struct Distribution {
    buckets: [AtomicU64; UPPER_BOUNDS_US.len() + 1],
    count: AtomicU64,
    sum_us: AtomicU64,
    abandoned: AtomicU64,
    in_flight: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistogramSnapshot {
    pub buckets: [u64; UPPER_BOUNDS_US.len() + 1],
    pub count: u64,
    pub sum_us: u64,
    pub abandoned_total: u64,
    pub in_flight: u64,
}

pub struct Observation {
    capacity: Arc<Capacity>,
    histogram: Histogram,
    started: Instant,
    completed: bool,
}

impl Default for Capacity {
    fn default() -> Self {
        Self::new()
    }
}

impl Capacity {
    pub fn new() -> Self {
        Self {
            created: Instant::now(),
            counters: [const { AtomicU64::new(0) }; Counter::ALL.len()],
            gauges: [const { AtomicU64::new(0) }; Gauge::ALL.len()],
            histograms: std::array::from_fn(|_| Distribution {
                buckets: [const { AtomicU64::new(0) }; UPPER_BOUNDS_US.len() + 1],
                count: AtomicU64::new(0),
                sum_us: AtomicU64::new(0),
                abandoned: AtomicU64::new(0),
                in_flight: AtomicU64::new(0),
            }),
        }
    }

    pub fn uptime_ms(&self) -> u64 {
        self.created.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }

    pub fn add(&self, counter: Counter, amount: u64) {
        add_saturating(&self.counters[counter as usize], amount);
    }

    pub fn counter(&self, counter: Counter) -> u64 {
        self.counters[counter as usize].load(Ordering::Relaxed)
    }

    pub fn enter(&self, gauge: Gauge) {
        add_saturating(&self.gauges[gauge as usize], 1);
    }

    pub fn leave(&self, gauge: Gauge) {
        self.gauges[gauge as usize].fetch_sub(1, Ordering::Relaxed);
    }

    pub fn gauge(&self, gauge: Gauge) -> u64 {
        self.gauges[gauge as usize].load(Ordering::Relaxed)
    }

    pub fn observe(self: &Arc<Self>, histogram: Histogram) -> Observation {
        add_saturating(&self.histograms[histogram as usize].in_flight, 1);
        Observation {
            capacity: Arc::clone(self),
            histogram,
            started: Instant::now(),
            completed: false,
        }
    }

    pub fn histogram(&self, histogram: Histogram) -> HistogramSnapshot {
        let distribution = &self.histograms[histogram as usize];
        HistogramSnapshot {
            buckets: std::array::from_fn(|index| {
                distribution.buckets[index].load(Ordering::Relaxed)
            }),
            count: distribution.count.load(Ordering::Relaxed),
            sum_us: distribution.sum_us.load(Ordering::Relaxed),
            abandoned_total: distribution.abandoned.load(Ordering::Relaxed),
            in_flight: distribution.in_flight.load(Ordering::Relaxed),
        }
    }
}

impl Observation {
    pub fn complete(mut self) {
        let elapsed = self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        self.record(elapsed);
    }

    pub(crate) fn transition(mut self, histogram: Histogram) -> Self {
        let started = Instant::now();
        let elapsed = started
            .duration_since(self.started)
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;
        self.record(elapsed);
        self.capacity.histograms[self.histogram as usize]
            .in_flight
            .fetch_sub(1, Ordering::Relaxed);
        add_saturating(&self.capacity.histograms[histogram as usize].in_flight, 1);
        self.histogram = histogram;
        self.started = started;
        self.completed = false;
        self
    }

    fn record(&mut self, elapsed: u64) {
        let distribution = &self.capacity.histograms[self.histogram as usize];
        let bucket = UPPER_BOUNDS_US.partition_point(|bound| *bound < elapsed);
        add_saturating(&distribution.buckets[bucket], 1);
        add_saturating(&distribution.count, 1);
        add_saturating(&distribution.sum_us, elapsed);
        self.completed = true;
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        let distribution = &self.capacity.histograms[self.histogram as usize];
        if !self.completed {
            add_saturating(&distribution.abandoned, 1);
        }
        distribution.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) fn add_saturating(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_are_non_cumulative_and_abandoned_work_has_no_sample() {
        let capacity = Arc::new(Capacity::new());
        for value in [0, 10, 11, 50, 5_000_000, 5_000_001] {
            let mut observation = capacity.observe(Histogram::OrderFixWait);
            observation.record(value);
        }
        drop(capacity.observe(Histogram::OrderFixWait));
        let snapshot = capacity.histogram(Histogram::OrderFixWait);
        assert_eq!(snapshot.count, 6);
        assert_eq!(snapshot.buckets[0], 2);
        assert_eq!(snapshot.buckets[1], 2);
        assert_eq!(snapshot.buckets[11], 1);
        assert_eq!(snapshot.buckets[12], 1);
        assert_eq!(snapshot.buckets.iter().sum::<u64>(), 6);
        assert_eq!(snapshot.abandoned_total, 1);
        assert_eq!(snapshot.in_flight, 0);
        capacity.add(Counter::MailboxAccepted, u64::MAX);
        capacity.add(Counter::MailboxAccepted, 1);
        assert_eq!(capacity.counter(Counter::MailboxAccepted), u64::MAX);
    }
}
