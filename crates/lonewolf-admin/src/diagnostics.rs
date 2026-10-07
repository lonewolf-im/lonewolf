// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use lonewolf_util::capacity::{HistogramSnapshot, UPPER_BOUNDS_US};
use lonewolf_util::pool::{BUCKET_SIZES, PoolStats};
use serde::Serialize;

/// Methods must not block or expose client identifiers or payloads.
pub trait DiagnosticsProvider: Send + Sync {
    fn readiness(&self) -> Readiness;
    fn snapshot(&self) -> DiagnosticsSnapshot;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Unknown,
    Starting,
    Ready,
    Stopping,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Readiness {
    pub schema_version: u32,
    pub state: ReadinessState,
    pub ready: bool,
}

impl Readiness {
    pub fn new(state: ReadinessState) -> Self {
        Self {
            schema_version: 1,
            state,
            ready: state == ReadinessState::Ready,
        }
    }
}

/// Concurrent updates can make independently read fields differ.
#[derive(Serialize)]
pub struct DiagnosticsSnapshot {
    pub schema_version: u32,
    pub uptime_ms: u64,
    pub readiness: Readiness,
    pub counters: BTreeMap<&'static str, u64>,
    pub gauges: BTreeMap<&'static str, u64>,
    pub histograms: BTreeMap<&'static str, HistogramView>,
    pub pool: PoolSnapshot,
}

/// Buckets are not cumulative; the last bucket contains durations above every bound.
#[derive(Serialize)]
pub struct HistogramView {
    pub upper_bounds_us: [u64; UPPER_BOUNDS_US.len()],
    pub buckets: [u64; UPPER_BOUNDS_US.len() + 1],
    pub count: u64,
    pub sum_us: u64,
    pub abandoned_total: u64,
    pub in_flight: u64,
}

impl From<HistogramSnapshot> for HistogramView {
    fn from(snapshot: HistogramSnapshot) -> Self {
        Self {
            upper_bounds_us: UPPER_BOUNDS_US,
            buckets: snapshot.buckets,
            count: snapshot.count,
            sum_us: snapshot.sum_us,
            abandoned_total: snapshot.abandoned_total,
            in_flight: snapshot.in_flight,
        }
    }
}

#[derive(Serialize)]
pub struct PoolSnapshot {
    pub reserved_bytes: u64,
    pub allocation_requests_total: u64,
    pub requested_bytes_total: u64,
    pub allocation_failures_total: u64,
    pub heap_fallback_allocations_total: u64,
    pub heap_fallback_requested_bytes_total: u64,
    pub buckets: [PoolBucket; BUCKET_SIZES.len()],
}

#[derive(Serialize)]
pub struct PoolBucket {
    pub chunk_bytes: usize,
    pub total_chunks: usize,
    pub available_chunks: usize,
    pub shard_count: usize,
    pub allocations_total: u64,
}

impl From<PoolStats> for PoolSnapshot {
    fn from(stats: PoolStats) -> Self {
        Self {
            reserved_bytes: stats.reserved_bytes,
            allocation_requests_total: stats.allocation_requests_total,
            requested_bytes_total: stats.requested_bytes_total,
            allocation_failures_total: stats.allocation_failures_total,
            heap_fallback_allocations_total: stats.heap_allocation_count,
            heap_fallback_requested_bytes_total: stats.heap_fallback_requested_bytes_total,
            buckets: stats.buckets.map(|bucket| PoolBucket {
                chunk_bytes: bucket.chunk_bytes,
                total_chunks: bucket.total_chunks,
                available_chunks: bucket.available_chunks,
                shard_count: bucket.shard_count,
                allocations_total: bucket.allocation_count,
            }),
        }
    }
}
