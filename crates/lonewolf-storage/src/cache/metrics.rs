// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlocklistLookup {
    Hit,
    Miss,
    Bypass,
}

impl BlocklistLookup {
    pub const ALL: [Self; 3] = [Self::Hit, Self::Miss, Self::Bypass];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Bypass => "bypass",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlocklistFill {
    Inserted,
    Discarded,
}

impl BlocklistFill {
    pub const ALL: [Self; 2] = [Self::Inserted, Self::Discarded];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inserted => "inserted",
            Self::Discarded => "discarded",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlocklistUpdate {
    Written,
    Invalidated,
}

impl BlocklistUpdate {
    pub const ALL: [Self; 2] = [Self::Written, Self::Invalidated];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Written => "written",
            Self::Invalidated => "invalidated",
        }
    }
}

#[derive(Default)]
pub struct CacheMetrics {
    blocklist_lookups: [AtomicU64; BlocklistLookup::ALL.len()],
    blocklist_fills: [AtomicU64; BlocklistFill::ALL.len()],
    blocklist_updates: [AtomicU64; BlocklistUpdate::ALL.len()],
    blocklist_evictions: AtomicU64,
    blocklist_entries: AtomicU64,
    blocklist_size_bytes: AtomicU64,
}

impl CacheMetrics {
    pub fn blocklist_lookups(&self) -> impl Iterator<Item = (BlocklistLookup, u64)> + '_ {
        BlocklistLookup::ALL.into_iter().map(|outcome| {
            (
                outcome,
                self.blocklist_lookups[outcome as usize].load(Ordering::Relaxed),
            )
        })
    }

    pub fn blocklist_fills(&self) -> impl Iterator<Item = (BlocklistFill, u64)> + '_ {
        BlocklistFill::ALL.into_iter().map(|outcome| {
            (
                outcome,
                self.blocklist_fills[outcome as usize].load(Ordering::Relaxed),
            )
        })
    }

    pub fn blocklist_updates(&self) -> impl Iterator<Item = (BlocklistUpdate, u64)> + '_ {
        BlocklistUpdate::ALL.into_iter().map(|outcome| {
            (
                outcome,
                self.blocklist_updates[outcome as usize].load(Ordering::Relaxed),
            )
        })
    }

    pub fn blocklist_evictions(&self) -> u64 {
        self.blocklist_evictions.load(Ordering::Relaxed)
    }

    pub fn blocklist_entries(&self) -> u64 {
        self.blocklist_entries.load(Ordering::Relaxed)
    }

    pub fn blocklist_size_bytes(&self) -> u64 {
        self.blocklist_size_bytes.load(Ordering::Relaxed)
    }

    pub(crate) fn record_blocklist_lookup(&self, outcome: BlocklistLookup) {
        self.blocklist_lookups[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_blocklist_fill(&self, outcome: BlocklistFill) {
        self.blocklist_fills[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_blocklist_update(&self, outcome: BlocklistUpdate) {
        self.blocklist_updates[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_blocklist_eviction(&self) {
        self.blocklist_evictions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn add_blocklist_entries(&self, count: usize, bytes: usize) {
        self.blocklist_entries
            .fetch_add(count as u64, Ordering::Relaxed);
        self.blocklist_size_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn remove_blocklist_entries(&self, count: usize, bytes: usize) {
        self.blocklist_entries
            .fetch_sub(count as u64, Ordering::Relaxed);
        self.blocklist_size_bytes
            .fetch_sub(bytes as u64, Ordering::Relaxed);
    }
}
