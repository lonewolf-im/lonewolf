// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use lonewolf_xmpp::jid::{JidRef, MAX_JID_LEN};
use parking_lot::Mutex as PlMutex;

use super::metrics::{BlocklistFill, BlocklistLookup, BlocklistUpdate, CacheMetrics};
use crate::CommitObserver;
use crate::account::AccountKey;
use crate::blocking::{MAX_BLOCKLIST_ITEM_BYTES, MAX_BLOCKLIST_ITEMS};
use crate::roster::RosterJid;

const SHARDS: usize = 64;
const MAX_ENTRIES: usize = 131_072;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const ENTRY_OVERHEAD: usize = 96;
const RULE_OVERHEAD: usize = 24;

const _: () = assert!(
    ENTRY_OVERHEAD + MAX_JID_LEN + MAX_BLOCKLIST_ITEMS * RULE_OVERHEAD + MAX_BLOCKLIST_ITEM_BYTES
        <= MAX_BYTES / SHARDS / 4
);

pub(crate) type Rules = Arc<[RosterJid]>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Stamp(u64);

pub(crate) enum Lookup {
    Hit(Rules),
    Miss(Stamp),
    Bypass,
}

pub(crate) struct BlocklistCache {
    epoch: AtomicU64,
    disabled: AtomicBool,
    shards: Box<[PlMutex<Shard>]>,
    hasher: RandomState,
    shard_entries: usize,
    shard_bytes: usize,
    metrics: CacheMetrics,
}

#[derive(Default)]
struct Shard {
    entries: HashMap<Arc<str>, Entry>,
    clock: VecDeque<Arc<str>>,
    bytes: usize,
}

struct Entry {
    rules: Rules,
    since: Stamp,
    referenced: Cell<bool>,
    bytes: usize,
}

impl BlocklistCache {
    pub(crate) fn new() -> Self {
        Self::with_limits(SHARDS, MAX_ENTRIES / SHARDS, MAX_BYTES / SHARDS)
    }

    fn with_limits(shards: usize, shard_entries: usize, shard_bytes: usize) -> Self {
        Self {
            epoch: AtomicU64::new(0),
            disabled: AtomicBool::new(false),
            shards: (0..shards)
                .map(|_| PlMutex::new(Shard::default()))
                .collect(),
            hasher: RandomState::new(),
            shard_entries,
            shard_bytes,
            metrics: CacheMetrics::default(),
        }
    }

    fn shard(&self, owner: &str) -> &PlMutex<Shard> {
        &self.shards[self.hasher.hash_one(owner) as usize % self.shards.len()]
    }

    pub(crate) fn metrics(&self) -> &CacheMetrics {
        &self.metrics
    }

    pub(crate) fn disable(&self) {
        if self.disabled.load(Ordering::Acquire) || self.disabled.swap(true, Ordering::AcqRel) {
            return;
        }
        for shard in &self.shards {
            let mut shard = shard.lock();
            self.metrics
                .remove_blocklist_entries(shard.entries.len(), shard.bytes);
            *shard = Shard::default();
        }
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub(crate) fn stamp(&self, before: u64) -> Option<Stamp> {
        // A commit can change the database before it publishes the new rules.
        (before.is_multiple_of(2)
            && before == self.epoch()
            && !self.disabled.load(Ordering::Acquire))
        .then_some(Stamp(before))
    }

    pub(crate) fn lookup(&self, owner: &str, stamp: Option<Stamp>) -> Lookup {
        let result = match stamp {
            Some(stamp) if !self.disabled.load(Ordering::Acquire) => {
                let shard = self.shard(owner).lock();
                if self.disabled.load(Ordering::Acquire) {
                    Lookup::Bypass
                } else {
                    match shard.entries.get(owner) {
                        None => Lookup::Miss(stamp),
                        Some(entry) if entry.since.0 <= stamp.0 => {
                            entry.referenced.set(true);
                            Lookup::Hit(Arc::clone(&entry.rules))
                        }
                        Some(_) => Lookup::Bypass,
                    }
                }
            }
            _ => Lookup::Bypass,
        };
        self.metrics.record_blocklist_lookup(match result {
            Lookup::Hit(_) => BlocklistLookup::Hit,
            Lookup::Miss(_) => BlocklistLookup::Miss,
            Lookup::Bypass => BlocklistLookup::Bypass,
        });
        result
    }

    pub(crate) fn fill(&self, owner: &str, stamp: Stamp, rules: Rules) -> bool {
        let mut shard = self.shard(owner).lock();
        if self.disabled.load(Ordering::Acquire)
            || self.epoch.load(Ordering::Acquire) != stamp.0
            || shard.entries.contains_key(owner)
        {
            self.metrics.record_blocklist_fill(BlocklistFill::Discarded);
            return false;
        }
        self.insert(&mut shard, owner, stamp, rules);
        self.metrics.record_blocklist_fill(BlocklistFill::Inserted);
        true
    }

    pub(crate) fn invalidate(&self, owner: &str) {
        let mut shard = self.shard(owner).lock();
        self.epoch.fetch_add(2, Ordering::AcqRel);
        shard.remove(owner, &self.metrics);
        shard.compact_clock();
    }

    pub(crate) fn commit_observer(
        self: &Arc<Self>,
        changes: Vec<(AccountKey, Option<Rules>)>,
    ) -> BlocklistCommit {
        BlocklistCommit {
            cache: Arc::clone(self),
            changes,
            started: false,
        }
    }

    fn insert(&self, shard: &mut Shard, owner: &str, since: Stamp, rules: Rules) {
        shard.remove(owner, &self.metrics);
        let bytes = ENTRY_OVERHEAD
            + owner.len()
            + rules
                .iter()
                .map(|rule| RULE_OVERHEAD + rule.as_str().len())
                .sum::<usize>();
        let key: Arc<str> = Arc::from(owner);
        shard.clock.push_back(Arc::clone(&key));
        shard.entries.insert(
            key,
            Entry {
                rules,
                since,
                referenced: Cell::new(false),
                bytes,
            },
        );
        shard.bytes += bytes;
        self.metrics.add_blocklist_entries(1, bytes);

        while shard.entries.len() > self.shard_entries || shard.bytes > self.shard_bytes {
            let Some(key) = shard.clock.pop_front() else {
                unreachable!("every cache entry has a CLOCK key");
            };
            let Some((current, entry)) = shard.entries.get_key_value(key.as_ref()) else {
                continue;
            };
            if !Arc::ptr_eq(current, &key) {
                continue;
            }
            if entry.referenced.replace(false) {
                shard.clock.push_back(key);
            } else {
                shard.remove(key.as_ref(), &self.metrics);
                self.metrics.record_blocklist_eviction();
            }
        }
        shard.compact_clock();
    }
}

impl Shard {
    fn remove(&mut self, owner: &str, metrics: &CacheMetrics) {
        if let Some(entry) = self.entries.remove(owner) {
            self.bytes -= entry.bytes;
            metrics.remove_blocklist_entries(1, entry.bytes);
        }
    }

    fn compact_clock(&mut self) {
        if self.clock.len() > 2 * self.entries.len() + 64 {
            self.clock = self.entries.keys().cloned().collect();
        }
    }
}

pub(crate) struct BlocklistCommit {
    cache: Arc<BlocklistCache>,
    changes: Vec<(AccountKey, Option<Rules>)>,
    started: bool,
}

impl CommitObserver for BlocklistCommit {
    fn before_commit(&mut self) {
        let previous = self.cache.epoch.fetch_add(1, Ordering::AcqRel);
        self.started = true;
        debug_assert!(previous.is_multiple_of(2));
    }

    fn after_commit(&mut self, committed: bool) {
        for (owner, rules) in &mut self.changes {
            let owner = owner.as_str();
            let mut shard = self.cache.shard(owner).lock();
            if let Some(rules) = rules
                .take()
                .filter(|_| committed && !self.cache.disabled.load(Ordering::Acquire))
            {
                let since = Stamp(self.cache.epoch() + 1);
                self.cache.insert(&mut shard, owner, since, rules);
                self.cache
                    .metrics
                    .record_blocklist_update(BlocklistUpdate::Written);
            } else {
                shard.remove(owner, &self.cache.metrics);
                shard.compact_clock();
                self.cache
                    .metrics
                    .record_blocklist_update(BlocklistUpdate::Invalidated);
            }
        }
        self.cache.epoch.fetch_add(1, Ordering::AcqRel);
        self.started = false;
    }
}

impl Drop for BlocklistCommit {
    fn drop(&mut self) {
        if self.started {
            self.after_commit(false);
        }
    }
}

pub(crate) fn rules_match(rules: &[RosterJid], peer: JidRef<'_>) -> bool {
    let contains = |candidate: &str| {
        rules
            .binary_search_by(|rule| rule.as_str().cmp(candidate))
            .is_ok()
    };
    let full = peer.as_str();
    let bare = peer.bare().as_str();
    let domain = peer.domainpart();
    contains(full) || (full != bare && contains(bare)) || (bare != domain && contains(domain))
}

#[cfg(test)]
mod tests;
