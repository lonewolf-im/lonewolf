// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::tests::{TestResult, jid, key};

const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
const CAROL: &str = "carol@example.test";

fn new_cache() -> Arc<BlocklistCache> {
    Arc::new(BlocklistCache::new())
}

fn stamp(cache: &BlocklistCache) -> Option<Stamp> {
    cache.stamp(cache.epoch())
}

fn update(cache: &Arc<BlocklistCache>, owner: &str, peer: &str) -> TestResult {
    let mut observer = cache.commit_observer(vec![(key(owner)?, Some(Arc::from([jid(peer)?])))]);
    observer.before_commit();
    observer.after_commit(true);
    Ok(())
}

#[test]
fn lookup_ignores_entries_newer_than_the_snapshot() -> TestResult {
    let cache = new_cache();
    let old = stamp(&cache);
    update(&cache, ALICE, BOB)?;
    let current = stamp(&cache);
    assert!(matches!(cache.lookup(ALICE, old), Lookup::Bypass));
    assert!(matches!(cache.lookup(ALICE, current), Lookup::Hit(_)));
    Ok(())
}

#[test]
fn fill_is_discarded_after_the_epoch_moves() -> TestResult {
    let cache = new_cache();
    let stamp = stamp(&cache).ok_or("missing stamp")?;
    update(&cache, CAROL, BOB)?;
    assert!(!cache.fill(ALICE, stamp, Arc::from([])));
    assert_eq!(cache.metrics.blocklist_entries(), 1);
    assert_eq!(
        cache.metrics.blocklist_fills().collect::<Vec<_>>(),
        [(BlocklistFill::Inserted, 0), (BlocklistFill::Discarded, 1),]
    );
    Ok(())
}

#[test]
fn fill_never_replaces_an_existing_entry() -> TestResult {
    let cache = new_cache();
    let stamp = stamp(&cache).ok_or("missing stamp")?;
    assert!(cache.fill(ALICE, stamp, Arc::from([])));
    assert!(!cache.fill(ALICE, stamp, Arc::from([jid(BOB)?])));
    assert!(matches!(cache.lookup(ALICE, Some(stamp)), Lookup::Hit(rules) if rules.is_empty()));
    assert_eq!(cache.metrics.blocklist_entries(), 1);
    Ok(())
}

#[test]
fn invalidate_discards_a_racing_fill() -> TestResult {
    let cache = new_cache();
    let old = stamp(&cache).ok_or("missing stamp")?;
    cache.invalidate(ALICE);
    assert!(!cache.fill(ALICE, old, Arc::from([])));
    assert!(matches!(
        cache.lookup(ALICE, stamp(&cache)),
        Lookup::Miss(_)
    ));
    assert_eq!(cache.metrics.blocklist_entries(), 0);
    Ok(())
}

#[test]
fn invalidate_during_a_commit_keeps_the_epoch_parity() -> TestResult {
    let cache = new_cache();
    update(&cache, CAROL, BOB)?;
    let mut observer = cache.commit_observer(vec![(key(ALICE)?, Some(Arc::from([jid(BOB)?])))]);
    observer.before_commit();
    let odd = cache.epoch();
    assert!(!odd.is_multiple_of(2));
    cache.invalidate(CAROL);
    assert_eq!(cache.epoch(), odd + 2);
    assert_eq!(stamp(&cache), None);
    observer.after_commit(true);
    assert_eq!(cache.epoch(), odd + 3);
    let current = stamp(&cache).ok_or("missing stamp")?;
    assert!(matches!(cache.lookup(ALICE, Some(current)), Lookup::Hit(_)));
    assert!(matches!(
        cache.lookup(CAROL, Some(current)),
        Lookup::Miss(_)
    ));
    Ok(())
}

#[test]
fn failed_commit_removes_changed_owners_and_restores_an_even_epoch() -> TestResult {
    let cache = new_cache();
    update(&cache, ALICE, BOB)?;
    update(&cache, CAROL, BOB)?;
    let mut observer = cache.commit_observer(vec![(key(ALICE)?, Some(Arc::from([])))]);
    observer.before_commit();
    observer.after_commit(false);
    let stamp = stamp(&cache);
    assert!(stamp.is_some());
    assert!(matches!(cache.lookup(ALICE, stamp), Lookup::Miss(_)));
    assert!(matches!(cache.lookup(CAROL, stamp), Lookup::Hit(_)));
    assert_eq!(cache.metrics.blocklist_entries(), 1);
    assert_eq!(
        cache.metrics.blocklist_updates().collect::<Vec<_>>(),
        [
            (BlocklistUpdate::Written, 2),
            (BlocklistUpdate::Invalidated, 1),
        ]
    );
    Ok(())
}

#[test]
fn dropped_observer_after_before_commit_invalidates_changed_owners() -> TestResult {
    let cache = new_cache();
    update(&cache, ALICE, BOB)?;
    let mut observer = cache.commit_observer(vec![(key(ALICE)?, Some(Arc::from([])))]);
    observer.before_commit();
    drop(observer);
    let stamp = stamp(&cache);
    assert!(stamp.is_some());
    assert!(matches!(cache.lookup(ALICE, stamp), Lookup::Miss(_)));
    assert_eq!(cache.metrics.blocklist_entries(), 0);
    assert_eq!(cache.metrics.blocklist_size_bytes(), 0);
    Ok(())
}

#[test]
fn stamp_is_absent_while_a_commit_runs_or_when_the_epoch_moves() -> TestResult {
    let cache = new_cache();
    let before = cache.epoch();
    let mut observer = cache.commit_observer(vec![(key(ALICE)?, None)]);
    observer.before_commit();
    assert_eq!(stamp(&cache), None);
    observer.after_commit(true);
    assert_eq!(cache.stamp(before), None);
    assert!(stamp(&cache).is_some());
    Ok(())
}

#[test]
fn eviction_keeps_each_shard_within_its_entry_and_byte_limits() -> TestResult {
    let empty_list_bytes = ENTRY_OVERHEAD + CAROL.len();
    for (max_entries, max_bytes) in [(2, usize::MAX), (usize::MAX, 2 * empty_list_bytes)] {
        let cache = BlocklistCache::with_limits(1, max_entries, max_bytes);
        let stamp = stamp(&cache).ok_or("missing stamp")?;
        for owner in [ALICE, BOB, CAROL] {
            assert!(cache.fill(owner, stamp, Arc::from([])));
            let shard = cache.shard(owner).lock();
            assert!(shard.entries.len() <= max_entries);
            assert!(shard.bytes <= max_bytes);
            assert_eq!(
                cache.metrics.blocklist_entries(),
                shard.entries.len() as u64
            );
            assert_eq!(cache.metrics.blocklist_size_bytes(), shard.bytes as u64);
        }
        assert_eq!(cache.metrics.blocklist_entries(), 2);
        assert_eq!(cache.metrics.blocklist_evictions(), 1);
    }
    Ok(())
}

#[test]
fn referenced_entries_survive_one_eviction_pass() -> TestResult {
    let cache = Arc::new(BlocklistCache::with_limits(1, 2, usize::MAX));
    let stamp = stamp(&cache).ok_or("missing stamp")?;
    assert!(cache.fill(ALICE, stamp, Arc::from([])));
    assert!(cache.fill(BOB, stamp, Arc::from([])));
    assert!(matches!(cache.lookup(ALICE, Some(stamp)), Lookup::Hit(_)));
    assert!(cache.fill(CAROL, stamp, Arc::from([])));
    assert!(matches!(cache.lookup(BOB, Some(stamp)), Lookup::Miss(_)));
    assert!(matches!(cache.lookup(ALICE, Some(stamp)), Lookup::Hit(_)));
    Ok(())
}

#[test]
fn stale_clock_keys_are_skipped_and_compacted() -> TestResult {
    let cache = Arc::new(BlocklistCache::with_limits(1, 2, usize::MAX));
    update(&cache, ALICE, BOB)?;
    update(&cache, BOB, CAROL)?;
    update(&cache, ALICE, CAROL)?;
    let stamp = stamp(&cache).ok_or("missing stamp")?;
    assert!(cache.fill(CAROL, stamp, Arc::from([])));
    assert!(matches!(cache.lookup(ALICE, Some(stamp)), Lookup::Hit(_)));
    assert!(matches!(cache.lookup(BOB, Some(stamp)), Lookup::Miss(_)));

    for _ in 0..100 {
        update(&cache, ALICE, BOB)?;
        let shard = cache.shard(ALICE).lock();
        assert!(shard.clock.len() <= 2 * shard.entries.len() + 64);
    }
    assert_eq!(cache.metrics.blocklist_entries(), 2);
    assert_eq!(cache.metrics.blocklist_evictions(), 1);
    Ok(())
}

#[test]
fn disabling_rejects_pending_fills_and_commit_updates() -> TestResult {
    let cache = new_cache();
    update(&cache, ALICE, BOB)?;
    let stamp = stamp(&cache).ok_or("missing stamp")?;
    assert!(matches!(cache.lookup(CAROL, Some(stamp)), Lookup::Miss(_)));
    let mut observer = cache.commit_observer(vec![(key(ALICE)?, Some(Arc::from([jid(CAROL)?])))]);
    observer.before_commit();
    cache.disable();
    assert!(!cache.fill(CAROL, stamp, Arc::from([])));
    observer.after_commit(true);
    assert_eq!(cache.stamp(cache.epoch()), None);
    assert!(matches!(cache.lookup(ALICE, Some(stamp)), Lookup::Bypass));
    assert!(cache.shard(ALICE).lock().clock.is_empty());
    assert_eq!(cache.metrics.blocklist_entries(), 0);
    assert_eq!(cache.metrics.blocklist_size_bytes(), 0);
    Ok(())
}
