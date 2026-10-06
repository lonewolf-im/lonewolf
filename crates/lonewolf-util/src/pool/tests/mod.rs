// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::sync::atomic::Ordering;

use super::{Bucket, MIN_POOL_SIZE, PoolConfig, PoolError, PooledChunkAllocator};

#[test]
fn arbitrary_shards_preserve_every_slot_across_wraparound_and_returns() {
    for count in [2, 4, 8, 16, 32, 256] {
        for requested in [1, 3, 16, 24, usize::MAX] {
            let bucket = Bucket::new(count, NonZeroUsize::new(requested).expect("shards"));
            let shard_count = count.min(requested);
            assert_eq!(bucket.shards.len(), shard_count);
            for (index, shard) in bucket.shards.iter().enumerate() {
                assert_eq!(
                    shard.available.capacity(),
                    count / shard_count + usize::from(index < count % shard_count),
                );
            }
            for hint in [0, 23, usize::MAX] {
                let mut seen = [false; 256];
                for _ in 0..count {
                    let slot = bucket.pop(hint).expect("available slot");
                    assert!(slot < count);
                    assert!(!seen[slot]);
                    seen[slot] = true;
                }
                assert_eq!(bucket.pop(hint), None);
                for slot in (0..count).rev() {
                    bucket.push(slot);
                }
                for shard in &bucket.shards {
                    assert_eq!(shard.available.len(), shard.available.capacity());
                }
            }
        }
    }
}

#[test]
fn statistics_saturate_when_shard_counters_overflow_the_total() -> Result<(), PoolError> {
    let mut pool = PooledChunkAllocator::try_new(PoolConfig {
        total_bytes: const { NonZeroUsize::new(MIN_POOL_SIZE).unwrap() },
        ..PoolConfig::default()
    })?;
    pool.buckets[0] = Bucket::new(256, const { NonZeroUsize::new(2).unwrap() });
    let shards = &pool.buckets[0].shards;
    shards[0]
        .allocation_count
        .store(u64::MAX - 1, Ordering::Relaxed);
    shards[1].allocation_count.store(2, Ordering::Relaxed);
    let stats = pool.stats().buckets[0];
    assert_eq!(stats.allocation_count, u64::MAX);
    assert_eq!(stats.available_chunks, stats.total_chunks);
    Ok(())
}

mod behavior;
