// SPDX-License-Identifier: Apache-2.0

//! Reuses fixed-size chunks across threads and falls back to the global heap.
//!
//! Configured capacity covers pooled chunks; heap fallback can exceed it.

use std::alloc::Layout;
use std::fmt;
use std::num::NonZeroUsize;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crossbeam_queue::ArrayQueue;
use crossbeam_utils::CachePadded;

use crate::arena::{AllocationError, Chunk, ChunkAllocator, GlobalChunkAllocator};

pub const BUCKET_SIZES: [usize; 8] = [
    4 * 1024,
    8 * 1024,
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
];
pub const MIN_POOL_SIZE: usize = 8 * 1024 * 1024;
pub const DEFAULT_POOL_SIZE: usize = 256 * 1024 * 1024;

static NEXT_SHARD_HINT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static SHARD_HINT: usize = NEXT_SHARD_HINT.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolConfig {
    /// Excludes bookkeeping and heap fallback allocations.
    ///
    /// Must be a power of two of at least 8 MiB that fits an allocation layout.
    pub total_bytes: NonZeroUsize,
    /// Capped by available CPU parallelism and each bucket's chunk count.
    pub shards_per_bucket: NonZeroUsize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            total_bytes: const { NonZeroUsize::new(DEFAULT_POOL_SIZE).unwrap() },
            shards_per_bucket: available_shards(),
        }
    }
}

fn available_shards() -> NonZeroUsize {
    std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN)
}

/// Reports approximate counts during concurrent allocations and returns.
///
/// Allocation counters count successes and saturate at [`u64::MAX`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolStats {
    /// Ordered by increasing chunk size.
    pub buckets: [BucketStats; BUCKET_SIZES.len()],
    /// Excludes pool initialization.
    pub heap_allocation_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BucketStats {
    pub chunk_bytes: usize,
    pub total_chunks: usize,
    pub shard_count: usize,
    pub available_chunks: usize,
    pub allocation_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolError {
    InvalidConfiguration,
    Allocation(AllocationError),
}

impl fmt::Display for PoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => formatter.write_str("invalid pool configuration"),
            Self::Allocation(error) => write!(formatter, "pool allocation failed: {error}"),
        }
    }
}

impl std::error::Error for PoolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfiguration => None,
            Self::Allocation(error) => Some(error),
        }
    }
}

/// Retains pooled storage until the allocator drops, even when all chunks return.
pub struct PooledChunkAllocator {
    config: PoolConfig,
    storage: Chunk,
    buckets: [Bucket; BUCKET_SIZES.len()],
    // Alignment separates allocator metadata from an enclosing shared reference count.
    heap_allocation_count: CachePadded<AtomicU64>,
}

impl PooledChunkAllocator {
    /// Preallocates equal byte capacity per bucket from the global allocator.
    ///
    /// Bookkeeping needs extra capacity; its allocation failure uses the global
    /// allocation error handler.
    ///
    /// # Errors
    ///
    /// Returns [`PoolError::InvalidConfiguration`] if `total_bytes` violates
    /// [`PoolConfig::total_bytes`], or [`PoolError::Allocation`] if allocation
    /// of the chunk storage fails.
    pub fn try_new(mut config: PoolConfig) -> Result<Self, PoolError> {
        let total_bytes = config.total_bytes.get();
        if total_bytes < MIN_POOL_SIZE || !total_bytes.is_power_of_two() {
            return Err(PoolError::InvalidConfiguration);
        }
        let layout = Layout::from_size_align(total_bytes, BUCKET_SIZES[BUCKET_SIZES.len() - 1])
            .map_err(|_| PoolError::InvalidConfiguration)?;
        let bucket_bytes = total_bytes / BUCKET_SIZES.len();
        config.shards_per_bucket = config.shards_per_bucket.min(available_shards());
        let buckets = std::array::from_fn(|index| {
            Bucket::new(bucket_bytes / BUCKET_SIZES[index], config.shards_per_bucket)
        });
        let storage = GlobalChunkAllocator
            .allocate(layout)
            .map_err(PoolError::Allocation)?;
        Ok(Self {
            config,
            storage,
            buckets,
            heap_allocation_count: CachePadded::new(AtomicU64::new(0)),
        })
    }

    /// Includes the CPU cap applied at construction.
    ///
    /// Per-bucket chunk limits can reduce the actual shard counts further;
    /// [`Self::stats`] reports those counts.
    pub fn config(&self) -> PoolConfig {
        self.config
    }

    /// Reads counters independently without stopping allocations or returns.
    ///
    /// Concurrent changes can prevent the fields from describing one instant.
    pub fn stats(&self) -> PoolStats {
        let bucket_bytes = self.config.total_bytes.get() / BUCKET_SIZES.len();
        PoolStats {
            buckets: std::array::from_fn(|index| {
                let bucket = &self.buckets[index];
                let (available_chunks, allocation_count) =
                    bucket
                        .shards
                        .iter()
                        .fold((0, 0_u64), |(available, allocations), shard| {
                            (
                                available + shard.available.len(),
                                allocations
                                    .saturating_add(shard.allocation_count.load(Ordering::Relaxed)),
                            )
                        });
                BucketStats {
                    chunk_bytes: BUCKET_SIZES[index],
                    total_chunks: bucket_bytes / BUCKET_SIZES[index],
                    shard_count: bucket.shards.len(),
                    available_chunks,
                    allocation_count,
                }
            }),
            heap_allocation_count: self.heap_allocation_count.load(Ordering::Relaxed),
        }
    }
}

// Each queued slot grants exclusive access to a disjoint range in the retained allocation.
unsafe impl ChunkAllocator for PooledChunkAllocator {
    /// Tries compatible buckets by increasing size before using the global heap.
    ///
    /// Pooled chunks are aligned to their full capacity. Heap fallback uses
    /// the exact requested layout.
    ///
    /// # Errors
    ///
    /// Returns [`AllocationError::UnsupportedLayout`] for a zero-sized layout
    /// or [`AllocationError::Exhausted`] if heap fallback allocation fails.
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        if layout.size() == 0 {
            return Err(AllocationError::UnsupportedLayout);
        }
        let bucket_bytes = self.config.total_bytes.get() / BUCKET_SIZES.len();
        let preferred_shard = SHARD_HINT.with(|hint| *hint);
        for (index, chunk_bytes) in BUCKET_SIZES.into_iter().enumerate() {
            if chunk_bytes < layout.size() || chunk_bytes < layout.align() {
                continue;
            }
            let chunk_layout = Layout::from_size_align(chunk_bytes, chunk_bytes)
                .map_err(|_| AllocationError::UnsupportedLayout)?;
            let bucket = &self.buckets[index];
            if let Some(slot) = bucket.pop(preferred_shard) {
                let offset = index * bucket_bytes + slot * chunk_bytes;
                // Bucket boundaries and slot strides preserve the chunk's alignment.
                return Ok(unsafe {
                    Chunk::from_raw_parts(
                        NonNull::new_unchecked(self.storage.as_ptr().add(offset)),
                        chunk_layout,
                    )
                });
            }
        }
        let chunk = GlobalChunkAllocator.allocate(layout)?;
        increment_saturating(&self.heap_allocation_count);
        Ok(chunk)
    }

    /// Returns pooled chunks to their original bucket and frees heap chunks.
    ///
    /// # Safety
    ///
    /// Each chunk must return once to its source pool with its layout intact.
    /// No references or pending accesses may remain.
    unsafe fn deallocate(&self, chunk: Chunk) {
        let offset = chunk
            .as_ptr()
            .addr()
            .checked_sub(self.storage.as_ptr().addr())
            .filter(|offset| *offset < self.storage.capacity());
        let Some(offset) = offset else {
            unsafe { GlobalChunkAllocator.deallocate(chunk) };
            return;
        };
        let bucket_bytes = self.config.total_bytes.get() / BUCKET_SIZES.len();
        let index = offset / bucket_bytes;
        let slot = (offset % bucket_bytes) / BUCKET_SIZES[index];
        self.buckets[index].push(slot);
    }
}

impl Drop for PooledChunkAllocator {
    fn drop(&mut self) {
        // Only the whole allocation can be freed; bucket chunks are interior ranges.
        unsafe { std::alloc::dealloc(self.storage.as_ptr(), self.storage.layout()) };
    }
}

struct Bucket {
    shards: Box<[Shard]>,
}

impl Bucket {
    fn new(chunk_count: usize, requested_shards: NonZeroUsize) -> Self {
        let shard_count = chunk_count.min(requested_shards.get());
        let chunks_per_shard = chunk_count / shard_count;
        let shards = (0..shard_count)
            .map(|index| {
                let capacity = chunks_per_shard + usize::from(index < chunk_count % shard_count);
                let available = ArrayQueue::new(capacity);
                for slot in (index..chunk_count).step_by(shard_count) {
                    assert!(available.push(slot).is_ok());
                }
                Shard {
                    available,
                    allocation_count: CachePadded::new(AtomicU64::new(0)),
                }
            })
            .collect();
        Self { shards }
    }

    fn pop(&self, preferred_shard: usize) -> Option<usize> {
        let start = preferred_shard % self.shards.len();
        for shard in self.shards[start..].iter().chain(&self.shards[..start]) {
            if let Some(slot) = shard.available.pop() {
                increment_saturating(&shard.allocation_count);
                return Some(slot);
            }
        }
        None
    }

    fn push(&self, slot: usize) {
        let shard = &self.shards[slot % self.shards.len()];
        // Each outstanding chunk leaves one free entry in its source queue.
        assert!(shard.available.push(slot).is_ok());
    }
}

struct Shard {
    available: ArrayQueue<usize>,
    allocation_count: CachePadded<AtomicU64>,
}

fn increment_saturating(counter: &AtomicU64) {
    let mut count = counter.load(Ordering::Relaxed);
    while let Some(next) = count.checked_add(1) {
        match counter.compare_exchange_weak(count, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(current) => count = current,
        }
    }
}

#[cfg(test)]
mod tests {
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
}
