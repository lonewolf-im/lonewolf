// SPDX-License-Identifier: Apache-2.0

use std::alloc::Layout;
use std::fmt;
use std::num::NonZeroUsize;
use std::ptr::NonNull;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolConfig {
    /// Must be a power of two of at least 8 MiB that fits an allocation layout.
    /// Excludes bookkeeping and heap fallback.
    pub total_bytes: NonZeroUsize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            total_bytes: const { NonZeroUsize::new(DEFAULT_POOL_SIZE).unwrap() },
        }
    }
}

/// Concurrent snapshots are approximate. Allocation counters count successes and saturate.
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

/// Pooled storage remains allocated until the allocator is dropped.
pub struct PooledChunkAllocator {
    config: PoolConfig,
    storage: Chunk,
    buckets: [Mutex<Bucket>; BUCKET_SIZES.len()],
    heap_allocation_count: AtomicU64,
}

impl PooledChunkAllocator {
    /// Preallocates equal capacity per bucket, plus bookkeeping, from the global allocator.
    pub fn try_new(config: PoolConfig) -> Result<Self, PoolError> {
        let total_bytes = config.total_bytes.get();
        if total_bytes < MIN_POOL_SIZE || !total_bytes.is_power_of_two() {
            return Err(PoolError::InvalidConfiguration);
        }
        let layout = Layout::from_size_align(total_bytes, BUCKET_SIZES[BUCKET_SIZES.len() - 1])
            .map_err(|_| PoolError::InvalidConfiguration)?;
        let bucket_bytes = total_bytes / BUCKET_SIZES.len();
        let mut buckets = std::array::from_fn(|_| {
            Mutex::new(Bucket {
                available: Vec::new(),
                allocation_count: 0,
            })
        });
        for (bucket, chunk_bytes) in buckets.iter_mut().zip(BUCKET_SIZES) {
            let bucket = bucket.get_mut().unwrap_or_else(|error| error.into_inner());
            let count = bucket_bytes / chunk_bytes;
            bucket
                .available
                .try_reserve_exact(count)
                .map_err(|_| PoolError::Allocation(AllocationError::Exhausted))?;
            bucket.available.extend((0..count).rev());
        }
        let storage = GlobalChunkAllocator
            .allocate(layout)
            .map_err(PoolError::Allocation)?;
        Ok(Self {
            config,
            storage,
            buckets,
            heap_allocation_count: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> PoolConfig {
        self.config
    }

    pub fn stats(&self) -> PoolStats {
        let bucket_bytes = self.config.total_bytes.get() / BUCKET_SIZES.len();
        PoolStats {
            buckets: std::array::from_fn(|index| {
                let bucket = self.buckets[index]
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                BucketStats {
                    chunk_bytes: BUCKET_SIZES[index],
                    total_chunks: bucket_bytes / BUCKET_SIZES[index],
                    available_chunks: bucket.available.len(),
                    allocation_count: bucket.allocation_count,
                }
            }),
            heap_allocation_count: self.heap_allocation_count.load(Ordering::Relaxed),
        }
    }
}

// Locked free lists give exclusive access to disjoint ranges in the retained allocation.
unsafe impl ChunkAllocator for PooledChunkAllocator {
    /// Tries buckets by increasing size. Pooled chunks are aligned to their full capacity.
    /// If no compatible chunk is available, uses the exact layout from the global allocator.
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        if layout.size() == 0 {
            return Err(AllocationError::UnsupportedLayout);
        }
        let bucket_bytes = self.config.total_bytes.get() / BUCKET_SIZES.len();
        for (index, chunk_bytes) in BUCKET_SIZES.into_iter().enumerate() {
            if chunk_bytes < layout.size() || chunk_bytes < layout.align() {
                continue;
            }
            let chunk_layout = Layout::from_size_align(chunk_bytes, chunk_bytes)
                .map_err(|_| AllocationError::UnsupportedLayout)?;
            let mut bucket = self.buckets[index]
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(slot) = bucket.available.pop() {
                bucket.allocation_count = bucket.allocation_count.saturating_add(1);
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
        let mut count = self.heap_allocation_count.load(Ordering::Relaxed);
        while let Some(next) = count.checked_add(1) {
            match self.heap_allocation_count.compare_exchange_weak(
                count,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => count = current,
            }
        }
        Ok(chunk)
    }

    /// Returns pooled chunks to their original bucket. Frees heap fallback chunks.
    ///
    /// # Safety
    /// Return each chunk once, to its source pool, with its layout intact.
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
        let mut bucket = self.buckets[index]
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // A returned slot vacated one entry, so the preallocated list cannot grow.
        bucket.available.push(slot);
    }
}

impl Drop for PooledChunkAllocator {
    fn drop(&mut self) {
        // Only the whole allocation can be freed; bucket chunks are interior ranges.
        unsafe { std::alloc::dealloc(self.storage.as_ptr(), self.storage.layout()) };
    }
}

struct Bucket {
    available: Vec<usize>,
    allocation_count: u64,
}
