// SPDX-License-Identifier: Apache-2.0

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::num::NonZeroUsize;
use std::ptr;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;

use lonewolf_util::arena::{
    AllocationError, Arena, ArenaConfig, Chunk, ChunkAllocator, ChunkAllocatorHandle, HandleError,
};
use lonewolf_util::pool::{
    DEFAULT_POOL_SIZE, MIN_POOL_SIZE, PoolConfig, PoolError, PooledChunkAllocator,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Default)]
struct Trace {
    enabled: bool,
    fail_at: Option<usize>,
    attempts: usize,
    allocations: usize,
    deallocations: usize,
    allocated_bytes: usize,
    deallocated_bytes: usize,
}

thread_local! {
    static TRACE: Cell<Trace> = const { Cell::new(Trace {
        enabled: false,
        fail_at: None,
        attempts: 0,
        allocations: 0,
        deallocations: 0,
        allocated_bytes: 0,
        deallocated_bytes: 0,
    }) };
}

struct TrackingAllocator;

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

// Thread-local counters cannot allocate, including during thread teardown.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let fail = TRACE
            .try_with(|trace| {
                let mut state = trace.get();
                if !state.enabled {
                    return false;
                }
                state.attempts += 1;
                trace.set(state);
                state.fail_at == Some(state.attempts)
            })
            .unwrap_or(false);
        if fail {
            return ptr::null_mut();
        }
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let _ = TRACE.try_with(|trace| {
                let mut state = trace.get();
                if state.enabled {
                    state.allocations += 1;
                    state.allocated_bytes += layout.size();
                    trace.set(state);
                }
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = TRACE.try_with(|trace| {
            let mut state = trace.get();
            if state.enabled {
                state.deallocations += 1;
                state.deallocated_bytes += layout.size();
                trace.set(state);
            }
        });
        unsafe { System.dealloc(pointer, layout) };
    }
}

fn traced<T>(fail_at: Option<usize>, operation: impl FnOnce() -> T) -> (T, Trace) {
    TRACE.set(Trace {
        enabled: true,
        fail_at,
        ..Trace::default()
    });
    let result = operation();
    (result, TRACE.replace(Trace::default()))
}

fn small_config() -> PoolConfig {
    PoolConfig {
        total_bytes: const { NonZeroUsize::new(MIN_POOL_SIZE).unwrap() },
        ..PoolConfig::default()
    }
}

#[test]
fn default_pool_capacity_is_preallocated_and_split_equally() -> TestResult {
    assert_eq!(PoolConfig::default().total_bytes.get(), DEFAULT_POOL_SIZE);
    assert_eq!(DEFAULT_POOL_SIZE, 256 * 1024 * 1024);
    let (result, trace) = traced(None, || {
        let pool = PooledChunkAllocator::try_new(PoolConfig::default())?;
        Ok::<_, PoolError>((pool.config(), pool.stats()))
    });
    let (config, stats) = result?;
    assert_eq!(config, PoolConfig::default());
    for (bucket, count) in stats
        .buckets
        .iter()
        .zip([8192, 4096, 2048, 1024, 512, 256, 128, 64])
    {
        assert_eq!(bucket.total_chunks, count);
        assert_eq!(bucket.available_chunks, count);
        assert_eq!(bucket.chunk_bytes * count, 32 * 1024 * 1024);
        assert_eq!(bucket.allocation_count, 0);
    }
    assert_eq!(stats.heap_allocation_count, 0);
    assert!(trace.allocated_bytes > DEFAULT_POOL_SIZE);
    assert_eq!(trace.allocations, trace.deallocations);
    assert_eq!(trace.allocated_bytes, trace.deallocated_bytes);
    Ok(())
}

#[test]
fn invalid_configurations_do_not_allocate() -> TestResult {
    for bytes in [
        1,
        MIN_POOL_SIZE / 2,
        MIN_POOL_SIZE + 4096,
        usize::MAX,
        1_usize << (usize::BITS - 1),
    ] {
        let config = PoolConfig {
            total_bytes: NonZeroUsize::new(bytes).ok_or("nonzero size")?,
            ..small_config()
        };
        let (result, trace) = traced(None, || PooledChunkAllocator::try_new(config));
        assert!(matches!(result, Err(PoolError::InvalidConfiguration)));
        assert_eq!(trace.attempts, 0);
    }
    Ok(())
}

#[test]
fn configured_capacity_scales_every_bucket() -> TestResult {
    for multiplier in [1, 2] {
        let config = PoolConfig {
            total_bytes: NonZeroUsize::new(multiplier * MIN_POOL_SIZE).ok_or("nonzero size")?,
            ..small_config()
        };
        let pool = PooledChunkAllocator::try_new(config)?;
        assert_eq!(pool.config(), config);
        for (bucket, count) in pool
            .stats()
            .buckets
            .iter()
            .zip([256, 128, 64, 32, 16, 8, 4, 2])
        {
            assert_eq!(bucket.total_chunks, multiplier * count);
            assert_eq!(bucket.available_chunks, bucket.total_chunks);
            assert_eq!(
                bucket.chunk_bytes * bucket.total_chunks,
                multiplier * 1024 * 1024
            );
        }
    }
    Ok(())
}

#[test]
fn shard_counts_respect_requests_cpu_limits_and_bucket_capacity() -> TestResult {
    let available = thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
    assert_eq!(PoolConfig::default().shards_per_bucket, available);
    for requested in [1, 3, 16, 24, usize::MAX] {
        let pool = PooledChunkAllocator::try_new(PoolConfig {
            shards_per_bucket: NonZeroUsize::new(requested).ok_or("nonzero shards")?,
            ..small_config()
        })?;
        let effective = requested.min(available.get());
        assert_eq!(pool.config().shards_per_bucket.get(), effective);
        for bucket in pool.stats().buckets {
            assert_eq!(bucket.shard_count, effective.min(bucket.total_chunks));
            assert_eq!(bucket.available_chunks, bucket.total_chunks);
        }
    }
    Ok(())
}

#[test]
fn failed_storage_allocation_releases_queue_bookkeeping() -> TestResult {
    let (probe, trace) = traced(None, || PooledChunkAllocator::try_new(small_config()));
    drop(probe?);
    let fail_at = trace.attempts;
    let (result, trace) = traced(Some(fail_at), || {
        PooledChunkAllocator::try_new(small_config())
    });
    assert!(matches!(
        result,
        Err(PoolError::Allocation(AllocationError::Exhausted))
    ));
    assert_eq!(trace.attempts, fail_at);
    assert!(trace.allocations > 0);
    assert_eq!(trace.allocations, trace.deallocations);
    assert_eq!(trace.allocated_bytes, trace.deallocated_bytes);
    Ok(())
}

#[test]
fn bucket_selection_respects_size_alignment_and_full_capacity() -> TestResult {
    let pool = PooledChunkAllocator::try_new(small_config())?;
    for (size, alignment, expected) in [
        (1, 1, 4096),
        (4096, 8, 4096),
        (4097, 1, 8192),
        (8, 16384, 16384),
        (27 * 1024, 8, 32 * 1024),
        (64 * 1024 + 1, 1, 128 * 1024),
        (128 * 1024 + 1, 1, 256 * 1024),
        (512 * 1024, 1, 512 * 1024),
    ] {
        let chunk = pool.allocate(Layout::from_size_align(size, alignment)?)?;
        assert_eq!(chunk.capacity(), expected);
        assert_eq!(chunk.layout().align(), expected);
        assert_eq!(chunk.as_ptr().addr() % expected, 0);
        unsafe {
            chunk.as_ptr().write_bytes(0x5a, chunk.capacity());
            assert_eq!(chunk.as_ptr().add(chunk.capacity() - 1).read(), 0x5a);
            pool.deallocate(chunk);
        }
    }
    assert_eq!(pool.stats().heap_allocation_count, 0);
    Ok(())
}

#[test]
fn all_larger_buckets_are_tried_before_heap_fallback() -> TestResult {
    let pool = PooledChunkAllocator::try_new(small_config())?;
    let before = pool.stats();
    let layout = Layout::new::<u64>();
    let mut chunks = Vec::new();
    for bucket in before.buckets {
        for _ in 0..bucket.total_chunks {
            let chunk = pool.allocate(layout)?;
            assert_eq!(chunk.capacity(), bucket.chunk_bytes);
            unsafe { chunk.as_ptr().cast::<usize>().write(chunks.len()) };
            chunks.push(chunk);
        }
    }
    let exhausted = pool.stats();
    for bucket in exhausted.buckets {
        assert_eq!(bucket.available_chunks, 0);
        assert_eq!(bucket.allocation_count, bucket.total_chunks as u64);
    }
    assert_eq!(exhausted.heap_allocation_count, 0);
    let fallback = pool.allocate(layout)?;
    assert_eq!(fallback.layout(), layout);
    unsafe { pool.deallocate(fallback) };
    assert_eq!(pool.stats().buckets, exhausted.buckets);
    assert_eq!(pool.stats().heap_allocation_count, 1);

    for (index, chunk) in chunks.into_iter().enumerate() {
        assert_eq!(unsafe { chunk.as_ptr().cast::<usize>().read() }, index);
        unsafe { pool.deallocate(chunk) };
    }
    for bucket in pool.stats().buckets {
        assert_eq!(bucket.available_chunks, bucket.total_chunks);
    }
    Ok(())
}

#[test]
fn heap_chunks_with_bucket_layouts_are_not_returned_to_buckets() -> TestResult {
    let pool = PooledChunkAllocator::try_new(small_config())?;
    let layout = Layout::from_size_align(512 * 1024, 512 * 1024)?;
    let first = pool.allocate(layout)?;
    let second = pool.allocate(layout)?;
    let fallback = pool.allocate(layout)?;
    let ((), trace) = traced(None, || unsafe { pool.deallocate(fallback) });
    assert_eq!(trace.deallocated_bytes, layout.size());
    assert_eq!(pool.stats().buckets[7].available_chunks, 0);
    let fallback = pool.allocate(layout)?;
    assert_eq!(pool.stats().heap_allocation_count, 2);
    unsafe {
        pool.deallocate(fallback);
        pool.deallocate(first);
        pool.deallocate(second);
    }
    assert_eq!(pool.stats().buckets[7].available_chunks, 2);
    Ok(())
}

#[test]
fn oversized_and_overaligned_requests_use_exact_heap_layouts() -> TestResult {
    let pool = PooledChunkAllocator::try_new(small_config())?;
    let before = pool.stats();
    for layout in [
        Layout::from_size_align(512 * 1024 + 1, 8)?,
        Layout::from_size_align(8, 1024 * 1024)?,
    ] {
        let (result, trace) = traced(None, || {
            let chunk = pool.allocate(layout)?;
            let returned_layout = chunk.layout();
            unsafe { pool.deallocate(chunk) };
            Ok::<_, AllocationError>(returned_layout)
        });
        assert_eq!(result?, layout);
        assert_eq!(trace.allocations, 1);
        assert_eq!(trace.deallocations, 1);
        assert_eq!(trace.allocated_bytes, layout.size());
        assert_eq!(trace.deallocated_bytes, layout.size());
    }
    assert_eq!(pool.stats().buckets, before.buckets);
    assert_eq!(pool.stats().heap_allocation_count, 2);
    Ok(())
}

#[test]
fn zero_sized_requests_do_not_change_the_pool() -> TestResult {
    let pool = PooledChunkAllocator::try_new(small_config())?;
    let before = pool.stats();
    let (result, trace) = traced(None, || pool.allocate(Layout::new::<()>()));
    assert!(matches!(result, Err(AllocationError::UnsupportedLayout)));
    assert_eq!(trace.attempts, 0);
    assert_eq!(pool.stats(), before);
    Ok(())
}

#[test]
fn moving_the_allocator_preserves_outstanding_chunks() -> TestResult {
    let pool = PooledChunkAllocator::try_new(small_config())?;
    let chunk = pool.allocate(Layout::new::<u64>())?;
    unsafe { chunk.as_ptr().cast::<u64>().write(42) };
    let shared: Arc<dyn ChunkAllocator> = Arc::new(pool);
    thread::spawn(move || {
        assert_eq!(unsafe { chunk.as_ptr().cast::<u64>().read() }, 42);
        unsafe { shared.deallocate(chunk) };
    })
    .join()
    .expect("reader completed");
    Ok(())
}

#[test]
fn failed_heap_fallback_preserves_pool_state_and_can_be_retried() -> TestResult {
    let pool = PooledChunkAllocator::try_new(small_config())?;
    let layout = Layout::from_size_align(512 * 1024, 8)?;
    let first = pool.allocate(layout)?;
    let second = pool.allocate(layout)?;
    let before = pool.stats();
    let (result, trace) = traced(Some(1), || pool.allocate(layout));
    assert!(matches!(result, Err(AllocationError::Exhausted)));
    assert_eq!(trace.attempts, 1);
    assert_eq!(trace.allocations, 0);
    assert_eq!(pool.stats(), before);
    let fallback = pool.allocate(layout)?;
    assert_eq!(pool.stats().heap_allocation_count, 1);
    unsafe {
        pool.deallocate(first);
        pool.deallocate(second);
        pool.deallocate(fallback);
    }
    Ok(())
}

#[test]
fn arena_reuse_needs_no_heap_allocations_after_producer_setup() -> TestResult {
    let pool = Arc::new(PooledChunkAllocator::try_new(small_config())?);
    let allocator = ChunkAllocatorHandle::new(pool.clone());
    let (result, trace) = traced(None, || {
        for _ in 0..32 {
            let mut arena = Arena::try_new_in(ArenaConfig::default(), allocator.clone())?;
            let text = arena.try_alloc_str("example.com")?;
            let bytes = arena.try_alloc_slice_fill(5000, 7_u8)?;
            let shared = arena.freeze();
            let recipient = shared.clone();
            drop(shared);
            assert_eq!(recipient.get(text)?, "example.com");
            assert_eq!(recipient.get(bytes)?[4999], 7);
            drop(recipient);
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    });
    result?;
    assert_eq!(trace.attempts, 0);
    assert_eq!(trace.deallocations, 0);
    assert_eq!(pool.stats().heap_allocation_count, 0);
    for bucket in pool.stats().buckets {
        assert_eq!(bucket.available_chunks, bucket.total_chunks);
    }
    Ok(())
}

#[test]
fn concurrent_allocations_can_return_on_another_thread() -> TestResult {
    let pool = Arc::new(PooledChunkAllocator::try_new(small_config())?);
    let heap_layout = Layout::from_size_align(size_of::<u64>(), 1024 * 1024)?;
    let (sender, receiver) = mpsc::sync_channel::<(Chunk, u64)>(8);
    thread::scope(|scope| {
        let reader_pool = pool.clone();
        scope.spawn(move || {
            for (chunk, value) in receiver {
                assert_eq!(unsafe { chunk.as_ptr().cast::<u64>().read() }, value);
                unsafe { reader_pool.deallocate(chunk) };
            }
        });
        for worker in 0..4_u64 {
            let sender = sender.clone();
            let pool = pool.clone();
            scope.spawn(move || {
                for iteration in 0..64 {
                    let value = worker * 64 + iteration;
                    let layout = if iteration % 2 == 0 {
                        Layout::new::<u64>()
                    } else {
                        heap_layout
                    };
                    let chunk = pool.allocate(layout).expect("chunk allocation");
                    unsafe { chunk.as_ptr().cast::<u64>().write(value) };
                    sender.send((chunk, value)).expect("live consumer");
                }
            });
        }
        drop(sender);
    });
    let stats = pool.stats();
    assert_eq!(stats.heap_allocation_count, 128);
    assert_eq!(stats.buckets[0].allocation_count, 128);
    for bucket in stats.buckets {
        assert_eq!(bucket.available_chunks, bucket.total_chunks);
    }
    Ok(())
}

#[test]
fn concurrent_returns_restore_every_slot_after_queue_wraparound() -> TestResult {
    let pool = PooledChunkAllocator::try_new(small_config())?;
    let barrier = Barrier::new(4);
    thread::scope(|scope| {
        for worker in 0..4 {
            let pool = &pool;
            let barrier = &barrier;
            scope.spawn(move || {
                for round in 0..4 {
                    let chunks = std::array::from_fn::<_, 64, _>(|slot| {
                        let chunk = pool.allocate(Layout::new::<usize>()).expect("chunk");
                        let value = round * 256 + worker * 64 + slot;
                        unsafe { chunk.as_ptr().cast::<usize>().write(value) };
                        chunk
                    });
                    barrier.wait();
                    for (slot, chunk) in chunks.into_iter().enumerate() {
                        let value = round * 256 + worker * 64 + slot;
                        assert_eq!(unsafe { chunk.as_ptr().cast::<usize>().read() }, value);
                        unsafe { pool.deallocate(chunk) };
                    }
                    barrier.wait();
                }
            });
        }
    });
    let stats = pool.stats();
    assert_eq!(stats.heap_allocation_count, 0);
    assert_eq!(stats.buckets[0].allocation_count, 1024);
    for bucket in stats.buckets {
        assert_eq!(bucket.available_chunks, bucket.total_chunks);
    }
    Ok(())
}

#[test]
fn arena_can_own_its_pool_inside_pooled_storage() -> TestResult {
    let (result, trace) = traced(None, || {
        let pool = PooledChunkAllocator::try_new(small_config())?;
        let mut arena = Arena::try_new_in(ArenaConfig::default(), pool)?;
        let text = arena.try_alloc_str("example.com")?;
        let bytes = arena.try_alloc_slice_fill(17 * 1024, 3_u8)?;
        let frozen = arena.freeze();
        let recipient = frozen.clone();
        drop(frozen);
        assert_eq!(recipient.get(text)?, "example.com");
        assert_eq!(recipient.get(bytes)?[17 * 1024 - 1], 3);
        drop(recipient);
        Ok::<_, Box<dyn std::error::Error>>(())
    });
    result?;
    assert_eq!(trace.allocations, trace.deallocations);
    assert_eq!(trace.allocated_bytes, trace.deallocated_bytes);
    Ok(())
}

#[test]
fn frozen_arena_returns_chunks_after_the_last_recipient() -> TestResult {
    let pool = Arc::new(PooledChunkAllocator::try_new(small_config())?);
    let backend: Arc<dyn ChunkAllocator> = pool.clone();
    let mut arena = Arena::try_new_in(ArenaConfig::default(), ChunkAllocatorHandle::new(backend))?;
    let text = arena.try_alloc_str("example.com")?;
    let bytes = arena.try_alloc_slice_fill(5000, 9_u8)?;
    let frozen = arena.freeze();
    let borrowed = pool.stats().buckets;
    let barrier = Barrier::new(3);
    thread::scope(|scope| {
        for _ in 0..2 {
            let recipient = frozen.clone();
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                assert_eq!(recipient.get(text), Ok("example.com"));
                assert_eq!(recipient.get(bytes).map(|bytes| bytes[4999]), Ok(9));
            });
        }
        drop(frozen);
        assert_eq!(pool.stats().buckets, borrowed);
        barrier.wait();
    });
    for bucket in pool.stats().buckets {
        assert_eq!(bucket.available_chunks, bucket.total_chunks);
    }
    Ok(())
}

#[test]
fn live_views_survive_neighbor_reuse_and_old_handles_stay_invalid() -> TestResult {
    let pool = Arc::new(PooledChunkAllocator::try_new(small_config())?);
    let mut first = Arena::try_new_in(ArenaConfig::default(), pool.clone())?;
    let first_text = first.try_alloc_str("first")?;
    let view = first.get(first_text)?;
    let mut second = Arena::try_new_in(ArenaConfig::default(), pool.clone())?;
    let old_text = second.try_alloc_str("second")?;
    let old_address = second.get(old_text)?.as_ptr();
    drop(second);
    let mut reused = false;
    for _ in 0..pool.stats().buckets[0].total_chunks {
        let mut third = Arena::try_new_in(ArenaConfig::default(), pool.clone())?;
        let new_text = third.try_alloc_str("third")?;
        assert_eq!(third.get(old_text), Err(HandleError::WrongArena));
        assert_eq!(view, "first");
        assert_eq!(third.get(new_text)?, "third");
        if third.get(new_text)?.as_ptr() == old_address {
            reused = true;
            break;
        }
    }
    assert!(reused);
    Ok(())
}
