// SPDX-License-Identifier: Apache-2.0

use std::alloc::Layout;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use lonewolf_util::arena::{
    AllocationError, Arena, ArenaConfig, ArenaError, Chunk, ChunkAllocator, GlobalChunkAllocator,
    Handle, HandleError, SharedArena,
};

fn assert_send<T: Send>() {}

fn assert_send_sync_static<T: Send + Sync + 'static>() {}

fn assert_copy<T: Copy>() {}

#[test]
fn owners_support_cross_thread_handoff() {
    assert_send::<Arena>();
    assert_send_sync_static::<Chunk>();
    assert_send_sync_static::<SharedArena>();
}

#[test]
fn arenas_accept_a_shared_allocator() {
    fn assert_allocator<A: ChunkAllocator>() {}

    type SharedAllocator = Arc<dyn ChunkAllocator>;

    assert_allocator::<SharedAllocator>();
    assert_send::<Arena<SharedAllocator>>();
    assert_send_sync_static::<SharedArena<SharedAllocator>>();

    let _: fn(ArenaConfig, SharedAllocator) -> Result<Arena<SharedAllocator>, ArenaError> =
        Arena::try_new_in;
}

#[test]
fn allocation_handles_are_copyable_across_threads() {
    assert_copy::<Handle<u64>>();
    assert_copy::<Handle<str>>();
    assert_copy::<Handle<[u8]>>();
    assert_send_sync_static::<Handle<u64>>();
    assert_send_sync_static::<Handle<str>>();
    assert_send_sync_static::<Handle<[u8]>>();
}

#[test]
fn shared_views_can_cross_await_in_a_send_future() {
    fn assert_future<F: Future<Output = Result<usize, HandleError>> + Send + 'static>(_future: F) {}

    let _check = |arena: SharedArena<Arc<dyn ChunkAllocator>>, handle: Handle<str>| {
        assert_future(async move {
            let text = arena.get(handle)?;
            std::future::ready(()).await;
            Ok(text.len())
        });
    };
}

fn config(chunk_size: usize, limit: usize) -> ArenaConfig {
    ArenaConfig {
        chunk_size: NonZeroUsize::new(chunk_size).expect("nonzero test chunk size"),
        max_reserved_bytes: NonZeroUsize::new(limit).expect("nonzero test limit"),
    }
}

#[derive(Default)]
struct AllocatorState {
    requests: AtomicUsize,
    allocations: AtomicUsize,
    deallocations: AtomicUsize,
    live_bytes: AtomicUsize,
    drops: AtomicUsize,
    extra_bytes: AtomicUsize,
    last_request: AtomicUsize,
    fail_next: AtomicBool,
}

struct TestAllocator(Arc<AllocatorState>);

// Extra capacity is backed by the returned layout. Counters use atomic access.
unsafe impl ChunkAllocator for TestAllocator {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        self.0.requests.fetch_add(1, Ordering::Relaxed);
        self.0.last_request.store(layout.size(), Ordering::Relaxed);
        if self.0.fail_next.swap(false, Ordering::Relaxed) {
            return Err(AllocationError::Exhausted);
        }
        let size = layout
            .size()
            .checked_add(self.0.extra_bytes.load(Ordering::Relaxed))
            .ok_or(AllocationError::UnsupportedLayout)?;
        let returned = Layout::from_size_align(size, layout.align())
            .map_err(|_| AllocationError::UnsupportedLayout)?;
        let chunk = GlobalChunkAllocator.allocate(returned)?;
        self.0.allocations.fetch_add(1, Ordering::Relaxed);
        self.0.live_bytes.fetch_add(size, Ordering::Relaxed);
        Ok(chunk)
    }

    unsafe fn deallocate(&self, chunk: Chunk) {
        self.0.deallocations.fetch_add(1, Ordering::Relaxed);
        self.0
            .live_bytes
            .fetch_sub(chunk.capacity(), Ordering::Relaxed);
        unsafe { GlobalChunkAllocator.deallocate(chunk) };
    }
}

impl Drop for TestAllocator {
    fn drop(&mut self) {
        assert_eq!(self.0.live_bytes.load(Ordering::Relaxed), 0);
        self.0.drops.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn values_slices_and_strings_survive_mutation_and_freezing()
-> Result<(), Box<dyn std::error::Error>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let number = arena.try_alloc(42_u64)?;
    let mut source = [1_u16, 2, 3];
    let slice = arena.try_alloc_slice_copy(&source)?;
    source.fill(0);
    let filled = arena.try_alloc_slice_fill(3, 7_u32)?;
    let text = arena.try_alloc_str("héllo")?;

    *arena.get_mut(number)? = 99;
    arena.get_mut(slice)?[1] = 5;
    arena.get_mut(text)?.make_ascii_uppercase();
    let address = arena.get(text)?.as_ptr();
    assert_eq!(arena.stats().used_bytes, 8 + 6 + 12 + "héllo".len());

    let shared = arena.freeze();
    assert_eq!(*shared.get(number)?, 99);
    assert_eq!(shared.get(slice)?, [1, 5, 3]);
    assert_eq!(shared.get(filled)?, [7, 7, 7]);
    assert_eq!(shared.get(text)?, "HéLLO");
    assert_eq!(shared.get(text)?.as_ptr(), address);
    Ok(())
}

#[test]
fn growth_uses_fixed_requests_and_preserves_earlier_values()
-> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AllocatorState::default());
    let mut arena = Arena::try_new_in(config(4096, 256 * 1024), TestAllocator(state.clone()))?;
    let initial = arena.stats();
    let first = arena.try_alloc(1_u8)?;
    assert_eq!(state.last_request.load(Ordering::Relaxed), 4096);
    assert_eq!(arena.stats().reserved_bytes, initial.reserved_bytes + 4096);
    let second = arena.try_alloc(2_u64)?;
    assert_eq!(state.requests.load(Ordering::Relaxed), 2);

    let large = arena.try_alloc_slice_fill(27 * 1024, 0xa5_u8)?;
    assert!(state.last_request.load(Ordering::Relaxed) > 27 * 1024);
    assert!(state.last_request.load(Ordering::Relaxed) < 28 * 1024);
    assert_eq!(*arena.get(first)?, 1);
    assert_eq!(*arena.get(second)?, 2);
    assert!(arena.get(large)?.iter().all(|value| *value == 0xa5));
    assert_eq!(arena.stats().used_bytes, 1 + 8 + 27 * 1024);
    assert_eq!(
        arena.stats().reserved_bytes,
        state.live_bytes.load(Ordering::Relaxed)
    );
    let count = arena.stats().chunk_count;
    drop(arena);
    assert_eq!(state.deallocations.load(Ordering::Relaxed), count);
    assert_eq!(state.drops.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn over_aligned_values_and_slices_remain_aligned() -> Result<(), Box<dyn std::error::Error>> {
    #[repr(align(8192))]
    #[derive(Clone, Copy)]
    struct Aligned(u64);

    let mut arena = Arena::try_new(config(4096, 256 * 1024))?;
    arena.try_alloc(1_u8)?;
    let value = arena.try_alloc(Aligned(42))?;
    let slice = arena.try_alloc_slice_fill(2, Aligned(99))?;
    assert_eq!((arena.get(value)? as *const Aligned).addr() % 8192, 0);
    assert_eq!(arena.get(slice)?.as_ptr().addr() % 8192, 0);
    assert_eq!(arena.get(value)?.0, 42);
    assert!(arena.get(slice)?.iter().all(|value| value.0 == 99));
    Ok(())
}

#[test]
fn allocator_extra_capacity_is_usable_and_counted() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AllocatorState::default());
    let mut arena = Arena::try_new_in(config(4096, 256 * 1024), TestAllocator(state.clone()))?;
    let initial = arena.stats();
    state.extra_bytes.store(1024, Ordering::Relaxed);
    arena.try_alloc(1_u8)?;
    let extra = arena.try_alloc_slice_fill(4300, 7_u8)?;
    assert_eq!(state.requests.load(Ordering::Relaxed), 2);
    assert_eq!(arena.stats().reserved_bytes, initial.reserved_bytes + 5120);
    assert_eq!(arena.get(extra)?.len(), 4300);
    Ok(())
}

#[test]
fn ownership_chunk_extra_capacity_is_usable() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AllocatorState::default());
    state.extra_bytes.store(1024, Ordering::Relaxed);
    let mut arena = Arena::try_new_in(config(4096, 256 * 1024), TestAllocator(state.clone()))?;
    let bytes = arena.try_alloc_slice_fill(1024, 7_u8)?;
    assert_eq!(arena.stats().chunk_count, 1);
    assert_eq!(state.requests.load(Ordering::Relaxed), 1);
    assert!(arena.get(bytes)?.iter().all(|value| *value == 7));
    Ok(())
}

#[test]
fn spare_capacity_in_older_chunks_remains_usable() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AllocatorState::default());
    let mut arena = Arena::try_new_in(config(256, 4096), TestAllocator(state.clone()))?;
    arena.try_alloc_slice_fill(100, 1_u8)?;
    arena.try_alloc_slice_fill(512, 2_u8)?;
    let requests = state.requests.load(Ordering::Relaxed);
    let value = arena.try_alloc_slice_fill(64, 3_u8)?;
    assert_eq!(state.requests.load(Ordering::Relaxed), requests);
    assert_eq!(arena.get(value)?, [3; 64]);
    Ok(())
}

#[test]
fn zero_sized_allocations_need_no_payload_space() -> Result<(), Box<dyn std::error::Error>> {
    #[repr(align(4096))]
    #[derive(Clone, Copy)]
    struct Empty;

    let state = Arc::new(AllocatorState::default());
    let mut arena = Arena::try_new_in(config(256, 4096), TestAllocator(state.clone()))?;
    let initial = arena.stats();
    let empty = arena.try_alloc(Empty)?;
    let empty_text = arena.try_alloc_str("")?;
    let empty_slice = arena.try_alloc_slice_copy::<u64>(&[])?;
    let filled = arena.try_alloc_slice_fill(usize::MAX, Empty)?;
    assert_eq!((arena.get(empty)? as *const Empty).addr() % 4096, 0);
    assert_eq!(arena.get(empty_text)?, "");
    assert!(arena.get(empty_slice)?.is_empty());
    assert_eq!(arena.get(filled)?.len(), usize::MAX);
    assert_eq!(arena.stats(), initial);
    assert_eq!(state.requests.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn foreign_handles_are_rejected_by_all_accessors() -> Result<(), Box<dyn std::error::Error>> {
    let mut first = Arena::try_new(config(256, 4096))?;
    let value = first.try_alloc(42_u64)?;
    let mut second = Arena::try_new(config(256, 4096))?;
    assert_eq!(second.get(value), Err(HandleError::WrongArena));
    assert_eq!(second.get_mut(value), Err(HandleError::WrongArena));
    assert_eq!(second.freeze().get(value), Err(HandleError::WrongArena));
    drop(first);
    let third = Arena::try_new(config(256, 4096))?;
    assert_eq!(third.get(value), Err(HandleError::WrongArena));
    Ok(())
}

#[test]
fn allocation_overflow_preserves_existing_state() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AllocatorState::default());
    let mut arena = Arena::try_new_in(config(256, 4096), TestAllocator(state.clone()))?;
    let before = arena.stats();
    assert!(matches!(
        arena.try_alloc_slice_fill(usize::MAX, 0_u64),
        Err(ArenaError::CapacityOverflow)
    ));
    assert_eq!(arena.stats(), before);
    assert_eq!(state.requests.load(Ordering::Relaxed), 1);
    let value = arena.try_alloc(42_u64)?;
    assert_eq!(*arena.get(value)?, 42);
    Ok(())
}

#[test]
fn invalid_configuration_does_not_request_memory() {
    for config in [
        config(4096, 1024),
        config(1, 1),
        config(usize::MAX, usize::MAX),
    ] {
        let state = Arc::new(AllocatorState::default());
        assert!(matches!(
            Arena::try_new_in(config, TestAllocator(state.clone())),
            Err(ArenaError::InvalidConfiguration)
        ));
        assert_eq!(state.requests.load(Ordering::Relaxed), 0);
        assert_eq!(state.drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn construction_failure_releases_the_allocator() {
    let state = Arc::new(AllocatorState::default());
    state.fail_next.store(true, Ordering::Relaxed);
    assert!(matches!(
        Arena::try_new_in(config(256, 4096), TestAllocator(state.clone())),
        Err(ArenaError::Allocation(AllocationError::Exhausted))
    ));
    assert_eq!(state.live_bytes.load(Ordering::Relaxed), 0);
    assert_eq!(state.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn failed_growth_preserves_values_and_allows_retry() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AllocatorState::default());
    let mut arena = Arena::try_new_in(config(256, 4096), TestAllocator(state.clone()))?;
    let value = arena.try_alloc(42_u64)?;
    let before = arena.stats();
    state.fail_next.store(true, Ordering::Relaxed);
    assert!(matches!(
        arena.try_alloc_slice_fill(512, 1_u8),
        Err(ArenaError::Allocation(AllocationError::Exhausted))
    ));
    assert_eq!(arena.stats(), before);
    assert_eq!(*arena.get(value)?, 42);
    let bytes = arena.try_alloc_slice_fill(512, 2_u8)?;
    assert_eq!(arena.get(bytes)?, [2; 512]);
    Ok(())
}

#[test]
fn limit_includes_metadata_and_unused_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AllocatorState::default());
    let probe = Arena::try_new_in(config(256, 4096), TestAllocator(state.clone()))?;
    let metadata = probe.stats().reserved_bytes;
    drop(probe);

    let mut arena = Arena::try_new_in(config(256, metadata + 256), TestAllocator(state.clone()))?;
    let value = arena.try_alloc_slice_fill(128, 1_u8)?;
    let before = arena.stats();
    let requests = state.requests.load(Ordering::Relaxed);
    assert_eq!(before.reserved_bytes, metadata + 256);
    assert!(matches!(
        arena.try_alloc_slice_fill(256, 1_u8),
        Err(ArenaError::ArenaLimitExceeded)
    ));
    assert_eq!(arena.stats(), before);
    assert_eq!(state.requests.load(Ordering::Relaxed), requests);
    assert_eq!(arena.get(value)?, [1; 128]);
    arena.try_alloc(2_u8)?;
    Ok(())
}

#[test]
fn oversized_initial_chunk_is_returned() {
    let state = Arc::new(AllocatorState::default());
    state.extra_bytes.store(4096, Ordering::Relaxed);
    assert!(matches!(
        Arena::try_new_in(config(256, 4096), TestAllocator(state.clone())),
        Err(ArenaError::ArenaLimitExceeded)
    ));
    assert_eq!(state.allocations.load(Ordering::Relaxed), 1);
    assert_eq!(state.deallocations.load(Ordering::Relaxed), 1);
    assert_eq!(state.live_bytes.load(Ordering::Relaxed), 0);
    assert_eq!(state.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn oversized_growth_chunk_is_returned_without_changing_state()
-> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AllocatorState::default());
    let probe = Arena::try_new_in(config(256, 4096), TestAllocator(state.clone()))?;
    let metadata = probe.stats().reserved_bytes;
    drop(probe);

    let mut arena = Arena::try_new_in(config(256, metadata + 384), TestAllocator(state.clone()))?;
    let before = arena.stats();
    state.extra_bytes.store(256, Ordering::Relaxed);
    assert!(matches!(
        arena.try_alloc(1_u8),
        Err(ArenaError::ArenaLimitExceeded)
    ));
    assert_eq!(arena.stats(), before);
    assert_eq!(state.live_bytes.load(Ordering::Relaxed), metadata);
    assert_eq!(state.deallocations.load(Ordering::Relaxed), 2);
    state.extra_bytes.store(0, Ordering::Relaxed);
    arena.try_alloc(2_u8)?;
    Ok(())
}

#[test]
fn freezing_and_cloning_keep_storage_until_the_last_owner() -> Result<(), Box<dyn std::error::Error>>
{
    let state = Arc::new(AllocatorState::default());
    let mut arena = Arena::try_new_in(config(256, 4096), TestAllocator(state.clone()))?;
    let text = arena.try_alloc_str("stanza")?;
    let stats = arena.stats();
    let requests = state.requests.load(Ordering::Relaxed);
    state.fail_next.store(true, Ordering::Relaxed);

    let shared = arena.freeze();
    let second = shared.clone();
    assert_eq!(state.requests.load(Ordering::Relaxed), requests);
    assert_eq!(shared.stats(), stats);
    drop(shared);
    assert_eq!(state.deallocations.load(Ordering::Relaxed), 0);
    assert_eq!(state.drops.load(Ordering::Relaxed), 0);
    assert_eq!(second.get(text)?, "stanza");
    drop(second);
    assert_eq!(
        state.deallocations.load(Ordering::Relaxed),
        stats.chunk_count
    );
    assert_eq!(state.drops.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn frozen_stanza_fans_out_across_threads() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AllocatorState::default());
    let mut arena = Arena::try_new_in(config(256, 4096), TestAllocator(state.clone()))?;
    let payload = arena.try_alloc_slice_fill(512, 7_u8)?;
    let arena = arena.freeze();
    let barrier = Barrier::new(4);
    thread::scope(|scope| {
        for _ in 0..4 {
            let recipient = arena.clone();
            let barrier = &barrier;
            scope.spawn(move || {
                for _ in 0..16 {
                    let copy = recipient.clone();
                    assert_eq!(copy.get(payload), Ok([7_u8; 512].as_slice()));
                }
                barrier.wait();
                assert_eq!(recipient.get(payload), Ok([7_u8; 512].as_slice()));
            });
        }
        drop(arena);
    });
    assert_eq!(state.live_bytes.load(Ordering::Relaxed), 0);
    assert_eq!(
        state.allocations.load(Ordering::Relaxed),
        state.deallocations.load(Ordering::Relaxed)
    );
    assert_eq!(state.drops.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn exclusive_arena_can_continue_building_on_another_thread()
-> Result<(), Box<dyn std::error::Error>> {
    let mut arena = Arena::try_new(config(256, 4096))?;
    let value = arena.try_alloc(1_u64)?;
    thread::scope(|scope| {
        scope
            .spawn(move || -> Result<(), ArenaError> {
                let second = arena.try_alloc(2_u64)?;
                assert_eq!(arena.get(value), Ok(&1));
                assert_eq!(arena.get(second), Ok(&2));
                Ok(())
            })
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })?;
    Ok(())
}

#[derive(Default)]
struct ReusingAllocator(Mutex<Option<Chunk>>);

// A cached block has no remaining users. Its original layout is preserved.
unsafe impl ChunkAllocator for ReusingAllocator {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        let cached = self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(chunk) = cached {
            if chunk.capacity() >= layout.size() && chunk.layout().align() >= layout.align() {
                return Ok(chunk);
            }
            unsafe { GlobalChunkAllocator.deallocate(chunk) };
        }
        let returned = Layout::from_size_align(4096.max(layout.size()), layout.align())
            .map_err(|_| AllocationError::UnsupportedLayout)?;
        GlobalChunkAllocator.allocate(returned)
    }

    unsafe fn deallocate(&self, chunk: Chunk) {
        let previous = self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace(chunk);
        if let Some(chunk) = previous {
            unsafe { GlobalChunkAllocator.deallocate(chunk) };
        }
    }
}

impl Drop for ReusingAllocator {
    fn drop(&mut self) {
        if let Some(chunk) = self
            .0
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            unsafe { GlobalChunkAllocator.deallocate(chunk) };
        }
    }
}

#[test]
fn stale_handles_are_rejected_when_addresses_are_reused() -> Result<(), Box<dyn std::error::Error>>
{
    let allocator: Arc<dyn ChunkAllocator> = Arc::new(ReusingAllocator::default());
    let mut first = Arena::try_new_in(config(256, 4096), allocator.clone())?;
    let stale = first.try_alloc(42_u64)?;
    let original_pointer = first.get(stale)? as *const u64;
    drop(first.freeze());

    let mut second = Arena::try_new_in(config(256, 4096), allocator)?;
    let current = second.try_alloc(99_u64)?;
    assert_eq!(second.get(current)? as *const u64, original_pointer);
    assert_eq!(second.get(stale), Err(HandleError::WrongArena));
    assert_eq!(second.get_mut(stale), Err(HandleError::WrongArena));
    assert_eq!(second.freeze().get(stale), Err(HandleError::WrongArena));
    Ok(())
}
