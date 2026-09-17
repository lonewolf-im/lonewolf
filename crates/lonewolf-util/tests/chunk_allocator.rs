// SPDX-License-Identifier: Apache-2.0

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use lonewolf_util::arena::{AllocationError, Chunk, ChunkAllocator, GlobalChunkAllocator};

#[derive(Clone, Copy, Default)]
struct AllocationTrace {
    allocated: Option<Layout>,
    deallocated: Option<(*mut u8, Layout)>,
}

thread_local! {
    static FAIL_NEXT_ALLOCATION: Cell<bool> = const { Cell::new(false) };
    static TRACE: Cell<AllocationTrace> = const {
        Cell::new(AllocationTrace { allocated: None, deallocated: None })
    };
}

struct TestGlobalAllocator;

#[global_allocator]
static GLOBAL: TestGlobalAllocator = TestGlobalAllocator;

// Thread-local bookkeeping cannot allocate or unwind, including during thread teardown.
unsafe impl GlobalAlloc for TestGlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = TRACE.try_with(|trace| {
            trace.set(AllocationTrace {
                allocated: Some(layout),
                ..trace.get()
            });
        });
        if FAIL_NEXT_ALLOCATION
            .try_with(|fail| fail.replace(false))
            .unwrap_or(false)
        {
            return ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = TRACE.try_with(|trace| {
            trace.set(AllocationTrace {
                deallocated: Some((pointer, layout)),
                ..trace.get()
            });
        });
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[test]
fn zero_sized_layouts_are_rejected_before_global_allocation() -> Result<(), std::alloc::LayoutError>
{
    for alignment in [1, 8, 4096] {
        let layout = Layout::from_size_align(0, alignment)?;
        TRACE.set(AllocationTrace::default());

        assert!(matches!(
            GlobalChunkAllocator.allocate(layout),
            Err(AllocationError::UnsupportedLayout)
        ));
        assert!(TRACE.get().allocated.is_none());
    }
    Ok(())
}

#[test]
fn chunks_have_exact_writable_layouts() -> Result<(), Box<dyn std::error::Error>> {
    for (size, alignment) in [
        (1, 1),
        (3, 8),
        (4096, 64),
        (27 * 1024, 4096),
        (128 * 1024, 65536),
    ] {
        let layout = Layout::from_size_align(size, alignment)?;
        let chunk = GlobalChunkAllocator.allocate(layout)?;
        assert_eq!(TRACE.get().allocated, Some(layout));
        assert_eq!(chunk.layout(), layout);
        assert_eq!(chunk.capacity(), size);
        let pointer = chunk.as_ptr();
        assert_eq!(pointer.addr() % alignment, 0);

        let all_bytes_written = unsafe {
            pointer.write_bytes(0xa5, size);
            std::slice::from_raw_parts(pointer, size)
                .iter()
                .all(|byte| *byte == 0xa5)
        };
        unsafe { GlobalChunkAllocator.deallocate(chunk) };

        assert_eq!(TRACE.get().deallocated, Some((pointer, layout)));
        assert!(all_bytes_written);
    }
    Ok(())
}

#[test]
fn raw_parts_preserve_ownership_and_layout() -> Result<(), Box<dyn std::error::Error>> {
    let layout = Layout::from_size_align(27 * 1024, 256)?;
    let chunk = GlobalChunkAllocator.allocate(layout)?;
    let original_pointer = chunk.as_ptr();
    let (pointer, returned_layout) = chunk.into_raw_parts();
    assert_eq!(pointer.as_ptr(), original_pointer);
    assert_eq!(returned_layout, layout);

    let chunk = unsafe { Chunk::from_raw_parts(pointer, returned_layout) };
    assert_eq!(chunk.as_ptr(), original_pointer);
    assert_eq!(chunk.capacity(), layout.size());
    assert_eq!(chunk.layout(), layout);
    unsafe { GlobalChunkAllocator.deallocate(chunk) };
    assert_eq!(TRACE.get().deallocated, Some((original_pointer, layout)));
    Ok(())
}

#[test]
fn live_chunks_are_disjoint_and_independent() -> Result<(), Box<dyn std::error::Error>> {
    let layout = Layout::from_size_align(4096, 64)?;
    let first = GlobalChunkAllocator.allocate(layout)?;
    let second = GlobalChunkAllocator.allocate(layout)?;
    let first_address = first.as_ptr().addr();
    let second_address = second.as_ptr().addr();
    assert!(
        first_address + first.capacity() <= second_address
            || second_address + second.capacity() <= first_address
    );

    let second_is_intact = unsafe {
        first.as_ptr().write_bytes(0x11, first.capacity());
        second.as_ptr().write_bytes(0x22, second.capacity());
        GlobalChunkAllocator.deallocate(first);
        std::slice::from_raw_parts(second.as_ptr(), second.capacity())
            .iter()
            .all(|byte| *byte == 0x22)
    };
    unsafe { GlobalChunkAllocator.deallocate(second) };
    assert!(second_is_intact);
    Ok(())
}

#[test]
fn null_global_allocation_returns_an_error_and_allows_retry() -> Result<(), AllocationError> {
    let layout = Layout::new::<u64>();
    FAIL_NEXT_ALLOCATION.set(true);

    let result = GlobalChunkAllocator.allocate(layout);

    assert!(!FAIL_NEXT_ALLOCATION.get());
    assert!(matches!(result, Err(AllocationError::Exhausted)));
    let chunk = GlobalChunkAllocator.allocate(layout)?;
    unsafe { GlobalChunkAllocator.deallocate(chunk) };
    Ok(())
}

#[derive(Default)]
struct CountingAllocator {
    allocations: AtomicUsize,
    deallocations: AtomicUsize,
}

// Atomic counters do not change the delegated allocation contracts.
unsafe impl ChunkAllocator for CountingAllocator {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        let chunk = GlobalChunkAllocator.allocate(layout)?;
        self.allocations.fetch_add(1, Ordering::Relaxed);
        Ok(chunk)
    }

    unsafe fn deallocate(&self, chunk: Chunk) {
        unsafe { GlobalChunkAllocator.deallocate(chunk) };
        self.deallocations.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn shared_allocator_returns_chunks_to_the_same_instance_across_threads()
-> Result<(), AllocationError> {
    let allocator = Arc::new(CountingAllocator::default());
    let shared: Arc<dyn ChunkAllocator> = allocator.clone();
    let chunk = shared.allocate(Layout::new::<u64>())?;
    unsafe { chunk.as_ptr().cast::<u64>().write(42) };

    thread::scope(|scope| {
        scope.spawn(move || {
            let value = unsafe { chunk.as_ptr().cast::<u64>().read() };
            unsafe { shared.deallocate(chunk) };
            assert_eq!(value, 42);
        });
    });

    assert_eq!(allocator.allocations.load(Ordering::Relaxed), 1);
    assert_eq!(allocator.deallocations.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn shared_allocator_preserves_allocation_errors() -> Result<(), AllocationError> {
    let allocator: Arc<dyn ChunkAllocator> = Arc::new(GlobalChunkAllocator);
    assert!(matches!(
        allocator.allocate(Layout::new::<()>()),
        Err(AllocationError::UnsupportedLayout)
    ));

    FAIL_NEXT_ALLOCATION.set(true);
    let result = allocator.allocate(Layout::new::<u64>());
    assert!(!FAIL_NEXT_ALLOCATION.get());
    assert!(matches!(result, Err(AllocationError::Exhausted)));

    let chunk = allocator.allocate(Layout::new::<u64>())?;
    unsafe { allocator.deallocate(chunk) };
    Ok(())
}
