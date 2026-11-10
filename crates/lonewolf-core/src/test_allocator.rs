// SPDX-License-Identifier: Apache-2.0

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

struct TrackingAllocator;

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

// Thread-local counters cannot allocate, including during thread teardown.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let _ = ALLOCATIONS.try_with(|count| {
                if let Some(current) = count.get() {
                    count.set(Some(current + 1));
                }
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}

pub(crate) fn allocations_during(operation: impl FnOnce()) -> usize {
    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            ALLOCATIONS.set(None);
        }
    }

    ALLOCATIONS.set(Some(0));
    let _reset = Reset;
    operation();
    ALLOCATIONS.get().unwrap_or(0)
}
