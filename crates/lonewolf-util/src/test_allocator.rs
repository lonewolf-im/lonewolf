// SPDX-License-Identifier: Apache-2.0

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ptr;

#[derive(Clone, Copy, Default)]
pub(crate) struct AllocationTrace {
    pub(crate) allocated: Option<Layout>,
    pub(crate) deallocated: Option<(*mut u8, Layout)>,
}

thread_local! {
    pub(crate) static FAIL_NEXT_ALLOCATION: Cell<bool> = const { Cell::new(false) };
    pub(crate) static LAST_ALLOCATION: Cell<AllocationTrace> = const {
        Cell::new(AllocationTrace { allocated: None, deallocated: None })
    };
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Trace {
    pub(crate) enabled: bool,
    pub(crate) fail_at: Option<usize>,
    pub(crate) attempts: usize,
    pub(crate) allocations: usize,
    pub(crate) deallocations: usize,
    pub(crate) allocated_bytes: usize,
    pub(crate) deallocated_bytes: usize,
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
        let _ = LAST_ALLOCATION.try_with(|trace| {
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
        let _ = LAST_ALLOCATION.try_with(|trace| {
            trace.set(AllocationTrace {
                deallocated: Some((pointer, layout)),
                ..trace.get()
            });
        });
        unsafe { System.dealloc(pointer, layout) };
    }
}

pub(crate) fn traced<T>(fail_at: Option<usize>, operation: impl FnOnce() -> T) -> (T, Trace) {
    TRACE.set(Trace {
        enabled: true,
        fail_at,
        ..Trace::default()
    });
    let result = operation();
    (result, TRACE.replace(Trace::default()))
}
