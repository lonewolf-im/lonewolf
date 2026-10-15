// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::num::NonZeroUsize;

use crossbeam_utils::CachePadded;
use lonewolf_util::core_dispatcher::current_worker_index;

/// One slot per dispatcher worker plus a shared slot for other threads.
pub struct PerWorker<T> {
    slots: Box<[CachePadded<T>]>,
}

impl<T: Default> PerWorker<T> {
    /// Allocates `workers + 1` slots; the last one is the shared slot.
    pub fn new(workers: NonZeroUsize) -> Self {
        Self {
            slots: (0..workers.get())
                .chain(std::iter::once(workers.get()))
                .map(|_| CachePadded::new(T::default()))
                .collect(),
        }
    }
}

impl<T> PerWorker<T> {
    /// Indexes at or beyond the worker count select the shared slot.
    pub fn slot(&self, worker: usize) -> &T {
        &self.slots[worker.min(self.slots.len() - 1)]
    }

    pub fn current(&self) -> &T {
        self.slot(current_worker_index().unwrap_or(usize::MAX))
    }

    pub fn slots(&self) -> impl Iterator<Item = &T> {
        self.slots.iter().map(|slot| &**slot)
    }

    pub fn sum(&self, read: impl Fn(&T) -> u64) -> u64 {
        self.slots()
            .fold(0u64, |sum, slot| sum.saturating_add(read(slot)))
    }
}

impl<T> fmt::Debug for PerWorker<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PerWorker")
            .field("slots", &self.slots.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    use prometheus_client::metrics::histogram::Histogram;

    use super::*;
    use crate::test_allocator::allocations_during;

    #[test]
    fn slots_include_one_shared_slot_for_other_threads() {
        let workers = PerWorker::<AtomicU64>::new(NonZeroUsize::MIN.saturating_add(2));
        let slots: Vec<_> = workers.slots().collect();
        assert_eq!(slots.len(), 4);
        for index in [3, 9, usize::MAX] {
            assert!(std::ptr::eq(workers.slot(index), slots[3]));
        }
    }

    #[test]
    fn current_uses_the_shared_slot_outside_dispatcher_workers() {
        let workers = PerWorker::<AtomicU64>::new(NonZeroUsize::MIN);
        assert!(std::ptr::eq(workers.current(), workers.slot(usize::MAX)));
    }

    #[test]
    fn adjacent_slots_do_not_share_a_cache_line() {
        let workers = PerWorker::<AtomicU64>::new(NonZeroUsize::MIN.saturating_add(1));
        assert!(workers.slot(1) as *const _ as usize - workers.slot(0) as *const _ as usize >= 64);
    }

    #[test]
    fn sum_adds_every_slot() {
        let workers = PerWorker::<AtomicU64>::new(NonZeroUsize::MIN.saturating_add(1));
        workers.slot(0).fetch_add(1, Relaxed);
        workers.slot(1).fetch_add(2, Relaxed);
        workers.slot(usize::MAX).fetch_add(4, Relaxed);
        assert_eq!(workers.sum(|slot| slot.load(Relaxed)), 7);
    }

    #[test]
    fn sum_saturates_on_overflow() {
        let workers = PerWorker::<AtomicU64>::new(NonZeroUsize::MIN);
        workers.slot(0).store(u64::MAX, Relaxed);
        workers.slot(usize::MAX).store(1, Relaxed);
        assert_eq!(workers.sum(|slot| slot.load(Relaxed)), u64::MAX);
    }

    #[test]
    fn recording_does_not_allocate() {
        let workers = PerWorker::<AtomicU64>::new(NonZeroUsize::MIN);
        let histogram = Histogram::new([0.1, 0.5, 1.0]);
        assert_eq!(
            allocations_during(|| {
                workers.slot(0).fetch_add(1, Relaxed);
                histogram.observe(0.5);
            }),
            0
        );
    }
}
