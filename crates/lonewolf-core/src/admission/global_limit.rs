// SPDX-License-Identifier: Apache-2.0

use super::rejection_report::RejectionReport;
use parking_lot::Mutex as PlMutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

pub(crate) struct GlobalLimit {
    active: AtomicUsize,
    max: usize,
    report: PlMutex<RejectionReport>,
}

pub(crate) struct GlobalPermit(Arc<GlobalLimit>);

impl Drop for GlobalPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl GlobalLimit {
    #[cfg(test)]
    pub(crate) fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub(crate) fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicUsize::new(0),
            max,
            report: PlMutex::new(RejectionReport::default()),
        })
    }

    pub(crate) fn reserve(self: &Arc<Self>, now: Instant) -> Result<GlobalPermit, Option<u64>> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.max {
                return Err(self.report.lock().record(now));
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(GlobalPermit(Arc::clone(self))),
                Err(current) => active = current,
            }
        }
    }
}
