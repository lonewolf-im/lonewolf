// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use lonewolf_admin::{DiagnosticsProvider, DiagnosticsSnapshot, Readiness, ReadinessState};
use lonewolf_util::capacity::{Capacity, Counter, Gauge, Histogram};
use lonewolf_util::pool::PooledChunkAllocator;
use tracing_appender::non_blocking::ErrorCounter;

use crate::router::{RouterHandle, RouterState};

const STARTING: u8 = 0;
const SERVING: u8 = 1;
const STOPPING: u8 = 2;
const FAILED: u8 = 3;

pub(crate) struct Diagnostics {
    pub(crate) capacity: Arc<Capacity>,
    pool: Arc<PooledChunkAllocator>,
    log_drops: ErrorCounter,
    root: AtomicU8,
    router: Mutex<Option<RouterHandle<Arc<PooledChunkAllocator>>>>,
}

impl Diagnostics {
    pub(crate) fn new(
        capacity: Arc<Capacity>,
        pool: Arc<PooledChunkAllocator>,
        log_drops: ErrorCounter,
    ) -> Self {
        Self {
            capacity,
            pool,
            log_drops,
            root: AtomicU8::new(STARTING),
            router: Mutex::new(None),
        }
    }
    pub(crate) fn set_router(&self, router: RouterHandle<Arc<PooledChunkAllocator>>) {
        *self.router.lock().unwrap_or_else(PoisonError::into_inner) = Some(router);
    }
    pub(crate) fn serving(&self) {
        self.root.store(SERVING, Ordering::Release);
    }
    pub(crate) fn stop(&self, failed: bool) {
        if failed {
            self.root.store(FAILED, Ordering::Release);
        } else {
            let _ = self
                .root
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                    (state != FAILED).then_some(STOPPING)
                });
        }
    }
}

impl DiagnosticsProvider for Diagnostics {
    fn readiness(&self) -> Readiness {
        let root = self.root.load(Ordering::Acquire);
        let router = self.router.lock().unwrap_or_else(PoisonError::into_inner);
        let state = match (root, router.as_ref().map(RouterHandle::state)) {
            (FAILED, _) | (_, Some(RouterState::Failed(_))) => ReadinessState::Failed,
            (STOPPING, _) | (_, Some(RouterState::Stopping)) => ReadinessState::Stopping,
            (SERVING, Some(RouterState::Running)) => ReadinessState::Ready,
            _ => ReadinessState::Starting,
        };
        Readiness::new(state)
    }

    fn snapshot(&self) -> DiagnosticsSnapshot {
        let mut counters = Counter::ALL
            .iter()
            .map(|counter| (counter.as_str(), self.capacity.counter(*counter)))
            .collect::<std::collections::BTreeMap<_, _>>();
        counters.insert(
            "log_dropped_lines_total",
            self.log_drops.dropped_lines() as u64,
        );
        DiagnosticsSnapshot {
            schema_version: 1,
            uptime_ms: self.capacity.uptime_ms(),
            readiness: self.readiness(),
            counters,
            gauges: Gauge::ALL
                .iter()
                .map(|gauge| (gauge.as_str(), self.capacity.gauge(*gauge)))
                .collect(),
            histograms: Histogram::ALL
                .iter()
                .map(|histogram| {
                    (
                        histogram.as_str(),
                        self.capacity.histogram(*histogram).into(),
                    )
                })
                .collect(),
            pool: self.pool.stats().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lonewolf_util::pool::PoolConfig;
    use std::io::{self, Write};
    use std::num::NonZeroUsize;
    use std::sync::{Condvar, mpsc};

    struct GatedWriter {
        entered: Option<mpsc::SyncSender<()>>,
        released: Arc<(Mutex<bool>, Condvar)>,
    }

    impl Write for GatedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
                let (lock, changed) = &*self.released;
                let mut released = lock
                    .lock()
                    .map_err(|_| io::Error::other("gate lock poisoned"))?;
                while !*released {
                    released = changed
                        .wait(released)
                        .map_err(|_| io::Error::other("gate lock poisoned"))?;
                }
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn dropped_log_writes_are_exported_without_retaining_source_text()
    -> Result<(), Box<dyn std::error::Error>> {
        let (entered, entering) = mpsc::sync_channel(1);
        let released = Arc::new((Mutex::new(false), Condvar::new()));
        let (mut writer, _guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(1)
            .finish(GatedWriter {
                entered: Some(entered),
                released: Arc::clone(&released),
            });
        writer.write_all(b"seeded-secret-first")?;
        entering.recv_timeout(std::time::Duration::from_secs(5))?;
        writer.write_all(b"seeded-secret-queued")?;
        writer.write_all(b"seeded-secret-dropped")?;
        let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
            total_bytes: NonZeroUsize::new(8 * 1024 * 1024).ok_or("zero pool")?,
            shards_per_bucket: NonZeroUsize::MIN,
        })?);
        let diagnostics = Diagnostics::new(Arc::new(Capacity::new()), pool, writer.error_counter());
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.counters["log_dropped_lines_total"], 1);
        assert_eq!(snapshot.counters.len(), 12);
        assert_eq!(snapshot.gauges.len(), 5);
        assert_eq!(snapshot.histograms.len(), 13);
        assert_eq!(snapshot.pool.buckets.len(), 8);
        let json = serde_json::to_string(&snapshot)?;
        assert!(!json.contains("seeded-secret"));
        *released.0.lock().map_err(|_| "gate lock poisoned")? = true;
        released.1.notify_all();
        Ok(())
    }
}
