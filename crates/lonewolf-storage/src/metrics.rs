// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use prometheus_client::metrics::histogram::Histogram;

use crate::StorageErrorKind;

pub const DURATION_BUCKETS: [f64; 12] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOperation {
    BeginRead,
    BeginWrite,
    Commit,
}

impl StoreOperation {
    pub const ALL: [Self; 3] = [Self::BeginRead, Self::BeginWrite, Self::Commit];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeginRead => "begin_read",
            Self::BeginWrite => "begin_write",
            Self::Commit => "commit",
        }
    }
}

/// Counts only operations made through the storage traits.
pub struct StoreMetrics {
    commit_duration: Histogram,
    write_wait_duration: Histogram,
    failures: [[AtomicU64; StorageErrorKind::ALL.len()]; StoreOperation::ALL.len()],
}

impl StoreMetrics {
    pub(crate) fn new() -> Self {
        Self {
            commit_duration: Histogram::new(DURATION_BUCKETS),
            write_wait_duration: Histogram::new(DURATION_BUCKETS),
            failures: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
        }
    }

    pub fn commit_duration(&self) -> &Histogram {
        &self.commit_duration
    }

    pub fn write_wait_duration(&self) -> &Histogram {
        &self.write_wait_duration
    }

    /// Yields every operation and kind pair, including zero counts.
    pub fn failures(&self) -> impl Iterator<Item = (StoreOperation, StorageErrorKind, u64)> + '_ {
        StoreOperation::ALL.into_iter().flat_map(move |operation| {
            StorageErrorKind::ALL.into_iter().map(move |kind| {
                let count =
                    self.failures[operation as usize][kind as usize].load(Ordering::Relaxed);
                (operation, kind, count)
            })
        })
    }

    pub(crate) fn record_failure(&self, operation: StoreOperation, kind: StorageErrorKind) {
        self.failures[operation as usize][kind as usize].fetch_add(1, Ordering::Relaxed);
    }
}

impl fmt::Debug for StoreMetrics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreMetrics")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;
    use prometheus_client::encoding::text::encode;
    use prometheus_client::metrics::histogram::Histogram;
    use prometheus_client::registry::Registry;

    use super::{StoreMetrics, StoreOperation};
    use crate::{RedbStorage, Storage, StorageErrorKind, WriteTransaction};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn assert_count(histogram: &Histogram, count: u64) -> Result<(), std::fmt::Error> {
        let mut registry = Registry::default();
        registry.register("duration", "Test duration.", histogram.clone());
        let mut output = String::new();
        encode(&mut output, &registry)?;
        let expected = format!("duration_count {count}");
        assert!(output.lines().any(|line| line == expected), "{output}");
        Ok(())
    }

    #[test]
    fn commits_through_the_storage_traits_record_wait_and_commit_durations() -> TestResult {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("store.redb"))?;
        block_on(async { storage.begin_write().await?.commit().await })?;
        assert_count(storage.metrics().commit_duration(), 1)?;
        assert_count(storage.metrics().write_wait_duration(), 1)?;
        Ok(())
    }

    #[test]
    fn reads_and_table_initialization_record_no_durations() -> TestResult {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("store.redb"))?;
        let _transaction = block_on(storage.begin_read())?;
        assert_count(storage.metrics().commit_duration(), 0)?;
        assert_count(storage.metrics().write_wait_duration(), 0)?;
        Ok(())
    }

    #[test]
    fn failures_are_counted_per_operation_and_kind() {
        let metrics = StoreMetrics::new();
        for _ in 0..2 {
            metrics.record_failure(StoreOperation::Commit, StorageErrorKind::CommitUnknown);
        }
        let mut pairs = 0;
        for (operation, kind, count) in metrics.failures() {
            let expected = u64::from(
                operation == StoreOperation::Commit && kind == StorageErrorKind::CommitUnknown,
            ) * 2;
            assert_eq!(count, expected);
            pairs += 1;
        }
        assert_eq!(pairs, 15);
    }

    #[test]
    fn indexes_follow_the_all_order() {
        for (index, operation) in StoreOperation::ALL.into_iter().enumerate() {
            assert_eq!(operation as usize, index);
            assert!(
                StoreOperation::ALL[..index]
                    .iter()
                    .all(|other| other.as_str() != operation.as_str())
            );
        }
        for (index, kind) in StorageErrorKind::ALL.into_iter().enumerate() {
            assert_eq!(kind as usize, index);
            assert!(
                StorageErrorKind::ALL[..index]
                    .iter()
                    .all(|other| other.as_str() != kind.as_str())
            );
        }
        assert_eq!(
            StoreOperation::ALL.map(StoreOperation::as_str),
            ["begin_read", "begin_write", "commit"]
        );
        assert_eq!(
            StorageErrorKind::ALL.map(StorageErrorKind::as_str),
            [
                "unavailable",
                "corrupt_data",
                "unsupported_version",
                "commit_unknown",
                "other"
            ]
        );
    }
}
