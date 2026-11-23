// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use lonewolf_storage::RedbStorage;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric};
use prometheus_client::metrics::{MetricType, counter::ConstCounter, gauge::ConstGauge};
use prometheus_client::registry::Unit;

pub(crate) struct StorageCollector {
    stores: Vec<(String, RedbStorage)>,
}

impl StorageCollector {
    pub(crate) fn new(stores: Vec<(String, RedbStorage)>) -> Self {
        Self { stores }
    }
}

impl fmt::Debug for StorageCollector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageCollector")
            .finish_non_exhaustive()
    }
}

impl Collector for StorageCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        if self.stores.is_empty() {
            return Ok(());
        }
        {
            let mut family = encoder.encode_descriptor(
                "storage_commit_duration",
                "Time to commit a write transaction, including the durable flush.",
                Some(&Unit::Seconds),
                MetricType::Histogram,
            )?;
            for (name, storage) in &self.stores {
                storage
                    .metrics()
                    .commit_duration()
                    .encode(family.encode_family(&[("store", name.as_str())])?)?;
            }
        }
        {
            let mut family = encoder.encode_descriptor(
                "storage_write_wait_duration",
                "Time to obtain the store's single write transaction.",
                Some(&Unit::Seconds),
                MetricType::Histogram,
            )?;
            for (name, storage) in &self.stores {
                storage
                    .metrics()
                    .write_wait_duration()
                    .encode(family.encode_family(&[("store", name.as_str())])?)?;
            }
        }
        if self
            .stores
            .iter()
            .any(|(_, storage)| storage.metrics().failures().any(|(_, _, count)| count != 0))
        {
            let mut family = encoder.encode_descriptor(
                "storage_transaction_failures",
                "Storage transaction operations that failed, by operation and error kind.",
                None,
                MetricType::Counter,
            )?;
            for (name, storage) in &self.stores {
                for (operation, kind, count) in storage.metrics().failures() {
                    if count != 0 {
                        ConstCounter::new(count).encode(family.encode_family(&[
                            ("store", name.as_str()),
                            ("operation", operation.as_str()),
                            ("kind", kind.as_str()),
                        ])?)?;
                    }
                }
            }
        }
        self.encode_blocklist(encoder)
    }
}

impl StorageCollector {
    fn encode_blocklist(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        {
            let mut family = encoder.encode_descriptor(
                "storage_blocklist_cache_lookups",
                "Blocklist lookups by cache outcome.",
                None,
                MetricType::Counter,
            )?;
            for (name, storage) in &self.stores {
                for (outcome, count) in storage.cache_metrics().blocklist_lookups() {
                    ConstCounter::new(count).encode(family.encode_family(&[
                        ("store", name.as_str()),
                        ("outcome", outcome.as_str()),
                    ])?)?;
                }
            }
        }
        {
            let mut family = encoder.encode_descriptor(
                "storage_blocklist_cache_fills",
                "Blocklists loaded after a cache miss by fill outcome.",
                None,
                MetricType::Counter,
            )?;
            for (name, storage) in &self.stores {
                for (outcome, count) in storage.cache_metrics().blocklist_fills() {
                    ConstCounter::new(count).encode(family.encode_family(&[
                        ("store", name.as_str()),
                        ("outcome", outcome.as_str()),
                    ])?)?;
                }
            }
        }
        {
            let mut family = encoder.encode_descriptor(
                "storage_blocklist_cache_updates",
                "Blocklist cache updates at commit by outcome.",
                None,
                MetricType::Counter,
            )?;
            for (name, storage) in &self.stores {
                for (outcome, count) in storage.cache_metrics().blocklist_updates() {
                    ConstCounter::new(count).encode(family.encode_family(&[
                        ("store", name.as_str()),
                        ("outcome", outcome.as_str()),
                    ])?)?;
                }
            }
        }
        {
            let mut family = encoder.encode_descriptor(
                "storage_blocklist_cache_evictions",
                "Blocklist cache entries evicted to stay within capacity.",
                None,
                MetricType::Counter,
            )?;
            for (name, storage) in &self.stores {
                ConstCounter::new(storage.cache_metrics().blocklist_evictions())
                    .encode(family.encode_family(&[("store", name.as_str())])?)?;
            }
        }
        {
            let mut family = encoder.encode_descriptor(
                "storage_blocklist_cache_entries",
                "Current blocklist cache entries.",
                None,
                MetricType::Gauge,
            )?;
            for (name, storage) in &self.stores {
                ConstGauge::new(storage.cache_metrics().blocklist_entries())
                    .encode(family.encode_family(&[("store", name.as_str())])?)?;
            }
        }
        {
            let mut family = encoder.encode_descriptor(
                "storage_blocklist_cache_size",
                "Estimated size of current blocklist cache entries.",
                Some(&Unit::Bytes),
                MetricType::Gauge,
            )?;
            for (name, storage) in &self.stores {
                ConstGauge::new(storage.cache_metrics().blocklist_size_bytes())
                    .encode(family.encode_family(&[("store", name.as_str())])?)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use compio::runtime::Runtime;
    use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
    use prometheus_client::encoding::text::encode;
    use prometheus_client::registry::Registry;

    use super::StorageCollector;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn storage_collector_labels_histograms_by_store() -> TestResult {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("store.redb"))?;
        Runtime::new()?.block_on(async { storage.begin_write().await?.commit().await })?;
        let mut registry = Registry::default();
        registry
            .sub_registry_with_prefix("lonewolf")
            .register_collector(Box::new(StorageCollector::new(vec![(
                "primary".into(),
                storage,
            )])));
        let mut output = String::new();
        encode(&mut output, &registry)?;
        for sample in [
            "lonewolf_storage_commit_duration_seconds_count{store=\"primary\"} 1",
            "lonewolf_storage_write_wait_duration_seconds_count{store=\"primary\"} 1",
            "lonewolf_storage_blocklist_cache_lookups_total{store=\"primary\",outcome=\"hit\"} 0",
            "lonewolf_storage_blocklist_cache_lookups_total{store=\"primary\",outcome=\"miss\"} 0",
            "lonewolf_storage_blocklist_cache_lookups_total{store=\"primary\",outcome=\"bypass\"} 0",
            "lonewolf_storage_blocklist_cache_fills_total{store=\"primary\",outcome=\"inserted\"} 0",
            "lonewolf_storage_blocklist_cache_fills_total{store=\"primary\",outcome=\"discarded\"} 0",
            "lonewolf_storage_blocklist_cache_updates_total{store=\"primary\",outcome=\"written\"} 0",
            "lonewolf_storage_blocklist_cache_updates_total{store=\"primary\",outcome=\"invalidated\"} 0",
            "lonewolf_storage_blocklist_cache_evictions_total{store=\"primary\"} 0",
            "lonewolf_storage_blocklist_cache_entries{store=\"primary\"} 0",
            "lonewolf_storage_blocklist_cache_size_bytes{store=\"primary\"} 0",
        ] {
            assert!(output.lines().any(|line| line == sample), "{output}");
        }
        assert!(
            !output.lines().any(
                |line| line.starts_with("lonewolf_storage_transaction_failures")
                    || line.starts_with("# TYPE lonewolf_storage_transaction_failures")
            ),
            "{output}"
        );
        Ok(())
    }

    #[test]
    fn no_open_stores_emit_no_descriptors() -> TestResult {
        let mut registry = Registry::default();
        registry.register_collector(Box::new(StorageCollector::new(Vec::new())));
        let mut output = String::new();
        encode(&mut output, &registry)?;
        assert_eq!(output, "# EOF\n");
        Ok(())
    }
}
