// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::Arc;

use lonewolf_util::pool::PooledChunkAllocator;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::ConstCounter;
use prometheus_client::metrics::gauge::ConstGauge;

pub(crate) struct StanzaPoolCollector {
    pool: Arc<PooledChunkAllocator>,
}

impl StanzaPoolCollector {
    pub(crate) fn new(pool: Arc<PooledChunkAllocator>) -> Self {
        Self { pool }
    }
}

impl fmt::Debug for StanzaPoolCollector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StanzaPoolCollector")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ChunkLabels {
    chunk_bytes: usize,
}

impl Collector for StanzaPoolCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        let stats = self.pool.stats();
        {
            let mut family = encoder.encode_descriptor(
                "stanza_pool_chunks",
                "Pooled stanza chunks reserved per chunk size.",
                None,
                MetricType::Gauge,
            )?;
            for bucket in &stats.buckets {
                let labels = ChunkLabels {
                    chunk_bytes: bucket.chunk_bytes,
                };
                ConstGauge::new(bucket.total_chunks).encode(family.encode_family(&labels)?)?;
            }
        }
        {
            let mut family = encoder.encode_descriptor(
                "stanza_pool_available_chunks",
                "Pooled stanza chunks currently free per chunk size.",
                None,
                MetricType::Gauge,
            )?;
            for bucket in &stats.buckets {
                let labels = ChunkLabels {
                    chunk_bytes: bucket.chunk_bytes,
                };
                ConstGauge::new(bucket.available_chunks).encode(family.encode_family(&labels)?)?;
            }
        }
        let family = encoder.encode_descriptor(
            "stanza_pool_heap_allocations",
            "Stanza chunk allocations served by the heap because no pooled chunk was free.",
            None,
            MetricType::Counter,
        )?;
        ConstCounter::new(stats.heap_allocation_count).encode(family)
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::Layout;
    use std::num::NonZeroUsize;
    use std::sync::Arc;

    use lonewolf_util::arena::ChunkAllocator;
    use lonewolf_util::pool::{MIN_POOL_SIZE, PoolConfig, PooledChunkAllocator};
    use prometheus_client::encoding::text::encode;
    use prometheus_client::registry::Registry;

    use super::StanzaPoolCollector;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn render(pool: &Arc<PooledChunkAllocator>) -> Result<String, std::fmt::Error> {
        let mut registry = Registry::default();
        registry
            .sub_registry_with_prefix("lonewolf")
            .register_collector(Box::new(StanzaPoolCollector::new(Arc::clone(pool))));
        let mut output = String::new();
        encode(&mut output, &registry)?;
        Ok(output)
    }

    fn has_line(output: &str, expected: &str) -> bool {
        output.lines().any(|line| line == expected)
    }

    #[test]
    fn pool_capacity_free_chunks_and_heap_fallback_are_reported() -> TestResult {
        let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
            total_bytes: NonZeroUsize::new(MIN_POOL_SIZE).ok_or("zero pool size")?,
            shards_per_bucket: NonZeroUsize::MIN,
        })?);
        let output = render(&pool)?;
        for (bytes, chunks) in [
            (4096, 256),
            (8192, 128),
            (16384, 64),
            (32768, 32),
            (65536, 16),
            (131072, 8),
            (262144, 4),
            (524288, 2),
        ] {
            let total = format!("lonewolf_stanza_pool_chunks{{chunk_bytes=\"{bytes}\"}} {chunks}");
            let free = format!(
                "lonewolf_stanza_pool_available_chunks{{chunk_bytes=\"{bytes}\"}} {chunks}"
            );
            assert!(has_line(&output, &total), "{output}");
            assert!(has_line(&output, &free), "{output}");
        }
        assert!(
            has_line(&output, "lonewolf_stanza_pool_heap_allocations_total 0"),
            "{output}"
        );

        let layout = Layout::from_size_align(524_288, 8)?;
        let first = pool.allocate(layout)?;
        let second = pool.allocate(layout)?;
        let fallback = pool.allocate(layout)?;
        let output = render(&pool)?;
        assert!(
            has_line(
                &output,
                "lonewolf_stanza_pool_available_chunks{chunk_bytes=\"524288\"} 0"
            ),
            "{output}"
        );
        assert!(
            has_line(&output, "lonewolf_stanza_pool_heap_allocations_total 1"),
            "{output}"
        );

        unsafe {
            pool.deallocate(fallback);
            pool.deallocate(first);
            pool.deallocate(second);
        }
        let output = render(&pool)?;
        assert!(
            has_line(
                &output,
                "lonewolf_stanza_pool_available_chunks{chunk_bytes=\"524288\"} 2"
            ),
            "{output}"
        );
        Ok(())
    }
}
