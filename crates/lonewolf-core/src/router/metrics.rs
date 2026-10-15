// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_utils::CachePadded;
use lonewolf_metrics::PerWorker;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::{MetricType, counter::ConstCounter, gauge::ConstGauge};

use super::{DetachedWork, MAX_DETACHED};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageOutcome {
    Routed,
    Stored,
    Discarded,
    Rejected,
    Failed,
}

impl MessageOutcome {
    pub(crate) const ALL: [Self; 5] = [
        Self::Routed,
        Self::Stored,
        Self::Discarded,
        Self::Rejected,
        Self::Failed,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Routed => "routed",
            Self::Stored => "stored",
            Self::Discarded => "discarded",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }
}

pub(crate) struct RouterMetrics {
    sessions: Box<[CachePadded<AtomicU64>]>,
    messages: PerWorker<[AtomicU64; MessageOutcome::ALL.len()]>,
}

impl RouterMetrics {
    pub(crate) fn new(shards: usize, workers: NonZeroUsize) -> Self {
        Self {
            sessions: (0..shards)
                .map(|_| CachePadded::new(AtomicU64::new(0)))
                .collect(),
            messages: PerWorker::new(workers),
        }
    }

    /// The caller holds the shard's lock or exclusively owns its teardown.
    pub(in crate::router) fn publish_sessions(&self, shard: usize, sessions: usize) {
        self.sessions[shard].store(sessions as u64, Ordering::Relaxed);
    }

    pub(crate) fn message(&self, outcome: MessageOutcome) {
        self.messages.current()[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn sessions(&self) -> u64 {
        self.sessions.iter().fold(0u64, |sum, sessions| {
            sum.saturating_add(sessions.load(Ordering::Relaxed))
        })
    }

    pub(crate) fn messages(&self, outcome: MessageOutcome) -> u64 {
        self.messages
            .sum(|slot| slot[outcome as usize].load(Ordering::Relaxed))
    }
}

pub(in crate::router) struct RouterCollector {
    metrics: Arc<RouterMetrics>,
    detached: DetachedWork,
}

impl RouterCollector {
    pub(in crate::router) fn new(metrics: Arc<RouterMetrics>, detached: DetachedWork) -> Self {
        Self { metrics, detached }
    }
}

impl fmt::Debug for RouterCollector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouterCollector")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct MessageLabels {
    outcome: &'static str,
}

impl Collector for RouterCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        ConstGauge::new(self.metrics.sessions()).encode(encoder.encode_descriptor(
            "router_sessions",
            "Bound client sessions registered in the router.",
            None,
            MetricType::Gauge,
        )?)?;
        {
            let mut family = encoder.encode_descriptor(
                "router_messages",
                "Messages handled by the delivery stage, by outcome.",
                None,
                MetricType::Counter,
            )?;
            for outcome in MessageOutcome::ALL {
                ConstCounter::new(self.metrics.messages(outcome)).encode(family.encode_family(
                    &MessageLabels {
                        outcome: outcome.as_str(),
                    },
                )?)?;
            }
        }
        ConstGauge::new(self.detached.active() as u64).encode(encoder.encode_descriptor(
            "router_detached_tasks",
            "Detached delivery tasks currently running.",
            None,
            MetricType::Gauge,
        )?)?;
        ConstGauge::new(MAX_DETACHED as u64).encode(encoder.encode_descriptor(
            "router_detached_tasks_limit",
            "Detached delivery tasks allowed before new work is refused.",
            None,
            MetricType::Gauge,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use prometheus_client::encoding::text::encode;
    use prometheus_client::registry::Registry;

    use super::*;

    #[test]
    fn router_collector_encodes_sessions_messages_and_detached_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let metrics = Arc::new(RouterMetrics::new(4, NonZeroUsize::MIN));
        metrics.message(MessageOutcome::Routed);
        metrics.message(MessageOutcome::Routed);
        metrics.message(MessageOutcome::Failed);
        metrics.publish_sessions(0, 3);
        metrics.publish_sessions(3, 1);
        let detached = DetachedWork::default();
        let guard = detached.try_start().ok_or("available detached slot")?;
        let mut registry = Registry::default();
        registry
            .sub_registry_with_prefix("lonewolf")
            .register_collector(Box::new(RouterCollector::new(metrics, detached)));
        let mut output = String::new();
        encode(&mut output, &registry)?;
        for sample in [
            "lonewolf_router_sessions 4",
            "lonewolf_router_messages_total{outcome=\"routed\"} 2",
            "lonewolf_router_messages_total{outcome=\"stored\"} 0",
            "lonewolf_router_messages_total{outcome=\"discarded\"} 0",
            "lonewolf_router_messages_total{outcome=\"rejected\"} 0",
            "lonewolf_router_messages_total{outcome=\"failed\"} 1",
            "lonewolf_router_detached_tasks 1",
            "lonewolf_router_detached_tasks_limit 4096",
        ] {
            assert!(output.lines().any(|line| line == sample), "{output}");
        }
        drop(guard);
        output.clear();
        encode(&mut output, &registry)?;
        assert!(
            output
                .lines()
                .any(|line| line == "lonewolf_router_detached_tasks 0"),
            "{output}"
        );
        Ok(())
    }

    #[test]
    fn message_outcome_indexes_follow_the_all_order() {
        for (index, outcome) in MessageOutcome::ALL.into_iter().enumerate() {
            assert_eq!(outcome as usize, index);
        }
    }

    #[test]
    fn message_counts_sum_worker_and_shared_slots() {
        let metrics = RouterMetrics::new(1, NonZeroUsize::MIN.saturating_add(1));
        metrics.messages.slot(0)[MessageOutcome::Routed as usize].store(1, Ordering::Relaxed);
        metrics.messages.slot(1)[MessageOutcome::Routed as usize].store(2, Ordering::Relaxed);
        metrics.message(MessageOutcome::Routed);
        assert_eq!(metrics.messages(MessageOutcome::Routed), 4);
    }
}
