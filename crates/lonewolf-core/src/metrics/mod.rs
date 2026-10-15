// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::Arc;

use lonewolf_metrics::ProcessCollector;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::{MetricType, counter::ConstCounter, info::Info};
use prometheus_client::registry::Registry;
use tracing_appender::non_blocking::ErrorCounter;

use crate::BuildInfo;

pub(crate) struct ServerMetrics {
    root: Registry,
}

impl ServerMetrics {
    pub(crate) fn new(build: &BuildInfo, dropped_logs: ErrorCounter) -> Self {
        let mut root = Registry::default();
        root.register_collector(Box::new(ProcessCollector::new()));
        let mut metrics = Self { root };
        let lonewolf = metrics.registry();
        lonewolf.register(
            "build",
            "Build information of the running server",
            Info::new(BuildLabels {
                version: build.version,
                branch: build.branch,
                commit: build.commit,
            }),
        );
        lonewolf.register_collector(Box::new(LogCollector { dropped_logs }));
        metrics
    }

    /// Metric names registered here start with `lonewolf_`.
    pub(crate) fn registry(&mut self) -> &mut Registry {
        self.root.sub_registry_with_prefix("lonewolf")
    }

    pub(crate) fn into_registry(self) -> Arc<Registry> {
        Arc::new(self.root)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BuildLabels {
    version: &'static str,
    branch: &'static str,
    commit: &'static str,
}

#[derive(Debug)]
struct LogCollector {
    dropped_logs: ErrorCounter,
}

impl Collector for LogCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        ConstCounter::new(u64::try_from(self.dropped_logs.dropped_lines()).unwrap_or(u64::MAX))
            .encode(encoder.encode_descriptor(
                "log_dropped_lines",
                "Log lines dropped because the log writer queue was full.",
                None,
                MetricType::Counter,
            )?)
    }
}

#[cfg(test)]
mod tests;
