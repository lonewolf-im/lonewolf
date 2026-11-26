// SPDX-License-Identifier: Apache-2.0

use crate::c2s::metrics::C2sWorkerMetrics;
use crate::xml_stream::traffic::{TrafficObserver, WriteProgress};

/// Counts TCP bytes and records when the client last accepted outgoing bytes.
#[derive(Clone)]
pub(crate) struct C2sTraffic {
    metrics: C2sWorkerMetrics,
    progress: WriteProgress,
}

impl C2sTraffic {
    pub(crate) fn new(metrics: C2sWorkerMetrics, progress: WriteProgress) -> Self {
        Self { metrics, progress }
    }

    pub(crate) fn into_parts(self) -> (C2sWorkerMetrics, WriteProgress) {
        (self.metrics, self.progress)
    }

    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        Self::new(
            C2sWorkerMetrics::detached(),
            WriteProgress::new(crate::clock::now()),
        )
    }
}

impl TrafficObserver for C2sTraffic {
    fn received(&self, bytes: usize) {
        self.metrics.bytes_received(bytes);
    }

    fn sent(&self, bytes: usize) {
        self.metrics.bytes_sent(bytes);
        if bytes > 0 {
            self.progress.record(crate::clock::now());
        }
    }
}

#[cfg(test)]
mod tests;
