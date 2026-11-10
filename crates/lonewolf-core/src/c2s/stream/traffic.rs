// SPDX-License-Identifier: Apache-2.0

use crate::c2s::metrics::C2sWorkerMetrics;
use crate::xml_stream::traffic::TrafficObserver;

impl TrafficObserver for C2sWorkerMetrics {
    fn received(&self, bytes: usize) {
        self.bytes_received(bytes);
    }

    fn sent(&self, bytes: usize) {
        self.bytes_sent(bytes);
    }
}

#[cfg(test)]
mod tests;
