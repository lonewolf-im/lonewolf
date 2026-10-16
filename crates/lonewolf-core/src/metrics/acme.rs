// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use lonewolf_acme::{HostState, HostStatus, StatusHandle};
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric};
use prometheus_client::metrics::{MetricType, counter::ConstCounter, gauge::ConstGauge};

pub(crate) struct AcmeCollector {
    status: StatusHandle,
}

impl AcmeCollector {
    pub(crate) fn new(status: StatusHandle) -> Self {
        Self { status }
    }
}

impl fmt::Debug for AcmeCollector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeCollector")
            .finish_non_exhaustive()
    }
}

const OUTCOMES: [&str; 10] = [
    "success",
    "network",
    "timeout",
    "rate_limited",
    "authorization",
    "protocol",
    "material",
    "account",
    "state",
    "deferred",
];

impl Collector for AcmeCollector {
    fn encode(&self, encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        encode_hosts(&self.status.snapshot(), encoder)
    }
}

pub(super) fn encode_hosts(
    hosts: &[(String, HostStatus)],
    mut encoder: DescriptorEncoder,
) -> Result<(), fmt::Error> {
    if hosts.is_empty() {
        return Ok(());
    }
    {
        let mut family = encoder.encode_descriptor(
            "acme_certificate_ready",
            "Managed certificate availability.",
            None,
            MetricType::Gauge,
        )?;
        for (host, status) in hosts {
            ConstGauge::new(i64::from(status.state == HostState::Ready))
                .encode(family.encode_family(&[("host", host.as_str())])?)?;
        }
    }
    for (name, help, expiry) in [
        (
            "acme_certificate_not_after_seconds",
            "Managed certificate expiry in Unix seconds.",
            true,
        ),
        (
            "acme_next_attempt_seconds",
            "Next managed certificate attempt in Unix seconds.",
            false,
        ),
    ] {
        let mut family = encoder.encode_descriptor(name, help, None, MetricType::Gauge)?;
        for (host, status) in hosts {
            if let Some(value) = if expiry {
                status.not_after_unix
            } else {
                status.next_attempt_unix
            } {
                ConstGauge::new(value as f64)
                    .encode(family.encode_family(&[("host", host.as_str())])?)?;
            }
        }
    }
    let mut family = encoder.encode_descriptor(
        "acme_attempts",
        "Managed certificate attempts by fixed outcome.",
        None,
        MetricType::Counter,
    )?;
    for (host, status) in hosts {
        for (outcome, count) in OUTCOMES
            .iter()
            .zip(std::iter::once(status.successes).chain(status.failures))
        {
            ConstCounter::new(count)
                .encode(family.encode_family(&[("host", host.as_str()), ("outcome", *outcome)])?)?;
        }
    }
    Ok(())
}
