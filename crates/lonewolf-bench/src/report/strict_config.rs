// SPDX-License-Identifier: Apache-2.0

use crate::config::{MeasurementConfig, MetricsConfig, ScenarioConfig};
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Scenario {
    Idle {
        connections: usize,
    },
    Messages {
        pairs: usize,
        rate_per_second: u32,
        body_bytes: usize,
    },
    Churn {
        accounts: usize,
        rate_per_second: u32,
    },
}

pub(super) fn scenario<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<ScenarioConfig, D::Error> {
    Ok(match Scenario::deserialize(deserializer)? {
        Scenario::Idle { connections } => ScenarioConfig::Idle { connections },
        Scenario::Messages {
            pairs,
            rate_per_second,
            body_bytes,
        } => ScenarioConfig::Messages {
            pairs,
            rate_per_second,
            body_bytes,
        },
        Scenario::Churn {
            accounts,
            rate_per_second,
        } => ScenarioConfig::Churn {
            accounts,
            rate_per_second,
        },
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Measurement {
    warmup_ms: u64,
    duration_ms: u64,
    operation_timeout_ms: u64,
    setup_timeout_ms: u64,
    shutdown_timeout_ms: u64,
    ramp_rate_per_second: u32,
    connect_concurrency: usize,
    driver_workers: usize,
    max_in_flight: usize,
    dispatch_quantum_us: u64,
    max_dispatch_batch: u64,
    max_schedule_lag_ms: u64,
}

pub(super) fn measurement<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<MeasurementConfig, D::Error> {
    let v = Measurement::deserialize(deserializer)?;
    Ok(MeasurementConfig {
        warmup_ms: v.warmup_ms,
        duration_ms: v.duration_ms,
        operation_timeout_ms: v.operation_timeout_ms,
        setup_timeout_ms: v.setup_timeout_ms,
        shutdown_timeout_ms: v.shutdown_timeout_ms,
        ramp_rate_per_second: v.ramp_rate_per_second,
        connect_concurrency: v.connect_concurrency,
        driver_workers: v.driver_workers,
        max_in_flight: v.max_in_flight,
        dispatch_quantum_us: v.dispatch_quantum_us,
        max_dispatch_batch: v.max_dispatch_batch,
        max_schedule_lag_ms: v.max_schedule_lag_ms,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metrics {
    interval_ms: u64,
    timeout_ms: u64,
}

pub(super) fn metrics<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<MetricsConfig, D::Error> {
    let v = Metrics::deserialize(deserializer)?;
    Ok(MetricsConfig {
        interval_ms: v.interval_ms,
        timeout_ms: v.timeout_ms,
    })
}
