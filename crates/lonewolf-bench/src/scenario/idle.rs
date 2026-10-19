// SPDX-License-Identifier: Apache-2.0

use crate::{
    error::BenchResult,
    measurement::MeasurementResult,
    report::{CounterReport, PhaseName},
    run::RunContext,
};
use std::{collections::BTreeMap, time::Duration};
use tokio::time::Instant;

pub async fn run(context: &mut RunContext) -> BenchResult<MeasurementResult> {
    context.connected_barrier().await?;
    if context.connections.established() != context.config.account_count()
        || context.connections.active() != context.config.account_count() as u64
    {
        return Err(crate::run::failure("all_connected_barrier"));
    }
    context
        .hold(
            PhaseName::Warmup,
            Duration::from_millis(context.config.measurement.warmup_ms),
        )
        .await?;
    context.barrier_phase(PhaseName::WarmupDrain).await?;
    let start = Instant::now();
    let end = start + Duration::from_millis(context.config.measurement.duration_ms);
    context.measurement_window = Some((start, end));
    context.report.counters = CounterReport {
        requested_connections: context.config.account_count() as u64,
        established_connections: context.connections.established() as u64,
        connections_at_measurement_start: context.connections.active(),
        peak_connections: context.connections.active(),
        ..CounterReport::default()
    };
    let outcome = context.hold_until(PhaseName::Measurement, start, end).await;
    context.barrier_phase(PhaseName::MeasurementDrain).await?;
    context.refresh_measurement();
    outcome?;
    Ok(MeasurementResult {
        counters: context.report.counters.clone(),
        latencies: BTreeMap::new(),
        reasons: context.report.reasons.clone(),
    })
}
