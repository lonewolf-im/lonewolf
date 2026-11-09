// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    report::{CounterReport, PhaseName, PhaseStatus, RunStatus},
    run::tests::context,
};
use std::time::Duration;
use tokio::time::Instant;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test(start_paused = true)]
async fn all_connected_barrier_prevents_silent_empty_or_reduced_runs() -> TestResult {
    let (mut context, _signal) = context(2)?;
    context.connections.simulated(None, Duration::ZERO);
    assert!(idle::run(&mut context).await.is_err());
    assert!(
        !context
            .report
            .phases
            .iter()
            .any(|phase| phase.name == PhaseName::Measurement)
    );
    assert_eq!(context.report.counters, CounterReport::default());
    context
        .connections
        .close_all(Instant::now() + Duration::from_millis(20))
        .await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn idle_plateau_has_fixed_duration_no_writes_and_no_reconnections_after_disconnect()
-> TestResult {
    let (mut context, _signal) = context(2)?;
    context
        .connections
        .simulated(Some(Duration::from_millis(30)), Duration::ZERO);
    context.connections.simulated(None, Duration::ZERO);
    let result = idle::run(&mut context).await?;
    assert_eq!(context.connections.established(), 2);
    assert_eq!(result.counters.connections_at_measurement_start, 2);
    assert_eq!(result.counters.connections_at_measurement_end, 1);
    assert_eq!(result.counters.unexpected_disconnects, 1);
    assert_eq!(result.counters.connection_attempts, 0);
    assert_eq!(result.counters.dispatched, 0);
    assert!(result.latencies.is_empty());
    assert_eq!(context.report.status, RunStatus::Degraded);
    assert_eq!(result.status(), RunStatus::Degraded);
    let phase = context
        .report
        .phases
        .iter()
        .find(|phase| phase.name == PhaseName::Measurement)
        .ok_or("measurement phase")?;
    assert_eq!(
        phase.planned_end_offset_ns.ok_or("planned end")? - phase.start_offset_ns,
        40_000_000
    );
    assert!(phase.end_offset_ns.ok_or("end")? >= phase.planned_end_offset_ns.ok_or("planned end")?);
    assert_eq!(phase.status, PhaseStatus::Completed);
    let summary = context
        .connections
        .close_all(Instant::now() + Duration::from_millis(20))
        .await;
    assert_eq!((summary.clean, summary.failed), (1, 1));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn interruption_truncates_workload_without_creating_scheduler_misses() -> TestResult {
    let (mut context, signal) = context(1)?;
    context.connections.simulated(None, Duration::ZERO);
    let interrupt = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        signal.send_replace(true);
    });
    let result = idle::run(&mut context).await;
    assert!(result.is_err_and(|error| error.context() == "interrupted"));
    let phase = context
        .report
        .phases
        .iter()
        .find(|phase| phase.name == PhaseName::Measurement)
        .ok_or("measurement phase")?;
    assert_eq!(phase.status, PhaseStatus::Truncated);
    assert!(phase.end_offset_ns < phase.planned_end_offset_ns);
    assert_eq!(context.report.counters.skipped_scheduler, 0);
    assert_eq!(context.report.counters.dispatched, 0);
    context
        .connections
        .close_all(Instant::now() + Duration::from_millis(20))
        .await;
    interrupt.await?;
    Ok(())
}
