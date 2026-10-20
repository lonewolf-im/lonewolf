// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    client::{BodyValidation, CorrelationId},
    measurement::{DispatchPolicy, ScheduledSlot},
    report::{LatencyKind, ReasonCode, RunStatus},
    run::tests::context,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn routes(pairs: u32) -> Arc<[PairRoute]> {
    (0..pairs)
        .map(|p| PairRoute {
            sender_index: p * 2,
            receiver_index: p * 2 + 1,
            sender_jid: format!("test{}@localhost/bench", p * 2),
            receiver_jid: format!("test{}@localhost/bench", p * 2 + 1),
        })
        .collect()
}

fn phase(start: Instant, planned: u64, max: usize, end: Duration) -> BenchResult<MessagePhase> {
    Ok(MessagePhase {
        ledger: Ledger::new(
            planned,
            max,
            Duration::from_millis(20),
            LedgerContext {
                run_nonce: [7; 16],
                phase: TrafficPhase::Measurement,
                start,
                end: start + end,
                shutdown_timeout: Duration::from_millis(20),
                topology: LedgerTopology::Messages {
                    pairs: NonZeroU32::new(2)
                        .ok_or("pairs")
                        .map_err(|_| failure("test_pairs"))?,
                },
            },
        )?,
        routes: routes(2),
        payload: Arc::from("xxx"),
        nonce: [7; 16],
        phase: TrafficPhase::Measurement,
        fatal: false,
        body_bytes: 0,
        wire_bytes: 0,
        errors: Default::default(),
    })
}

fn dispatch(phase: &mut MessagePhase, sequence: u64, at: Instant) -> BenchResult<OperationId> {
    let route = phase.ledger.expected_route(sequence)?;
    let operation = phase
        .ledger
        .reserve(
            ScheduledSlot {
                sequence,
                scheduled_at: at,
            },
            route,
        )
        .map_err(|_| failure("test_reserve"))?;
    phase.ledger.commit_dispatch(operation, at)?;
    Ok(operation)
}

fn receipt(operation: OperationId, at: Instant) -> RunEvent {
    let sender = (operation.sequence % 2) as u32 * 2;
    RunEvent::Received {
        index: sender + 1,
        event: ReceivedEvent {
            at,
            kind: ReceivedKind::Chat {
                correlation: Some(operation),
                from: Some(format!("test{sender}@localhost/bench")),
                to: Some(format!("test{}@localhost/bench", sender + 1)),
                body: BodyValidation {
                    bytes: 3,
                    ascii_x: true,
                },
                route_valid: true,
            },
        },
    }
}

fn started(operation: OperationId, at: Instant) -> RunEvent {
    RunEvent::WriteStarted {
        index: (operation.sequence % 2) as u32 * 2,
        operation,
        at,
    }
}

fn written(operation: OperationId, at: Instant, succeeded: bool) -> RunEvent {
    RunEvent::WriteFinished {
        index: (operation.sequence % 2) as u32 * 2,
        operation,
        at,
        succeeded,
        bytes: if succeeded { 120 } else { 0 },
    }
}

fn finished(phase: MessagePhase) -> MeasurementResult {
    phase.finish(Termination::Completed, PhaseBarrier::RetiredAndDrained)
}

fn assert_message_equations(result: &MeasurementResult) {
    let c = &result.counters;
    assert_eq!(
        c.planned,
        c.dispatched
            + c.skipped_scheduler
            + c.skipped_in_flight
            + c.skipped_writer_busy
            + c.skipped_account_busy
            + c.cancelled_before_dispatch
    );
    assert_eq!(
        c.dispatched,
        c.dispatched_in_window + c.dispatched_during_drain
    );
    assert_eq!(
        c.dispatched,
        c.write_succeeded + c.write_failed + c.write_cancelled
    );
    assert_eq!(
        c.dispatched,
        c.received_on_time
            + c.unreceived_timeout
            + c.unreceived_send_failed
            + c.unreceived_connection_closed
            + c.unreceived_cancelled
    );
    assert_eq!(
        c.received_on_time,
        c.received_in_window + c.received_during_drain
    );
    assert_eq!(
        c.write_succeeded,
        c.write_succeeded_in_window + c.write_succeeded_during_drain
    );
}

#[test]
fn observation_order_preserves_independent_write_and_delivery_axes() -> TestResult {
    let start = Instant::now();
    for succeed in [true, false] {
        for order in [[0, 1, 2], [1, 0, 2], [1, 2, 0], [2, 1, 0]] {
            let mut phase = phase(start, 1, 2, Duration::from_millis(10))?;
            let operation = dispatch(&mut phase, 0, start)?;
            let events = [
                started(operation, start + Duration::from_millis(1)),
                receipt(operation, start + Duration::from_millis(4)),
                written(operation, start + Duration::from_millis(5), succeed),
            ];
            for index in order {
                phase.observe(events[index].clone())?;
            }
            phase.observe(receipt(operation, start + Duration::from_millis(6)))?;
            let result = finished(phase);
            assert_message_equations(&result);
            assert_eq!(result.counters.received_on_time, 1);
            assert_eq!(result.counters.duplicates, 1);
            assert_eq!(result.counters.write_succeeded, u64::from(succeed));
            assert_eq!(result.counters.write_failed, u64::from(!succeed));
            assert_eq!(
                result.counters.message_body_bytes_write_succeeded,
                if succeed { 3 } else { 0 }
            );
            assert_eq!(
                result.counters.serialized_stanza_bytes_write_succeeded,
                if succeed { 120 } else { 0 }
            );
            for kind in [
                LatencyKind::DispatchSchedulingLag,
                LatencyKind::SchedulingLag,
                LatencyKind::MessageScheduleToReceive,
                LatencyKind::MessageWriteStartToReceive,
            ] {
                assert_eq!(result.latencies[&kind].count, 1);
            }
            assert_eq!(
                result.latencies[&LatencyKind::MessageWriteDuration].count,
                u64::from(succeed)
            );
            assert!(
                !result
                    .reasons
                    .iter()
                    .any(|r| r.code == ReasonCode::AccountingError)
            );
        }
    }
    Ok(())
}

#[test]
fn wrong_connection_route_body_and_ids_never_acknowledge() -> TestResult {
    let start = Instant::now();
    for case in 0..10 {
        let mut phase = phase(start, 1, 2, Duration::from_millis(10))?;
        let operation = dispatch(&mut phase, 0, start)?;
        phase.observe(started(operation, start))?;
        phase.observe(written(operation, start, true))?;
        let RunEvent::Received {
            mut index,
            mut event,
        } = receipt(operation, start)
        else {
            return Err("receipt".into());
        };
        if let ReceivedKind::Chat {
            correlation,
            from,
            to,
            body,
            route_valid,
        } = &mut event.kind
        {
            match case {
                0 => index = 0,
                1 => *from = Some("other@localhost/bench".into()),
                2 => *to = Some("test3@localhost/bench".into()),
                3 => body.bytes = 4,
                4 => body.ascii_x = false,
                5 => *correlation = None,
                6 => correlation.as_mut().ok_or("id")?.run_nonce = [8; 16],
                7 => correlation.as_mut().ok_or("id")?.phase = TrafficPhase::Warmup,
                8 => correlation.as_mut().ok_or("id")?.sequence = 9_999_999,
                _ => *route_valid = false,
            }
        }
        phase.observe(RunEvent::Received { index, event })?;
        let result = finished(phase);
        assert_message_equations(&result);
        assert_eq!(result.counters.received_on_time, 0, "case {case}");
        assert_eq!(result.counters.unreceived_timeout, 1);
        assert_eq!(
            result.latencies[&LatencyKind::MessageScheduleToReceive].count,
            0
        );
        assert_eq!(
            result.counters.wrong_recipient
                + result.counters.unknown_ids
                + result.counters.stale_phase_stanzas,
            1
        );
    }
    for id in [
        "",
        "00000000000000000000000000000000.m.10000000",
        "00000000000000000000000000000000.m.01",
        "00000000000000000000000000000000.m.1.extra",
    ] {
        assert!(CorrelationId::parse(id).is_none());
    }
    Ok(())
}

#[test]
fn delayed_observation_uses_reader_time_and_late_receipts_have_no_timeout_samples() -> TestResult {
    let start = Instant::now();
    for receipt_ms in [20, 21] {
        let mut phase = phase(start, 1, 2, Duration::from_millis(10))?;
        let operation = dispatch(&mut phase, 0, start)?;
        phase.observe(started(operation, start + Duration::from_millis(1)))?;
        phase.observe(written(operation, start + Duration::from_millis(2), true))?;
        phase
            .ledger
            .expire_through(start + Duration::from_secs(1))?;
        phase.observe(receipt(
            operation,
            start + Duration::from_millis(receipt_ms),
        ))?;
        phase.observe(receipt(operation, start + Duration::from_millis(22)))?;
        let result = finished(phase);
        assert_message_equations(&result);
        assert_eq!(result.counters.duplicates, 1);
        let on_time = u64::from(receipt_ms == 20);
        assert_eq!(result.counters.received_on_time, on_time);
        assert_eq!(result.counters.received_during_drain, on_time);
        assert_eq!(result.counters.received_in_window, 0);
        assert_eq!(result.counters.late_receipts, 1 - on_time);
        assert_eq!(result.counters.unreceived_timeout, 1 - on_time);
        assert_eq!(
            result.latencies[&LatencyKind::MessageScheduleToReceive].count,
            on_time
        );
        assert_eq!(
            result.latencies[&LatencyKind::MessageWriteStartToReceive].count,
            on_time
        );
        let rates = result.rates(
            Duration::from_millis(10),
            100,
            LedgerTopology::Messages {
                pairs: NonZeroU32::MIN,
            },
        );
        assert_eq!(rates.received_in_window_per_second, Some(0.0));
        assert_eq!(
            rates.cohort_receipts_per_second,
            Some(on_time as f64 * 100.0)
        );
    }
    Ok(())
}

#[test]
fn sender_stanza_errors_and_disconnects_preserve_the_cohort() -> TestResult {
    let start = Instant::now();
    let mut phase = phase(start, 3, 3, Duration::from_millis(10))?;
    let first = dispatch(&mut phase, 0, start)?;
    let second = dispatch(&mut phase, 1, start)?;
    let third = dispatch(&mut phase, 2, start)?;
    for operation in [first, second, third] {
        phase.observe(started(operation, start))?;
        phase.observe(written(operation, start, true))?;
    }
    phase.observe(RunEvent::Received {
        index: 0,
        event: ReceivedEvent {
            at: start,
            kind: ReceivedKind::StanzaError {
                correlation: Some(first),
                condition: "resource-constraint",
            },
        },
    })?;
    phase.observe(RunEvent::ConnectionClosed {
        index: 3,
        at: start,
    })?;
    phase.observe(receipt(third, start))?;
    let result = finished(phase);
    assert_message_equations(&result);
    assert_eq!(
        (
            result.counters.unreceived_send_failed,
            result.counters.unreceived_connection_closed,
            result.counters.received_on_time
        ),
        (1, 1, 1)
    );
    assert_eq!(result.counters.errors[&ErrorCategory::Policy], 1);
    assert_eq!(result.status(), RunStatus::Degraded);
    Ok(())
}

#[test]
fn admission_refusals_are_counted_once_without_retry() -> TestResult {
    let start = Instant::now();
    let mut phase = phase(start, 4, 1, Duration::from_millis(10))?;
    let operation = dispatch(&mut phase, 0, start)?;
    assert!(matches!(
        phase.ledger.reserve(
            ScheduledSlot {
                sequence: 1,
                scheduled_at: start
            },
            phase.ledger.expected_route(1)?
        ),
        Err(ReserveError::Skipped(SkipReason::InFlight))
    ));
    phase.observe(started(operation, start))?;
    phase.observe(written(operation, start, true))?;
    phase.observe(receipt(operation, start))?;
    let reserved = phase
        .ledger
        .reserve(
            ScheduledSlot {
                sequence: 2,
                scheduled_at: start,
            },
            phase.ledger.expected_route(2)?,
        )
        .map_err(|_| "reserve")?;
    phase
        .ledger
        .rollback_reservation(reserved, SkipReason::WriterBusy)?;
    phase.ledger.record_skipped(3..4, SkipReason::Scheduler)?;
    let result = finished(phase);
    assert_message_equations(&result);
    assert_eq!(
        (
            result.counters.dispatched,
            result.counters.skipped_in_flight,
            result.counters.skipped_writer_busy,
            result.counters.skipped_scheduler
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(result.status(), RunStatus::Degraded);
    Ok(())
}

#[test]
fn absolute_global_slots_have_exact_pairs_and_a_bounded_original_cohort_tail() -> TestResult {
    let start = Instant::now();
    let mut schedule = RateSchedule::new(
        start,
        Duration::from_millis(10),
        NonZeroU32::new(1000).ok_or("rate")?,
        DispatchPolicy::default(),
    )?;
    assert_eq!(schedule.planned(), 10);
    let mut phase = phase(start, 10, 16, Duration::from_millis(10))?;
    let due = schedule.poll_due(start + Duration::from_millis(11));
    assert_eq!(due.dispatch, 0..10);
    for sequence in due.dispatch {
        let slot = schedule.slot(sequence);
        assert!(slot.scheduled_at < schedule.end());
        assert_eq!(
            phase.ledger.expected_route(sequence)?,
            routes(2)[sequence as usize % 2].identity()
        );
        let operation = phase
            .ledger
            .reserve(slot, phase.ledger.expected_route(sequence)?)
            .map_err(|_| "reserve")?;
        phase
            .ledger
            .commit_dispatch(operation, start + Duration::from_millis(11))?;
        phase.observe(started(operation, start + Duration::from_millis(12)))?;
        phase.observe(receipt(operation, start + Duration::from_millis(13)))?;
        phase.observe(written(operation, start + Duration::from_millis(14), true))?;
    }
    assert!(schedule.poll_due(schedule.tail_end()).dispatch.is_empty());
    let result = finished(phase);
    assert_message_equations(&result);
    assert_eq!(
        (
            result.counters.dispatched_during_drain,
            result.counters.write_succeeded_during_drain,
            result.counters.received_during_drain
        ),
        (10, 10, 10)
    );
    let rates = result.rates(
        Duration::from_millis(10),
        1000,
        LedgerTopology::Messages {
            pairs: NonZeroU32::MIN,
        },
    );
    assert_eq!(rates.cohort_receipts_per_second, Some(1000.0));
    assert_eq!(rates.dispatched_in_window_per_second, Some(0.0));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn readers_all_connected_warmup_and_fresh_measurement_complete_before_shutdown() -> TestResult
{
    let (mut context, _signal) = context(4)?;
    context.config.scenario = ScenarioConfig::Messages {
        pairs: 2,
        rate_per_second: 1000,
        body_bytes: 3,
    };
    context.report.run_id = Some("07070707070707070707070707070707".into());
    for _ in 0..4 {
        context.connections.simulated_messages();
    }
    let result = run(&mut context).await?;
    assert_message_equations(&result);
    assert_eq!(
        (result.counters.planned, result.counters.received_on_time),
        (40, 40)
    );
    assert_eq!(result.status(), RunStatus::Passed);
    let warmup = context
        .report
        .phases
        .iter()
        .find(|p| p.name == PhaseName::Warmup)
        .ok_or("warmup")?;
    assert_eq!(
        (warmup.counters.planned, warmup.counters.received_on_time),
        (10, 10)
    );
    assert_eq!(context.connections.active(), 0);
    assert_eq!(context.report.counters.connections_at_measurement_start, 4);
    assert_eq!(context.report.counters.connections_at_measurement_end, 4);
    assert_eq!(
        context.report.rates.received_in_window_per_second,
        Some(1000.0)
    );
    assert_eq!(
        context.report.counters.message_body_bytes_write_succeeded,
        120
    );
    assert_eq!(
        context
            .report
            .counters
            .serialized_stanza_bytes_write_succeeded,
        4800
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn missing_reader_or_interrupted_warmup_never_starts_measurement() -> TestResult {
    for interrupted in [false, true] {
        let (mut context, signal) = context(2)?;
        context.config.scenario = ScenarioConfig::Messages {
            pairs: 1,
            rate_per_second: 1000,
            body_bytes: 3,
        };
        context.report.run_id = Some("07070707070707070707070707070707".into());
        context.connections.simulated_messages();
        if interrupted {
            context.connections.simulated_messages();
            signal.send_replace(true);
        }
        assert!(run(&mut context).await.is_err());
        assert!(context.measurement_window.is_none());
        context
            .connections
            .close_all(Instant::now() + Duration::from_secs(1))
            .await;
    }
    Ok(())
}

#[test]
fn retirement_preserves_on_time_warmup_receipts() -> TestResult {
    let start = Instant::now();
    let mut phase = phase(start, 1, 2, Duration::from_millis(10))?;
    phase.phase = TrafficPhase::Warmup;
    phase.ledger = Ledger::new(
        1,
        2,
        Duration::from_millis(20),
        LedgerContext {
            run_nonce: [7; 16],
            phase: TrafficPhase::Warmup,
            start,
            end: start + Duration::from_millis(10),
            shutdown_timeout: Duration::from_millis(20),
            topology: LedgerTopology::Messages {
                pairs: NonZeroU32::MIN,
            },
        },
    )?;
    let operation = dispatch(&mut phase, 0, start)?;
    phase.observe(started(operation, start))?;
    phase.observe(written(operation, start + Duration::from_millis(1), true))?;
    phase
        .ledger
        .expire_through(start + Duration::from_secs(1))?;
    phase.observe(receipt(operation, start + Duration::from_millis(2)))?;
    let result = finished(phase);
    assert_message_equations(&result);
    assert_eq!(result.counters.received_on_time, 1);
    assert_eq!(result.status(), RunStatus::Passed);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn degraded_warmup_still_runs_the_measurement_without_degrading_the_run() -> TestResult {
    let (mut context, _signal) = context(4)?;
    context.config.scenario = ScenarioConfig::Messages {
        pairs: 2,
        rate_per_second: 1000,
        body_bytes: 3,
    };
    context.config.measurement.operation_timeout_ms = 20;
    context.report.run_id = Some("07070707070707070707070707070707".into());
    for _ in 0..4 {
        context.connections.simulated_lagged_messages();
    }
    let result = run(&mut context).await?;
    let warmup = context
        .report
        .phases
        .iter()
        .find(|p| p.name == PhaseName::Warmup)
        .ok_or("warmup")?;
    assert_eq!(warmup.counters.write_succeeded, 10);
    assert_eq!(warmup.counters.unreceived_timeout, 10);
    assert!(
        context
            .report
            .phases
            .iter()
            .any(|p| p.name == PhaseName::Measurement)
    );
    assert!(context.measurement_window.is_some());
    assert_eq!(result.counters.dispatched, result.counters.planned);
    assert_eq!(result.counters.stale_phase_stanzas, 10);
    assert_eq!(
        context.report.status,
        RunStatus::Passed,
        "{:?}",
        context.report.reasons
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn cancellation_and_integrity_failure_cancel_unstarted_slots_without_scheduler_misses()
-> TestResult {
    for overflow in [false, true] {
        let (mut context, signal) = context(4)?;
        context.config.scenario = ScenarioConfig::Messages {
            pairs: 2,
            rate_per_second: 1000,
            body_bytes: 3,
        };
        context.report.run_id = Some("07070707070707070707070707070707".into());
        for _ in 0..4 {
            context.connections.simulated_messages();
        }
        let invalid = context.invalid.clone();
        let stop = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            if overflow {
                invalid.store(true, Ordering::Release);
            } else {
                signal.send_replace(true);
            }
        });
        let result = run_phase(
            &mut context,
            PhaseSettings {
                routes: routes(2),
                payload: Arc::from("xxx"),
                nonce: [7; 16],
                topology: LedgerTopology::Messages {
                    pairs: NonZeroU32::new(2).ok_or("pairs")?,
                },
                phase: TrafficPhase::Measurement,
                rate: 1000,
                duration: Duration::from_millis(40),
            },
        )
        .await?;
        stop.await?;
        assert_message_equations(&result);
        assert!(result.counters.cancelled_before_dispatch > 0);
        assert_eq!(result.counters.skipped_scheduler, 0);
        assert_eq!(
            result.counters.write_succeeded,
            result.counters.received_on_time
        );
        assert_eq!(
            result.status(),
            if overflow {
                RunStatus::Invalid
            } else {
                RunStatus::Interrupted
            }
        );
        assert_eq!(context.connections.active(), 0);
    }
    Ok(())
}

#[test]
fn stream_errors_wait_for_the_connection_loss_and_keep_committed_evidence() -> TestResult {
    let start = Instant::now();
    let mut phase = phase(start, 2, 2, Duration::from_millis(10))?;
    let operation = dispatch(&mut phase, 0, start)?;
    phase.observe(RunEvent::Received {
        index: 1,
        event: ReceivedEvent {
            at: start,
            kind: ReceivedKind::StreamError,
        },
    })?;
    assert!(!phase.fatal);
    phase.observe(receipt(operation, start + Duration::from_millis(2)))?;
    phase.observe(started(operation, start))?;
    phase.observe(written(operation, start + Duration::from_millis(3), true))?;
    let result = phase.finish(Termination::Failed, PhaseBarrier::RetiredAndDrained);
    assert_message_equations(&result);
    assert_eq!(
        (
            result.counters.received_on_time,
            result.counters.cancelled_before_dispatch
        ),
        (1, 1)
    );
    assert_eq!(
        result.latencies[&LatencyKind::MessageWriteStartToReceive].count,
        1
    );
    Ok(())
}

#[test]
fn metric_failure_after_enqueue_keeps_admission_and_all_later_evidence() -> TestResult {
    let start = Instant::now();
    let mut phase = phase(start, 1, 2, Duration::from_millis(10))?;
    let operation = phase
        .ledger
        .reserve(
            ScheduledSlot {
                sequence: 0,
                scheduled_at: start,
            },
            phase.ledger.expected_route(0)?,
        )
        .map_err(|_| "reserve")?;
    assert!(
        phase
            .ledger
            .commit_dispatch(operation, start + Duration::from_millis(41))
            .is_err()
    );
    assert_eq!(phase.ledger.counters().dispatched, 1);
    assert!(
        phase
            .ledger
            .rollback_reservation(operation, SkipReason::WriterBusy)
            .is_err()
    );
    assert!(
        phase
            .observe(started(operation, start + Duration::from_millis(42)))
            .is_err()
    );
    phase.observe(written(operation, start + Duration::from_millis(43), true))?;
    let result = finished(phase);
    assert_message_equations(&result);
    assert_eq!(
        (
            result.counters.dispatched,
            result.counters.write_succeeded,
            result.counters.unreceived_timeout
        ),
        (1, 1, 1)
    );
    assert_eq!(result.counters.message_body_bytes_write_succeeded, 3);
    assert_eq!(result.status(), RunStatus::Invalid);
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::HistogramError)
    );
    Ok(())
}

#[test]
fn every_admission_rechecks_lag_and_tail_after_the_due_batch_was_selected() -> TestResult {
    let start = Instant::now();
    let policy = DispatchPolicy::default();
    let mut schedule =
        RateSchedule::new(start, Duration::from_millis(10), NonZeroU32::MIN, policy)?;
    assert_eq!(schedule.poll_due(start).dispatch, 0..1);
    let slot = schedule.slot(0);
    assert!(within_dispatch_bounds(
        slot,
        start + policy.lag_allowance,
        schedule.tail_end(),
        policy.lag_allowance
    ));
    assert!(!within_dispatch_bounds(
        slot,
        start + policy.lag_allowance + Duration::from_nanos(1),
        schedule.tail_end(),
        policy.lag_allowance
    ));
    assert!(!within_dispatch_bounds(
        slot,
        schedule.tail_end(),
        schedule.tail_end(),
        policy.lag_allowance
    ));
    Ok(())
}
