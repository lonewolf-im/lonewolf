// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::measurement::{DispatchPolicy, RateSchedule};
use crate::{
    client::{ConnectTimings, CorrelationId, TrafficPhase, WriterEvent},
    report::{ErrorCategory, LatencyKind, ReasonCode, RunStatus},
};
use std::{num::NonZeroU32, time::Duration};
use tokio::time::Instant;

fn nz(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
fn context(start: Instant, duration: Duration) -> LedgerContext {
    LedgerContext {
        run_nonce: [3; 16],
        phase: TrafficPhase::Measurement,
        start,
        end: start + duration,
        shutdown_timeout: ms(100),
        topology: LedgerTopology::Messages { pairs: nz(2) },
    }
}
fn ledger(planned: u64, cap: usize) -> Ledger {
    Ledger::new(planned, cap, ms(10), context(Instant::now(), ms(5))).unwrap()
}
fn admit(ledger: &mut Ledger, sequence: u64) -> CorrelationId {
    let at = ledger_context_start(ledger);
    admit_at(ledger, sequence, at, at)
}
fn ledger_context_start(ledger: &Ledger) -> Instant {
    ledger.context.start
}
fn admit_at(
    ledger: &mut Ledger,
    sequence: u64,
    scheduled: Instant,
    enqueued: Instant,
) -> CorrelationId {
    let route = ledger.expected_route(sequence).unwrap();
    let id = ledger
        .reserve(
            ScheduledSlot {
                sequence,
                scheduled_at: scheduled,
            },
            route,
        )
        .unwrap();
    ledger.commit_dispatch(id, enqueued).unwrap();
    id
}
fn receipt(ledger: &mut Ledger, id: CorrelationId, at: Instant) {
    ledger
        .observe(OperationEvent::Receipt {
            operation: id,
            at,
            route: ledger.expected_route(id.sequence).unwrap(),
        })
        .unwrap();
}
fn started(ledger: &mut Ledger, id: CorrelationId, at: Instant) {
    ledger
        .observe(OperationEvent::Writer(WriterEvent::WriteStarted {
            operation: id,
            at,
        }))
        .unwrap();
}
fn completed(ledger: &mut Ledger, id: CorrelationId, at: Instant, success: bool) {
    ledger
        .observe(OperationEvent::Writer(if success {
            WriterEvent::WriteCompleted {
                operation: id,
                at,
                bytes: 20,
            }
        } else {
            WriterEvent::WriteFailed { operation: id, at }
        }))
        .unwrap();
}
fn finish(ledger: Ledger) -> MeasurementResult {
    ledger.finish(FinishReason {
        termination: Termination::Completed,
        barrier: PhaseBarrier::RetiredAndDrained,
    })
}
fn reconcile(c: &crate::report::CounterReport) {
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
        c.write_succeeded + c.write_failed + c.write_cancelled
    );
    assert_eq!(
        c.dispatched,
        c.received_on_time
            + c.unreceived_timeout
            + c.unreceived_connection_closed
            + c.unreceived_send_failed
            + c.unreceived_cancelled
    );
    assert_eq!(
        c.received_on_time,
        c.received_in_window + c.received_during_drain
    );
    assert_eq!(
        c.dispatched,
        c.dispatched_in_window + c.dispatched_during_drain
    );
    assert_eq!(
        c.write_succeeded,
        c.write_succeeded_in_window + c.write_succeeded_during_drain
    );
}

#[test]
fn fractional_schedule_and_cohort_boundaries() {
    let start = Instant::now();
    let schedule = RateSchedule::new(
        start,
        Duration::from_secs(1),
        nz(3),
        DispatchPolicy::default(),
    )
    .unwrap();
    assert_eq!(schedule.planned(), 3);
    assert_eq!(
        schedule.slot(1).scheduled_at - start,
        Duration::from_nanos(333_333_333)
    );
    assert_eq!(
        schedule.slot(2).scheduled_at - start,
        Duration::from_nanos(666_666_666)
    );
    let tiny = RateSchedule::new(
        start,
        Duration::from_nanos(1),
        nz(3),
        DispatchPolicy::default(),
    )
    .unwrap();
    assert_eq!(tiny.planned(), 1);
    let empty = RateSchedule::new(start, Duration::ZERO, nz(3), DispatchPolicy::default()).unwrap();
    assert_eq!(empty.planned(), 0);
    for i in 0..schedule.planned() {
        assert!(schedule.slot(i).scheduled_at < schedule.end());
    }
}

#[tokio::test(start_paused = true)]
async fn rounded_wakes_dispatch_two_without_skip_and_never_spin() {
    let start = Instant::now();
    let mut schedule = RateSchedule::new(
        start,
        ms(5),
        nz(1000),
        DispatchPolicy {
            max_batch: 2,
            ..DispatchPolicy::default()
        },
    )
    .unwrap();
    tokio::time::advance(Duration::from_micros(1800)).await;
    let due = schedule.poll_due(Instant::now());
    assert_eq!(due.skipped, 0..0);
    assert_eq!(due.dispatch, 0..2);
    assert_eq!(due.next_deadline, Some(start + ms(2)));
    let repeated = schedule.poll_due(Instant::now());
    assert!(repeated.dispatch.is_empty());
    assert!(repeated.next_deadline.unwrap() > Instant::now());
    tokio::time::advance(Duration::from_micros(1800)).await;
    let due = schedule.poll_due(Instant::now());
    assert_eq!(due.dispatch, 2..4);
    assert!(due.skipped.is_empty());
}

#[test]
fn bounded_batch_stale_slots_exact_lag_and_tail() {
    let start = Instant::now();
    let policy = DispatchPolicy {
        max_batch: 2,
        lag_allowance: ms(10),
        ..DispatchPolicy::default()
    };
    let mut schedule = RateSchedule::new(start, ms(100), nz(1000), policy).unwrap();
    let due = schedule.poll_due(start + ms(50));
    assert_eq!(due.skipped, 0..40);
    assert_eq!(due.dispatch, 40..42);
    assert_eq!(due.next_deadline, Some(start + ms(51)));
    assert!(schedule.poll_due(start + ms(50)).dispatch.is_empty());
    let due = schedule.poll_due(start + ms(110));
    assert_eq!(due.skipped, 42..100);
    assert!(due.dispatch.is_empty());
    assert_eq!(due.next_deadline, None);
    let mut tail = RateSchedule::new(start, ms(3), nz(1000), policy).unwrap();
    assert_eq!(tail.poll_due(start + ms(4)).dispatch, 0..2);
    assert_eq!(tail.poll_due(start + ms(5)).dispatch, 2..3);
    assert_eq!(tail.poll_due(start + ms(6)).next_deadline, None);
    assert_eq!(tail.tail_end(), start + ms(13));
}

#[test]
fn invalid_schedule_policy_and_checked_overflow() {
    let start = Instant::now();
    assert!(
        RateSchedule::new(
            start,
            Duration::MAX,
            nz(u32::MAX),
            DispatchPolicy::default()
        )
        .is_err()
    );
    assert!(RateSchedule::new(start, Duration::MAX, nz(1000), DispatchPolicy::default()).is_err());
    assert!(
        RateSchedule::new(
            start,
            ms(1),
            nz(1000),
            DispatchPolicy {
                max_batch: 0,
                ..DispatchPolicy::default()
            }
        )
        .is_err()
    );
    assert!(
        RateSchedule::new(
            start,
            ms(1),
            nz(100_000),
            DispatchPolicy {
                max_batch: 2,
                ..DispatchPolicy::default()
            }
        )
        .is_err()
    );
    assert!(
        RateSchedule::new(
            start,
            ms(1),
            nz(1000),
            DispatchPolicy {
                quantum: ms(2),
                lag_allowance: ms(1),
                ..DispatchPolicy::default()
            }
        )
        .is_err()
    );
}

#[test]
fn all_start_flush_receipt_orderings_keep_independent_axes() {
    for success in [true, false] {
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut ledger = ledger(1, 1);
            let at = ledger_context_start(&ledger);
            let id = admit(&mut ledger, 0);
            for event in order {
                match event {
                    0 => started(&mut ledger, id, at + ms(1)),
                    1 => completed(&mut ledger, id, at + ms(3), success),
                    _ => receipt(&mut ledger, id, at + ms(2)),
                }
            }
            assert_eq!(ledger.retained(), 0);
            receipt(&mut ledger, id, at + ms(4));
            let result = finish(ledger);
            reconcile(&result.counters);
            assert_eq!(result.counters.received_on_time, 1);
            assert_eq!(result.counters.duplicates, 1);
            assert_eq!(result.counters.write_succeeded, u64::from(success));
            assert_eq!(result.counters.write_failed, u64::from(!success));
            assert_eq!(
                result.latencies[&LatencyKind::MessageWriteStartToReceive].sum_us,
                1000
            );
        }
    }
}

#[test]
fn receipt_exact_deadline_and_original_on_time_stamp_after_expiry() {
    for delay_start in [true, false] {
        let mut ledger = ledger(1, 1);
        let at = ledger_context_start(&ledger);
        let id = admit(&mut ledger, 0);
        if !delay_start {
            started(&mut ledger, id, at + ms(1));
        }
        completed(&mut ledger, id, at + ms(3), true);
        ledger.expire_through(at + ms(20)).unwrap();
        assert_eq!(ledger.retained(), 1);
        receipt(&mut ledger, id, at + ms(10));
        if delay_start {
            started(&mut ledger, id, at + ms(1));
        }
        let result = finish(ledger);
        reconcile(&result.counters);
        assert_eq!(result.counters.received_on_time, 1);
        assert_eq!(result.counters.received_during_drain, 1);
        assert_eq!(result.counters.unreceived_timeout, 0);
        assert_eq!(
            result.latencies[&LatencyKind::MessageWriteStartToReceive].sum_us,
            9000
        );
    }
}

#[test]
fn late_first_and_duplicates_never_create_timeout_samples() {
    for expire_first in [true, false] {
        let mut ledger = ledger(1, 1);
        let at = ledger_context_start(&ledger);
        let id = admit(&mut ledger, 0);
        started(&mut ledger, id, at);
        if expire_first {
            ledger.expire_through(at + ms(11)).unwrap();
        }
        receipt(&mut ledger, id, at + ms(10) + Duration::from_nanos(1));
        receipt(&mut ledger, id, at + ms(12));
        completed(&mut ledger, id, at + ms(1), true);
        let result = finish(ledger);
        reconcile(&result.counters);
        assert_eq!(result.counters.late_receipts, 1);
        assert_eq!(result.counters.duplicates, 1);
        assert_eq!(result.counters.unreceived_timeout, 1);
        assert_eq!(
            result.latencies[&LatencyKind::MessageScheduleToReceive].count,
            0
        );
    }
}

#[test]
fn duplicate_before_write_completion_is_retained_in_history() {
    let mut ledger = ledger(1, 1);
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    receipt(&mut ledger, id, at + ms(2));
    receipt(&mut ledger, id, at + ms(3));
    assert_eq!(ledger.retained(), 1);
    completed(&mut ledger, id, at + ms(4), true);
    started(&mut ledger, id, at + ms(1));
    let result = finish(ledger);
    assert_eq!(result.counters.duplicates, 1);
    reconcile(&result.counters);
}

#[test]
fn unknown_wrong_recipient_and_warmup_cannot_acknowledge_measurement() {
    let mut ledger = ledger(1, 1);
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    for invalid in [
        CorrelationId {
            run_nonce: [7; 16],
            ..id
        },
        CorrelationId { sequence: 9, ..id },
        CorrelationId {
            phase: TrafficPhase::Warmup,
            ..id
        },
    ] {
        ledger
            .observe(OperationEvent::Receipt {
                operation: invalid,
                at,
                route: RouteIdentity::Message {
                    sender_index: 0,
                    receiver_index: 1,
                },
            })
            .unwrap();
    }
    ledger
        .observe(OperationEvent::Receipt {
            operation: id,
            at,
            route: RouteIdentity::Message {
                sender_index: 0,
                receiver_index: 3,
            },
        })
        .unwrap();
    let result = finish(ledger);
    assert_eq!(result.counters.unknown_ids, 2);
    assert_eq!(result.counters.stale_phase_stanzas, 1);
    assert_eq!(result.counters.wrong_recipient, 1);
    assert_eq!(result.counters.received_on_time, 0);
    reconcile(&result.counters);
}

#[test]
fn retained_expiry_and_send_failure_are_bounded_by_cap() {
    let mut ledger = ledger(1000, 2);
    let at = ledger_context_start(&ledger);
    for i in 0..1000 {
        let slot = ScheduledSlot {
            sequence: i,
            scheduled_at: at,
        };
        let result = ledger.reserve(slot, ledger.expected_route(i).unwrap());
        if i < 2 {
            let id = result.unwrap();
            ledger.commit_dispatch(id, at).unwrap();
            started(&mut ledger, id, at);
            completed(&mut ledger, id, at, false);
        } else {
            assert!(matches!(
                result,
                Err(ReserveError::Skipped(SkipReason::InFlight))
            ));
        }
        ledger.expire_through(at + ms(20)).unwrap();
        assert!(ledger.retained() <= 2);
    }
    let result = finish(ledger);
    reconcile(&result.counters);
    assert_eq!(result.counters.skipped_in_flight, 998);
    assert_eq!(result.counters.unreceived_send_failed, 2);
    assert_eq!(result.counters.peak_in_flight, 2);
    assert_eq!(result.status(), RunStatus::Degraded);
    assert!(std::mem::size_of::<super::LedgerEntry>() <= 4);
}

#[test]
fn rollback_and_explicit_skips_never_become_dispatched() {
    let mut ledger = ledger(5, 2);
    let at = ledger_context_start(&ledger);
    let id = ledger
        .reserve(
            ScheduledSlot {
                sequence: 0,
                scheduled_at: at,
            },
            ledger.expected_route(0).unwrap(),
        )
        .unwrap();
    ledger
        .rollback_reservation(id, SkipReason::WriterBusy)
        .unwrap();
    ledger.record_skipped(1..3, SkipReason::Scheduler).unwrap();
    ledger
        .record_skipped(3..4, SkipReason::AccountBusy)
        .unwrap();
    ledger.record_skipped(4..5, SkipReason::Cancelled).unwrap();
    assert!(ledger.record_skipped(0..1, SkipReason::Scheduler).is_err());
    let result = finish(ledger);
    reconcile(&result.counters);
    assert_eq!(result.counters.dispatched, 0);
    assert_eq!(result.counters.skipped_writer_busy, 1);
    assert_eq!(result.status(), RunStatus::Invalid);
}

#[test]
fn invalid_reservation_retains_accounting_reason() {
    let mut ledger = ledger(1, 1);
    let at = ledger_context_start(&ledger);
    assert!(matches!(
        ledger.reserve(
            ScheduledSlot {
                sequence: 0,
                scheduled_at: at + ms(5)
            },
            ledger.expected_route(0).unwrap()
        ),
        Err(ReserveError::Invalid(_))
    ));
    ledger
        .record_skipped(0..1, SkipReason::AccountBusy)
        .unwrap();
    assert_eq!(finish(ledger).status(), RunStatus::Invalid);
}

#[test]
fn cancellation_and_early_failure_account_for_every_planned_slot() {
    for termination in [Termination::Cancelled, Termination::Failed] {
        let mut ledger = ledger(10, 2);
        admit(&mut ledger, 0);
        let at = ledger_context_start(&ledger);
        ledger
            .reserve(
                ScheduledSlot {
                    sequence: 1,
                    scheduled_at: at,
                },
                ledger.expected_route(1).unwrap(),
            )
            .unwrap();
        let result = ledger.finish(FinishReason {
            termination,
            barrier: PhaseBarrier::RetiredAndDrained,
        });
        reconcile(&result.counters);
        assert_eq!(result.counters.cancelled_before_dispatch, 9);
        assert_eq!(result.counters.write_cancelled, 1);
    }
}

#[test]
fn closure_and_known_send_failure_precede_timeout_but_not_delivery() {
    for send_failed in [true, false] {
        let mut ledger = ledger(1, 1);
        let at = ledger_context_start(&ledger);
        let id = admit(&mut ledger, 0);
        ledger
            .observe(OperationEvent::ConnectionClosed {
                session_index: 1,
                at: at + ms(2),
            })
            .unwrap();
        if send_failed {
            ledger
                .observe(OperationEvent::SendFailed {
                    operation: id,
                    at: at + ms(1),
                })
                .unwrap();
        }
        ledger.expire_through(at + ms(20)).unwrap();
        let result = finish(ledger);
        reconcile(&result.counters);
        assert_eq!(
            result.counters.unreceived_send_failed,
            u64::from(send_failed)
        );
        assert_eq!(
            result.counters.unreceived_connection_closed,
            u64::from(!send_failed)
        );
        assert_eq!(result.counters.unreceived_timeout, 0);
    }
}

#[test]
fn finalization_requires_correct_barrier_and_complete_cohort() {
    let mut unresolved = ledger(1, 1);
    admit(&mut unresolved, 0);
    assert_eq!(
        unresolved
            .finish(FinishReason {
                termination: Termination::Completed,
                barrier: PhaseBarrier::Settled
            })
            .status(),
        RunStatus::Invalid
    );
    assert_eq!(
        ledger(1, 1)
            .finish(FinishReason {
                termination: Termination::Completed,
                barrier: PhaseBarrier::RetiredAndDrained
            })
            .status(),
        RunStatus::Invalid
    );
    let mut warmup = ledger(1, 1);
    warmup.context.phase = TrafficPhase::Warmup;
    let at = ledger_context_start(&warmup);
    let id = admit(&mut warmup, 0);
    started(&mut warmup, id, at);
    completed(&mut warmup, id, at, true);
    warmup.expire_through(at + ms(20)).unwrap();
    receipt(&mut warmup, id, at + ms(1));
    let result = finish(warmup);
    assert_eq!(result.counters.received_on_time, 1);
    assert_eq!(result.status(), RunStatus::Passed);
}

#[test]
fn settled_phase_finalizes_expired_operations_as_degraded_timeouts() {
    let mut ledger = ledger(2, 2);
    let at = ledger_context_start(&ledger);
    let delivered = admit(&mut ledger, 0);
    started(&mut ledger, delivered, at);
    completed(&mut ledger, delivered, at, true);
    receipt(&mut ledger, delivered, at + ms(1));
    let lost = admit(&mut ledger, 1);
    started(&mut ledger, lost, at);
    completed(&mut ledger, lost, at, true);
    ledger.expire_through(at + ms(100)).unwrap();
    let result = ledger.finish(FinishReason {
        termination: Termination::Completed,
        barrier: PhaseBarrier::Settled,
    });
    reconcile(&result.counters);
    assert_eq!(result.counters.received_on_time, 1);
    assert_eq!(result.counters.unreceived_timeout, 1);
    assert_eq!(result.status(), RunStatus::Degraded);
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::OperationsFailed)
    );
}

#[test]
fn timestamp_window_splits_and_rates_use_actual_population() {
    let mut ledger = ledger(1, 1);
    let at = ledger_context_start(&ledger);
    let id = admit_at(&mut ledger, 0, at + ms(4), at + ms(5));
    started(&mut ledger, id, at + ms(5));
    receipt(&mut ledger, id, at + ms(6));
    completed(&mut ledger, id, at + ms(7), true);
    let result = finish(ledger);
    reconcile(&result.counters);
    assert_eq!(result.counters.dispatched_during_drain, 1);
    assert_eq!(result.counters.received_during_drain, 1);
    assert_eq!(result.counters.write_succeeded_during_drain, 1);
    let rates = result.rates(ms(5), 1000, LedgerTopology::Messages { pairs: nz(2) });
    assert_eq!(rates.received_in_window_per_second, Some(0.0));
    assert_eq!(rates.cohort_receipts_per_second, Some(200.0));
    assert_eq!(rates.cohort_logins_per_second, None);
}

#[test]
fn histogram_rounding_sparse_buckets_and_empty_quantiles() {
    let mut histogram = LatencyHistogram::new(ms(100)).unwrap();
    let empty = histogram.report();
    assert_eq!(empty.count, 0);
    assert_eq!(empty.min_us, None);
    assert_eq!(empty.mean_us, None);
    assert_eq!(empty.p50_us, None);
    assert_eq!(empty.max_us, None);
    for ns in [0, 1, 999, 1000, 1001, 2_123_001] {
        histogram.record(Duration::from_nanos(ns)).unwrap();
    }
    let report = histogram.report();
    assert_eq!(report.count, 6);
    assert_eq!(report.sum_us, 2129);
    assert_eq!(report.buckets.iter().map(|b| b.count).sum::<u64>(), 6);
    assert!(
        report
            .buckets
            .windows(2)
            .all(|w| w[0].upper_bound_us < w[1].upper_bound_us)
    );
    assert_eq!(report.min_us, Some(0));
    assert_eq!(report.max_us, Some(2124));
    assert!(histogram.record(ms(101)).is_err());
    assert!(LatencyHistogram::new(Duration::MAX).is_err());
    assert!(LatencyHistogram::new(Duration::ZERO).is_err());
}

#[test]
fn histogram_failure_and_event_overflow_are_visible_invalid_reasons() {
    let mut ledger = ledger(1, 1);
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    assert!(
        ledger
            .observe(OperationEvent::Writer(WriterEvent::WriteStarted {
                operation: id,
                at: at + ms(500)
            }))
            .is_err()
    );
    ledger.observe(OperationEvent::EventOverflow).unwrap();
    let result = finish(ledger);
    assert_eq!(result.status(), RunStatus::Invalid);
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::HistogramError)
    );
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::EventOverflow)
    );
}

#[test]
fn negative_latencies_fail_instead_of_saturating() {
    let mut ledger = ledger(1, 1);
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    assert!(
        ledger
            .observe(OperationEvent::Receipt {
                operation: id,
                at: at - ms(1),
                route: ledger.expected_route(0).unwrap()
            })
            .is_err()
    );
    assert_eq!(finish(ledger).status(), RunStatus::Invalid);
}

#[test]
fn churn_reconciles_bind_success_independently_of_close_failure() {
    let start = Instant::now();
    let mut context = context(start, ms(5));
    context.topology = LedgerTopology::Churn { accounts: nz(3) };
    let mut ledger = Ledger::new(4, 4, ms(20), context).unwrap();
    for i in 0..4 {
        let id = admit(&mut ledger, i);
        let login = if i < 2 {
            LoginOutcome::Succeeded {
                at: start + ms(5),
                timings: ConnectTimings {
                    tcp_us: 1000,
                    starttls_us: 1000,
                    authenticate_us: 1000,
                    bind_us: 1000,
                    total_us: 4000,
                },
            }
        } else if i == 2 {
            LoginOutcome::Failed {
                at: start + ms(2),
                category: ErrorCategory::Auth,
            }
        } else {
            LoginOutcome::Cancelled { at: start }
        };
        let close = match i {
            0 => Some(CloseOutcome::Clean { at: start + ms(8) }),
            1 => Some(CloseOutcome::Failed {
                at: start + ms(8),
                category: ErrorCategory::Cleanup,
            }),
            _ => None,
        };
        ledger
            .observe(OperationEvent::ChurnFinished {
                operation: id,
                account_index: i as u32 % 3,
                connect_started_at: (i != 3).then_some(start + ms(1)),
                login,
                close,
            })
            .unwrap();
    }
    assert_eq!(ledger.retained(), 0);
    let result = finish(ledger);
    let c = &result.counters;
    assert_eq!(c.connection_attempts, c.dispatched);
    assert_eq!(c.login_succeeded + c.login_failed, c.dispatched);
    assert_eq!(c.closed_cleanly + c.close_failed, c.login_succeeded);
    assert_eq!(c.login_in_window + c.login_during_drain, c.login_succeeded);
    assert_eq!(c.login_succeeded, 2);
    assert_eq!(c.login_during_drain, 2);
    assert_eq!(c.closed_cleanly, 1);
    assert_eq!(c.close_failed, 1);
    assert_eq!(c.write_succeeded, 0);
    assert_eq!(result.latencies[&LatencyKind::Close].sum_us, 3000);
    let rates = result.rates(ms(5), 10, context.topology);
    assert_eq!(rates.cohort_receipts_per_second, None);
    assert_eq!(rates.cohort_logins_per_second, Some(400.0));
}

#[test]
fn churn_unresolved_cancelled_attempt_is_failed_login() {
    let start = Instant::now();
    let mut context = context(start, ms(5));
    context.topology = LedgerTopology::Churn { accounts: nz(1) };
    let mut ledger = Ledger::new(2, 1, ms(10), context).unwrap();
    admit(&mut ledger, 0);
    let result = ledger.finish(FinishReason {
        termination: Termination::Cancelled,
        barrier: PhaseBarrier::RetiredAndDrained,
    });
    assert_eq!(result.counters.connection_attempts, 1);
    assert_eq!(result.counters.login_failed, 1);
    assert_eq!(result.counters.cancelled_before_dispatch, 1);
    assert_eq!(result.counters.close_failed, 0);
}

#[test]
fn invalid_ledger_bounds_and_route_mapping() {
    let start = Instant::now();
    let context = context(start, ms(5));
    assert!(Ledger::new(1, 0, ms(10), context).is_err());
    assert!(Ledger::new(10_000_001, 1, ms(10), context).is_err());
    assert!(Ledger::new(0, 1, ms(10), context).is_err());
    assert!(Ledger::new(1, 1, Duration::MAX, context).is_err());
    let ledger = Ledger::new(10, 1, ms(10), context).unwrap();
    assert_eq!(
        ledger.expected_route(3).unwrap(),
        RouteIdentity::Message {
            sender_index: 2,
            receiver_index: 3
        }
    );
    assert_eq!(
        ledger.expected_route(4).unwrap(),
        RouteIdentity::Message {
            sender_index: 0,
            receiver_index: 1
        }
    );
}

#[test]
fn settled_delivery_survives_later_stanza_failure_and_closure() {
    let mut ledger = ledger(1, 1);
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    started(&mut ledger, id, at);
    completed(&mut ledger, id, at + ms(2), true);
    receipt(&mut ledger, id, at + ms(1));
    ledger
        .observe(OperationEvent::SendFailed {
            operation: id,
            at: at + ms(3),
        })
        .unwrap();
    ledger
        .observe(OperationEvent::ConnectionClosed {
            session_index: 0,
            at: at + ms(4),
        })
        .unwrap();
    let result = finish(ledger);
    reconcile(&result.counters);
    assert_eq!(result.counters.received_on_time, 1);
    assert_eq!(result.counters.unreceived_send_failed, 0);
}

#[test]
fn duplicate_internal_events_and_reused_slots_are_accounting_errors() {
    let mut ledger = ledger(1, 1);
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    started(&mut ledger, id, at);
    assert!(
        ledger
            .observe(OperationEvent::Writer(WriterEvent::WriteStarted {
                operation: id,
                at
            }))
            .is_err()
    );
    assert!(matches!(
        ledger.reserve(
            ScheduledSlot {
                sequence: 0,
                scheduled_at: at
            },
            ledger.expected_route(0).unwrap()
        ),
        Err(ReserveError::Invalid(_))
    ));
    completed(&mut ledger, id, at, true);
    receipt(&mut ledger, id, at);
    assert_eq!(finish(ledger).status(), RunStatus::Invalid);
}

#[test]
fn healthy_warmup_settles_without_retiring_sessions() {
    let mut ledger = ledger(1, 1);
    ledger.context.phase = TrafficPhase::Warmup;
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    started(&mut ledger, id, at);
    completed(&mut ledger, id, at, true);
    receipt(&mut ledger, id, at + ms(1));
    assert!(ledger.is_settled());
    let result = ledger.finish(FinishReason {
        termination: Termination::Completed,
        barrier: PhaseBarrier::Settled,
    });
    assert_eq!(result.status(), RunStatus::Passed);
}

#[test]
fn successful_operations_release_capacity_for_a_large_cohort() {
    let mut ledger = ledger(1000, 1);
    let at = ledger_context_start(&ledger);
    for sequence in 0..1000 {
        let id = admit(&mut ledger, sequence);
        receipt(&mut ledger, id, at + ms(1));
        completed(&mut ledger, id, at + ms(2), true);
        started(&mut ledger, id, at);
        assert_eq!(ledger.retained(), 0);
    }
    let result = finish(ledger);
    reconcile(&result.counters);
    assert_eq!(result.counters.dispatched, 1000);
    assert_eq!(result.counters.peak_in_flight, 1);
    assert_eq!(result.counters.skipped_in_flight, 0);
}

#[test]
fn empty_phase_is_valid_and_has_null_rates_and_quantiles() {
    let start = Instant::now();
    let ledger = Ledger::new(0, 1, ms(10), context(start, Duration::ZERO)).unwrap();
    let result = ledger.finish(FinishReason {
        termination: Termination::Completed,
        barrier: PhaseBarrier::Settled,
    });
    assert_eq!(result.status(), RunStatus::Passed);
    assert!(
        result
            .latencies
            .values()
            .all(|h| h.count == 0 && h.p99_us.is_none())
    );
    assert_eq!(
        result
            .rates(
                Duration::ZERO,
                1000,
                LedgerTopology::Messages { pairs: nz(1) }
            )
            .planned_per_second,
        None
    );
}

#[test]
fn zero_window_rates_have_no_denominator() {
    let start = Instant::now();
    let result = finish(Ledger::new(0, 1, ms(10), context(start, Duration::ZERO)).unwrap());
    assert_eq!(
        result
            .rates(
                Duration::ZERO,
                1000,
                LedgerTopology::Messages { pairs: nz(1) }
            )
            .window_seconds,
        None
    );
}

#[test]
fn churn_rejects_impossible_or_duplicate_terminal_events() {
    for invalid_case in 0..4 {
        let start = Instant::now();
        let mut context = context(start, ms(5));
        context.topology = LedgerTopology::Churn { accounts: nz(1) };
        let mut ledger = Ledger::new(1, 1, ms(10), context).unwrap();
        let id = admit(&mut ledger, 0);
        let event = OperationEvent::ChurnFinished {
            operation: id,
            account_index: 0,
            connect_started_at: Some(start),
            login: LoginOutcome::Succeeded {
                at: start + ms(1),
                timings: ConnectTimings::default(),
            },
            close: Some(CloseOutcome::Clean { at: start + ms(2) }),
        };
        let invalid = match invalid_case {
            0 => OperationEvent::ChurnFinished {
                operation: id,
                account_index: 0,
                connect_started_at: None,
                login: LoginOutcome::Succeeded {
                    at: start + ms(1),
                    timings: ConnectTimings::default(),
                },
                close: Some(CloseOutcome::Clean { at: start + ms(2) }),
            },
            1 => OperationEvent::ChurnFinished {
                operation: id,
                account_index: 0,
                connect_started_at: Some(start),
                login: LoginOutcome::Failed {
                    at: start + ms(1),
                    category: ErrorCategory::Auth,
                },
                close: Some(CloseOutcome::Clean { at: start + ms(2) }),
            },
            2 => OperationEvent::ChurnFinished {
                operation: id,
                account_index: 0,
                connect_started_at: Some(start),
                login: LoginOutcome::Succeeded {
                    at: start + ms(1),
                    timings: ConnectTimings::default(),
                },
                close: None,
            },
            _ => {
                ledger.observe(event.clone()).unwrap();
                event
            }
        };
        assert!(ledger.observe(invalid).is_err());
        assert_eq!(finish(ledger).status(), RunStatus::Invalid);
    }
}

#[test]
fn counter_overflow_fails_visibly() {
    let mut value = u64::MAX;
    assert!(crate::measurement::increment(&mut value, 1).is_err());
    let mut ledger = ledger(1, 1);
    ledger.counters.unknown_ids = u64::MAX;
    assert!(
        ledger
            .observe(OperationEvent::Rejected(RejectedObservation::UnknownId))
            .is_err()
    );
    ledger
        .record_skipped(0..1, SkipReason::AccountBusy)
        .unwrap();
    assert_eq!(finish(ledger).status(), RunStatus::Invalid);
}

#[test]
fn closure_and_expiry_in_every_event_order_preserve_on_time_receipts() {
    for a in 0..5 {
        for b in 0..5 {
            for c in 0..5 {
                for d in 0..5 {
                    for e in 0..5 {
                        let order = [a, b, c, d, e];
                        if (0..5).any(|i| order[..i].contains(&order[i])) {
                            continue;
                        }
                        let mut ledger = ledger(1, 1);
                        let at = ledger_context_start(&ledger);
                        let id = admit(&mut ledger, 0);
                        for event in order {
                            match event {
                                0 => started(&mut ledger, id, at + ms(1)),
                                1 => completed(&mut ledger, id, at + ms(3), false),
                                2 => receipt(&mut ledger, id, at + ms(2)),
                                3 => ledger
                                    .observe(OperationEvent::ConnectionClosed {
                                        session_index: 1,
                                        at: at + ms(4),
                                    })
                                    .unwrap(),
                                _ => ledger.expire_through(at + ms(20)).unwrap(),
                            }
                        }
                        let result = finish(ledger);
                        reconcile(&result.counters);
                        assert_eq!(result.counters.received_on_time, 1);
                        assert_eq!(result.counters.unreceived_connection_closed, 0);
                        assert_eq!(result.counters.unreceived_timeout, 0);
                        assert_eq!(
                            result.latencies[&LatencyKind::MessageWriteStartToReceive].sum_us,
                            1000
                        );
                    }
                }
            }
        }
    }
}

fn churn_ledger() -> Ledger {
    let start = Instant::now();
    let mut context = context(start, ms(5));
    context.topology = LedgerTopology::Churn { accounts: nz(1) };
    Ledger::new(1, 1, ms(10), context).unwrap()
}

fn assert_churn_success_preserved(result: &MeasurementResult) {
    let c = &result.counters;
    assert_eq!(c.planned, 1);
    assert_eq!(c.dispatched, 1);
    assert_eq!(c.connection_attempts, 1);
    assert_eq!(c.login_succeeded, 1);
    assert_eq!(c.closed_cleanly, 1);
    assert_eq!(c.login_failed, 0);
    assert_eq!(c.close_failed, 0);
    assert_eq!(c.login_succeeded + c.login_failed, c.connection_attempts);
    assert_eq!(c.closed_cleanly + c.close_failed, c.login_succeeded);
    assert_eq!(result.status(), RunStatus::Invalid);
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::HistogramError)
    );
    assert!(
        !result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::AccountingError)
    );
}

#[test]
fn churn_close_histogram_overflow_preserves_terminal_success() {
    let mut ledger = churn_ledger();
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    assert!(
        ledger
            .observe(OperationEvent::ChurnFinished {
                operation: id,
                account_index: 0,
                connect_started_at: Some(at),
                login: LoginOutcome::Succeeded {
                    at: at + ms(1),
                    timings: ConnectTimings::default()
                },
                close: Some(CloseOutcome::Clean { at: at + ms(112) }),
            })
            .is_err()
    );
    assert_eq!(ledger.retained(), 0);
    let result = finish(ledger);
    assert_churn_success_preserved(&result);
    assert_eq!(result.latencies[&LatencyKind::Close].count, 0);
    assert_eq!(
        result.latencies[&LatencyKind::LoginScheduleToBound].count,
        1
    );
}

#[test]
fn early_churn_histogram_overflow_still_attempts_independent_samples() {
    let mut ledger = churn_ledger();
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    assert!(
        ledger
            .observe(OperationEvent::ChurnFinished {
                operation: id,
                account_index: 0,
                connect_started_at: Some(at),
                login: LoginOutcome::Succeeded {
                    at: at + ms(1),
                    timings: ConnectTimings {
                        tcp_us: 111_000,
                        starttls_us: 100,
                        authenticate_us: 200,
                        bind_us: 300,
                        total_us: 1000
                    }
                },
                close: Some(CloseOutcome::Clean { at: at + ms(2) }),
            })
            .is_err()
    );
    assert_eq!(ledger.retained(), 0);
    let result = finish(ledger);
    assert_churn_success_preserved(&result);
    assert_eq!(result.latencies[&LatencyKind::TcpConnect].count, 0);
    assert_eq!(result.latencies[&LatencyKind::Starttls].sum_us, 100);
    assert_eq!(result.latencies[&LatencyKind::Authenticate].sum_us, 200);
    assert_eq!(result.latencies[&LatencyKind::Bind].sum_us, 300);
    assert_eq!(result.latencies[&LatencyKind::Close].sum_us, 1000);
}

#[test]
fn dispatch_histogram_failure_cannot_undo_admission_or_authorize_rollback() {
    let mut ledger = ledger(1, 1);
    let at = ledger_context_start(&ledger);
    let id = ledger
        .reserve(
            ScheduledSlot {
                sequence: 0,
                scheduled_at: at,
            },
            ledger.expected_route(0).unwrap(),
        )
        .unwrap();
    assert!(ledger.commit_dispatch(id, at + ms(111)).is_err());
    assert_eq!(ledger.counters.dispatched, 1);
    assert!(
        !ledger
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::AccountingError)
    );
    assert!(
        ledger
            .rollback_reservation(id, SkipReason::WriterBusy)
            .is_err()
    );
    assert!(
        ledger
            .observe(OperationEvent::Writer(WriterEvent::WriteStarted {
                operation: id,
                at: at + ms(111)
            }))
            .is_err()
    );
    completed(&mut ledger, id, at + ms(112), true);
    receipt(&mut ledger, id, at + ms(113));
    let result = finish(ledger);
    reconcile(&result.counters);
    assert_eq!(result.counters.dispatched, 1);
    assert_eq!(result.counters.write_succeeded, 1);
    assert_eq!(result.counters.skipped_writer_busy, 0);
    assert_eq!(result.counters.late_receipts, 1);
    assert_eq!(result.counters.unreceived_timeout, 1);
    assert_eq!(
        result.latencies[&LatencyKind::MessageWriteDuration].sum_us,
        1000
    );
}

#[test]
fn message_histogram_failure_preserves_delivery_and_never_retries_samples() {
    let mut ledger = ledger(1, 1);
    ledger.histograms.insert(
        LatencyKind::MessageWriteStartToReceive,
        LatencyHistogram::new(Duration::from_micros(1)).unwrap(),
    );
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    started(&mut ledger, id, at);
    assert!(
        ledger
            .observe(OperationEvent::Receipt {
                operation: id,
                at: at + ms(1),
                route: ledger.expected_route(0).unwrap()
            })
            .is_err()
    );
    assert_eq!(ledger.counters.received_on_time, 1);
    assert!(ledger.active[&0].receive_start_attempted);
    assert_eq!(
        ledger.histograms[&LatencyKind::MessageScheduleToReceive]
            .report()
            .count,
        1
    );
    ledger.histograms.insert(
        LatencyKind::MessageWriteStartToReceive,
        LatencyHistogram::new(ms(100)).unwrap(),
    );
    completed(&mut ledger, id, at + ms(2), true);
    receipt(&mut ledger, id, at + ms(3));
    assert_eq!(ledger.retained(), 0);
    let result = finish(ledger);
    reconcile(&result.counters);
    assert_eq!(result.counters.received_on_time, 1);
    assert_eq!(result.counters.write_succeeded, 1);
    assert_eq!(result.counters.duplicates, 1);
    assert_eq!(
        result.latencies[&LatencyKind::MessageWriteStartToReceive].count,
        0
    );
    assert_eq!(
        result.latencies[&LatencyKind::MessageWriteDuration].count,
        1
    );
    assert_eq!(
        result.latencies[&LatencyKind::MessageScheduleToReceive].count,
        1
    );
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::HistogramError)
    );
    assert!(
        !result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::AccountingError)
    );
}

#[test]
fn invalid_barrier_returns_known_evidence_without_finalizing_active_work() {
    let mut ledger = ledger(2, 2);
    let at = ledger_context_start(&ledger);
    let first = admit(&mut ledger, 0);
    let second = admit(&mut ledger, 1);
    started(&mut ledger, first, at);
    completed(&mut ledger, first, at + ms(2), true);
    receipt(&mut ledger, first, at + ms(1));
    ledger.expire_through(at + ms(5)).unwrap();
    let result = ledger.finish(FinishReason {
        termination: Termination::Cancelled,
        barrier: PhaseBarrier::Settled,
    });
    assert_eq!(second.sequence, 1);
    assert_eq!(result.status(), RunStatus::Invalid);
    assert_eq!(result.counters.dispatched, 2);
    assert_eq!(result.counters.write_succeeded, 1);
    assert_eq!(result.counters.received_on_time, 1);
    assert_eq!(result.counters.write_cancelled, 0);
    assert_eq!(result.counters.unreceived_timeout, 0);
    assert_eq!(result.counters.unreceived_cancelled, 0);
    assert_eq!(
        result.latencies[&LatencyKind::MessageScheduleToReceive].count,
        1
    );
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::AccountingError)
    );
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::Interrupted)
    );
}

#[test]
fn incomplete_cohort_returns_partial_success_without_fabricated_skips() {
    let mut ledger = ledger(2, 1);
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    started(&mut ledger, id, at);
    completed(&mut ledger, id, at, true);
    receipt(&mut ledger, id, at + ms(1));
    let result = finish(ledger);
    assert_eq!(result.status(), RunStatus::Invalid);
    assert_eq!(result.counters.planned, 2);
    assert_eq!(result.counters.dispatched, 1);
    assert_eq!(result.counters.received_on_time, 1);
    assert_eq!(result.counters.cancelled_before_dispatch, 0);
    assert_eq!(result.counters.skipped_scheduler, 0);
    assert_eq!(
        result.latencies[&LatencyKind::MessageScheduleToReceive].count,
        1
    );
}

#[test]
fn reconciliation_failure_keeps_counters_samples_and_failure_reason() {
    let mut ledger = ledger(1, 1);
    let at = ledger_context_start(&ledger);
    let id = admit(&mut ledger, 0);
    started(&mut ledger, id, at);
    completed(&mut ledger, id, at, true);
    receipt(&mut ledger, id, at + ms(1));
    ledger.counters.dispatched_in_window = 0;
    let result = ledger.finish(FinishReason {
        termination: Termination::Failed,
        barrier: PhaseBarrier::RetiredAndDrained,
    });
    assert_eq!(result.status(), RunStatus::Invalid);
    assert_eq!(result.counters.dispatched, 1);
    assert_eq!(result.counters.dispatched_in_window, 0);
    assert_eq!(result.counters.received_on_time, 1);
    assert_eq!(
        result.latencies[&LatencyKind::MessageScheduleToReceive].count,
        1
    );
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::AccountingError)
    );
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::WorkloadFailure)
    );
}
