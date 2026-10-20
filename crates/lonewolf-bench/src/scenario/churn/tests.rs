// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    client::ConnectTimings,
    config::ScenarioConfig,
    report::{LatencyKind, RunStatus},
    run::tests::context,
};
use std::sync::Mutex;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type LaunchTrace = Arc<Mutex<Vec<(u32, KeyMode, String, Instant)>>>;

fn accounts(count: usize) -> BenchResult<AccountPool> {
    (0..count)
        .map(|i| PreparedAccount::new(&format!("user{i}@example.test"), "password".into()))
        .collect::<BenchResult<Vec<_>>>()
        .map(AccountPool::new)
}

fn phase(start: Instant, end: Instant, planned: u64) -> BenchResult<ChurnPhase> {
    Ok(ChurnPhase {
        ledger: Ledger::new(
            planned,
            4,
            Duration::from_secs(1),
            LedgerContext {
                run_nonce: [1; 16],
                phase: TrafficPhase::Measurement,
                start,
                end,
                shutdown_timeout: Duration::from_millis(20),
                topology: LedgerTopology::Churn {
                    accounts: NonZeroU32::MIN,
                },
            },
        )?,
        nonce: [1; 16],
        phase: TrafficPhase::Measurement,
        reasons: Vec::new(),
        errors: BTreeMap::new(),
        end,
        connected_at_end: 0,
    })
}

fn admit(phase: &mut ChurnPhase, at: Instant, sequence: u64) -> BenchResult<()> {
    let id = phase
        .ledger
        .reserve(
            ScheduledSlot {
                sequence,
                scheduled_at: at,
            },
            RouteIdentity::Churn { account_index: 0 },
        )
        .map_err(|_| failure("reservation"))?;
    phase.ledger.commit_dispatch(id, at)
}

fn success(sequence: u64, at: Instant, bound: Instant, close: CloseOutcome) -> CycleOutcome {
    CycleOutcome {
        sequence,
        account_index: 0,
        scheduled_at: at,
        connect_started_at: Some(at),
        login: LoginOutcome::Succeeded {
            at: bound,
            timings: ConnectTimings {
                tcp_us: 10,
                starttls_us: 20,
                authenticate_us: 30,
                bind_us: 40,
                total_us: 100,
            },
        },
        close: Some(close),
        failure: None,
    }
}

#[test]
fn bind_window_and_drain_use_source_time_even_when_close_fails() -> TestResult {
    let start = Instant::now();
    let end = start + Duration::from_millis(10);
    let mut phase = phase(start, end, 2)?;
    admit(&mut phase, start, 0)?;
    admit(&mut phase, start + Duration::from_millis(1), 1)?;
    phase.observe(success(
        0,
        start,
        end - Duration::from_nanos(1),
        CloseOutcome::Failed {
            at: end + Duration::from_millis(1),
            category: ErrorCategory::Cleanup,
        },
    ))?;
    phase.observe(success(
        1,
        start + Duration::from_millis(1),
        end,
        CloseOutcome::Clean {
            at: end + Duration::from_millis(2),
        },
    ))?;
    let result = phase.finish(Termination::Completed, PhaseBarrier::Settled);
    let c = &result.counters;
    assert_eq!(
        (
            c.dispatched,
            c.connection_attempts,
            c.login_succeeded,
            c.login_failed
        ),
        (2, 2, 2, 0)
    );
    assert_eq!(
        (
            c.closed_cleanly,
            c.close_failed,
            c.login_in_window,
            c.login_during_drain
        ),
        (1, 1, 1, 1)
    );
    assert_eq!((c.write_succeeded, c.received_on_time), (0, 0));
    assert_eq!(result.latencies[&LatencyKind::LoginConnectToBound].count, 2);
    assert_eq!(result.latencies[&LatencyKind::Close].count, 1);
    let rates = result.rates(
        Duration::from_millis(10),
        200,
        LedgerTopology::Churn {
            accounts: NonZeroU32::MIN,
        },
    );
    assert_eq!(
        (
            rates.login_in_window_per_second,
            rates.cohort_logins_per_second,
            rates.closed_cycles_per_second
        ),
        (Some(100.0), Some(200.0), Some(100.0))
    );
    assert_eq!(result.status(), RunStatus::Degraded);
    Ok(())
}

#[test]
fn stage_failures_deadlines_and_unpolled_cancellation_reconcile_without_latency_samples()
-> TestResult {
    for stage in [
        ConnectStage::Tcp,
        ConnectStage::Starttls,
        ConnectStage::Authenticate,
        ConnectStage::Bind,
    ] {
        for kind in [
            ConnectFailureKind::Error,
            ConnectFailureKind::Deadline,
            ConnectFailureKind::Cancelled,
        ] {
            let start = Instant::now();
            let at = start + Duration::from_millis(1);
            let mut phase = phase(start, start + Duration::from_secs(1), 1)?;
            admit(&mut phase, start, 0)?;
            phase.observe(CycleOutcome {
                sequence: 0,
                account_index: 0,
                scheduled_at: start,
                connect_started_at: Some(start),
                login: if kind == ConnectFailureKind::Cancelled {
                    LoginOutcome::Cancelled { at }
                } else {
                    LoginOutcome::Failed {
                        at,
                        category: stage_category(Some(stage)),
                    }
                },
                close: None,
                failure: Some(StageFailure {
                    stage: Some(stage),
                    kind,
                    at,
                    error: failure("xml_read"),
                }),
            })?;
            let result = phase.finish(Termination::Completed, PhaseBarrier::Settled);
            assert_eq!(
                (
                    result.counters.login_failed,
                    result.counters.closed_cleanly,
                    result.counters.close_failed
                ),
                (1, 0, 0)
            );
            assert_eq!(
                result.latencies[&LatencyKind::LoginScheduleToBound].count,
                0
            );
            if kind != ConnectFailureKind::Cancelled {
                assert_eq!(result.counters.errors[&stage_category(Some(stage))], 1);
            }
            if kind == ConnectFailureKind::Deadline {
                assert_eq!(result.counters.errors[&ErrorCategory::Deadline], 1);
            }
        }
    }
    for kind in [
        ConnectFailureKind::Deadline,
        ConnectFailureKind::Cancelled,
        ConnectFailureKind::Error,
    ] {
        let start = Instant::now();
        let mut phase = phase(start, start + Duration::from_secs(1), 1)?;
        admit(&mut phase, start, 0)?;
        phase.observe(CycleOutcome {
            sequence: 0,
            account_index: 0,
            scheduled_at: start,
            connect_started_at: None,
            login: LoginOutcome::Cancelled { at: start },
            close: None,
            failure: Some(StageFailure {
                stage: None,
                kind,
                at: start,
                error: failure("connect_deadline"),
            }),
        })?;
        let result = phase.finish(Termination::Cancelled, PhaseBarrier::Settled);
        assert_eq!(
            (
                result.counters.connection_attempts,
                result.counters.login_failed
            ),
            (1, 1)
        );
        assert_eq!(result.latencies[&LatencyKind::SchedulingLag].count, 0);
        assert!(!result.counters.errors.contains_key(&ErrorCategory::Tcp));
        if kind == ConnectFailureKind::Error {
            assert!(
                result
                    .reasons
                    .iter()
                    .any(|reason| reason.code == ReasonCode::AccountingError)
            );
            assert!(
                !result
                    .reasons
                    .iter()
                    .any(|reason| reason.code == ReasonCode::DriverLimited)
            );
        } else if kind == ConnectFailureKind::Deadline {
            assert!(
                result
                    .reasons
                    .iter()
                    .any(|reason| reason.code == ReasonCode::DriverLimited)
            );
            assert!(
                !result
                    .reasons
                    .iter()
                    .any(|reason| reason.code == ReasonCode::AccountingError)
            );
        }
        assert_eq!(
            result.status(),
            if kind == ConnectFailureKind::Error {
                RunStatus::Invalid
            } else {
                RunStatus::Interrupted
            }
        );
    }
    Ok(())
}

#[test]
fn resource_ids_are_unique_across_priming_warmup_measurement_and_max_sequence() {
    let nonce = "0123456789abcdef0123456789abcdef";
    let mut resources = std::collections::HashSet::new();
    for phase in ['p', 'w', 'm'] {
        for sequence in [0, 1, 9_999_999] {
            let value = resource(nonce, phase, sequence);
            assert!(value.len() < 1023);
            assert!(resources.insert(value));
        }
    }
}

fn fake_launch(
    trace: LaunchTrace,
    delay: Duration,
    fail_close: bool,
) -> impl FnMut(PreparedAccount, CycleRequest, CycleControl) -> CycleFuture {
    move |account, request, mut control| {
        trace.lock().unwrap().push((
            request.index,
            request.mode,
            request.resource.clone(),
            request.slot.scheduled_at,
        ));
        Box::pin(async move {
            let started = Instant::now();
            let cancelled = tokio::select! { biased; _=control.cancelled()=>true, _=tokio::time::sleep(delay)=>false };
            let at = Instant::now();
            CompletedCycle {
                account,
                tls: None,
                outcome: if cancelled {
                    CycleOutcome {
                        sequence: request.slot.sequence,
                        account_index: request.index,
                        scheduled_at: request.slot.scheduled_at,
                        connect_started_at: Some(started),
                        login: LoginOutcome::Cancelled { at },
                        close: None,
                        failure: Some(StageFailure {
                            stage: Some(ConnectStage::Authenticate),
                            kind: ConnectFailureKind::Cancelled,
                            at,
                            error: failure("connect_cancelled"),
                        }),
                    }
                } else {
                    CycleOutcome {
                        account_index: request.index,
                        connect_started_at: Some(started),
                        ..success(
                            request.slot.sequence,
                            request.slot.scheduled_at,
                            at,
                            if fail_close {
                                CloseOutcome::Failed {
                                    at,
                                    category: ErrorCategory::Deadline,
                                }
                            } else {
                                CloseOutcome::Clean { at }
                            },
                        )
                    }
                },
            }
        })
    }
}

async fn synthetic_phase(
    count: usize,
    concurrency: usize,
    delay: Duration,
    fail_close: bool,
) -> TestResult {
    let (mut context, _signal) = context(count)?;
    context.config.scenario = ScenarioConfig::Churn {
        accounts: count,
        rate_per_second: 1000,
    };
    context.config.measurement.connect_concurrency = concurrency;
    context.report.run_id = Some("0123456789abcdef0123456789abcdef".into());
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut launch = fake_launch(trace.clone(), delay, fail_close);
    let mut pool = accounts(count)?;
    let result = run_phase(
        &mut context,
        &mut pool,
        &mut launch,
        PhaseSettings {
            nonce: [1; 16],
            phase: TrafficPhase::Measurement,
            rate: 1000,
            duration: Duration::from_millis(10),
        },
    )
    .await?;
    assert_eq!(result.counters.planned, 10);
    assert_eq!(
        result.counters.planned,
        result.counters.dispatched
            + result.counters.skipped_account_busy
            + result.counters.skipped_disconnected
            + result.counters.skipped_in_flight
    );
    if fail_close {
        assert!(result.counters.skipped_disconnected > 0);
    }
    assert_eq!(
        result.counters.connection_attempts,
        result.counters.login_succeeded + result.counters.login_failed
    );
    assert_eq!(
        result.counters.closed_cleanly + result.counters.close_failed,
        result.counters.login_succeeded
    );
    assert!(result.counters.peak_in_flight <= concurrency as u64);
    assert!(pool.states.iter().all(|s| *s != ChurnAccountState::Busy));
    let trace = trace.lock().unwrap();
    for (index, mode, name, _) in trace.iter() {
        assert_eq!(*mode, KeyMode::Reuse);
        assert!(name.contains("-m-"));
        let sequence: usize = name.rsplit('-').next().ok_or("sequence")?.parse()?;
        assert_eq!(*index as usize, sequence % count);
    }
    if count == 1 && !fail_close {
        assert!(result.counters.skipped_account_busy > 0);
    }
    if concurrency < count {
        assert!(result.counters.skipped_in_flight > 0);
    }
    if fail_close {
        assert!(pool.states.contains(&ChurnAccountState::Retired));
        assert!(
            result
                .reasons
                .iter()
                .any(|r| r.context.as_deref() == Some("churn_retired_account_selected"))
        );
        assert!(trace.len() <= count);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn rotation_no_overlap_and_cycle_capacity_remain_bounded_through_close() -> TestResult {
    synthetic_phase(1, 4, Duration::from_millis(4), false).await?;
    synthetic_phase(8, 2, Duration::from_millis(4), false).await?;
    synthetic_phase(1, 4, Duration::ZERO, true).await
}

#[tokio::test(start_paused = true)]
async fn interruption_joins_cycles_and_returns_accounts_without_inventing_close() -> TestResult {
    let (mut context, signal) = context(2)?;
    context.config.measurement.connect_concurrency = 2;
    context.report.run_id = Some("0123456789abcdef0123456789abcdef".into());
    let mut pool = accounts(2)?;
    let mut launch = fake_launch(
        Arc::new(Mutex::new(Vec::new())),
        Duration::from_secs(10),
        false,
    );
    let interrupt = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(3)).await;
        signal.send_replace(true);
    });
    let result = run_phase(
        &mut context,
        &mut pool,
        &mut launch,
        PhaseSettings {
            nonce: [1; 16],
            phase: TrafficPhase::Warmup,
            rate: 1000,
            duration: Duration::from_millis(10),
        },
    )
    .await?;
    interrupt.await?;
    assert_eq!(result.status(), RunStatus::Interrupted);
    assert_eq!(result.counters.login_failed, 2);
    assert_eq!(result.counters.closed_cleanly, 0);
    assert_eq!(pool.into_accounts().len(), 2);
    assert!(context.measurement_window.is_none());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn prime_is_once_per_account_closed_and_untimed_and_failure_stops() -> TestResult {
    for fail in [false, true] {
        let (mut context, _signal) = context(3)?;
        context.config.scenario = ScenarioConfig::Churn {
            accounts: 3,
            rate_per_second: 1,
        };
        context.report.run_id = Some("0123456789abcdef0123456789abcdef".into());
        context.start_phase(PhaseName::AccountPrimingConnections, None);
        let mut pool = accounts(3)?;
        let trace = Arc::new(Mutex::new(Vec::new()));
        let mut launch = fake_launch(trace.clone(), Duration::from_millis(1), fail);
        let result = prime_with(&mut context, &mut pool, &mut launch).await;
        assert_eq!(result.is_err(), fail);
        assert!(context.measurement_window.is_none());
        assert!(context.report.latencies.is_empty());
        assert_eq!(pool.into_accounts().len(), 3);
        let trace = trace.lock().unwrap();
        if !fail {
            assert_eq!(trace.len(), 3);
        }
        for (_, mode, name, _) in trace.iter() {
            assert_eq!(*mode, KeyMode::Prime);
            assert!(name.contains("-p-"));
        }
    }
    Ok(())
}

#[test]
fn metric_failure_after_bind_keeps_login_close_and_all_other_pending_outcomes() -> TestResult {
    let start = Instant::now();
    let mut phase = phase(start, start + Duration::from_secs(1), 2)?;
    admit(&mut phase, start, 0)?;
    admit(&mut phase, start, 1)?;
    let bound = start + Duration::from_millis(1);
    let mut first = success(
        0,
        start,
        bound,
        CloseOutcome::Clean {
            at: bound + Duration::from_millis(1),
        },
    );
    if let LoginOutcome::Succeeded { timings, .. } = &mut first.login {
        timings.authenticate_us = u64::MAX;
    }
    assert!(phase.observe(first).is_err());
    phase.observe(success(
        1,
        start,
        bound,
        CloseOutcome::Cancelled {
            at: bound + Duration::from_millis(1),
        },
    ))?;
    let result = phase.finish(Termination::Failed, PhaseBarrier::Settled);
    assert_eq!(
        (
            result.counters.dispatched,
            result.counters.login_succeeded,
            result.counters.closed_cleanly,
            result.counters.close_failed
        ),
        (2, 2, 1, 1)
    );
    assert_eq!(result.latencies[&LatencyKind::LoginConnectToBound].count, 2);
    assert_eq!(result.status(), RunStatus::Invalid);
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::HistogramError)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn warmup_drains_before_fresh_measurement_epoch_and_retains_original_deadlines() -> TestResult
{
    let (mut context, _signal) = context(8)?;
    context.config.scenario = ScenarioConfig::Churn {
        accounts: 8,
        rate_per_second: 1000,
    };
    context.report.run_id = Some("0123456789abcdef0123456789abcdef".into());
    context.target = Some(ResolvedTarget {
        address: "127.0.0.1:9".parse()?,
        xmpp_domain: "example.test".into(),
        tls: client::remote_tls_config(None)?,
    });
    let settings = CycleSettings::new(&context)?;
    let mut pool = accounts(8)?;
    let trace = Arc::new(Mutex::new(Vec::new()));
    let saved = trace.clone();
    let operation_timeout = Duration::from_millis(context.config.measurement.operation_timeout_ms);
    let mut launch = move |account, request: CycleRequest, control| -> CycleFuture {
        assert_eq!(
            request.deadline,
            request.slot.scheduled_at + operation_timeout
        );
        fake_launch(saved.clone(), Duration::from_millis(3), false)(account, request, control)
    };
    let outcome = run_with(&mut context, &mut pool, &mut launch, &settings).await;
    assert!(outcome.is_ok(), "{:?}", context.report.reasons);
    let result = outcome?;
    assert_eq!(result.status(), RunStatus::Passed);
    assert_eq!(result.counters.planned, 40);
    let trace = trace.lock().unwrap();
    assert_eq!(trace.len(), 50);
    let warmup_last = trace
        .iter()
        .filter(|(_, _, name, _)| name.contains("-w-"))
        .map(|(_, _, _, at)| *at)
        .max()
        .ok_or("warmup")?;
    let measurement_first = trace
        .iter()
        .find(|(_, _, name, _)| name.contains("-m-"))
        .ok_or("measurement")?
        .3;
    assert!(measurement_first >= warmup_last + Duration::from_millis(3));
    assert!(
        pool.states
            .iter()
            .all(|state| *state == ChurnAccountState::Idle)
    );
    assert_eq!(
        context
            .report
            .phases
            .iter()
            .filter(|p| matches!(
                p.name,
                PhaseName::Warmup
                    | PhaseName::WarmupDrain
                    | PhaseName::Measurement
                    | PhaseName::MeasurementDrain
            ))
            .count(),
        4
    );
    Ok(())
}

#[test]
fn changed_parameters_invalidate_and_uncertain_close_retires_account_with_owned_cache() -> TestResult
{
    let mut pool = accounts(1)?;
    let account = pool.take(0).ok_or("account")?;
    assert!(pool.take(0).is_none());
    let start = Instant::now();
    let outcome = success(
        0,
        start,
        start,
        CloseOutcome::Failed {
            at: start,
            category: ErrorCategory::Deadline,
        },
    );
    let parameter_failure = StageFailure {
        stage: Some(ConnectStage::Authenticate),
        kind: ConnectFailureKind::Error,
        at: start,
        error: failure("scram_parameters_changed"),
    };
    let mut phase = phase(start, start + Duration::from_secs(1), 1)?;
    admit(&mut phase, start, 0)?;
    phase.observe(pool.complete(CompletedCycle {
        account,
        outcome,
        tls: None,
    }))?;
    assert_eq!(pool.states[0], ChurnAccountState::Retired);
    assert!(pool.take(0).is_none());
    assert_eq!(pool.into_accounts().len(), 1);
    assert_eq!(
        phase
            .finish(Termination::Completed, PhaseBarrier::Settled)
            .status(),
        RunStatus::Degraded
    );
    let mut phase = self::phase(start, start + Duration::from_secs(1), 1)?;
    admit(&mut phase, start, 0)?;
    phase.observe(CycleOutcome {
        sequence: 0,
        account_index: 0,
        scheduled_at: start,
        connect_started_at: Some(start),
        login: LoginOutcome::Failed {
            at: start,
            category: ErrorCategory::Auth,
        },
        close: None,
        failure: Some(parameter_failure),
    })?;
    assert_eq!(
        phase
            .finish(Termination::Completed, PhaseBarrier::Settled)
            .status(),
        RunStatus::Invalid
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn admitted_unpolled_cycle_cancellation_and_expiry_return_account_without_tcp_or_close()
-> TestResult {
    for cancelled in [true, false] {
        let (mut context, _signal) = context(1)?;
        context.target = Some(ResolvedTarget {
            address: "127.0.0.1:9".parse()?,
            xmpp_domain: "example.test".into(),
            tls: client::remote_tls_config(None)?,
        });
        let settings = CycleSettings::new(&context)?;
        let (stop, stopped) = watch::channel(cancelled);
        let control = CycleControl {
            interruption: context.interruption.clone(),
            stop: stopped,
        };
        let start = Instant::now();
        let mut pool = accounts(1)?;
        let account = pool.take(0).ok_or("account")?;
        let completed = cycle(
            account,
            CycleRequest {
                slot: ScheduledSlot {
                    sequence: 0,
                    scheduled_at: start,
                },
                index: 0,
                resource: resource("0123456789abcdef0123456789abcdef", 'm', 0),
                mode: KeyMode::Reuse,
                deadline: start,
            },
            control,
            settings,
        )
        .await;
        assert!(completed.outcome.connect_started_at.is_none());
        assert!(completed.outcome.close.is_none());
        assert!(matches!(
            completed.outcome.login,
            LoginOutcome::Cancelled { .. }
        ));
        assert_eq!(completed.account.cached_scram_iterations(), None);
        let mut phase = phase(start, start + Duration::from_secs(1), 1)?;
        admit(&mut phase, start, 0)?;
        phase.observe(pool.complete(completed))?;
        assert_eq!(pool.into_accounts().len(), 1);
        let result = phase.finish(Termination::Cancelled, PhaseBarrier::Settled);
        assert_eq!(
            (
                result.counters.dispatched,
                result.counters.connection_attempts,
                result.counters.login_failed
            ),
            (1, 1, 1)
        );
        assert_eq!(result.status(), RunStatus::Interrupted);
        drop(stop);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn cancelled_warmup_after_last_natural_close_remains_interrupted_with_settled_evidence()
-> TestResult {
    let (mut context, signal) = context(1)?;
    context.config.scenario = ScenarioConfig::Churn {
        accounts: 1,
        rate_per_second: 1,
    };
    context.config.measurement.warmup_ms = 100;
    context.report.run_id = Some("0123456789abcdef0123456789abcdef".into());
    context.target = Some(ResolvedTarget {
        address: "127.0.0.1:9".parse()?,
        xmpp_domain: "example.test".into(),
        tls: client::remote_tls_config(None)?,
    });
    let settings = CycleSettings::new(&context)?;
    let mut pool = accounts(1)?;
    let mut launch = fake_launch(Arc::new(Mutex::new(Vec::new())), Duration::ZERO, false);
    let interrupt = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        signal.send_replace(true);
    });
    let outcome = run_with(&mut context, &mut pool, &mut launch, &settings).await;
    interrupt.await?;
    assert!(outcome.is_err_and(|error| error.context() == "churn_warmup_failed"));
    assert_eq!(context.report.status, RunStatus::Interrupted);
    assert_eq!(context.report.status.exit_code(), 130);
    let warmup = context
        .report
        .phases
        .iter()
        .find(|phase| phase.name == PhaseName::Warmup)
        .ok_or("warmup")?;
    let c = &warmup.counters;
    assert_eq!(
        (
            c.planned,
            c.dispatched,
            c.connection_attempts,
            c.login_succeeded,
            c.closed_cleanly
        ),
        (1, 1, 1, 1, 1)
    );
    assert_eq!(
        (c.login_failed, c.close_failed, c.cancelled_before_dispatch),
        (0, 0, 0)
    );
    assert_eq!(c.login_in_window + c.login_during_drain, c.login_succeeded);
    assert!(
        !context
            .report
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::AccountingError)
    );
    assert!(
        context
            .report
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::Interrupted)
    );
    assert!(context.measurement_window.is_none());
    assert!(
        !context
            .report
            .phases
            .iter()
            .any(|phase| phase.name == PhaseName::Measurement)
    );
    assert_eq!(pool.states[0], ChurnAccountState::Idle);
    assert_eq!(pool.into_accounts().len(), 1);
    Ok(())
}
