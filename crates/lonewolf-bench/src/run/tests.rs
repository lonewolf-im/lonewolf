// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::{fs, num::NonZeroUsize, os::unix::fs::PermissionsExt};

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) fn config(count: usize) -> BenchResult<RunConfig> {
    toml::from_str(&format!("[target]\nmode='local'\nserver_binary='/absent/lonewolf'\n[scenario]\nkind='idle'\nconnections={count}\n[measurement]\nwarmup_ms=10\nduration_ms=40\nsetup_timeout_ms=1000\nshutdown_timeout_ms=20\nramp_rate_per_second=1000\n"))
        .map_err(|_| failure("test_configuration"))
}

pub(crate) fn context(count: usize) -> BenchResult<(RunContext, watch::Sender<bool>)> {
    let (context, signal, _sender) = context_with_events(count)?;
    Ok((context, signal))
}

fn context_with_events(
    count: usize,
) -> BenchResult<(RunContext, watch::Sender<bool>, EventSender)> {
    let config = config(count)?;
    let report = initial_report(&config, 1);
    let (signal, interruption) = watch::channel(false);
    let invalid = Arc::new(AtomicBool::new(false));
    let (sender, events) = EventSender::new(
        event_capacity(config.measurement.max_in_flight, count)?,
        invalid.clone(),
    );
    let observed = sender.clone();
    let origin = Instant::now();
    let context = RunContext {
        connections: ConnectionSet::new(sender, invalid.clone(), RunObserver::default()),
        config,
        target: None,
        accounts: Vec::new(),
        observer: RunObserver::default(),
        report,
        fixture: None,
        cpu: CpuPool::new(NonZeroUsize::MIN),
        origin,
        setup_deadline: origin + Duration::from_secs(10),
        events,
        invalid,
        interruption,
        measurement_window: None,
        setup_attempts: 0,
        setup_failures: 0,
        message_phase: None,
        telemetry: None,
        telemetry_raw: Vec::new(),
    };
    Ok((context, signal, observed))
}

#[tokio::test]
async fn failed_setup_returns_private_partial_report_without_invented_metadata_or_window()
-> TestResult {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("output");
    let report = run(config(1)?, &output).await?;
    assert_eq!(report.status, RunStatus::Failed);
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(output.join("result.json"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(report.run_id.is_some() && report.started_at_utc.is_some());
    assert_eq!(report.counters, CounterReport::default());
    assert_eq!(report.rates, RateReport::default());
    assert!(
        !report
            .phases
            .iter()
            .any(|phase| phase.name == PhaseName::Measurement)
    );
    assert!(
        report
            .phases
            .iter()
            .all(|phase| phase.end_offset_ns.is_some() && phase.status != PhaseStatus::Running)
    );
    assert_eq!(report.phases[0].name, PhaseName::Preflight);
    assert_eq!(report.phases[1].name, PhaseName::TargetSetup);
    assert_eq!(report.phases[1].status, PhaseStatus::Failed);
    let saved: RunReport = serde_json::from_slice(&fs::read(output.join("result.json"))?)?;
    assert_eq!(saved, report);
    assert!(output.join("summary.md").is_file());
    assert!(run(config(1)?, &output).await.is_err());
    Ok(())
}

#[tokio::test]
async fn invalid_external_inputs_preserve_partial_evidence_and_status_precedence() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut config = config(1)?;
    config.target = TargetConfig::Remote {
        connect_host: "127.0.0.1".into(),
        port: 1,
        xmpp_domain: "localhost".into(),
        credentials_file: directory.path().join("credentials"),
        ca_pem: None,
        metrics_url: None,
    };
    fs::write(
        directory.path().join("credentials"),
        "malformed PRIVATE_SENTINEL",
    )?;
    fs::set_permissions(
        directory.path().join("credentials"),
        fs::Permissions::from_mode(0o600),
    )?;
    let report = run(config, &directory.path().join("output")).await?;
    assert_eq!(report.status, RunStatus::Invalid);
    assert!(
        report
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::InvalidConfig)
    );
    assert!(!serde_json::to_string(&report)?.contains("PRIVATE_SENTINEL"));
    let (mut context, _signal) = context(1)?;
    context.retain_error(failure("login_failed"));
    context.retain_error(failure("interrupted"));
    context.retain_error(invalid_input("descriptor_invalid"));
    context.retain_error(failure("late_failure"));
    assert_eq!(context.report.status, RunStatus::Invalid);
    assert_eq!(context.report.reasons.len(), 5);
    Ok(())
}

#[tokio::test]
async fn interrupted_preflight_has_no_setup_counts_or_measurement_window() -> TestResult {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("output");
    let writer = ArtifactWriter::create(&output)?;
    let (_signal, interruption) = watch::channel(true);
    let report = execute(
        config(2)?,
        writer,
        RunObserver::default(),
        interruption,
        None,
    )
    .await?;
    assert_eq!(report.status, RunStatus::Interrupted);
    assert_eq!(report.phases[0].status, PhaseStatus::Cancelled);
    assert_eq!(report.counters, CounterReport::default());
    assert_eq!(report.config.account_count(), 2);
    Ok(())
}

#[tokio::test]
async fn artifact_failure_is_reported_without_replacing_existing_files() -> TestResult {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("output");
    let writer = ArtifactWriter::create(&output)?;
    fs::write(output.join("result.json"), b"existing")?;
    let (_signal, interruption) = watch::channel(true);
    let report = execute(
        config(1)?,
        writer,
        RunObserver::default(),
        interruption,
        None,
    )
    .await?;
    assert_eq!(report.status, RunStatus::Interrupted);
    for code in [ReasonCode::Interrupted, ReasonCode::ArtifactFailure] {
        assert!(report.reasons.iter().any(|reason| reason.code == code));
    }
    assert_eq!(fs::read(output.join("result.json"))?, b"existing");
    assert!(output.join("summary.md").is_file());
    Ok(())
}

#[test]
fn workload_event_capacity_is_checked_and_overflow_is_sticky() -> TestResult {
    assert_eq!(event_capacity(10, 3)?, 110);
    assert!(event_capacity(usize::MAX, 1).is_err());
    assert!(event_capacity(1, usize::MAX).is_err());
    let invalid = Arc::new(AtomicBool::new(false));
    let (sender, mut receiver) = EventSender::new(1, invalid.clone());
    sender.emit(RunEvent::Received {
        index: 0,
        event: crate::client::ReceivedEvent {
            at: Instant::now(),
            kind: crate::client::ReceivedKind::Unexpected,
        },
    });
    sender.emit(RunEvent::ConnectionClosed {
        index: 0,
        at: Instant::now(),
    });
    assert!(invalid.load(Ordering::Acquire));
    assert!(matches!(receiver.try_recv(), Ok(RunEvent::Received { .. })));
    drop(receiver);
    sender.emit(RunEvent::Received {
        index: 0,
        event: crate::client::ReceivedEvent {
            at: Instant::now(),
            kind: crate::client::ReceivedKind::Unexpected,
        },
    });
    assert!(invalid.load(Ordering::Acquire));
    Ok(())
}

#[tokio::test]
async fn observer_is_optional_bounded_and_never_waits_for_a_receiver() -> TestResult {
    let (observer, mut events) = RunObserver::bounded(NonZeroUsize::MIN);
    observer.phase_started(PhaseName::Preflight);
    observer.active_connections(10);
    assert!(matches!(
        events.recv().await,
        Some(events::ObserverEvent::PhaseStarted(PhaseName::Preflight))
    ));
    observer.phase_finished(PhaseName::Preflight);
    drop(events);
    observer.active_connections(0);
    RunObserver::default().phase_started(PhaseName::Preflight);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn timestamped_events_belong_to_their_phase_and_not_the_drain_or_setup() -> TestResult {
    let (mut context, _signal) = context(1)?;
    let start = Instant::now();
    let warmup = context.start_phase_at(
        PhaseName::Warmup,
        start,
        Some(start + Duration::from_millis(10)),
    );
    tokio::time::advance(Duration::from_millis(10)).await;
    context.finish_phase(warmup, PhaseStatus::Completed);
    let measured = Instant::now();
    let end = measured + Duration::from_millis(40);
    context.measurement_window = Some((measured, end));
    let measurement = context.start_phase_at(PhaseName::Measurement, measured, Some(end));
    tokio::time::advance(Duration::from_millis(40)).await;
    context.finish_phase(measurement, PhaseStatus::Completed);
    let drain = context.start_phase(PhaseName::MeasurementDrain, None);
    for at in [
        start + Duration::from_millis(1),
        measured,
        end - Duration::from_nanos(1),
        end,
    ] {
        context.consume(RunEvent::ConnectionClosed { index: 0, at });
    }
    assert_eq!(
        context.report.phases[warmup]
            .counters
            .unexpected_disconnects,
        1
    );
    assert_eq!(
        context.report.phases[measurement]
            .counters
            .unexpected_disconnects,
        2
    );
    assert_eq!(
        context.report.phases[drain].counters.unexpected_disconnects,
        1
    );
    assert_eq!(context.report.counters.unexpected_disconnects, 2);
    assert_eq!(context.report.status, RunStatus::Degraded);
    Ok(())
}

#[test]
fn nullable_metadata_round_trips() -> TestResult {
    let report = initial_report(&config(1)?, 1);
    let encoded = serde_json::to_value(&report)?;
    for key in ["run_id", "started_at_utc"] {
        assert!(encoded[key].is_null());
    }
    assert!(encoded["driver"]["system"]["arch"].is_null());
    assert!(encoded["target"]["server_build"].is_null());
    assert_eq!(serde_json::from_value::<RunReport>(encoded)?, report);
    Ok(())
}

#[tokio::test]
async fn remote_credential_and_target_failures_keep_partial_evidence() -> TestResult {
    let directory = tempfile::tempdir()?;
    let credentials = directory.path().join("credentials.json");
    let mut config = config(2)?;
    config.measurement.connect_concurrency = 1;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    config.target = TargetConfig::Remote {
        connect_host: "127.0.0.1".into(),
        port,
        xmpp_domain: "localhost".into(),
        credentials_file: credentials.clone(),
        ca_pem: None,
        metrics_url: None,
    };
    let report = run(config.clone(), &directory.path().join("before_accounts")).await?;
    assert_eq!(report.status, RunStatus::Invalid);
    crate::accounts::generate_credentials("localhost", "test", 3, &credentials)?;
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        drop(socket);
        Ok::<_, std::io::Error>(())
    });
    let report = run(config, &directory.path().join("after_accounts")).await?;
    peer.await??;
    assert_eq!(report.status, RunStatus::Failed);
    assert_eq!(report.counters, CounterReport::default());
    let setup = report
        .phases
        .iter()
        .find(|phase| phase.name == PhaseName::AccountPrimingConnections)
        .ok_or("setup phase")?;
    assert_eq!(setup.counters.requested_connections, 2);
    assert_eq!(setup.counters.connection_attempts, 1);
    assert_eq!(setup.counters.login_failed, 1);
    assert!(
        !report
            .phases
            .iter()
            .any(|phase| phase.name == PhaseName::Measurement)
    );
    Ok(())
}

#[tokio::test]
async fn global_event_receiver_closes_and_cancelled_waits_keep_the_queue() -> TestResult {
    let invalid = Arc::new(AtomicBool::new(false));
    let (sender, mut receiver) = EventSender::new(2, invalid);
    assert!(
        tokio::time::timeout(Duration::from_millis(1), receiver.recv())
            .await
            .is_err()
    );
    sender.emit(RunEvent::Received {
        index: 42,
        event: crate::client::ReceivedEvent {
            at: Instant::now(),
            kind: crate::client::ReceivedKind::Unexpected,
        },
    });
    assert!(matches!(
        receiver.recv().await,
        Some(RunEvent::Received { index: 42, .. })
    ));
    drop(sender);
    assert!(receiver.recv().await.is_none());
    Ok(())
}

#[tokio::test]
async fn cleanup_awaits_cancelled_cpu_work_before_clearing_accounts() -> TestResult {
    let (mut context, _signal) = context(1)?;
    context
        .accounts
        .push(PreparedAccount::new("test@localhost", "private".into())?);
    let cpu = context.cpu.clone();
    let finished = Arc::new(AtomicBool::new(false));
    let completed = finished.clone();
    let (started, admitted) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let work = tokio::spawn(async move {
        let _ = cpu
            .run(move || {
                let _ = started.send(());
                let _ = blocked.recv();
                completed.store(true, Ordering::Release);
                Ok(())
            })
            .await;
    });
    admitted.await?;
    work.abort();
    let _ = work.await;
    let release = tokio::spawn(async move {
        sleep(Duration::from_millis(5)).await;
        let _ = release.send(());
    });
    context.cleanup().await;
    assert!(finished.load(Ordering::Acquire));
    assert!(context.accounts.is_empty());
    release.await?;
    Ok(())
}

#[tokio::test]
async fn warmup_settlement_drains_invalid_events_beyond_the_hot_loop_batch() -> TestResult {
    let (mut context, _signal, sender) = context_with_events(1)?;
    let batch = policy(&context.config).max_batch as u64;
    let phase = context.start_phase(PhaseName::Warmup, None);
    let at = Instant::now();
    for _ in 0..batch + 3 {
        sender.emit(RunEvent::Received {
            index: 0,
            event: crate::client::ReceivedEvent {
                at,
                kind: crate::client::ReceivedKind::Unexpected,
            },
        });
    }
    sender.emit(RunEvent::Invalid { index: 0, at });
    context.consume_events();
    context.finish_phase(phase, PhaseStatus::Completed);
    assert!(context.barrier_phase(PhaseName::WarmupDrain).await.is_err());
    assert_eq!(context.report.status, RunStatus::Invalid);
    assert_eq!(
        context.report.phases[phase].counters.unexpected_stanzas,
        batch + 3
    );
    assert!(context.events.try_recv().is_err());
    assert!(context.measurement_window.is_none());
    Ok(())
}

#[tokio::test]
async fn stopped_fixture_retains_finalized_safe_logs_through_artifact_finalization() -> TestResult {
    let (mut context, _signal) = context(1)?;
    let mut config = config(1)?;
    if let TargetConfig::Local { server_binary, .. } = &mut config.target {
        *server_binary = "/usr/bin/true".into();
    }
    context.fixture = Some(LocalFixture::prepare(&config, &context.cpu).await?);
    assert!(
        context
            .fixture
            .as_mut()
            .ok_or("fixture")?
            .start(Instant::now() + Duration::from_secs(1))
            .await
            .is_err()
    );
    context.cleanup().await;
    let fixture = context
        .fixture
        .as_mut()
        .ok_or("stopped fixture was dropped")?;
    assert!(fixture.credentials().is_empty());
    assert!(fixture.server_log().is_some());
    assert_eq!(fixture.stop(Duration::ZERO).await?, StopOutcome::Exited);
    let artifact = context.start_phase(PhaseName::ArtifactFinalization, None);
    assert!(
        context
            .fixture
            .as_ref()
            .and_then(LocalFixture::server_log)
            .is_some()
    );
    context.finish_phase(artifact, PhaseStatus::Completed);
    Ok(())
}

#[test]
fn observed_restart_invalidates_even_when_telemetry_already_contains_the_reason() -> TestResult {
    let (mut context, _signal) = context(1)?;
    let mut telemetry = context.report.telemetry.clone();
    telemetry.identity_changes = 1;
    telemetry.quality = TelemetryStatus::Partial;
    telemetry.reasons = vec![RunReason {
        code: ReasonCode::ServerRestarted,
        context: Some("server_restarted".into()),
    }];
    context.apply_telemetry(telemetry, Vec::new(), None);
    assert_eq!(context.report.status, RunStatus::Invalid);
    assert_eq!(
        context
            .report
            .reasons
            .iter()
            .filter(|r| r.code == ReasonCode::ServerRestarted)
            .count(),
        1
    );
    let (mut context, _signal) = self::context(1)?;
    let mut telemetry = context.report.telemetry.clone();
    telemetry.quality = TelemetryStatus::Partial;
    telemetry.reasons = vec![RunReason {
        code: ReasonCode::TelemetryPartial,
        context: Some("output_limit".into()),
    }];
    context.apply_telemetry(telemetry, Vec::new(), None);
    assert_eq!(context.report.status, RunStatus::Passed);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn failed_close_degrades_the_run_and_interruption_takes_precedence() -> TestResult {
    let (mut context, _signal) = context(1)?;
    context.connections.simulated(None, Duration::from_secs(10));
    context
        .close_connections(Instant::now() + Duration::from_millis(10))
        .await;
    assert_eq!(context.report.status, RunStatus::Degraded);
    assert!(
        context
            .report
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::OperationsFailed)
    );
    context.retain_error(failure("interrupted"));
    assert_eq!(context.report.status, RunStatus::Interrupted);
    Ok(())
}
