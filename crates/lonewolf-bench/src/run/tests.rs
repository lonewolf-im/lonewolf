// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::os::unix::fs::PermissionsExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) fn config(count: usize) -> BenchResult<RunConfig> {
    toml::from_str(&format!("schema_version=1\nenvironment_id='test'\n[target]\nmode='local'\nserver_binary='/absent/lonewolf'\n[scenario]\nkind='idle'\nconnections={count}\n[measurement]\nwarmup_ms=10\nduration_ms=40\nsetup_timeout_ms=1000\nshutdown_timeout_ms=20\nramp_rate_per_second=1000\n"))
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
    let report = initial_report(&config);
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
        cpu: BlockingExecutor::new(NonZeroUsize::MIN),
        origin,
        setup_deadline: origin + Duration::from_secs(10),
        events,
        invalid,
        interruption,
        measurement_window: None,
        setup_attempts: 0,
        setup_failures: 0,
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
    assert!(report.environment.is_none());
    assert!(report.dataset.account_jids_sha256.is_none());
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
            .all(|phase| phase.end_offset_ns.is_some()
                && !matches!(phase.status, PhaseStatus::Pending | PhaseStatus::Running))
    );
    assert_eq!(report.phases[0].name, PhaseName::Preflight);
    assert_eq!(report.phases[1].name, PhaseName::TargetSetup);
    assert_eq!(report.phases[1].status, PhaseStatus::Failed);
    let saved: RunReport = serde_json::from_slice(&fs::read(output.join("result.json"))?)?;
    assert_eq!(saved, report);
    assert!(!output.join(".incomplete").exists());
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
        environment_file: directory.path().join("environment"),
        ca_pem: None,
        metrics_url: None,
    };
    fs::write(
        directory.path().join("environment"),
        "malformed PRIVATE_SENTINEL",
    )?;
    let report = run(config, &directory.path().join("output")).await?;
    assert_eq!(report.status, RunStatus::Invalid);
    assert!(
        report
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::InvalidConfig)
    );
    assert!(report.target.declared_build.is_none());
    assert!(report.environment.is_none());
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
    acquire_output(&output)?;
    let (_signal, interruption) = watch::channel(true);
    let report = execute(
        config(2)?,
        &output,
        RunObserver::default(),
        interruption,
        None,
    )
    .await?;
    assert_eq!(report.status, RunStatus::Interrupted);
    assert_eq!(report.phases[0].status, PhaseStatus::Cancelled);
    assert_eq!(report.counters, CounterReport::default());
    assert_eq!(report.dataset.account_count, 2);
    assert!(report.environment.is_none());
    Ok(())
}

#[tokio::test]
async fn artifact_failure_retains_all_reasons_and_an_incomplete_marker() -> TestResult {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("output");
    acquire_output(&output)?;
    fs::write(output.join("result.json"), b"existing")?;
    let (_signal, interruption) = watch::channel(true);
    let report = execute(
        config(1)?,
        &output,
        RunObserver::default(),
        interruption,
        None,
    )
    .await?;
    assert_eq!(report.status, RunStatus::Invalid);
    assert!(
        report
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::Interrupted)
    );
    assert!(
        report
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::ArtifactFailure)
    );
    assert_eq!(
        report.phases.last().map(|phase| phase.status),
        Some(PhaseStatus::Failed)
    );
    assert_eq!(fs::read(output.join("result.json"))?, b"existing");
    assert!(output.join(".incomplete").exists());
    assert!(output.join(".result.json.partial").exists());
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
        at: Instant::now(),
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
        at: Instant::now(),
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
    assert_eq!(context.report.status, RunStatus::Failed);
    Ok(())
}

#[test]
fn nullable_metadata_and_strict_remote_descriptor_validation() -> TestResult {
    let report = initial_report(&config(1)?);
    let encoded = serde_json::to_value(&report)?;
    for key in ["run_id", "started_at_utc", "environment"] {
        assert!(encoded[key].is_null());
    }
    assert!(encoded["dataset"]["account_jids_sha256"].is_null());
    assert!(encoded["driver"]["system"]["arch"].is_null());
    assert_eq!(serde_json::from_value::<RunReport>(encoded)?, report);
    let mut descriptor = descriptor()?;
    validate_descriptor(&descriptor, "test")?;
    descriptor.server.arch = None;
    assert!(validate_descriptor(&descriptor, "test").is_err());
    descriptor.server.arch = Some("test".into());
    descriptor.server_settings.max_connections_per_ip = 0;
    assert!(validate_descriptor(&descriptor, "test").is_err());
    Ok(())
}

fn descriptor() -> Result<EnvironmentDescriptor, Box<dyn std::error::Error>> {
    let settings: ServerSettings = serde_json::from_value(serde_json::json!({
        "workers":1,"stanza_pool_size_mib":8,"logging_level":"info","host_extensions":[],"storage_backend":"redb",
        "max_unauthenticated_connections":1,"max_resources_per_account":1,"max_directed_presence_recipients_per_resource":1,
        "max_connections_per_ip":1,"max_stanza_bytes":262144,"connection_establishment_timeout_secs":10,
        "authentication_timeout_secs":10,"resource_binding_timeout_secs":10,"authentication_retries":1,"resource_binding_retries":1,
        "connection_attempts_per_ip":{"rate_per_second":1,"burst":1},"incoming_stanzas_per_connection":{"rate_per_second":1,"burst":1},
        "new_recipients_per_connection":{"rate_per_second":1,"burst":1},"incoming_xml_per_connection":{"bytes_per_second":1,"burst_bytes":1},
        "offered_auth_mechanisms":["SCRAM-SHA-256"],"tls_min":"1.2","tls_max":"1.3","empty_roster":true,"offline_storage":false
    }))?;
    Ok(EnvironmentDescriptor {
        schema_version: 1,
        environment_id: "test".into(),
        network_path: NetworkPath::Loopback,
        server: system_metadata(),
        server_build: initial_report(&config(1)?)
            .target
            .declared_build
            .ok_or("local build")?,
        server_settings: settings,
    })
}

#[tokio::test]
async fn later_credential_or_target_failure_preserves_validated_environment_and_selected_hash()
-> TestResult {
    let directory = tempfile::tempdir()?;
    let environment = directory.path().join("environment.json");
    let descriptor = descriptor()?;
    fs::write(&environment, serde_json::to_vec(&descriptor)?)?;
    let credentials = directory.path().join("credentials.json");
    let mut config = config(2)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    config.target = TargetConfig::Remote {
        connect_host: "127.0.0.1".into(),
        port,
        xmpp_domain: "localhost".into(),
        credentials_file: credentials.clone(),
        environment_file: environment,
        ca_pem: None,
        metrics_url: None,
    };
    let report = run(config.clone(), &directory.path().join("before_accounts")).await?;
    assert_eq!(report.status, RunStatus::Invalid);
    assert_eq!(report.environment.as_ref(), Some(&descriptor));
    assert_eq!(
        report.target.declared_build.as_ref(),
        Some(&descriptor.server_build)
    );
    assert!(report.dataset.account_jids_sha256.is_none());
    crate::accounts::generate_credentials("localhost", "test", 3, &credentials)?;
    let hash = CredentialSet::read(&credentials, Some("localhost"), Some(2))?.jids_sha256();
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        drop(socket);
        Ok::<_, std::io::Error>(())
    });
    let report = run(config, &directory.path().join("after_accounts")).await?;
    peer.await??;
    assert_eq!(report.status, RunStatus::Failed);
    assert_eq!(report.environment.as_ref(), Some(&descriptor));
    assert_eq!(
        report.dataset.account_jids_sha256.as_deref(),
        Some(hash.as_str())
    );
    assert!(!report.target.cache_primed);
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
        at: Instant::now(),
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
        cpu.run(move || {
            let _ = started.send(());
            let _ = blocked.recv();
            completed.store(true, Ordering::Release);
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
    context.config.measurement.max_dispatch_batch = 1;
    let phase = context.start_phase(PhaseName::Warmup, None);
    let at = Instant::now();
    for _ in 0..3 {
        sender.emit(RunEvent::Received { index: 0, at });
    }
    sender.emit(RunEvent::Invalid { index: 0, at });
    context.consume_events();
    context.finish_phase(phase, PhaseStatus::Completed);
    assert!(context.barrier_phase(PhaseName::WarmupDrain).await.is_err());
    assert_eq!(context.report.status, RunStatus::Invalid);
    assert_eq!(context.report.phases[phase].counters.unexpected_stanzas, 3);
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
    assert!(fixture.sanitized_server_log().is_some());
    assert_eq!(fixture.stop(Duration::ZERO).await?, StopOutcome::Graceful);
    let artifact = context.start_phase(PhaseName::ArtifactFinalization, None);
    assert!(
        context
            .fixture
            .as_ref()
            .and_then(LocalFixture::sanitized_server_log)
            .is_some()
    );
    context.finish_phase(artifact, PhaseStatus::Completed);
    Ok(())
}
