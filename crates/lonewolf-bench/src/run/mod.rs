// SPDX-License-Identifier: Apache-2.0

pub mod connections;
pub mod events;
#[cfg(test)]
pub(crate) mod tests;

use crate::{
    accounts::CredentialSet,
    client::{PreparedAccount, ResolvedTarget, remote_tls_config},
    config::{
        MeasurementConfig, RunConfig, TargetConfig, printable, validate_build, validate_new_output,
    },
    error::{BenchError, BenchResult, ErrorCode},
    fixture::{LocalFixture, StopOutcome, preflight_descriptors},
    measurement::DispatchPolicy,
    report::*,
};
use connections::ConnectionSet;
use events::{EventReceiver, EventSender, RunEvent, RunObserver};
use lonewolf_util::blocking::BlockingExecutor;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    future::Future,
    io::{BufWriter, Read, Write},
    num::NonZeroUsize,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::watch,
    time::{Instant, sleep, sleep_until, timeout_at},
};

pub(crate) fn failure(context: &'static str) -> BenchError {
    BenchError::new(ErrorCode::Runtime, context)
}
fn invalid_input(context: &'static str) -> BenchError {
    BenchError::new(ErrorCode::InvalidConfig, context)
}

pub struct RunContext {
    pub config: RunConfig,
    pub target: Option<ResolvedTarget>,
    pub accounts: Vec<PreparedAccount>,
    pub connections: ConnectionSet,
    pub observer: RunObserver,
    pub report: RunReport,
    fixture: Option<LocalFixture>,
    cpu: BlockingExecutor,
    origin: Instant,
    setup_deadline: Instant,
    events: EventReceiver,
    invalid: Arc<AtomicBool>,
    interruption: watch::Receiver<bool>,
    pub(crate) measurement_window: Option<(Instant, Instant)>,
    setup_attempts: u64,
    setup_failures: u64,
}

pub async fn run(config: RunConfig, output: &Path) -> BenchResult<RunReport> {
    run_with_observer(config, output, RunObserver::default()).await
}

pub async fn run_with_observer(
    config: RunConfig,
    output: &Path,
    observer: RunObserver,
) -> BenchResult<RunReport> {
    config.validate()?;
    crate::scenario::validate_supported(&config.scenario)?;
    acquire_output(output)?;
    let (sender, interruption) = watch::channel(false);
    let signal = signals(sender);
    execute(config, output, observer, interruption, Some(signal)).await
}

async fn execute(
    config: RunConfig,
    output: &Path,
    observer: RunObserver,
    interruption: watch::Receiver<bool>,
    signal: Option<BenchResult<tokio::task::JoinHandle<()>>>,
) -> BenchResult<RunReport> {
    let origin = Instant::now();
    let setup_deadline = origin + Duration::from_millis(config.measurement.setup_timeout_ms);
    let capacity = event_capacity(config.measurement.max_in_flight, config.account_count())?;
    let invalid = Arc::new(AtomicBool::new(false));
    let (sender, events) = EventSender::new(capacity, invalid.clone());
    let report = initial_report(&config);
    let mut context = RunContext {
        connections: ConnectionSet::new(sender, invalid.clone(), observer.clone()),
        config,
        target: None,
        accounts: Vec::new(),
        observer,
        report,
        fixture: None,
        cpu: BlockingExecutor::new(NonZeroUsize::MIN),
        origin,
        setup_deadline,
        events,
        invalid,
        interruption,
        measurement_window: None,
        setup_attempts: 0,
        setup_failures: 0,
    };
    let mut signal_task = None;
    let phase = context.start_phase(PhaseName::Preflight, Some(setup_deadline));
    let preflight = match signal {
        Some(Err(error)) => Err(error),
        other => {
            signal_task = other.and_then(Result::ok);
            context.preflight()
        }
    };
    context.finish_phase(phase, phase_status(&preflight));
    let outcome = match preflight {
        Ok(()) => context.coordinate().await,
        Err(error) => Err(error),
    };
    if let Err(error) = outcome {
        context.retain_error(error);
    }
    context.cleanup().await;
    if *context.interruption.borrow() {
        context.reason(ReasonCode::Interrupted, "signal_received");
    }
    if let Some(task) = signal_task {
        task.abort();
        let _ = task.await;
    }
    context.consume_events();
    context.refresh_measurement();
    let phase = context.start_phase(PhaseName::ArtifactFinalization, None);
    context.finish_phase(phase, PhaseStatus::Completed);
    if publish(output, &context.report).is_err() {
        context.reason(ReasonCode::ArtifactFailure, "result_publication_failed");
        context.report.phases[phase].status = PhaseStatus::Failed;
    }
    Ok(context.report)
}

impl RunContext {
    fn preflight(&mut self) -> BenchResult<()> {
        let mut random = [0; 16];
        let identity = getrandom::fill(&mut random)
            .map(|()| hex(&random))
            .map_err(|_| failure("run_identity_unavailable"));
        self.report.run_id = identity.as_ref().ok().cloned();
        self.report.started_at_utc = utc_now();
        if let Err(error) = &identity {
            self.retain_error(error.clone());
        }
        if self.report.started_at_utc.is_none() {
            self.reason(ReasonCode::SetupFailure, "utc_time_unavailable");
        }
        self.report.driver.system = system_metadata();
        self.connections.reserve(self.config.account_count())?;
        let workers = match self.config.target {
            TargetConfig::Local { server_workers, .. } => Some(server_workers),
            TargetConfig::Remote { .. } => None,
        };
        let budget = preflight_descriptors(self.config.account_count(), workers)?;
        self.report.driver.rlimit_nofile_soft = Some(budget.soft);
        self.report.driver.rlimit_nofile_hard = Some(budget.hard);
        if let TargetConfig::Remote {
            credentials_file,
            environment_file,
            xmpp_domain,
            ..
        } = &self.config.target
        {
            let descriptor: EnvironmentDescriptor =
                serde_json::from_slice(&read_bounded(environment_file, 1_048_576)?)
                    .map_err(|_| invalid_input("remote_descriptor_schema"))?;
            validate_descriptor(&descriptor, &self.config.environment_id)?;
            self.report.target.declared_build = Some(descriptor.server_build.clone());
            self.report.environment = Some(descriptor);
            let credentials = CredentialSet::read(
                credentials_file,
                Some(xmpp_domain),
                Some(self.config.account_count()),
            )
            .map_err(|_| invalid_input("remote_credentials_invalid"))?;
            self.report.dataset.account_jids_sha256 = Some(credentials.jids_sha256());
            self.accounts = credentials
                .into_prepared()
                .map_err(|_| invalid_input("remote_credentials_invalid"))?;
        }
        identity?;
        if self.report.started_at_utc.is_none() {
            return Err(failure("utc_time_unavailable"));
        }
        self.check_running()
    }

    async fn coordinate(&mut self) -> BenchResult<()> {
        let phase = self.start_phase(PhaseName::TargetSetup, Some(self.setup_deadline));
        let outcome = self.prepare_target().await;
        self.finish_phase(phase, phase_status(&outcome));
        outcome?;
        let phase = self.start_phase(
            PhaseName::AccountPrimingConnections,
            Some(self.setup_deadline),
        );
        let outcome = match ConnectionSet::establish(self, self.config.account_count()).await {
            Ok(()) => self.connected_barrier().await,
            error => error,
        };
        self.report.phases[phase].counters.connection_attempts = self.setup_attempts;
        self.report.phases[phase].counters.login_failed = self.setup_failures;
        self.report.phases[phase].counters.requested_connections =
            self.config.account_count() as u64;
        self.report.phases[phase].counters.established_connections =
            self.connections.established() as u64;
        self.report.phases[phase].counters.login_succeeded = self.connections.established() as u64;
        self.report.phases[phase].counters.peak_connections = self.connections.peak();
        if outcome
            .as_ref()
            .is_err_and(|error| error.context() == "interrupted")
        {
            self.report.phases[phase].counters.cancelled_before_dispatch =
                self.config.account_count() as u64 - self.setup_attempts;
        }
        self.finish_phase(phase, phase_status(&outcome));
        outcome?;
        crate::scenario::idle::run(self).await?;
        Ok(())
    }

    async fn prepare_target(&mut self) -> BenchResult<()> {
        self.check_running()?;
        match &self.config.target {
            TargetConfig::Local { .. } => {
                let prepared = LocalFixture::prepare_for_run(
                    &self.config,
                    &self.cpu,
                    self.setup_deadline,
                    &mut self.interruption,
                )
                .await?;
                self.fixture = Some(prepared);
                let fixture = self
                    .fixture
                    .as_mut()
                    .ok_or_else(|| failure("fixture_owner"))?;
                let settings = fixture.sanitized_server_settings();
                let mut hash = Sha256::new();
                for account in fixture.credentials() {
                    hash.update(account.bare_jid().as_bytes());
                    hash.update(b"\n");
                }
                self.report.dataset.account_jids_sha256 = Some(hex(&hash.finalize()));
                self.report.environment = Some(EnvironmentDescriptor {
                    schema_version: 1,
                    environment_id: self.config.environment_id.clone(),
                    network_path: NetworkPath::Loopback,
                    server: self.report.driver.system.clone(),
                    server_build: self
                        .report
                        .target
                        .declared_build
                        .clone()
                        .ok_or_else(|| failure("local_build_declaration"))?,
                    server_settings: settings,
                });
                self.target = Some(
                    bounded(
                        &mut self.interruption,
                        self.setup_deadline,
                        fixture.start(self.setup_deadline),
                    )
                    .await?,
                );
            }
            TargetConfig::Remote {
                connect_host,
                port,
                xmpp_domain,
                ca_pem,
                ..
            } => {
                let extra = ca_pem
                    .as_ref()
                    .map(|path| read_bounded(path, 1_048_576))
                    .transpose()?;
                let tls = remote_tls_config(extra.as_deref())?;
                let mut addresses = bounded(&mut self.interruption, self.setup_deadline, async {
                    tokio::net::lookup_host((connect_host.as_str(), *port))
                        .await
                        .map_err(|_| failure("target_resolution_failed"))
                })
                .await?;
                let address = addresses
                    .next()
                    .ok_or_else(|| failure("target_resolution_empty"))?;
                self.target = Some(ResolvedTarget {
                    address,
                    xmpp_domain: xmpp_domain.clone(),
                    tls,
                });
            }
        }
        self.check_running()
    }

    async fn cleanup(&mut self) {
        let timeout = Duration::from_millis(self.config.measurement.shutdown_timeout_ms);
        let deadline = Instant::now() + timeout;
        let phase = self.start_phase(PhaseName::ConnectionShutdown, Some(deadline));
        let summary = self.connections.close_all(deadline).await;
        while let Ok(event) = self.events.try_recv() {
            self.consume(event);
        }
        self.consume_events();
        self.report.phases[phase].counters.closed_cleanly = summary.clean;
        self.report.phases[phase].counters.close_failed = summary.failed;
        if summary.failed > 0 {
            self.reason(ReasonCode::WorkloadFailure, "connection_close_failed");
        }
        self.finish_phase(
            phase,
            if summary.failed > 0 {
                PhaseStatus::Failed
            } else {
                PhaseStatus::Completed
            },
        );
        // One CPU permit makes this a barrier for all previously admitted jobs.
        self.cpu.run(|| ()).await;
        let phase = self.start_phase(
            PhaseName::LocalChildShutdown,
            Some(Instant::now() + timeout),
        );
        let stopped = if let Some(fixture) = &mut self.fixture {
            fixture.stop(timeout).await
        } else {
            Ok(StopOutcome::NotStarted)
        };
        if !matches!(stopped, Ok(StopOutcome::Graceful | StopOutcome::NotStarted)) {
            self.reason(ReasonCode::TargetFailure, "local_child_cleanup_failed");
        }
        self.finish_phase(
            phase,
            if matches!(stopped, Ok(StopOutcome::Graceful | StopOutcome::NotStarted)) {
                PhaseStatus::Completed
            } else {
                PhaseStatus::Failed
            },
        );
        self.accounts.clear();
    }

    pub(crate) fn consume_events(&mut self) {
        self.consume_prefix(self.config.measurement.max_dispatch_batch as usize);
    }

    fn consume_prefix(&mut self, limit: usize) {
        for _ in 0..limit {
            let Ok(event) = self.events.try_recv() else {
                break;
            };
            self.consume(event);
        }
        if self.invalid.load(Ordering::Acquire) {
            self.reason(ReasonCode::EventOverflow, "event_queue_overflow");
        }
        self.observer.active_connections(self.connections.active());
    }

    fn consume(&mut self, event: RunEvent) {
        let (at, disconnected, unexpected) = match event {
            RunEvent::ConnectionClosed { at, .. } => (at, true, false),
            RunEvent::Received { at, .. } => (at, false, true),
            RunEvent::Invalid { .. } => {
                self.invalid.store(true, Ordering::Release);
                self.reason(ReasonCode::EventOverflow, "reader_event_overflow");
                return;
            }
            RunEvent::WriteStarted { .. } | RunEvent::WriteFinished { .. } => {
                self.reason(ReasonCode::AccountingError, "idle_application_write");
                return;
            }
        };
        let offset = self.offset(at);
        if let Some(phase) =
            self.report.phases.iter_mut().rev().find(|p| {
                p.start_offset_ns <= offset && p.end_offset_ns.is_none_or(|end| offset < end)
            })
        {
            phase.counters.unexpected_disconnects += u64::from(disconnected);
            phase.counters.unexpected_stanzas += u64::from(unexpected);
        }
        if self
            .measurement_window
            .is_some_and(|(start, end)| start <= at && at < end)
            && self
                .report
                .phases
                .iter()
                .find(|phase| phase.name == PhaseName::Measurement)
                .is_some_and(|phase| phase.end_offset_ns.is_none_or(|end| offset < end))
        {
            self.report.counters.unexpected_disconnects += u64::from(disconnected);
            self.report.counters.unexpected_stanzas += u64::from(unexpected);
        }
        self.reason(
            ReasonCode::WorkloadFailure,
            if disconnected {
                "unexpected_disconnect"
            } else {
                "unexpected_idle_traffic"
            },
        );
    }

    pub(crate) async fn connected_barrier(&mut self) -> BenchResult<()> {
        self.settle_until(self.setup_deadline).await?;
        self.check_running()
    }

    pub(crate) async fn settle(&mut self) -> BenchResult<()> {
        self.settle_until(
            Instant::now() + Duration::from_millis(self.config.measurement.operation_timeout_ms),
        )
        .await
    }

    async fn settle_until(&mut self, deadline: Instant) -> BenchResult<()> {
        self.connections.begin_barrier();
        while !self.connections.settled() {
            tokio::select! {
                event = self.events.recv() => if let Some(event) = event { self.consume(event); },
                _ = sleep(Duration::from_millis(1)) => {},
                _ = sleep_until(deadline) => return Err(failure("phase_barrier_deadline")),
            }
        }
        self.consume_prefix(event_capacity(
            self.config.measurement.max_in_flight,
            self.config.account_count(),
        )?);
        if self.invalid.load(Ordering::Acquire) {
            Err(failure("event_queue_overflow"))
        } else if self.report.status == RunStatus::Invalid {
            Err(failure("run_integrity_failure"))
        } else {
            Ok(())
        }
    }

    pub(crate) async fn barrier_phase(&mut self, name: PhaseName) -> BenchResult<()> {
        let phase = self.start_phase(name, None);
        let result = self.settle().await;
        self.finish_phase(phase, phase_status(&result));
        result
    }

    pub(crate) async fn hold(&mut self, name: PhaseName, duration: Duration) -> BenchResult<()> {
        let start = Instant::now();
        self.hold_until(name, start, start + duration).await
    }

    pub(crate) async fn hold_until(
        &mut self,
        name: PhaseName,
        start: Instant,
        end: Instant,
    ) -> BenchResult<()> {
        let phase = self.start_phase_at(name, start, Some(end));
        let result = loop {
            self.consume_events();
            if *self.interruption.borrow() {
                break Err(failure("interrupted"));
            }
            if self.invalid.load(Ordering::Acquire) {
                break Err(failure("event_queue_overflow"));
            }
            if self.report.status == RunStatus::Invalid {
                break Err(failure("run_integrity_failure"));
            }
            if Instant::now() >= end {
                break Ok(());
            }
            tokio::select! {
                biased;
                _ = self.interruption.changed() => break Err(failure("interrupted")),
                event = self.events.recv() => if let Some(event) = event { self.consume(event); },
                _ = sleep_until(end) => break Ok(()),
            }
        };
        self.consume_events();
        if let Err(error) = &result {
            self.retain_error(error.clone());
        }
        self.finish_phase(
            phase,
            if result.is_ok() {
                PhaseStatus::Completed
            } else {
                PhaseStatus::Truncated
            },
        );
        result
    }

    pub(crate) fn refresh_measurement(&mut self) {
        if let Some((start, end)) = self.measurement_window {
            self.report.counters.connections_at_measurement_start =
                self.connections.active_at(start);
            self.report.counters.peak_connections =
                self.report.counters.connections_at_measurement_start;
            if let Some(phase) = self
                .report
                .phases
                .iter()
                .find(|p| p.name == PhaseName::Measurement)
            {
                let observed = self.origin
                    + Duration::from_nanos(phase.end_offset_ns.unwrap_or(phase.start_offset_ns));
                self.report.counters.connections_at_measurement_end =
                    self.connections.active_at(end.min(observed));
            }
            if let Some(phase) = self
                .report
                .phases
                .iter_mut()
                .find(|p| p.name == PhaseName::Measurement)
            {
                phase.counters = self.report.counters.clone();
            }
        }
    }

    fn check_running(&self) -> BenchResult<()> {
        if *self.interruption.borrow() {
            Err(failure("interrupted"))
        } else if Instant::now() >= self.setup_deadline {
            Err(failure("setup_deadline"))
        } else {
            Ok(())
        }
    }
    fn offset(&self, at: Instant) -> u64 {
        at.saturating_duration_since(self.origin)
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64
    }
    fn start_phase(&mut self, name: PhaseName, deadline: Option<Instant>) -> usize {
        self.start_phase_at(name, Instant::now(), deadline)
    }
    fn start_phase_at(
        &mut self,
        name: PhaseName,
        start: Instant,
        deadline: Option<Instant>,
    ) -> usize {
        let index = self.report.phases.len();
        self.report.phases.push(PhaseReport {
            name,
            start_offset_ns: self.offset(start),
            end_offset_ns: None,
            planned_end_offset_ns: deadline.map(|at| self.offset(at)),
            status: PhaseStatus::Running,
            counters: CounterReport::default(),
            rates: RateReport::default(),
        });
        self.observer.phase_started(name);
        index
    }
    fn finish_phase(&mut self, index: usize, status: PhaseStatus) {
        let end = self.offset(Instant::now());
        let phase = &mut self.report.phases[index];
        phase.end_offset_ns = Some(end);
        phase.status = status;
        self.observer.phase_finished(phase.name);
    }
    fn retain_error(&mut self, error: BenchError) {
        let code = match (error.code, error.context()) {
            (_, "interrupted") => ReasonCode::Interrupted,
            (_, "ramp_scheduler_miss") => ReasonCode::SchedulerMiss,
            (_, "run_integrity_failure") => ReasonCode::AccountingError,
            (_, "event_queue_overflow" | "phase_barrier_deadline") => ReasonCode::EventOverflow,
            (ErrorCode::InvalidConfig, _) => ReasonCode::InvalidConfig,
            _ if self.measurement_window.is_some() => ReasonCode::WorkloadFailure,
            _ => ReasonCode::SetupFailure,
        };
        self.reason(code, error.context());
    }
    fn reason(&mut self, code: ReasonCode, context: &'static str) {
        if self
            .report
            .reasons
            .iter()
            .any(|reason| reason.code == code && reason.context.as_deref() == Some(context))
        {
            return;
        }
        self.report.reasons.push(RunReason {
            code,
            context: Some(context.into()),
        });
        self.report.status = crate::measurement::MeasurementResult {
            counters: CounterReport::default(),
            latencies: BTreeMap::new(),
            reasons: self.report.reasons.clone(),
        }
        .status();
    }
}

fn phase_status(result: &BenchResult<()>) -> PhaseStatus {
    match result {
        Ok(()) => PhaseStatus::Completed,
        Err(error) if error.context() == "interrupted" => PhaseStatus::Cancelled,
        Err(_) => PhaseStatus::Failed,
    }
}

pub(crate) fn policy(config: &MeasurementConfig) -> DispatchPolicy {
    DispatchPolicy {
        quantum: Duration::from_micros(config.dispatch_quantum_us),
        max_batch: config.max_dispatch_batch as u32,
        lag_allowance: Duration::from_millis(config.max_schedule_lag_ms),
    }
}

fn event_capacity(max_in_flight: usize, accounts: usize) -> BenchResult<usize> {
    max_in_flight
        .checked_mul(4)
        .and_then(|n| accounts.checked_mul(2).and_then(|a| n.checked_add(a)))
        .and_then(|n| n.checked_add(64))
        .ok_or_else(|| failure("event_capacity_overflow"))
}

async fn bounded<T>(
    interruption: &mut watch::Receiver<bool>,
    deadline: Instant,
    work: impl Future<Output = BenchResult<T>>,
) -> BenchResult<T> {
    if *interruption.borrow() {
        return Err(failure("interrupted"));
    }
    tokio::select! {
        biased;
        _ = interruption.changed() => Err(failure("interrupted")),
        result = timeout_at(deadline, work) => result.map_err(|_| failure("setup_deadline"))?,
    }
}

fn signals(sender: watch::Sender<bool>) -> BenchResult<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|_| failure("signal_registration"))?;
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|_| failure("signal_registration"))?;
    Ok(tokio::spawn(async move {
        tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        sender.send_replace(true);
    }))
}

fn acquire_output(output: &Path) -> BenchResult<()> {
    validate_new_output(output)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|_| BenchError::new(ErrorCode::InvalidPath, "output_directory_create"))?;
    Ok(())
}

fn publish(output: &Path, report: &RunReport) -> BenchResult<()> {
    let error = || BenchError::new(ErrorCode::ArtifactFailure, "result_publication_failed");
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(output.join(".incomplete"))
        .map_err(|_| error())?;
    let staging = output.join(".result.json.partial");
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&staging)
        .map_err(|_| error())?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, report).map_err(|_| error())?;
    writer.flush().map_err(|_| error())?;
    writer.get_ref().sync_all().map_err(|_| error())?;
    fs::hard_link(&staging, output.join("result.json")).map_err(|_| error())?;
    fs::remove_file(staging).map_err(|_| error())?;
    fs::remove_file(output.join(".incomplete")).map_err(|_| error())?;
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> BenchResult<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| invalid_input("input_file_open"))?;
    let metadata = file
        .metadata()
        .map_err(|_| invalid_input("input_file_metadata"))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(invalid_input("input_file_size_or_type"));
    }
    let mut data = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| invalid_input("input_file_read"))?;
    if data.len() as u64 > limit {
        return Err(invalid_input("input_file_size"));
    }
    Ok(data)
}

fn validate_descriptor(
    descriptor: &EnvironmentDescriptor,
    environment_id: &str,
) -> BenchResult<()> {
    let system = &descriptor.server;
    let build = &descriptor.server_build;
    let settings = &descriptor.server_settings;
    if descriptor.schema_version != 1
        || descriptor.environment_id != environment_id
        || !system
            .os_release
            .as_deref()
            .is_some_and(|v| printable(v, 1024))
        || !system.arch.as_deref().is_some_and(|v| printable(v, 128))
        || !printable(&build.revision, 1024)
        || settings.workers == 0
        || settings.stanza_pool_size_mib == 0
        || !printable(&settings.logging_level, 32)
        || !printable(&settings.storage_backend, 64)
        || settings.max_unauthenticated_connections == 0
        || settings.max_resources_per_account == 0
        || settings.max_connections_per_ip == 0
        || settings.max_stanza_bytes == 0
        || settings.connection_establishment_timeout_secs == 0
        || settings.authentication_timeout_secs == 0
        || settings.resource_binding_timeout_secs == 0
        || settings.connection_attempts_per_ip.rate_per_second == 0
        || settings.connection_attempts_per_ip.burst == 0
        || settings.incoming_stanzas_per_connection.rate_per_second == 0
        || settings.incoming_stanzas_per_connection.burst == 0
        || settings.new_recipients_per_connection.rate_per_second == 0
        || settings.new_recipients_per_connection.burst == 0
        || settings.incoming_xml_per_connection.bytes_per_second == 0
        || settings.incoming_xml_per_connection.burst_bytes == 0
        || !settings.host_extensions.iter().all(|v| printable(v, 128))
        || !settings
            .offered_auth_mechanisms
            .iter()
            .any(|v| v == "SCRAM-SHA-256")
        || !settings
            .offered_auth_mechanisms
            .iter()
            .all(|v| printable(v, 128))
        || !matches!(settings.tls_min.as_str(), "1.2" | "1.3")
        || !matches!(settings.tls_max.as_str(), "1.2" | "1.3")
    {
        return Err(invalid_input("remote_descriptor_invalid"));
    }
    validate_build(
        &build.profile,
        build.toolchain.as_deref(),
        build.features.as_deref(),
    )
    .map_err(|_| invalid_input("remote_descriptor_build"))
}

fn initial_report(config: &RunConfig) -> RunReport {
    let mode = match config.target {
        TargetConfig::Local { .. } => TargetMode::Local,
        TargetConfig::Remote { .. } => TargetMode::Remote,
    };
    let (domain, endpoint, build) = match &config.target {
        TargetConfig::Local {
            server_revision,
            server_profile,
            server_toolchain,
            server_features,
            ..
        } => (
            "localhost".into(),
            None,
            Some(ServerBuildDeclaration {
                revision: server_revision.clone(),
                profile: server_profile.clone(),
                toolchain: server_toolchain.clone(),
                features: server_features.clone(),
            }),
        ),
        TargetConfig::Remote {
            xmpp_domain,
            connect_host,
            port,
            ..
        } => (
            xmpp_domain.clone(),
            Some(format!("{connect_host}:{port}")),
            None,
        ),
    };
    RunReport {
        schema_version: 1,
        measurement_version: 1,
        run_id: None,
        started_at_utc: None,
        status: RunStatus::Passed,
        reasons: vec![RunReason {
            code: ReasonCode::TelemetryUnavailable,
            context: None,
        }],
        telemetry_status: TelemetryStatus::Unavailable,
        phases: Vec::with_capacity(10),
        config: SanitizedConfig::from(config),
        driver: DriverMetadata {
            executable_sha256: None,
            package_version: env!("CARGO_PKG_VERSION").into(),
            revision: env!("LONEWOLF_BENCH_REVISION").into(),
            build_profile: env!("LONEWOLF_BENCH_PROFILE").into(),
            build_target: env!("LONEWOLF_BENCH_TARGET").into(),
            rustc: env!("LONEWOLF_BENCH_RUSTC").into(),
            worker_count: config.measurement.driver_workers,
            scheduler_policy: policy(&config.measurement).metadata(),
            available_parallelism: std::thread::available_parallelism()
                .ok()
                .map(NonZeroUsize::get),
            rlimit_nofile_soft: None,
            rlimit_nofile_hard: None,
            system: unknown_system(),
            sources: BTreeMap::new(),
        },
        target: TargetMetadata {
            mode,
            xmpp_domain: domain,
            configured_endpoint: endpoint,
            negotiated_tls: None,
            cipher: None,
            auth_mechanism: "SCRAM-SHA-256".into(),
            resumption: false,
            cache_primed: false,
            observed_scram_iterations: None,
            observed_build: None,
            observed_process_start_time_seconds: None,
            local_binary_sha256: None,
            declared_build: build,
        },
        environment: None,
        dataset: DatasetIdentity {
            account_jids_sha256: None,
            account_count: config.account_count() as u64,
            pair_count: None,
            resource_policy: "one_bound_resource_per_account:bench".into(),
            availability_policy: "unavailable_no_presence".into(),
            body_bytes: None,
        },
        counters: CounterReport::default(),
        rates: RateReport::default(),
        latencies: BTreeMap::new(),
        telemetry: TelemetryReport {
            quality: TelemetryStatus::Unavailable,
            samples_ok: 0,
            samples_failed: 0,
            missed_ticks: 0,
            queue_overflows: 0,
            bytes: 0,
            total_scrape_duration_ms: 0,
            server: ResourceSummary::default(),
            generator: ResourceSummary::default(),
            policy_rejections: BTreeMap::new(),
            identity_changes: 0,
            reasons: vec![RunReason {
                code: ReasonCode::TelemetryUnavailable,
                context: None,
            }],
        },
        artifacts: BTreeMap::new(),
    }
}

fn unknown_system() -> SystemMetadata {
    SystemMetadata {
        os_release: None,
        kernel: None,
        arch: None,
        cpu_model: None,
        logical_cpus: None,
        memory_bytes: None,
        virtualization: None,
        storage_description: None,
        cpu_affinity: None,
        cpu_quota: None,
    }
}
fn system_metadata() -> SystemMetadata {
    let mut system = unknown_system();
    let mut name = std::mem::MaybeUninit::<nix::libc::utsname>::uninit();
    // uname initializes all fields only on success.
    if unsafe { nix::libc::uname(name.as_mut_ptr()) } == 0 {
        let name = unsafe { name.assume_init() };
        let field = |value: &[nix::libc::c_char]| {
            let bytes: Vec<_> = value
                .iter()
                .take_while(|c| **c != 0)
                .map(|c| *c as u8)
                .collect();
            String::from_utf8(bytes).ok().filter(|v| printable(v, 1024))
        };
        system.kernel = field(&name.release);
        system.os_release = field(&name.sysname)
            .zip(system.kernel.as_deref())
            .map(|(os, release)| format!("{os} {release}"));
        system.arch = field(&name.machine);
    }
    system.logical_cpus = std::thread::available_parallelism()
        .ok()
        .map(|n| n.get() as u64);
    system
}
fn utc_now() -> Option<String> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let seconds = nix::libc::time_t::try_from(seconds).ok()?;
    let mut date = std::mem::MaybeUninit::<nix::libc::tm>::uninit();
    // gmtime_r initializes date only when it returns a non-null pointer.
    if unsafe { nix::libc::gmtime_r(&seconds, date.as_mut_ptr()) }.is_null() {
        return None;
    }
    let date = unsafe { date.assume_init() };
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        date.tm_year + 1900,
        date.tm_mon + 1,
        date.tm_mday,
        date.tm_hour,
        date.tm_min,
        date.tm_sec
    ))
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
