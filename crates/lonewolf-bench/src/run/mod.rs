// SPDX-License-Identifier: Apache-2.0

pub mod connections;
pub mod events;
#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
use crate::report::metadata::system_metadata;
use crate::{
    accounts::CredentialSet,
    client::{PreparedAccount, ResolvedTarget, remote_tls_config},
    config::{MeasurementConfig, RunConfig, ScenarioConfig, TargetConfig},
    error::{BenchError, BenchResult, ErrorCode},
    fixture::{LocalFixture, StopOutcome, preflight_descriptors},
    measurement::DispatchPolicy,
    report::*,
};
use crate::{
    report::{
        artifacts::ArtifactWriter,
        metadata::{canonical_hash, collect_metadata, initial_report},
    },
    telemetry::{
        MetricsEndpoint, PhaseSampleRequest, SamplerConfig, TelemetrySampler, allocate_buffer,
    },
};
use connections::ConnectionSet;
use events::{EventReceiver, EventSender, RunEvent, RunObserver};
use lonewolf_util::blocking::BlockingExecutor;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    future::Future,
    io::Read,
    num::NonZeroUsize,
    os::unix::fs::OpenOptionsExt,
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
    pub(crate) fixture: Option<LocalFixture>,
    pub(crate) cpu: BlockingExecutor,
    origin: Instant,
    pub(crate) setup_deadline: Instant,
    pub(crate) events: EventReceiver,
    pub(crate) invalid: Arc<AtomicBool>,
    pub(crate) interruption: watch::Receiver<bool>,
    pub(crate) measurement_window: Option<(Instant, Instant)>,
    pub(crate) setup_attempts: u64,
    pub(crate) setup_failures: u64,
    pub(crate) telemetry: Option<TelemetrySampler>,
    pub(crate) telemetry_buffer: Option<Vec<u8>>,
    pub(crate) message_phase: Option<crate::scenario::messages::MessagePhase>,
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
    let writer = ArtifactWriter::create(output)?;
    let (sender, interruption) = watch::channel(false);
    let signal = signals(sender);
    execute(config, writer, observer, interruption, Some(signal)).await
}

async fn execute(
    config: RunConfig,
    writer: ArtifactWriter,
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
        message_phase: None,
        telemetry: None,
        telemetry_buffer: None,
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
    let raw = context.telemetry_buffer.take().unwrap_or_default();
    let preparation = writer.prepare_data(
        &mut context.report,
        &raw,
        context
            .fixture
            .as_ref()
            .and_then(LocalFixture::sanitized_server_log),
    );
    context.finish_phase(phase, phase_status(&preparation));
    let publication = preparation
        .and_then(|()| writer.prepare_summary(&mut context.report))
        .and_then(|()| writer.finish(&context.report));
    if publication.is_err() {
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
        let metadata = collect_metadata(&self.config)?;
        self.report.driver = metadata.driver;
        self.report.target = metadata.target;
        if self
            .report
            .target
            .declared_build
            .as_ref()
            .is_some_and(|build| build.profile == "unknown" || build.features.is_none())
        {
            self.reason(
                ReasonCode::UnknownServerBuild,
                "server_profile_or_features_unknown",
            );
        }
        self.telemetry_buffer = Some(allocate_buffer()?);
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
            let descriptor = EnvironmentDescriptor::read(environment_file)?;
            descriptor.validate(&self.config.environment_id)?;
            self.report.driver.sources.insert(
                "server_build".into(),
                "operator_environment_descriptor".into(),
            );
            self.report.target.declared_build = Some(descriptor.server_build.clone());
            self.report.environment = Some(descriptor);
            let credentials = CredentialSet::read(
                credentials_file,
                Some(xmpp_domain),
                Some(self.config.account_count()),
            )
            .map_err(|_| invalid_input("remote_credentials_invalid"))?;
            self.accounts = credentials
                .into_prepared()
                .map_err(|_| invalid_input("remote_credentials_invalid"))?;
            self.report.dataset.account_jids_sha256 = Some(canonical_hash(
                &self
                    .accounts
                    .iter()
                    .map(PreparedAccount::bare_jid)
                    .collect::<Vec<_>>(),
            )?);
        }
        if self
            .report
            .target
            .declared_build
            .as_ref()
            .is_some_and(|build| build.profile == "unknown" || build.features.is_none())
        {
            self.reason(
                ReasonCode::UnknownServerBuild,
                "server_profile_or_features_unknown",
            );
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
        let churn = matches!(self.config.scenario, ScenarioConfig::Churn { .. });
        let outcome = if churn {
            crate::scenario::churn::prime(self).await
        } else {
            match ConnectionSet::establish(self, self.config.account_count()).await {
                Ok(()) => self.connected_barrier().await,
                error => error,
            }
        };
        if !churn {
            self.report.phases[phase].counters.connection_attempts = self.setup_attempts;
            self.report.phases[phase].counters.login_failed = self.setup_failures;
            self.report.phases[phase].counters.requested_connections =
                self.config.account_count() as u64;
            self.report.phases[phase].counters.established_connections =
                self.connections.established() as u64;
            self.report.phases[phase].counters.login_succeeded =
                self.connections.established() as u64;
            self.report.phases[phase].counters.peak_connections = self.connections.peak();
        }
        if outcome
            .as_ref()
            .is_err_and(|error| error.context() == "interrupted")
        {
            self.report.phases[phase].counters.cancelled_before_dispatch =
                self.config.account_count() as u64 - self.setup_attempts;
        }
        self.finish_phase(phase, phase_status(&outcome));
        outcome?;
        match self.config.scenario {
            ScenarioConfig::Idle { .. } => {
                crate::scenario::idle::run(self).await?;
            }
            ScenarioConfig::Messages { .. } => {
                crate::scenario::messages::run(self).await?;
            }
            ScenarioConfig::Churn { .. } => {
                crate::scenario::churn::run(self).await?;
            }
        }
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
                let mut settings = fixture.sanitized_server_settings();
                settings.tls_min = settings.tls_min.trim_start_matches("TLSv").to_owned();
                settings.tls_max = settings.tls_max.trim_start_matches("TLSv").to_owned();
                self.report.dataset.account_jids_sha256 = Some(canonical_hash(
                    &fixture
                        .credentials()
                        .iter()
                        .map(PreparedAccount::bare_jid)
                        .collect::<Vec<_>>(),
                )?);
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
        self.start_telemetry().await;
        self.check_running()
    }

    async fn start_telemetry(&mut self) {
        let url = match &self.config.target {
            TargetConfig::Local { .. } => self
                .fixture
                .as_ref()
                .map(|fixture| fixture.metrics_url().to_owned()),
            TargetConfig::Remote { metrics_url, .. } => metrics_url.clone(),
        };
        let endpoint = if let Some(url) = url {
            bounded(
                &mut self.interruption,
                self.setup_deadline,
                MetricsEndpoint::resolve(&url),
            )
            .await
            .ok()
        } else {
            None
        };
        if let Some(buffer) = self.telemetry_buffer.take() {
            match TelemetrySampler::start(
                SamplerConfig {
                    endpoint,
                    timing: self.config.metrics.clone(),
                },
                self.origin,
                buffer,
            ) {
                Ok(mut sampler) => {
                    sampler.ready().await;
                    self.telemetry = Some(sampler);
                }
                Err(_) => self.reason(ReasonCode::TelemetryUnavailable, "sampler_start_failed"),
            }
        }
    }

    async fn stop_telemetry(&mut self, deadline: Instant) {
        if let Some(sampler) = self.telemetry.take() {
            match sampler.stop_observed(deadline).await {
                Ok((report, raw, identity)) => self.apply_telemetry(report, raw, identity),
                Err(_) => self.reason(ReasonCode::TelemetryUnavailable, "sampler_join_failed"),
            }
        }
    }

    fn apply_connection_observations(&mut self, observations: connections::ConnectionObservations) {
        self.report.target.negotiated_tls = observations
            .negotiated_tls
            .map(|value| format!("{value:?}"));
        self.report.target.cipher = observations.cipher.map(|value| format!("{value:?}"));
        self.report.target.observed_scram_iterations = observations.observed_scram_iterations;
    }

    fn apply_telemetry(
        &mut self,
        report: TelemetryReport,
        raw: Vec<u8>,
        identity: Option<crate::telemetry::openmetrics::MetricSnapshot>,
    ) {
        self.report
            .reasons
            .retain(|r| r.code != ReasonCode::TelemetryUnavailable);
        for reason in &report.reasons {
            if !self.report.reasons.contains(reason) {
                self.report.reasons.push(reason.clone());
            }
        }
        self.report.telemetry_status = report.quality;
        if report.identity_changes > 0 {
            self.report.status = RunStatus::Invalid;
            self.reason(ReasonCode::ServerRestarted, "server_restarted");
        }
        if let Some(identity) = identity {
            self.report.target.observed_build = identity.build;
            self.report.target.observed_process_start_time_seconds = identity.process_start;
        }
        self.report.telemetry = report;
        self.telemetry_buffer = Some(raw);
    }

    fn notify_telemetry(&self, phase: PhaseName, at: Instant) {
        if let Some(sampler) = &self.telemetry {
            let _ = sampler.try_notify(PhaseSampleRequest {
                phase,
                scheduled_at: at,
                window: self.measurement_window,
                achieved_connections: if matches!(self.config.scenario, ScenarioConfig::Idle { .. })
                {
                    self.connections.established() as u64
                } else {
                    0
                },
            });
        }
    }

    async fn cleanup(&mut self) {
        let timeout = Duration::from_millis(self.config.measurement.shutdown_timeout_ms);
        let deadline = Instant::now() + timeout;
        self.close_connections(deadline).await;
        self.stop_telemetry(Instant::now() + timeout).await;
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

    pub(crate) async fn close_connections(&mut self, deadline: Instant) {
        if self
            .report
            .phases
            .iter()
            .any(|phase| phase.name == PhaseName::ConnectionShutdown)
        {
            return;
        }
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

    pub(crate) fn consume(&mut self, event: RunEvent) {
        if let Some(phase) = &mut self.message_phase {
            let _ = phase.observe(event);
            return;
        }
        let (at, disconnected, unexpected) = match event {
            RunEvent::ConnectionClosed { at, .. } => (at, true, false),
            RunEvent::Received { event, .. } => (event.at, false, true),
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

    pub(crate) async fn settle_until(&mut self, deadline: Instant) -> BenchResult<()> {
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
        if matches!(self.config.scenario, ScenarioConfig::Churn { .. }) {
            return;
        }
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
                && matches!(self.config.scenario, ScenarioConfig::Idle { .. })
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
    pub(crate) fn start_phase(&mut self, name: PhaseName, deadline: Option<Instant>) -> usize {
        self.start_phase_at(name, Instant::now(), deadline)
    }
    pub(crate) fn start_phase_at(
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
        self.notify_telemetry(name, start);
        index
    }
    pub(crate) fn finish_phase(&mut self, index: usize, status: PhaseStatus) {
        let end = self.offset(Instant::now());
        let phase = &mut self.report.phases[index];
        phase.end_offset_ns = Some(end);
        phase.status = status;
        self.observer.phase_finished(phase.name);
        let name = phase.name;
        if matches!(name, PhaseName::Measurement | PhaseName::ConnectionShutdown) {
            self.notify_telemetry(name, Instant::now());
        }
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
    pub(crate) fn reason(&mut self, code: ReasonCode, context: &'static str) {
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
