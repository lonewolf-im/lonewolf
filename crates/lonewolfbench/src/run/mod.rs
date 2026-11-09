// SPDX-License-Identifier: Apache-2.0

pub mod connections;
pub mod events;
#[cfg(test)]
pub(crate) mod tests;

use crate::{
    accounts::CredentialSet,
    client::{PreparedAccount, ResolvedTarget, remote_tls_config},
    config::{RunConfig, ScenarioConfig, TargetConfig},
    cpu::CpuPool,
    error::{BenchError, BenchResult, ErrorCode},
    fixture::{LocalFixture, StopOutcome, preflight_descriptors},
    measurement::DispatchPolicy,
    report::{
        artifacts::ArtifactWriter,
        metadata::{collect_host_facts, initial_report},
        summary, *,
    },
    telemetry::{MetricsEndpoint, PhaseSampleRequest, SamplerConfig, TelemetrySampler},
};
use connections::ConnectionSet;
use events::{EventReceiver, EventSender, RunEvent, RunObserver};
use std::{
    fs::OpenOptions,
    future::Future,
    io::Read,
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
    pub(crate) cpu: CpuPool,
    origin: Instant,
    pub(crate) setup_deadline: Instant,
    pub(crate) events: EventReceiver,
    pub(crate) invalid: Arc<AtomicBool>,
    pub(crate) interruption: watch::Receiver<bool>,
    pub(crate) measurement_window: Option<(Instant, Instant)>,
    pub(crate) setup_attempts: u64,
    pub(crate) setup_failures: u64,
    pub(crate) telemetry: Option<TelemetrySampler>,
    pub(crate) telemetry_raw: Vec<u8>,
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
    let cpu = CpuPool::per_core();
    let report = initial_report(&config, cpu.size());
    let mut context = RunContext {
        connections: ConnectionSet::new(sender, invalid.clone(), observer.clone()),
        config,
        target: None,
        accounts: Vec::new(),
        observer,
        report,
        fixture: None,
        cpu,
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
        telemetry_raw: Vec::new(),
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
    let mut written = writer.write("telemetry.ndjson", &context.telemetry_raw);
    if let Some(log) = context.fixture.as_ref().and_then(LocalFixture::server_log) {
        written = written.and(writer.write("server.log", log));
    }
    context.finish_phase(phase, phase_status(&written));
    if written.is_err() {
        context.reason(ReasonCode::ArtifactFailure, "artifact_write_failed");
    }
    if writer
        .write("summary.md", summary::render(&context.report).as_bytes())
        .is_err()
    {
        context.reason(ReasonCode::ArtifactFailure, "summary_write_failed");
    }
    if writer.write_json(RESULT_FILE, &context.report).is_err() {
        context.reason(ReasonCode::ArtifactFailure, "result_write_failed");
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
        collect_host_facts(&mut self.report);
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
            xmpp_domain,
            ..
        } = &self.config.target
        {
            let credentials = CredentialSet::read(
                credentials_file,
                Some(xmpp_domain),
                Some(self.config.account_count()),
            )
            .map_err(|_| invalid_input("remote_credentials_invalid"))?;
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
        self.require_progress();
        Ok(())
    }

    /// A measurement without a single success means the target stopped working, not that it slowed down.
    fn require_progress(&mut self) {
        let c = &self.report.counters;
        let stalled = match self.config.scenario {
            ScenarioConfig::Idle { .. } => c.connections_at_measurement_end == 0,
            ScenarioConfig::Messages { .. } => c.planned > 0 && c.received_on_time == 0,
            ScenarioConfig::Churn { .. } => c.planned > 0 && c.closed_cleanly == 0,
        };
        if stalled {
            self.reason(ReasonCode::WorkloadFailure, "no_operation_succeeded");
        }
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
        match TelemetrySampler::start(
            SamplerConfig {
                endpoint,
                timing: self.config.metrics.clone(),
            },
            self.origin,
        ) {
            Ok(mut sampler) => {
                sampler.ready().await;
                self.telemetry = Some(sampler);
            }
            Err(_) => self.reason(ReasonCode::TelemetryUnavailable, "sampler_start_failed"),
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
        self.report.status = status_of(&self.report.reasons);
        if report.identity_changes > 0 {
            self.reason(ReasonCode::ServerRestarted, "server_restarted");
        }
        if let Some(identity) = identity {
            self.report.target.server_build = identity.build;
        }
        self.report.telemetry = report;
        self.telemetry_raw = raw;
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
        self.cpu.barrier().await;
        let phase = self.start_phase(
            PhaseName::LocalChildShutdown,
            Some(Instant::now() + timeout),
        );
        let stopped = if let Some(fixture) = &mut self.fixture {
            fixture.stop(timeout).await
        } else {
            Ok(StopOutcome::NotStarted)
        };
        match stopped {
            Ok(StopOutcome::Graceful | StopOutcome::NotStarted) => {}
            Ok(StopOutcome::Exited) => {
                self.reason(ReasonCode::TargetFailure, "local_server_exited");
            }
            _ => self.reason(ReasonCode::TargetFailure, "local_child_cleanup_failed"),
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
            self.reason(ReasonCode::OperationsFailed, "connection_close_failed");
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
        self.consume_prefix(policy(&self.config).max_batch as usize);
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
        if disconnected {
            self.reason(ReasonCode::OperationsFailed, "unexpected_disconnect");
        }
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
        loop {
            self.connections.begin_barrier();
            while !self.connections.settled() {
                tokio::select! {
                    event = self.events.recv() => if let Some(event) = event { self.consume(event); },
                    _ = sleep(Duration::from_millis(1)) => {},
                    _ = sleep_until(deadline) => return Err(failure("phase_barrier_deadline")),
                }
            }
            // An actor acknowledges the barrier before it takes its queued command.
            if !self.connections.commands_queued() {
                break;
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
        self.report.status = status_of(&self.report.reasons);
    }
}

fn phase_status(result: &BenchResult<()>) -> PhaseStatus {
    match result {
        Ok(()) => PhaseStatus::Completed,
        Err(error) if error.context() == "interrupted" => PhaseStatus::Cancelled,
        Err(_) => PhaseStatus::Failed,
    }
}

pub(crate) fn policy(config: &RunConfig) -> DispatchPolicy {
    let rate = config
        .offered_rate()
        .unwrap_or_default()
        .max(config.measurement.ramp_rate_per_second);
    DispatchPolicy {
        lag_allowance: Duration::from_millis(config.measurement.max_schedule_lag_ms),
        ..DispatchPolicy::for_rate(rate)
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
