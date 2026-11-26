// SPDX-License-Identifier: Apache-2.0

use crate::{
    client::{
        self, ClientSession, ConnectFailureKind, ConnectObservation, ConnectStage, KeyMode,
        NegotiatedTls, OperationId, PreparedAccount, ReceivedKind, ResolvedTarget, StageFailure,
        TrafficPhase,
    },
    cpu::CpuPool,
    error::{BenchError, BenchResult},
    measurement::{
        CloseOutcome, DueSlots, FinishReason, Ledger, LedgerContext, LedgerTopology, LoginOutcome,
        MeasurementResult, OperationEvent, PhaseBarrier, RateSchedule, ReserveError, RouteIdentity,
        ScheduledSlot, SkipReason, Termination,
    },
    report::{CounterReport, ErrorCategory, PhaseName, PhaseStatus, ReasonCode, RunReason},
    run::{RunContext, events::RunObserver, failure, policy},
};
use std::{
    collections::BTreeMap,
    future::{Future, poll_fn},
    num::NonZeroU32,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    sync::watch,
    time::{Instant, sleep_until},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChurnAccountState {
    Idle,
    Busy,
    Retired,
}

struct AccountPool {
    accounts: Vec<Option<PreparedAccount>>,
    states: Vec<ChurnAccountState>,
}

impl AccountPool {
    fn new(accounts: Vec<PreparedAccount>) -> Self {
        Self {
            states: vec![ChurnAccountState::Idle; accounts.len()],
            accounts: accounts.into_iter().map(Some).collect(),
        }
    }

    fn take(&mut self, index: usize) -> Option<PreparedAccount> {
        if self.states[index] != ChurnAccountState::Idle {
            return None;
        }
        let account = self.accounts[index].take()?;
        self.states[index] = ChurnAccountState::Busy;
        Some(account)
    }

    fn complete(&mut self, completed: CompletedCycle) -> CycleOutcome {
        let index = completed.outcome.account_index as usize;
        self.states[index] = if matches!(
            completed.outcome.close,
            Some(CloseOutcome::Failed { .. } | CloseOutcome::Cancelled { .. })
        ) {
            ChurnAccountState::Retired
        } else {
            ChurnAccountState::Idle
        };
        self.accounts[index] = Some(completed.account);
        completed.outcome
    }

    fn into_accounts(self) -> Vec<PreparedAccount> {
        self.accounts.into_iter().flatten().collect()
    }
}

struct CycleOutcome {
    sequence: u64,
    account_index: u32,
    scheduled_at: Instant,
    connect_started_at: Option<Instant>,
    login: LoginOutcome,
    close: Option<CloseOutcome>,
    failure: Option<StageFailure>,
}

struct CompletedCycle {
    account: PreparedAccount,
    outcome: CycleOutcome,
    tls: Option<NegotiatedTls>,
}

#[derive(Clone)]
struct CycleControl {
    interruption: watch::Receiver<bool>,
    stop: watch::Receiver<bool>,
}

impl CycleControl {
    async fn cancelled(&mut self) {
        loop {
            if *self.interruption.borrow() || *self.stop.borrow() {
                return;
            }
            tokio::select! {
                changed = self.interruption.changed() => if changed.is_err() { return; },
                changed = self.stop.changed() => if changed.is_err() { return; },
            }
        }
    }
}

struct CycleSettings {
    target: ResolvedTarget,
    cpu: CpuPool,
    shutdown: Duration,
    active: AtomicU64,
    peak: AtomicU64,
    invalid: Arc<AtomicBool>,
    observer: RunObserver,
}

impl CycleSettings {
    fn new(context: &RunContext) -> BenchResult<Arc<Self>> {
        let target = context
            .target
            .as_ref()
            .ok_or_else(|| failure("target_unavailable"))?;
        Ok(Arc::new(Self {
            target: ResolvedTarget {
                address: target.address,
                xmpp_domain: target.xmpp_domain.clone(),
                tls: target.tls.clone(),
            },
            cpu: context.cpu.clone(),
            shutdown: Duration::from_millis(context.config.measurement.shutdown_timeout_ms),
            active: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            invalid: context.invalid.clone(),
            observer: context.observer.clone(),
        }))
    }
}

struct CycleRequest {
    slot: ScheduledSlot,
    index: u32,
    resource: String,
    mode: KeyMode,
    deadline: Instant,
}

type CycleFuture = Pin<Box<dyn Future<Output = CompletedCycle> + Send>>;
type Launcher<'a> = dyn FnMut(PreparedAccount, CycleRequest, CycleControl) -> CycleFuture + 'a;

fn resource(nonce: &str, phase: char, sequence: u64) -> String {
    format!("bench-{nonce}-{phase}-{sequence}")
}

async fn cycle(
    mut account: PreparedAccount,
    request: CycleRequest,
    mut control: CycleControl,
    settings: Arc<CycleSettings>,
) -> CompletedCycle {
    let mut observation = ConnectObservation::default();
    let result = {
        let connecting = client::connect_observed(
            &settings.target,
            &mut account,
            &request.resource,
            request.mode,
            request.deadline,
            &settings.cpu,
            &mut observation,
        );
        tokio::pin!(connecting);
        tokio::select! {
            biased;
            _ = control.cancelled() => None,
            result = &mut connecting => Some(result),
        }
    };
    let (login, close, failure, tls) = match result {
        Some(Ok((session, timings))) => {
            let Some(bound) = observation.bound_at else {
                unreachable!("validated bind has a timestamp")
            };
            let login = LoginOutcome::Succeeded { at: bound, timings };
            let tls = session.identity().tls.clone();
            let active = settings.active.fetch_add(1, Ordering::AcqRel) + 1;
            settings.peak.fetch_max(active, Ordering::AcqRel);
            settings.observer.active_connections(active);
            let close =
                close_session(session, settings.shutdown, &mut control, &settings.invalid).await;
            settings
                .observer
                .active_connections(settings.active.fetch_sub(1, Ordering::AcqRel) - 1);
            (login, Some(close), None, Some(tls))
        }
        other => {
            let failure = match other {
                Some(Err(failure)) => failure,
                None => StageFailure {
                    stage: observation.stage,
                    kind: ConnectFailureKind::Cancelled,
                    at: Instant::now(),
                    error: failure("connect_cancelled"),
                },
                Some(Ok(_)) => unreachable!(),
            };
            let login = if failure.kind == ConnectFailureKind::Cancelled
                || observation.connect_started_at.is_none()
            {
                LoginOutcome::Cancelled { at: failure.at }
            } else {
                LoginOutcome::Failed {
                    at: failure.at,
                    category: stage_category(failure.stage),
                }
            };
            (login, None, Some(failure), None)
        }
    };
    CompletedCycle {
        account,
        tls,
        outcome: CycleOutcome {
            sequence: request.slot.sequence,
            account_index: request.index,
            scheduled_at: request.slot.scheduled_at,
            connect_started_at: observation.connect_started_at,
            login,
            close,
            failure,
        },
    }
}

async fn close_session(
    session: ClientSession,
    shutdown: Duration,
    control: &mut CycleControl,
    invalid: &AtomicBool,
) -> CloseOutcome {
    let (mut reader, mut writer, _) = session.into_parts();
    let mut received = |event: client::ReceivedEvent| {
        if matches!(event.kind, ReceivedKind::StreamEnd) {
            Ok(())
        } else {
            Err(failure("churn_unexpected_close_event"))
        }
    };
    let result = {
        let closing = client::shutdown(&mut reader, &mut writer, shutdown, &mut received);
        tokio::pin!(closing);
        tokio::select! {
            biased;
            _ = control.cancelled() => None,
            result = &mut closing => Some(result),
        }
    };
    writer.retire();
    let cleaned = reader.retire_and_drain(&mut received).await;
    if reader.run_invalid() {
        invalid.store(true, Ordering::Release);
    }
    let at = Instant::now();
    match result {
        None => CloseOutcome::Cancelled { at },
        Some(Ok(())) if cleaned.is_ok() && !reader.run_invalid() => CloseOutcome::Clean { at },
        Some(Err(error)) if error.context() == "close_deadline" => CloseOutcome::Failed {
            at,
            category: ErrorCategory::Deadline,
        },
        _ => CloseOutcome::Failed {
            at,
            category: ErrorCategory::Cleanup,
        },
    }
}

fn stage_category(stage: Option<ConnectStage>) -> ErrorCategory {
    match stage {
        Some(ConnectStage::Tcp) => ErrorCategory::Tcp,
        Some(ConnectStage::Starttls) => ErrorCategory::Tls,
        Some(ConnectStage::Authenticate) => ErrorCategory::Auth,
        Some(ConnectStage::Bind) => ErrorCategory::Bind,
        None => ErrorCategory::Protocol,
    }
}

fn poll_completed(
    pending: &mut Vec<CycleFuture>,
    cx: &mut std::task::Context<'_>,
) -> Poll<CompletedCycle> {
    for (index, future) in pending.iter_mut().enumerate() {
        if let Poll::Ready(value) = future.as_mut().poll(cx) {
            drop(pending.swap_remove(index));
            return Poll::Ready(value);
        }
    }
    Poll::Pending
}

async fn next_completed(pending: &mut Vec<CycleFuture>) -> CompletedCycle {
    poll_fn(|cx| poll_completed(pending, cx)).await
}

pub(crate) async fn prime(context: &mut RunContext) -> BenchResult<()> {
    let settings = CycleSettings::new(context)?;
    if let Some(fixture) = &mut context.fixture {
        context.accounts = fixture.take_credentials();
    }
    let mut pool = AccountPool::new(std::mem::take(&mut context.accounts));
    let mut launch = |account, request, control| -> CycleFuture {
        Box::pin(cycle(account, request, control, settings.clone()))
    };
    let result = prime_with(context, &mut pool, &mut launch).await;
    context.accounts = pool.into_accounts();
    if let Some(phase) = context.report.phases.last_mut() {
        phase.counters.peak_connections = settings.peak.load(Ordering::Acquire);
    }
    context.cpu.barrier().await;
    result
}

async fn prime_with(
    context: &mut RunContext,
    pool: &mut AccountPool,
    launch: &mut Launcher<'_>,
) -> BenchResult<()> {
    let count = pool.accounts.len();
    if count != context.config.account_count() || count == 0 {
        return Err(failure("churn_account_count"));
    }
    let nonce = context
        .report
        .run_id
        .as_deref()
        .ok_or_else(|| failure("churn_nonce"))?;
    let rate = NonZeroU32::new(context.config.measurement.ramp_rate_per_second)
        .ok_or_else(|| failure("ramp_rate"))?;
    let duration =
        Duration::from_nanos((count as u64 - 1) * 1_000_000_000 / u64::from(rate.get()) + 1);
    let schedule = RateSchedule::new(Instant::now(), duration, rate, policy(&context.config))?;
    let (stop, stopped) = watch::channel(false);
    let control = CycleControl {
        interruption: context.interruption.clone(),
        stop: stopped,
    };
    let mut pending = Vec::with_capacity(count.min(context.config.measurement.connect_concurrency));
    let mut next = 0;
    let mut tally = PrimeTally {
        counters: CounterReport {
            requested_connections: count as u64,
            ..Default::default()
        },
        error: None,
        iterations: None,
        mixed_iterations: false,
        tls: None,
    };
    let concurrency = context.config.measurement.connect_concurrency;
    while next < count || !pending.is_empty() {
        let now = Instant::now();
        if tally.error.is_none() {
            if *context.interruption.borrow() {
                tally.error = Some(failure("interrupted"));
            } else if now >= context.setup_deadline {
                tally.error = Some(failure("setup_deadline"));
            }
        }
        if tally.error.is_some() {
            stop.send_replace(true);
        }
        let slot = (next < count).then(|| schedule.slot(next as u64));
        if tally.error.is_none()
            && let Some(slot) = slot
            && now >= slot.scheduled_at
            && pending.len() < concurrency
        {
            let Some(account) = pool.take(next) else {
                tally.error = Some(failure("churn_prime_account"));
                continue;
            };
            pending.push(launch(
                account,
                CycleRequest {
                    slot,
                    index: next as u32,
                    resource: resource(nonce, 'p', next as u64),
                    mode: KeyMode::Prime,
                    deadline: context.setup_deadline,
                },
                control.clone(),
            ));
            tally.counters.connection_attempts += 1;
            next += 1;
            continue;
        }
        if tally.error.is_some() && pending.is_empty() {
            break;
        }
        let wake = if tally.error.is_some() {
            context.setup_deadline
        } else {
            match slot {
                Some(slot) if pending.len() < concurrency => slot.scheduled_at,
                _ => context.setup_deadline,
            }
            .min(context.setup_deadline)
        };
        tokio::select! {
            biased;
            completed = next_completed(&mut pending), if !pending.is_empty() => {
                tally.record(&completed, &context.interruption);
                pool.complete(completed);
            },
            _ = context.interruption.changed(), if tally.error.is_none() => {},
            _ = sleep_until(wake), if tally.error.is_none() => {},
        }
    }
    tally.finish(context)
}

struct PrimeTally {
    counters: CounterReport,
    error: Option<BenchError>,
    iterations: Option<u32>,
    mixed_iterations: bool,
    tls: Option<NegotiatedTls>,
}

impl PrimeTally {
    fn record(&mut self, completed: &CompletedCycle, interruption: &watch::Receiver<bool>) {
        let Self {
            counters,
            error,
            iterations,
            mixed_iterations,
            tls,
        } = self;
        let succeeded = matches!(completed.outcome.login, LoginOutcome::Succeeded { .. });
        let clean = matches!(completed.outcome.close, Some(CloseOutcome::Clean { .. }));
        if succeeded {
            counters.login_succeeded += 1;
        } else {
            counters.login_failed += 1;
        }
        if let LoginOutcome::Failed { category, .. } = completed.outcome.login {
            *counters.errors.entry(category).or_default() += 1;
        }
        if let Some(failure) = &completed.outcome.failure
            && failure.kind == ConnectFailureKind::Deadline
        {
            *counters.errors.entry(ErrorCategory::Deadline).or_default() += 1;
        }
        if let Some(CloseOutcome::Failed { category, .. }) = completed.outcome.close {
            *counters.errors.entry(category).or_default() += 1;
        }
        if clean {
            counters.closed_cleanly += 1;
            let observed = completed.account.cached_scram_iterations();
            if counters.closed_cleanly == 1 {
                *iterations = observed;
                *tls = completed.tls.clone();
            } else if *iterations != observed {
                *mixed_iterations = true;
            }
        } else {
            counters.close_failed += u64::from(succeeded);
            if error.is_none() {
                *error = Some(if *interruption.borrow() {
                    failure("interrupted")
                } else {
                    completed.outcome.failure.as_ref().map_or_else(
                        || failure("churn_prime_close_failed"),
                        |failure| failure.error.clone(),
                    )
                });
            }
        }
    }

    fn finish(self, context: &mut RunContext) -> BenchResult<()> {
        let Self {
            mut counters,
            error,
            iterations,
            mixed_iterations,
            tls,
        } = self;
        context.setup_attempts = counters.connection_attempts;
        context.setup_failures = counters.login_failed;
        counters.established_connections = counters.login_succeeded;
        if let Some(phase) = context.report.phases.last_mut() {
            phase.counters = counters;
        }
        if error.is_none() {
            context.report.target.scram_iterations =
                if mixed_iterations { None } else { iterations };
            if let Some(tls) = tls {
                context.report.target.negotiated_tls = Some(format!("{:?}", tls.version));
                context.report.target.cipher = Some(format!("{:?}", tls.cipher));
            }
        }
        error.map_or(Ok(()), Err)
    }
}

struct ChurnPhase {
    ledger: Ledger,
    nonce: [u8; 16],
    phase: TrafficPhase,
    reasons: Vec<RunReason>,
    errors: BTreeMap<ErrorCategory, u64>,
    end: Instant,
    connected_at_end: u64,
}

impl ChurnPhase {
    fn reason(&mut self, code: ReasonCode, context: &'static str) {
        if !self
            .reasons
            .iter()
            .any(|r| r.code == code && r.context.as_deref() == Some(context))
        {
            self.reasons.push(RunReason {
                code,
                context: Some(context.into()),
            });
        }
    }

    fn observe(&mut self, outcome: CycleOutcome) -> BenchResult<()> {
        if matches!(
            outcome.close,
            Some(CloseOutcome::Failed { .. } | CloseOutcome::Cancelled { .. })
        ) {
            self.reason(
                ReasonCode::OperationsFailed,
                "churn_account_retired_after_close",
            );
        }
        if let Some(failure) = &outcome.failure {
            if failure.kind == ConnectFailureKind::Cancelled
                && let Some(stage) = failure.stage
            {
                *self.errors.entry(stage_category(Some(stage))).or_default() += 1;
            }
            if failure.kind == ConnectFailureKind::Deadline {
                *self.errors.entry(ErrorCategory::Deadline).or_default() += 1;
            }
            if outcome.connect_started_at.is_none() && failure.kind != ConnectFailureKind::Cancelled
            {
                self.reason(
                    if failure.kind == ConnectFailureKind::Deadline {
                        ReasonCode::DriverLimited
                    } else {
                        ReasonCode::AccountingError
                    },
                    if failure.kind == ConnectFailureKind::Deadline {
                        "churn_deadline_before_tcp_poll"
                    } else {
                        "churn_validation_before_tcp_poll"
                    },
                );
            }
            if failure.error.context() == "scram_parameters_changed" {
                self.reason(
                    ReasonCode::AccountingError,
                    "churn_scram_parameters_changed",
                );
            }
        }
        if let (LoginOutcome::Succeeded { at: bound, .. }, Some(close)) =
            (outcome.login, outcome.close)
        {
            let closed = match close {
                CloseOutcome::Clean { at }
                | CloseOutcome::Failed { at, .. }
                | CloseOutcome::Cancelled { at } => at,
            };
            if bound <= self.end && closed > self.end {
                self.connected_at_end += 1;
            }
        }
        let terminal_at = match outcome.login {
            LoginOutcome::Succeeded { at, .. }
            | LoginOutcome::Failed { at, .. }
            | LoginOutcome::Cancelled { at } => at,
        };
        if terminal_at < outcome.scheduled_at {
            self.reason(
                ReasonCode::AccountingError,
                "churn_terminal_before_schedule",
            );
        }
        self.ledger.observe(OperationEvent::ChurnFinished {
            operation: OperationId {
                run_nonce: self.nonce,
                phase: self.phase,
                sequence: outcome.sequence,
            },
            account_index: outcome.account_index,
            connect_started_at: outcome.connect_started_at,
            login: outcome.login,
            close: outcome.close,
        })
    }

    fn finish(self, termination: Termination, barrier: PhaseBarrier) -> MeasurementResult {
        let mut result = self.ledger.finish(FinishReason {
            termination,
            barrier,
        });
        result.counters.connections_at_measurement_end = self.connected_at_end;
        result.reasons.extend(self.reasons);
        for (category, count) in self.errors {
            *result.counters.errors.entry(category).or_default() += count;
        }
        result
    }
}

pub async fn run(context: &mut RunContext) -> BenchResult<MeasurementResult> {
    let settings = CycleSettings::new(context)?;
    let mut pool = AccountPool::new(std::mem::take(&mut context.accounts));
    let mut launch = |account, request, control| -> CycleFuture {
        Box::pin(cycle(account, request, control, settings.clone()))
    };
    let result = run_with(context, &mut pool, &mut launch, &settings).await;
    context.accounts = pool.into_accounts();
    result
}

async fn run_with(
    context: &mut RunContext,
    pool: &mut AccountPool,
    launch: &mut Launcher<'_>,
    settings: &CycleSettings,
) -> BenchResult<MeasurementResult> {
    let crate::config::ScenarioConfig::Churn {
        accounts,
        rate_per_second,
    } = context.config.scenario
    else {
        return Err(failure("churn_scenario"));
    };
    if accounts != pool.accounts.len() {
        return Err(failure("churn_account_count"));
    }
    let nonce = context
        .report
        .run_id
        .as_ref()
        .and_then(|id| OperationId::parse(&format!("{id}.w.0")))
        .ok_or_else(|| failure("churn_nonce"))?
        .run_nonce;
    for phase in [TrafficPhase::Warmup, TrafficPhase::Measurement] {
        settings.peak.store(0, Ordering::Release);
        let mut result = run_phase(
            context,
            pool,
            launch,
            PhaseSettings {
                nonce,
                phase,
                rate: rate_per_second,
                duration: Duration::from_millis(if phase == TrafficPhase::Warmup {
                    context.config.measurement.warmup_ms
                } else {
                    context.config.measurement.duration_ms
                }),
            },
        )
        .await?;
        let peak = settings.peak.load(Ordering::Acquire);
        result.counters.peak_connections = peak;
        if let Some(report) = context.report.phases.iter_mut().find(|report| {
            report.name
                == if phase == TrafficPhase::Warmup {
                    PhaseName::Warmup
                } else {
                    PhaseName::Measurement
                }
        }) {
            report.counters.peak_connections = peak;
        }
        if phase == TrafficPhase::Measurement {
            context.report.counters.peak_connections = peak;
            return Ok(result);
        }
        if !result.status().measured() {
            return Err(failure("churn_warmup_failed"));
        }
    }
    unreachable!()
}

struct PhaseSettings {
    nonce: [u8; 16],
    phase: TrafficPhase,
    rate: u32,
    duration: Duration,
}

async fn run_phase(
    context: &mut RunContext,
    pool: &mut AccountPool,
    launch: &mut Launcher<'_>,
    settings: PhaseSettings,
) -> BenchResult<MeasurementResult> {
    let start = Instant::now();
    let timeout = Duration::from_millis(context.config.measurement.operation_timeout_ms);
    let shutdown = Duration::from_millis(context.config.measurement.shutdown_timeout_ms);
    let dispatch = policy(&context.config);
    let schedule = RateSchedule::new(
        start,
        settings.duration,
        NonZeroU32::new(settings.rate).ok_or_else(|| failure("churn_rate"))?,
        dispatch,
    )?;
    let end = schedule.end();
    let topology = LedgerTopology::Churn {
        accounts: NonZeroU32::new(pool.accounts.len() as u32)
            .ok_or_else(|| failure("churn_accounts"))?,
    };
    let phase = ChurnPhase {
        ledger: Ledger::new(
            schedule.planned(),
            context
                .config
                .measurement
                .max_in_flight
                .min(context.config.measurement.connect_concurrency),
            timeout,
            LedgerContext {
                run_nonce: settings.nonce,
                phase: settings.phase,
                start,
                end,
                shutdown_timeout: shutdown,
                topology,
            },
        )?,
        nonce: settings.nonce,
        phase: settings.phase,
        reasons: Vec::new(),
        errors: BTreeMap::new(),
        end,
        connected_at_end: 0,
    };
    let measuring = settings.phase == TrafficPhase::Measurement;
    let (name, drain_name, letter) = if measuring {
        (PhaseName::Measurement, PhaseName::MeasurementDrain, 'm')
    } else {
        (PhaseName::Warmup, PhaseName::WarmupDrain, 'w')
    };
    let nonce = context
        .report
        .run_id
        .clone()
        .ok_or_else(|| failure("churn_nonce"))?;
    if measuring {
        context.measurement_window = Some((start, end));
    }
    let phase_index = context.start_phase_at(name, start, Some(end));
    let drain_deadline = end + timeout + shutdown;
    let pending = Vec::with_capacity(
        pool.accounts
            .len()
            .min(context.config.measurement.connect_concurrency),
    );
    let (stop, stopped) = watch::channel(false);
    let control = CycleControl {
        interruption: context.interruption.clone(),
        stop: stopped,
    };
    let mut run = ChurnRun {
        phase,
        schedule,
        pending,
        next_dispatch: Some(start),
        phase_index,
        drain_index: None,
        drain_name,
        end,
        drain_deadline,
        timeout,
        lag_allowance: dispatch.lag_allowance,
        letter,
        nonce,
        control,
        stop,
        measuring,
        duration: settings.duration,
        rate: settings.rate,
        topology,
    };
    let termination = run.drive(context, pool, launch).await;
    Ok(run.conclude(context, pool, termination).await)
}

struct InvalidLedger;

struct ChurnRun {
    phase: ChurnPhase,
    schedule: RateSchedule,
    pending: Vec<CycleFuture>,
    next_dispatch: Option<Instant>,
    phase_index: usize,
    drain_index: Option<usize>,
    drain_name: PhaseName,
    end: Instant,
    drain_deadline: Instant,
    timeout: Duration,
    lag_allowance: Duration,
    letter: char,
    nonce: String,
    control: CycleControl,
    stop: watch::Sender<bool>,
    measuring: bool,
    duration: Duration,
    rate: u32,
    topology: LedgerTopology,
}

impl ChurnRun {
    async fn drive(
        &mut self,
        context: &mut RunContext,
        pool: &mut AccountPool,
        launch: &mut Launcher<'_>,
    ) -> Termination {
        loop {
            if self.observe_ready(pool).await {
                break Termination::Failed;
            }
            let now = Instant::now();
            if *context.interruption.borrow() {
                break Termination::Cancelled;
            }
            if context.invalid.load(Ordering::Acquire) {
                let _ = self.phase.ledger.observe(OperationEvent::EventOverflow);
                break Termination::Failed;
            }
            if now >= self.end && self.drain_index.is_none() {
                context.finish_phase(self.phase_index, PhaseStatus::Completed);
                self.drain_index = Some(context.start_phase_at(
                    self.drain_name,
                    self.end,
                    Some(self.drain_deadline),
                ));
            }
            if self.next_dispatch.is_some_and(|at| now >= at) {
                let due = self.schedule.poll_due(now);
                if self.dispatch_due(due, pool, launch).is_err() {
                    break Termination::Failed;
                }
            }
            if now >= self.end && self.next_dispatch.is_none() && self.pending.is_empty() {
                break Termination::Completed;
            }
            if now >= self.drain_deadline {
                self.phase
                    .reason(ReasonCode::AccountingError, "churn_drain_deadline");
                break Termination::Failed;
            }
            let wake = self.wake(now);
            tokio::select! {
                biased;
                completed = next_completed(&mut self.pending), if !self.pending.is_empty() => {
                    let outcome = pool.complete(completed);
                    if self.phase.observe(outcome).is_err() { break Termination::Failed; }
                },
                _ = context.interruption.changed() => {},
                _ = sleep_until(wake) => {},
            }
        }
    }

    async fn observe_ready(&mut self, pool: &mut AccountPool) -> bool {
        let mut observation_error = false;
        for _ in 0..self.pending.len() {
            let completed = poll_fn(|cx| {
                Poll::Ready(match poll_completed(&mut self.pending, cx) {
                    Poll::Ready(value) => Some(value),
                    Poll::Pending => None,
                })
            })
            .await;
            let Some(completed) = completed else {
                break;
            };
            if self.phase.observe(pool.complete(completed)).is_err() {
                observation_error = true;
            }
        }
        observation_error
    }

    fn dispatch_due(
        &mut self,
        due: DueSlots,
        pool: &mut AccountPool,
        launch: &mut Launcher<'_>,
    ) -> Result<(), InvalidLedger> {
        let Self {
            phase,
            schedule,
            pending,
            next_dispatch,
            timeout,
            lag_allowance,
            letter,
            nonce,
            control,
            ..
        } = self;
        let (timeout, lag_allowance, letter) = (*timeout, *lag_allowance, *letter);
        if phase
            .ledger
            .record_skipped(due.skipped, SkipReason::Scheduler)
            .is_err()
        {
            return Err(InvalidLedger);
        }
        let mut invalid = false;
        for sequence in due.dispatch {
            let slot = schedule.slot(sequence);
            let index = (sequence % pool.accounts.len() as u64) as usize;
            let at = Instant::now();
            let skipped = if at >= schedule.tail_end()
                || at.saturating_duration_since(slot.scheduled_at) > lag_allowance
            {
                Some(SkipReason::Scheduler)
            } else if pool.states[index] == ChurnAccountState::Retired {
                Some(SkipReason::Disconnected)
            } else if pool.states[index] != ChurnAccountState::Idle {
                Some(SkipReason::AccountBusy)
            } else {
                None
            };
            if let Some(reason) = skipped {
                if pool.states[index] == ChurnAccountState::Retired {
                    phase.reason(
                        ReasonCode::OperationsFailed,
                        "churn_retired_account_selected",
                    );
                }
                if phase
                    .ledger
                    .record_skipped(sequence..sequence + 1, reason)
                    .is_err()
                {
                    invalid = true;
                    break;
                }
                continue;
            }
            let operation = match phase.ledger.reserve(
                slot,
                RouteIdentity::Churn {
                    account_index: index as u32,
                },
            ) {
                Ok(id) => id,
                Err(ReserveError::Skipped(_)) => continue,
                Err(ReserveError::Invalid(_)) => {
                    invalid = true;
                    break;
                }
            };
            let admitted = Instant::now();
            if admitted >= schedule.tail_end()
                || admitted.saturating_duration_since(slot.scheduled_at) > lag_allowance
            {
                if phase
                    .ledger
                    .rollback_reservation(operation, SkipReason::Scheduler)
                    .is_err()
                {
                    invalid = true;
                    break;
                }
                continue;
            }
            let Some(account) = pool.take(index) else {
                let _ = phase
                    .ledger
                    .rollback_reservation(operation, SkipReason::AccountBusy);
                invalid = true;
                break;
            };
            pending.push(launch(
                account,
                CycleRequest {
                    slot,
                    index: index as u32,
                    resource: resource(nonce, letter, sequence),
                    mode: KeyMode::Reuse,
                    deadline: slot.scheduled_at + timeout,
                },
                control.clone(),
            ));
            if phase.ledger.commit_dispatch(operation, admitted).is_err() {
                invalid = true;
                break;
            }
        }
        *next_dispatch = due.next_deadline;
        if invalid { Err(InvalidLedger) } else { Ok(()) }
    }

    fn wake(&self, now: Instant) -> Instant {
        self.next_dispatch
            .unwrap_or(self.drain_deadline)
            .min(if now < self.end {
                self.end
            } else {
                self.drain_deadline
            })
    }

    async fn conclude(
        self,
        context: &mut RunContext,
        pool: &mut AccountPool,
        termination: Termination,
    ) -> MeasurementResult {
        let Self {
            mut phase,
            mut pending,
            phase_index,
            mut drain_index,
            drain_name,
            drain_deadline,
            control: _control,
            stop,
            measuring,
            duration,
            rate,
            topology,
            ..
        } = self;
        if drain_index.is_none() {
            context.finish_phase(phase_index, PhaseStatus::Truncated);
            drain_index = Some(context.start_phase(drain_name, Some(drain_deadline)));
        }
        let barrier = if pending.is_empty() && phase.ledger.is_settled() {
            PhaseBarrier::Settled
        } else {
            PhaseBarrier::RetiredAndDrained
        };
        stop.send_replace(true);
        while !pending.is_empty() {
            let completed = next_completed(&mut pending).await;
            let outcome = pool.complete(completed);
            let _ = phase.observe(outcome);
        }
        if context.invalid.load(Ordering::Acquire) {
            let _ = phase.ledger.observe(OperationEvent::EventOverflow);
        }
        let result = phase.finish(termination, barrier);
        if let Some(index) = drain_index {
            context.finish_phase(
                index,
                if result.status().measured() {
                    PhaseStatus::Completed
                } else {
                    PhaseStatus::Failed
                },
            );
        }
        context.report.phases[phase_index].counters = result.counters.clone();
        let rates = result.rates(duration, rate, topology);
        context.report.phases[phase_index].rates = rates.clone();
        for reason in &result.reasons {
            if (measuring || !reason.code.status().measured())
                && !context.report.reasons.contains(reason)
            {
                context.report.reasons.push(reason.clone());
                context.report.status = context.report.status.combine(reason.code.status());
            }
        }
        if measuring {
            context.report.counters = result.counters.clone();
            context.report.counters.requested_connections = pool.accounts.len() as u64;
            context.report.rates = rates;
            context.report.latencies = result.latencies.clone();
        }
        result
    }
}

#[cfg(test)]
mod tests;
