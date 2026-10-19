// SPDX-License-Identifier: Apache-2.0

use crate::{
    client::{
        self, ClientSession, ConnectFailureKind, ConnectObservation, ConnectStage, KeyMode,
        NegotiatedTls, OperationId, PreparedAccount, ReceivedKind, ResolvedTarget, StageFailure,
        TrafficPhase,
    },
    error::BenchResult,
    measurement::{
        CloseOutcome, FinishReason, Ledger, LedgerContext, LedgerTopology, LoginOutcome,
        MeasurementResult, OperationEvent, PhaseBarrier, RateSchedule, ReserveError, RouteIdentity,
        ScheduledSlot, SkipReason, Termination,
    },
    report::{
        CounterReport, ErrorCategory, PhaseName, PhaseStatus, ReasonCode, RunReason, RunStatus,
    },
    run::{RunContext, events::RunObserver, failure, policy},
};
use lonewolf_util::blocking::BlockingExecutor;
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
    cpu: BlockingExecutor,
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
            let bound = match observation.bound_at {
                Some(at) => at,
                None => unreachable!("validated bind has a timestamp"),
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
    context.cpu.run(|| ()).await;
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
    let schedule = RateSchedule::new(
        Instant::now(),
        duration,
        rate,
        policy(&context.config.measurement),
    )?;
    let (stop, stopped) = watch::channel(false);
    let control = CycleControl {
        interruption: context.interruption.clone(),
        stop: stopped,
    };
    let mut pending = Vec::with_capacity(count.min(context.config.measurement.connect_concurrency));
    let mut next = 0;
    let mut error = None;
    let mut iterations = None;
    let mut mixed_iterations = false;
    let mut tls = None;
    let mut counters = CounterReport {
        requested_connections: count as u64,
        ..Default::default()
    };
    let dispatch = policy(&context.config.measurement);
    let start = schedule.slot(0).scheduled_at;
    let mut tick_end = start + dispatch.quantum;
    let mut batch = 0;
    while next < count || !pending.is_empty() {
        let now = Instant::now();
        if error.is_none() {
            if *context.interruption.borrow() {
                error = Some(failure("interrupted"));
            } else if now >= context.setup_deadline {
                error = Some(failure("setup_deadline"));
            }
        }
        if error.is_some() {
            stop.send_replace(true);
        }
        if now >= tick_end {
            tick_end = start
                + Duration::from_nanos(
                    ((now.duration_since(start).as_nanos() / dispatch.quantum.as_nanos() + 1)
                        * dispatch.quantum.as_nanos()) as u64,
                );
            batch = 0;
        }
        let slot = (next < count).then(|| schedule.slot(next as u64));
        if error.is_none()
            && let Some(slot) = slot
        {
            if now.saturating_duration_since(slot.scheduled_at) > dispatch.lag_allowance {
                error = Some(failure("ramp_scheduler_miss"));
                continue;
            }
            if now >= slot.scheduled_at
                && pending.len() < context.config.measurement.connect_concurrency
                && batch < dispatch.max_batch
            {
                let Some(account) = pool.take(next) else {
                    error = Some(failure("churn_prime_account"));
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
                counters.connection_attempts += 1;
                next += 1;
                batch += 1;
                continue;
            }
        }
        if error.is_some() && pending.is_empty() {
            break;
        }
        let wake = if error.is_some() {
            context.setup_deadline
        } else {
            match slot {
                Some(slot) if pending.len() == context.config.measurement.connect_concurrency => {
                    slot.scheduled_at + dispatch.lag_allowance + Duration::from_nanos(1)
                }
                Some(_) if batch == dispatch.max_batch => tick_end,
                Some(slot) => slot.scheduled_at,
                None => context.setup_deadline,
            }
            .min(context.setup_deadline)
        };
        tokio::select! {
            biased;
            completed = next_completed(&mut pending), if !pending.is_empty() => {
                let succeeded = matches!(completed.outcome.login, LoginOutcome::Succeeded { .. });
                let clean = matches!(completed.outcome.close, Some(CloseOutcome::Clean { .. }));
                if succeeded { counters.login_succeeded += 1; } else { counters.login_failed += 1; }
                if let LoginOutcome::Failed { category, .. } = completed.outcome.login { *counters.errors.entry(category).or_default() += 1; }
                if let Some(failure) = &completed.outcome.failure && failure.kind == ConnectFailureKind::Deadline { *counters.errors.entry(ErrorCategory::Deadline).or_default() += 1; }
                if let Some(CloseOutcome::Failed { category, .. }) = completed.outcome.close { *counters.errors.entry(category).or_default() += 1; }
                if clean {
                    counters.closed_cleanly += 1;
                    let observed = completed.account.cached_scram_iterations();
                    if counters.closed_cleanly == 1 { iterations = observed; tls = completed.tls.clone(); }
                    else if iterations != observed { mixed_iterations = true; }
                } else {
                    counters.close_failed += u64::from(succeeded);
                    if error.is_none() {
                        error = Some(if *context.interruption.borrow() { failure("interrupted") }
                            else { completed.outcome.failure.as_ref().map_or_else(|| failure("churn_prime_close_failed"), |failure| failure.error.clone()) });
                    }
                }
                pool.complete(completed);
            },
            _ = context.interruption.changed(), if error.is_none() => {},
            _ = sleep_until(wake), if error.is_none() => {},
        }
    }
    context.setup_attempts = counters.connection_attempts;
    context.setup_failures = counters.login_failed;
    counters.established_connections = counters.login_succeeded;
    if let Some(phase) = context.report.phases.last_mut() {
        phase.counters = counters;
    }
    context.report.target.cache_primed = error.is_none();
    if error.is_none() {
        context.report.target.observed_scram_iterations =
            if mixed_iterations { None } else { iterations };
        if let Some(tls) = tls {
            context.report.target.negotiated_tls = Some(format!("{:?}", tls.version));
            context.report.target.cipher = Some(format!("{:?}", tls.cipher));
        }
    }
    error.map_or(Ok(()), Err)
}

struct ChurnPhase {
    ledger: Ledger,
    nonce: [u8; 16],
    phase: TrafficPhase,
    reasons: Vec<RunReason>,
    errors: BTreeMap<ErrorCategory, u64>,
    failed: bool,
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
        if !matches!(outcome.login, LoginOutcome::Succeeded { .. })
            || !matches!(outcome.close, Some(CloseOutcome::Clean { .. }))
        {
            self.failed = true;
        }
        if matches!(
            outcome.close,
            Some(CloseOutcome::Failed { .. } | CloseOutcome::Cancelled { .. })
        ) {
            self.reason(
                ReasonCode::WorkloadFailure,
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
                        ReasonCode::SchedulerMiss
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
        let termination = if self.failed && termination == Termination::Completed {
            Termination::Failed
        } else {
            termination
        };
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
    if !context.report.target.cache_primed {
        return Err(failure("churn_not_primed"));
    }
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
        if result.status() != RunStatus::Passed {
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
    let dispatch = policy(&context.config.measurement);
    let mut schedule = RateSchedule::new(
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
    let mut phase = ChurnPhase {
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
        failed: false,
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
    let mut drain_index = None;
    let mut pending = Vec::with_capacity(
        pool.accounts
            .len()
            .min(context.config.measurement.connect_concurrency),
    );
    let (stop, stopped) = watch::channel(false);
    let control = CycleControl {
        interruption: context.interruption.clone(),
        stop: stopped,
    };
    let mut next_dispatch = Some(start);
    let termination = loop {
        let mut observation_error = false;
        for _ in 0..pending.len() {
            let completed = poll_fn(|cx| {
                Poll::Ready(match poll_completed(&mut pending, cx) {
                    Poll::Ready(value) => Some(value),
                    Poll::Pending => None,
                })
            })
            .await;
            let Some(completed) = completed else {
                break;
            };
            if phase.observe(pool.complete(completed)).is_err() {
                observation_error = true;
            }
        }
        if observation_error {
            break Termination::Failed;
        }
        let now = Instant::now();
        if *context.interruption.borrow() {
            break Termination::Cancelled;
        }
        if context.invalid.load(Ordering::Acquire) {
            let _ = phase.ledger.observe(OperationEvent::EventOverflow);
            break Termination::Failed;
        }
        if now >= end && drain_index.is_none() {
            context.finish_phase(phase_index, PhaseStatus::Completed);
            drain_index = Some(context.start_phase_at(drain_name, end, Some(drain_deadline)));
        }
        if next_dispatch.is_some_and(|at| now >= at) {
            let due = schedule.poll_due(now);
            if phase
                .ledger
                .record_skipped(due.skipped, SkipReason::Scheduler)
                .is_err()
                || phase
                    .ledger
                    .record_dispatch_batch(due.dispatch.end - due.dispatch.start)
                    .is_err()
            {
                break Termination::Failed;
            }
            let mut invalid = false;
            for sequence in due.dispatch {
                let slot = schedule.slot(sequence);
                let index = (sequence % pool.accounts.len() as u64) as usize;
                let at = Instant::now();
                let skipped = if at >= schedule.tail_end()
                    || at.saturating_duration_since(slot.scheduled_at) > dispatch.lag_allowance
                {
                    Some(SkipReason::Scheduler)
                } else if pool.states[index] != ChurnAccountState::Idle {
                    Some(SkipReason::AccountBusy)
                } else {
                    None
                };
                if let Some(reason) = skipped {
                    if pool.states[index] == ChurnAccountState::Retired {
                        phase.reason(
                            ReasonCode::WorkloadFailure,
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
                    || admitted.saturating_duration_since(slot.scheduled_at)
                        > dispatch.lag_allowance
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
                        resource: resource(&nonce, letter, sequence),
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
            next_dispatch = due.next_deadline;
            if invalid {
                break Termination::Failed;
            }
        }
        if now >= end && next_dispatch.is_none() && pending.is_empty() {
            break Termination::Completed;
        }
        if now >= drain_deadline {
            phase.reason(ReasonCode::AccountingError, "churn_drain_deadline");
            break Termination::Failed;
        }
        let wake = next_dispatch.unwrap_or(drain_deadline).min(if now < end {
            end
        } else {
            drain_deadline
        });
        tokio::select! {
            biased;
            completed = next_completed(&mut pending), if !pending.is_empty() => {
                let outcome = pool.complete(completed);
                if phase.observe(outcome).is_err() { break Termination::Failed; }
            },
            _ = context.interruption.changed() => {},
            _ = sleep_until(wake) => {},
        }
    };
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
            if result.status() == RunStatus::Passed {
                PhaseStatus::Completed
            } else {
                PhaseStatus::Failed
            },
        );
    }
    context.report.phases[phase_index].counters = result.counters.clone();
    let rates = result.rates(settings.duration, settings.rate, topology);
    context.report.phases[phase_index].rates = rates.clone();
    context.report.status = context.report.status.combine(result.status());
    for reason in &result.reasons {
        if !context.report.reasons.contains(reason) {
            context.report.reasons.push(reason.clone());
        }
    }
    if measuring {
        context.report.counters = result.counters.clone();
        context.report.counters.requested_connections = pool.accounts.len() as u64;
        context.report.rates = rates;
        context.report.latencies = result.latencies.clone();
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
