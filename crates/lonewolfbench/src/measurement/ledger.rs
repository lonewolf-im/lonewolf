// SPDX-License-Identifier: Apache-2.0

use super::{
    LatencyHistogram, MeasurementResult, ScheduledSlot, increment as checked_increment, invalid,
};
use crate::{
    client::{ConnectTimings, CorrelationId, OperationId, TrafficPhase, WriterEvent},
    config::{MAX_ACCOUNTS, MAX_PHASE_OPERATIONS},
    error::{BenchError, BenchResult},
    report::{CounterReport, ErrorCategory, LatencyKind, ReasonCode, RunReason},
};
use std::{
    collections::{BTreeMap, HashMap},
    num::NonZeroU32,
    ops::Range,
    time::Duration,
};
use tokio::time::Instant;

#[derive(Clone, Copy, Debug)]
pub enum LedgerTopology {
    Messages { pairs: NonZeroU32 },
    Churn { accounts: NonZeroU32 },
}

#[derive(Clone, Copy, Debug)]
pub struct LedgerContext {
    pub run_nonce: [u8; 16],
    pub phase: TrafficPhase,
    pub start: Instant,
    pub end: Instant,
    pub shutdown_timeout: Duration,
    pub topology: LedgerTopology,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteIdentity {
    Message {
        sender_index: u32,
        receiver_index: u32,
    },
    Churn {
        account_index: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkipReason {
    Scheduler,
    InFlight,
    WriterBusy,
    AccountBusy,
    Disconnected,
    Cancelled,
}

#[derive(Debug)]
pub enum ReserveError {
    Skipped(SkipReason),
    Invalid(BenchError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseBarrier {
    /// The coordinator has reconciled idle actor queues.
    Settled,
    /// The coordinator has joined producers and consumed their remaining events.
    RetiredAndDrained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Termination {
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug)]
pub struct FinishReason {
    pub termination: Termination,
    pub barrier: PhaseBarrier,
}

#[derive(Clone, Copy, Debug)]
pub enum LoginOutcome {
    Succeeded {
        at: Instant,
        timings: ConnectTimings,
    },
    Failed {
        at: Instant,
        category: ErrorCategory,
    },
    Cancelled {
        at: Instant,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum CloseOutcome {
    Clean {
        at: Instant,
    },
    Failed {
        at: Instant,
        category: ErrorCategory,
    },
    Cancelled {
        at: Instant,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum RejectedObservation {
    UnknownId,
    StalePhase,
    WrongRecipient,
    Unexpected,
}

#[derive(Clone, Debug)]
pub enum OperationEvent {
    Writer(WriterEvent),
    Receipt {
        operation: OperationId,
        at: Instant,
        route: RouteIdentity,
    },
    ConnectionClosed {
        session_index: u32,
        at: Instant,
    },
    SendFailed {
        operation: OperationId,
        at: Instant,
    },
    Deadline {
        at: Instant,
    },
    Rejected(RejectedObservation),
    EventOverflow,
    ChurnFinished {
        operation: OperationId,
        account_index: u32,
        connect_started_at: Option<Instant>,
        login: LoginOutcome,
        close: Option<CloseOutcome>,
    },
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum EntryState {
    #[default]
    Unstarted,
    Reserved,
    Skipped,
    Dispatched,
    Settled,
}

#[derive(Clone, Copy, Default)]
struct LedgerEntry {
    state: EntryState,
    receipt_seen: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WriteOutcome {
    Pending,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy)]
struct Active {
    scheduled: Instant,
    deadline: Instant,
    enqueued: Option<Instant>,
    started: Option<Instant>,
    write_at: Option<Instant>,
    write: WriteOutcome,
    receipt: Option<Instant>,
    on_time: bool,
    receive_start_attempted: bool,
    write_duration_attempted: bool,
    expired: bool,
    connection_closed: bool,
    send_failed: bool,
    churn_terminal: bool,
}

#[derive(Default)]
struct Samples {
    values: [Option<(LatencyKind, Duration)>; 8],
    len: usize,
}

impl Samples {
    fn push(&mut self, kind: LatencyKind, duration: Duration) {
        self.values[self.len] = Some((kind, duration));
        self.len += 1;
    }
}

fn retain_reason(reasons: &mut Vec<RunReason>, code: ReasonCode) {
    if !reasons.iter().any(|reason| reason.code == code) {
        reasons.push(RunReason {
            code,
            context: None,
        });
    }
}

fn increment(value: &mut u64, amount: u64, reasons: &mut Vec<RunReason>) -> BenchResult<()> {
    let result = checked_increment(value, amount);
    if result.is_err() {
        retain_reason(reasons, ReasonCode::AccountingError);
    }
    result
}

pub struct Ledger {
    context: LedgerContext,
    timeout: Duration,
    entries: Vec<LedgerEntry>,
    active: HashMap<u64, Active>,
    max_in_flight: usize,
    counters: CounterReport,
    histograms: BTreeMap<LatencyKind, LatencyHistogram>,
    reasons: Vec<RunReason>,
}

impl Ledger {
    pub fn new(
        planned: u64,
        max_in_flight: usize,
        timeout: Duration,
        context: LedgerContext,
    ) -> BenchResult<Self> {
        let accounts = match context.topology {
            LedgerTopology::Messages { pairs } => u64::from(pairs.get()) * 2,
            LedgerTopology::Churn { accounts } => accounts.get().into(),
        };
        if planned > MAX_PHASE_OPERATIONS
            || !(1..=65_536).contains(&max_in_flight)
            || accounts > MAX_ACCOUNTS as u64
            || timeout.is_zero()
            || context.shutdown_timeout.is_zero()
            || (planned == 0 && context.start != context.end)
            || (planned != 0 && context.start >= context.end)
        {
            return Err(invalid("invalid ledger bounds"));
        }
        let max = timeout
            .checked_add(context.shutdown_timeout)
            .ok_or_else(|| invalid("histogram bound overflow"))?;
        context
            .end
            .checked_add(max)
            .ok_or_else(|| invalid("ledger deadline overflow"))?;
        let count = usize::try_from(planned).map_err(|_| invalid("ledger size overflow"))?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| invalid("ledger allocation failed"))?;
        entries.resize(count, LedgerEntry::default());
        let mut active = HashMap::new();
        active
            .try_reserve(max_in_flight)
            .map_err(|_| invalid("active ledger allocation failed"))?;
        use LatencyKind::*;
        let mut histograms = BTreeMap::new();
        for kind in [
            DispatchSchedulingLag,
            SchedulingLag,
            MessageScheduleToReceive,
            MessageWriteStartToReceive,
            MessageWriteDuration,
            LoginScheduleToBound,
            LoginConnectToBound,
            TcpConnect,
            Starttls,
            Authenticate,
            Bind,
            Close,
        ] {
            histograms.insert(kind, LatencyHistogram::new(max)?);
        }
        let mut reasons = Vec::new();
        reasons
            .try_reserve_exact(8)
            .map_err(|_| invalid("reason allocation failed"))?;
        Ok(Self {
            context,
            timeout,
            entries,
            active,
            max_in_flight,
            counters: CounterReport {
                planned,
                ..CounterReport::default()
            },
            histograms,
            reasons,
        })
    }

    pub fn counters(&self) -> &CounterReport {
        &self.counters
    }
    pub fn retained(&self) -> usize {
        self.active.len()
    }
    pub fn is_settled(&self) -> bool {
        self.active.is_empty()
    }

    pub fn expected_route(&self, sequence: u64) -> BenchResult<RouteIdentity> {
        if sequence >= self.counters.planned {
            return Err(invalid("sequence outside phase"));
        }
        Ok(match self.context.topology {
            LedgerTopology::Messages { pairs } => {
                let pair = (sequence % u64::from(pairs.get())) as u32;
                RouteIdentity::Message {
                    sender_index: 2 * pair,
                    receiver_index: 2 * pair + 1,
                }
            }
            LedgerTopology::Churn { accounts } => RouteIdentity::Churn {
                account_index: (sequence % u64::from(accounts.get())) as u32,
            },
        })
    }

    fn reason(&mut self, code: ReasonCode) {
        retain_reason(&mut self.reasons, code);
    }

    fn accounting(&mut self, context: &'static str) -> BenchError {
        self.reason(ReasonCode::AccountingError);
        invalid(context)
    }

    fn record_samples(&mut self, samples: Samples) -> BenchResult<()> {
        let mut first_error = None;
        for (kind, duration) in samples.values.into_iter().flatten() {
            let result = match self.histograms.get_mut(&kind) {
                Some(histogram) => histogram.record(duration),
                None => Err(self.accounting("missing histogram")),
            };
            if let Err(error) = result {
                self.reason(ReasonCode::HistogramError);
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn elapsed(&mut self, end: Instant, start: Instant) -> BenchResult<Duration> {
        end.checked_duration_since(start)
            .ok_or_else(|| self.accounting("negative operation latency"))
    }

    pub fn reserve(
        &mut self,
        slot: ScheduledSlot,
        route: RouteIdentity,
    ) -> Result<OperationId, ReserveError> {
        let valid = self.expected_route(slot.sequence).is_ok_and(|r| r == route)
            && slot.scheduled_at >= self.context.start
            && slot.scheduled_at < self.context.end
            && self
                .entries
                .get(slot.sequence as usize)
                .is_some_and(|e| e.state == EntryState::Unstarted);
        if !valid {
            return Err(ReserveError::Invalid(
                self.accounting("invalid operation reservation"),
            ));
        }
        if self.active.len() == self.max_in_flight {
            self.record_skipped(slot.sequence..slot.sequence + 1, SkipReason::InFlight)
                .map_err(ReserveError::Invalid)?;
            return Err(ReserveError::Skipped(SkipReason::InFlight));
        }
        let deadline = slot
            .scheduled_at
            .checked_add(self.timeout)
            .ok_or_else(|| ReserveError::Invalid(self.accounting("operation deadline overflow")))?;
        self.active.insert(
            slot.sequence,
            Active {
                scheduled: slot.scheduled_at,
                deadline,
                enqueued: None,
                started: None,
                write_at: None,
                write: WriteOutcome::Pending,
                receipt: None,
                on_time: false,
                receive_start_attempted: false,
                write_duration_attempted: false,
                expired: false,
                connection_closed: false,
                send_failed: false,
                churn_terminal: false,
            },
        );
        self.entries[slot.sequence as usize].state = EntryState::Reserved;
        self.counters.peak_in_flight = self.counters.peak_in_flight.max(self.active.len() as u64);
        Ok(CorrelationId {
            run_nonce: self.context.run_nonce,
            phase: self.context.phase,
            sequence: slot.sequence,
        })
    }

    fn own_id(&self, id: OperationId) -> bool {
        id.run_nonce == self.context.run_nonce
            && id.phase == self.context.phase
            && id.sequence < self.counters.planned
    }

    /// An error after admission does not permit rollback or retry.
    pub fn commit_dispatch(&mut self, id: OperationId, enqueued_at: Instant) -> BenchResult<()> {
        if !self.own_id(id) || self.entries[id.sequence as usize].state != EntryState::Reserved {
            return Err(self.accounting("commit without reservation"));
        }
        let scheduled = self.active[&id.sequence].scheduled;
        let lag = self.elapsed(enqueued_at, scheduled)?;
        let Some(active) = self.active.get_mut(&id.sequence) else {
            return Err(self.accounting("missing reservation"));
        };
        active.enqueued = Some(enqueued_at);
        self.entries[id.sequence as usize].state = EntryState::Dispatched;
        increment(&mut self.counters.dispatched, 1, &mut self.reasons)?;
        if enqueued_at < self.context.end {
            increment(
                &mut self.counters.dispatched_in_window,
                1,
                &mut self.reasons,
            )?;
        } else {
            increment(
                &mut self.counters.dispatched_during_drain,
                1,
                &mut self.reasons,
            )?;
        }
        if matches!(self.context.topology, LedgerTopology::Churn { .. }) {
            increment(&mut self.counters.connection_attempts, 1, &mut self.reasons)?;
        }
        let mut samples = Samples::default();
        samples.push(LatencyKind::DispatchSchedulingLag, lag);
        self.record_samples(samples)
    }

    fn count_skip(&mut self, reason: SkipReason, count: u64) -> BenchResult<()> {
        let value = match reason {
            SkipReason::Scheduler => &mut self.counters.skipped_scheduler,
            SkipReason::InFlight => &mut self.counters.skipped_in_flight,
            SkipReason::WriterBusy => &mut self.counters.skipped_writer_busy,
            SkipReason::AccountBusy => &mut self.counters.skipped_account_busy,
            SkipReason::Disconnected => &mut self.counters.skipped_disconnected,
            SkipReason::Cancelled => &mut self.counters.cancelled_before_dispatch,
        };
        increment(value, count, &mut self.reasons)?;
        if count > 0 {
            self.reason(match reason {
                SkipReason::Cancelled => ReasonCode::Interrupted,
                SkipReason::Disconnected => ReasonCode::OperationsFailed,
                _ => ReasonCode::DriverLimited,
            });
        }
        Ok(())
    }

    pub fn record_skipped(&mut self, sequences: Range<u64>, reason: SkipReason) -> BenchResult<()> {
        if sequences.start > sequences.end
            || sequences.end > self.counters.planned
            || self.entries[sequences.start as usize..sequences.end as usize]
                .iter()
                .any(|e| e.state != EntryState::Unstarted)
        {
            return Err(self.accounting("overlapping skipped slots"));
        }
        self.count_skip(reason, sequences.end - sequences.start)?;
        for entry in &mut self.entries[sequences.start as usize..sequences.end as usize] {
            entry.state = EntryState::Skipped;
        }
        Ok(())
    }

    pub fn rollback_reservation(&mut self, id: OperationId, reason: SkipReason) -> BenchResult<()> {
        if !self.own_id(id) || self.entries[id.sequence as usize].state != EntryState::Reserved {
            return Err(self.accounting("rollback without reservation"));
        }
        self.count_skip(reason, 1)?;
        self.active.remove(&id.sequence);
        self.entries[id.sequence as usize].state = EntryState::Skipped;
        Ok(())
    }

    pub fn expire_through(&mut self, now: Instant) -> BenchResult<()> {
        for active in self.active.values_mut() {
            if active.deadline <= now {
                active.expired = true;
            }
        }
        Ok(())
    }

    /// Keep consuming producer events after an error until the retirement barrier.
    pub fn observe(&mut self, event: OperationEvent) -> BenchResult<()> {
        self.observe_inner(event)
    }

    fn observe_inner(&mut self, event: OperationEvent) -> BenchResult<()> {
        match event {
            OperationEvent::Deadline { at } => self.expire_through(at),
            OperationEvent::EventOverflow => {
                self.reason(ReasonCode::EventOverflow);
                Ok(())
            }
            OperationEvent::Rejected(kind) => increment(
                match kind {
                    RejectedObservation::UnknownId => &mut self.counters.unknown_ids,
                    RejectedObservation::StalePhase => &mut self.counters.stale_phase_stanzas,
                    RejectedObservation::WrongRecipient => &mut self.counters.wrong_recipient,
                    RejectedObservation::Unexpected => &mut self.counters.unexpected_stanzas,
                },
                1,
                &mut self.reasons,
            ),
            OperationEvent::ConnectionClosed {
                session_index,
                at: _,
            } => {
                let accounts = match self.context.topology {
                    LedgerTopology::Messages { pairs } => pairs.get() * 2,
                    LedgerTopology::Churn { accounts } => accounts.get(),
                };
                // A closure detected just before the phase can be consumed after it starts.
                if session_index >= accounts {
                    return Err(self.accounting("invalid connection closure"));
                }
                increment(
                    &mut self.counters.unexpected_disconnects,
                    1,
                    &mut self.reasons,
                )?;
                for (&sequence, active) in &mut self.active {
                    if let LedgerTopology::Messages { pairs } = self.context.topology {
                        let sender = (sequence % u64::from(pairs.get())) as u32 * 2;
                        if session_index == sender || session_index == sender + 1 {
                            active.connection_closed = true;
                        }
                    }
                }
                Ok(())
            }
            OperationEvent::Receipt {
                operation,
                at,
                route,
            } => self.receipt(operation, at, route),
            OperationEvent::Writer(event) => {
                let (operation, at, outcome) = match event {
                    WriterEvent::WriteStarted { operation, at } => (operation, at, None),
                    WriterEvent::WriteCompleted { operation, at, .. } => {
                        (operation, at, Some(WriteOutcome::Succeeded))
                    }
                    WriterEvent::WriteFailed { operation, at } => {
                        (operation, at, Some(WriteOutcome::Failed))
                    }
                };
                self.with_active(operation, |this, active| {
                    if !matches!(this.context.topology, LedgerTopology::Messages { .. }) {
                        return Err(this.accounting("writer event for churn"));
                    }
                    let enqueued = active
                        .enqueued
                        .ok_or_else(|| this.accounting("uncommitted event"))?;
                    this.elapsed(at, enqueued)?;
                    let mut next = *active;
                    if let Some(outcome) = outcome {
                        if active.write != WriteOutcome::Pending {
                            return Err(this.accounting("duplicate writer completion"));
                        }
                        next.write = outcome;
                        next.write_at = Some(at);
                    } else {
                        if active.started.is_some() {
                            return Err(this.accounting("duplicate writer start"));
                        }
                        next.started = Some(at);
                    }
                    this.validate_message(&next)?;
                    *active = next;
                    match outcome {
                        Some(WriteOutcome::Succeeded) => {
                            increment(&mut this.counters.write_succeeded, 1, &mut this.reasons)?;
                            if at < this.context.end {
                                increment(
                                    &mut this.counters.write_succeeded_in_window,
                                    1,
                                    &mut this.reasons,
                                )?;
                            } else {
                                increment(
                                    &mut this.counters.write_succeeded_during_drain,
                                    1,
                                    &mut this.reasons,
                                )?;
                            }
                        }
                        Some(WriteOutcome::Failed) => {
                            increment(&mut this.counters.write_failed, 1, &mut this.reasons)?;
                        }
                        _ => {}
                    }
                    let mut samples = this.message_samples(active);
                    if outcome.is_none() {
                        samples.push(
                            LatencyKind::SchedulingLag,
                            at.duration_since(active.scheduled),
                        );
                    }
                    Ok(samples)
                })
            }
            OperationEvent::SendFailed { operation, at } => {
                if !self.own_id(operation) {
                    return Err(self.accounting("invalid stanza failure ID"));
                }
                if self.entries[operation.sequence as usize].state == EntryState::Settled {
                    return Ok(());
                }
                self.with_active(operation, |this, active| {
                    this.elapsed(at, active.scheduled)?;
                    active.send_failed = true;
                    Ok(Samples::default())
                })
            }
            OperationEvent::ChurnFinished {
                operation,
                account_index,
                connect_started_at,
                login,
                close,
            } => {
                let expected = self
                    .expected_route(operation.sequence)
                    .map_err(|_| self.accounting("invalid churn sequence"))?;
                if expected != (RouteIdentity::Churn { account_index }) {
                    return Err(self.accounting("invalid churn route"));
                }
                self.with_active(operation, |this, active| {
                    this.churn(active, connect_started_at, login, close)
                })
            }
        }
    }

    fn with_active(
        &mut self,
        id: OperationId,
        f: impl FnOnce(&mut Self, &mut Active) -> BenchResult<Samples>,
    ) -> BenchResult<()> {
        if !self.own_id(id) || self.entries[id.sequence as usize].state != EntryState::Dispatched {
            return Err(self.accounting("event without committed dispatch"));
        }
        let mut active = self
            .active
            .remove(&id.sequence)
            .ok_or_else(|| self.accounting("event after settlement"))?;
        let result = f(self, &mut active);
        let settled = active.churn_terminal
            || (active.on_time
                && active.started.is_some()
                && active.write != WriteOutcome::Pending);
        if settled {
            self.entries[id.sequence as usize].state = EntryState::Settled;
        } else {
            self.active.insert(id.sequence, active);
        }
        self.record_samples(result?)
    }

    fn receipt(
        &mut self,
        operation: OperationId,
        at: Instant,
        route: RouteIdentity,
    ) -> BenchResult<()> {
        if operation.run_nonce != self.context.run_nonce {
            return increment(&mut self.counters.unknown_ids, 1, &mut self.reasons);
        }
        if operation.phase != self.context.phase {
            return increment(&mut self.counters.stale_phase_stanzas, 1, &mut self.reasons);
        }
        if operation.sequence >= self.counters.planned {
            return increment(&mut self.counters.unknown_ids, 1, &mut self.reasons);
        }
        if self.expected_route(operation.sequence)? != route {
            return increment(&mut self.counters.wrong_recipient, 1, &mut self.reasons);
        }
        if !matches!(self.context.topology, LedgerTopology::Messages { .. }) {
            return increment(&mut self.counters.unexpected_stanzas, 1, &mut self.reasons);
        }
        let entry = self.entries[operation.sequence as usize];
        if !matches!(entry.state, EntryState::Dispatched | EntryState::Settled) {
            return increment(&mut self.counters.unknown_ids, 1, &mut self.reasons);
        }
        if entry.receipt_seen {
            return increment(&mut self.counters.duplicates, 1, &mut self.reasons);
        }
        self.with_active(operation, |this, active| {
            let latency = this.elapsed(at, active.scheduled)?;
            let mut next = *active;
            next.receipt = Some(at);
            next.on_time = at <= active.deadline;
            this.validate_message(&next)?;
            *active = next;
            this.entries[operation.sequence as usize].receipt_seen = true;
            if active.on_time {
                increment(&mut this.counters.received_on_time, 1, &mut this.reasons)?;
                if at < this.context.end {
                    increment(&mut this.counters.received_in_window, 1, &mut this.reasons)?;
                } else {
                    increment(
                        &mut this.counters.received_during_drain,
                        1,
                        &mut this.reasons,
                    )?;
                }
            } else {
                increment(&mut this.counters.late_receipts, 1, &mut this.reasons)?;
            }
            let mut samples = this.message_samples(active);
            if active.on_time {
                samples.push(LatencyKind::MessageScheduleToReceive, latency);
            }
            Ok(samples)
        })
    }

    fn validate_message(&mut self, active: &Active) -> BenchResult<()> {
        if let Some(started) = active.started {
            self.elapsed(started, active.scheduled)?;
            if let Some(at) = active.write_at {
                self.elapsed(at, started)?;
            }
            if let Some(at) = active.receipt {
                self.elapsed(at, started)?;
            }
        }
        Ok(())
    }

    fn message_samples(&self, active: &mut Active) -> Samples {
        let mut samples = Samples::default();
        if let Some(started) = active.started {
            if let Some(receipt) = active
                .receipt
                .filter(|_| active.on_time && !active.receive_start_attempted)
            {
                active.receive_start_attempted = true;
                samples.push(
                    LatencyKind::MessageWriteStartToReceive,
                    receipt.duration_since(started),
                );
            }
            if let Some(completed) = active.write_at.filter(|_| {
                active.write == WriteOutcome::Succeeded && !active.write_duration_attempted
            }) {
                active.write_duration_attempted = true;
                samples.push(
                    LatencyKind::MessageWriteDuration,
                    completed.duration_since(started),
                );
            }
        }
        samples
    }

    fn stage_error(&mut self, category: ErrorCategory) -> BenchResult<()> {
        increment(
            self.counters.errors.entry(category).or_default(),
            1,
            &mut self.reasons,
        )
    }

    fn churn(
        &mut self,
        active: &mut Active,
        started: Option<Instant>,
        login: LoginOutcome,
        close: Option<CloseOutcome>,
    ) -> BenchResult<Samples> {
        let login_at = match login {
            LoginOutcome::Succeeded { at, .. }
            | LoginOutcome::Failed { at, .. }
            | LoginOutcome::Cancelled { at } => at,
        };
        let schedule_latency = self.elapsed(login_at, active.scheduled)?;
        let mut samples = Samples::default();
        if let Some(start) = started {
            let enqueued = active
                .enqueued
                .ok_or_else(|| self.accounting("uncommitted churn"))?;
            self.elapsed(start, enqueued)?;
            self.elapsed(login_at, start)?;
            let lag = self.elapsed(start, active.scheduled)?;
            samples.push(LatencyKind::SchedulingLag, lag);
        } else if !matches!(login, LoginOutcome::Cancelled { .. }) {
            return Err(self.accounting("missing churn start"));
        }
        if !matches!(login, LoginOutcome::Succeeded { .. }) && close.is_some() {
            return Err(self.accounting("close after unsuccessful login"));
        }
        if let LoginOutcome::Succeeded { at, timings } = login {
            let start = started.ok_or_else(|| self.accounting("missing churn start"))?;
            let close = close.ok_or_else(|| self.accounting("missing churn close"))?;
            let close_at = match close {
                CloseOutcome::Clean { at }
                | CloseOutcome::Failed { at, .. }
                | CloseOutcome::Cancelled { at } => at,
            };
            let close_duration = self.elapsed(close_at, at)?;
            let connect_latency = self.elapsed(at, start)?;
            samples.push(LatencyKind::LoginScheduleToBound, schedule_latency);
            samples.push(LatencyKind::LoginConnectToBound, connect_latency);
            for (kind, us) in [
                (LatencyKind::TcpConnect, timings.tcp_us),
                (LatencyKind::Starttls, timings.starttls_us),
                (LatencyKind::Authenticate, timings.authenticate_us),
                (LatencyKind::Bind, timings.bind_us),
            ] {
                samples.push(kind, Duration::from_micros(us));
            }
            if matches!(close, CloseOutcome::Clean { .. }) {
                samples.push(LatencyKind::Close, close_duration);
            }
        }
        active.churn_terminal = true;
        match login {
            LoginOutcome::Succeeded { at, .. } => {
                increment(&mut self.counters.login_succeeded, 1, &mut self.reasons)?;
                if at < self.context.end {
                    increment(&mut self.counters.login_in_window, 1, &mut self.reasons)?;
                } else {
                    increment(&mut self.counters.login_during_drain, 1, &mut self.reasons)?;
                }
                match close {
                    Some(CloseOutcome::Clean { .. }) => {
                        increment(&mut self.counters.closed_cleanly, 1, &mut self.reasons)?;
                    }
                    Some(CloseOutcome::Failed { category, .. }) => {
                        increment(&mut self.counters.close_failed, 1, &mut self.reasons)?;
                        self.stage_error(category)?;
                    }
                    Some(CloseOutcome::Cancelled { .. }) => {
                        increment(&mut self.counters.close_failed, 1, &mut self.reasons)?;
                        self.reason(ReasonCode::Interrupted);
                    }
                    None => return Err(self.accounting("missing churn close")),
                }
            }
            LoginOutcome::Failed { category, .. } => {
                increment(&mut self.counters.login_failed, 1, &mut self.reasons)?;
                self.stage_error(category)?;
            }
            LoginOutcome::Cancelled { .. } => {
                increment(&mut self.counters.login_failed, 1, &mut self.reasons)?;
                self.reason(ReasonCode::Interrupted);
            }
        }
        Ok(samples)
    }

    /// Returns partial evidence even when accounting or the caller's barrier is invalid.
    pub fn finish(mut self, reason: FinishReason) -> MeasurementResult {
        match reason.termination {
            Termination::Cancelled => self.reason(ReasonCode::Interrupted),
            Termination::Failed => self.reason(ReasonCode::WorkloadFailure),
            Termination::Completed => {}
        }
        let may_finalize = reason.barrier == PhaseBarrier::RetiredAndDrained
            || self.active.values().all(|active| active.expired);
        if !may_finalize {
            self.reason(ReasonCode::AccountingError);
        }
        if reason.termination == Termination::Completed
            && self
                .entries
                .iter()
                .any(|e| matches!(e.state, EntryState::Unstarted | EntryState::Reserved))
        {
            self.reason(ReasonCode::AccountingError);
        }
        if may_finalize {
            if reason.termination != Termination::Completed {
                let unstarted = self
                    .entries
                    .iter()
                    .filter(|e| matches!(e.state, EntryState::Unstarted | EntryState::Reserved))
                    .count() as u64;
                let _ = increment(
                    &mut self.counters.cancelled_before_dispatch,
                    unstarted,
                    &mut self.reasons,
                );
            }
            let missing_start = self.active.values().any(|active| {
                (active.write != WriteOutcome::Pending || active.receipt.is_some())
                    && active.started.is_none()
            });
            if missing_start {
                self.reason(ReasonCode::AccountingError);
            }
            for (sequence, active) in self.active.drain() {
                if self.entries[sequence as usize].state != EntryState::Dispatched {
                    continue;
                }
                if matches!(self.context.topology, LedgerTopology::Churn { .. }) {
                    let _ = increment(&mut self.counters.login_failed, 1, &mut self.reasons);
                } else {
                    if active.write == WriteOutcome::Pending {
                        let _ = increment(&mut self.counters.write_cancelled, 1, &mut self.reasons);
                    }
                    if !active.on_time {
                        let category = if active.write == WriteOutcome::Failed || active.send_failed
                        {
                            &mut self.counters.unreceived_send_failed
                        } else if active.connection_closed {
                            &mut self.counters.unreceived_connection_closed
                        } else if reason.termination == Termination::Cancelled {
                            &mut self.counters.unreceived_cancelled
                        } else {
                            &mut self.counters.unreceived_timeout
                        };
                        let _ = increment(category, 1, &mut self.reasons);
                    }
                }
            }
        }
        if self.reconcile().is_err() {
            self.reason(ReasonCode::AccountingError);
        }
        let c = &self.counters;
        if [
            c.write_failed,
            c.unreceived_timeout,
            c.unreceived_connection_closed,
            c.unreceived_send_failed,
            c.late_receipts,
            c.duplicates,
            c.unknown_ids,
            c.wrong_recipient,
            c.unexpected_disconnects,
            c.login_failed,
            c.close_failed,
        ]
        .iter()
        .any(|&count| count > 0)
            && reason.termination != Termination::Cancelled
        {
            self.reason(ReasonCode::OperationsFailed);
        }
        MeasurementResult {
            counters: self.counters,
            latencies: self
                .histograms
                .into_iter()
                .map(|(kind, histogram)| (kind, histogram.report()))
                .collect(),
            reasons: self.reasons,
        }
    }

    fn reconcile(&mut self) -> BenchResult<()> {
        let c = &self.counters;
        let sum = |values: &[u64]| {
            values
                .iter()
                .try_fold(0u64, |sum, &value| sum.checked_add(value))
                .ok_or_else(|| invalid("counter reconciliation overflow"))
        };
        let valid = c.planned
            == sum(&[
                c.dispatched,
                c.skipped_scheduler,
                c.skipped_in_flight,
                c.skipped_writer_busy,
                c.skipped_account_busy,
                c.skipped_disconnected,
                c.cancelled_before_dispatch,
            ])?
            && c.dispatched == sum(&[c.dispatched_in_window, c.dispatched_during_drain])?
            && match self.context.topology {
                LedgerTopology::Messages { .. } => {
                    c.dispatched == sum(&[c.write_succeeded, c.write_failed, c.write_cancelled])?
                        && c.dispatched
                            == sum(&[
                                c.received_on_time,
                                c.unreceived_timeout,
                                c.unreceived_connection_closed,
                                c.unreceived_send_failed,
                                c.unreceived_cancelled,
                            ])?
                        && c.received_on_time
                            == sum(&[c.received_in_window, c.received_during_drain])?
                        && c.write_succeeded
                            == sum(&[c.write_succeeded_in_window, c.write_succeeded_during_drain])?
                }
                LedgerTopology::Churn { .. } => {
                    c.connection_attempts == c.dispatched
                        && c.connection_attempts == sum(&[c.login_succeeded, c.login_failed])?
                        && c.login_succeeded == sum(&[c.closed_cleanly, c.close_failed])?
                        && c.login_succeeded == sum(&[c.login_in_window, c.login_during_drain])?
                }
            };
        if !valid {
            return Err(self.accounting("broken phase accounting"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
