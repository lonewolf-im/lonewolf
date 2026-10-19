// SPDX-License-Identifier: Apache-2.0

use crate::{
    client::{
        MessageCommand, OperationId, ReceivedEvent, ReceivedKind, TrafficPhase, WriteCommand,
        WriterEvent,
    },
    config::ScenarioConfig,
    error::BenchResult,
    measurement::{
        FinishReason, Ledger, LedgerContext, LedgerTopology, MeasurementResult, OperationEvent,
        PhaseBarrier, RateSchedule, RejectedObservation, ReserveError, RouteIdentity,
        ScheduledSlot, SkipReason, Termination,
    },
    report::{ErrorCategory, PhaseName, PhaseStatus, RunStatus},
    run::{RunContext, events::RunEvent, failure, policy},
};
use std::{
    num::NonZeroU32,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    sync::mpsc::error::TrySendError,
    time::{Instant, sleep_until},
};

#[derive(Debug)]
pub struct PairRoute {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub sender_jid: String,
    pub receiver_jid: String,
}

impl PairRoute {
    fn identity(&self) -> RouteIdentity {
        RouteIdentity::Message {
            sender_index: self.sender_index,
            receiver_index: self.receiver_index,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptClassification {
    Matching,
    WrongRouteOrBody,
    UnknownId,
    StalePhase,
    Unrelated,
}

pub fn validate_receipt(
    event: &ReceivedEvent,
    route: &PairRoute,
    payload: &[u8],
    id: OperationId,
) -> BenchResult<ReceiptClassification> {
    let ReceivedKind::Chat {
        correlation,
        from,
        to,
        body,
        route_valid,
    } = &event.kind
    else {
        return Ok(ReceiptClassification::Unrelated);
    };
    let Some(observed) = correlation else {
        return Ok(ReceiptClassification::UnknownId);
    };
    if observed.run_nonce != id.run_nonce || observed.sequence != id.sequence {
        return Ok(ReceiptClassification::UnknownId);
    }
    if observed.phase != id.phase {
        return Ok(ReceiptClassification::StalePhase);
    }
    if !route_valid
        || from.as_deref() != Some(&route.sender_jid)
        || to.as_deref() != Some(&route.receiver_jid)
        || !body.ascii_x
        || body.bytes != payload.len()
        || !payload.iter().all(|byte| *byte == b'x')
    {
        return Ok(ReceiptClassification::WrongRouteOrBody);
    }
    Ok(ReceiptClassification::Matching)
}

pub(crate) struct MessagePhase {
    ledger: Ledger,
    routes: Arc<[PairRoute]>,
    payload: Arc<str>,
    nonce: [u8; 16],
    phase: TrafficPhase,
    fatal: bool,
    workload_failed: bool,
    body_bytes: u64,
    wire_bytes: u64,
    errors: std::collections::BTreeMap<ErrorCategory, u64>,
}

impl MessagePhase {
    fn rejected(&mut self, kind: RejectedObservation) -> BenchResult<()> {
        self.ledger.observe(OperationEvent::Rejected(kind))
    }

    pub(crate) fn observe(&mut self, event: RunEvent) -> BenchResult<()> {
        let result = self.observe_inner(event);
        if result.is_err() {
            self.fatal = true;
        }
        result
    }

    fn route_for(&self, operation: OperationId) -> Result<&PairRoute, RejectedObservation> {
        if operation.run_nonce != self.nonce {
            return Err(RejectedObservation::UnknownId);
        }
        if operation.phase != self.phase {
            return Err(RejectedObservation::StalePhase);
        }
        if operation.sequence >= self.ledger.counters().planned {
            return Err(RejectedObservation::UnknownId);
        }
        Ok(&self.routes[operation.sequence as usize % self.routes.len()])
    }

    fn observe_inner(&mut self, event: RunEvent) -> BenchResult<()> {
        match event {
            RunEvent::WriteStarted {
                index,
                operation,
                at,
            } => match self.route_for(operation) {
                Ok(route) if route.sender_index == index => {
                    self.ledger
                        .observe(OperationEvent::Writer(WriterEvent::WriteStarted {
                            operation,
                            at,
                        }))
                }
                Ok(_) => self.rejected(RejectedObservation::WrongRecipient),
                Err(kind) => self.rejected(kind),
            },
            RunEvent::WriteFinished {
                index,
                operation,
                at,
                succeeded,
                bytes,
            } => {
                match self.route_for(operation) {
                    Ok(route) if route.sender_index == index => {}
                    Ok(_) => return self.rejected(RejectedObservation::WrongRecipient),
                    Err(kind) => return self.rejected(kind),
                }
                let before = self.ledger.counters().write_succeeded;
                let result = self.ledger.observe(OperationEvent::Writer(if succeeded {
                    WriterEvent::WriteCompleted {
                        operation,
                        at,
                        bytes,
                    }
                } else {
                    WriterEvent::WriteFailed { operation, at }
                }));
                if self.ledger.counters().write_succeeded > before {
                    self.body_bytes += self.payload.len() as u64;
                    self.wire_bytes += bytes as u64;
                }
                result
            }
            RunEvent::Received { index, event } => {
                let operation = match &event.kind {
                    ReceivedKind::Chat { correlation, .. }
                    | ReceivedKind::StanzaError { correlation, .. } => *correlation,
                    ReceivedKind::StreamError | ReceivedKind::StreamEnd => {
                        self.fatal = true;
                        return Err(failure("message_stream_closed"));
                    }
                    ReceivedKind::Unexpected => {
                        return self.rejected(RejectedObservation::Unexpected);
                    }
                };
                let Some(operation) = operation else {
                    return self.rejected(RejectedObservation::UnknownId);
                };
                let route = match self.route_for(operation) {
                    Ok(route) => route,
                    Err(kind) => return self.rejected(kind),
                };
                if let ReceivedKind::StanzaError { condition, .. } = event.kind {
                    if index != route.sender_index {
                        return self.rejected(RejectedObservation::WrongRecipient);
                    }
                    self.workload_failed = true;
                    let category = match condition {
                        "resource-constraint" | "forbidden" | "not-allowed" => {
                            ErrorCategory::Policy
                        }
                        _ => ErrorCategory::Protocol,
                    };
                    *self.errors.entry(category).or_default() += 1;
                    return self.ledger.observe(OperationEvent::SendFailed {
                        operation,
                        at: event.at,
                    });
                }
                if index != route.receiver_index {
                    return self.rejected(RejectedObservation::WrongRecipient);
                }
                match validate_receipt(&event, route, self.payload.as_bytes(), operation)? {
                    ReceiptClassification::Matching => {
                        self.ledger.observe(OperationEvent::Receipt {
                            operation,
                            at: event.at,
                            route: route.identity(),
                        })
                    }
                    ReceiptClassification::WrongRouteOrBody => {
                        self.rejected(RejectedObservation::WrongRecipient)
                    }
                    ReceiptClassification::UnknownId => {
                        self.rejected(RejectedObservation::UnknownId)
                    }
                    ReceiptClassification::StalePhase => {
                        self.rejected(RejectedObservation::StalePhase)
                    }
                    ReceiptClassification::Unrelated => {
                        self.rejected(RejectedObservation::Unexpected)
                    }
                }
            }
            RunEvent::ConnectionClosed { index, at } => {
                self.workload_failed = true;
                self.ledger.observe(OperationEvent::ConnectionClosed {
                    session_index: index,
                    at,
                })
            }
            RunEvent::Invalid { .. } => {
                self.fatal = true;
                self.ledger.observe(OperationEvent::EventOverflow)
            }
        }
    }

    fn finish(self, termination: Termination, barrier: PhaseBarrier) -> MeasurementResult {
        let termination = if self.workload_failed && termination == Termination::Completed {
            Termination::Failed
        } else {
            termination
        };
        let mut result = self.ledger.finish(FinishReason {
            termination,
            barrier,
        });
        result.counters.message_body_bytes_write_succeeded = self.body_bytes;
        result.counters.serialized_stanza_bytes_write_succeeded = self.wire_bytes;
        for (category, count) in self.errors {
            *result.counters.errors.entry(category).or_default() += count;
        }
        result
    }
}

fn pair_routes(context: &RunContext, pairs: u32) -> BenchResult<Arc<[PairRoute]>> {
    let mut identities = context.connections.identities().collect::<Vec<_>>();
    identities.sort_unstable_by_key(|(index, _)| *index);
    if identities.len() != pairs as usize * 2
        || identities
            .iter()
            .enumerate()
            .any(|(index, (actual, jid))| index != *actual as usize || !jid.contains('/'))
    {
        return Err(failure("message_topology"));
    }
    Ok(identities
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| PairRoute {
            sender_index: pair[0].0,
            receiver_index: pair[1].0,
            sender_jid: pair[0].1.into(),
            receiver_jid: pair[1].1.into(),
        })
        .collect())
}

pub async fn run(context: &mut RunContext) -> BenchResult<MeasurementResult> {
    context.connected_barrier().await?;
    let ScenarioConfig::Messages {
        pairs,
        rate_per_second,
        body_bytes,
    } = context.config.scenario
    else {
        return Err(failure("message_scenario"));
    };
    if context.connections.active() != pairs as u64 * 2 {
        return Err(failure("all_connected_barrier"));
    }
    let routes = pair_routes(context, pairs as u32)?;
    let payload = context.connections.message_payload()?;
    if payload.len() != body_bytes {
        return Err(failure("message_payload_mismatch"));
    }
    let nonce = context
        .report
        .run_id
        .as_ref()
        .and_then(|id| OperationId::parse(&format!("{id}.w.0")))
        .ok_or_else(|| failure("message_nonce"))?
        .run_nonce;
    let topology = LedgerTopology::Messages {
        pairs: NonZeroU32::new(pairs as u32).ok_or_else(|| failure("message_pairs"))?,
    };
    let warmup = run_phase(
        context,
        PhaseSettings {
            routes: routes.clone(),
            payload: payload.clone(),
            nonce,
            topology,
            phase: TrafficPhase::Warmup,
            rate: rate_per_second,
            duration: Duration::from_millis(context.config.measurement.warmup_ms),
        },
    )
    .await?;
    if warmup.status() != RunStatus::Passed
        || context.invalid.load(Ordering::Acquire)
        || context.connections.active() != context.config.account_count() as u64
    {
        return Err(failure("message_warmup_failed"));
    }
    run_phase(
        context,
        PhaseSettings {
            routes,
            payload,
            nonce,
            topology,
            phase: TrafficPhase::Measurement,
            rate: rate_per_second,
            duration: Duration::from_millis(context.config.measurement.duration_ms),
        },
    )
    .await
}

struct PhaseSettings {
    routes: Arc<[PairRoute]>,
    payload: Arc<str>,
    nonce: [u8; 16],
    topology: LedgerTopology,
    phase: TrafficPhase,
    rate: u32,
    duration: Duration,
}

fn within_dispatch_bounds(
    slot: ScheduledSlot,
    at: Instant,
    tail_end: Instant,
    lag: Duration,
) -> bool {
    at >= slot.scheduled_at && at < tail_end && at.duration_since(slot.scheduled_at) <= lag
}

async fn run_phase(
    context: &mut RunContext,
    settings: PhaseSettings,
) -> BenchResult<MeasurementResult> {
    let start = Instant::now();
    let timeout = Duration::from_millis(context.config.measurement.operation_timeout_ms);
    let shutdown = Duration::from_millis(context.config.measurement.shutdown_timeout_ms);
    let dispatch_policy = policy(&context.config.measurement);
    let mut schedule = RateSchedule::new(
        start,
        settings.duration,
        NonZeroU32::new(settings.rate).ok_or_else(|| failure("message_rate"))?,
        dispatch_policy,
    )?;
    let end = schedule.end();
    let ledger = Ledger::new(
        schedule.planned(),
        context.config.measurement.max_in_flight,
        timeout,
        LedgerContext {
            run_nonce: settings.nonce,
            phase: settings.phase,
            start,
            end,
            shutdown_timeout: shutdown,
            topology: settings.topology,
        },
    )?;
    let measuring = settings.phase == TrafficPhase::Measurement;
    let name = if measuring {
        PhaseName::Measurement
    } else {
        PhaseName::Warmup
    };
    let drain_name = if measuring {
        PhaseName::MeasurementDrain
    } else {
        PhaseName::WarmupDrain
    };
    if measuring {
        context.measurement_window = Some((start, end));
    }
    let phase_index = context.start_phase_at(name, start, Some(end));
    context.message_phase = Some(MessagePhase {
        ledger,
        routes: settings.routes,
        payload: settings.payload,
        nonce: settings.nonce,
        phase: settings.phase,
        fatal: false,
        workload_failed: false,
        body_bytes: 0,
        wire_bytes: 0,
        errors: Default::default(),
    });
    let mut next_dispatch = Some(start);
    let mut drain_index = None;
    let drain_deadline = end + timeout;
    let termination = loop {
        context.consume_events();
        if *context.interruption.borrow() {
            break Termination::Cancelled;
        }
        if context.invalid.load(Ordering::Acquire) {
            if let Some(phase) = &mut context.message_phase {
                phase.observe(RunEvent::Invalid {
                    index: 0,
                    at: Instant::now(),
                })?;
            }
            break Termination::Failed;
        }
        let phase = context
            .message_phase
            .as_mut()
            .ok_or_else(|| failure("message_phase_missing"))?;
        if phase.fatal {
            break Termination::Failed;
        }
        let now = Instant::now();
        if phase.ledger.expire_through(now).is_err() {
            break Termination::Failed;
        }
        if next_dispatch.is_some_and(|at| at <= now) {
            let due = schedule.poll_due(now);
            if phase
                .ledger
                .record_skipped(due.skipped, SkipReason::Scheduler)
                .is_err()
            {
                break Termination::Failed;
            }
            if phase
                .ledger
                .record_dispatch_batch(due.dispatch.end - due.dispatch.start)
                .is_err()
            {
                break Termination::Failed;
            }
            let mut invalid = false;
            for sequence in due.dispatch {
                let route = &phase.routes[sequence as usize % phase.routes.len()];
                let slot = schedule.slot(sequence);
                let operation = match phase.ledger.reserve(slot, route.identity()) {
                    Ok(operation) => operation,
                    Err(ReserveError::Skipped(_)) => continue,
                    Err(ReserveError::Invalid(_)) => {
                        invalid = true;
                        break;
                    }
                };
                let command = WriteCommand::Message(MessageCommand {
                    operation,
                    scheduled_at: slot.scheduled_at,
                    route_index: (sequence % phase.routes.len() as u64) as u32,
                    phase: settings.phase,
                });
                let admitted_at = Instant::now();
                if !within_dispatch_bounds(
                    slot,
                    admitted_at,
                    schedule.tail_end(),
                    dispatch_policy.lag_allowance,
                ) {
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
                let result = match context.connections.try_send(route.sender_index, command) {
                    Ok(()) => phase.ledger.commit_dispatch(operation, admitted_at),
                    Err(TrySendError::Full(_)) => phase
                        .ledger
                        .rollback_reservation(operation, SkipReason::WriterBusy),
                    Err(TrySendError::Closed(_)) => phase
                        .ledger
                        .rollback_reservation(operation, SkipReason::WriterBusy),
                };
                if result.is_err() {
                    invalid = true;
                    break;
                }
            }
            if invalid {
                break Termination::Failed;
            }
            next_dispatch = due.next_deadline;
        }
        if now >= end && drain_index.is_none() {
            context.finish_phase(phase_index, PhaseStatus::Completed);
            drain_index = Some(context.start_phase_at(drain_name, end, Some(drain_deadline)));
        }
        let settled = context
            .message_phase
            .as_ref()
            .is_some_and(|phase| phase.ledger.is_settled());
        if now >= end && next_dispatch.is_none() && (settled || now >= drain_deadline) {
            break Termination::Completed;
        }
        let wake = next_dispatch.unwrap_or(drain_deadline).min(if now < end {
            end
        } else {
            drain_deadline
        });
        tokio::select! {
            biased;
            _ = context.interruption.changed() => {},
            event = context.events.recv() => if let Some(event) = event { context.consume(event); },
            _ = sleep_until(wake) => {},
        }
    };
    if drain_index.is_none() {
        context.finish_phase(phase_index, PhaseStatus::Truncated);
        drain_index = Some(context.start_phase(drain_name, Some(drain_deadline)));
    }
    let settled = if termination == Termination::Completed
        && !context.invalid.load(Ordering::Acquire)
        && context
            .message_phase
            .as_ref()
            .is_some_and(|phase| !phase.fatal)
        && !*context.interruption.borrow()
    {
        context.settle_until(Instant::now() + timeout).await
    } else {
        Err(failure("message_phase_stopped"))
    };
    let healthy = settled.is_ok()
        && termination == Termination::Completed
        && context.message_phase.as_ref().is_some_and(|phase| {
            phase.ledger.is_settled() && !phase.fatal && !phase.workload_failed
        })
        && !*context.interruption.borrow();
    if let Some(index) = drain_index {
        context.finish_phase(
            index,
            if termination == Termination::Completed {
                PhaseStatus::Completed
            } else {
                PhaseStatus::Truncated
            },
        );
    }
    let barrier = if measuring || !healthy {
        context.close_connections(Instant::now() + shutdown).await;
        PhaseBarrier::RetiredAndDrained
    } else {
        PhaseBarrier::Settled
    };
    let termination = if *context.interruption.borrow() {
        Termination::Cancelled
    } else if settled.is_err()
        || context
            .message_phase
            .as_ref()
            .is_some_and(|phase| phase.fatal)
    {
        Termination::Failed
    } else {
        termination
    };
    if context.invalid.load(Ordering::Acquire)
        && let Some(phase) = &mut context.message_phase
    {
        let _ = phase.ledger.observe(OperationEvent::EventOverflow);
    }
    let result = context
        .message_phase
        .take()
        .ok_or_else(|| failure("message_phase_missing"))?
        .finish(termination, barrier);
    let status = if result.status() == RunStatus::Passed {
        PhaseStatus::Completed
    } else {
        PhaseStatus::Failed
    };
    if let Some(index) = drain_index {
        context.report.phases[index].status = status;
    }
    context.report.phases[phase_index].counters = result.counters.clone();
    let rates = result.rates(settings.duration, settings.rate, settings.topology);
    context.report.phases[phase_index].rates = rates.clone();
    for reason in &result.reasons {
        context.reason(reason.code, "message_phase_outcome");
    }
    if measuring {
        context.report.counters = result.counters.clone();
        context.report.counters.requested_connections = context.config.account_count() as u64;
        context.report.counters.established_connections = context.connections.established() as u64;
        context.report.rates = rates;
        context.report.latencies = result.latencies.clone();
        context.refresh_measurement();
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
