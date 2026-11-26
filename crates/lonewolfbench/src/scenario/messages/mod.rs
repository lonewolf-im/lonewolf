// SPDX-License-Identifier: Apache-2.0

use crate::{
    client::{
        MessageCommand, OperationId, ReceivedEvent, ReceivedKind, TrafficPhase, WriteCommand,
        WriterEvent,
    },
    config::ScenarioConfig,
    error::BenchResult,
    measurement::{
        DueSlots, FinishReason, Ledger, LedgerContext, LedgerTopology, MeasurementResult,
        OperationEvent, PhaseBarrier, RateSchedule, RejectedObservation, ReserveError,
        RouteIdentity, ScheduledSlot, SkipReason, Termination,
    },
    report::{ErrorCategory, PhaseName, PhaseStatus, ReasonCode},
    run::{RunContext, connections::ConnectionSet, events::RunEvent, failure, policy},
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
                    // The connection actor reports the loss as a closed connection.
                    ReceivedKind::StreamError | ReceivedKind::StreamEnd => return Ok(()),
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
    if !warmup.status().measured() || context.invalid.load(Ordering::Acquire) {
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
    let dispatch_policy = policy(&context.config);
    let schedule = RateSchedule::new(
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
        body_bytes: 0,
        wire_bytes: 0,
        errors: Default::default(),
    });
    let mut run = MessageRun {
        schedule,
        next_dispatch: Some(start),
        phase_index,
        drain_index: None,
        drain_name,
        end,
        drain_deadline: end + timeout,
        timeout,
        shutdown,
        lag_allowance: dispatch_policy.lag_allowance,
        traffic_phase: settings.phase,
        measuring,
        duration: settings.duration,
        rate: settings.rate,
        topology: settings.topology,
    };
    let termination = run.drive(context).await?;
    run.conclude(context, termination).await
}

struct InvalidLedger;

struct MessageRun {
    schedule: RateSchedule,
    next_dispatch: Option<Instant>,
    phase_index: usize,
    drain_index: Option<usize>,
    drain_name: PhaseName,
    end: Instant,
    drain_deadline: Instant,
    timeout: Duration,
    shutdown: Duration,
    lag_allowance: Duration,
    traffic_phase: TrafficPhase,
    measuring: bool,
    duration: Duration,
    rate: u32,
    topology: LedgerTopology,
}

impl MessageRun {
    async fn drive(&mut self, context: &mut RunContext) -> BenchResult<Termination> {
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
            if self.next_dispatch.is_some_and(|at| at <= now) {
                let due = self.schedule.poll_due(now);
                if self.dispatch_due(phase, &context.connections, due).is_err() {
                    break Termination::Failed;
                }
            }
            if now >= self.end && self.drain_index.is_none() {
                context.finish_phase(self.phase_index, PhaseStatus::Completed);
                self.drain_index = Some(context.start_phase_at(
                    self.drain_name,
                    self.end,
                    Some(self.drain_deadline),
                ));
            }
            let settled = context
                .message_phase
                .as_ref()
                .is_some_and(|phase| phase.ledger.is_settled());
            if now >= self.end
                && self.next_dispatch.is_none()
                && (settled || now >= self.drain_deadline)
            {
                break Termination::Completed;
            }
            let wake = self.wake(now);
            tokio::select! {
                biased;
                _ = context.interruption.changed() => {},
                event = context.events.recv() => if let Some(event) = event { context.consume(event); },
                _ = sleep_until(wake) => {},
            }
        };
        Ok(termination)
    }

    fn dispatch_due(
        &mut self,
        phase: &mut MessagePhase,
        connections: &ConnectionSet,
        due: DueSlots,
    ) -> Result<(), InvalidLedger> {
        let Self {
            schedule,
            lag_allowance,
            traffic_phase,
            next_dispatch,
            ..
        } = self;
        let (lag_allowance, traffic_phase) = (*lag_allowance, *traffic_phase);
        if phase
            .ledger
            .record_skipped(due.skipped, SkipReason::Scheduler)
            .is_err()
        {
            return Err(InvalidLedger);
        }
        for sequence in due.dispatch {
            let route = &phase.routes[sequence as usize % phase.routes.len()];
            let slot = schedule.slot(sequence);
            let operation = match phase.ledger.reserve(slot, route.identity()) {
                Ok(operation) => operation,
                Err(ReserveError::Skipped(_)) => continue,
                Err(ReserveError::Invalid(_)) => {
                    return Err(InvalidLedger);
                }
            };
            let command = WriteCommand::Message(MessageCommand {
                operation,
                scheduled_at: slot.scheduled_at,
                route_index: (sequence % phase.routes.len() as u64) as u32,
                phase: traffic_phase,
            });
            let admitted_at = Instant::now();
            if !within_dispatch_bounds(slot, admitted_at, schedule.tail_end(), lag_allowance) {
                if phase
                    .ledger
                    .rollback_reservation(operation, SkipReason::Scheduler)
                    .is_err()
                {
                    return Err(InvalidLedger);
                }
                continue;
            }
            let result = match connections.try_send(route.sender_index, command) {
                Ok(()) => phase.ledger.commit_dispatch(operation, admitted_at),
                Err(TrySendError::Full(_)) => phase
                    .ledger
                    .rollback_reservation(operation, SkipReason::WriterBusy),
                Err(TrySendError::Closed(_)) => phase
                    .ledger
                    .rollback_reservation(operation, SkipReason::Disconnected),
            };
            if result.is_err() {
                return Err(InvalidLedger);
            }
        }
        *next_dispatch = due.next_deadline;
        Ok(())
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
        termination: Termination,
    ) -> BenchResult<MeasurementResult> {
        let Self {
            phase_index,
            mut drain_index,
            drain_name,
            drain_deadline,
            timeout,
            shutdown,
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
        let barrier = if measuring || settled.is_err() {
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
        let status = if result.status().measured() {
            PhaseStatus::Completed
        } else {
            PhaseStatus::Failed
        };
        if let Some(index) = drain_index {
            context.report.phases[index].status = status;
        }
        context.report.phases[phase_index].counters = result.counters.clone();
        let rates = result.rates(duration, rate, topology);
        context.report.phases[phase_index].rates = rates.clone();
        for reason in &result.reasons {
            if measuring || !reason.code.status().measured() {
                context.reason(reason.code, phase_context(reason.code));
            }
        }
        if measuring {
            context.report.counters = result.counters.clone();
            context.report.counters.requested_connections = context.config.account_count() as u64;
            context.report.counters.established_connections =
                context.connections.established() as u64;
            context.report.rates = rates;
            context.report.latencies = result.latencies.clone();
            context.refresh_measurement();
        }
        Ok(result)
    }
}

fn phase_context(code: ReasonCode) -> &'static str {
    match code {
        ReasonCode::DriverLimited => "message_operations_skipped",
        ReasonCode::OperationsFailed => "message_operations_failed",
        ReasonCode::Interrupted => "interrupted",
        ReasonCode::EventOverflow => "event_queue_overflow",
        ReasonCode::HistogramError => "latency_out_of_range",
        ReasonCode::AccountingError => "message_accounting",
        _ => "message_phase_failed",
    }
}

#[cfg(test)]
mod tests;
