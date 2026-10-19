// SPDX-License-Identifier: Apache-2.0

use super::events::RunEvent;
use super::{
    RunContext,
    events::{EventSender, RunObserver},
    failure,
};
use crate::{
    client::{
        self, ClientSession, EventSink, KeyMode, PreparedAccount, ReceivedKind, ResolvedTarget,
        SessionReader, SessionWriter, WriteCommand, WriterEvent,
    },
    error::BenchResult,
    measurement::{DispatchPolicy, RateSchedule},
};
use lonewolf_util::blocking::BlockingExecutor;
use std::{
    future::{Future, poll_fn},
    num::{NonZeroU32, NonZeroUsize},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time::{Instant, sleep_until, timeout_at},
};

pub struct ClientHandle {
    pub index: u32,
    pub commands: mpsc::Sender<WriteCommand>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShutdownSummary {
    pub clean: u64,
    pub forced: u64,
    pub failed: u64,
}

#[derive(Clone, Copy)]
enum Control {
    Observe(u64),
    Shutdown(Instant),
}

#[derive(Clone, Copy)]
struct ActorState {
    epoch: u64,
    bound_at: Instant,
    closed_at: Option<Instant>,
}

struct OwnedConnection {
    handle: Option<ClientHandle>,
    index: u32,
    jid: String,
    state: watch::Receiver<ActorState>,
    task: Option<JoinHandle<ShutdownSummary>>,
}

pub struct ConnectionSet {
    entries: Vec<OwnedConnection>,
    control: watch::Sender<Control>,
    epoch: u64,
    peak: u64,
    shutdown_summary: ShutdownSummary,
    message_payload: Option<Arc<str>>,
    active: Arc<AtomicU64>,
    observer: RunObserver,
    events: EventSender,
    invalid: Arc<AtomicBool>,
}

impl ConnectionSet {
    pub(crate) fn new(
        events: EventSender,
        invalid: Arc<AtomicBool>,
        observer: RunObserver,
    ) -> Self {
        let entries = Vec::new();
        let (control, _) = watch::channel(Control::Observe(0));
        Self {
            entries,
            control,
            epoch: 0,
            peak: 0,
            shutdown_summary: ShutdownSummary::default(),
            message_payload: None,
            active: Arc::new(AtomicU64::new(0)),
            observer,
            events,
            invalid,
        }
    }

    pub(crate) fn reserve(&mut self, count: usize) -> BenchResult<()> {
        self.entries
            .try_reserve_exact(count)
            .map_err(|_| failure("connection_allocation"))
    }

    fn admit(&mut self, index: u32, session: ClientSession) {
        let (reader, writer, identity) = session.into_parts();
        let (commands, receiver) = mpsc::channel(1);
        let (state, observed) = watch::channel(ActorState {
            epoch: self.epoch,
            bound_at: Instant::now(),
            closed_at: None,
        });
        let current = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak = self.peak.max(current);
        self.observer.active_connections(current);
        let task = tokio::spawn(
            Actor {
                index,
                reader,
                writer,
                commands: receiver,
                control: self.control.subscribe(),
                state,
                events: self.events.clone(),
                invalid: self.invalid.clone(),
                active: self.active.clone(),
                observer: self.observer.clone(),
            }
            .run(),
        );
        self.entries.push(OwnedConnection {
            handle: Some(ClientHandle { index, commands }),
            index,
            jid: identity.bound_jid,
            state: observed,
            task: Some(task),
        });
    }

    pub(crate) fn message_payload(&self) -> BenchResult<Arc<str>> {
        self.message_payload
            .clone()
            .ok_or_else(|| failure("message_payload_missing"))
    }

    pub(crate) fn identities(&self) -> impl Iterator<Item = (u32, &str)> {
        self.entries
            .iter()
            .map(|entry| (entry.index, entry.jid.as_str()))
    }

    pub(crate) fn try_send(
        &self,
        index: u32,
        command: WriteCommand,
    ) -> Result<(), mpsc::error::TrySendError<WriteCommand>> {
        match self
            .entries
            .get(index as usize)
            .filter(|entry| entry.index == index)
            .and_then(|entry| entry.handle.as_ref())
        {
            Some(handle) => handle.commands.try_send(command),
            None => Err(mpsc::error::TrySendError::Closed(command)),
        }
    }

    pub fn established(&self) -> usize {
        self.entries.len()
    }
    pub fn peak(&self) -> u64 {
        self.peak
    }
    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Acquire)
    }
    pub fn active_at(&self, at: Instant) -> u64 {
        self.entries
            .iter()
            .filter(|entry| {
                let state = entry.state.borrow();
                state.bound_at <= at && state.closed_at.is_none_or(|closed| closed > at)
            })
            .count() as u64
    }
    pub(crate) fn begin_barrier(&mut self) {
        self.epoch += 1;
        self.control.send_replace(Control::Observe(self.epoch));
    }
    pub(crate) fn settled(&self) -> bool {
        self.entries.iter().all(|entry| {
            entry.state.borrow().epoch == self.epoch
                || entry.task.as_ref().is_none_or(|task| task.is_finished())
        })
    }

    pub async fn establish(context: &mut RunContext, count: usize) -> BenchResult<()> {
        if count != context.config.account_count() {
            return Err(failure("connection_count_mismatch"));
        }
        let target = context
            .target
            .as_ref()
            .ok_or_else(|| failure("target_unavailable"))?;
        let accounts = match context.fixture.as_mut() {
            Some(fixture) => fixture.credentials(),
            None => &mut context.accounts,
        };
        let settings = &context.config.measurement;
        let outcome = establish_accounts(Establish {
            accounts,
            target,
            cpu: &context.cpu,
            connections: &mut context.connections,
            deadline: context.setup_deadline,
            concurrency: settings.connect_concurrency,
            rate: settings.ramp_rate_per_second,
            policy: super::policy(settings),
            interruption: &mut context.interruption,
            attempts: &mut context.setup_attempts,
            failures: &mut context.setup_failures,
            resource: match context.config.scenario {
                crate::config::ScenarioConfig::Messages { .. } => context
                    .report
                    .run_id
                    .as_deref()
                    .ok_or_else(|| failure("message_nonce"))?,
                _ => "bench",
            },
            scenario: &context.config.scenario,
        })
        .await;
        context
            .connections
            .entries
            .sort_unstable_by_key(|entry| entry.index);
        context.consume_events();
        context.report.target.cache_primed =
            outcome.is_ok() && context.connections.established() == count;
        outcome
    }

    pub async fn close_all(&mut self, deadline: Instant) -> ShutdownSummary {
        for entry in &mut self.entries {
            entry.handle.take();
        }
        self.control.send_replace(Control::Shutdown(deadline));
        for entry in &mut self.entries {
            if let Some(task) = &mut entry.task {
                match task.await {
                    Ok(result) => {
                        self.shutdown_summary.clean += result.clean;
                        self.shutdown_summary.forced += result.forced;
                        self.shutdown_summary.failed += result.failed;
                    }
                    Err(_) => {
                        self.shutdown_summary.failed += 1;
                        self.invalid
                            .store(true, std::sync::atomic::Ordering::Release);
                    }
                }
                entry.task.take();
            }
        }
        self.shutdown_summary
    }
}

impl Drop for ConnectionSet {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            if let Some(task) = &entry.task {
                task.abort();
            }
        }
    }
}

type Attempt<'a, T> = Pin<Box<dyn Future<Output = (u32, BenchResult<T>)> + Send + 'a>>;

struct Establish<'a> {
    accounts: &'a mut [PreparedAccount],
    target: &'a ResolvedTarget,
    cpu: &'a BlockingExecutor,
    connections: &'a mut ConnectionSet,
    deadline: Instant,
    concurrency: usize,
    rate: u32,
    policy: DispatchPolicy,
    interruption: &'a mut watch::Receiver<bool>,
    attempts: &'a mut u64,
    failures: &'a mut u64,
    resource: &'a str,
    scenario: &'a crate::config::ScenarioConfig,
}

async fn establish_accounts(setup: Establish<'_>) -> BenchResult<()> {
    let Establish {
        accounts,
        target,
        cpu,
        connections,
        deadline,
        concurrency,
        rate,
        policy,
        interruption,
        attempts,
        failures,
        resource,
        scenario,
    } = setup;
    let count = accounts.len();
    let invalid = connections.invalid.clone();
    let messages = match scenario {
        crate::config::ScenarioConfig::Messages { body_bytes, .. } => {
            let routes: Arc<[client::MessageRoute]> = accounts
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| client::MessageRoute {
                    to: format!("{}/{resource}", pair[1].bare_jid()),
                })
                .collect();
            let senders: Arc<[String]> = accounts
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| format!("{}/{resource}", pair[0].bare_jid()))
                .collect();
            let setup = Arc::new(client::MessageSetup::new(
                routes,
                Arc::<str>::from("x".repeat(*body_bytes)),
            )?);
            connections.message_payload = Some(setup.payload());
            Some((setup, senders, *body_bytes))
        }
        _ => None,
    };
    let mut accounts = accounts.iter_mut().enumerate();
    ramp(
        Ramp {
            count,
            deadline,
            concurrency,
            rate,
            policy,
            interruption,
            attempts,
            failures,
            invalid: &invalid,
        },
        || {
            let (index, account) = accounts.next()?;
            let messages = messages.clone();
            Some(Box::pin(async move {
                let result =
                    client::connect(target, account, resource, KeyMode::Prime, deadline, cpu)
                        .await
                        .and_then(|(mut session, _)| {
                            if let Some((setup, senders, body_bytes)) = messages {
                                if index % 2 == 1 {
                                    session.set_receive_route(client::ReceiveRoute {
                                        from: senders[index / 2].clone(),
                                        body_bytes,
                                    })?;
                                } else {
                                    session.configure_messages(&setup)?;
                                }
                            }
                            Ok(session)
                        });
                (index as u32, result)
            }))
        },
        |index, session| connections.admit(index, session),
    )
    .await
}

struct Ramp<'a> {
    count: usize,
    deadline: Instant,
    concurrency: usize,
    rate: u32,
    policy: DispatchPolicy,
    interruption: &'a mut watch::Receiver<bool>,
    attempts: &'a mut u64,
    failures: &'a mut u64,
    invalid: &'a AtomicBool,
}

async fn ramp<'a, T>(
    settings: Ramp<'_>,
    mut launch: impl FnMut() -> Option<Attempt<'a, T>>,
    mut admit: impl FnMut(u32, T),
) -> BenchResult<()> {
    let Ramp {
        count,
        deadline,
        concurrency,
        rate,
        policy,
        interruption,
        attempts,
        failures,
        invalid,
    } = settings;
    let rate = NonZeroU32::new(rate).ok_or_else(|| failure("ramp_rate"))?;
    let duration =
        Duration::from_nanos(((count as u64 - 1) * 1_000_000_000 / u64::from(rate.get())) + 1);
    let schedule = RateSchedule::new(Instant::now(), duration, rate, policy)?;
    let mut pending: Vec<Option<Attempt<'_, T>>> = Vec::new();
    pending
        .try_reserve_exact(concurrency.min(count))
        .map_err(|_| failure("handshake_allocation"))?;
    pending.resize_with(concurrency.min(count), || None);
    let mut next = 0_u64;
    let mut running = 0;
    let start = schedule.slot(0).scheduled_at;
    let mut next_tick = start + policy.quantum;
    let mut batch = 0;
    loop {
        if *interruption.borrow() {
            return Err(failure("interrupted"));
        }
        if Instant::now() >= deadline {
            return Err(failure("setup_deadline"));
        }
        if invalid.load(std::sync::atomic::Ordering::Acquire) {
            return Err(failure("event_queue_overflow"));
        }
        if next == count as u64 && running == 0 {
            return Ok(());
        }
        let now = Instant::now();
        if now >= next_tick {
            let tick = now.duration_since(start).as_nanos() / policy.quantum.as_nanos() + 1;
            next_tick = start + Duration::from_nanos((tick * policy.quantum.as_nanos()) as u64);
            batch = 0;
        }
        let slot = (next < count as u64).then(|| schedule.slot(next).scheduled_at);
        if let Some(at) = slot {
            if Instant::now().saturating_duration_since(at) > policy.lag_allowance {
                return Err(failure("ramp_scheduler_miss"));
            }
            if Instant::now() >= at && running < pending.len() && batch < policy.max_batch {
                let attempt = launch().ok_or_else(|| failure("account_count_mismatch"))?;
                let place = pending
                    .iter_mut()
                    .find(|entry| entry.is_none())
                    .ok_or_else(|| failure("handshake_capacity"))?;
                *place = Some(attempt);
                *attempts += 1;
                running += 1;
                next += 1;
                batch += 1;
                continue;
            }
        }
        let wake = match slot {
            Some(at) if running == pending.len() => {
                (at + policy.lag_allowance + Duration::from_nanos(1)).min(deadline)
            }
            Some(_) if batch == policy.max_batch => next_tick.min(deadline),
            Some(at) => at.min(deadline),
            None => deadline,
        };
        tokio::select! {
            biased;
            _ = interruption.changed() => return Err(failure("interrupted")),
            completed = poll_fn(|cx| {
                for (position, entry) in pending.iter_mut().enumerate() {
                    if let Some(attempt) = entry && let Poll::Ready(result) = attempt.as_mut().poll(cx) {
                        return Poll::Ready((position, result));
                    }
                }
                Poll::Pending
            }), if running > 0 => {
                let (position, (index, result)) = completed;
                pending[position] = None;
                running -= 1;
                match result {
                    Ok(session) => admit(index, session),
                    Err(error) => { *failures += 1; return Err(error); }
                }
            }
            _ = sleep_until(wake) => {}
        }
    }
}

struct Actor {
    index: u32,
    reader: SessionReader,
    writer: SessionWriter,
    commands: mpsc::Receiver<WriteCommand>,
    control: watch::Receiver<Control>,
    state: watch::Sender<ActorState>,
    events: EventSender,
    invalid: Arc<AtomicBool>,
    active: Arc<AtomicU64>,
    observer: RunObserver,
}

impl Actor {
    async fn run(self) -> ShutdownSummary {
        let Self {
            index,
            mut reader,
            mut writer,
            mut commands,
            mut control,
            state,
            events,
            invalid,
            active,
            observer,
        } = self;
        let (writes, mut written) =
            EventSink::bounded(const { NonZeroUsize::new(2).unwrap() }, invalid.clone());
        let mut spontaneous = None;
        let deadline = loop {
            mirror_reader_invalid(&reader, index, &events, &invalid);
            let current = *control.borrow_and_update();
            match current {
                Control::Shutdown(deadline) => break Some(deadline),
                Control::Observe(epoch) => {
                    if state.borrow().epoch != epoch {
                        for _ in 0..256 {
                            let queued = poll_fn(|cx| {
                                let mut next = std::pin::pin!(reader.next());
                                Poll::Ready(match next.as_mut().poll(cx) {
                                    Poll::Ready(result) => Some(result),
                                    Poll::Pending => None,
                                })
                            })
                            .await;
                            let Some(result) = queued else {
                                break;
                            };
                            if let Some(at) = receive(index, result, &events) {
                                spontaneous = Some(at);
                                break;
                            }
                        }
                        mirror_reader_invalid(&reader, index, &events, &invalid);
                        state.send_modify(|state| state.epoch = epoch);
                        if spontaneous.is_some() {
                            break None;
                        }
                    }
                }
            }
            if invalid.load(std::sync::atomic::Ordering::Acquire) {
                break None;
            }
            tokio::select! {
                biased;
                changed = control.changed() => { if changed.is_err() { break None; } }
                received = reader.next() => { if let Some(at) = receive(index, received, &events) { spontaneous = Some(at); break None; } }
                command = commands.recv(), if !commands.is_closed() => {
                    if let Some(command) = command {
                        let result = send_until_shutdown(writer.send(&command, &writes), &mut control).await;
                        while let Ok(event) = written.try_recv() {
                            events.emit(match event {
                                WriterEvent::WriteStarted { operation, at } => RunEvent::WriteStarted { index, operation, at },
                                WriterEvent::WriteCompleted { operation, at, bytes } => RunEvent::WriteFinished { index, operation, at, succeeded: true, bytes },
                                WriterEvent::WriteFailed { operation, at } => RunEvent::WriteFinished { index, operation, at, succeeded: false, bytes: 0 },
                            });
                        }
                        if result.is_err() {
                            let at = Instant::now();
                            events.emit(RunEvent::ConnectionClosed { index, at });
                            spontaneous = Some(at);
                            break None;
                        }
                    }
                }
            }
        };
        mirror_reader_invalid(&reader, index, &events, &invalid);
        if let Some(at) = spontaneous {
            state.send_modify(|state| state.closed_at = Some(at));
            observer.active_connections(active.fetch_sub(1, Ordering::AcqRel) - 1);
        }
        let mut received = |event: client::ReceivedEvent| {
            if !matches!(event.kind, ReceivedKind::StreamEnd) {
                events.emit(RunEvent::Received { index, event });
            }
            Ok(())
        };
        let graceful = if let Some(deadline) = deadline {
            timeout_at(
                deadline,
                client::shutdown(
                    &mut reader,
                    &mut writer,
                    deadline.saturating_duration_since(Instant::now()),
                    &mut received,
                ),
            )
            .await
            .unwrap_or_else(|_| Err(failure("close_deadline")))
        } else {
            Err(failure("connection_retired"))
        };
        writer.retire();
        let drained = retire_reader(&mut reader, index, &events, &invalid, &mut received).await;
        if state.borrow().closed_at.is_none() {
            observer.active_connections(active.fetch_sub(1, Ordering::AcqRel) - 1);
        }
        state.send_modify(|state| {
            if state.closed_at.is_none() {
                state.closed_at = Some(Instant::now());
            }
        });
        if graceful.is_ok() && drained.is_ok() {
            ShutdownSummary {
                clean: 1,
                ..ShutdownSummary::default()
            }
        } else {
            ShutdownSummary {
                failed: 1,
                forced: u64::from(
                    graceful
                        .as_ref()
                        .is_err_and(|error| error.context() == "close_deadline"),
                ),
                clean: 0,
            }
        }
    }
}

async fn send_until_shutdown(
    sending: impl Future<Output = BenchResult<()>>,
    control: &mut watch::Receiver<Control>,
) -> BenchResult<()> {
    tokio::pin!(sending);
    loop {
        tokio::select! {
            biased;
            changed = control.changed() => {
                if changed.is_err() || matches!(*control.borrow(), Control::Shutdown(_)) {
                    return Err(failure("write_cancelled"));
                }
            }
            result = &mut sending => return result,
        }
    }
}

fn mirror_reader_invalid(
    reader: &SessionReader,
    index: u32,
    events: &EventSender,
    invalid: &AtomicBool,
) {
    if reader.run_invalid() {
        invalid.store(true, Ordering::Release);
        events.emit(RunEvent::Invalid {
            index,
            at: Instant::now(),
        });
    }
}

async fn retire_reader(
    reader: &mut SessionReader,
    index: u32,
    events: &EventSender,
    invalid: &AtomicBool,
    received: &mut impl FnMut(client::ReceivedEvent) -> BenchResult<()>,
) -> BenchResult<()> {
    let result = reader.retire_and_drain(received).await;
    mirror_reader_invalid(reader, index, events, invalid);
    result
}

fn receive(
    index: u32,
    result: BenchResult<client::ReceivedEvent>,
    events: &EventSender,
) -> Option<Instant> {
    match result {
        Ok(event) if matches!(event.kind, ReceivedKind::StreamError) => {
            let at = event.at;
            events.emit(RunEvent::Received { index, event });
            events.emit(RunEvent::ConnectionClosed { index, at });
            Some(at)
        }
        Err(error) if error.context() == "xml_protocol" => {
            let at = Instant::now();
            events.emit(RunEvent::Received {
                index,
                event: client::ReceivedEvent {
                    at,
                    kind: ReceivedKind::StreamError,
                },
            });
            events.emit(RunEvent::ConnectionClosed { index, at });
            Some(at)
        }
        Ok(event)
            if !matches!(
                event.kind,
                ReceivedKind::StreamEnd | ReceivedKind::StreamError
            ) =>
        {
            events.emit(RunEvent::Received { index, event });
            None
        }
        result => {
            let at = result
                .as_ref()
                .map_or_else(|_| Instant::now(), |event| event.at);
            events.emit(RunEvent::ConnectionClosed { index, at });
            Some(at)
        }
    }
}

#[cfg(test)]
impl ConnectionSet {
    pub(crate) fn simulated(&mut self, close_after: Option<Duration>, shutdown_delay: Duration) {
        self.simulate(close_after, shutdown_delay, None);
    }

    pub(crate) fn simulated_messages(&mut self) {
        self.simulate(None, Duration::ZERO, Some(false));
    }

    pub(crate) fn simulated_lagged_messages(&mut self) {
        self.simulate(None, Duration::ZERO, Some(true));
    }

    fn simulate(
        &mut self,
        close_after: Option<Duration>,
        shutdown_delay: Duration,
        messages: Option<bool>,
    ) {
        let index = self.entries.len() as u32;
        if messages.is_some() {
            self.message_payload = Some(Arc::from("xxx"));
        }
        let (commands, mut pending) = mpsc::channel(1);
        let (state, observed) = watch::channel(ActorState {
            epoch: self.epoch,
            bound_at: Instant::now(),
            closed_at: None,
        });
        let mut control = self.control.subscribe();
        let events = self.events.clone();
        let active = self.active.clone();
        let observer = self.observer.clone();
        let current = active.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak = self.peak.max(current);
        self.observer.active_connections(current);
        let closed = close_after.map(|delay| Instant::now() + delay);
        let task = tokio::spawn(async move {
            let mut disconnected = false;
            let mut retained = Vec::new();
            loop {
                let current = *control.borrow_and_update();
                match current {
                    Control::Observe(epoch) => {
                        state.send_modify(|state| state.epoch = epoch);
                    }
                    Control::Shutdown(deadline) => {
                        for event in retained.drain(..) {
                            events.emit(event);
                        }
                        let graceful = timeout_at(deadline, tokio::time::sleep(shutdown_delay))
                            .await
                            .is_ok();
                        if !disconnected {
                            observer.active_connections(active.fetch_sub(1, Ordering::AcqRel) - 1);
                        }
                        state.send_modify(|state| {
                            if state.closed_at.is_none() {
                                state.closed_at = Some(Instant::now());
                            }
                        });
                        return if graceful && !disconnected {
                            ShutdownSummary {
                                clean: 1,
                                forced: 0,
                                failed: 0,
                            }
                        } else {
                            ShutdownSummary {
                                clean: 0,
                                forced: u64::from(!graceful),
                                failed: 1,
                            }
                        };
                    }
                }
                tokio::select! {
                    _ = control.changed() => {},
                    command = pending.recv(), if messages.is_some() && !pending.is_closed() => {
                        if let Some(WriteCommand::Message(command)) = command {
                            let at = Instant::now();
                            events.emit(RunEvent::WriteStarted { index, operation: command.operation, at });
                            let receipt = RunEvent::Received { index: index + 1, event: client::ReceivedEvent {
                                at,
                                kind: ReceivedKind::Chat { correlation: Some(command.operation), from: Some(format!("test{index}@localhost/bench")), to: Some(format!("test{}@localhost/bench", index + 1)), body: client::BodyValidation { bytes: 3, ascii_x: true }, route_valid: true },
                            } };
                            if messages == Some(true) { retained.push(receipt); } else { events.emit(receipt); }
                            events.emit(RunEvent::WriteFinished { index, operation: command.operation, at, succeeded: true, bytes: 120 });
                        }
                    },
                    _ = async { if let Some(at) = closed { sleep_until(at).await; } else { std::future::pending::<()>().await; } }, if !disconnected => {
                        disconnected = true;
                        observer.active_connections(active.fetch_sub(1, Ordering::AcqRel) - 1);
                        let at = Instant::now();
                        state.send_modify(|state| state.closed_at = Some(at));
                        events.emit(RunEvent::ConnectionClosed { index, at });
                    }
                }
            }
        });
        self.entries.push(OwnedConnection {
            handle: Some(ClientHandle { index, commands }),
            index,
            jid: format!("test{index}@localhost/bench"),
            state: observed,
            task: Some(task),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::sleep;

    #[tokio::test(start_paused = true)]
    async fn observation_preserves_the_pending_write_and_shutdown_cancels_it() -> BenchResult<()> {
        let (control, mut observed) = watch::channel(Control::Observe(0));
        let (release, completed) = tokio::sync::oneshot::channel();
        let sending = async { completed.await.map_err(|_| failure("write_test")) };
        let future = send_until_shutdown(sending, &mut observed);
        tokio::pin!(future);
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut future)
                .await
                .is_err()
        );
        control.send_replace(Control::Observe(1));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut future)
                .await
                .is_err()
        );
        release
            .send(())
            .map_err(|_| failure("write_cancelled_by_observation"))?;
        future.await?;
        let mut observed = control.subscribe();
        let future = send_until_shutdown(std::future::pending(), &mut observed);
        tokio::pin!(future);
        control.send_replace(Control::Shutdown(Instant::now()));
        assert!(
            future
                .await
                .is_err_and(|error| error.context() == "write_cancelled")
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn absolute_ramp_is_bounded_and_waits_for_all_bind_results() -> BenchResult<()> {
        let (_signal, mut interruption) = watch::channel(false);
        let invalid = AtomicBool::new(false);
        let mut attempts = 0;
        let mut failures = 0;
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        let mut admitted = Vec::new();
        let mut index = 0;
        ramp(
            Ramp {
                count: 3,
                deadline: start + Duration::from_secs(5),
                concurrency: 2,
                rate: 10,
                policy: DispatchPolicy::default(),
                interruption: &mut interruption,
                attempts: &mut attempts,
                failures: &mut failures,
                invalid: &invalid,
            },
            || {
                let current_index = index;
                index += 1;
                let active = active.clone();
                let peak = peak.clone();
                Some(Box::pin(async move {
                    let now = Instant::now();
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    sleep(Duration::from_millis(150)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    (current_index, Ok(now))
                }))
            },
            |_, at| admitted.push(at),
        )
        .await?;
        assert_eq!((attempts, failures, admitted.len()), (3, 0, 3));
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert!(admitted[0] >= start);
        assert!(admitted[1] >= start + Duration::from_millis(100));
        assert!(admitted[2] >= start + Duration::from_millis(200));
        assert!(Instant::now() >= start + Duration::from_millis(350));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn interrupted_ramp_never_marks_unstarted_accounts_as_scheduler_misses() {
        let (_signal, mut interruption) = watch::channel(true);
        let invalid = AtomicBool::new(false);
        let (mut attempts, mut failures) = (0, 0);
        let result = ramp::<()>(
            Ramp {
                count: 10,
                deadline: Instant::now() + Duration::from_secs(1),
                concurrency: 2,
                rate: 10,
                policy: DispatchPolicy::default(),
                interruption: &mut interruption,
                attempts: &mut attempts,
                failures: &mut failures,
                invalid: &invalid,
            },
            || panic!("cancelled ramp dispatched"),
            |_, ()| {},
        )
        .await;
        assert!(result.is_err_and(|error| error.context() == "interrupted"));
        assert_eq!((attempts, failures), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn ramp_failure_keeps_partial_success_and_drops_pending_attempts() {
        let (_signal, mut interruption) = watch::channel(false);
        let invalid = AtomicBool::new(false);
        let (mut attempts, mut failures) = (0, 0);
        let mut next = 0;
        let mut admitted = Vec::new();
        let result = ramp(
            Ramp {
                count: 4,
                deadline: Instant::now() + Duration::from_secs(5),
                concurrency: 2,
                rate: 10,
                policy: DispatchPolicy::default(),
                interruption: &mut interruption,
                attempts: &mut attempts,
                failures: &mut failures,
                invalid: &invalid,
            },
            || {
                let index = next;
                next += 1;
                Some(Box::pin(async move {
                    (
                        index,
                        if index == 1 {
                            Err(failure("login_failed"))
                        } else {
                            Ok(())
                        },
                    )
                }))
            },
            |index, ()| admitted.push(index),
        )
        .await;
        assert!(result.is_err_and(|error| error.context() == "login_failed"));
        assert_eq!((attempts, failures), (2, 1));
        assert_eq!(admitted, vec![0]);
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_uses_one_aggregate_deadline_for_all_owned_actors() -> BenchResult<()> {
        let invalid = Arc::new(AtomicBool::new(false));
        let (events, _receiver) = EventSender::new(256, invalid.clone());
        let mut set = ConnectionSet::new(events, invalid, RunObserver::default());
        set.reserve(100)?;
        for _ in 0..100 {
            set.simulated(None, Duration::from_secs(30));
        }
        let start = Instant::now();
        let summary = set.close_all(start + Duration::from_millis(10)).await;
        assert_eq!(
            summary,
            ShutdownSummary {
                clean: 0,
                failed: 100,
                forced: 100
            }
        );
        assert!(Instant::now() - start < Duration::from_millis(20));
        assert!(
            set.entries
                .iter()
                .all(|entry| entry.task.is_none() && entry.handle.is_none())
        );
        assert_eq!(set.close_all(Instant::now()).await, summary);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn saturated_ramp_exposes_schedule_failure_without_reducing_the_cohort() {
        let (_signal, mut interruption) = watch::channel(false);
        let invalid = AtomicBool::new(false);
        let (mut attempts, mut failures) = (0, 0);
        let start = Instant::now();
        let result = ramp(
            Ramp {
                count: 2,
                deadline: start + Duration::from_secs(5),
                concurrency: 1,
                rate: 1000,
                policy: DispatchPolicy::default(),
                interruption: &mut interruption,
                attempts: &mut attempts,
                failures: &mut failures,
                invalid: &invalid,
            },
            || {
                Some(Box::pin(async {
                    sleep(Duration::from_secs(1)).await;
                    (0, Ok(()))
                }))
            },
            |_, ()| panic!("ramp bound succeeded after schedule failure"),
        )
        .await;
        assert!(result.is_err_and(|error| error.context() == "ramp_scheduler_miss"));
        assert_eq!((attempts, failures), (1, 0));
        assert!(Instant::now() - start < Duration::from_millis(200));
    }

    #[tokio::test(start_paused = true)]
    async fn resumed_cleanup_retains_completed_summaries_and_pending_owners() {
        let invalid = Arc::new(AtomicBool::new(false));
        let (events, _receiver) = EventSender::new(256, invalid.clone());
        let mut set = ConnectionSet::new(events, invalid, RunObserver::default());
        set.simulated(None, Duration::ZERO);
        set.simulated(None, Duration::from_millis(50));
        let deadline = Instant::now() + Duration::from_millis(100);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), set.close_all(deadline))
                .await
                .is_err()
        );
        assert!(set.entries[0].task.is_none());
        assert!(set.entries[1].task.is_some());
        assert_eq!(
            set.close_all(deadline).await,
            ShutdownSummary {
                clean: 2,
                forced: 0,
                failed: 0
            }
        );
        assert!(set.entries.iter().all(|entry| entry.task.is_none()));
    }

    #[tokio::test]
    async fn reader_overflow_during_close_is_sticky_after_join_and_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::AsyncWriteExt;
        let (input, mut peer) = tokio::io::duplex(4096);
        let mut reader = SessionReader::test_stream(input, NonZeroUsize::MIN);
        let invalid = Arc::new(AtomicBool::new(false));
        let (events, mut receiver) = EventSender::new(64, invalid.clone());
        mirror_reader_invalid(&reader, 0, &events, &invalid);
        assert!(!invalid.load(Ordering::Acquire));
        let mut blocked_footer = Box::pin(std::future::pending::<()>());
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(blocked_footer.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        peer.write_all(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><presence/>").await?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !reader.run_invalid() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        drop(blocked_footer);
        let mut drained = 0;
        let result = retire_reader(&mut reader, 0, &events, &invalid, &mut |_| {
            drained += 1;
            Ok(())
        })
        .await;
        assert!(result.is_err());
        assert_eq!(drained, 1);
        assert!(invalid.load(Ordering::Acquire));
        let event = receiver.try_recv()?;
        assert!(matches!(event, RunEvent::Invalid { index: 0, .. }));
        let (mut context, _signal) = crate::run::tests::context(1)?;
        context.retain_error(failure("close_failed"));
        context.consume(event);
        assert_eq!(context.report.status, crate::report::RunStatus::Invalid);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn final_snapshots_reconcile_close_events_forwarded_after_their_timestamp()
    -> BenchResult<()> {
        let (mut context, _signal) = crate::run::tests::context(1)?;
        let bound = Instant::now();
        let (state, observed) = watch::channel(ActorState {
            epoch: 0,
            bound_at: bound,
            closed_at: None,
        });
        context.connections.entries.push(OwnedConnection {
            handle: None,
            index: 0,
            jid: "test@localhost/bench".into(),
            state: observed,
            task: None,
        });
        tokio::time::advance(Duration::from_millis(10)).await;
        let start = Instant::now();
        let end = start + Duration::from_millis(40);
        context.measurement_window = Some((start, end));
        let phase = context.start_phase_at(crate::report::PhaseName::Measurement, start, Some(end));
        context.report.counters.connections_at_measurement_start = 1;
        context.report.counters.peak_connections = 1;
        tokio::time::advance(Duration::from_millis(40)).await;
        context.finish_phase(phase, crate::report::PhaseStatus::Completed);
        state.send_modify(|state| state.closed_at = Some(bound + Duration::from_millis(5)));
        context.refresh_measurement();
        assert_eq!(context.report.counters.connections_at_measurement_start, 0);
        assert_eq!(context.report.counters.connections_at_measurement_end, 0);
        assert_eq!(context.report.counters.peak_connections, 0);
        assert_eq!(
            context.report.phases[phase].counters,
            context.report.counters
        );
        Ok(())
    }
}
