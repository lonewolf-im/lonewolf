// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::{Either, LocalBoxFuture, Shared, select};

use super::metrics::{Direction, StreamClose};
use super::revocation::{FetchSignal, RevocationSource, RevocationVerdict};

pub(super) struct LinkValidity {
    state: Rc<State>,
}

struct State {
    valid_until: Cell<SystemTime>,
    deadline_reason: Cell<StreamClose>,
    invalidated: Cell<Option<StreamClose>>,
    invalidation_reported: Cell<bool>,
    signal: Shared<LocalBoxFuture<'static, StreamClose>>,
}

impl LinkValidity {
    pub(super) fn fixed(valid_until: SystemTime) -> Self {
        Self {
            state: Rc::new(State {
                valid_until: Cell::new(valid_until),
                deadline_reason: Cell::new(StreamClose::CertificateExpired),
                invalidated: Cell::new(None),
                invalidation_reported: Cell::new(false),
                signal: async move {
                    super::expiry::wait(valid_until).await;
                    StreamClose::CertificateExpired
                }
                .boxed_local()
                .shared(),
            }),
        }
    }

    pub(super) fn monitored(
        valid_until: SystemTime,
        verdict: RevocationVerdict,
        recheck_interval: Duration,
        revalidate: Revalidate,
    ) -> (Self, ValidityMonitor) {
        let (deadline, reason) = effective_deadline(valid_until, &verdict);
        let (sender, receiver) = oneshot::channel();
        let state = Rc::new(State {
            valid_until: Cell::new(deadline),
            deadline_reason: Cell::new(reason),
            invalidated: Cell::new(None),
            invalidation_reported: Cell::new(false),
            signal: receiver
                .map(|result| result.unwrap_or(StreamClose::CertificateExpired))
                .boxed_local()
                .shared(),
        });
        let monitor = ValidityMonitor {
            state: Rc::clone(&state),
            sender: Some(sender),
            verdict,
            certificate_until: valid_until,
            interval: recheck_interval,
            revalidate,
        };
        (Self { state }, monitor)
    }

    pub(super) fn invalidated(&self) -> Shared<LocalBoxFuture<'static, StreamClose>> {
        self.state.signal.clone()
    }

    pub(super) async fn wait(&self) -> StreamClose {
        self.wait_with(SystemTime::now).await
    }

    async fn wait_with(&self, now: impl FnOnce() -> SystemTime) -> StreamClose {
        let observed = match self.check(now()) {
            Err(reason) => reason,
            Ok(()) => self.invalidated().await,
        };
        self.state.record(observed)
    }

    pub(super) fn record_invalidation(&self, observed: StreamClose) -> StreamClose {
        self.state.record(observed)
    }

    pub(super) fn reason(&self) -> Option<StreamClose> {
        self.state.reason()
    }

    pub(super) fn check(&self, now: SystemTime) -> Result<(), StreamClose> {
        self.state.check(now)
    }
}

impl State {
    fn reason(&self) -> Option<StreamClose> {
        self.invalidated
            .get()
            .or_else(|| self.signal.peek().copied())
    }

    fn check(&self, now: SystemTime) -> Result<(), StreamClose> {
        if let Some(reason) = self.reason() {
            Err(reason)
        } else if now >= self.valid_until.get() {
            Err(self.deadline_reason.get())
        } else {
            Ok(())
        }
    }

    fn report(&self, log: &MonitorLog<'_>) {
        let Some(reason) = self.invalidated.get() else {
            return;
        };
        if matches!(
            reason,
            StreamClose::CertificateRevoked
                | StreamClose::RevocationUnknown
                | StreamClose::RevocationStale
                | StreamClose::RevocationUnavailable
        ) && !self.invalidation_reported.replace(true)
        {
            tracing::warn!(connection_id = log.connection_id, local_domain = %super::log_domain(log.local), remote_domain = %super::log_domain(log.remote), direction = log.direction.as_str(), outcome = reason.as_str(), "s2s link certificate invalidated");
        }
    }

    fn record(&self, observed: StreamClose) -> StreamClose {
        let reason = self.invalidated.get().unwrap_or(observed);
        self.invalidated.set(Some(reason));
        reason
    }
}

pub(super) type Revalidate = Box<dyn Fn() -> LocalBoxFuture<'static, Option<RevocationVerdict>>>;

#[derive(Clone, Copy)]
pub(super) struct MonitorLog<'a> {
    pub(super) direction: Direction,
    pub(super) connection_id: u64,
    pub(super) local: &'a str,
    pub(super) remote: &'a str,
}

pub(super) struct ValidityMonitor {
    state: Rc<State>,
    sender: Option<oneshot::Sender<StreamClose>>,
    verdict: RevocationVerdict,
    certificate_until: SystemTime,
    interval: Duration,
    revalidate: Revalidate,
}

impl Drop for ValidityMonitor {
    fn drop(&mut self) {
        if let Some(reason) = self.state.invalidated.get()
            && let Some(sender) = self.sender.take()
        {
            let _ = sender.send(reason);
        }
    }
}

struct MonitorReport<'a> {
    state: Rc<State>,
    log: MonitorLog<'a>,
}

impl Drop for MonitorReport<'_> {
    fn drop(&mut self) {
        self.state.report(&self.log);
    }
}

fn effective_deadline(
    certificate_until: SystemTime,
    verdict: &RevocationVerdict,
) -> (SystemTime, StreamClose) {
    if verdict.source == RevocationSource::File
        && let Some(next_update) = verdict.next_update
        && next_update < certificate_until
    {
        return (next_update, StreamClose::RevocationStale);
    }
    (certificate_until, StreamClose::CertificateExpired)
}

async fn pending_download(signals: &[FetchSignal]) {
    let mut waiters = signals.to_vec();
    poll_fn(|cx| {
        for signal in &mut waiters {
            if signal.poll_unpin(cx).is_ready() {
                return std::task::Poll::Ready(());
            }
        }
        std::task::Poll::Pending
    })
    .await;
}

impl ValidityMonitor {
    pub(super) async fn run(self, log: MonitorLog<'_>, timeout: Duration) {
        self.run_with(log, timeout, SystemTime::now, compio::time::sleep)
            .await;
    }

    async fn run_with<N, S, F>(mut self, log: MonitorLog<'_>, timeout: Duration, now: N, sleep: S)
    where
        N: Fn() -> SystemTime,
        S: Fn(Duration) -> F,
        F: Future<Output = ()>,
    {
        let periodic = now() + self.interval;
        let mut recheck_at = self
            .verdict
            .refresh_at
            .map_or(periodic, |at| at.min(periodic));
        loop {
            {
                let deadline = super::expiry::wait_with(self.state.valid_until.get(), &now, &sleep);
                let scheduled = super::expiry::wait_with(recheck_at, &now, &sleep);
                let pending = pending_download(&self.verdict.pending);
                let _ = select(pin!(deadline), pin!(select(pin!(scheduled), pin!(pending)))).await;
            }
            let attempt_started = now();
            if let Err(reason) = self.state.check(attempt_started) {
                return self.invalidate(&log, reason).await;
            }
            self.verdict
                .pending
                .retain(|signal| signal.clone().now_or_never().is_none());
            let result = {
                let deadline = super::expiry::wait_with(self.state.valid_until.get(), &now, &sleep);
                let timeout = sleep(timeout);
                let revalidate = (self.revalidate)();
                match select(
                    pin!(deadline),
                    pin!(select(pin!(timeout), pin!(revalidate))),
                )
                .await
                {
                    Either::Left(_) => Err(self.state.deadline_reason.get()),
                    Either::Right((Either::Left(_), _)) => Ok(Err(())),
                    Either::Right((Either::Right((result, _)), _)) => Ok(Ok(result)),
                }
            };
            let completed_at = now();
            if let Err(reason) = self.state.check(completed_at) {
                return self.invalidate(&log, reason).await;
            }
            match result {
                Err(reason) => return self.invalidate(&log, reason).await,
                Ok(Err(())) if self.verdict.source == RevocationSource::File => {
                    return self
                        .invalidate(&log, StreamClose::RevocationUnavailable)
                        .await;
                }
                Ok(Ok(Some(verdict))) => {
                    if let Some(reason) = verdict.close_reason() {
                        return self.invalidate(&log, reason).await;
                    }
                    self.verdict = verdict;
                    let (deadline, reason) =
                        effective_deadline(self.certificate_until, &self.verdict);
                    self.state.valid_until.set(deadline);
                    self.state.deadline_reason.set(reason);
                    if let Err(reason) = self.state.check(completed_at) {
                        return self.invalidate(&log, reason).await;
                    }
                    let periodic = completed_at + self.interval;
                    recheck_at = self
                        .verdict
                        .refresh_at
                        .filter(|at| *at > attempt_started)
                        .map_or(periodic, |at| at.min(periodic));
                    tracing::debug!(connection_id = log.connection_id, local_domain = %super::log_domain(log.local), remote_domain = %super::log_domain(log.remote), direction = log.direction.as_str(), outcome = self.verdict.status.as_str(), "s2s link certificate rechecked");
                }
                Ok(Err(())) | Ok(Ok(None)) => recheck_at = completed_at + self.interval,
            }
        }
    }

    async fn invalidate(mut self, log: &MonitorLog<'_>, observed: StreamClose) {
        let reason = self.state.record(observed);
        self.state.report(log);
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(reason);
        }
        std::future::pending::<()>().await;
    }
}

pub(super) async fn supervise<T>(
    monitor: Option<ValidityMonitor>,
    log: MonitorLog<'_>,
    timeout: Duration,
    work: impl Future<Output = T>,
) -> T {
    let _report = monitor.as_ref().map(|monitor| MonitorReport {
        state: Rc::clone(&monitor.state),
        log,
    });
    let monitoring = async {
        match monitor {
            Some(monitor) => monitor.run(log, timeout).await,
            None => std::future::pending().await,
        }
    };
    match select(pin!(work), pin!(monitoring)).await {
        Either::Left((result, _)) => result,
        Either::Right(_) => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use crate::s2s::revocation::{CrlLease, RevocationStatus, UnknownReason};
    use std::pin::pin;
    use std::sync::Arc;
    use std::time::Duration;

    use compio::runtime::Runtime;
    use futures_util::future::join;
    use futures_util::poll;

    use super::*;

    #[test]
    fn fixed_deadline_resolves_all_waiters_and_retains_its_reason() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let now = SystemTime::now();
            let validity = LinkValidity::fixed(now + Duration::from_millis(200));
            assert!(validity.check(now).is_ok());
            assert!(validity.reason().is_none());
            let signal = validity.invalidated();
            let (first, second) = join(signal.clone(), signal).await;
            assert!(matches!(first, StreamClose::CertificateExpired));
            assert!(matches!(second, StreamClose::CertificateExpired));
            assert!(matches!(
                validity.reason(),
                Some(StreamClose::CertificateExpired)
            ));
            assert!(matches!(
                validity.check(now),
                Err(StreamClose::CertificateExpired)
            ));
        });
        Ok(())
    }

    #[test]
    fn each_wait_checks_wall_time_and_keeps_the_first_observed_reason() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            for reason in [
                StreamClose::CertificateExpired,
                StreamClose::RevocationStale,
            ] {
                let now = Cell::new(SystemTime::now());
                let deadline = now.get() + Duration::from_secs(3600);
                let validity = LinkValidity::fixed(deadline);
                validity.state.deadline_reason.set(reason);
                {
                    let mut first = pin!(validity.wait_with(|| now.get()));
                    assert!(poll!(first.as_mut()).is_pending());
                }
                now.set(deadline + Duration::from_nanos(1));
                assert!(validity.invalidated().now_or_never().is_none());
                let observed = validity.wait_with(|| now.get()).now_or_never();
                assert_eq!(observed.map(StreamClose::as_str), Some(reason.as_str()));
                assert_eq!(
                    validity.reason().map(StreamClose::as_str),
                    Some(reason.as_str())
                );
                assert_eq!(
                    validity
                        .check(deadline - Duration::from_secs(1))
                        .err()
                        .map(StreamClose::as_str),
                    Some(reason.as_str()),
                );
            }
        });
        Ok(())
    }

    #[test]
    fn past_deadline_fails_before_polling_and_resolves_at_once() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let now = SystemTime::now();
            let validity = LinkValidity::fixed(now - Duration::from_millis(200));
            assert!(validity.reason().is_none());
            assert!(matches!(
                validity.check(now),
                Err(StreamClose::CertificateExpired)
            ));
            assert!(matches!(
                validity.invalidated().now_or_never(),
                Some(StreamClose::CertificateExpired)
            ));
        });
        Ok(())
    }

    struct Clock {
        now: Cell<SystemTime>,
        timers: std::cell::RefCell<Vec<(SystemTime, oneshot::Sender<()>)>>,
    }

    impl Clock {
        fn new() -> Rc<Self> {
            Rc::new(Self {
                now: Cell::new(at(0)),
                timers: Default::default(),
            })
        }

        fn sleep(&self, duration: Duration) -> impl Future<Output = ()> {
            let (sender, receiver) = oneshot::channel();
            self.timers
                .borrow_mut()
                .push((self.now.get() + duration, sender));
            async move {
                let _ = receiver.await;
            }
        }

        fn advance(&self, seconds: u64) {
            self.now.set(at(seconds));
            let mut timers = self.timers.borrow_mut();
            let mut index = 0;
            while index < timers.len() {
                if timers[index].0 <= self.now.get() || timers[index].1.is_canceled() {
                    let (_, sender) = timers.swap_remove(index);
                    let _ = sender.send(());
                } else {
                    index += 1;
                }
            }
        }
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1000 + seconds)
    }

    fn log() -> MonitorLog<'static> {
        MonitorLog {
            direction: Direction::Inbound,
            connection_id: 1,
            local: "local.test",
            remote: "peer.test",
        }
    }

    fn verdict(source: RevocationSource, status: RevocationStatus) -> RevocationVerdict {
        RevocationVerdict {
            source,
            status,
            next_update: None,
            refresh_at: None,
            pending: Vec::new(),
            leases: Vec::new(),
            recheckable: true,
        }
    }

    fn good() -> RevocationVerdict {
        verdict(RevocationSource::Fetched, RevocationStatus::Good)
    }

    fn revoked() -> RevocationVerdict {
        verdict(RevocationSource::Fetched, RevocationStatus::Revoked)
    }

    fn signal() -> (oneshot::Sender<()>, FetchSignal) {
        let (sender, receiver) = oneshot::channel();
        (
            sender,
            async {
                let _ = receiver.await;
            }
            .boxed()
            .shared(),
        )
    }

    fn ready_signal() -> FetchSignal {
        async {}.boxed().shared()
    }

    enum Reply {
        Ready(Option<RevocationVerdict>),
        Held(oneshot::Receiver<Option<RevocationVerdict>>),
    }

    struct Script {
        clock: Rc<Clock>,
        calls: Rc<Cell<usize>>,
        steps: Rc<std::cell::RefCell<std::collections::VecDeque<(u64, Reply)>>>,
    }

    impl Script {
        fn new(clock: &Rc<Clock>) -> Self {
            Self {
                clock: Rc::clone(clock),
                calls: Rc::new(Cell::new(0)),
                steps: Default::default(),
            }
        }

        fn ready(&self, seconds: u64, verdict: Option<RevocationVerdict>) {
            self.steps
                .borrow_mut()
                .push_back((seconds, Reply::Ready(verdict)));
        }

        fn held(&self, seconds: u64) -> oneshot::Sender<Option<RevocationVerdict>> {
            let (sender, receiver) = oneshot::channel();
            self.steps
                .borrow_mut()
                .push_back((seconds, Reply::Held(receiver)));
            sender
        }

        fn revalidate(&self) -> Revalidate {
            let clock = Rc::clone(&self.clock);
            let calls = Rc::clone(&self.calls);
            let steps = Rc::clone(&self.steps);
            Box::new(move || {
                let (seconds, reply) = steps.borrow_mut().pop_front().expect("unexpected recheck");
                assert_eq!(clock.now.get(), at(seconds));
                calls.set(calls.get() + 1);
                async move {
                    match reply {
                        Reply::Ready(verdict) => verdict,
                        Reply::Held(receiver) => receiver.await.expect("recheck gate dropped"),
                    }
                }
                .boxed_local()
            })
        }
    }

    #[test]
    fn scheduling_uses_first_poll_clock_refresh_and_completion_time() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let clock = Clock::new();
            let script = Script::new(&clock);
            script.ready(5, Some(good()));
            script.ready(15, Some(revoked()));
            let mut initial = good();
            initial.refresh_at = Some(at(5));
            let (validity, monitor) = LinkValidity::monitored(
                at(100),
                initial,
                Duration::from_secs(10),
                script.revalidate(),
            );
            clock.advance(2);
            let mut running = pin!(monitor.run_with(
                log(),
                Duration::from_secs(3),
                || clock.now.get(),
                |duration| clock.sleep(duration)
            ));
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(script.calls.get(), 0);
            clock.advance(4);
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(script.calls.get(), 0);
            clock.advance(5);
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(script.calls.get(), 1);
            clock.advance(14);
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(script.calls.get(), 1);
            clock.advance(15);
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(script.calls.get(), 2);
            assert!(matches!(
                validity.check(at(15)),
                Err(StreamClose::CertificateRevoked)
            ));
        });
        Ok(())
    }

    #[test]
    fn periodic_initialization_waits_an_interval_from_first_poll() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let clock = Clock::new();
            let script = Script::new(&clock);
            script.ready(17, Some(revoked()));
            let (validity, monitor) = LinkValidity::monitored(
                at(100),
                good(),
                Duration::from_secs(10),
                script.revalidate(),
            );
            clock.advance(7);
            let mut running = pin!(monitor.run_with(
                log(),
                Duration::from_secs(3),
                || clock.now.get(),
                |duration| clock.sleep(duration)
            ));
            assert!(poll!(running.as_mut()).is_pending());
            clock.advance(16);
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(script.calls.get(), 0);
            clock.advance(17);
            assert!(poll!(running.as_mut()).is_pending());
            assert!(matches!(
                validity.reason(),
                Some(StreamClose::CertificateRevoked)
            ));
        });
        Ok(())
    }

    #[test]
    fn overdue_initial_refresh_runs_once_for_good_and_unknown_results() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            for status in [
                RevocationStatus::Good,
                RevocationStatus::Unknown(UnknownReason::FetchFailed),
            ] {
                let clock = Clock::new();
                let script = Script::new(&clock);
                let mut initial = good();
                initial.refresh_at = Some(at(0));
                let mut updated = verdict(RevocationSource::Fetched, status);
                updated.refresh_at = Some(at(0));
                script.ready(0, Some(updated));
                script.ready(10, Some(revoked()));
                let (validity, monitor) = LinkValidity::monitored(
                    at(100),
                    initial,
                    Duration::from_secs(10),
                    script.revalidate(),
                );
                let mut running = pin!(monitor.run_with(
                    log(),
                    Duration::from_secs(3),
                    || clock.now.get(),
                    |duration| clock.sleep(duration)
                ));
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(script.calls.get(), 1);
                assert!(validity.reason().is_none());
                clock.advance(9);
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(script.calls.get(), 1);
                clock.advance(10);
                assert!(poll!(running.as_mut()).is_pending());
                assert!(matches!(
                    validity.reason(),
                    Some(StreamClose::CertificateRevoked)
                ));
            }
        });
        Ok(())
    }

    #[test]
    fn refresh_due_during_attempt_runs_one_follow_up_then_waits() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let clock = Clock::new();
            let script = Script::new(&clock);
            let release = script.held(0);
            let mut follow_up = good();
            follow_up.refresh_at = Some(at(5));
            script.ready(7, Some(follow_up));
            script.ready(17, Some(revoked()));
            let mut initial = good();
            initial.pending.push(ready_signal());
            let (validity, monitor) = LinkValidity::monitored(
                at(100),
                initial,
                Duration::from_secs(10),
                script.revalidate(),
            );
            let mut running = pin!(monitor.run_with(
                log(),
                Duration::from_secs(20),
                || clock.now.get(),
                |duration| clock.sleep(duration)
            ));
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(script.calls.get(), 1);
            clock.advance(7);
            let mut result = good();
            result.refresh_at = Some(at(5));
            assert!(release.send(Some(result)).is_ok());
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(script.calls.get(), 2);
            clock.advance(16);
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(script.calls.get(), 2);
            clock.advance(17);
            assert!(poll!(running.as_mut()).is_pending());
            assert!(matches!(
                validity.reason(),
                Some(StreamClose::CertificateRevoked)
            ));
        });
        Ok(())
    }

    #[test]
    fn timeout_and_none_consume_ready_signals_and_keep_leases_until_replaced() -> std::io::Result<()>
    {
        Runtime::new()?.block_on(async {
            for timeout in [false, true] {
                let clock = Clock::new();
                let script = Script::new(&clock);
                let token = Arc::new(());
                let mut initial = good();
                initial.pending.push(ready_signal());
                initial.refresh_at = Some(at(0));
                initial.leases.push(CrlLease(Arc::clone(&token)));
                let mut gate = Some(script.held(0));
                let retry = 13;
                script.ready(retry, Some(good()));
                let (validity, monitor) = LinkValidity::monitored(
                    at(100),
                    initial,
                    Duration::from_secs(10),
                    script.revalidate(),
                );
                let mut running = pin!(monitor.run_with(
                    log(),
                    Duration::from_secs(if timeout { 3 } else { 20 }),
                    || clock.now.get(),
                    |duration| clock.sleep(duration)
                ));
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(script.calls.get(), 1);
                clock.advance(3);
                if !timeout {
                    assert!(gate.take().expect("held attempt").send(None).is_ok());
                }
                assert!(poll!(running.as_mut()).is_pending());
                if timeout {
                    assert!(gate.as_ref().is_some_and(|gate| gate.is_canceled()));
                }
                assert_eq!(Arc::strong_count(&token), 2);
                assert!(validity.reason().is_none());
                clock.advance(retry - 1);
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(script.calls.get(), 1);
                clock.advance(retry);
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(script.calls.get(), 2);
                assert_eq!(Arc::strong_count(&token), 1);
            }
        });
        Ok(())
    }

    #[test]
    fn unconsumed_downloads_survive_timeout_and_ready_replacement_signals_trigger()
    -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            for reject in [false, true] {
                let clock = Clock::new();
                let script = Script::new(&clock);
                let _held = script.held(0);
                let mut replacement = good();
                replacement.pending.push(ready_signal());
                script.ready(3, Some(replacement));
                script.ready(3, Some(if reject { revoked() } else { good() }));
                if !reject {
                    script.ready(13, Some(revoked()));
                }
                let (complete_b, b) = signal();
                let mut initial = good();
                initial.pending = vec![ready_signal(), b];
                let (validity, monitor) = LinkValidity::monitored(
                    at(100),
                    initial,
                    Duration::from_secs(10),
                    script.revalidate(),
                );
                let mut running = pin!(monitor.run_with(
                    log(),
                    Duration::from_secs(3),
                    || clock.now.get(),
                    |duration| clock.sleep(duration)
                ));
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(script.calls.get(), 1);
                clock.advance(1);
                assert!(complete_b.send(()).is_ok());
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(script.calls.get(), 1);
                clock.advance(3);
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(script.calls.get(), 3);
                if reject {
                    assert!(matches!(
                        validity.reason(),
                        Some(StreamClose::CertificateRevoked)
                    ));
                } else {
                    assert!(validity.reason().is_none());
                    clock.advance(12);
                    assert!(poll!(running.as_mut()).is_pending());
                    assert_eq!(script.calls.get(), 3);
                    clock.advance(13);
                    assert!(poll!(running.as_mut()).is_pending());
                    assert!(matches!(
                        validity.reason(),
                        Some(StreamClose::CertificateRevoked)
                    ));
                }
            }
        });
        Ok(())
    }

    #[test]
    fn ready_initial_snapshot_signals_trigger_immediate_rechecks() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            for reject in [false, true] {
                let clock = Clock::new();
                let script = Script::new(&clock);
                script.ready(0, Some(if reject { revoked() } else { good() }));
                let mut initial = good();
                initial.pending.push(ready_signal());
                let (validity, monitor) = LinkValidity::monitored(
                    at(100),
                    initial,
                    Duration::from_secs(10),
                    script.revalidate(),
                );
                let mut running = pin!(monitor.run_with(
                    log(),
                    Duration::from_secs(3),
                    || clock.now.get(),
                    |duration| clock.sleep(duration)
                ));
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(script.calls.get(), 1);
                assert_eq!(
                    validity.reason().map(StreamClose::as_str),
                    reject.then_some("certificate_revoked")
                );
                clock.advance(1);
                assert!(poll!(running.as_mut()).is_pending());
                assert_eq!(script.calls.get(), 1);
            }
        });
        Ok(())
    }

    #[test]
    fn pending_completion_triggers_before_the_periodic_deadline() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let clock = Clock::new();
            let script = Script::new(&clock);
            script.ready(2, Some(revoked()));
            let (complete, pending) = signal();
            let mut initial = good();
            initial.pending.push(pending);
            let (validity, monitor) = LinkValidity::monitored(
                at(100),
                initial,
                Duration::from_secs(10),
                script.revalidate(),
            );
            let mut running = pin!(monitor.run_with(
                log(),
                Duration::from_secs(3),
                || clock.now.get(),
                |duration| clock.sleep(duration)
            ));
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(script.calls.get(), 0);
            clock.advance(2);
            assert!(complete.send(()).is_ok());
            assert!(poll!(running.as_mut()).is_pending());
            assert_eq!(script.calls.get(), 1);
            assert!(matches!(
                validity.reason(),
                Some(StreamClose::CertificateRevoked)
            ));
        });
        Ok(())
    }

    #[test]
    fn elapsed_file_deadline_precedes_timeout_and_extending_results() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            for simultaneous_result in [false, true] {
                let clock = Clock::new();
                let script = Script::new(&clock);
                let release = script.held(1);
                let mut initial = verdict(RevocationSource::File, RevocationStatus::Good);
                initial.next_update = Some(at(5));
                let (validity, monitor) = LinkValidity::monitored(
                    at(100),
                    initial,
                    Duration::from_secs(1),
                    script.revalidate(),
                );
                assert!(matches!(
                    validity.check(at(5)),
                    Err(StreamClose::RevocationStale)
                ));
                assert!(validity.reason().is_none());
                let mut running = pin!(monitor.run_with(
                    log(),
                    Duration::from_secs(4),
                    || clock.now.get(),
                    |duration| clock.sleep(duration)
                ));
                assert!(poll!(running.as_mut()).is_pending());
                clock.advance(1);
                assert!(poll!(running.as_mut()).is_pending());
                clock.advance(5);
                if simultaneous_result {
                    let mut next = verdict(RevocationSource::File, RevocationStatus::Good);
                    next.next_update = Some(at(50));
                    assert!(release.send(Some(next)).is_ok());
                }
                assert!(poll!(running.as_mut()).is_pending());
                assert!(matches!(
                    validity.check(at(5)),
                    Err(StreamClose::RevocationStale)
                ));
                assert!(matches!(
                    validity.invalidated().now_or_never(),
                    Some(StreamClose::RevocationStale)
                ));
            }
        });
        Ok(())
    }

    #[test]
    fn refreshed_file_deadline_extends_up_to_original_certificate_cap() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            for next_update in [20, 200] {
                let clock = Clock::new();
                let script = Script::new(&clock);
                let release = script.held(2);
                let mut initial = verdict(RevocationSource::File, RevocationStatus::Good);
                initial.next_update = Some(at(5));
                let (validity, monitor) = LinkValidity::monitored(
                    at(100),
                    initial,
                    Duration::from_secs(2),
                    script.revalidate(),
                );
                let mut signal = pin!(validity.invalidated());
                assert!(poll!(signal.as_mut()).is_pending());
                let mut running = pin!(monitor.run_with(
                    log(),
                    Duration::from_secs(10),
                    || clock.now.get(),
                    |duration| clock.sleep(duration)
                ));
                assert!(poll!(running.as_mut()).is_pending());
                clock.advance(2);
                assert!(poll!(running.as_mut()).is_pending());
                clock.advance(4);
                let mut next = verdict(RevocationSource::File, RevocationStatus::Good);
                next.next_update = Some(at(next_update));
                assert!(release.send(Some(next)).is_ok());
                assert!(poll!(running.as_mut()).is_pending());
                clock.advance(5);
                assert!(poll!(running.as_mut()).is_pending());
                assert!(poll!(signal.as_mut()).is_pending());
                assert!(validity.check(at(5)).is_ok());
                let cap = next_update.min(100);
                clock.advance(cap);
                assert!(poll!(running.as_mut()).is_pending());
                let reason = if next_update < 100 {
                    StreamClose::RevocationStale
                } else {
                    StreamClose::CertificateExpired
                };
                assert_eq!(
                    validity.reason().map(StreamClose::as_str),
                    Some(reason.as_str())
                );
                assert_eq!(signal.await.as_str(), reason.as_str());
            }
        });
        Ok(())
    }

    #[test]
    fn file_unknown_and_timeout_invalidate_with_their_own_reasons() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            for timeout in [false, true] {
                let clock = Clock::new();
                let script = Script::new(&clock);
                let _gate = if timeout {
                    Some(script.held(2))
                } else {
                    script.ready(
                        2,
                        Some(verdict(
                            RevocationSource::File,
                            RevocationStatus::Unknown(UnknownReason::NotAuthoritative),
                        )),
                    );
                    None
                };
                let initial = verdict(RevocationSource::File, RevocationStatus::Good);
                let (validity, monitor) = LinkValidity::monitored(
                    at(100),
                    initial,
                    Duration::from_secs(2),
                    script.revalidate(),
                );
                let mut running = pin!(monitor.run_with(
                    log(),
                    Duration::from_secs(3),
                    || clock.now.get(),
                    |duration| clock.sleep(duration)
                ));
                assert!(poll!(running.as_mut()).is_pending());
                clock.advance(2);
                assert!(poll!(running.as_mut()).is_pending());
                if timeout {
                    clock.advance(5);
                    assert!(poll!(running.as_mut()).is_pending());
                }
                let reason = if timeout {
                    StreamClose::RevocationUnavailable
                } else {
                    StreamClose::RevocationUnknown
                };
                assert_eq!(
                    validity.reason().map(StreamClose::as_str),
                    Some(reason.as_str())
                );
            }
        });
        Ok(())
    }

    #[test]
    fn certificate_deadline_invalidates_before_polling_the_signal() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let clock = Clock::new();
            let script = Script::new(&clock);
            let (validity, monitor) = LinkValidity::monitored(
                at(5),
                good(),
                Duration::from_secs(10),
                script.revalidate(),
            );
            let mut running = pin!(monitor.run_with(
                log(),
                Duration::from_secs(3),
                || clock.now.get(),
                |duration| clock.sleep(duration)
            ));
            assert!(poll!(running.as_mut()).is_pending());
            clock.advance(5);
            assert!(poll!(running.as_mut()).is_pending());
            assert!(matches!(
                validity.check(at(0)),
                Err(StreamClose::CertificateExpired)
            ));
            assert!(matches!(
                validity.invalidated().now_or_never(),
                Some(StreamClose::CertificateExpired)
            ));
        });
        Ok(())
    }

    #[test]
    fn supervise_cancels_recheck_and_releases_leases_when_work_finishes() -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let token = Arc::new(());
            let (finish, work) = oneshot::channel();
            let (release, held) = oneshot::channel();
            let held = Rc::new(std::cell::RefCell::new(Some(held)));
            let calls = Rc::new(Cell::new(0));
            let count = Rc::clone(&calls);
            let revalidate: Revalidate = Box::new(move || {
                count.set(count.get() + 1);
                let held = held.borrow_mut().take().expect("one recheck");
                async move { held.await.expect("held recheck") }.boxed_local()
            });
            let mut initial = good();
            initial.pending.push(ready_signal());
            initial.leases.push(CrlLease(Arc::clone(&token)));
            let (validity, monitor) = LinkValidity::monitored(
                SystemTime::now() + Duration::from_secs(3600),
                initial,
                Duration::from_secs(3600),
                revalidate,
            );
            let signal = validity.invalidated();
            let mut supervised = pin!(supervise(
                Some(monitor),
                log(),
                Duration::from_secs(3600),
                work
            ));
            assert!(poll!(supervised.as_mut()).is_pending());
            assert_eq!(calls.get(), 1);
            assert_eq!(Arc::strong_count(&token), 2);
            assert!(finish.send(42).is_ok());
            assert_eq!(supervised.await, Ok(42));
            assert!(release.is_canceled());
            assert!(matches!(signal.await, StreamClose::CertificateExpired));
            assert_eq!(Arc::strong_count(&token), 1);
        });
        Ok(())
    }
    #[test]
    fn supervise_preserves_recorded_file_reason_on_completion_or_cancellation()
    -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            for complete in [false, true] {
                let now = SystemTime::now();
                let token = Arc::new(());
                let calls = Rc::new(Cell::new(0));
                let count = Rc::clone(&calls);
                let revalidate: Revalidate = Box::new(move || {
                    count.set(count.get() + 1);
                    async { panic!("recheck must not run") }.boxed_local()
                });
                let mut initial = verdict(RevocationSource::File, RevocationStatus::Good);
                initial.next_update = Some(now + Duration::from_secs(5));
                initial.leases.push(CrlLease(Arc::clone(&token)));
                let (validity, monitor) = LinkValidity::monitored(
                    now + Duration::from_secs(60),
                    initial,
                    Duration::from_secs(10),
                    revalidate,
                );
                let signal = validity.invalidated();
                let work = async {
                    assert!(matches!(
                        validity.wait_with(|| now + Duration::from_secs(5)).await,
                        StreamClose::RevocationStale
                    ));
                    if complete {
                        42
                    } else {
                        std::future::pending().await
                    }
                };
                let mut supervised = Box::pin(supervise(
                    Some(monitor),
                    log(),
                    Duration::from_secs(3),
                    work,
                ));
                if complete {
                    assert_eq!(supervised.await, 42);
                } else {
                    assert!(poll!(supervised.as_mut()).is_pending());
                    assert_eq!(Arc::strong_count(&token), 2);
                    drop(supervised);
                }
                assert_eq!(calls.get(), 0);
                assert!(matches!(signal.await, StreamClose::RevocationStale));
                assert_eq!(Arc::strong_count(&token), 1);
            }
        });
        Ok(())
    }
}
