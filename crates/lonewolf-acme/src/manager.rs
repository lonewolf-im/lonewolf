// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use futures_util::FutureExt;
use futures_util::future::{AbortHandle, Abortable, Either, LocalBoxFuture, join, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
use parking_lot::Mutex as PlMutex;

use crate::issuer::RenewalWindow;
use crate::schedule;
use crate::types::*;
use crate::{AcmeHttpClient, Challenges, Issuer, StateStore, TransportOptions};

pub const FAILURE_KIND_COUNT: usize = 9;
const EVENT_COUNT: usize = 5;

pub struct ManagerOptions {
    pub directory_url: String,
    pub state_path: PathBuf,
    pub ca_certificates_path: Option<PathBuf>,
    pub hosts: Vec<ManagedHost>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostState {
    Pending,
    Ready,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostEvent {
    InitialLoad,
    AttemptOutcome,
    NextRetry,
    Expiry,
    Installed,
}

#[derive(Clone, Debug)]
pub struct HostStatus {
    pub state: HostState,
    pub not_after_unix: Option<u64>,
    pub next_attempt_unix: Option<u64>,
    pub attempts: u64,
    pub successes: u64,
    pub failures: [u64; FAILURE_KIND_COUNT],
    pub generation: u64,
    pub last_event: HostEvent,
    pub events: [u64; EVENT_COUNT],
}

#[derive(Clone)]
pub struct StatusHandle {
    inner: Arc<PlMutex<Vec<(String, HostStatus)>>>,
}

impl StatusHandle {
    pub fn snapshot(&self) -> Vec<(String, HostStatus)> {
        self.inner.lock().clone()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagerError {
    State(StateError),
    Transport(AcmeError),
    Task,
    Deadline,
}

impl From<StateError> for ManagerError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}
impl fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ACME manager {self:?}")
    }
}
impl std::error::Error for ManagerError {}

pub struct Manager<I: Installer> {
    store: StateStore,
    transport: AcmeHttpClient,
    issuer: Arc<Issuer>,
    challenges: Challenges,
    installer: Arc<I>,
    hosts: Vec<StoredHost>,
    status: StatusHandle,
}

impl<I: Installer> Manager<I> {
    pub async fn load(
        options: ManagerOptions,
        challenges: Challenges,
        installer: I,
    ) -> Result<Self, ManagerError> {
        let store = StateStore::open(options.state_path, options.directory_url.clone()).await?;
        let transport = AcmeHttpClient::new(TransportOptions {
            ca_certificates_path: options.ca_certificates_path,
        })
        .await
        .map_err(ManagerError::Transport)?;
        let issuer = Arc::new(
            Issuer::new(
                store.clone(),
                challenges.clone(),
                transport.clone(),
                options.directory_url,
            )
            .map_err(fatal)?,
        );
        issuer.validate_cached_account().await.map_err(fatal)?;
        let mut hosts = Vec::with_capacity(options.hosts.len());
        let mut snapshots = Vec::with_capacity(options.hosts.len());
        for host in options.hosts {
            if hosts
                .iter()
                .any(|record: &StoredHost| record.host.dns_name == host.dns_name)
            {
                return Err(StateError::InvalidData.into());
            }
            let record = store
                .host(host.dns_name.clone())
                .await?
                .unwrap_or(StoredHost {
                    host: host.clone(),
                    certificate: None,
                    order: None,
                    retry: RetryState {
                        failures: 0,
                        not_before_unix: 0,
                    },
                });
            record.validate().map_err(|_| StateError::CorruptData)?;
            if record.host.xmpp_domain != host.xmpp_domain || record.host.dns_name != host.dns_name
            {
                return Err(StateError::CorruptData.into());
            }
            let installed = prepare_cache(&record, &installer, schedule::now)?;
            let now = schedule::now()?;
            let mut initial_state = state(&record, now);
            if initial_state == HostState::Ready && !installed {
                initial_state = HostState::Pending;
            }
            let mut status = HostStatus {
                state: initial_state,
                not_after_unix: record.certificate.as_ref().map(|cert| cert.not_after_unix),
                next_attempt_unix: Some(issue_due(&record, now)),
                attempts: 0,
                successes: 0,
                failures: [0; FAILURE_KIND_COUNT],
                generation: u64::from(installed),
                last_event: HostEvent::InitialLoad,
                events: [0; EVENT_COUNT],
            };
            event(&mut status, HostEvent::InitialLoad);
            if installed {
                event(&mut status, HostEvent::Installed);
            }
            snapshots.push((host.xmpp_domain, status));
            hosts.push(record);
        }
        let status = StatusHandle {
            inner: Arc::new(PlMutex::new(snapshots)),
        };
        Ok(Self {
            store,
            transport,
            issuer,
            challenges,
            installer: Arc::new(installer),
            hosts,
            status,
        })
    }

    pub fn status(&self) -> StatusHandle {
        self.status.clone()
    }

    pub async fn run(
        mut self,
        shutdown: impl Future<Output = Instant>,
    ) -> Result<(), ManagerError> {
        let production = Production {
            issuer: self.issuer.clone(),
            installer: self.installer.clone(),
        };
        let result = until_shutdown(
            drive(
                &self.store,
                &production,
                &SystemClock,
                std::mem::take(&mut self.hosts),
                &self.status,
            ),
            shutdown,
        )
        .await;
        self.challenges.clear();
        let deadline = result
            .as_ref()
            .copied()
            .unwrap_or_else(|_| Instant::now() + Duration::from_secs(5));
        let (store, transport) =
            join(self.store.drain(deadline), self.transport.drain(deadline)).await;
        result?;
        store.map_err(|error| {
            if error == StateError::DeadlineElapsed {
                ManagerError::Deadline
            } else {
                error.into()
            }
        })?;
        transport.map_err(|error| {
            if error.kind() == AcmeErrorKind::Timeout {
                ManagerError::Deadline
            } else {
                ManagerError::Transport(error)
            }
        })?;
        Ok(())
    }
}

async fn until_shutdown(
    work: impl Future<Output = Result<(), ManagerError>>,
    shutdown: impl Future<Output = Instant>,
) -> Result<Instant, ManagerError> {
    let work = pin!(work);
    let shutdown = pin!(shutdown);
    match select(shutdown, work).await {
        Either::Left((deadline, _)) => Ok(deadline),
        Either::Right((result, _)) => Err(result.err().unwrap_or(ManagerError::Task)),
    }
}

fn prepare_cache<I: Installer>(
    record: &StoredHost,
    installer: &I,
    now: impl FnOnce() -> Result<u64, StateError>,
) -> Result<bool, ManagerError> {
    let Some(certificate) = &record.certificate else {
        return Ok(false);
    };
    let prepared = installer
        .prepare(&record.host, &certificate.material)
        .map_err(|_| StateError::CorruptData)?;
    if prepared.validity.not_before_unix != certificate.not_before_unix
        || prepared.validity.not_after_unix != certificate.not_after_unix
    {
        return Err(StateError::CorruptData.into());
    }
    let now = now()?;
    if certificate.not_before_unix <= now && now < certificate.not_after_unix {
        installer.activate(prepared.candidate);
        return Ok(true);
    }
    Ok(false)
}

fn state(record: &StoredHost, now: u64) -> HostState {
    match record.certificate.as_ref() {
        Some(cert) if now >= cert.not_after_unix => HostState::Expired,
        Some(cert) if now >= cert.not_before_unix => HostState::Ready,
        _ => HostState::Pending,
    }
}
fn issue_due(record: &StoredHost, now: u64) -> u64 {
    record.retry.not_before_unix.max(
        record
            .certificate
            .as_ref()
            .filter(|cert| now < cert.not_after_unix)
            .map_or(0, |cert| cert.renew_at_unix),
    )
}
fn event(status: &mut HostStatus, event: HostEvent) {
    status.last_event = event;
    let index = event as usize;
    status.events[index] = status.events[index].saturating_add(1);
}
fn fatal(failure: AttemptFailure) -> ManagerError {
    failure
        .state_error
        .map_or(ManagerError::Task, ManagerError::State)
}

trait Storage {
    async fn account(&self) -> Result<Option<StoredAccount>, StateError>;
    async fn save_account(&self, record: StoredAccount) -> Result<(), StateError>;
    async fn host(&self, dns: String) -> Result<Option<StoredHost>, StateError>;
    async fn save_host(&self, record: StoredHost) -> Result<(), StateError>;
}
impl Storage for StateStore {
    async fn account(&self) -> Result<Option<StoredAccount>, StateError> {
        self.account().await
    }
    async fn save_account(&self, record: StoredAccount) -> Result<(), StateError> {
        self.save_account(record).await
    }
    async fn host(&self, dns: String) -> Result<Option<StoredHost>, StateError> {
        self.host(dns).await
    }
    async fn save_host(&self, record: StoredHost) -> Result<(), StateError> {
        self.save_host(record).await
    }
}
trait Clock {
    fn now(&self) -> Result<u64, StateError>;
    fn uniform(&self, maximum: u64) -> Result<u64, StateError>;
    async fn sleep(&self, delay: Duration);
}
struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Result<u64, StateError> {
        schedule::now()
    }
    fn uniform(&self, maximum: u64) -> Result<u64, StateError> {
        schedule::uniform(maximum)
    }
    async fn sleep(&self, delay: Duration) {
        compio::time::sleep(delay).await
    }
}
trait Engine {
    fn publish_cache(&self, host: &StoredHost, now: u64) -> Result<bool, ManagerError>;
    async fn ensure_account(&self) -> Result<(), AttemptFailure>;
    async fn issue(&self, host: StoredHost) -> Result<AttemptSuccess, AttemptFailure>;
    async fn ari(&self, host: StoredHost) -> Result<Option<RenewalWindow>, AttemptFailure>;
}
struct Production<I> {
    issuer: Arc<Issuer>,
    installer: Arc<I>,
}
impl<I: Installer> Engine for Production<I> {
    fn publish_cache(&self, host: &StoredHost, _: u64) -> Result<bool, ManagerError> {
        prepare_cache(host, self.installer.as_ref(), schedule::now)
    }

    async fn ensure_account(&self) -> Result<(), AttemptFailure> {
        self.issuer.ensure_account().await
    }
    async fn issue(&self, host: StoredHost) -> Result<AttemptSuccess, AttemptFailure> {
        self.issuer
            .issue(host.host, self.installer.as_ref(), None)
            .await
    }

    async fn ari(&self, host: StoredHost) -> Result<Option<RenewalWindow>, AttemptFailure> {
        self.issuer.renewal_info(&host).await
    }
}

enum Outcome {
    Account(Result<(), AttemptFailure>),
    Cancelled,
    Issue(Result<AttemptSuccess, AttemptFailure>),
    Ari(Result<Option<RenewalWindow>, AttemptFailure>),
}
struct Completed {
    index: Option<usize>,
    generation: Option<Vec<Vec<u8>>>,
    account_retry: Option<RetryState>,
    outcome: Outcome,
}

type Publication = (Option<Vec<Vec<u8>>>, bool);

fn housekeeping(
    hosts: &[StoredHost],
    engine: &impl Engine,
    clock: &impl Clock,
    status: &StatusHandle,
    published: &mut [Publication],
    overrides: &[Option<CertificateValidity>],
) -> Result<u64, ManagerError> {
    let now = clock.now()?;
    for (index, host) in hosts.iter().enumerate() {
        if overrides[index].is_none() {
            let generation = host.certificate.as_ref().map(|cert| &cert.material.chain);
            if published[index].0.as_ref() != generation {
                published[index] = (generation.cloned(), false);
            }
            if !published[index].1
                && host
                    .certificate
                    .as_ref()
                    .is_some_and(|cert| cert.not_before_unix <= now && now < cert.not_after_unix)
                && engine.publish_cache(host, clock.now()?)?
            {
                published[index].1 = true;
                let mut snapshots = status.inner.lock();
                snapshots[index].1.generation = snapshots[index].1.generation.saturating_add(1);
                event(&mut snapshots[index].1, HostEvent::Installed);
            }
        }
        let mut current = if let Some(validity) = overrides[index] {
            if now < validity.not_before_unix {
                HostState::Pending
            } else if now >= validity.not_after_unix {
                HostState::Expired
            } else {
                HostState::Ready
            }
        } else {
            state(host, clock.now()?)
        };
        if current == HostState::Ready && !published[index].1 {
            current = HostState::Pending;
        }
        let mut snapshots = status.inner.lock();
        let snapshot = &mut snapshots[index].1;
        if snapshot.state != current {
            snapshot.state = current;
            event(snapshot, HostEvent::Expiry);
        }
    }
    Ok(now)
}

async fn storage<T>(
    work: impl Future<Output = Result<T, StateError>>,
    hosts: &[StoredHost],
    engine: &impl Engine,
    clock: &impl Clock,
    status: &StatusHandle,
    published: &mut [Publication],
    overrides: &[Option<CertificateValidity>],
) -> Result<T, ManagerError> {
    let mut work = pin!(work);
    loop {
        let now = housekeeping(hosts, engine, clock, status, published, overrides)?;
        let mut next = now.saturating_add(60);
        for (index, host) in hosts.iter().enumerate() {
            let validity = overrides[index].or_else(|| {
                host.certificate.as_ref().map(|cert| CertificateValidity {
                    not_before_unix: cert.not_before_unix,
                    not_after_unix: cert.not_after_unix,
                })
            });
            if let Some(validity) = validity {
                if now < validity.not_before_unix {
                    next = next.min(validity.not_before_unix);
                }
                if now < validity.not_after_unix {
                    next = next.min(validity.not_after_unix);
                }
            }
        }
        let timer = pin!(clock.sleep(Duration::from_secs(next.saturating_sub(now).clamp(1, 60))));
        if let Either::Left((result, _)) = select(work.as_mut(), timer).await {
            return result.map_err(Into::into);
        }
    }
}

async fn drive(
    store: &impl Storage,
    engine: &impl Engine,
    clock: &impl Clock,
    mut hosts: Vec<StoredHost>,
    status: &StatusHandle,
) -> Result<(), ManagerError> {
    let mut jobs: FuturesUnordered<LocalBoxFuture<'_, Completed>> = FuturesUnordered::new();
    let mut busy = vec![false; hosts.len()];
    let mut ari_aborts: Vec<Option<AbortHandle>> = vec![None; hosts.len()];
    let mut account_ready = false;
    let mut account_busy = false;
    let mut published: Vec<_> = hosts
        .iter()
        .enumerate()
        .map(|(index, host)| {
            (
                host.certificate
                    .as_ref()
                    .map(|cert| cert.material.chain.clone()),
                status.inner.lock()[index].1.generation > 0,
            )
        })
        .collect();
    let mut overrides = vec![None; hosts.len()];
    loop {
        let account = storage(
            store.account(),
            &hosts,
            engine,
            clock,
            status,
            &mut published,
            &overrides,
        )
        .await?;
        let now = housekeeping(&hosts, engine, clock, status, &mut published, &overrides)?;
        let account_floor = account
            .as_ref()
            .map_or(0, |account| account.retry.not_before_unix);
        {
            let mut snapshots = status.inner.lock();
            for (index, host) in hosts.iter().enumerate() {
                let snapshot = &mut snapshots[index].1;
                snapshot.next_attempt_unix = Some(issue_due(host, now).max(account_floor));
            }
        }
        let mut next = now.saturating_add(60);
        let mut candidates = Vec::with_capacity(hosts.len());
        for (index, host) in hosts.iter().enumerate() {
            if !published[index].1
                && let Some(cert) = host
                    .certificate
                    .as_ref()
                    .filter(|cert| now < cert.not_before_unix)
            {
                next = next.min(cert.not_before_unix);
            }
            let issuance = issue_due(host, now).max(account_floor);
            if let Some(abort) = &ari_aborts[index] {
                next = next.min(issuance.max(now));
                if issuance <= now {
                    abort.abort();
                }
            }
            if busy[index] {
                continue;
            }
            let ari = host
                .certificate
                .as_ref()
                .filter(|cert| now < cert.not_after_unix)
                .map(|cert| cert.ari_check_at_unix.max(account_floor));
            let (due, is_ari) = match ari {
                Some(ari) if ari < issuance && now < issuance => (ari, true),
                _ => (issuance, false),
            };
            if account_ready || !account_busy || due > now {
                next = next.min(due.max(now));
            }
            if due <= now {
                candidates.push((due, host.host.dns_name.as_str(), index, is_ari));
            }
        }
        candidates.sort_unstable_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        if jobs.len() < 2 && !candidates.is_empty() && !account_ready && !account_busy {
            account_busy = true;
            jobs.push(
                async {
                    Completed {
                        index: None,
                        generation: None,
                        account_retry: None,
                        outcome: Outcome::Account(engine.ensure_account().await),
                    }
                }
                .boxed_local(),
            );
        }
        for (_, _, index, ari) in
            candidates
                .into_iter()
                .take(if account_ready { 2 - jobs.len() } else { 0 })
        {
            let host = hosts[index].clone();
            let generation = host
                .certificate
                .as_ref()
                .map(|cert| cert.material.chain.clone());
            let account_retry = account.as_ref().map(|account| account.retry);
            busy[index] = true;
            if !ari {
                let mut snapshots = status.inner.lock();
                snapshots[index].1.attempts = snapshots[index].1.attempts.saturating_add(1);
            }
            let registration = if ari {
                let (abort, registration) = AbortHandle::new_pair();
                ari_aborts[index] = Some(abort);
                Some(registration)
            } else {
                None
            };
            jobs.push(
                async move {
                    let outcome = if let Some(registration) = registration {
                        match Abortable::new(engine.ari(host), registration).await {
                            Ok(result) => Outcome::Ari(result),
                            Err(_) => Outcome::Cancelled,
                        }
                    } else {
                        Outcome::Issue(engine.issue(host).await)
                    };
                    Completed {
                        index: Some(index),
                        generation,
                        account_retry,
                        outcome,
                    }
                }
                .boxed_local(),
            );
        }
        let wait = Duration::from_secs(next.saturating_sub(clock.now()?).clamp(1, 60));
        let completed = if jobs.is_empty() {
            clock.sleep(wait).await;
            continue;
        } else {
            let sleep = pin!(clock.sleep(wait));
            let ready = pin!(jobs.next());
            match select(ready, sleep).await {
                Either::Left((Some(result), _)) => result,
                _ => continue,
            }
        };
        if let Outcome::Account(result) = completed.outcome {
            account_busy = false;
            match result {
                Ok(()) => account_ready = true,
                Err(error) if error.state_error.is_some() || error.kind == FailureKind::State => {
                    return Err(fatal(error));
                }
                Err(_) => {}
            }
            continue;
        }
        let index = completed.index.ok_or(ManagerError::Task)?;
        match completed.outcome {
            Outcome::Issue(Err(error)) | Outcome::Ari(Err(error))
                if error.state_error.is_some() || error.kind == FailureKind::State =>
            {
                return Err(fatal(error));
            }
            _ => {}
        }
        if let Outcome::Issue(Ok(success)) = completed.outcome {
            overrides[index] = Some(success.validity);
            published[index] = (None, true);
            let mut snapshots = status.inner.lock();
            let snapshot = &mut snapshots[index].1;
            snapshot.successes = snapshot.successes.saturating_add(1);
            snapshot.generation = snapshot.generation.saturating_add(1);
            snapshot.not_after_unix = Some(success.validity.not_after_unix);
            event(snapshot, HostEvent::Installed);
        }
        let mut host = storage(
            store.host(hosts[index].host.dns_name.clone()),
            &hosts,
            engine,
            clock,
            status,
            &mut published,
            &overrides,
        )
        .await?
        .ok_or(StateError::CorruptData)?;
        if let Some(validity) = overrides[index] {
            let certificate = host.certificate.as_ref().ok_or(StateError::CorruptData)?;
            if certificate.not_before_unix != validity.not_before_unix
                || certificate.not_after_unix != validity.not_after_unix
            {
                return Err(StateError::CorruptData.into());
            }
            hosts[index] = host.clone();
            published[index] = (Some(certificate.material.chain.clone()), true);
            overrides[index] = None;
        }
        let now = clock.now()?;
        match completed.outcome {
            Outcome::Account(_) => return Err(ManagerError::Task),
            Outcome::Cancelled => {}
            Outcome::Issue(result) => {
                match result {
                    Ok(_) => {
                        if let Some(mut account) = storage(
                            store.account(),
                            &hosts,
                            engine,
                            clock,
                            status,
                            &mut published,
                            &overrides,
                        )
                        .await?
                            && Some(account.retry) == completed.account_retry
                            && account.retry.failures > 0
                        {
                            account.retry = RetryState {
                                failures: 0,
                                not_before_unix: 0,
                            };
                            storage(
                                store.save_account(account),
                                &hosts,
                                engine,
                                clock,
                                status,
                                &mut published,
                                &overrides,
                            )
                            .await?;
                        }
                    }
                    Err(error) => {
                        if error.state_error.is_some() {
                            return Err(fatal(error));
                        }
                        {
                            let mut snapshots = status.inner.lock();
                            let snapshot = &mut snapshots[index].1;
                            if error.kind == FailureKind::Deferred {
                                snapshot.attempts = snapshot.attempts.saturating_sub(1);
                            } else {
                                snapshot.failures[error.kind as usize] =
                                    snapshot.failures[error.kind as usize].saturating_add(1);
                            }
                            event(snapshot, HostEvent::NextRetry);
                        }
                        if error.kind == FailureKind::Account {
                            let mut account = storage(
                                store.account(),
                                &hosts,
                                engine,
                                clock,
                                status,
                                &mut published,
                                &overrides,
                            )
                            .await?
                            .ok_or(StateError::CorruptData)?;
                            account.retry.failures = account.retry.failures.saturating_add(1);
                            let delay = schedule::retry_delay(account.retry.failures, |maximum| {
                                clock.uniform(maximum)
                            })?;
                            account.retry.not_before_unix = account
                                .retry
                                .not_before_unix
                                .max(schedule::add(now, delay)?);
                            if let Some(hint) = error.retry_not_before {
                                let duration = hint
                                    .duration_since(UNIX_EPOCH)
                                    .map_err(|_| StateError::InvalidData)?;
                                account.retry.not_before_unix =
                                    account.retry.not_before_unix.max(schedule::add(
                                        duration.as_secs(),
                                        u64::from(duration.subsec_nanos() != 0),
                                    )?);
                            }
                            storage(
                                store.save_account(account),
                                &hosts,
                                engine,
                                clock,
                                status,
                                &mut published,
                                &overrides,
                            )
                            .await?;
                            account_ready = false;
                        }
                    }
                }
                event(&mut status.inner.lock()[index].1, HostEvent::AttemptOutcome);
            }
            Outcome::Ari(result) => {
                if let Err(error) = result
                    && (error.state_error.is_some() || error.kind == FailureKind::State)
                {
                    return Err(fatal(error));
                }
                if let Some(certificate) = host.certificate.as_mut().filter(|cert| {
                    completed.generation.as_ref() == Some(&cert.material.chain)
                        && now < cert.not_after_unix
                }) {
                    let delay = match result {
                        Ok(Some(window)) => {
                            certificate.ari_failures = 0;
                            let valid = match (window.start, window.end) {
                                (Some(start), Some(end)) => {
                                    schedule::apply_window(certificate, start, end, |maximum| {
                                        clock.uniform(maximum)
                                    })?
                                }
                                _ => false,
                            };
                            if !valid {
                                certificate.ari_window = None;
                                certificate.renew_at_unix = certificate.fallback_at_unix;
                            }
                            if valid { window.delay.max(60) } else { 43_200 }
                        }
                        Ok(None) => 43_200,
                        Err(error) => {
                            if error.state_error.is_some() {
                                return Err(fatal(error));
                            }
                            certificate.ari_failures = certificate.ari_failures.saturating_add(1);
                            let delay = schedule::ari_delay(
                                certificate.ari_failures,
                                matches!(
                                    error.kind,
                                    FailureKind::Network
                                        | FailureKind::Timeout
                                        | FailureKind::RateLimited
                                ),
                            );
                            if let Some(hint) = error.retry_not_before {
                                let duration = hint
                                    .duration_since(UNIX_EPOCH)
                                    .map_err(|_| StateError::InvalidData)?;
                                let hint = schedule::add(
                                    duration.as_secs(),
                                    u64::from(duration.subsec_nanos() != 0),
                                )?;
                                delay.max(hint.saturating_sub(now))
                            } else {
                                delay
                            }
                        }
                    };
                    certificate.ari_check_at_unix = schedule::add(now, delay)?;
                    storage(
                        store.save_host(host.clone()),
                        &hosts,
                        engine,
                        clock,
                        status,
                        &mut published,
                        &overrides,
                    )
                    .await?;
                }
            }
        }
        hosts[index] = host;
        busy[index] = false;
        ari_aborts[index] = None;
    }
}

#[cfg(test)]
mod tests;
