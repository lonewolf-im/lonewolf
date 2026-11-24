// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
#[cfg(test)]
use std::time::UNIX_EPOCH;
use std::time::{Duration, Instant};

#[cfg(test)]
use futures_util::FutureExt;
use futures_util::future::{Either, join, select};
use parking_lot::Mutex as PlMutex;

use crate::issuer::RenewalWindow;
use crate::schedule;
use crate::time::Time;
use crate::types::*;
use crate::{AcmeHttpClient, Challenges, Issuer, StateStore, TransportOptions};

pub const FAILURE_KIND_COUNT: usize = 10;
const EVENT_COUNT: usize = 5;

pub struct ManagerOptions {
    pub directory_url: String,
    pub state_path: PathBuf,
    pub ca_certificates_path: Option<PathBuf>,
    pub hosts: Vec<ManagedHost>,
    pub certificate_profile: Option<String>,
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
    pub profile: Option<Arc<str>>,
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
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Transport(error) => error.fmt(formatter),
            Self::Task => formatter.write_str("ACME manager task failed"),
            Self::Deadline => formatter.write_str("ACME manager drain deadline elapsed"),
        }
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
    started: bool,
    time: Time,
    profile: Option<Arc<str>>,
}

impl<I: Installer> Manager<I> {
    pub async fn load(
        options: ManagerOptions,
        challenges: Challenges,
        installer: I,
    ) -> Result<Self, ManagerError> {
        Self::with_time(options, challenges, installer, Time::default()).await
    }

    #[cfg(feature = "test-support")]
    pub async fn load_with_clock(
        options: ManagerOptions,
        challenges: Challenges,
        installer: I,
        clock: crate::test_support::TestClock,
    ) -> Result<Self, ManagerError> {
        Self::with_time(options, challenges, installer, Time::controlled(clock)).await
    }

    async fn with_time(
        options: ManagerOptions,
        challenges: Challenges,
        installer: I,
        time: Time,
    ) -> Result<Self, ManagerError> {
        let store = StateStore::open(options.state_path, options.directory_url.clone()).await?;
        let transport = AcmeHttpClient::new(TransportOptions {
            ca_certificates_path: options.ca_certificates_path,
        })
        .await
        .map_err(ManagerError::Transport)?;
        let profile = options.certificate_profile.as_deref().map(Arc::from);
        let issuer = Arc::new(
            Issuer::with_time(
                store.clone(),
                challenges.clone(),
                transport.clone(),
                options.directory_url,
                time.clone(),
                profile.clone(),
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
            let installed = prepare_cache(&record, &installer, || Clock::now(&time))?;
            let now = Clock::now(&time)?;
            let mut initial_state = state(&record, now);
            if initial_state == HostState::Ready && !installed {
                initial_state = HostState::Pending;
            }
            let mut status = HostStatus {
                state: initial_state,
                profile: record
                    .certificate
                    .as_ref()
                    .and_then(|cert| cert.profile.as_deref())
                    .map(Arc::from),
                not_after_unix: record.certificate.as_ref().map(|cert| cert.not_after_unix),
                next_attempt_unix: Some(issue_due(&record, now, profile.as_deref())),
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
            tracing::info!(host = %host.xmpp_domain, phase = "load", outcome = if installed { "ready" } else { "unavailable" }, not_after = status.not_after_unix, profile = status.profile.as_deref(), "ACME certificate loaded");
            if record
                .certificate
                .as_ref()
                .is_some_and(|cert| cert.profile.as_deref() != profile.as_deref())
            {
                tracing::info!(host = %host.xmpp_domain, phase = "schedule", outcome = "profile_changed", profile = profile.as_deref(), "ACME certificate profile changed");
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
            started: false,
            time,
            profile,
        })
    }

    pub fn status(&self) -> StatusHandle {
        self.status.clone()
    }

    /// Runs once. After a fatal error, the caller must drain the resources.
    pub async fn run(
        &mut self,
        shutdown: impl Future<Output = Instant>,
    ) -> Result<(), ManagerError> {
        if self.started {
            return Err(ManagerError::Task);
        }
        self.started = true;
        let cleanup = ClearChallenges(self.challenges.clone());
        let production = Production {
            issuer: self.issuer.clone(),
            installer: self.installer.clone(),
            time: self.time.clone(),
        };
        // Keep the scheduler future off the server thread stack.
        let scheduler = Box::pin(drive(
            &self.store,
            &production,
            &self.time,
            std::mem::take(&mut self.hosts),
            &self.status,
            self.profile.as_deref(),
        ));
        let result = until_shutdown(scheduler, shutdown).await;
        drop(cleanup);
        let deadline = result?;
        self.drain(deadline).await
    }

    /// Permanently closes admission and drains both resources using the caller's deadline.
    pub async fn drain(&mut self, deadline: Instant) -> Result<(), ManagerError> {
        self.started = true;
        self.challenges.clear();
        let (store, transport) =
            join(self.store.drain(deadline), self.transport.drain(deadline)).await;
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

struct ClearChallenges(Challenges);

impl Drop for ClearChallenges {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl<I: Installer> Drop for Manager<I> {
    fn drop(&mut self) {
        self.challenges.clear();
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
fn issue_due(record: &StoredHost, now: u64, profile: Option<&str>) -> u64 {
    record.retry.not_before_unix.max(
        record
            .certificate
            .as_ref()
            .filter(|cert| now < cert.not_after_unix && cert.profile.as_deref() == profile)
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
    async fn idle_sleep(&self, delay: Duration) {
        self.sleep(delay).await
    }
}
impl Clock for Time {
    fn now(&self) -> Result<u64, StateError> {
        self.unix()
    }
    fn uniform(&self, maximum: u64) -> Result<u64, StateError> {
        schedule::uniform(maximum)
    }
    async fn sleep(&self, delay: Duration) {
        Time::sleep(self, delay).await
    }
    async fn idle_sleep(&self, delay: Duration) {
        Time::idle_sleep(self, delay).await
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
    time: Time,
}
impl<I: Installer> Engine for Production<I> {
    fn publish_cache(&self, host: &StoredHost, _: u64) -> Result<bool, ManagerError> {
        prepare_cache(host, self.installer.as_ref(), || self.time.unix())
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
                tracing::info!(host = %host.host.xmpp_domain, phase = "cache", outcome = "ready", not_after = host.certificate.as_ref().map(|cert| cert.not_after_unix), profile = host.certificate.as_ref().and_then(|cert| cert.profile.as_deref()), "ACME certificate installed");
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
            tracing::warn!(host = %host.host.xmpp_domain, phase = "availability", outcome = ?current, not_after = snapshot.not_after_unix, "ACME certificate availability changed");
        }
    }
    Ok(now)
}

mod scheduler;
use scheduler::drive;

#[cfg(test)]
mod tests;
