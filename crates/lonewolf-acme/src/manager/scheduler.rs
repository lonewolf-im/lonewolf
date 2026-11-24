// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use futures_util::FutureExt;
use futures_util::future::{AbortHandle, Abortable, Either, LocalBoxFuture, select};
use futures_util::stream::{FuturesUnordered, StreamExt};

use super::{
    Clock, Engine, HostEvent, ManagerError, Publication, StatusHandle, Storage, event, fatal,
    housekeeping, issue_due,
};
use crate::issuer::RenewalWindow;
use crate::schedule;
use crate::types::{
    AttemptFailure, AttemptSuccess, CertificateValidity, FailureKind, RetryState, StateError,
    StoredCertificate, StoredHost,
};

const MAX_JOBS: usize = 2;

enum Completed {
    Account(Result<(), AttemptFailure>),
    Host(usize, HostOutcome),
}

enum HostOutcome {
    Cancelled,
    Issued(Result<AttemptSuccess, AttemptFailure>, Option<RetryState>),
    RenewalInfo(
        Result<Option<RenewalWindow>, AttemptFailure>,
        Option<Vec<Vec<u8>>>,
    ),
}

#[derive(Clone)]
enum HostJob {
    Idle,
    Issuing,
    RenewalInfo(AbortHandle),
}

#[derive(PartialEq)]
enum AccountState {
    Needed,
    Preparing,
    Ready,
}

struct Scheduler<'a, S, E, C> {
    store: &'a S,
    engine: &'a E,
    clock: &'a C,
    status: &'a StatusHandle,
    profile: Option<&'a str>,
    hosts: Vec<StoredHost>,
    published: Vec<Publication>,
    overrides: Vec<Option<CertificateValidity>>,
    active: Vec<HostJob>,
    account: AccountState,
    jobs: FuturesUnordered<LocalBoxFuture<'a, Completed>>,
}

pub(super) async fn drive(
    store: &impl Storage,
    engine: &impl Engine,
    clock: &impl Clock,
    hosts: Vec<StoredHost>,
    status: &StatusHandle,
    profile: Option<&str>,
) -> Result<(), ManagerError> {
    let published = hosts
        .iter()
        .zip(status.inner.lock().iter())
        .map(|(host, (_, snapshot))| {
            (
                host.certificate
                    .as_ref()
                    .map(|cert| cert.material.chain.clone()),
                snapshot.generation > 0,
            )
        })
        .collect();
    let mut scheduler = Scheduler {
        store,
        engine,
        clock,
        status,
        profile,
        published,
        overrides: vec![None; hosts.len()],
        active: vec![HostJob::Idle; hosts.len()],
        hosts,
        account: AccountState::Needed,
        jobs: FuturesUnordered::new(),
    };
    let mut candidates = Vec::with_capacity(scheduler.hosts.len());
    loop {
        let account = scheduler.await_storage(store.account()).await?;
        let next = scheduler.schedule(account.map(|a| a.retry), &mut candidates)?;
        if let Some(completed) = scheduler.wait(next).await? {
            scheduler.complete(completed).await?;
        }
    }
}

#[derive(Clone, Copy)]
struct Candidate {
    due: u64,
    index: usize,
    renewal_info: bool,
}

impl<'a, S: Storage, E: Engine, C: Clock> Scheduler<'a, S, E, C> {
    async fn await_storage<T>(
        &mut self,
        work: impl Future<Output = Result<T, StateError>>,
    ) -> Result<T, ManagerError> {
        let mut work = pin!(work);
        loop {
            let now = self.housekeeping()?;
            let mut next = now.saturating_add(60);
            for (index, host) in self.hosts.iter().enumerate() {
                let validity = self.overrides[index].or_else(|| {
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
            let timer = pin!(
                self.clock
                    .sleep(Duration::from_secs(next.saturating_sub(now).clamp(1, 60)))
            );
            if let Either::Left((result, _)) = select(work.as_mut(), timer).await {
                return result.map_err(Into::into);
            }
        }
    }

    fn schedule(
        &mut self,
        retry: Option<RetryState>,
        candidates: &mut Vec<Candidate>,
    ) -> Result<u64, ManagerError> {
        let now = self.housekeeping()?;
        let floor = retry.map_or(0, |r| r.not_before_unix);
        self.update_deadlines(now, floor);
        let mut next = now.saturating_add(60);
        candidates.clear();
        for index in 0..self.hosts.len() {
            if let Some(job) = self.candidate(index, now, floor, &mut next) {
                candidates.push(job);
            }
        }
        candidates.sort_unstable_by_key(|job| (job.due, &self.hosts[job.index].host.dns_name));
        self.start_jobs(candidates, retry);
        Ok(next)
    }

    fn housekeeping(&mut self) -> Result<u64, ManagerError> {
        housekeeping(
            &self.hosts,
            self.engine,
            self.clock,
            self.status,
            &mut self.published,
            &self.overrides,
        )
    }

    fn update_deadlines(&self, now: u64, floor: u64) {
        let mut snapshots = self.status.inner.lock();
        for (host, (_, snapshot)) in self.hosts.iter().zip(snapshots.iter_mut()) {
            let next_attempt = issue_due(host, now, self.profile).max(floor);
            if snapshot.next_attempt_unix != Some(next_attempt) {
                tracing::debug!(host = %host.host.xmpp_domain, phase = "schedule", retry_seconds = next_attempt.saturating_sub(now), "ACME attempt scheduled");
            }
            snapshot.next_attempt_unix = Some(next_attempt);
        }
    }

    fn candidate(&self, index: usize, now: u64, floor: u64, next: &mut u64) -> Option<Candidate> {
        let host = &self.hosts[index];
        if !self.published[index].1
            && let Some(cert) = host
                .certificate
                .as_ref()
                .filter(|c| now < c.not_before_unix)
        {
            *next = (*next).min(cert.not_before_unix);
        }
        let issuance = issue_due(host, now, self.profile).max(floor);
        match &self.active[index] {
            HostJob::Issuing => return None,
            HostJob::RenewalInfo(abort) => {
                *next = (*next).min(issuance.max(now));
                if issuance <= now {
                    abort.abort();
                }
                return None;
            }
            HostJob::Idle => {}
        }
        let ari = host
            .certificate
            .as_ref()
            .filter(|cert| now < cert.not_after_unix)
            .map(|cert| cert.ari_check_at_unix.max(floor))
            .filter(|due| *due < issuance && now < issuance);
        let due = ari.unwrap_or(issuance);
        if self.account != AccountState::Preparing || due > now {
            *next = (*next).min(due.max(now));
        }
        (due <= now).then_some(Candidate {
            due,
            index,
            renewal_info: ari.is_some(),
        })
    }

    fn start_jobs(&mut self, candidates: &[Candidate], retry: Option<RetryState>) {
        if candidates.is_empty() || self.jobs.len() >= MAX_JOBS {
            return;
        }
        match self.account {
            AccountState::Preparing => {}
            AccountState::Needed => {
                self.account = AccountState::Preparing;
                let engine = self.engine;
                self.jobs.push(
                    async move { Completed::Account(engine.ensure_account().await) }.boxed_local(),
                );
            }
            AccountState::Ready => {
                for job in candidates.iter().take(MAX_JOBS - self.jobs.len()) {
                    self.start_host(*job, retry);
                }
            }
        }
    }

    fn start_host(&mut self, job: Candidate, retry: Option<RetryState>) {
        let index = job.index;
        let host = self.hosts[index].clone();
        let engine = self.engine;
        if job.renewal_info {
            let generation = host
                .certificate
                .as_ref()
                .map(|cert| cert.material.chain.clone());
            let (abort, registration) = AbortHandle::new_pair();
            self.active[index] = HostJob::RenewalInfo(abort);
            self.jobs.push(
                async move {
                    let outcome = match Abortable::new(engine.ari(host), registration).await {
                        Ok(result) => HostOutcome::RenewalInfo(result, generation),
                        Err(_) => HostOutcome::Cancelled,
                    };
                    Completed::Host(index, outcome)
                }
                .boxed_local(),
            );
        } else {
            self.active[index] = HostJob::Issuing;
            {
                let mut snapshots = self.status.inner.lock();
                let attempts = &mut snapshots[index].1.attempts;
                *attempts = attempts.saturating_add(1);
            }
            self.jobs.push(
                async move {
                    Completed::Host(index, HostOutcome::Issued(engine.issue(host).await, retry))
                }
                .boxed_local(),
            );
        }
    }

    async fn wait(&mut self, next: u64) -> Result<Option<Completed>, ManagerError> {
        let wait = Duration::from_secs(next.saturating_sub(self.clock.now()?).clamp(1, 60));
        if self.jobs.is_empty() {
            self.clock.idle_sleep(wait).await;
            return Ok(None);
        }
        Ok(
            match select(pin!(self.jobs.next()), pin!(self.clock.sleep(wait))).await {
                Either::Left((result, _)) => result,
                Either::Right(_) => None,
            },
        )
    }

    async fn complete(&mut self, completed: Completed) -> Result<(), ManagerError> {
        match completed {
            Completed::Account(Ok(())) => self.account = AccountState::Ready,
            Completed::Account(Err(error)) => {
                check_failure(error)?;
                self.account = AccountState::Needed;
                tracing::warn!(phase = "account", outcome = ?error.kind, "ACME account will retry");
            }
            Completed::Host(index, outcome) => self.complete_host(index, outcome).await?,
        }
        Ok(())
    }

    async fn complete_host(
        &mut self,
        index: usize,
        outcome: HostOutcome,
    ) -> Result<(), ManagerError> {
        match outcome {
            HostOutcome::Issued(Ok(success), _) => self.installed(index, success.validity),
            HostOutcome::Issued(Err(error), _) | HostOutcome::RenewalInfo(Err(error), _) => {
                check_failure(error)?
            }
            _ => {}
        }
        let mut host = self.reload(index).await?;
        let now = self.clock.now()?;
        match outcome {
            HostOutcome::Cancelled => {}
            HostOutcome::Issued(result, retry) => {
                match result {
                    Ok(_) => self.reset_retry(retry).await?,
                    Err(error) => self.issue_failed(index, &host, error, now).await?,
                }
                event(
                    &mut self.status.inner.lock()[index].1,
                    HostEvent::AttemptOutcome,
                );
            }
            HostOutcome::RenewalInfo(result, generation) => {
                if update_renewal_info(&mut host, generation.as_deref(), result, self.clock, now)? {
                    self.await_storage(self.store.save_host(host.clone()))
                        .await?;
                }
            }
        }
        self.hosts[index] = host;
        self.active[index] = HostJob::Idle;
        Ok(())
    }

    fn installed(&mut self, index: usize, validity: CertificateValidity) {
        self.overrides[index] = Some(validity);
        self.published[index] = (None, true);
        let mut snapshots = self.status.inner.lock();
        let snapshot = &mut snapshots[index].1;
        tracing::info!(host = %self.hosts[index].host.xmpp_domain, phase = "issuance", outcome = if snapshot.generation == 0 { "issued" } else { "rotated" }, not_after = validity.not_after_unix, profile = self.profile, "ACME certificate installed");
        snapshot.successes = snapshot.successes.saturating_add(1);
        snapshot.generation = snapshot.generation.saturating_add(1);
        snapshot.not_after_unix = Some(validity.not_after_unix);
        event(snapshot, HostEvent::Installed);
    }

    async fn reload(&mut self, index: usize) -> Result<StoredHost, ManagerError> {
        let host = self
            .await_storage(self.store.host(self.hosts[index].host.dns_name.clone()))
            .await?
            .ok_or(StateError::CorruptData)?;
        if let Some(validity) = self.overrides[index] {
            let cert = host.certificate.as_ref().ok_or(StateError::CorruptData)?;
            if cert.not_before_unix != validity.not_before_unix
                || cert.not_after_unix != validity.not_after_unix
            {
                return Err(StateError::CorruptData.into());
            }
            self.hosts[index] = host.clone();
            self.status.inner.lock()[index].1.profile = cert.profile.as_deref().map(Arc::from);
            self.published[index] = (Some(cert.material.chain.clone()), true);
            self.overrides[index] = None;
        }
        Ok(host)
    }

    async fn reset_retry(&mut self, previous: Option<RetryState>) -> Result<(), ManagerError> {
        if let Some(mut account) = self.await_storage(self.store.account()).await?
            && Some(account.retry) == previous
            && account.retry.failures > 0
        {
            account.retry = RetryState {
                failures: 0,
                not_before_unix: 0,
            };
            self.await_storage(self.store.save_account(account)).await?;
        }
        Ok(())
    }

    async fn issue_failed(
        &mut self,
        index: usize,
        host: &StoredHost,
        error: AttemptFailure,
        now: u64,
    ) -> Result<(), ManagerError> {
        if error.kind == FailureKind::ProfileNotOffered {
            tracing::error!(host = %host.host.xmpp_domain, phase = "issuance", outcome = "profile_not_offered", profile = self.profile, retry_seconds = host.retry.not_before_unix.saturating_sub(now), "ACME certificate profile not offered");
        } else if error.kind != FailureKind::Deferred {
            tracing::warn!(host = %host.host.xmpp_domain, phase = "issuance", outcome = ?error.kind, retry_seconds = host.retry.not_before_unix.saturating_sub(now), "ACME certificate will retry");
        }
        {
            let mut snapshots = self.status.inner.lock();
            let snapshot = &mut snapshots[index].1;
            if error.kind == FailureKind::Deferred {
                snapshot.attempts = snapshot.attempts.saturating_sub(1);
            } else {
                let count = &mut snapshot.failures[error.kind as usize];
                *count = count.saturating_add(1);
            }
            event(snapshot, HostEvent::NextRetry);
        }
        if error.kind == FailureKind::Account {
            self.defer_account(error, now).await?;
        }
        Ok(())
    }

    async fn defer_account(&mut self, error: AttemptFailure, now: u64) -> Result<(), ManagerError> {
        let mut account = self
            .await_storage(self.store.account())
            .await?
            .ok_or(StateError::CorruptData)?;
        account.retry.failures = account.retry.failures.saturating_add(1);
        let lifetime = self
            .hosts
            .iter()
            .filter_map(|h| h.certificate.as_ref())
            .map(StoredCertificate::lifetime)
            .min();
        let delay = schedule::retry_delay(account.retry.failures, lifetime, |max| {
            self.clock.uniform(max)
        })?;
        account.retry.not_before_unix = account
            .retry
            .not_before_unix
            .max(schedule::add(now, delay)?)
            .max(retry_floor(error)?);
        self.await_storage(self.store.save_account(account)).await?;
        if self.account == AccountState::Ready {
            self.account = AccountState::Needed;
        }
        Ok(())
    }
}

fn check_failure(error: AttemptFailure) -> Result<(), ManagerError> {
    if error.state_error.is_some() || error.kind == FailureKind::State {
        return Err(fatal(error));
    }
    Ok(())
}

fn retry_floor(error: AttemptFailure) -> Result<u64, StateError> {
    let Some(hint) = error.retry_not_before else {
        return Ok(0);
    };
    let duration = hint
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StateError::InvalidData)?;
    schedule::add(duration.as_secs(), u64::from(duration.subsec_nanos() != 0))
}

fn update_renewal_info(
    host: &mut StoredHost,
    generation: Option<&[Vec<u8>]>,
    result: Result<Option<RenewalWindow>, AttemptFailure>,
    clock: &impl Clock,
    now: u64,
) -> Result<bool, ManagerError> {
    let Some(cert) = host
        .certificate
        .as_mut()
        .filter(|c| generation == Some(c.material.chain.as_slice()) && now < c.not_after_unix)
    else {
        return Ok(false);
    };
    let delay = match result {
        Ok(Some(window)) => renewal_window(cert, window, clock)?,
        Ok(None) => 43_200,
        Err(error) => {
            tracing::warn!(host = %host.host.xmpp_domain, phase = "renewal_info", outcome = ?error.kind, "ACME renewal information will retry");
            cert.ari_failures = cert.ari_failures.saturating_add(1);
            let delay = schedule::ari_delay(
                cert.ari_failures,
                matches!(
                    error.kind,
                    FailureKind::Network | FailureKind::Timeout | FailureKind::RateLimited
                ),
            );
            delay.max(retry_floor(error)?.saturating_sub(now))
        }
    };
    cert.ari_check_at_unix = schedule::add(now, delay)?;
    Ok(true)
}

fn renewal_window(
    cert: &mut StoredCertificate,
    window: RenewalWindow,
    clock: &impl Clock,
) -> Result<u64, StateError> {
    cert.ari_failures = 0;
    if let (Some(start), Some(end)) = (window.start, window.end)
        && schedule::apply_window(cert, start, end, |max| clock.uniform(max))?
    {
        return Ok(window.delay.max(60));
    }
    cert.ari_window = None;
    cert.renew_at_unix = cert.fallback_at_unix;
    Ok(43_200)
}
