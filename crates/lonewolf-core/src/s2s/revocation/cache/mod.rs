// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime};

use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::LocalBoxFuture;
use parking_lot::Mutex as PlMutex;
use tracing::instrument::WithSubscriber;

use crate::hosts::revocation::CrlNumber;
use crate::s2s::log_domain;
use crate::s2s::metrics::{CrlEviction, CrlFetchOutcome, S2sMetrics};

use super::fetch::{CrlUrl, FetchFailure, FetchedCrl};
use super::{CheckPhase, CrlLease, FetchSignal, UnknownReason};

fn saturating_add(time: SystemTime, duration: Duration) -> SystemTime {
    if let Some(result) = time.checked_add(duration) {
        return result;
    }
    let mut low = 0;
    let mut high = duration.as_nanos();
    let mut latest = time;
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        let candidate = Duration::new(
            (middle / 1_000_000_000) as u64,
            (middle % 1_000_000_000) as u32,
        );
        if let Some(result) = time.checked_add(candidate) {
            low = middle;
            latest = result;
        } else {
            high = middle - 1;
        }
    }
    latest
}

pub(crate) const STALE_GRACE: Duration = Duration::from_secs(7 * 24 * 3600);
pub(crate) type FetchFn = Arc<
    dyn Fn(CrlUrl, SystemTime) -> LocalBoxFuture<'static, Result<FetchedCrl, FetchFailure>>
        + Send
        + Sync,
>;

#[derive(Clone, Copy, Debug)]
pub(crate) struct CacheLimits {
    pub(crate) max_entries: usize,
    pub(crate) max_bytes: usize,
}

impl CacheLimits {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) const DEFAULT: Self = Self {
        max_entries: 256,
        max_bytes: 64 * 1024 * 1024,
    };
}

#[cfg_attr(not(test), expect(dead_code))]
pub(crate) struct CachedCrl {
    pub(crate) crl: webpki::CertRevocationList<'static>,
    pub(crate) this_update: SystemTime,
    pub(crate) next_update: SystemTime,
    pub(crate) crl_number: Option<CrlNumber>,
    pub(crate) cost: usize,
    pub(crate) refresh_at: SystemTime,
}

#[cfg_attr(not(test), expect(dead_code))]
pub(crate) struct Lookup {
    pub(crate) crl: Option<Arc<CachedCrl>>,
    pub(crate) unknown: Option<UnknownReason>,
    pub(crate) pending: Option<FetchSignal>,
    pub(crate) lease: Option<CrlLease>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Fetch(FetchFailure),
    Rollback,
    Capacity,
}

impl Failure {
    fn unknown(self) -> UnknownReason {
        match self {
            Self::Fetch(
                FetchFailure::DnsFailed | FetchFailure::ConnectFailed | FetchFailure::HttpStatus,
            ) => UnknownReason::FetchFailed,
            Self::Fetch(FetchFailure::BlockedAddress) => UnknownReason::BlockedAddress,
            Self::Fetch(FetchFailure::Timeout) => UnknownReason::Timeout,
            Self::Fetch(FetchFailure::TooLarge) => UnknownReason::TooLarge,
            Self::Fetch(FetchFailure::Invalid) => UnknownReason::Invalid,
            Self::Fetch(FetchFailure::Stale) | Self::Rollback => UnknownReason::Stale,
            Self::Capacity => UnknownReason::CacheFull,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Fetch(failure) => fetch_outcome(failure).as_str(),
            Self::Rollback => "rollback",
            Self::Capacity => "cache_full",
        }
    }
}

fn fetch_outcome(failure: FetchFailure) -> CrlFetchOutcome {
    match failure {
        FetchFailure::DnsFailed => CrlFetchOutcome::DnsFailed,
        FetchFailure::BlockedAddress => CrlFetchOutcome::BlockedAddress,
        FetchFailure::ConnectFailed => CrlFetchOutcome::ConnectFailed,
        FetchFailure::Timeout => CrlFetchOutcome::Timeout,
        FetchFailure::HttpStatus => CrlFetchOutcome::HttpStatus,
        FetchFailure::TooLarge => CrlFetchOutcome::TooLarge,
        FetchFailure::Invalid => CrlFetchOutcome::Invalid,
        FetchFailure::Stale => CrlFetchOutcome::Stale,
    }
}

struct Entry {
    crl: Option<Arc<CachedCrl>>,
    pending: Option<FetchSignal>,
    failures: u32,
    retry_after: Option<SystemTime>,
    last_failure: Option<Failure>,
    last_logged: Option<Failure>,
    last_access: SystemTime,
    handshake_used_at: Option<SystemTime>,
    token: Arc<()>,
}

impl Entry {
    fn new(now: SystemTime) -> Self {
        Self {
            crl: None,
            pending: None,
            failures: 0,
            retry_after: None,
            last_failure: None,
            last_logged: None,
            last_access: now,
            handshake_used_at: None,
            token: Arc::new(()),
        }
    }

    fn in_use(&self, now: SystemTime, refresh: Duration) -> bool {
        self.pending.is_some()
            || Arc::strong_count(&self.token) > 1
            || self
                .handshake_used_at
                .is_some_and(|used| now < saturating_add(used, refresh))
    }

    fn failed(&mut self, failure: Failure, now: SystemTime, effects: &mut Effects) {
        self.failures = self.failures.saturating_add(1);
        let seconds = (60u64 * (1u64 << self.failures.saturating_sub(1).min(6))).min(3600);
        self.retry_after = Some(saturating_add(now, Duration::from_secs(seconds)));
        self.last_failure = Some(failure);
        if self.last_logged != Some(failure) {
            effects.log = Some(LogEvent::Failed(failure));
        }
        self.last_logged = Some(failure);
    }
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<CrlUrl, Entry>,
    bytes: usize,
    full: bool,
}

impl CacheState {
    fn set_full(&mut self, full: bool, effects: &mut Effects) {
        if self.full != full {
            self.full = full;
            effects.full = Some(full);
        }
    }

    fn sweep(&mut self, now: SystemTime, refresh: Duration, effects: &mut Effects) {
        let Self { entries, bytes, .. } = self;
        entries.retain(|_, entry| {
            let reason = if entry
                .crl
                .as_ref()
                .is_some_and(|crl| now >= saturating_add(crl.next_update, STALE_GRACE))
            {
                Some(CrlEviction::StaleExpired)
            } else if !entry.in_use(now, refresh)
                && (entry.crl.as_ref().is_some_and(|crl| now >= crl.next_update)
                    || (entry.crl.is_none() && entry.retry_after.is_none_or(|retry| now >= retry)))
            {
                Some(CrlEviction::Unused)
            } else {
                None
            };
            if let Some(reason) = reason {
                *bytes -= entry.crl.as_ref().map_or(0, |crl| crl.cost);
                effects.evictions[reason as usize] += 1;
                false
            } else {
                true
            }
        });
    }

    fn evict(&mut self, now: SystemTime, refresh: Duration, effects: &mut Effects) -> bool {
        let victim = self
            .entries
            .iter()
            .filter(|(_, entry)| !entry.in_use(now, refresh))
            .min_by_key(|(_, entry)| entry.last_access)
            .map(|(url, _)| url.clone());
        if let Some(url) = victim
            && let Some(entry) = self.entries.remove(&url)
        {
            self.bytes -= entry.crl.as_ref().map_or(0, |crl| crl.cost);
            effects.evictions[CrlEviction::Capacity as usize] += 1;
            true
        } else {
            false
        }
    }
}

enum LogEvent {
    Failed(Failure),
    Recovered,
    Fetched,
}

#[derive(Default)]
struct Effects {
    evictions: [usize; 3],
    full: Option<bool>,
    log: Option<LogEvent>,
}

impl Effects {
    fn emit(self, metrics: &S2sMetrics, url: &CrlUrl) {
        for reason in CrlEviction::ALL {
            for _ in 0..self.evictions[reason as usize] {
                metrics.crl_cache_evicted(reason);
            }
        }
        if let Some(full) = self.full {
            if full {
                tracing::warn!("s2s CRL cache full");
            } else {
                tracing::info!("s2s CRL cache has room");
            }
        }
        match self.log {
            Some(LogEvent::Failed(failure)) => {
                tracing::warn!(crl_host = %log_domain(url.host()), outcome = failure.as_str(), "s2s CRL fetch failed")
            }
            Some(LogEvent::Recovered) => {
                tracing::info!(crl_host = %log_domain(url.host()), "s2s CRL fetch recovered")
            }
            Some(LogEvent::Fetched) => {
                tracing::debug!(crl_host = %log_domain(url.host()), "s2s CRL fetched")
            }
            None => {}
        }
    }
}

pub(crate) struct CrlCache {
    fetch: FetchFn,
    state: PlMutex<CacheState>,
    limits: CacheLimits,
    refresh_interval: Duration,
    metrics: Arc<S2sMetrics>,
}

impl CrlCache {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn new(
        fetch: FetchFn,
        metrics: Arc<S2sMetrics>,
        limits: CacheLimits,
        refresh_interval: Duration,
    ) -> Arc<Self> {
        metrics.crl_cache_size(0, 0);
        Arc::new(Self {
            fetch,
            state: PlMutex::new(CacheState::default()),
            limits,
            refresh_interval,
            metrics,
        })
    }

    /// Must run on a Compio runtime; starts at most one detached download per URL.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn lookup(
        self: &Arc<Self>,
        url: &CrlUrl,
        now: SystemTime,
        phase: CheckPhase,
    ) -> Lookup {
        self.lookup_with_clock(url, now, phase, Instant::now)
    }

    fn lookup_with_clock<N: Fn() -> Instant + 'static>(
        self: &Arc<Self>,
        url: &CrlUrl,
        now: SystemTime,
        phase: CheckPhase,
        monotonic_now: N,
    ) -> Lookup {
        let mut effects = Effects::default();
        let mut start = None;
        let lookup = {
            let mut state = self.state.lock();
            state.sweep(now, self.refresh_interval, &mut effects);
            if !state.entries.contains_key(url)
                && state.entries.len() >= self.limits.max_entries
                && !state.evict(now, self.refresh_interval, &mut effects)
            {
                state.set_full(true, &mut effects);
                self.metrics
                    .crl_cache_size(state.entries.len(), state.bytes);
                Lookup {
                    crl: None,
                    unknown: Some(UnknownReason::CacheFull),
                    pending: None,
                    lease: None,
                }
            } else {
                let mut access = |entry: &mut Entry| {
                    entry.last_access = now;
                    if phase == CheckPhase::Handshake {
                        entry.handshake_used_at = Some(now);
                    }
                    if entry.pending.is_none()
                        && entry.retry_after.is_none_or(|retry| now >= retry)
                        && entry.crl.as_ref().is_none_or(|crl| now >= crl.refresh_at)
                    {
                        let (sender, receiver) = oneshot::channel::<()>();
                        entry.pending = Some(receiver.map(|_| ()).boxed().shared());
                        start = Some((sender, Arc::downgrade(&entry.token), monotonic_now()));
                    }
                    let unknown = if entry.crl.as_ref().is_some_and(|crl| now < crl.next_update) {
                        None
                    } else if entry.pending.is_some() {
                        Some(UnknownReason::Pending)
                    } else if entry.crl.is_some() {
                        Some(UnknownReason::Stale)
                    } else {
                        Some(
                            entry
                                .last_failure
                                .map_or(UnknownReason::Unavailable, Failure::unknown),
                        )
                    };
                    Lookup {
                        crl: entry.crl.clone(),
                        unknown,
                        pending: entry.pending.clone(),
                        lease: Some(CrlLease(Arc::clone(&entry.token))),
                    }
                };
                let lookup = match state.entries.get_mut(url) {
                    Some(entry) => access(entry),
                    None => access(
                        state
                            .entries
                            .entry(url.clone())
                            .or_insert_with(|| Entry::new(now)),
                    ),
                };
                self.metrics
                    .crl_cache_size(state.entries.len(), state.bytes);
                lookup
            }
        };
        effects.emit(&self.metrics, url);
        if let Some((sender, generation, started)) = start {
            let cache = Arc::clone(self);
            let url = url.clone();
            compio::runtime::spawn(
                async move {
                    let result = (cache.fetch)(url.clone(), now).await;
                    let elapsed = monotonic_now().saturating_duration_since(started);
                    let completed_at = saturating_add(now, elapsed);
                    cache.complete(&url, &generation, result, completed_at, elapsed);
                    drop(sender);
                }
                .with_current_subscriber(),
            )
            .detach();
        }
        lookup
    }

    fn complete(
        &self,
        url: &CrlUrl,
        generation: &Weak<()>,
        result: Result<FetchedCrl, FetchFailure>,
        now: SystemTime,
        elapsed: Duration,
    ) {
        let mut effects = Effects::default();
        let mut outcome = result.as_ref().map_or_else(
            |failure| fetch_outcome(*failure),
            |_| CrlFetchOutcome::Success,
        );
        {
            let mut state = self.state.lock();
            let current = state
                .entries
                .get(url)
                .is_some_and(|entry| Weak::ptr_eq(generation, &Arc::downgrade(&entry.token)));
            if current {
                state.sweep(now, self.refresh_interval, &mut effects);
            }
            if current
                && state
                    .entries
                    .get(url)
                    .is_some_and(|entry| Weak::ptr_eq(generation, &Arc::downgrade(&entry.token)))
                && let Some(mut entry) = state.entries.remove(url)
            {
                match result {
                    Ok(fetched) => {
                        let rollback = entry.crl.as_ref().is_some_and(|old| {
                            match (&old.crl_number, &fetched.crl_number) {
                                (Some(old), Some(new)) => new < old,
                                _ => fetched.this_update < old.this_update,
                            }
                        });
                        if rollback {
                            outcome = CrlFetchOutcome::Rollback;
                            entry.failed(Failure::Rollback, now, &mut effects);
                        } else {
                            let cost = fetched.cost.checked_add(url.as_str().len());
                            let old_cost = entry.crl.as_ref().map_or(0, |crl| crl.cost);
                            while cost.is_some_and(|cost| {
                                cost <= self.limits.max_bytes
                                    && state.bytes - old_cost > self.limits.max_bytes - cost
                            }) && state.evict(now, self.refresh_interval, &mut effects)
                            {
                            }
                            if let Some(cost) = cost.filter(|cost| {
                                *cost <= self.limits.max_bytes
                                    && state.bytes - old_cost <= self.limits.max_bytes - cost
                            }) {
                                state.bytes = state.bytes - old_cost + cost;
                                let refresh_at = saturating_add(now, self.refresh_interval)
                                    .min(fetched.next_update);
                                entry.crl = Some(Arc::new(CachedCrl {
                                    crl: fetched.crl,
                                    this_update: fetched.this_update,
                                    next_update: fetched.next_update,
                                    crl_number: fetched.crl_number,
                                    cost,
                                    refresh_at,
                                }));
                                entry.failures = 0;
                                entry.retry_after = None;
                                entry.last_failure = None;
                                effects.log = Some(if entry.last_logged.take().is_some() {
                                    LogEvent::Recovered
                                } else {
                                    LogEvent::Fetched
                                });
                                state.set_full(false, &mut effects);
                            } else {
                                entry.failed(Failure::Capacity, now, &mut effects);
                                state.set_full(true, &mut effects);
                            }
                        }
                    }
                    Err(failure) => entry.failed(Failure::Fetch(failure), now, &mut effects),
                }
                entry.pending = None;
                state.entries.insert(url.clone(), entry);
                state.sweep(now, self.refresh_interval, &mut effects);
            }
            if current {
                self.metrics
                    .crl_cache_size(state.entries.len(), state.bytes);
            }
        }
        self.metrics.crl_fetched(outcome, elapsed);
        effects.emit(&self.metrics, url);
    }
}

#[cfg(test)]
mod tests;
