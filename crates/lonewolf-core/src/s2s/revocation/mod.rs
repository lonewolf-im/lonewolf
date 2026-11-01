// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use lonewolf_util::blocking::BlockingExecutor;
use parking_lot::Mutex as PlMutex;
use rustls::pki_types::{CertificateDer, UnixTime};

use crate::config::{S2sConfig, limits::S2sLimits};
use crate::hosts::peer_identity::PeerTrust;
use crate::hosts::revocation::{CrlLoadError, CrlSet, RevocationRules};
use crate::s2s::dns::Resolver;
use crate::s2s::metrics::{Direction, S2sMetrics};

use super::metrics::{AuthOutcome, StreamClose};

pub(crate) mod address;
pub(crate) mod cache;
pub(crate) mod fetch;
mod fetched;

#[derive(Clone)]
pub(crate) struct PeerVerification {
    pub(crate) trust: Arc<PeerTrust>,
    pub(crate) revocation: Arc<PeerRevocation>,
}

enum Source {
    Disabled,
    File {
        trust: Arc<PeerTrust>,
        path: Arc<Path>,
        last: Arc<PlMutex<Option<Result<u64, CrlLoadError>>>>,
    },
    Fetched {
        trust: Arc<PeerTrust>,
        cache: Arc<cache::CrlCache>,
    },
}

pub(crate) struct PeerRevocation {
    source: Source,
    verifier: BlockingExecutor,
    metrics: Arc<S2sMetrics>,
    wait: Duration,
    recheck_interval: Duration,
}

impl PeerRevocation {
    pub(crate) fn new(
        config: &S2sConfig,
        limits: &S2sLimits,
        trust: Arc<PeerTrust>,
        resolver: Arc<Resolver>,
        metrics: Arc<S2sMetrics>,
        recheck_interval: Duration,
    ) -> Result<Arc<Self>, RevocationStartupError> {
        let source = if let Some(path) = &config.tls.crls_path {
            let last = Arc::new(PlMutex::new(None));
            let loaded = CrlSet::load_for_startup(path, SystemTime::now());
            report_file_load(
                &metrics,
                &last,
                loaded
                    .as_ref()
                    .map(CrlSet::next_update)
                    .map_err(|error| *error),
            );
            if let Err(error @ (CrlLoadError::Unreadable | CrlLoadError::Invalid)) = loaded {
                return Err(RevocationStartupError::CrlFile(error));
            }
            Source::File {
                trust,
                path: Arc::from(path.as_path()),
                last,
            }
        } else if config.tls.fetch_crls {
            let policy = if config.tls.trust_anchors_path.is_some() {
                address::AddressPolicy::Any
            } else {
                address::AddressPolicy::PublicOnly
            };
            #[cfg(feature = "test-support")]
            let policy = if crate::test_support::s2s_crl_public_destinations_only() {
                address::AddressPolicy::PublicOnly
            } else {
                policy
            };
            let fetcher = Arc::new(fetch::CrlFetcher::new(
                resolver,
                policy,
                fetch::FetchLimits::DEFAULT,
            ));
            let fetch: cache::FetchFn = Arc::new(move |url, now| {
                let fetcher = Arc::clone(&fetcher);
                async move { fetcher.fetch(&url, now).await }.boxed_local()
            });
            Source::Fetched {
                trust,
                cache: cache::CrlCache::new(
                    fetch,
                    Arc::clone(&metrics),
                    cache::CacheLimits::DEFAULT,
                    recheck_interval,
                ),
            }
        } else {
            Source::Disabled
        };
        Ok(Arc::new(Self {
            source,
            verifier: BlockingExecutor::new(const { NonZeroUsize::new(2).unwrap() }),
            metrics,
            wait: Duration::from_secs(2)
                .min(Duration::from_secs(limits.negotiation_timeout_secs.get()) / 4),
            recheck_interval,
        }))
    }

    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn disabled() -> Arc<Self> {
        Arc::new(Self {
            source: Source::Disabled,
            verifier: BlockingExecutor::new(NonZeroUsize::MIN),
            metrics: S2sMetrics::new(0),
            wait: Duration::ZERO,
            recheck_interval: crate::hosts::revocation::RECHECK_INTERVAL,
        })
    }

    pub(crate) fn recheck_interval(&self) -> Duration {
        self.recheck_interval
    }

    pub(crate) async fn check(
        &self,
        chain: Arc<[CertificateDer<'static>]>,
        direction: Direction,
        phase: CheckPhase,
    ) -> Option<RevocationVerdict> {
        self.check_at(chain, direction, phase, SystemTime::now())
            .await
    }

    async fn check_at(
        &self,
        chain: Arc<[CertificateDer<'static>]>,
        direction: Direction,
        phase: CheckPhase,
        now: SystemTime,
    ) -> Option<RevocationVerdict> {
        self.check_at_with_loader(chain, direction, phase, now, CrlSet::load)
            .await
    }

    async fn check_at_with_loader<L>(
        &self,
        chain: Arc<[CertificateDer<'static>]>,
        direction: Direction,
        phase: CheckPhase,
        now: SystemTime,
        load: L,
    ) -> Option<RevocationVerdict>
    where
        L: FnOnce(&Path, SystemTime) -> Result<CrlSet, CrlLoadError> + Send + 'static,
    {
        let verdict = match &self.source {
            Source::Disabled => return None,
            Source::Fetched { trust, cache } => {
                fetched::check(trust, cache, &self.verifier, chain, now, phase, self.wait).await
            }
            Source::File { trust, path, last } => {
                let trust = Arc::clone(trust);
                let path = Arc::clone(path);
                let last = Arc::clone(last);
                let metrics = Arc::clone(&self.metrics);
                self.verifier
                    .run(move || {
                        let loaded = load(&path, now);
                        report_file_load(
                            &metrics,
                            &last,
                            loaded
                                .as_ref()
                                .map(CrlSet::next_update)
                                .map_err(|error| *error),
                        );
                        let mut verdict = RevocationVerdict {
                            source: RevocationSource::File,
                            status: RevocationStatus::Unknown(UnknownReason::Unavailable),
                            next_update: None,
                            refresh_at: None,
                            pending: Vec::new(),
                            leases: Vec::new(),
                            recheckable: true,
                        };
                        let set = match loaded {
                            Ok(set) => set,
                            Err(error) => {
                                verdict.status = RevocationStatus::Unknown(match error {
                                    CrlLoadError::Stale => UnknownReason::Stale,
                                    CrlLoadError::Unreadable => UnknownReason::Unavailable,
                                    CrlLoadError::Invalid => UnknownReason::Invalid,
                                });
                                return verdict;
                            }
                        };
                        let Ok(elapsed) = now.duration_since(UNIX_EPOCH) else {
                            return verdict;
                        };
                        let crls: Vec<_> = set.lists().iter().collect();
                        verdict.status = match trust.check_crls(
                            &chain,
                            UnixTime::since_unix_epoch(elapsed),
                            RevocationRules {
                                crls: &crls,
                                unknown: webpki::UnknownStatusPolicy::Deny,
                                expiration: webpki::ExpirationPolicy::Enforce,
                            },
                        ) {
                            Ok(()) => {
                                verdict.next_update = Some(set.next_update());
                                RevocationStatus::Good
                            }
                            Err(webpki::Error::CertRevoked) => RevocationStatus::Revoked,
                            Err(webpki::Error::UnknownRevocationStatus) => {
                                RevocationStatus::Unknown(UnknownReason::NotAuthoritative)
                            }
                            Err(webpki::Error::CrlExpired { .. }) => {
                                RevocationStatus::Unknown(UnknownReason::Stale)
                            }
                            Err(error) if fetched::signature_error(&error) => {
                                RevocationStatus::Unknown(UnknownReason::BadSignature)
                            }
                            Err(_) => RevocationStatus::Unknown(UnknownReason::Unavailable),
                        };
                        verdict
                    })
                    .await
            }
        };
        self.metrics.revocation_checked(direction, phase, &verdict);
        Some(verdict)
    }
}

#[derive(Debug)]
pub(crate) enum RevocationStartupError {
    CrlFile(CrlLoadError),
}

impl fmt::Display for RevocationStartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CrlFile(CrlLoadError::Unreadable) => "cannot read s2s.tls.crls_path",
            Self::CrlFile(CrlLoadError::Invalid) => "s2s.tls.crls_path holds invalid CRLs",
            Self::CrlFile(CrlLoadError::Stale) => "s2s.tls.crls_path holds stale CRLs",
        })
    }
}
impl std::error::Error for RevocationStartupError {}

fn report_file_load(
    metrics: &S2sMetrics,
    last: &PlMutex<Option<Result<u64, CrlLoadError>>>,
    outcome: Result<SystemTime, CrlLoadError>,
) {
    match outcome {
        Ok(next_update) => metrics.crl_file_loaded(next_update),
        Err(error) => metrics.crl_file_load_failed(error),
    }
    let outcome = outcome.map(|next_update| {
        next_update
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    });
    let changed = last.lock().replace(outcome) != Some(outcome);
    if changed {
        match outcome {
            Ok(secs) => tracing::info!(next_update_unix = secs, "s2s revocation lists loaded"),
            Err(error) => tracing::error!(reason = error.as_str(), "s2s revocation lists unusable"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RevocationSource {
    File,
    Fetched,
}

impl RevocationSource {
    pub(crate) const ALL: [Self; 2] = [Self::File, Self::Fetched];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Fetched => "fetched",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CheckPhase {
    Handshake,
    Recheck,
}

impl CheckPhase {
    pub(crate) const ALL: [Self; 2] = [Self::Handshake, Self::Recheck];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::Recheck => "recheck",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnknownReason {
    NoDistributionPoint,
    UnsupportedScheme,
    BlockedAddress,
    FetchFailed,
    Timeout,
    Pending,
    TooLarge,
    Invalid,
    BadSignature,
    Stale,
    NotAuthoritative,
    Unavailable,
    CacheFull,
}

impl UnknownReason {
    pub(crate) const ALL: [Self; 13] = [
        Self::NoDistributionPoint,
        Self::UnsupportedScheme,
        Self::BlockedAddress,
        Self::FetchFailed,
        Self::Timeout,
        Self::Pending,
        Self::TooLarge,
        Self::Invalid,
        Self::BadSignature,
        Self::Stale,
        Self::NotAuthoritative,
        Self::Unavailable,
        Self::CacheFull,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NoDistributionPoint => "no_distribution_point",
            Self::UnsupportedScheme => "unsupported_scheme",
            Self::BlockedAddress => "blocked_address",
            Self::FetchFailed => "fetch_failed",
            Self::Timeout => "timeout",
            Self::Pending => "pending",
            Self::TooLarge => "too_large",
            Self::Invalid => "invalid",
            Self::BadSignature => "bad_signature",
            Self::Stale => "stale",
            Self::NotAuthoritative => "not_authoritative",
            Self::Unavailable => "unavailable",
            Self::CacheFull => "cache_full",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RevocationStatus {
    Good,
    Revoked,
    Unknown(UnknownReason),
}

impl RevocationStatus {
    pub(crate) const ALL: [Self; 15] = [
        Self::Good,
        Self::Revoked,
        Self::Unknown(UnknownReason::ALL[0]),
        Self::Unknown(UnknownReason::ALL[1]),
        Self::Unknown(UnknownReason::ALL[2]),
        Self::Unknown(UnknownReason::ALL[3]),
        Self::Unknown(UnknownReason::ALL[4]),
        Self::Unknown(UnknownReason::ALL[5]),
        Self::Unknown(UnknownReason::ALL[6]),
        Self::Unknown(UnknownReason::ALL[7]),
        Self::Unknown(UnknownReason::ALL[8]),
        Self::Unknown(UnknownReason::ALL[9]),
        Self::Unknown(UnknownReason::ALL[10]),
        Self::Unknown(UnknownReason::ALL[11]),
        Self::Unknown(UnknownReason::ALL[12]),
    ];

    pub(crate) fn index(self) -> usize {
        match self {
            Self::Good => 0,
            Self::Revoked => 1,
            Self::Unknown(reason) => 2 + reason as usize,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Revoked => "revoked",
            Self::Unknown(_) => "unknown",
        }
    }

    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Good | Self::Revoked => "none",
            Self::Unknown(reason) => reason.as_str(),
        }
    }
}

pub(crate) type FetchSignal = Shared<BoxFuture<'static, ()>>;

#[derive(Clone)]
pub(crate) struct CrlLease(#[cfg_attr(not(test), expect(dead_code))] pub(crate) Arc<()>);

#[derive(Clone)]
pub(crate) struct RevocationVerdict {
    pub(crate) source: RevocationSource,
    pub(crate) status: RevocationStatus,
    /// The earliest static-file nextUpdate caps the link lifetime.
    pub(crate) next_update: Option<SystemTime>,
    /// The earliest future cached refresh schedules a live-link recheck.
    pub(crate) refresh_at: Option<SystemTime>,
    /// A ready signal still requires a recheck of the lookup snapshot.
    pub(crate) pending: Vec<FetchSignal>,
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) leases: Vec<CrlLease>,
    /// False means that a recheck cannot change the outcome.
    pub(crate) recheckable: bool,
}

impl RevocationVerdict {
    pub(crate) fn accepts(&self) -> bool {
        match self.source {
            RevocationSource::File => self.status == RevocationStatus::Good,
            RevocationSource::Fetched => self.status != RevocationStatus::Revoked,
        }
    }

    pub(crate) fn auth_outcome(&self) -> Option<AuthOutcome> {
        if self.accepts() {
            return None;
        }
        Some(match self.status {
            RevocationStatus::Revoked => AuthOutcome::CertificateRevoked,
            RevocationStatus::Unknown(UnknownReason::NotAuthoritative) => {
                AuthOutcome::RevocationUnknown
            }
            RevocationStatus::Unknown(UnknownReason::Stale) => AuthOutcome::RevocationStale,
            RevocationStatus::Unknown(_) => AuthOutcome::RevocationUnavailable,
            RevocationStatus::Good => return None,
        })
    }

    pub(crate) fn close_reason(&self) -> Option<StreamClose> {
        if self.accepts() {
            return None;
        }
        Some(match self.status {
            RevocationStatus::Revoked => StreamClose::CertificateRevoked,
            RevocationStatus::Unknown(UnknownReason::NotAuthoritative) => {
                StreamClose::RevocationUnknown
            }
            RevocationStatus::Unknown(UnknownReason::Stale) => StreamClose::RevocationStale,
            RevocationStatus::Unknown(_) => StreamClose::RevocationUnavailable,
            RevocationStatus::Good => return None,
        })
    }

    pub(crate) fn needs_rechecks(&self) -> bool {
        self.recheckable
    }
}

#[cfg(test)]
mod tests;
