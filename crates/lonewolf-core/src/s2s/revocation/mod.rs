// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::SystemTime;

use futures_util::future::{BoxFuture, Shared};

use super::metrics::{AuthOutcome, StreamClose};

pub(crate) mod address;
pub(crate) mod fetch;

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
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) next_update: Option<SystemTime>,
    /// Downloaded CRLs must refresh at the earliest time of any used CRL.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) refresh_at: Option<SystemTime>,
    #[cfg_attr(not(test), expect(dead_code))]
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

    #[cfg_attr(not(test), expect(dead_code))]
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

    #[cfg_attr(not(test), expect(dead_code))]
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

    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn needs_rechecks(&self) -> bool {
        self.recheckable
    }
}

#[cfg(test)]
mod tests;
