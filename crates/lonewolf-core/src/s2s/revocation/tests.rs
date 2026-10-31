// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::FutureExt;

use super::*;

#[test]
fn verdicts_apply_source_policy_to_every_status() {
    let statuses = [
        (RevocationStatus::Good, None, None),
        (
            RevocationStatus::Revoked,
            Some("certificate_revoked"),
            Some("certificate_revoked"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::NoDistributionPoint),
            Some("revocation_unavailable"),
            Some("revocation_unavailable"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::UnsupportedScheme),
            Some("revocation_unavailable"),
            Some("revocation_unavailable"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::BlockedAddress),
            Some("revocation_unavailable"),
            Some("revocation_unavailable"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::FetchFailed),
            Some("revocation_unavailable"),
            Some("revocation_unavailable"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::Timeout),
            Some("revocation_unavailable"),
            Some("revocation_unavailable"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::Pending),
            Some("revocation_unavailable"),
            Some("revocation_unavailable"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::TooLarge),
            Some("revocation_unavailable"),
            Some("revocation_unavailable"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::Invalid),
            Some("revocation_unavailable"),
            Some("revocation_unavailable"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::BadSignature),
            Some("revocation_unavailable"),
            Some("revocation_unavailable"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::Stale),
            Some("revocation_stale"),
            Some("revocation_stale"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::NotAuthoritative),
            Some("revocation_unknown"),
            Some("revocation_unknown"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::Unavailable),
            Some("revocation_unavailable"),
            Some("revocation_unavailable"),
        ),
        (
            RevocationStatus::Unknown(UnknownReason::CacheFull),
            Some("revocation_unavailable"),
            Some("revocation_unavailable"),
        ),
    ];
    for source in RevocationSource::ALL {
        for (index, (status, auth, close)) in statuses.into_iter().enumerate() {
            assert_eq!(RevocationStatus::ALL[index], status);
            assert_eq!(status.index(), index);
            let accepted = match source {
                RevocationSource::File => index == 0,
                RevocationSource::Fetched => index != 1,
            };
            for recheckable in [false, true] {
                let verdict = RevocationVerdict {
                    source,
                    status,
                    next_update: None,
                    refresh_at: None,
                    pending: Vec::new(),
                    leases: Vec::new(),
                    recheckable,
                };
                assert_eq!(verdict.accepts(), accepted, "{source:?}: {status:?}");
                assert_eq!(
                    verdict.auth_outcome().map(AuthOutcome::as_str),
                    if accepted { None } else { auth }
                );
                assert_eq!(
                    verdict.close_reason().map(StreamClose::as_str),
                    if accepted { None } else { close }
                );
                assert_eq!(verdict.needs_rechecks(), recheckable);
            }
        }
    }
}

#[test]
fn revocation_labels_and_indexes_are_fixed_and_unique() {
    let labels = [
        "no_distribution_point",
        "unsupported_scheme",
        "blocked_address",
        "fetch_failed",
        "timeout",
        "pending",
        "too_large",
        "invalid",
        "bad_signature",
        "stale",
        "not_authoritative",
        "unavailable",
        "cache_full",
    ];
    for (index, reason) in UnknownReason::ALL.into_iter().enumerate() {
        assert_eq!(reason as usize, index);
        assert_eq!(reason.as_str(), labels[index]);
        assert!(!labels[..index].contains(&reason.as_str()));
    }
    for (index, source) in RevocationSource::ALL.into_iter().enumerate() {
        assert_eq!(source as usize, index);
        assert_eq!(source.as_str(), ["file", "fetched"][index]);
    }
    for (index, phase) in CheckPhase::ALL.into_iter().enumerate() {
        assert_eq!(phase as usize, index);
        assert_eq!(phase.as_str(), ["handshake", "recheck"][index]);
    }
}

#[test]
fn cloned_verdict_retains_cache_leases_and_shares_completion() {
    let lease = Arc::new(());
    let completions = Arc::new(AtomicUsize::new(0));
    let completed = Arc::clone(&completions);
    let pending = async move {
        completed.fetch_add(1, Ordering::Relaxed);
    }
    .boxed()
    .shared();
    let next_update = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(3600));
    let refresh_at = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(600));
    let verdict = RevocationVerdict {
        source: RevocationSource::Fetched,
        status: RevocationStatus::Unknown(UnknownReason::Pending),
        next_update,
        refresh_at,
        pending: vec![pending],
        leases: vec![CrlLease(Arc::clone(&lease))],
        recheckable: true,
    };
    let clone = verdict.clone();
    assert_eq!(Arc::strong_count(&lease), 3);
    assert!(Arc::ptr_eq(&verdict.leases[0].0, &clone.leases[0].0));
    assert_eq!(clone.next_update, next_update);
    assert_eq!(clone.refresh_at, refresh_at);
    assert_eq!(verdict.pending[0].clone().now_or_never(), Some(()));
    assert_eq!(clone.pending[0].clone().now_or_never(), Some(()));
    assert_eq!(completions.load(Ordering::Relaxed), 1);
    drop(verdict);
    assert_eq!(Arc::strong_count(&lease), 2);
    drop(clone);
    assert_eq!(Arc::strong_count(&lease), 1);
}
