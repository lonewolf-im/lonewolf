// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::future::join_all;
use lonewolf_util::blocking::BlockingExecutor;
use rustls::pki_types::{CertificateDer, UnixTime};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode, asn1::AnyRef};
use x509_cert::ext::pkix::{
    CrlDistributionPoints,
    name::{DistributionPointName, GeneralName},
};

use crate::hosts::peer_identity::PeerTrust;
use crate::hosts::revocation::RevocationRules;

use super::cache::{CachedCrl, CrlCache};
use super::fetch::CrlUrl;
use super::{
    CheckPhase, CrlLease, FetchSignal, RevocationSource, RevocationStatus, RevocationVerdict,
    UnknownReason,
};

struct CertificateUrls {
    urls: Vec<CrlUrl>,
    missing: UnknownReason,
    issuer: Vec<u8>,
    serial: Vec<u8>,
}

struct Prepared {
    path: Vec<CertificateDer<'static>>,
    certificates: Vec<CertificateUrls>,
}

fn prepare(trust: &PeerTrust, chain: &[CertificateDer<'_>], now: UnixTime) -> Result<Prepared, ()> {
    let path = trust.path_certificates(chain, now).map_err(|_| ())?;
    let mut certificates = Vec::with_capacity(path.len());
    let mut total = 0;
    for der in &path {
        let parsed: Certificate = Certificate::from_der(der.as_ref()).map_err(|_| ())?;
        let points = parsed
            .tbs_certificate()
            .get_extension::<CrlDistributionPoints>()
            .map_err(|_| ())?;
        let mut urls = Vec::new();
        let missing = if let Some((_, points)) = points {
            for point in points.0 {
                if point.reasons.is_some() || point.crl_issuer.is_some() {
                    continue;
                }
                let Some(DistributionPointName::FullName(names)) = point.distribution_point else {
                    continue;
                };
                for name in names {
                    if urls.len() < 4
                        && total < 8
                        && let GeneralName::UniformResourceIdentifier(uri) = name
                        && let Ok(url) = CrlUrl::parse(uri.as_str())
                        && !urls.contains(&url)
                    {
                        urls.push(url);
                        total += 1;
                    }
                }
            }
            UnknownReason::UnsupportedScheme
        } else {
            UnknownReason::NoDistributionPoint
        };
        let mut issuer = parsed.tbs_certificate().issuer().to_der().map_err(|_| ())?;
        let contents = AnyRef::from_der(&issuer).map_err(|_| ())?.value().len();
        // webpki compares only the value of the issuer's DER sequence.
        issuer.drain(..issuer.len() - contents);
        certificates.push(CertificateUrls {
            urls,
            missing,
            issuer,
            serial: parsed.tbs_certificate().serial_number().as_bytes().to_vec(),
        });
    }
    Ok(Prepared { path, certificates })
}

struct Candidate {
    fresh: Option<Arc<CachedCrl>>,
    stale: Vec<Arc<CachedCrl>>,
    reason: UnknownReason,
}

struct Batch {
    candidates: Vec<Candidate>,
    leases: Vec<CrlLease>,
    pending: Vec<FetchSignal>,
    refresh_at: Option<SystemTime>,
}

fn lookups(
    cache: &Arc<CrlCache>,
    prepared: &Prepared,
    now: SystemTime,
    phase: CheckPhase,
) -> Batch {
    let mut batch = Batch {
        candidates: Vec::with_capacity(prepared.certificates.len()),
        leases: Vec::new(),
        pending: Vec::new(),
        refresh_at: None,
    };
    for certificate in &prepared.certificates {
        let mut candidate = Candidate {
            fresh: None,
            stale: Vec::new(),
            reason: certificate.missing,
        };
        let mut reason = None;
        let mut waiting = false;
        for url in &certificate.urls {
            let lookup = cache.lookup(url, now, phase);
            if let Some(lease) = lookup.lease {
                batch.leases.push(lease);
            }
            if let Some(signal) = lookup.pending {
                waiting = true;
                if !batch.pending.iter().any(|pending| pending.ptr_eq(&signal)) {
                    batch.pending.push(signal);
                }
            }
            if reason.is_none() {
                reason = lookup.unknown;
            }
            if let Some(crl) = lookup.crl {
                if crl.refresh_at > now {
                    batch.refresh_at = Some(
                        batch
                            .refresh_at
                            .map_or(crl.refresh_at, |old| old.min(crl.refresh_at)),
                    );
                }
                if now < crl.next_update {
                    if candidate
                        .fresh
                        .as_ref()
                        .is_none_or(|old| crl.this_update > old.this_update)
                    {
                        candidate.fresh = Some(crl);
                    }
                } else {
                    candidate.stale.push(crl);
                }
            }
        }
        candidate.reason = if waiting {
            UnknownReason::Pending
        } else {
            reason.unwrap_or(certificate.missing)
        };
        batch.candidates.push(candidate);
    }
    batch
}

fn unknown(reason: UnknownReason) -> RevocationStatus {
    RevocationStatus::Unknown(reason)
}

#[allow(deprecated)]
fn signature_error(error: &webpki::Error) -> bool {
    matches!(
        error,
        webpki::Error::InvalidCrlSignatureForPublicKey
            | webpki::Error::UnsupportedCrlSignatureAlgorithm
            | webpki::Error::UnsupportedCrlSignatureAlgorithmContext(_)
            | webpki::Error::UnsupportedCrlSignatureAlgorithmForPublicKey
            | webpki::Error::UnsupportedCrlSignatureAlgorithmForPublicKeyContext(_)
            | webpki::Error::IssuerNotCrlSigner
    )
}

fn pass(
    trust: &PeerTrust,
    path: &[CertificateDer<'_>],
    now: UnixTime,
    crls: &[&webpki::CertRevocationList<'_>],
    policy: webpki::UnknownStatusPolicy,
) -> Result<(), webpki::Error> {
    trust.check_crls(
        path,
        now,
        RevocationRules {
            crls,
            unknown: policy,
            expiration: webpki::ExpirationPolicy::Ignore,
        },
    )
}

fn verify(
    trust: &PeerTrust,
    prepared: &Prepared,
    candidates: &mut [Candidate],
    now: UnixTime,
) -> RevocationStatus {
    let fresh: Vec<_> = candidates
        .iter()
        .filter_map(|candidate| candidate.fresh.as_ref().map(|crl| &crl.crl))
        .collect();
    if !fresh.is_empty() {
        match pass(
            trust,
            &prepared.path,
            now,
            &fresh,
            webpki::UnknownStatusPolicy::Allow,
        ) {
            Err(webpki::Error::CertRevoked) => return RevocationStatus::Revoked,
            Err(error) if signature_error(&error) => {
                for candidate in candidates.iter_mut() {
                    let Some(crl) = &candidate.fresh else {
                        continue;
                    };
                    match pass(
                        trust,
                        &prepared.path,
                        now,
                        &[&crl.crl],
                        webpki::UnknownStatusPolicy::Allow,
                    ) {
                        Err(webpki::Error::CertRevoked) => return RevocationStatus::Revoked,
                        Err(error) if signature_error(&error) => {
                            candidate.fresh = None;
                            candidate.reason = UnknownReason::BadSignature;
                        }
                        Err(_) => return unknown(UnknownReason::Unavailable),
                        Ok(()) => {}
                    }
                }
            }
            Err(_) => return unknown(UnknownReason::Unavailable),
            Ok(()) => {}
        }
    }
    for candidate in candidates.iter_mut() {
        for crl in &candidate.stale {
            match pass(
                trust,
                &prepared.path,
                now,
                &[&crl.crl],
                webpki::UnknownStatusPolicy::Allow,
            ) {
                Err(webpki::Error::CertRevoked) => {
                    for certificate in &prepared.certificates {
                        if certificate.issuer == crl.crl.issuer()
                            && crl.crl.find_serial(&certificate.serial).is_ok_and(|entry| {
                                entry.is_some_and(|entry| {
                                    entry.reason_code
                                        != Some(webpki::RevocationReason::CertificateHold)
                                })
                            })
                        {
                            return RevocationStatus::Revoked;
                        }
                    }
                    candidate.reason = UnknownReason::Stale;
                }
                Err(error) if signature_error(&error) => {
                    candidate.reason = UnknownReason::BadSignature
                }
                _ => candidate.reason = UnknownReason::Stale,
            }
        }
    }
    if let Some(candidate) = candidates
        .iter()
        .find(|candidate| candidate.fresh.is_none())
    {
        return unknown(candidate.reason);
    }
    let fresh: Vec<_> = candidates
        .iter()
        .filter_map(|candidate| candidate.fresh.as_ref().map(|crl| &crl.crl))
        .collect();
    match pass(
        trust,
        &prepared.path,
        now,
        &fresh,
        webpki::UnknownStatusPolicy::Deny,
    ) {
        Ok(()) => RevocationStatus::Good,
        Err(webpki::Error::UnknownRevocationStatus) => unknown(UnknownReason::NotAuthoritative),
        Err(_) => unknown(UnknownReason::Unavailable),
    }
}

pub(super) async fn check(
    trust: &Arc<PeerTrust>,
    cache: &Arc<CrlCache>,
    executor: &BlockingExecutor,
    chain: Arc<[CertificateDer<'static>]>,
    now: SystemTime,
    phase: CheckPhase,
    wait: Duration,
) -> RevocationVerdict {
    let verdict = RevocationVerdict {
        source: RevocationSource::Fetched,
        status: unknown(UnknownReason::Unavailable),
        next_update: None,
        refresh_at: None,
        pending: Vec::new(),
        leases: Vec::new(),
        recheckable: false,
    };
    let Ok(duration) = now.duration_since(UNIX_EPOCH) else {
        return verdict;
    };
    let unix = UnixTime::since_unix_epoch(duration);
    let verifier = Arc::clone(trust);
    let Ok(prepared) = executor.run(move || prepare(&verifier, &chain, unix)).await else {
        return verdict;
    };
    let mut batch = lookups(cache, &prepared, now, phase);
    if phase == CheckPhase::Handshake
        && batch.candidates.iter().any(|candidate| {
            candidate.fresh.is_none() && candidate.reason == UnknownReason::Pending
        })
        && !batch.pending.is_empty()
    {
        let _ = compio::time::timeout(wait, join_all(batch.pending.iter().cloned())).await;
        batch = lookups(cache, &prepared, now, phase);
    }
    finish_snapshot(trust, executor, prepared, batch, unix).await
}

async fn finish_snapshot(
    trust: &Arc<PeerTrust>,
    executor: &BlockingExecutor,
    prepared: Prepared,
    batch: Batch,
    unix: UnixTime,
) -> RevocationVerdict {
    let recheckable = prepared
        .certificates
        .iter()
        .any(|certificate| !certificate.urls.is_empty());
    let Batch {
        mut candidates,
        leases,
        pending,
        refresh_at,
    } = batch;
    let status = if candidates
        .iter()
        .all(|candidate| candidate.fresh.is_none() && candidate.stale.is_empty())
    {
        unknown(
            candidates
                .first()
                .map_or(UnknownReason::Unavailable, |candidate| candidate.reason),
        )
    } else {
        let verifier = Arc::clone(trust);
        executor
            .run(move || verify(&verifier, &prepared, &mut candidates, unix))
            .await
    };
    RevocationVerdict {
        source: RevocationSource::Fetched,
        status,
        next_update: None,
        refresh_at,
        pending,
        leases,
        recheckable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s2s::revocation::cache::CacheLimits;
    use crate::s2s::revocation::{
        Source,
        tests::{FetchedFixture, LEAF_CRL, ROOT_CRL, Script, checked, fixture_time},
    };
    use compio::runtime::Runtime;
    use futures_util::FutureExt;
    use std::error::Error;

    #[test]
    fn completed_download_signals_stay_with_the_snapshot_they_invalidated()
    -> Result<(), Box<dyn Error>> {
        let fixture = FetchedFixture::new(&[LEAF_CRL])?;
        for old_fresh in [false, true] {
            let script = Arc::new(Script::default());
            if old_fresh {
                script.ready(LEAF_CRL, Ok(fixture.crl(false, None, false, 10000)?));
            }
            script.ready(ROOT_CRL, Ok(fixture.crl(true, None, false, 10000)?));
            let (release, entered) = script.held(
                LEAF_CRL,
                Ok(fixture.crl(false, Some((3, None)), false, 10000)?),
            );
            let peer = fixture.peer(&script, Duration::ZERO, CacheLimits::DEFAULT);
            Runtime::new()?.block_on(async {
                let Source::Fetched { cache, .. } = &peer.source else {
                    return Err("missing cache".into());
                };
                if old_fresh {
                    let initial = cache.lookup(
                        &CrlUrl::parse(LEAF_CRL).map_err(|_| "bad URL")?,
                        fixture_time(),
                        CheckPhase::Handshake,
                    );
                    initial.pending.ok_or("no initial fetch")?.await;
                }
                let root_time =
                    fixture_time() + Duration::from_secs(if old_fresh { 1000 } else { 0 });
                let root = cache.lookup(
                    &CrlUrl::parse(ROOT_CRL).map_err(|_| "bad URL")?,
                    root_time,
                    CheckPhase::Handshake,
                );
                root.pending.ok_or("no root fetch")?.await;
                let now = fixture_time() + Duration::from_secs(if old_fresh { 3601 } else { 0 });
                let unix = UnixTime::since_unix_epoch(now.duration_since(UNIX_EPOCH)?);
                let trust = Arc::clone(&fixture.trust);
                let chain = Arc::clone(&fixture.chain);
                let prepared = peer
                    .verifier
                    .run(move || prepare(&trust, &chain, unix))
                    .await
                    .map_err(|_| "path preparation failed")?;
                let batch = lookups(cache, &prepared, now, CheckPhase::Recheck);
                assert_eq!(batch.pending.len(), 1);
                let completion = batch.pending[0].clone();
                entered.await?;
                release.send(()).map_err(|_| "download dropped")?;
                completion.await;
                let verdict =
                    finish_snapshot(&fixture.trust, &peer.verifier, prepared, batch, unix).await;
                assert_eq!(
                    verdict.status,
                    if old_fresh {
                        RevocationStatus::Good
                    } else {
                        unknown(UnknownReason::Pending)
                    }
                );
                assert_eq!(verdict.pending.len(), 1);
                assert_eq!(verdict.pending[0].clone().now_or_never(), Some(()));
                let updated =
                    checked(&peer, Arc::clone(&fixture.chain), now, CheckPhase::Recheck).await?;
                assert_eq!(updated.status, RevocationStatus::Revoked);
                assert!(updated.pending.is_empty());
                Ok::<(), Box<dyn Error>>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn overdue_pending_or_backoff_urls_do_not_hide_future_refreshes() -> Result<(), Box<dyn Error>>
    {
        let fixture = FetchedFixture::new(&[LEAF_CRL, ROOT_CRL])?;
        for held in [false, true] {
            let script = Arc::new(Script::default());
            script.ready(LEAF_CRL, Ok(fixture.crl(false, None, false, 10000)?));
            script.ready(ROOT_CRL, Ok(fixture.crl(true, None, false, 10000)?));
            let gate = if held {
                Some(script.held(LEAF_CRL, Ok(fixture.crl(false, None, false, 10000)?)))
            } else {
                script.ready(LEAF_CRL, Err(super::super::fetch::FetchFailure::HttpStatus));
                None
            };
            let peer = fixture.peer(&script, Duration::ZERO, CacheLimits::DEFAULT);
            Runtime::new()?.block_on(async {
                let Source::Fetched { cache, .. } = &peer.source else {
                    return Err("missing cache".into());
                };
                let a = CrlUrl::parse(LEAF_CRL).map_err(|_| "bad URL")?;
                let b = CrlUrl::parse(ROOT_CRL).map_err(|_| "bad URL")?;
                cache
                    .lookup(&a, fixture_time(), CheckPhase::Handshake)
                    .pending
                    .ok_or("missing fetch")?
                    .await;
                let b_time = fixture_time() + Duration::from_secs(1000);
                cache
                    .lookup(&b, b_time, CheckPhase::Handshake)
                    .pending
                    .ok_or("missing fetch")?
                    .await;
                let future_refresh = cache
                    .lookup(&b, b_time, CheckPhase::Recheck)
                    .crl
                    .ok_or("missing cached CRL")?
                    .refresh_at;
                let now = fixture_time() + Duration::from_secs(3601);
                let pending = cache
                    .lookup(&a, now, CheckPhase::Recheck)
                    .pending
                    .ok_or("missing refresh")?;
                if !held {
                    pending.clone().await;
                }
                let mut prepared = Prepared {
                    path: Vec::new(),
                    certificates: vec![CertificateUrls {
                        urls: vec![a, b],
                        missing: UnknownReason::NoDistributionPoint,
                        issuer: Vec::new(),
                        serial: Vec::new(),
                    }],
                };
                let batch = lookups(cache, &prepared, now, CheckPhase::Recheck);
                assert_eq!(batch.refresh_at, Some(future_refresh));
                assert!(future_refresh > now);
                assert_eq!(batch.pending.len(), usize::from(held));
                prepared.certificates[0].urls.pop();
                let overdue = lookups(cache, &prepared, now, CheckPhase::Recheck);
                assert!(overdue.refresh_at.is_none());
                assert_eq!(overdue.pending.len(), usize::from(held));
                if let Some((release, entered)) = gate {
                    entered.await?;
                    assert!(batch.pending[0].ptr_eq(&pending));
                    assert!(release.send(()).is_ok());
                    pending.await;
                }
                Ok::<_, Box<dyn Error>>(())
            })?;
        }
        Ok(())
    }
}
