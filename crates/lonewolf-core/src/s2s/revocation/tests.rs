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

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fs;
use std::time::Instant;

use compio::runtime::Runtime;
use futures_channel::oneshot;
use graviola::hashing::Sha256;
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey};
use parking_lot::Mutex as PlMutex;
use prometheus_client::registry::Registry;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
    CrlDistributionPoint, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyUsagePurpose,
    RevokedCertParams,
};

use crate::hosts::revocation::parse_crl;
use cache::{CacheLimits, CrlCache, FetchFn};
use fetch::{CrlUrl, FetchFailure, FetchedCrl};

pub(super) const LEAF_CRL: &str = "http://ca.example/leaf.crl";
pub(super) const ROOT_CRL: &str = "http://ca.example/root.crl";
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Signer {
    key: SigningKey<P256>,
    public: [u8; 65],
}
impl Signer {
    fn new() -> TestResult<Self> {
        let key = SigningKey::<P256> {
            private_key: StaticPrivateKey::new_random()?,
        };
        Ok(Self {
            public: key.private_key.public_key_uncompressed(),
            key,
        })
    }
}
impl rcgen::PublicKeyData for Signer {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
impl rcgen::SigningKey for Signer {
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut signature = [0; 80];
        self.key
            .sign_asn1::<Sha256>(&[bytes], &mut signature)
            .map(<[u8]>::to_vec)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

pub(super) fn fixture_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}
fn parameters(name: &str, serial: u64, ca: bool) -> TestResult<CertificateParams> {
    let mut params = CertificateParams::new(vec![format!("{name}.example")])?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.serial_number = Some(serial.into());
    params.not_before = (fixture_time() - Duration::from_secs(86400)).into();
    params.not_after = (fixture_time() + Duration::from_secs(30 * 86400)).into();
    params.key_identifier_method = KeyIdMethod::PreSpecified(vec![serial as u8]);
    if ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    } else {
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    }
    Ok(params)
}

pub(super) struct FetchedFixture {
    root: CertifiedIssuer<'static, Signer>,
    issuer: CertifiedIssuer<'static, Signer>,
    pub(super) chain: Arc<[CertificateDer<'static>]>,
    pub(super) trust: Arc<PeerTrust>,
    _directory: tempfile::TempDir,
}
impl FetchedFixture {
    pub(super) fn new(leaf_urls: &[&str]) -> TestResult<Self> {
        let root = CertifiedIssuer::self_signed(parameters("root", 1, true)?, Signer::new()?)?;
        let mut params = parameters("issuer", 2, true)?;
        params.crl_distribution_points.push(CrlDistributionPoint {
            uris: vec![ROOT_CRL.into()],
        });
        let issuer = CertifiedIssuer::signed_by(params, Signer::new()?, &root)?;
        let mut params = parameters("peer", 3, false)?;
        if !leaf_urls.is_empty() {
            params.crl_distribution_points.push(CrlDistributionPoint {
                uris: leaf_urls.iter().map(|uri| (*uri).into()).collect(),
            });
        }
        let leaf = params.signed_by(&Signer::new()?, &issuer)?;
        let directory = tempfile::tempdir()?;
        let roots = directory.path().join("roots.pem");
        use base64::Engine;
        fs::write(
            &roots,
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                base64::engine::general_purpose::STANDARD.encode(root.der())
            ),
        )?;
        let trust = PeerTrust::load(
            &crate::config::S2sTlsConfig {
                trust_anchors_path: Some(roots),
                ..Default::default()
            },
            Arc::new(rustls_graviola::default_provider()),
        )?;
        let chain = Arc::from([leaf.der().clone(), issuer.der().clone()]);
        Ok(Self {
            root,
            issuer,
            chain,
            trust,
            _directory: directory,
        })
    }

    pub(super) fn crl(
        &self,
        root: bool,
        revoked: Option<(u64, Option<rcgen::RevocationReason>)>,
        corrupt: bool,
        expires: u64,
    ) -> TestResult<FetchedCrl> {
        make_crl(
            if root { &self.root } else { &self.issuer },
            if root { 1 } else { 2 },
            revoked,
            corrupt,
            expires,
        )
    }

    pub(super) fn peer(
        &self,
        script: &Arc<Script>,
        wait: Duration,
        limits: CacheLimits,
    ) -> Arc<PeerRevocation> {
        let metrics = S2sMetrics::new(0);
        Arc::new(PeerRevocation {
            source: Source::Fetched {
                trust: Arc::clone(&self.trust),
                cache: CrlCache::new(
                    script.fetch(),
                    Arc::clone(&metrics),
                    limits,
                    Duration::from_secs(3600),
                ),
            },
            verifier: BlockingExecutor::new(const { NonZeroUsize::new(2).unwrap() }),
            metrics,
            wait,
            recheck_interval: Duration::from_secs(3600),
        })
    }
}

fn make_crl(
    issuer: &CertifiedIssuer<'_, Signer>,
    key_id: u8,
    revoked: Option<(u64, Option<rcgen::RevocationReason>)>,
    corrupt: bool,
    expires: u64,
) -> TestResult<FetchedCrl> {
    let crl = CertificateRevocationListParams {
        this_update: (fixture_time() - Duration::from_secs(60)).into(),
        next_update: (fixture_time() + Duration::from_secs(expires)).into(),
        crl_number: 1u64.into(),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .into_iter()
            .map(|(serial, reason)| RevokedCertParams {
                serial_number: serial.into(),
                revocation_time: fixture_time().into(),
                reason_code: reason,
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: KeyIdMethod::PreSpecified(vec![key_id]),
    }
    .signed_by(issuer)?;
    let mut der = crl.der().to_vec();
    if corrupt {
        *der.last_mut().ok_or("empty CRL")? ^= 1;
    }
    let parsed = parse_crl(&der, fixture_time()).map_err(|error| format!("{error:?}"))?;
    Ok(FetchedCrl {
        crl: parsed.crl,
        this_update: parsed.this_update,
        next_update: parsed.next_update,
        crl_number: parsed.crl_number,
        cost: parsed.cost,
    })
}

struct Step {
    result: Result<FetchedCrl, FetchFailure>,
    gate: Option<oneshot::Receiver<()>>,
    entered: Option<oneshot::Sender<()>>,
}
#[derive(Default)]
pub(super) struct Script {
    entries: PlMutex<HashMap<String, VecDeque<Step>>>,
    calls: AtomicUsize,
}
impl Script {
    pub(super) fn ready(&self, url: &str, result: Result<FetchedCrl, FetchFailure>) {
        self.entries
            .lock()
            .entry(url.into())
            .or_default()
            .push_back(Step {
                result,
                gate: None,
                entered: None,
            });
    }
    pub(super) fn held(
        &self,
        url: &str,
        result: Result<FetchedCrl, FetchFailure>,
    ) -> (oneshot::Sender<()>, oneshot::Receiver<()>) {
        let (release, gate) = oneshot::channel();
        let (entered, entry) = oneshot::channel();
        self.entries
            .lock()
            .entry(url.into())
            .or_default()
            .push_back(Step {
                result,
                gate: Some(gate),
                entered: Some(entered),
            });
        (release, entry)
    }
    fn fetch(self: &Arc<Self>) -> FetchFn {
        let script = Arc::clone(self);
        Arc::new(move |url, _| {
            script.calls.fetch_add(1, Ordering::Relaxed);
            let step = script
                .entries
                .lock()
                .get_mut(url.as_str())
                .and_then(VecDeque::pop_front);
            async move {
                let Some(step) = step else {
                    return Err(FetchFailure::HttpStatus);
                };
                if let Some(entered) = step.entered {
                    let _ = entered.send(());
                }
                if let Some(gate) = step.gate {
                    let _ = gate.await;
                }
                step.result
            }
            .boxed_local()
        })
    }
}
fn metric_text(metrics: &Arc<S2sMetrics>) -> TestResult<String> {
    let mut registry = Registry::default();
    metrics.register(registry.sub_registry_with_prefix("lonewolf"));
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry)?;
    Ok(text)
}
fn assert_metric(text: &str, sample: &str) {
    assert!(
        text.lines().any(|line| line == sample),
        "missing {sample} in {text}"
    );
}
pub(super) async fn checked(
    peer: &PeerRevocation,
    chain: Arc<[CertificateDer<'static>]>,
    now: SystemTime,
    phase: CheckPhase,
) -> TestResult<RevocationVerdict> {
    peer.check_at(chain, Direction::Inbound, phase, now)
        .await
        .ok_or("revocation disabled".into())
}

#[test]
fn fetched_fresh_crls_establish_coverage_and_find_any_chain_revocation() -> TestResult {
    let fixture = FetchedFixture::new(&[LEAF_CRL])?;
    for (leaf_revoked, issuer_revoked, missing, expected) in [
        (false, false, false, RevocationStatus::Good),
        (true, false, false, RevocationStatus::Revoked),
        (false, true, true, RevocationStatus::Revoked),
    ] {
        let script = Arc::new(Script::default());
        if !missing {
            script.ready(
                LEAF_CRL,
                Ok(fixture.crl(false, leaf_revoked.then_some((3, None)), false, 10000)?),
            );
        }
        script.ready(
            ROOT_CRL,
            Ok(fixture.crl(true, issuer_revoked.then_some((2, None)), false, 10000)?),
        );
        let peer = fixture.peer(&script, Duration::from_secs(1), CacheLimits::DEFAULT);
        Runtime::new()?.block_on(async {
            let verdict = checked(&peer, Arc::clone(&fixture.chain), fixture_time(), CheckPhase::Handshake).await?;
            assert_eq!(verdict.status, expected);
            assert_eq!(verdict.leases.len(), 2); assert!(verdict.pending.is_empty()); assert!(verdict.needs_rechecks());
            if expected == RevocationStatus::Good { assert_eq!(verdict.refresh_at, match &peer.source { Source::Fetched { cache, .. } => [LEAF_CRL, ROOT_CRL].into_iter().filter_map(|uri| CrlUrl::parse(uri).ok().and_then(|url| cache.lookup(&url, fixture_time(), CheckPhase::Recheck).crl.map(|crl| crl.refresh_at))).min(), _ => None }); }
            if expected == RevocationStatus::Revoked { assert_metric(&metric_text(&peer.metrics)?, "lonewolf_s2s_revocation_checks_total{direction=\"inbound\",source=\"fetched\",phase=\"handshake\",status=\"revoked\",reason=\"none\"} 1"); }
            Ok::<(), Box<dyn Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn fetched_bad_signatures_cannot_hide_another_crls_revocation() -> TestResult {
    let fixture = FetchedFixture::new(&[LEAF_CRL])?;
    for revoked in [false, true] {
        let script = Arc::new(Script::default());
        script.ready(LEAF_CRL, Ok(fixture.crl(false, None, true, 10000)?));
        if revoked {
            script.ready(
                ROOT_CRL,
                Ok(fixture.crl(true, Some((2, None)), false, 10000)?),
            );
        }
        let peer = fixture.peer(&script, Duration::from_secs(1), CacheLimits::DEFAULT);
        let verdict = Runtime::new()?.block_on(checked(
            &peer,
            Arc::clone(&fixture.chain),
            fixture_time(),
            CheckPhase::Handshake,
        ))?;
        assert_eq!(
            verdict.status,
            if revoked {
                RevocationStatus::Revoked
            } else {
                RevocationStatus::Unknown(UnknownReason::BadSignature)
            }
        );
    }
    let unrelated =
        CertifiedIssuer::self_signed(parameters("unrelated", 4, true)?, Signer::new()?)?;
    let script = Arc::new(Script::default());
    script.ready(LEAF_CRL, Ok(make_crl(&unrelated, 4, None, false, 10000)?));
    script.ready(ROOT_CRL, Ok(fixture.crl(true, None, false, 10000)?));
    let peer = fixture.peer(&script, Duration::from_secs(1), CacheLimits::DEFAULT);
    assert_eq!(
        Runtime::new()?
            .block_on(checked(
                &peer,
                Arc::clone(&fixture.chain),
                fixture_time(),
                CheckPhase::Handshake
            ))?
            .status,
        RevocationStatus::Unknown(UnknownReason::NotAuthoritative)
    );
    Ok(())
}

#[test]
fn fetched_distribution_point_absence_and_unsupported_schemes_stay_unknown() -> TestResult {
    for (urls, reason) in [
        (&[][..], UnknownReason::NoDistributionPoint),
        (
            &["https://ca.example/leaf.crl"][..],
            UnknownReason::UnsupportedScheme,
        ),
    ] {
        let fixture = FetchedFixture::new(urls)?;
        let script = Arc::new(Script::default());
        script.ready(ROOT_CRL, Ok(fixture.crl(true, None, false, 10000)?));
        let peer = fixture.peer(&script, Duration::from_secs(1), CacheLimits::DEFAULT);
        let verdict = Runtime::new()?.block_on(checked(
            &peer,
            Arc::clone(&fixture.chain),
            fixture_time(),
            CheckPhase::Handshake,
        ))?;
        assert_eq!(verdict.status, RevocationStatus::Unknown(reason));
        assert!(verdict.accepts());
        assert_metric(
            &metric_text(&peer.metrics)?,
            &format!(
                "lonewolf_s2s_revocation_checks_total{{direction=\"inbound\",source=\"fetched\",phase=\"handshake\",status=\"unknown\",reason=\"{}\"}} 1",
                reason.as_str()
            ),
        );
    }
    Ok(())
}

#[test]
fn fetched_stale_crls_establish_only_non_hold_revocation() -> TestResult {
    let fixture = FetchedFixture::new(&[LEAF_CRL])?;
    for (revoked, corrupt, expected) in [
        (
            Some((3, Some(rcgen::RevocationReason::KeyCompromise))),
            false,
            RevocationStatus::Revoked,
        ),
        (Some((3, None)), false, RevocationStatus::Revoked),
        (
            Some((3, Some(rcgen::RevocationReason::CertificateHold))),
            false,
            RevocationStatus::Unknown(UnknownReason::Stale),
        ),
        (None, false, RevocationStatus::Unknown(UnknownReason::Stale)),
        (
            Some((3, None)),
            true,
            RevocationStatus::Unknown(UnknownReason::BadSignature),
        ),
    ] {
        let script = Arc::new(Script::default());
        script.ready(LEAF_CRL, Ok(fixture.crl(false, revoked, corrupt, 5)?));
        script.ready(ROOT_CRL, Ok(fixture.crl(true, None, false, 10000)?));
        let peer = fixture.peer(&script, Duration::from_secs(1), CacheLimits::DEFAULT);
        Runtime::new()?.block_on(async {
            let retained = checked(
                &peer,
                Arc::clone(&fixture.chain),
                fixture_time(),
                CheckPhase::Handshake,
            )
            .await?;
            let stale = checked(
                &peer,
                Arc::clone(&fixture.chain),
                fixture_time() + Duration::from_secs(10),
                CheckPhase::Handshake,
            )
            .await?;
            assert_eq!(stale.status, expected);
            assert_eq!(stale.leases.len(), 2);
            drop(retained);
            Ok::<(), Box<dyn Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn fetched_waits_are_bounded_and_rechecks_never_wait() -> TestResult {
    let fixture = FetchedFixture::new(&[LEAF_CRL])?;
    let script = Arc::new(Script::default());
    let (release, entered) = script.held(LEAF_CRL, Ok(fixture.crl(false, None, false, 10000)?));
    script.ready(ROOT_CRL, Ok(fixture.crl(true, None, false, 10000)?));
    let peer = fixture.peer(&script, Duration::from_millis(30), CacheLimits::DEFAULT);
    Runtime::new()?.block_on(async {
        let started = Instant::now();
        let verdict = checked(
            &peer,
            Arc::clone(&fixture.chain),
            fixture_time(),
            CheckPhase::Handshake,
        )
        .await?;
        assert!(started.elapsed() >= Duration::from_millis(30));
        entered.await?;
        assert_eq!(
            verdict.status,
            RevocationStatus::Unknown(UnknownReason::Pending)
        );
        assert_eq!(verdict.pending.len(), 1);
        release.send(()).map_err(|_| "download dropped")?;
        verdict.pending[0].clone().await;
        assert_eq!(
            checked(
                &peer,
                Arc::clone(&fixture.chain),
                fixture_time(),
                CheckPhase::Handshake
            )
            .await?
            .status,
            RevocationStatus::Good
        );
        Ok::<(), Box<dyn Error>>(())
    })?;
    let script = Arc::new(Script::default());
    let (release, entered) = script.held(LEAF_CRL, Ok(fixture.crl(false, None, false, 10000)?));
    script.ready(ROOT_CRL, Ok(fixture.crl(true, None, false, 10000)?));
    let peer = fixture.peer(&script, Duration::from_secs(10), CacheLimits::DEFAULT);
    Runtime::new()?.block_on(async {
        let verdict = compio::time::timeout(
            Duration::from_secs(2),
            checked(
                &peer,
                Arc::clone(&fixture.chain),
                fixture_time(),
                CheckPhase::Recheck,
            ),
        )
        .await??;
        assert_eq!(
            verdict.status,
            RevocationStatus::Unknown(UnknownReason::Pending)
        );
        entered.await?;
        release.send(()).map_err(|_| "download dropped")?;
        for signal in verdict.pending {
            signal.await;
        }
        Ok::<(), Box<dyn Error>>(())
    })?;
    let script = Arc::new(Script::default());
    let (release, entered) = script.held(LEAF_CRL, Ok(fixture.crl(false, None, false, 10000)?));
    script.ready(ROOT_CRL, Ok(fixture.crl(true, None, false, 10000)?));
    let peer = fixture.peer(&script, Duration::from_secs(1), CacheLimits::DEFAULT);
    Runtime::new()?.block_on(async {
        let (verdict, released) = futures_util::future::join(
            checked(
                &peer,
                Arc::clone(&fixture.chain),
                fixture_time(),
                CheckPhase::Handshake,
            ),
            async {
                entered.await.map_err(|_| "download never entered")?;
                release.send(()).map_err(|_| "download dropped")?;
                Ok::<(), Box<dyn Error>>(())
            },
        )
        .await;
        released?;
        assert_eq!(verdict?.status, RevocationStatus::Good);
        Ok::<(), Box<dyn Error>>(())
    })?;
    Ok(())
}

#[test]
fn fetched_checks_report_full_cache_and_disabled_checks_do_no_work() -> TestResult {
    let fixture = FetchedFixture::new(&[LEAF_CRL])?;
    let script = Arc::new(Script::default());
    let peer = fixture.peer(
        &script,
        Duration::ZERO,
        CacheLimits {
            max_entries: 0,
            max_bytes: 0,
        },
    );
    let verdict = Runtime::new()?.block_on(checked(
        &peer,
        Arc::clone(&fixture.chain),
        fixture_time(),
        CheckPhase::Handshake,
    ))?;
    assert_eq!(
        verdict.status,
        RevocationStatus::Unknown(UnknownReason::CacheFull)
    );
    assert!(verdict.leases.is_empty());
    assert_eq!(script.calls.load(Ordering::Relaxed), 0);
    let disabled = PeerRevocation::disabled();
    assert_eq!(
        disabled.recheck_interval(),
        crate::hosts::revocation::RECHECK_INTERVAL
    );
    assert!(
        Runtime::new()?
            .block_on(disabled.check(
                Arc::clone(&fixture.chain),
                Direction::Inbound,
                CheckPhase::Handshake
            ))
            .is_none()
    );
    assert!(!metric_text(&disabled.metrics)?.contains("revocation_checks"));
    Ok(())
}

#[test]
fn cancelling_a_handshake_check_keeps_downloads_running_without_a_check_sample() -> TestResult {
    let fixture = FetchedFixture::new(&[LEAF_CRL])?;
    let script = Arc::new(Script::default());
    let (release, entered) = script.held(LEAF_CRL, Ok(fixture.crl(false, None, false, 10000)?));
    script.ready(ROOT_CRL, Ok(fixture.crl(true, None, false, 10000)?));
    let peer = fixture.peer(&script, Duration::from_secs(10), CacheLimits::DEFAULT);
    Runtime::new()?.block_on(async {
        let mut check = Box::pin(checked(
            &peer,
            Arc::clone(&fixture.chain),
            fixture_time(),
            CheckPhase::Handshake,
        ));
        match futures_util::future::select(check.as_mut(), entered).await {
            futures_util::future::Either::Right((Ok(()), _)) => {}
            _ => return Err("check did not wait for download".into()),
        }
        drop(check);
        let Source::Fetched { cache, .. } = &peer.source else {
            return Err("missing cache".into());
        };
        let lookup = cache.lookup(
            &CrlUrl::parse(LEAF_CRL).map_err(|_| "bad URL")?,
            fixture_time(),
            CheckPhase::Recheck,
        );
        let pending = lookup
            .pending
            .ok_or("download stopped after cancellation")?;
        release.send(()).map_err(|_| "download dropped")?;
        pending.await;
        assert!(
            cache
                .lookup(
                    &CrlUrl::parse(LEAF_CRL).map_err(|_| "bad URL")?,
                    fixture_time(),
                    CheckPhase::Recheck
                )
                .crl
                .is_some()
        );
        assert!(!metric_text(&peer.metrics)?.contains("revocation_checks"));
        Ok::<(), Box<dyn Error>>(())
    })
}

fn file_crl(
    issuer: &CertifiedIssuer<'_, Signer>,
    this_update: SystemTime,
    next_update: SystemTime,
    revoked: Option<u64>,
) -> TestResult<Vec<u8>> {
    Ok(CertificateRevocationListParams {
        this_update: this_update.into(),
        next_update: next_update.into(),
        crl_number: 1u64.into(),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .into_iter()
            .map(|serial| RevokedCertParams {
                serial_number: serial.into(),
                revocation_time: this_update.into(),
                reason_code: None,
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: KeyIdMethod::PreSpecified(vec![1]),
    }
    .signed_by(issuer)?
    .der()
    .to_vec())
}

fn write_file_crls(path: &Path, lists: &[Vec<u8>]) -> TestResult {
    use base64::Engine as _;
    let mut material = String::new();
    for der in lists {
        material.push_str("-----BEGIN X509 CRL-----\n");
        material.push_str(&base64::engine::general_purpose::STANDARD.encode(der));
        material.push_str("\n-----END X509 CRL-----\n");
    }
    fs::write(path, material)?;
    Ok(())
}

struct FileFixture {
    full: FetchedFixture,
    chain: Arc<[CertificateDer<'static>]>,
    path: std::path::PathBuf,
    before: SystemTime,
    next: SystemTime,
}
impl FileFixture {
    fn new() -> TestResult<Self> {
        let full = FetchedFixture::new(&[])?;
        let leaf = parameters("file-peer", 42, false)?.signed_by(&Signer::new()?, &full.root)?;
        let path = full._directory.path().join("file-crls.pem");
        let before = fixture_time().min(SystemTime::now()) - Duration::from_secs(60);
        let next = UNIX_EPOCH
            + Duration::from_secs(
                fixture_time()
                    .max(SystemTime::now())
                    .duration_since(UNIX_EPOCH)?
                    .as_secs()
                    + 600,
            );
        let fixture = Self {
            full,
            chain: Arc::from([leaf.der().clone()]),
            path,
            before,
            next,
        };
        fixture.write(None, fixture.next)?;
        Ok(fixture)
    }
    fn write(&self, revoked: Option<u64>, next: SystemTime) -> TestResult {
        write_file_crls(
            &self.path,
            &[file_crl(&self.full.root, self.before, next, revoked)?],
        )
    }
    fn config(&self) -> S2sConfig {
        S2sConfig {
            tls: crate::config::S2sTlsConfig {
                trust_anchors_path: Some(self.full._directory.path().join("roots.pem")),
                fetch_crls: true,
                crls_path: Some(self.path.clone()),
            },
            ..Default::default()
        }
    }
    fn peer(&self, metrics: Arc<S2sMetrics>) -> TestResult<Arc<PeerRevocation>> {
        let config = self.config();
        Ok(PeerRevocation::new(
            &config,
            &S2sLimits::default(),
            Arc::clone(&self.full.trust),
            Arc::new(Resolver::new(&config)?),
            metrics,
            Duration::from_secs(3600),
        )?)
    }
}

#[test]
fn file_source_enforces_full_chain_coverage_and_applies_replacements() -> TestResult {
    let fixture = FileFixture::new()?;
    write_file_crls(
        &fixture.path,
        &[
            file_crl(
                &fixture.full.root,
                fixture.before,
                fixture.next + Duration::from_secs(600),
                None,
            )?,
            file_crl(&fixture.full.root, fixture.before, fixture.next, None)?,
        ],
    )?;
    let metrics = S2sMetrics::new(0);
    let peer = fixture.peer(Arc::clone(&metrics))?;
    assert!(matches!(peer.source, Source::File { .. }));
    Runtime::new()?.block_on(async {
        let good = checked(&peer, Arc::clone(&fixture.chain), fixture_time(), CheckPhase::Handshake).await?;
        assert_eq!(good.status, RevocationStatus::Good); assert_eq!(good.next_update, Some(fixture.next));
        assert!(good.accepts()); assert!(good.needs_rechecks()); assert_eq!(good.source, RevocationSource::File);
        assert!(good.refresh_at.is_none()); assert!(good.pending.is_empty()); assert!(good.leases.is_empty());
        let uncovered = checked(&peer, Arc::clone(&fixture.full.chain), fixture_time(), CheckPhase::Recheck).await?;
        assert_eq!(uncovered.status, RevocationStatus::Unknown(UnknownReason::NotAuthoritative));
        assert!(!uncovered.accepts()); assert!(matches!(uncovered.auth_outcome(), Some(AuthOutcome::RevocationUnknown)));
        fixture.write(Some(42), fixture.next)?;
        let revoked = checked(&peer, Arc::clone(&fixture.chain), fixture_time(), CheckPhase::Recheck).await?;
        assert_eq!(revoked.status, RevocationStatus::Revoked); assert!(!revoked.accepts()); assert!(matches!(revoked.auth_outcome(), Some(AuthOutcome::CertificateRevoked)));
        assert_metric(&metric_text(&metrics)?, "lonewolf_s2s_revocation_checks_total{direction=\"inbound\",source=\"file\",phase=\"handshake\",status=\"good\",reason=\"none\"} 1");
        Ok(())
    })
}

#[test]
fn file_load_and_signature_failures_reject_with_source_specific_outcomes() -> TestResult {
    let fixture = FileFixture::new()?;
    let peer = fixture.peer(S2sMetrics::new(0))?;
    let wrong_key = CertifiedIssuer::self_signed(parameters("root", 1, true)?, Signer::new()?)?;
    let stale = file_crl(
        &fixture.full.root,
        fixture_time() - Duration::from_secs(120),
        fixture_time() - Duration::from_secs(60),
        None,
    )?;
    let wrong = file_crl(&wrong_key, fixture.before, fixture.next, None)?;
    Runtime::new()?.block_on(async {
        for (material, reason, outcome) in [
            (
                Some(stale),
                UnknownReason::Stale,
                AuthOutcome::RevocationStale,
            ),
            (
                None,
                UnknownReason::Unavailable,
                AuthOutcome::RevocationUnavailable,
            ),
            (
                Some(b"invalid".to_vec()),
                UnknownReason::Invalid,
                AuthOutcome::RevocationUnavailable,
            ),
            (
                Some(wrong),
                UnknownReason::BadSignature,
                AuthOutcome::RevocationUnavailable,
            ),
        ] {
            match material {
                None => fs::remove_file(&fixture.path)?,
                Some(material) if material == b"invalid" => fs::write(&fixture.path, material)?,
                Some(material) => write_file_crls(&fixture.path, &[material])?,
            }
            let verdict = checked(
                &peer,
                Arc::clone(&fixture.chain),
                fixture_time(),
                CheckPhase::Handshake,
            )
            .await?;
            assert_eq!(verdict.status, RevocationStatus::Unknown(reason));
            assert!(!verdict.accepts());
            assert_eq!(
                verdict.auth_outcome().map(AuthOutcome::as_str),
                Some(outcome.as_str())
            );
        }
        Ok(())
    })
}

#[test]
fn startup_rejects_unreadable_invalid_files_but_accepts_stale_files() -> TestResult {
    let fixture = FileFixture::new()?;
    let config = fixture.config();
    for error in [
        CrlLoadError::Unreadable,
        CrlLoadError::Invalid,
        CrlLoadError::Stale,
    ] {
        match error {
            CrlLoadError::Unreadable => fs::remove_file(&fixture.path)?,
            CrlLoadError::Invalid => fs::write(&fixture.path, b"invalid")?,
            CrlLoadError::Stale => {
                let now = SystemTime::now();
                write_file_crls(
                    &fixture.path,
                    &[file_crl(
                        &fixture.full.root,
                        now - Duration::from_secs(120),
                        now - Duration::from_secs(60),
                        None,
                    )?],
                )?;
            }
        }
        let metrics = S2sMetrics::new(0);
        let result = PeerRevocation::new(
            &config,
            &S2sLimits::default(),
            Arc::clone(&fixture.full.trust),
            Arc::new(Resolver::new(&config)?),
            Arc::clone(&metrics),
            Duration::from_secs(3600),
        );
        if error == CrlLoadError::Stale {
            assert!(result.is_ok());
        } else {
            assert!(
                matches!(result, Err(RevocationStartupError::CrlFile(actual)) if actual == error)
            );
        }
        assert_metric(
            &metric_text(&metrics)?,
            &format!(
                "lonewolf_s2s_crl_file_load_failures_total{{reason=\"{}\"}} 1",
                error.as_str()
            ),
        );
        assert!(!metric_text(&metrics)?.contains("s2s_crl_file_next_update_seconds"));
    }
    for (error, text) in [
        (CrlLoadError::Unreadable, "cannot read s2s.tls.crls_path"),
        (
            CrlLoadError::Invalid,
            "s2s.tls.crls_path holds invalid CRLs",
        ),
        (CrlLoadError::Stale, "s2s.tls.crls_path holds stale CRLs"),
    ] {
        assert_eq!(RevocationStartupError::CrlFile(error).to_string(), text);
    }
    Ok(())
}

#[test]
fn cancelled_submitted_file_loads_report_without_the_waiter_or_peer_owner() -> TestResult {
    for failure in [false, true] {
        let fixture = FileFixture::new()?;
        let metrics = S2sMetrics::new(0);
        let mut peer = fixture.peer(Arc::clone(&metrics))?;
        Arc::get_mut(&mut peer).ok_or("shared peer")?.verifier =
            BlockingExecutor::new(NonZeroUsize::MIN);
        let executor = peer.verifier.clone();
        let next = fixture.next + Duration::from_secs(600);
        if failure {
            fs::write(&fixture.path, b"invalid")?;
        } else {
            fixture.write(None, next)?;
        }
        Runtime::new()?.block_on(async {
            let (entered, started) = oneshot::channel();
            let (release, held) = std::sync::mpsc::channel();
            let mut check = Box::pin(peer.check_at_with_loader(
                Arc::clone(&fixture.chain),
                Direction::Inbound,
                CheckPhase::Recheck,
                fixture_time(),
                move |path, now| {
                    let _ = entered.send(());
                    assert!(held.recv_timeout(Duration::from_secs(5)).is_ok());
                    CrlSet::load(path, now)
                },
            ));
            assert!(futures_util::poll!(check.as_mut()).is_pending());
            compio::time::timeout(Duration::from_secs(5), started).await??;
            drop(check);
            drop(peer);
            release.send(())?;
            executor.run(|| ()).await;
            let output = metric_text(&metrics)?;
            if failure {
                assert_metric(
                    &output,
                    "lonewolf_s2s_crl_file_load_failures_total{reason=\"invalid\"} 1",
                );
            } else {
                assert_metric(
                    &output,
                    &format!(
                        "lonewolf_s2s_crl_file_next_update_seconds {}",
                        next.duration_since(UNIX_EPOCH)?.as_secs()
                    ),
                );
            }
            assert!(!output.contains("s2s_revocation_checks_total"));
            Ok::<_, Box<dyn Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn cancelled_file_checks_waiting_for_executor_admission_do_not_load() -> TestResult {
    use std::sync::atomic::{AtomicBool, Ordering};
    let fixture = FileFixture::new()?;
    let metrics = S2sMetrics::new(0);
    let mut peer = fixture.peer(Arc::clone(&metrics))?;
    Arc::get_mut(&mut peer).ok_or("shared peer")?.verifier =
        BlockingExecutor::new(NonZeroUsize::MIN);
    let executor = peer.verifier.clone();
    Runtime::new()?.block_on(async {
        let (entered, started) = oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let mut occupied = Box::pin(executor.run(move || {
            let _ = entered.send(());
            held.recv_timeout(Duration::from_secs(5))
        }));
        assert!(futures_util::poll!(occupied.as_mut()).is_pending());
        compio::time::timeout(Duration::from_secs(5), started).await??;
        let loaded = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&loaded);
        let mut check = Box::pin(peer.check_at_with_loader(
            Arc::clone(&fixture.chain),
            Direction::Inbound,
            CheckPhase::Recheck,
            fixture_time(),
            move |path, now| {
                observed.store(true, Ordering::Relaxed);
                CrlSet::load(path, now)
            },
        ));
        assert!(futures_util::poll!(check.as_mut()).is_pending());
        drop(check);
        drop(peer);
        release.send(())?;
        occupied.await?;
        executor.run(|| ()).await;
        assert!(!loaded.load(Ordering::Relaxed));
        let output = metric_text(&metrics)?;
        assert!(!output.contains("s2s_crl_file_load_failures"));
        assert!(!output.contains("s2s_revocation_checks_total"));
        assert_metric(
            &output,
            &format!(
                "lonewolf_s2s_crl_file_next_update_seconds {}",
                fixture.next.duration_since(UNIX_EPOCH)?.as_secs()
            ),
        );
        Ok::<_, Box<dyn Error>>(())
    })
}
