// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use compio::runtime::Runtime;
use graviola::hashing::Sha256;
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey};
use prometheus_client::registry::Registry;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, DnType,
    IsCa, KeyIdMethod, KeyUsagePurpose,
};

use crate::hosts::revocation::parse_crl;

use super::*;

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

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000 + seconds)
}
fn fixture_url(index: u8) -> TestResult<CrlUrl> {
    CrlUrl::parse(&format!("http://ca{index}.example/list.crl"))
        .map_err(|_| "bad fixture URL".into())
}

fn material(number: Option<u64>, issued_ago: u64, expires: u64) -> TestResult<FetchedCrl> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.serial_number = Some(1u64.into());
    params.distinguished_name.push(DnType::CommonName, "Root");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root = CertifiedIssuer::self_signed(params, Signer::new()?)?;
    let der = CertificateRevocationListParams {
        this_update: (at(0) - Duration::from_secs(issued_ago)).into(),
        next_update: at(expires).into(),
        crl_number: number.unwrap_or(1).into(),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::PreSpecified(vec![1]),
    }
    .signed_by(&root)?;
    let parsed = parse_crl(der.der(), at(0)).map_err(|error| format!("{error:?}"))?;
    Ok(FetchedCrl {
        crl: parsed.crl,
        this_update: parsed.this_update,
        next_update: parsed.next_update,
        crl_number: if number.is_some() {
            parsed.crl_number
        } else {
            None
        },
        cost: parsed.cost,
    })
}

#[derive(Clone)]
struct Clock(Arc<PlMutex<Instant>>);
impl Clock {
    fn new() -> Self {
        Self(Arc::new(PlMutex::new(Instant::now())))
    }
    fn advance(&self, elapsed: Duration) {
        let mut clock = self.0.lock();
        *clock += elapsed;
    }
    fn lookup(
        &self,
        cache: &Arc<CrlCache>,
        url: &CrlUrl,
        now: SystemTime,
        phase: CheckPhase,
    ) -> Lookup {
        let clock = self.clone();
        cache.lookup_with_clock(url, now, phase, move || *clock.0.lock())
    }
}

struct Step {
    gate: oneshot::Receiver<()>,
    entered: oneshot::Sender<()>,
    result: Result<FetchedCrl, FetchFailure>,
}
struct Gate {
    release: oneshot::Sender<()>,
    entered: Option<oneshot::Receiver<()>>,
}
impl Gate {
    async fn entered(&mut self) -> TestResult {
        self.entered
            .take()
            .ok_or("entry signal already used")?
            .await?;
        Ok::<(), Box<dyn Error>>(())
    }
}
#[derive(Default)]
struct Script {
    steps: PlMutex<VecDeque<Step>>,
    calls: AtomicUsize,
}
impl Script {
    fn queue(&self, result: Result<FetchedCrl, FetchFailure>) -> Gate {
        let (release, gate) = oneshot::channel();
        let (entered, entry) = oneshot::channel();
        self.steps.lock().push_back(Step {
            gate,
            entered,
            result,
        });
        Gate {
            release,
            entered: Some(entry),
        }
    }
    fn fetch(self: &Arc<Self>) -> FetchFn {
        let script = Arc::clone(self);
        Arc::new(move |_, _| {
            script.calls.fetch_add(1, Ordering::Relaxed);
            let step = script.steps.lock().pop_front();
            async move {
                if let Some(step) = step {
                    let _ = step.entered.send(());
                    let _ = step.gate.await;
                    step.result
                } else {
                    Err(FetchFailure::Invalid)
                }
            }
            .boxed_local()
        })
    }
}

async fn finish(lookup: &Lookup, release: Gate) -> TestResult {
    release
        .release
        .send(())
        .map_err(|_| "download already dropped")?;
    lookup.pending.clone().ok_or("no pending download")?.await;
    Ok::<(), Box<dyn Error>>(())
}
fn cache(script: &Arc<Script>, refresh: u64, limits: CacheLimits) -> Arc<CrlCache> {
    CrlCache::new(
        script.fetch(),
        S2sMetrics::new(0),
        limits,
        Duration::from_secs(refresh),
    )
}
fn render(metrics: &Arc<S2sMetrics>) -> TestResult<String> {
    let mut registry = Registry::default();
    metrics.register(registry.sub_registry_with_prefix("lonewolf"));
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry)?;
    Ok(text)
}
fn sample(text: &str, expected: &str) {
    assert!(
        text.lines().any(|line| line == expected),
        "missing {expected} in {text}"
    );
}
fn accounting(cache: &CrlCache) {
    let state = cache.state.lock();
    assert_eq!(
        state.bytes,
        state
            .entries
            .values()
            .filter_map(|entry| entry.crl.as_ref())
            .map(|crl| crl.cost)
            .sum::<usize>()
    );
    assert!(state.bytes <= cache.limits.max_bytes);
    assert!(state.entries.len() <= cache.limits.max_entries);
}

#[test]
fn single_flight_detaches_and_publishes_metrics_before_releasing_waiters() -> TestResult {
    let script = Arc::new(Script::default());
    let release = script.queue(Ok(material(Some(1), 60, 10000)?));
    let cache = cache(&script, 3600, CacheLimits::DEFAULT);
    let clock = Clock::new();
    let url = fixture_url(1)?;
    Runtime::new()?.block_on(async {
        let first = cache.lookup(&url, at(0), CheckPhase::Handshake);
        let second = clock.lookup(&cache, &url, at(0), CheckPhase::Handshake);
        let third = clock.lookup(&cache, &url, at(0), CheckPhase::Handshake);
        assert!(
            first
                .pending
                .as_ref()
                .ok_or("no pending")?
                .ptr_eq(second.pending.as_ref().ok_or("no pending")?)
        );
        assert!(
            first
                .pending
                .as_ref()
                .ok_or("no pending")?
                .ptr_eq(third.pending.as_ref().ok_or("no pending")?)
        );
        let signal = third.pending.clone().ok_or("no pending")?;
        drop(first);
        drop(second);
        drop(third);
        release.release.send(()).map_err(|_| "download dropped")?;
        signal.await;
        assert_eq!(script.calls.load(Ordering::Relaxed), 1);
        let ready = clock.lookup(&cache, &url, at(1), CheckPhase::Handshake);
        assert!(ready.crl.is_some());
        assert!(ready.pending.is_none());
        assert_eq!(ready.unknown, None);
        let text = render(&cache.metrics)?;
        sample(
            &text,
            "lonewolf_s2s_crl_fetches_total{outcome=\"success\"} 1",
        );
        sample(&text, "lonewolf_s2s_crl_fetch_duration_seconds_count 1");
        sample(&text, "lonewolf_s2s_crl_cache_entries 1");
        let stored = ready.crl.as_ref().ok_or("missing CRL")?;
        assert!(matches!(stored.crl, webpki::CertRevocationList::Owned(_)));
        sample(
            &text,
            &format!("lonewolf_s2s_crl_cache_bytes {}", stored.cost),
        );
        accounting(&cache);
        let restarted = CrlCache::new(
            script.fetch(),
            S2sMetrics::new(0),
            CacheLimits::DEFAULT,
            Duration::from_secs(3600),
        );
        assert!(restarted.state.lock().entries.is_empty());
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn refresh_shares_downloads_and_rejects_rollback_with_backoff() -> TestResult {
    let script = Arc::new(Script::default());
    let first = script.queue(Ok(material(Some(2), 60, 10000)?));
    let older = script.queue(Ok(material(Some(1), 60, 10000)?));
    let same = script.queue(Ok(material(Some(2), 60, 10000)?));
    let cache = cache(&script, 10, CacheLimits::DEFAULT);
    let clock = Clock::new();
    let url = fixture_url(1)?;
    Runtime::new()?.block_on(async {
        let lookup = clock.lookup(&cache, &url, at(0), CheckPhase::Handshake);
        finish(&lookup, first).await?;
        let initial = clock.lookup(&cache, &url, at(1), CheckPhase::Handshake);
        let old = initial.crl.as_ref().ok_or("missing initial CRL")?;
        let refresh = clock.lookup(&cache, &url, at(11), CheckPhase::Recheck);
        assert!(Arc::ptr_eq(
            refresh.crl.as_ref().ok_or("missing old CRL")?,
            old
        ));
        let second = clock.lookup(&cache, &url, at(11), CheckPhase::Recheck);
        assert!(
            refresh
                .pending
                .as_ref()
                .ok_or("no pending")?
                .ptr_eq(second.pending.as_ref().ok_or("no pending")?)
        );
        finish(&refresh, older).await?;
        let retained = clock.lookup(&cache, &url, at(70), CheckPhase::Recheck);
        assert!(Arc::ptr_eq(
            retained.crl.as_ref().ok_or("missing old CRL")?,
            old
        ));
        assert!(retained.pending.is_none());
        sample(
            &render(&cache.metrics)?,
            "lonewolf_s2s_crl_fetches_total{outcome=\"rollback\"} 1",
        );
        let retry = clock.lookup(&cache, &url, at(71), CheckPhase::Recheck);
        finish(&retry, same).await?;
        let replaced = clock.lookup(&cache, &url, at(72), CheckPhase::Recheck);
        assert!(!Arc::ptr_eq(
            replaced.crl.as_ref().ok_or("missing new CRL")?,
            old
        ));
        assert_eq!(script.calls.load(Ordering::Relaxed), 3);
        accounting(&cache);
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn unnumbered_refreshes_use_this_update_for_rollback() -> TestResult {
    let script = Arc::new(Script::default());
    let first = script.queue(Ok(material(None, 120, 10000)?));
    let older = script.queue(Ok(material(None, 180, 10000)?));
    let newer = script.queue(Ok(material(None, 60, 10000)?));
    let cache = cache(&script, 10, CacheLimits::DEFAULT);
    let clock = Clock::new();
    let url = fixture_url(1)?;
    Runtime::new()?.block_on(async {
        let initial = clock.lookup(&cache, &url, at(0), CheckPhase::Handshake);
        finish(&initial, first).await?;
        let refresh = clock.lookup(&cache, &url, at(11), CheckPhase::Recheck);
        finish(&refresh, older).await?;
        assert_eq!(
            clock
                .lookup(&cache, &url, at(12), CheckPhase::Recheck)
                .crl
                .as_ref()
                .ok_or("missing CRL")?
                .this_update,
            at(0) - Duration::from_secs(120)
        );
        let retry = clock.lookup(&cache, &url, at(71), CheckPhase::Recheck);
        finish(&retry, newer).await?;
        assert_eq!(
            clock
                .lookup(&cache, &url, at(72), CheckPhase::Recheck)
                .crl
                .as_ref()
                .ok_or("missing CRL")?
                .this_update,
            at(0) - Duration::from_secs(60)
        );
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn leases_and_handshake_uses_bound_stale_retention() -> TestResult {
    for leased in [false, true] {
        let script = Arc::new(Script::default());
        let release = script.queue(Ok(material(Some(1), 60, 5)?));
        let cache = cache(&script, 10, CacheLimits::DEFAULT);
        let clock = Clock::new();
        let url = fixture_url(1)?;
        let other = fixture_url(2)?;
        Runtime::new()?.block_on(async {
            let lookup = clock.lookup(&cache, &url, at(0), CheckPhase::Handshake);
            finish(&lookup, release).await?;
            let lease = if leased { lookup.lease.clone() } else { None };
            drop(lookup);
            let sweep = clock.lookup(&cache, &other, at(11), CheckPhase::Recheck);
            drop(sweep);
            assert_eq!(cache.state.lock().entries.contains_key(&url), leased);
            if leased {
                let sweep = clock.lookup(&cache, &other, at(5) + STALE_GRACE, CheckPhase::Recheck);
                drop(sweep);
                assert!(!cache.state.lock().entries.contains_key(&url));
                sample(
                    &render(&cache.metrics)?,
                    "lonewolf_s2s_crl_cache_evictions_total{reason=\"stale_expired\"} 1",
                );
            } else {
                sample(
                    &render(&cache.metrics)?,
                    "lonewolf_s2s_crl_cache_evictions_total{reason=\"unused\"} 1",
                );
            }
            drop(lease);
            accounting(&cache);
            Ok::<(), Box<dyn Error>>(())
        })?;
    }
    Ok::<(), Box<dyn Error>>(())
}

#[test]
fn lru_entry_capacity_and_leases_control_admission() -> TestResult {
    let script = Arc::new(Script::default());
    let a = script.queue(Ok(material(Some(1), 60, 10000)?));
    let b = script.queue(Ok(material(Some(1), 60, 10000)?));
    let c = script.queue(Ok(material(Some(1), 60, 10000)?));
    let cache = cache(
        &script,
        10,
        CacheLimits {
            max_entries: 2,
            ..CacheLimits::DEFAULT
        },
    );
    let clock = Clock::new();
    let a_url = fixture_url(1)?;
    let b_url = fixture_url(2)?;
    let c_url = fixture_url(3)?;
    Runtime::new()?.block_on(async {
        let first = clock.lookup(&cache, &a_url, at(0), CheckPhase::Recheck);
        finish(&first, a).await?;
        let second = clock.lookup(&cache, &b_url, at(1), CheckPhase::Recheck);
        finish(&second, b).await?;
        let refused = clock.lookup(&cache, &c_url, at(2), CheckPhase::Recheck);
        assert_eq!(refused.unknown, Some(UnknownReason::CacheFull));
        assert!(refused.pending.is_none());
        assert_eq!(script.calls.load(Ordering::Relaxed), 2);
        drop(first);
        drop(second);
        let admitted = clock.lookup(&cache, &c_url, at(3), CheckPhase::Recheck);
        assert!(!cache.state.lock().entries.contains_key(&a_url));
        assert!(cache.state.lock().entries.contains_key(&b_url));
        finish(&admitted, c).await?;
        sample(
            &render(&cache.metrics)?,
            "lonewolf_s2s_crl_cache_evictions_total{reason=\"capacity\"} 1",
        );
        accounting(&cache);
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn byte_capacity_refusal_preserves_success_metrics_and_applies_backoff() -> TestResult {
    let script = Arc::new(Script::default());
    let first = material(Some(1), 60, 10000)?;
    let second = material(Some(1), 60, 10000)?;
    let third = material(Some(1), 60, 10000)?;
    let budget = first.cost.max(second.cost).max(third.cost) + fixture_url(1)?.as_str().len();
    let a = script.queue(Ok(first));
    let b = script.queue(Ok(second));
    let c = script.queue(Ok(third));
    let cache = cache(
        &script,
        10,
        CacheLimits {
            max_entries: 3,
            max_bytes: budget,
        },
    );
    let clock = Clock::new();
    let a_url = fixture_url(1)?;
    let b_url = fixture_url(2)?;
    Runtime::new()?.block_on(async {
        let first = clock.lookup(&cache, &a_url, at(0), CheckPhase::Recheck);
        finish(&first, a).await?;
        let refused = clock.lookup(&cache, &b_url, at(1), CheckPhase::Recheck);
        finish(&refused, b).await?;
        let failure = clock.lookup(&cache, &b_url, at(2), CheckPhase::Recheck);
        assert_eq!(failure.unknown, Some(UnknownReason::CacheFull));
        assert!(failure.pending.is_none());
        sample(
            &render(&cache.metrics)?,
            "lonewolf_s2s_crl_fetches_total{outcome=\"success\"} 2",
        );
        drop(first);
        let retry = clock.lookup(&cache, &b_url, at(61), CheckPhase::Recheck);
        finish(&retry, c).await?;
        assert!(!cache.state.lock().entries.contains_key(&a_url));
        assert!(
            clock
                .lookup(&cache, &b_url, at(62), CheckPhase::Recheck)
                .crl
                .is_some()
        );
        accounting(&cache);
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn completed_failure_uses_elapsed_time_for_backoff_and_histogram() -> TestResult {
    let script = Arc::new(Script::default());
    let mut release = script.queue(Err(FetchFailure::HttpStatus));
    let next = script.queue(Err(FetchFailure::Timeout));
    let cache = cache(&script, 3600, CacheLimits::DEFAULT);
    let clock = Clock::new();
    let url = fixture_url(1)?;
    Runtime::new()?.block_on(async {
        let held = clock.lookup(&cache, &url, at(0), CheckPhase::Handshake);
        release.entered().await?;
        clock.advance(Duration::from_secs(90));
        finish(&held, release).await?;
        assert_eq!(cache.state.lock().entries[&url].retry_after, Some(at(150)));
        sample(
            &render(&cache.metrics)?,
            "lonewolf_s2s_crl_fetch_duration_seconds_sum 90.0",
        );
        let before = clock.lookup(
            &cache,
            &url,
            at(150) - Duration::from_nanos(1),
            CheckPhase::Handshake,
        );
        assert!(before.pending.is_none());
        assert_eq!(before.unknown, Some(UnknownReason::FetchFailed));
        let exact = clock.lookup(&cache, &url, at(150), CheckPhase::Handshake);
        finish(&exact, next).await?;
        assert_eq!(script.calls.load(Ordering::Relaxed), 2);
        assert_eq!(cache.state.lock().entries[&url].retry_after, Some(at(270)));
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn completed_success_uses_elapsed_time_and_caps_refresh_at_next_update() -> TestResult {
    for expires in [300, 10000] {
        let script = Arc::new(Script::default());
        let mut release = script.queue(Ok(material(Some(1), 60, expires)?));
        let cache = cache(&script, 3600, CacheLimits::DEFAULT);
        let clock = Clock::new();
        let url = fixture_url(1)?;
        Runtime::new()?.block_on(async {
            let held = clock.lookup(&cache, &url, at(0), CheckPhase::Handshake);
            release.entered().await?;
            clock.advance(Duration::from_secs(180));
            finish(&held, release).await?;
            assert_eq!(
                cache.state.lock().entries[&url]
                    .crl
                    .as_ref()
                    .ok_or("missing CRL")?
                    .refresh_at,
                at(3780.min(expires))
            );
            Ok::<(), Box<dyn Error>>(())
        })?;
    }
    Ok::<(), Box<dyn Error>>(())
}

#[test]
fn stale_lookup_keeps_evidence_and_reports_pending_then_stale() -> TestResult {
    let script = Arc::new(Script::default());
    let first = script.queue(Ok(material(Some(1), 60, 5)?));
    let failure = script.queue(Err(FetchFailure::HttpStatus));
    let cache = cache(&script, 10, CacheLimits::DEFAULT);
    let clock = Clock::new();
    let url = fixture_url(1)?;
    Runtime::new()?.block_on(async {
        let first_lookup = clock.lookup(&cache, &url, at(0), CheckPhase::Handshake);
        finish(&first_lookup, first).await?;
        let stale = clock.lookup(&cache, &url, at(6), CheckPhase::Recheck);
        assert!(stale.crl.is_some());
        assert_eq!(stale.unknown, Some(UnknownReason::Pending));
        finish(&stale, failure).await?;
        let failed = clock.lookup(&cache, &url, at(7), CheckPhase::Recheck);
        assert!(failed.crl.is_some());
        assert_eq!(failed.unknown, Some(UnknownReason::Stale));
        assert_eq!(
            cache.state.lock().entries[&url].handshake_used_at,
            Some(at(0))
        );
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn failure_backoff_doubles_to_one_hour_and_success_resets_it() -> TestResult {
    let script = Arc::new(Script::default());
    let mut releases = VecDeque::new();
    for _ in 0..8 {
        releases.push_back(script.queue(Err(FetchFailure::HttpStatus)));
    }
    let success = script.queue(Ok(material(Some(1), 60, 50000)?));
    let failure = script.queue(Err(FetchFailure::Invalid));
    let cache = cache(&script, 10, CacheLimits::DEFAULT);
    let clock = Clock::new();
    let url = fixture_url(1)?;
    Runtime::new()?.block_on(async {
        let mut now = at(0);
        let mut leases = Vec::new();
        for delay in [60, 120, 240, 480, 960, 1920, 3600, 3600] {
            let lookup = clock.lookup(&cache, &url, now, CheckPhase::Handshake);
            leases.push(lookup.lease.clone());
            finish(&lookup, releases.pop_front().ok_or("missing release")?).await?;
            let retry = cache.state.lock().entries[&url]
                .retry_after
                .ok_or("missing backoff")?;
            assert_eq!(retry.duration_since(now)?, Duration::from_secs(delay));
            now = retry;
        }
        let recovered = clock.lookup(&cache, &url, now, CheckPhase::Handshake);
        finish(&recovered, success).await?;
        assert_eq!(cache.state.lock().entries[&url].failures, 0);
        let refresh = clock.lookup(
            &cache,
            &url,
            now + Duration::from_secs(11),
            CheckPhase::Recheck,
        );
        finish(&refresh, failure).await?;
        assert!(refresh.crl.is_some());
        let still_fresh = clock.lookup(
            &cache,
            &url,
            now + Duration::from_secs(12),
            CheckPhase::Recheck,
        );
        assert!(still_fresh.crl.is_some());
        assert_eq!(still_fresh.unknown, None);
        assert!(still_fresh.pending.is_none());
        assert_eq!(
            cache.state.lock().entries[&url].retry_after,
            Some(now + Duration::from_secs(71))
        );
        drop(leases);
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn completion_sweep_uses_completion_time_for_unrelated_entries() -> TestResult {
    let script = Arc::new(Script::default());
    let first = script.queue(Ok(material(Some(1), 60, 5)?));
    let mut held = script.queue(Ok(material(Some(1), 60, 10000)?));
    let cache = cache(&script, 3600, CacheLimits::DEFAULT);
    let clock = Clock::new();
    let first_url = fixture_url(1)?;
    let second_url = fixture_url(2)?;
    Runtime::new()?.block_on(async {
        let initial = clock.lookup(&cache, &first_url, at(0), CheckPhase::Recheck);
        finish(&initial, first).await?;
        drop(initial);
        let second = clock.lookup(&cache, &second_url, at(1), CheckPhase::Handshake);
        assert!(cache.state.lock().entries.contains_key(&first_url));
        held.entered().await?;
        clock.advance(Duration::from_secs(10));
        finish(&second, held).await?;
        assert!(!cache.state.lock().entries.contains_key(&first_url));
        sample(
            &render(&cache.metrics)?,
            "lonewolf_s2s_crl_cache_evictions_total{reason=\"unused\"} 1",
        );
        accounting(&cache);
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn obsolete_completions_never_mutate_the_replacement_generation() -> TestResult {
    for failure in [false, true] {
        let script = Arc::new(Script::default());
        let first = script.queue(Ok(material(Some(2), 60, 5)?));
        let mut old = script.queue(if failure {
            Err(FetchFailure::HttpStatus)
        } else {
            Ok(material(Some(1), 60, 10000)?)
        });
        let mut replacement =
            script.queue(Ok(material(Some(3), 60, STALE_GRACE.as_secs() + 10000)?));
        let cache = cache(
            &script,
            10,
            CacheLimits {
                max_entries: 1,
                ..CacheLimits::DEFAULT
            },
        );
        let clock = Clock::new();
        let url = fixture_url(1)?;
        let other = fixture_url(2)?;
        Runtime::new()?.block_on(async {
            let initial = clock.lookup(&cache, &url, at(0), CheckPhase::Handshake);
            finish(&initial, first).await?;
            let refresh = clock.lookup(&cache, &url, at(6), CheckPhase::Recheck);
            old.entered().await?;
            let replacement_lookup =
                clock.lookup(&cache, &url, at(5) + STALE_GRACE, CheckPhase::Handshake);
            replacement.entered().await?;
            assert_eq!(
                clock
                    .lookup(&cache, &other, at(5) + STALE_GRACE, CheckPhase::Recheck)
                    .unknown,
                Some(UnknownReason::CacheFull)
            );
            let before = {
                let state = cache.state.lock();
                let entry = &state.entries[&url];
                (
                    entry.crl.clone(),
                    entry.pending.clone().ok_or("missing replacement signal")?,
                    entry.retry_after,
                    entry.failures,
                    Arc::downgrade(&entry.token),
                    state.bytes,
                    state.full,
                    entry.last_failure,
                    entry.last_access,
                    entry.handshake_used_at,
                )
            };
            clock.advance(STALE_GRACE + Duration::from_secs(20));
            finish(&refresh, old).await?;
            {
                let state = cache.state.lock();
                let entry = &state.entries[&url];
                assert!(before.0.is_none());
                assert!(entry.crl.is_none());
                assert!(
                    before
                        .1
                        .ptr_eq(entry.pending.as_ref().ok_or("replacement signal cleared")?)
                );
                assert_eq!(entry.retry_after, before.2);
                assert_eq!(entry.failures, before.3);
                assert!(Weak::ptr_eq(&before.4, &Arc::downgrade(&entry.token)));
                assert_eq!(state.bytes, before.5);
                assert_eq!(state.full, before.6);
                assert_eq!(entry.last_failure, before.7);
                assert_eq!(entry.last_access, before.8);
                assert_eq!(entry.handshake_used_at, before.9);
            }
            assert!(before.1.clone().now_or_never().is_none());
            let text = render(&cache.metrics)?;
            sample(&text, "lonewolf_s2s_crl_fetch_duration_seconds_count 2");
            if failure {
                sample(
                    &text,
                    "lonewolf_s2s_crl_fetches_total{outcome=\"http_status\"} 1",
                );
            } else {
                sample(
                    &text,
                    "lonewolf_s2s_crl_fetches_total{outcome=\"success\"} 2",
                );
            }
            assert!(!text.contains("outcome=\"rollback\""));
            finish(&replacement_lookup, replacement).await?;
            accounting(&cache);
            Ok::<(), Box<dyn Error>>(())
        })?;
    }
    Ok::<(), Box<dyn Error>>(())
}

#[test]
fn fetch_failures_map_to_lookup_reasons_through_completed_attempts() -> TestResult {
    for (failure, expected) in [
        (FetchFailure::DnsFailed, UnknownReason::FetchFailed),
        (FetchFailure::ConnectFailed, UnknownReason::FetchFailed),
        (FetchFailure::HttpStatus, UnknownReason::FetchFailed),
        (FetchFailure::BlockedAddress, UnknownReason::BlockedAddress),
        (FetchFailure::Timeout, UnknownReason::Timeout),
        (FetchFailure::TooLarge, UnknownReason::TooLarge),
        (FetchFailure::Invalid, UnknownReason::Invalid),
        (FetchFailure::Stale, UnknownReason::Stale),
    ] {
        let script = Arc::new(Script::default());
        let release = script.queue(Err(failure));
        let cache = cache(&script, 3600, CacheLimits::DEFAULT);
        let clock = Clock::new();
        let url = fixture_url(1)?;
        Runtime::new()?.block_on(async {
            let lookup = clock.lookup(&cache, &url, at(0), CheckPhase::Handshake);
            finish(&lookup, release).await?;
            assert_eq!(
                clock
                    .lookup(&cache, &url, at(1), CheckPhase::Handshake)
                    .unknown,
                Some(expected)
            );
            sample(
                &render(&cache.metrics)?,
                &format!(
                    "lonewolf_s2s_crl_fetches_total{{outcome=\"{}\"}} 1",
                    fetch_outcome(failure).as_str()
                ),
            );
            Ok::<(), Box<dyn Error>>(())
        })?;
    }
    Ok::<(), Box<dyn Error>>(())
}

#[test]
fn repeated_failures_and_recovery_update_retry_and_capacity_state() -> TestResult {
    let script = Arc::new(Script::default());
    let first = script.queue(Err(FetchFailure::HttpStatus));
    let repeat = script.queue(Err(FetchFailure::HttpStatus));
    let changed = script.queue(Err(FetchFailure::Timeout));
    let recovered = script.queue(Ok(material(Some(1), 60, 10000)?));
    let healthy = script.queue(Ok(material(Some(1), 60, 10000)?));
    let cache = cache(
        &script,
        10,
        CacheLimits {
            max_entries: 1,
            ..CacheLimits::DEFAULT
        },
    );
    let clock = Clock::new();
    let url = fixture_url(1)?;
    let other = fixture_url(2)?;
    Runtime::new()?.block_on(async {
        let first_lookup = clock.lookup(&cache, &url, at(0), CheckPhase::Handshake);
        finish(&first_lookup, first).await?;
        assert_eq!(
            cache.state.lock().entries[&url].last_failure,
            Some(Failure::Fetch(FetchFailure::HttpStatus))
        );
        let repeated = clock.lookup(&cache, &url, at(60), CheckPhase::Handshake);
        finish(&repeated, repeat).await?;
        assert_eq!(cache.state.lock().entries[&url].failures, 2);
        assert_eq!(cache.state.lock().entries[&url].retry_after, Some(at(180)));
        let different = clock.lookup(&cache, &url, at(180), CheckPhase::Handshake);
        finish(&different, changed).await?;
        assert_eq!(
            cache.state.lock().entries[&url].last_failure,
            Some(Failure::Fetch(FetchFailure::Timeout))
        );
        assert_eq!(cache.state.lock().entries[&url].retry_after, Some(at(420)));
        for _ in 0..3 {
            assert_eq!(
                clock
                    .lookup(&cache, &other, at(181), CheckPhase::Handshake)
                    .unknown,
                Some(UnknownReason::CacheFull)
            );
            assert!(cache.state.lock().full);
        }
        let success = clock.lookup(&cache, &url, at(420), CheckPhase::Handshake);
        finish(&success, recovered).await?;
        {
            let state = cache.state.lock();
            assert!(!state.full);
            assert_eq!(state.entries[&url].last_failure, None);
            assert_eq!(state.entries[&url].retry_after, None);
            assert_eq!(state.entries[&url].failures, 0);
        }
        let refresh = clock.lookup(&cache, &url, at(431), CheckPhase::Recheck);
        finish(&refresh, healthy).await?;
        let text = render(&cache.metrics)?;
        sample(
            &text,
            "lonewolf_s2s_crl_fetches_total{outcome=\"http_status\"} 2",
        );
        sample(
            &text,
            "lonewolf_s2s_crl_fetches_total{outcome=\"timeout\"} 1",
        );
        sample(
            &text,
            "lonewolf_s2s_crl_fetches_total{outcome=\"success\"} 2",
        );
        sample(&text, "lonewolf_s2s_crl_fetch_duration_seconds_count 5");
        accounting(&cache);
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn positive_time_addition_clamps_at_the_greatest_representable_time() {
    let base = SystemTime::UNIX_EPOCH;
    let limit = saturating_add(base, Duration::MAX);
    assert!(limit > base);
    assert!(limit.checked_add(Duration::from_nanos(1)).is_none());
    assert_eq!(saturating_add(limit, Duration::from_nanos(1)), limit);
    assert_eq!(
        saturating_add(base, Duration::from_secs(90)),
        base + Duration::from_secs(90)
    );
}
