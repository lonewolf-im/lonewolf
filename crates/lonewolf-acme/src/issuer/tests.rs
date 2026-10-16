// SPDX-License-Identifier: Apache-2.0

use super::*;
use rustls::pki_types::Der;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use x509_cert::ext::pkix::AuthorityKeyIdentifier;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_executor::block_on;
use futures_util::{FutureExt, future};
use serde_json::json;
use x509_cert::der::Encode;

const DIRECTORY: &str = "https://ca.example/directory";
const ORDER: &str = "https://ca.example/order/1";
const DNS: &str = "xmpp.example.com";
const NOW: u64 = 1_800_000_000;
const EXPIRY: u64 = NOW + 10_000;

#[derive(Clone, Default)]
struct Gate {
    remaining: Rc<Cell<Option<usize>>>,
    events: Rc<RefCell<Vec<&'static str>>>,
}

impl Gate {
    async fn enter(&self, name: &'static str) {
        self.events.borrow_mut().push(name);
        if let Some(remaining) = self.remaining.get() {
            if remaining == 0 {
                future::pending::<()>().await;
            }
            self.remaining.set(Some(remaining - 1));
        }
    }
}

#[derive(Default)]
struct Records {
    account: Option<StoredAccount>,
    host: Option<StoredHost>,
    failure: Option<StateError>,
    fail_candidate: Option<StateError>,
    fail_terminal: bool,
}

#[derive(Clone, Default)]
struct Memory {
    records: Arc<PlMutex<Records>>,
    gate: Gate,
}

impl Storage for Memory {
    async fn account(&self) -> Result<Option<StoredAccount>, StateError> {
        self.gate.enter("load account").await;
        let records = self.records.lock();
        if let Some(error) = records.failure {
            return Err(error);
        }
        Ok(records.account.clone())
    }
    async fn save_account(&self, account: &StoredAccount) -> Result<(), StateError> {
        self.gate.enter("save account").await;
        account.validate()?;
        {
            let mut records = self.records.lock();
            if let Some(error) = records.failure {
                return Err(error);
            }
            records.account = Some(account.clone());
        }
        self.gate.enter("account committed").await;
        Ok(())
    }
    async fn host(&self, _: &str) -> Result<Option<StoredHost>, StateError> {
        self.gate.enter("load host").await;
        let records = self.records.lock();
        if let Some(error) = records.failure {
            return Err(error);
        }
        Ok(records.host.clone())
    }
    async fn save_host(&self, host: &StoredHost) -> Result<(), StateError> {
        self.gate.enter("save host").await;
        host.validate()?;
        {
            let mut records = self.records.lock();
            if let Some(error) = records.failure {
                return Err(error);
            }
            if host.certificate.is_some()
                && host.order.is_none()
                && host.retry.failures == 0
                && let Some(error) = records.fail_candidate
            {
                return Err(error);
            }
            if records.fail_terminal
                && host.order.is_none()
                && host.retry.failures != 0
                && records
                    .host
                    .as_ref()
                    .is_some_and(|host| host.order.is_some())
            {
                return Err(StateError::StateUncertain);
            }
            records.host = Some(host.clone());
        }
        self.gate.enter("host committed").await;
        Ok(())
    }
}

struct FakeClock {
    elapsed: Cell<Duration>,
    start: Instant,
    sleeps: RefCell<Vec<Duration>>,
    jitter: Cell<u64>,
    block_sleep: Cell<Option<Duration>>,
}

impl Default for FakeClock {
    fn default() -> Self {
        Self {
            elapsed: Cell::new(Duration::ZERO),
            start: Instant::now(),
            sleeps: RefCell::new(Vec::new()),
            jitter: Cell::new(0),
            block_sleep: Cell::new(None),
        }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW) + self.elapsed.get()
    }
    fn monotonic(&self) -> Instant {
        self.start + self.elapsed.get()
    }
    fn uniform(&self, max: u64) -> Result<u64, AttemptFailure> {
        Ok(self.jitter.get().min(max))
    }
    async fn sleep(&self, duration: Duration) {
        self.sleeps.borrow_mut().push(duration);
        if self
            .block_sleep
            .get()
            .is_some_and(|minimum| duration >= minimum)
        {
            future::pending::<()>().await;
        }
        self.elapsed.set(self.elapsed.get() + duration);
    }
}

struct Script {
    memory: Memory,
    challenges: Challenges,
    gate: Gate,
    status: OrderStatus,
    initial: OrderStatus,
    auth_status: AuthorizationStatus,
    challenge_status: ChallengeStatus,
    missing_challenge: bool,
    wrong_name: bool,
    ari: bool,
    replaced: Option<CertificateIdentifier<'static>>,
    hint: Cell<Option<SystemTime>>,
    next_hint: Option<SystemTime>,
    hint_at: Option<&'static str>,
    echo_at: Option<(&'static str, Option<CertificateIdentifier<'static>>)>,
    error: Option<(&'static str, AttemptFailure)>,
    new_orders: usize,
    resumes: usize,
    finalizes: usize,
    ready_calls: usize,
    registration_keys: Vec<Vec<u8>>,
    restore_host: Option<StoredHost>,
    csr: Vec<u8>,
    expired: bool,
    omit_expiry: bool,
    stay_pending: bool,
    pem: String,
}

fn host() -> ManagedHost {
    ManagedHost {
        xmpp_domain: DNS.into(),
        dns_name: DNS.into(),
    }
}

fn credential_bytes(key: &[u8], directory: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(&json!({ "id": "https://ca.example/account/1", "key_pkcs8": URL_SAFE_NO_PAD.encode(key), "directory": directory })).unwrap())
}

fn certificate() -> Vec<u8> {
    let signer = CertificateSigner::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![DNS.into()]).unwrap();
    params.serial_number = Some(1u64.into());
    params.self_signed(&signer).unwrap().der().to_vec()
}

fn pem(der: &[u8]) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(der)
    )
}

impl Script {
    fn new(memory: Memory, challenges: Challenges) -> Self {
        Self {
            gate: memory.gate.clone(),
            memory,
            challenges,
            status: OrderStatus::Pending,
            initial: OrderStatus::Pending,
            auth_status: AuthorizationStatus::Pending,
            challenge_status: ChallengeStatus::Pending,
            missing_challenge: false,
            wrong_name: false,
            ari: false,
            replaced: None,
            hint: Cell::new(None),
            next_hint: None,
            hint_at: None,
            echo_at: None,
            error: None,
            new_orders: 0,
            resumes: 0,
            finalizes: 0,
            ready_calls: 0,
            registration_keys: Vec::new(),
            restore_host: None,
            csr: Vec::new(),
            expired: false,
            omit_expiry: false,
            stay_pending: false,
            pem: pem(&certificate()),
        }
    }
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            status: self.status,
            url: ORDER.into(),
            expires: if self.omit_expiry {
                None
            } else {
                Some(if self.expired { NOW - 1 } else { EXPIRY })
            },
            replaces: self.replaced.clone(),
            dns_name: if self.wrong_name {
                "wrong.example.com".into()
            } else {
                DNS.into()
            },
        }
    }
    async fn step(&mut self, name: &'static str) -> Result<(), AttemptFailure> {
        self.gate.enter(name).await;
        if self
            .echo_at
            .as_ref()
            .is_some_and(|(stage, _)| *stage == name)
        {
            self.replaced = self.echo_at.take().unwrap().1;
        }
        if self.error.as_ref().is_some_and(|(at, _)| *at == name) {
            return Err(self.error.take().unwrap().1);
        }
        if self.hint_at.is_none_or(|stage| stage == name)
            && let Some(hint) = self.next_hint.take()
        {
            self.hint.set(Some(hint));
        }
        Ok(())
    }
}

impl Engine for Script {
    fn directory(&self) -> &str {
        DIRECTORY
    }
    fn reset_hint(&self) {
        self.hint.set(None);
    }
    fn hint(&self) -> Option<SystemTime> {
        self.hint.get()
    }
    fn supports_ari(&self) -> bool {
        self.ari
    }
    async fn renewal(
        &mut self,
        _: &CertificateIdentifier<'_>,
    ) -> Result<RenewalWindow, AttemptFailure> {
        self.step("renewal info").await?;
        Ok(RenewalWindow {
            start: Some(NOW),
            end: Some(NOW + 100),
            delay: 60,
        })
    }
    async fn register(&mut self, key: &[u8]) -> Result<Zeroizing<Vec<u8>>, AttemptFailure> {
        assert_eq!(
            self.memory
                .records
                .lock()
                .account
                .as_ref()
                .unwrap()
                .key_pkcs8
                .as_slice(),
            key
        );
        self.registration_keys.push(key.to_vec());
        self.step("register").await?;
        Ok(credential_bytes(key, DIRECTORY))
    }
    async fn restore(&mut self, _: AccountCredentials) -> Result<(), AttemptFailure> {
        self.step("restore").await?;
        if let Some(host) = self.restore_host.take() {
            self.memory.records.lock().host = Some(host);
        }
        Ok(())
    }
    async fn new_order(
        &mut self,
        _: &str,
        replaces: Option<CertificateIdentifier<'static>>,
    ) -> Result<Snapshot, AttemptFailure> {
        {
            let records = self.memory.records.lock();
            let account = records.account.as_ref().unwrap();
            assert!(account.credentials_json.is_some());
            let pending = records.host.as_ref().unwrap().order.as_ref().unwrap();
            assert_ne!(pending.key_pkcs8.as_slice(), account.key_pkcs8.as_slice());
            assert!(!pending.csr_der.is_empty());
        }
        self.new_orders += 1;
        self.replaced = replaces;
        self.step("new order").await?;
        self.status = self.initial;
        Ok(self.snapshot())
    }
    async fn resume(&mut self, url: &str) -> Result<Snapshot, AttemptFailure> {
        assert_eq!(url, ORDER);
        self.resumes += 1;
        self.step("resume").await?;
        Ok(self.snapshot())
    }
    async fn authorization(&mut self, _: bool) -> Result<Authorization, AttemptFailure> {
        self.step("authorization").await?;
        Ok(Authorization {
            dns_name: DNS.into(),
            wildcard: false,
            status: self.auth_status,
            challenge: if self.missing_challenge {
                None
            } else {
                Some(HttpChallenge {
                    token: "A".repeat(22),
                    authorization: format!("{}.{}", "A".repeat(22), "B".repeat(43)),
                    status: self.challenge_status,
                })
            },
        })
    }
    async fn ready(&mut self) -> Result<(), AttemptFailure> {
        assert!(self.challenges.lookup(DNS, &"A".repeat(22)).is_some());
        {
            let records = self.memory.records.lock();
            let pending = records.host.as_ref().unwrap().order.as_ref().unwrap();
            assert_eq!(pending.url.as_deref(), Some(ORDER));
            assert_eq!(pending.expires_unix, Some(EXPIRY));
        }
        self.step("ready").await?;
        self.ready_calls += 1;
        if !self.stay_pending {
            self.status = OrderStatus::Ready;
        }
        Ok(())
    }
    async fn refresh(&mut self) -> Result<Snapshot, AttemptFailure> {
        self.step("refresh").await?;
        self.status = match self.status {
            OrderStatus::Processing => OrderStatus::Valid,
            OrderStatus::Pending
                if self.auth_status == AuthorizationStatus::Valid
                    || self.challenge_status == ChallengeStatus::Processing =>
            {
                OrderStatus::Ready
            }
            status => status,
        };
        Ok(self.snapshot())
    }
    async fn finalize(&mut self, csr: &[u8]) -> Result<Snapshot, AttemptFailure> {
        assert_eq!(
            self.memory
                .records
                .lock()
                .host
                .as_ref()
                .unwrap()
                .order
                .as_ref()
                .unwrap()
                .csr_der,
            csr
        );
        self.step("finalize").await?;
        self.csr = csr.into();
        self.finalizes += 1;
        self.status = OrderStatus::Processing;
        Ok(self.snapshot())
    }
    async fn certificate(&mut self) -> Result<String, AttemptFailure> {
        self.step("certificate").await?;
        Ok(self.pem.clone())
    }
}

struct TestInstaller {
    records: Arc<PlMutex<Records>>,
    active: PlMutex<Vec<CertificateValidity>>,
    invalid: Option<InstallError>,
}

impl Installer for TestInstaller {
    type Prepared = CertificateValidity;
    fn prepare(
        &self,
        _: &ManagedHost,
        _: &CertificateMaterial,
    ) -> Result<PreparedInstall<Self::Prepared>, InstallError> {
        if let Some(error) = self.invalid {
            return Err(error);
        }
        let validity = CertificateValidity {
            not_before_unix: NOW - 1000,
            not_after_unix: NOW + 100_000,
        };
        Ok(PreparedInstall {
            candidate: validity,
            validity,
        })
    }
    fn activate(&self, validity: Self::Prepared) {
        let records = self.records.lock();
        let host = records.host.as_ref().unwrap();
        assert!(host.order.is_none());
        assert_eq!(
            host.retry,
            RetryState {
                failures: 0,
                not_before_unix: 0
            }
        );
        let stored = host.certificate.as_ref().unwrap();
        assert_eq!(
            (stored.not_before_unix, stored.not_after_unix),
            (validity.not_before_unix, validity.not_after_unix)
        );
        self.active.lock().push(validity);
    }
}

fn setup() -> (Memory, Challenges, FakeClock, Script, TestInstaller) {
    let memory = Memory::default();
    let challenges = Challenges::new(&[host()]).unwrap();
    let key = CertificateSigner::generate().unwrap().pkcs8().unwrap();
    memory.records.lock().account = Some(StoredAccount {
        credentials_json: Some(credential_bytes(&key, DIRECTORY)),
        key_pkcs8: key,
        retry: RetryState {
            failures: 0,
            not_before_unix: 0,
        },
    });
    let script = Script::new(memory.clone(), challenges.clone());
    let installer = TestInstaller {
        records: memory.records.clone(),
        active: PlMutex::new(Vec::new()),
        invalid: None,
    };
    (memory, challenges, FakeClock::default(), script, installer)
}

#[test]
fn new_pending_ready_processing_valid_commits_then_activates() {
    let (memory, challenges, clock, mut engine, installer) = setup();
    let success = block_on(attempt(
        &memory,
        &challenges,
        &clock,
        &mut engine,
        host(),
        &installer,
        None,
    ))
    .unwrap();
    assert_eq!(installer.active.lock().as_slice(), &[success.validity]);
    assert_eq!(
        (engine.new_orders, engine.ready_calls, engine.finalizes),
        (1, 1, 1)
    );
    assert!(challenges.lookup(DNS, &"A".repeat(22)).is_none());
    let stored = memory.records.lock();
    let certificate = stored.host.as_ref().unwrap().certificate.as_ref().unwrap();
    assert_eq!(certificate.renew_at_unix, NOW - 1000 + 101_000 / 2);
    assert_eq!(certificate.ari_check_at_unix, NOW + 6);
}

#[test]
fn reused_valid_authorization_and_processing_challenge_need_no_ack() {
    for valid in [false, true] {
        let (memory, challenges, clock, mut engine, installer) = setup();
        if valid {
            engine.auth_status = AuthorizationStatus::Valid;
            engine.missing_challenge = true;
        } else {
            engine.challenge_status = ChallengeStatus::Processing;
        }
        block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        ))
        .unwrap();
        assert_eq!(engine.ready_calls, 0);
    }
}

#[test]
fn ready_processing_valid_start_states_never_repeat_finalize() {
    for state in [
        OrderStatus::Ready,
        OrderStatus::Processing,
        OrderStatus::Valid,
    ] {
        let (memory, challenges, clock, mut engine, installer) = setup();
        engine.initial = state;
        block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        ))
        .unwrap();
        assert_eq!(engine.finalizes, usize::from(state == OrderStatus::Ready));
        assert_eq!(engine.ready_calls, 0);
    }
}

#[test]
fn terminal_states_clear_only_with_retry_commit() {
    for scenario in 0..4 {
        let (memory, challenges, clock, mut engine, installer) = setup();
        match scenario {
            0 => engine.initial = OrderStatus::Invalid,
            1 => engine.expired = true,
            2 => engine.missing_challenge = true,
            _ => engine.auth_status = AuthorizationStatus::Expired,
        }
        let error = block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        ))
        .unwrap_err();
        assert!(error.terminal_order);
        let records = memory.records.lock();
        let host = records.host.as_ref().unwrap();
        assert!(host.order.is_none());
        assert_eq!(host.retry.failures, 1);
        assert!(host.retry.not_before_unix >= NOW + 60);
        assert!(installer.active.lock().is_empty());
        assert!(challenges.lookup(DNS, &"A".repeat(22)).is_none());
    }
}

#[test]
fn transient_failure_resumes_url_key_csr_without_new_order() {
    let (memory, challenges, clock, mut engine, installer) = setup();
    engine.error = Some(("ready", failure(FailureKind::Network)));
    block_on(attempt(
        &memory,
        &challenges,
        &clock,
        &mut engine,
        host(),
        &installer,
        None,
    ))
    .unwrap_err();
    let original = memory
        .records
        .lock()
        .host
        .as_ref()
        .unwrap()
        .order
        .as_ref()
        .unwrap()
        .clone();
    assert!(!original.csr_der.is_empty());
    let deferred = block_on(attempt(
        &memory,
        &challenges,
        &clock,
        &mut engine,
        host(),
        &installer,
        None,
    ))
    .unwrap_err();
    assert_eq!(deferred.kind, FailureKind::Deferred);
    clock.elapsed.set(Duration::from_secs(60));
    block_on(attempt(
        &memory,
        &challenges,
        &clock,
        &mut engine,
        host(),
        &installer,
        None,
    ))
    .unwrap();
    assert_eq!(
        (engine.new_orders, engine.resumes, engine.finalizes),
        (1, 1, 1)
    );
    assert_eq!(engine.csr, original.csr_der);
    assert_eq!(
        memory
            .records
            .lock()
            .host
            .as_ref()
            .unwrap()
            .certificate
            .as_ref()
            .unwrap()
            .material
            .private_key_pkcs8,
        original.key_pkcs8
    );
}

#[test]
fn lost_new_order_response_enforces_cooldown_and_reuses_intent() {
    let (memory, challenges, clock, mut engine, installer) = setup();
    engine.error = Some(("new order", failure(FailureKind::Network)));
    block_on(attempt(
        &memory,
        &challenges,
        &clock,
        &mut engine,
        host(),
        &installer,
        None,
    ))
    .unwrap_err();
    let original = memory
        .records
        .lock()
        .host
        .as_ref()
        .unwrap()
        .order
        .as_ref()
        .unwrap()
        .clone();
    assert!(original.url.is_none());
    assert_eq!(
        block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None
        ))
        .unwrap_err()
        .kind,
        FailureKind::Deferred
    );
    assert_eq!(engine.new_orders, 1);
    clock.elapsed.set(Duration::from_secs(60));
    block_on(attempt(
        &memory,
        &challenges,
        &clock,
        &mut engine,
        host(),
        &installer,
        None,
    ))
    .unwrap();
    assert_eq!(engine.csr, original.csr_der);
    assert_eq!(engine.new_orders, 2);
}

#[test]
fn account_initialization_recovery_and_local_restore() {
    let (memory, _, clock, mut engine, _) = setup();
    memory.records.lock().account = None;
    engine.error = Some(("register", failure(FailureKind::Network)));
    block_on(ensure_account(&memory, &clock, &mut engine, DIRECTORY)).unwrap_err();
    let key = memory
        .records
        .lock()
        .account
        .as_ref()
        .unwrap()
        .key_pkcs8
        .clone();
    assert_eq!(
        block_on(ensure_account(&memory, &clock, &mut engine, DIRECTORY))
            .unwrap_err()
            .kind,
        FailureKind::Deferred
    );
    clock.elapsed.set(Duration::from_secs(60));
    block_on(ensure_account(&memory, &clock, &mut engine, DIRECTORY)).unwrap();
    assert_eq!(engine.registration_keys, vec![key.to_vec(), key.to_vec()]);
    let count = engine.gate.events.borrow().len();
    block_on(ensure_account(&memory, &clock, &mut engine, DIRECTORY)).unwrap();
    assert_eq!(&engine.gate.events.borrow()[count..], &["load account"]);
}

#[test]
fn corrupt_credentials_namespace_or_key_never_reaches_network() {
    for bad_namespace in [false, true] {
        let (memory, challenges, clock, mut engine, installer) = setup();
        {
            let mut records = memory.records.lock();
            let account = records.account.as_mut().unwrap();
            let other_key = CertificateSigner::generate().unwrap().pkcs8().unwrap();
            account.credentials_json = Some(credential_bytes(
                if bad_namespace {
                    &account.key_pkcs8
                } else {
                    &other_key
                },
                if bad_namespace {
                    "https://other.example/directory"
                } else {
                    DIRECTORY
                },
            ));
        }
        let error = block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        ))
        .unwrap_err();
        assert_eq!(error.state_error, Some(StateError::CorruptData));
        assert!(!engine.gate.events.borrow().contains(&"restore"));
        assert_eq!(engine.new_orders, 0);
    }
}

#[test]
fn material_and_commit_failures_never_activate() {
    for scenario in 0..6 {
        let (memory, challenges, clock, mut engine, mut installer) = setup();
        engine.initial = OrderStatus::Valid;
        let old = CertificateValidity {
            not_before_unix: NOW - 5000,
            not_after_unix: NOW + 500_000,
        };
        memory.records.lock().host = Some(StoredHost {
            host: host(),
            order: None,
            retry: RetryState {
                failures: 0,
                not_before_unix: 0,
            },
            certificate: Some(StoredCertificate {
                replaces: None,
                material: CertificateMaterial {
                    chain: vec![certificate()],
                    private_key_pkcs8: CertificateSigner::generate().unwrap().pkcs8().unwrap(),
                },
                not_before_unix: old.not_before_unix,
                not_after_unix: old.not_after_unix,
                renew_at_unix: NOW + 100,
                ari_check_at_unix: NOW,
                fallback_at_unix: 0,
                ari_window: None,
                ari_failures: 0,
            }),
        });
        installer.active.lock().push(old);
        match scenario {
            0 => installer.invalid = Some(InstallError::Invalid),
            1 => installer.invalid = Some(InstallError::Expired),
            2 => installer.invalid = Some(InstallError::NotYetValid),
            3 => engine.pem = "private remote detail".into(),
            4 => memory.records.lock().fail_candidate = Some(StateError::Unavailable),
            _ => memory.records.lock().fail_candidate = Some(StateError::StateUncertain),
        }
        let error = block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        ))
        .unwrap_err();
        assert_eq!(
            error.kind,
            if scenario >= 4 {
                FailureKind::State
            } else {
                FailureKind::Material
            }
        );
        assert_eq!(installer.active.lock().as_slice(), &[old]);
        assert_eq!(
            memory
                .records
                .lock()
                .host
                .as_ref()
                .unwrap()
                .certificate
                .as_ref()
                .unwrap()
                .not_after_unix,
            old.not_after_unix
        );
        assert!(memory.records.lock().host.as_ref().unwrap().order.is_some());
    }
}

#[test]
fn retry_after_beyond_budget_keeps_resumable_state_without_sleep() {
    let (memory, challenges, clock, mut engine, installer) = setup();
    engine.next_hint = Some(UNIX_EPOCH + Duration::from_secs(NOW + 901));
    let error = block_on(attempt(
        &memory,
        &challenges,
        &clock,
        &mut engine,
        host(),
        &installer,
        None,
    ))
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Timeout);
    assert_eq!(
        error.retry_not_before,
        Some(UNIX_EPOCH + Duration::from_secs(NOW + 901))
    );
    assert!(clock.sleeps.borrow().is_empty());
    assert!(memory.records.lock().host.as_ref().unwrap().order.is_some());
}

#[test]
fn retry_after_wait_and_exponential_polling_use_private_clock() {
    let (memory, challenges, clock, mut engine, installer) = setup();
    engine.next_hint = Some(UNIX_EPOCH + Duration::from_secs(NOW + 10));
    block_on(attempt(
        &memory,
        &challenges,
        &clock,
        &mut engine,
        host(),
        &installer,
        None,
    ))
    .unwrap();
    assert_eq!(
        clock.sleeps.borrow().as_slice(),
        &[
            Duration::from_secs(10),
            Duration::from_secs(2),
            Duration::from_secs(4)
        ]
    );
}

#[test]
fn cancellation_at_every_storage_and_protocol_boundary_drops_leases_and_reloads() {
    let (memory, challenges, clock, mut engine, installer) = setup();
    block_on(attempt(
        &memory,
        &challenges,
        &clock,
        &mut engine,
        host(),
        &installer,
        None,
    ))
    .unwrap();
    let boundary_count = memory.gate.events.borrow().len();
    let mut committed_candidate_observed = false;
    for boundary in 0..boundary_count {
        let (memory, challenges, clock, mut engine, installer) = setup();
        memory.gate.remaining.set(Some(boundary));
        let future = attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        );
        assert!(future.now_or_never().is_none(), "boundary {boundary}");
        assert!(installer.active.lock().is_empty());
        assert!(challenges.lookup(DNS, &"A".repeat(22)).is_none());
        memory.gate.remaining.set(None);
        let before = memory
            .records
            .lock()
            .host
            .as_ref()
            .and_then(|host| host.order.clone());
        let old_new = engine.new_orders;
        let old_finalize = engine.finalizes;
        clock.elapsed.set(Duration::from_secs(120));
        let completed = memory
            .records
            .lock()
            .host
            .as_ref()
            .is_some_and(|host| host.certificate.is_some() && host.order.is_none());
        if completed {
            assert_eq!(memory.gate.events.borrow().last(), Some(&"host committed"));
            let records = memory.records.lock();
            let retained = records.host.as_ref().unwrap();
            assert_eq!(retained.retry.failures, 0);
            assert_eq!(retained.retry.not_before_unix, 0);
            assert!(retained.order.is_none());
            assert!(
                !retained
                    .certificate
                    .as_ref()
                    .unwrap()
                    .material
                    .chain
                    .is_empty()
            );
            assert!(installer.active.lock().is_empty());
            committed_candidate_observed = true;
            continue;
        }
        block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        ))
        .unwrap();
        if before.as_ref().is_some_and(|order| order.url.is_some()) {
            assert_eq!(engine.new_orders, old_new);
        }
        if old_finalize != 0 {
            assert_eq!(engine.finalizes, old_finalize);
        }
        if let Some(before) = before {
            assert_eq!(
                memory
                    .records
                    .lock()
                    .host
                    .as_ref()
                    .unwrap()
                    .certificate
                    .as_ref()
                    .unwrap()
                    .material
                    .private_key_pkcs8,
                before.key_pkcs8
            );
        }
    }
    assert!(committed_candidate_observed);
}

#[test]
fn account_cancellation_at_every_boundary_reuses_durable_key() {
    let mut response_before_save_observed = false;
    for boundary in 0..7 {
        let (memory, _, clock, mut engine, _) = setup();
        memory.records.lock().account = None;
        memory.gate.remaining.set(Some(boundary));
        let outcome = ensure_account(&memory, &clock, &mut engine, DIRECTORY).now_or_never();
        if outcome.is_some() {
            continue;
        }
        if engine.registration_keys.len() == 1
            && memory.gate.events.borrow().last() == Some(&"save account")
        {
            let records = memory.records.lock();
            let account = records.account.as_ref().unwrap();
            assert!(account.credentials_json.is_none());
            assert!(account.retry.not_before_unix > NOW);
            assert_eq!(account.key_pkcs8.as_slice(), engine.registration_keys[0]);
            response_before_save_observed = true;
        }
        memory.gate.remaining.set(None);
        let old = memory
            .records
            .lock()
            .account
            .as_ref()
            .map(|account| account.key_pkcs8.clone());
        clock.elapsed.set(Duration::from_secs(61));
        block_on(ensure_account(&memory, &clock, &mut engine, DIRECTORY)).unwrap();
        if let Some(old) = old {
            assert_eq!(
                memory.records.lock().account.as_ref().unwrap().key_pkcs8,
                old
            );
        }
    }
    assert!(response_before_save_observed);
}

#[test]
fn retry_backoff_and_jitter_are_sampled_once_and_rounded_up() {
    let clock = FakeClock::default();
    clock.jitter.set(u64::MAX);
    for (failures, delay) in [(0, 66), (1, 660), (2, 6600), (3, 95040), (u32::MAX, 95040)] {
        let mut retry = RetryState {
            failures,
            not_before_unix: 0,
        };
        assert_eq!(reserve(&mut retry, &clock).unwrap(), delay);
        assert_eq!(retry.failures, failures.saturating_add(1));
        assert_eq!(retry.not_before_unix, NOW + delay);
        refresh_retry(
            &mut retry,
            &clock,
            delay,
            Some(clock.now() + Duration::from_secs(delay) + Duration::from_millis(1)),
        )
        .unwrap();
        assert_eq!(retry.not_before_unix, NOW + delay + 1);
    }
}

#[test]
fn fallback_uses_lifetime_threshold_and_jitter_without_now_clamping() {
    let clock = FakeClock::default();
    for lifetime in [100, 863_999, 864_000, 864_001] {
        let validity = CertificateValidity {
            not_before_unix: 1000,
            not_after_unix: 1000 + lifetime,
        };
        let expected = 1000
            + if lifetime >= 864000 {
                2 * lifetime / 3
            } else {
                lifetime / 2
            };
        assert_eq!(fallback(validity, &clock).unwrap(), expected);
        clock.jitter.set(lifetime / 20);
        assert_eq!(
            fallback(validity, &clock).unwrap(),
            expected - lifetime / 20
        );
        clock.jitter.set(0);
    }
}

#[test]
fn bounded_pem_rejects_malformed_der_trailing_data_and_excess_chains() {
    let valid = pem(&certificate());
    assert_eq!(parse_chain(&valid).unwrap().len(), 1);
    for invalid in [
        String::new(),
        pem(b"invalid"),
        format!("{valid}garbage"),
        valid.repeat(17),
        "x".repeat(2 * 1024 * 1024 + 1),
    ] {
        assert_eq!(
            parse_chain(&invalid).unwrap_err().kind,
            FailureKind::Material
        );
    }
}

fn ari_material() -> CertificateMaterial {
    let aki = URL_SAFE_NO_PAD
        .decode("aYhba4dGQEHhs3uEe6CuLN4ByNQ")
        .unwrap();
    let signer = CertificateSigner::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![DNS.into()]).unwrap();
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&[0x87, 0x65, 0x43, 0x21]));
    let value = AuthorityKeyIdentifier {
        key_identifier: Some(x509_cert::der::asn1::OctetString::new(aki).unwrap()),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 35],
            value.to_der().unwrap(),
        ));
    CertificateMaterial {
        chain: vec![params.self_signed(&signer).unwrap().der().to_vec()],
        private_key_pkcs8: signer.pkcs8().unwrap(),
    }
}

#[test]
fn replacement_identifier_preserves_der_integer_content_leading_zero() {
    let material = ari_material();
    assert_eq!(
        replacement_id(&material).unwrap().to_string(),
        "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
    );
}

#[test]
fn metadata_rejects_missing_extra_wrong_identifiers_null_and_invalid_expiry() {
    for identifiers in [
        json!([]),
        json!([{"type":"dns","value":DNS},{"type":"dns","value":DNS}]),
        json!([{"type":"ip","value":"127.0.0.1"}]),
        json!([{"type":"dns","value":"*.example.com"}]),
    ] {
        assert!(
            order_metadata(&serde_json::to_vec(&json!({"identifiers":identifiers})).unwrap())
                .is_err()
        );
    }
    for expires in [
        json!(null),
        json!(42),
        json!("bad"),
        json!("1960-01-01T00:00:00Z"),
    ] {
        assert!(
            order_metadata(
                &serde_json::to_vec(
                    &json!({"identifiers":[{"type":"dns","value":DNS}],"expires":expires})
                )
                .unwrap()
            )
            .is_err()
        );
    }
    assert!(order_metadata(b"{}").is_err());
}

#[test]
fn metadata_rfc3339_offsets_fractions_and_absence() {
    let metadata = |expires: &str| {
        order_metadata(
            &serde_json::to_vec(
                &json!({"identifiers":[{"type":"dns","value":DNS}],"expires":expires}),
            )
            .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(
        metadata("2027-01-15T08:00:00.999999999Z").expires_unix,
        Some(NOW)
    );
    assert_eq!(
        metadata("2027-01-15T09:00:00+01:00").expires_unix,
        Some(NOW)
    );
    assert!(
        order_metadata(
            &serde_json::to_vec(&json!({"identifiers":[{"type":"dns","value":DNS}]})).unwrap()
        )
        .unwrap()
        .expires_unix
        .is_none()
    );
}

#[test]
fn metadata_status_rules_and_wrong_identity_prevent_finalize_or_activation() {
    for status in [
        OrderStatus::Pending,
        OrderStatus::Ready,
        OrderStatus::Processing,
        OrderStatus::Valid,
        OrderStatus::Invalid,
    ] {
        let (memory, challenges, clock, mut engine, installer) = setup();
        engine.initial = status;
        engine.omit_expiry = true;
        let outcome = block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        ));
        assert!(outcome.is_err());
        if matches!(status, OrderStatus::Pending | OrderStatus::Valid) {
            assert_eq!(engine.finalizes, 0);
        }
    }
    for status in [OrderStatus::Ready, OrderStatus::Valid] {
        let (memory, challenges, clock, mut engine, installer) = setup();
        engine.initial = status;
        engine.wrong_name = true;
        assert_eq!(
            block_on(attempt(
                &memory,
                &challenges,
                &clock,
                &mut engine,
                host(),
                &installer,
                None
            ))
            .unwrap_err()
            .kind,
            FailureKind::Protocol
        );
        assert_eq!(engine.finalizes, 0);
        assert!(installer.active.lock().is_empty());
    }
}

#[derive(Clone)]
struct Responses(Arc<PlMutex<VecDeque<http::Response<Full<Bytes>>>>>);

impl AttemptTransport for Responses {
    fn reset_retry_hint(&self) {}
    fn retry_not_before(&self) -> Option<SystemTime> {
        None
    }
}

impl HttpClient for Responses {
    fn request(
        &self,
        _: http::Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> Pin<
        Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>,
    > {
        let response = self.0.lock().pop_front();
        Box::pin(async move {
            response.map(Into::into).ok_or_else(|| {
                instant_acme::Error::Other(Box::new(AcmeError::new(AcmeErrorKind::Timeout)))
            })
        })
    }
}

fn response(status: u16, bytes: impl Into<Bytes>) -> http::Response<Full<Bytes>> {
    http::Response::builder()
        .status(status)
        .header("replay-nonce", "nonce")
        .header("retry-after", "2")
        .body(Full::new(bytes.into()))
        .unwrap()
}

fn request(method: &str, url: &str) -> http::Request<instant_acme::BodyWrapper<Bytes>> {
    http::Request::builder()
        .method(method)
        .uri(url)
        .body(instant_acme::BodyWrapper::default())
        .unwrap()
}

#[test]
fn observer_preserves_bytes_headers_status_and_ignores_unrelated_and_nonce_errors() {
    block_on(async {
        let body = Bytes::from(serde_json::to_vec(&json!({"identifiers":[{"type":"dns","value":DNS}],"expires":"2027-01-15T08:00:00Z"})).unwrap());
        let observations = Arc::new(PlMutex::new(Observations::default()));
        let slot = Arc::new(PlMutex::new(None));
        observations.lock().armed = Some((ORDER.parse().unwrap(), slot.clone(), false));
        let client = DirectoryClient {
            transport: Responses(Arc::new(PlMutex::new(VecDeque::from([
                response(200, body.clone()),
                response(400, "nonce error"),
                response(201, body.clone()),
            ])))),
            directory: DIRECTORY.parse().unwrap(),
            observations,
        };
        client
            .request(request("POST", "https://ca.example/authz/1"))
            .await
            .unwrap();
        assert!(slot.lock().is_none());
        client.request(request("POST", ORDER)).await.unwrap();
        assert!(slot.lock().is_none());
        let mut result = client.request(request("POST", ORDER)).await.unwrap();
        assert_eq!(result.parts.status, 201);
        assert_eq!(result.parts.headers["replay-nonce"], "nonce");
        assert_eq!(result.parts.headers["retry-after"], "2");
        assert_eq!(result.body.into_bytes().await.unwrap(), body);
        assert_eq!(
            slot.lock().as_ref().unwrap().as_ref().unwrap().dns_name,
            DNS
        );
    });
}

#[test]
fn observer_generation_ownership_ignores_late_and_other_attempt_responses() {
    block_on(async {
        let body = Bytes::from(
            serde_json::to_vec(&json!({"identifiers":[{"type":"dns","value":DNS}]})).unwrap(),
        );
        let observations = Arc::new(PlMutex::new(Observations::default()));
        let old = Arc::new(PlMutex::new(None));
        observations.lock().armed = Some((ORDER.parse().unwrap(), old.clone(), false));
        let client = DirectoryClient {
            transport: Responses(Arc::new(PlMutex::new(VecDeque::from([response(
                200, body,
            )])))),
            directory: DIRECTORY.parse().unwrap(),
            observations: observations.clone(),
        };
        let outstanding = client.request(request("POST", ORDER));
        let new = Arc::new(PlMutex::new(None));
        observations.lock().armed = Some((ORDER.parse().unwrap(), new.clone(), false));
        outstanding.await.unwrap();
        assert!(old.lock().is_none());
        assert!(new.lock().is_none());
        assert!(observations.lock().response_status.is_none());
        assert!(Observations::default().armed.is_none());
    });
}

#[test]
fn upstream_handles_bad_nonce_without_a_second_jws_stack() {
    block_on(async {
        let responses = Responses(Arc::new(PlMutex::new(VecDeque::from([
            response(200, json!({"newNonce":"https://ca.example/nonce","newAccount":"https://ca.example/account","newOrder":"https://ca.example/order"}).to_string()),
            response(200, ""),
            response(400, json!({"type":"urn:ietf:params:acme:error:badNonce","status":400}).to_string()),
            http::Response::builder().status(201).header("location","https://ca.example/account/1").header("replay-nonce","fresh").body(Full::new(Bytes::from_static(b"{}"))).unwrap(),
        ]))));
        let (key, der) = Key::generate(crypto_provider()).unwrap();
        let (_, credentials) = Account::builder(Box::new(responses.clone()), crypto_provider())
            .unwrap()
            .create_from_key((key, PrivateKeyDer::Pkcs8(der)), DIRECTORY.into())
            .await
            .unwrap();
        assert!(!credentials.private_key().secret_pkcs8_der().is_empty());
        assert!(responses.0.lock().is_empty());
    });
}

#[test]
fn error_classification_retains_no_remote_details() {
    for (kind, expected) in [
        ("rateLimited", FailureKind::RateLimited),
        ("accountDoesNotExist", FailureKind::Account),
        ("unauthorized", FailureKind::Authorization),
        ("unknown", FailureKind::Protocol),
    ] {
        let error: instant_acme::Problem = serde_json::from_value(json!({"type":format!("urn:ietf:params:acme:error:{kind}"),"detail":"secret remote response","status":400})).unwrap();
        let classified = classify(instant_acme::Error::Api(error));
        assert_eq!(classified.kind, expected);
        assert_eq!(classified.status, Some(400));
        assert!(!format!("{classified:?} {classified}").contains("secret"));
    }
}

#[test]
fn pending_poll_backoff_caps_at_thirty_seconds_and_budget_retains_order() {
    let (memory, challenges, clock, mut engine, installer) = setup();
    engine.stay_pending = true;
    let error = block_on(attempt(
        &memory,
        &challenges,
        &clock,
        &mut engine,
        host(),
        &installer,
        None,
    ))
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Timeout);
    assert!(clock.elapsed.get() < ATTEMPT_BUDGET);
    assert_eq!(
        &clock.sleeps.borrow()[..5],
        &[
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8),
            Duration::from_secs(16),
            Duration::from_secs(30)
        ]
    );
    assert!(
        clock
            .sleeps
            .borrow()
            .iter()
            .all(|duration| *duration <= Duration::from_secs(30))
    );
    let records = memory.records.lock();
    assert_eq!(
        records
            .host
            .as_ref()
            .unwrap()
            .order
            .as_ref()
            .unwrap()
            .url
            .as_deref(),
        Some(ORDER)
    );
    assert_eq!(records.host.as_ref().unwrap().retry.failures, 1);
    assert!(challenges.lookup(DNS, &"A".repeat(22)).is_none());
}

#[test]
fn failed_terminal_commit_preserves_order_and_returns_fatal_state() {
    let (memory, challenges, clock, mut engine, installer) = setup();
    memory.records.lock().fail_terminal = true;
    engine.error = Some((
        "refresh",
        AttemptFailure {
            terminal_order: true,
            status: Some(404),
            ..failure(FailureKind::Protocol)
        },
    ));
    let error = block_on(attempt(
        &memory,
        &challenges,
        &clock,
        &mut engine,
        host(),
        &installer,
        None,
    ))
    .unwrap_err();
    assert_eq!(error.state_error, Some(StateError::StateUncertain));
    assert!(!error.terminal_order);
    assert!(memory.records.lock().host.as_ref().unwrap().order.is_some());
    assert!(installer.active.lock().is_empty());
    assert!(challenges.lookup(DNS, &"A".repeat(22)).is_none());
}

#[test]
fn optional_expiry_never_erases_the_durable_expiry() {
    block_on(async {
        let (memory, challenges, clock, mut engine, _) = setup();
        let (key_pkcs8, csr_der) = new_certificate_request(DNS).unwrap();
        let mut driver = Driver {
            store: &memory,
            challenges: &challenges,
            clock: &clock,
            engine: &mut engine,
            delay: 60,
            deadline: clock.monotonic() + ATTEMPT_BUDGET,
            host: StoredHost {
                host: host(),
                certificate: None,
                order: Some(PendingOrder {
                    replaces: None,
                    key_pkcs8,
                    csr_der,
                    url: None,
                    started_unix: NOW,
                    expires_unix: Some(EXPIRY),
                }),
                retry: RetryState {
                    failures: 1,
                    not_before_unix: NOW + 60,
                },
            },
        };
        for status in [
            OrderStatus::Ready,
            OrderStatus::Processing,
            OrderStatus::Invalid,
        ] {
            let snapshot = Snapshot {
                status,
                url: ORDER.into(),
                expires: None,
                replaces: None,
                dns_name: DNS.into(),
            };
            driver.observe(&snapshot, None).await.unwrap();
            assert_eq!(
                driver.host.order.as_ref().unwrap().expires_unix,
                Some(EXPIRY)
            );
            assert_eq!(
                memory
                    .records
                    .lock()
                    .host
                    .as_ref()
                    .unwrap()
                    .order
                    .as_ref()
                    .unwrap()
                    .expires_unix,
                Some(EXPIRY)
            );
        }
        for status in [OrderStatus::Pending, OrderStatus::Valid] {
            let snapshot = Snapshot {
                status,
                url: ORDER.into(),
                expires: None,
                replaces: None,
                dns_name: DNS.into(),
            };
            assert_eq!(
                driver.observe(&snapshot, None).await.unwrap_err().kind,
                FailureKind::Protocol
            );
        }
    });
}

#[test]
fn directory_observer_uses_parsed_uri_and_rejects_null_or_unsafe_ari() {
    block_on(async {
        for renewal_info in [
            None,
            Some(json!("https://ca.example/renewal")),
            Some(json!(null)),
            Some(json!("http://ca.example/renewal")),
            Some(json!(17)),
        ] {
            let mut body = json!({ "newOrder": "https://ca.example/order" });
            if let Some(value) = &renewal_info {
                body["renewalInfo"] = value.clone();
            }
            let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
            let observations = Arc::new(PlMutex::new(Observations::default()));
            let client = DirectoryClient {
                transport: Responses(Arc::new(PlMutex::new(VecDeque::from([response(
                    200,
                    bytes.clone(),
                )])))),
                directory: "https://ca.example".parse().unwrap(),
                observations: observations.clone(),
            };
            let result = client.request(request("GET", "https://ca.example/")).await;
            let valid = renewal_info
                .as_ref()
                .is_none_or(|value| value == "https://ca.example/renewal");
            assert_eq!(result.is_ok(), valid);
            if valid {
                let mut result = result.unwrap();
                assert_eq!(result.body.into_bytes().await.unwrap(), bytes);
                assert_eq!(observations.lock().ari, renewal_info.is_some());
                assert_eq!(
                    observations.lock().new_order.as_ref().unwrap(),
                    "https://ca.example/order"
                );
            }
        }
    });
}

#[test]
fn constructor_rejects_directory_namespace_mismatch_before_network() {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::open(directory.path().join("state.redb"), DIRECTORY.into())
            .await
            .unwrap();
        let transport = AcmeHttpClient::new(Default::default()).await.unwrap();
        let issuer = Issuer::new(
            store,
            Challenges::new(&[host()]).unwrap(),
            transport,
            "https://other.example/directory".into(),
        );
        assert_eq!(
            issuer.err().unwrap().state_error,
            Some(StateError::InvalidData)
        );
    });
}

#[test]
fn ari_replacement_is_derived_from_current_material_and_forgery_is_rejected() {
    for scenario in 0..3 {
        let (memory, challenges, clock, mut engine, installer) = setup();
        let material = ari_material();
        let expected = replacement_id(&material).unwrap();
        memory.records.lock().host = Some(StoredHost {
            host: host(),
            order: None,
            certificate: Some(StoredCertificate {
                replaces: None,
                material,
                not_before_unix: NOW - 1000,
                not_after_unix: NOW + 100_000,
                renew_at_unix: NOW,
                ari_check_at_unix: NOW,
                fallback_at_unix: 0,
                ari_window: None,
                ari_failures: 0,
            }),
            retry: RetryState {
                failures: 0,
                not_before_unix: 0,
            },
        });
        engine.ari = scenario != 1;
        let supplied = if scenario == 2 {
            Some(
                CertificateIdentifier::new(Der::from(&b"forged"[..]), Der::from(&b"serial"[..]))
                    .into_owned(),
            )
        } else {
            Some(expected.clone())
        };
        let outcome = block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            supplied,
        ));
        if scenario == 2 {
            assert_eq!(outcome.unwrap_err().kind, FailureKind::Material);
            assert_eq!(engine.new_orders, 0);
        } else {
            outcome.unwrap();
            let records = memory.records.lock();
            let stored = records.host.as_ref().unwrap().certificate.as_ref().unwrap();
            assert_eq!(
                stored.replaces,
                if scenario == 0 {
                    Some(expected.to_string())
                } else {
                    None
                }
            );
            assert_eq!(stored.renew_at_unix, stored.fallback_at_unix);
            assert!(stored.ari_window.is_none());
            assert_eq!(
                engine.replaced,
                if scenario == 0 { Some(expected) } else { None }
            );
        }
    }
}

#[test]
fn actual_order_status_controls_not_found_and_rate_limit_classification() {
    block_on(async {
        for (status, endpoint, body_status, terminal, kind) in [
            (404, ORDER, None, true, FailureKind::Protocol),
            (410, ORDER, Some(400), true, FailureKind::Protocol),
            (
                404,
                "https://ca.example/nonce",
                None,
                false,
                FailureKind::Protocol,
            ),
            (503, ORDER, Some(404), false, FailureKind::Network),
            (429, ORDER, None, false, FailureKind::RateLimited),
        ] {
            let observations = Arc::new(PlMutex::new(Observations::default()));
            observations.lock().armed =
                Some((ORDER.parse().unwrap(), Arc::new(PlMutex::new(None)), false));
            let body = json!({"type":"urn:ietf:params:acme:error:malformed","status":body_status,"detail":"private CA detail"});
            let client = DirectoryClient {
                transport: Responses(Arc::new(PlMutex::new(VecDeque::from([response(
                    status,
                    body.to_string(),
                )])))),
                directory: DIRECTORY.parse().unwrap(),
                observations: observations.clone(),
            };
            let method = if endpoint == ORDER { "POST" } else { "HEAD" };
            client.request(request(method, endpoint)).await.unwrap();
            let problem = serde_json::from_value(body).unwrap();
            let error = classify_observed(instant_acme::Error::Api(problem), &observations, true);
            assert_eq!(error.status, Some(status));
            assert_eq!(error.terminal_order, terminal);
            assert_eq!(error.kind, kind);
        }
    });
}

#[test]
fn nonce_success_and_transport_read_status_cannot_clear_an_order() {
    block_on(async {
        let observations = Arc::new(PlMutex::new(Observations::default()));
        observations.lock().armed =
            Some((ORDER.parse().unwrap(), Arc::new(PlMutex::new(None)), false));
        let client = DirectoryClient {
            transport: Responses(Arc::new(PlMutex::new(VecDeque::from([response(200, "")])))),
            directory: DIRECTORY.parse().unwrap(),
            observations: observations.clone(),
        };
        client
            .request(request("HEAD", "https://ca.example/nonce"))
            .await
            .unwrap();
        let error = client.request(request("POST", ORDER)).await.err().unwrap();
        let error = classify_observed(error, &observations, true);
        assert_eq!(error.kind, FailureKind::Timeout);
        assert_eq!(error.status, None);
        assert!(!error.terminal_order);
        let error = classify_observed(
            instant_acme::Error::Other(Box::new(AcmeError::with_status(
                AcmeErrorKind::Timeout,
                404,
            ))),
            &observations,
            true,
        );
        assert_eq!(error.status, Some(404));
        assert!(!error.terminal_order);
    });
}

#[test]
fn cancellation_during_hint_and_poll_sleeps_preserves_floor_for_a_fresh_engine() {
    for stage in ["restore", "authorization", "ready", "finalize"] {
        let (memory, challenges, clock, mut engine, installer) = setup();
        clock.block_sleep.set(Some(Duration::from_secs(60)));
        engine.next_hint = Some(UNIX_EPOCH + Duration::from_secs(NOW + 600));
        engine.hint_at = Some(stage);
        let future = attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        );
        assert!(future.now_or_never().is_none());
        assert_eq!(
            clock.sleeps.borrow().last().copied(),
            Some(Duration::from_secs(600) - clock.elapsed.get())
        );
        assert!(challenges.lookup(DNS, &"A".repeat(22)).is_none());
        let pending = {
            let records = memory.records.lock();
            let host = records.host.as_ref().unwrap();
            assert_eq!(host.retry.not_before_unix, NOW + 600);
            assert_eq!(host.retry.failures, 1);
            host.order.as_ref().unwrap().clone()
        };
        let mut resumed = Script::new(memory.clone(), challenges.clone());
        resumed.status = engine.status;
        let restarted = FakeClock::default();
        restarted.elapsed.set(Duration::from_secs(61));
        let error = block_on(attempt(
            &memory,
            &challenges,
            &restarted,
            &mut resumed,
            host(),
            &installer,
            None,
        ))
        .unwrap_err();
        assert_eq!(error.kind, FailureKind::Deferred);
        assert_eq!(
            error.retry_not_before,
            Some(UNIX_EPOCH + Duration::from_secs(NOW + 600))
        );
        assert_eq!(
            (resumed.new_orders, resumed.resumes, resumed.finalizes),
            (0, 0, 0)
        );
        restarted.elapsed.set(Duration::from_secs(600));
        block_on(attempt(
            &memory,
            &challenges,
            &restarted,
            &mut resumed,
            host(),
            &installer,
            None,
        ))
        .unwrap();
        let records = memory.records.lock();
        assert_eq!(
            records
                .host
                .as_ref()
                .unwrap()
                .certificate
                .as_ref()
                .unwrap()
                .material
                .private_key_pkcs8,
            pending.key_pkcs8
        );
        if pending.url.is_some() {
            assert_eq!(resumed.new_orders, 0);
        }
        assert_eq!(engine.finalizes + resumed.finalizes, 1);
    }
}

#[test]
fn pinned_new_order_boundary_requires_one_valid_https_location() {
    block_on(async {
        for locations in [
            vec![],
            vec![ORDER, ORDER],
            vec![ORDER, "https://ca.example/order/2"],
            vec!["http://ca.example/order/1"],
            vec!["/order/1"],
            vec!["https://ca.example/order/1#fragment"],
            vec![ORDER],
        ] {
            let (memory, challenges, clock, _, installer) = setup();
            let directory = json!({"newNonce":"https://ca.example/nonce","newAccount":"https://ca.example/account","newOrder":"https://ca.example/new-order"});
            let order = |status: &str| json!({"status":status,"authorizations":[],"identifiers":[{"type":"dns","value":DNS}],"expires":"2027-01-15T10:46:40Z","finalize":"https://ca.example/finalize","certificate":"https://ca.example/certificate"});
            let mut new_order = response(201, order("ready").to_string());
            for location in &locations {
                new_order
                    .headers_mut()
                    .append(http::header::LOCATION, location.parse().unwrap());
            }
            let valid = locations.as_slice() == [ORDER];
            let mut responses = VecDeque::from([
                response(200, directory.to_string()),
                response(200, ""),
                new_order,
            ]);
            if valid {
                responses.push_back(response(200, order("valid").to_string()));
                responses.push_back(response(200, pem(&certificate())));
            }
            let transport = Responses(Arc::new(PlMutex::new(responses)));
            let mut engine = Upstream::new(transport.clone(), DIRECTORY);
            let result = attempt(
                &memory,
                &challenges,
                &clock,
                &mut engine,
                host(),
                &installer,
                None,
            )
            .await;
            if valid {
                result.unwrap();
                assert_eq!(installer.active.lock().len(), 1);
            } else {
                assert_eq!(result.unwrap_err().kind, FailureKind::Protocol);
                assert!(installer.active.lock().is_empty());
                let records = memory.records.lock();
                assert!(
                    records
                        .host
                        .as_ref()
                        .unwrap()
                        .order
                        .as_ref()
                        .unwrap()
                        .url
                        .is_none()
                );
            }
            assert!(transport.0.lock().is_empty());
            assert!(challenges.lookup(DNS, &"A".repeat(22)).is_none());
        }
    });
}

fn install_pending(memory: &Memory, replaces: bool, url: Option<&str>) -> PendingOrder {
    let material = ari_material();
    let identifier = replacement_id(&material).unwrap();
    let (key_pkcs8, csr_der) = new_certificate_request(DNS).unwrap();
    let pending = PendingOrder {
        url: url.map(Into::into),
        replaces: replaces.then(|| identifier.to_string()),
        key_pkcs8,
        csr_der,
        started_unix: NOW,
        expires_unix: Some(EXPIRY),
    };
    memory.records.lock().host = Some(StoredHost {
        host: host(),
        order: Some(pending.clone()),
        certificate: Some(StoredCertificate {
            replaces: None,
            material,
            not_before_unix: NOW - 1000,
            not_after_unix: NOW + 100_000,
            renew_at_unix: NOW,
            ari_check_at_unix: NOW,
            fallback_at_unix: 0,
            ari_window: None,
            ari_failures: 0,
        }),
        retry: RetryState {
            failures: 0,
            not_before_unix: 0,
        },
    });
    pending
}

#[test]
fn restart_keeps_original_replacement_intent_when_ari_capability_changes() {
    for original_ari in [false, true] {
        let (memory, challenges, clock, mut engine, installer) = setup();
        install_pending(&memory, false, None);
        memory.records.lock().host.as_mut().unwrap().order = None;
        engine.ari = original_ari;
        engine.error = Some(("ready", failure(FailureKind::Network)));
        block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        ))
        .unwrap_err();
        let original = memory
            .records
            .lock()
            .host
            .as_ref()
            .unwrap()
            .order
            .as_ref()
            .unwrap()
            .clone();
        assert_eq!(
            original.replaces,
            engine.replaced.as_ref().map(ToString::to_string)
        );
        let mut restarted = Script::new(memory.clone(), challenges.clone());
        restarted.ari = !original_ari;
        restarted.replaced = engine.replaced;
        clock.elapsed.set(Duration::from_secs(60));
        let supplied = if original_ari {
            None
        } else {
            Some(
                replacement_id(
                    &memory
                        .records
                        .lock()
                        .host
                        .as_ref()
                        .unwrap()
                        .certificate
                        .as_ref()
                        .unwrap()
                        .material,
                )
                .unwrap(),
            )
        };
        block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut restarted,
            host(),
            &installer,
            supplied,
        ))
        .unwrap();
        assert_eq!((restarted.new_orders, restarted.resumes), (0, 1));
        assert_eq!(
            memory
                .records
                .lock()
                .host
                .as_ref()
                .unwrap()
                .certificate
                .as_ref()
                .unwrap()
                .material
                .private_key_pkcs8,
            original.key_pkcs8
        );
    }
}

#[test]
fn resumed_refreshed_and_finalized_echo_must_match_original_choice() {
    for phase in ["resume", "refresh", "finalize"] {
        for scenario in 0..3 {
            let (memory, challenges, clock, mut engine, installer) = setup();
            let original = install_pending(&memory, scenario != 0, Some(ORDER));
            let expected = replacement_id(
                &memory
                    .records
                    .lock()
                    .host
                    .as_ref()
                    .unwrap()
                    .certificate
                    .as_ref()
                    .unwrap()
                    .material,
            )
            .unwrap();
            engine.replaced = (scenario != 0).then_some(expected);
            let bad = if scenario == 1 {
                None
            } else {
                Some(
                    CertificateIdentifier::new(Der::from(&b"other"[..]), Der::from(&[2][..]))
                        .into_owned(),
                )
            };
            engine.echo_at = Some((phase, bad));
            let error = block_on(attempt(
                &memory,
                &challenges,
                &clock,
                &mut engine,
                host(),
                &installer,
                None,
            ))
            .unwrap_err();
            assert_eq!(error.kind, FailureKind::Protocol);
            assert!(!error.terminal_order);
            let records = memory.records.lock();
            let pending = records.host.as_ref().unwrap().order.as_ref().unwrap();
            assert_eq!(pending.replaces, original.replaces);
            assert_eq!(pending.url, original.url);
            assert_eq!(pending.key_pkcs8, original.key_pkcs8);
            assert!(installer.active.lock().is_empty());
            assert_eq!(engine.new_orders, 0);
        }
    }
}

#[test]
fn orphan_intent_never_changes_with_directory_capability() {
    for replacing in [false, true] {
        let (memory, challenges, clock, mut engine, installer) = setup();
        let pending = install_pending(&memory, replacing, None);
        engine.ari = !replacing;
        let result = block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        ));
        if replacing {
            let error = result.unwrap_err();
            assert_eq!(error.kind, FailureKind::Protocol);
            assert!(!error.terminal_order);
            assert_eq!(engine.new_orders, 0);
            assert_eq!(
                memory
                    .records
                    .lock()
                    .host
                    .as_ref()
                    .unwrap()
                    .order
                    .as_ref()
                    .unwrap()
                    .replaces,
                pending.replaces
            );
            clock.elapsed.set(Duration::from_secs(60));
            engine.ari = true;
            block_on(attempt(
                &memory,
                &challenges,
                &clock,
                &mut engine,
                host(),
                &installer,
                None,
            ))
            .unwrap();
            assert_eq!(
                engine.replaced.as_ref().map(ToString::to_string),
                pending.replaces
            );
        } else {
            result.unwrap();
            assert!(engine.replaced.is_none());
        }
        assert_eq!(engine.csr, pending.csr_der);
        assert_eq!(
            memory
                .records
                .lock()
                .host
                .as_ref()
                .unwrap()
                .certificate
                .as_ref()
                .unwrap()
                .material
                .private_key_pkcs8,
            pending.key_pkcs8
        );
    }
}

#[test]
fn corrupt_persisted_choice_or_forged_caller_never_reaches_ca() {
    for scenario in 0..3 {
        let (memory, challenges, clock, mut engine, installer) = setup();
        install_pending(&memory, true, Some(ORDER));
        let forged =
            CertificateIdentifier::new(Der::from(&b"other"[..]), Der::from(&[2][..])).into_owned();
        let supplied = match scenario {
            0 => {
                memory
                    .records
                    .lock()
                    .host
                    .as_mut()
                    .unwrap()
                    .order
                    .as_mut()
                    .unwrap()
                    .replaces = Some(forged.to_string());
                None
            }
            1 => {
                memory.records.lock().host.as_mut().unwrap().certificate = None;
                None
            }
            _ => Some(forged),
        };
        let error = block_on(attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            supplied,
        ))
        .unwrap_err();
        if scenario < 2 {
            assert_eq!(error.state_error, Some(StateError::CorruptData));
        } else {
            assert_eq!(error.kind, FailureKind::Material);
        }
        assert!(!engine.gate.events.borrow().contains(&"restore"));
        assert_eq!((engine.new_orders, engine.resumes), (0, 0));
    }
}

#[test]
fn ari_rechecks_expiry_and_generation_after_account_restoration_before_get() {
    struct JumpClock {
        reads: Cell<usize>,
        expire: bool,
    }
    impl Clock for JumpClock {
        fn now(&self) -> SystemTime {
            let count = self.reads.get();
            self.reads.set(count + 1);
            UNIX_EPOCH
                + Duration::from_secs(if self.expire && count > 0 {
                    NOW + 1000
                } else {
                    NOW
                })
        }
        fn monotonic(&self) -> Instant {
            Instant::now()
        }
        fn uniform(&self, _: u64) -> Result<u64, AttemptFailure> {
            Ok(0)
        }
        async fn sleep(&self, _: Duration) {}
    }
    for expire in [false, true] {
        let (memory, challenges, _, mut engine, _) = setup();
        block_on(ensure_account(
            &memory,
            &FakeClock::default(),
            &mut engine,
            DIRECTORY,
        ))
        .unwrap();
        let record = StoredHost {
            host: host(),
            certificate: Some(StoredCertificate {
                replaces: None,
                material: ari_material(),
                not_before_unix: NOW - 100,
                not_after_unix: NOW + 1000,
                renew_at_unix: NOW + 500,
                ari_check_at_unix: NOW,
                fallback_at_unix: NOW + 500,
                ari_window: None,
                ari_failures: 0,
            }),
            order: None,
            retry: RetryState {
                failures: 0,
                not_before_unix: 0,
            },
        };
        memory.records.lock().host = Some(record.clone());
        let mut engine = Script::new(memory.clone(), challenges);
        if !expire {
            let mut replaced = record.clone();
            replaced.certificate.as_mut().unwrap().material = ari_material();
            engine.restore_host = Some(replaced);
        }
        let clock = JumpClock {
            reads: Cell::new(0),
            expire,
        };
        assert!(
            block_on(renewal_request(&memory, &clock, &mut engine, &record))
                .unwrap()
                .is_none()
        );
        assert!(engine.gate.events.borrow().contains(&"restore"));
        assert!(!engine.gate.events.borrow().contains(&"renewal info"));
    }
}

#[test]
fn upstream_ari_uses_renewal_get_and_default_retry_after_without_fetching_explanation() {
    for supported in [false, true] {
        let material = ari_material();
        let identifier = replacement_id(&material).unwrap();
        let signer = CertificateSigner::generate().unwrap();
        let key = signer.pkcs8().unwrap();
        let stored = StoredAccount {
            key_pkcs8: key.clone(),
            credentials_json: Some(credential_bytes(&key, DIRECTORY)),
            retry: RetryState {
                failures: 0,
                not_before_unix: 0,
            },
        };
        let mut directory = json!({"newNonce":"https://ca.example/nonce","newAccount":"https://ca.example/account","newOrder":"https://ca.example/new-order"});
        if supported {
            directory["renewalInfo"] = json!("https://ca.example/renewal");
        }
        let mut ari=response(200,serde_json::to_vec(&json!({"suggestedWindow":{"start":"2027-01-15T08:00:00Z","end":"2027-01-15T08:01:40Z"},"explanationURL":"https://secret.invalid/private-token"})).unwrap());
        ari.headers_mut().remove(http::header::RETRY_AFTER);
        let responses = Responses(Arc::new(PlMutex::new(VecDeque::from([
            response(200, serde_json::to_vec(&directory).unwrap()),
            ari,
        ]))));
        let mut engine = Upstream::new(AriTransport(responses.clone()), DIRECTORY);
        block_on(engine.restore(credentials(&stored, DIRECTORY).unwrap())).unwrap();
        let result = block_on(engine.renewal(&identifier));
        if supported {
            let result = result.unwrap();
            assert_eq!(result.start, Some(NOW));
            assert_eq!(result.end, Some(NOW + 100));
            assert!((43199..=43200).contains(&result.delay));
            assert!(responses.0.lock().is_empty());
        } else {
            assert_eq!(result.err().unwrap().kind, FailureKind::Protocol);
            assert_eq!(responses.0.lock().len(), 1);
        }
    }
}

#[test]
fn fractional_ari_windows_select_only_representable_seconds_inside_original_bounds() {
    let parse = |text| {
        time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).unwrap()
    };
    for (start, end, expected) in [
        (
            "2027-01-15T08:00:00.001Z",
            "2027-01-15T08:00:01.001Z",
            Some((NOW + 1, NOW + 2)),
        ),
        (
            "2027-01-15T08:00:00Z",
            "2027-01-15T08:00:00.001Z",
            Some((NOW, NOW + 1)),
        ),
        ("2027-01-15T08:00:00.001Z", "2027-01-15T08:00:00.999Z", None),
        ("2027-01-15T08:00:00.001Z", "2027-01-15T08:00:01Z", None),
    ] {
        let start = parse(start);
        let end = parse(end);
        let before = window_second(start).unwrap();
        let after = window_second(end).unwrap();
        if let Some((first, last)) = expected {
            assert_eq!((before, after), (first, last));
            assert!(time::OffsetDateTime::from_unix_timestamp(before as i64).unwrap() >= start);
            assert!(time::OffsetDateTime::from_unix_timestamp((after - 1) as i64).unwrap() < end);
        } else {
            assert!(before >= after);
        }
    }
    assert_eq!(window_second(parse("1969-12-31T23:59:59.999Z")), None);
}

fn ari_directory_response() -> http::Response<Full<Bytes>> {
    response(200,json!({"newNonce":"https://ca.example/nonce","newAccount":"https://ca.example/account","newOrder":"https://ca.example/new-order","renewalInfo":"https://ca.example/renewal"}).to_string())
}

fn restored_credentials() -> AccountCredentials {
    let key = CertificateSigner::generate().unwrap().pkcs8().unwrap();
    serde_json::from_slice(&credential_bytes(&key, DIRECTORY)).unwrap()
}

#[test]
fn pinned_ari_rejects_unsafe_retry_after_without_panicking() {
    block_on(async {
        for header in [
            "18446744073709551615",
            "+18446744073709551615",
            " 18446744073709551615 ",
        ] {
            let mut reply=response(200,json!({"suggestedWindow":{"start":"2027-01-15T08:00:00Z","end":"2027-01-15T08:01:40Z"}}).to_string());
            reply
                .headers_mut()
                .insert(http::header::RETRY_AFTER, header.parse().unwrap());
            let replies = Responses(Arc::new(PlMutex::new(VecDeque::from([
                ari_directory_response(),
                reply,
            ]))));
            let mut engine = Upstream::new(AriTransport(replies.clone()), DIRECTORY);
            engine.restore(restored_credentials()).await.unwrap();
            let error = engine
                .renewal(&replacement_id(&ari_material()).unwrap())
                .await
                .err()
                .unwrap();
            assert_eq!(error.kind, FailureKind::Protocol);
            assert_eq!(error.status, Some(200));
            assert!(!error.terminal_order);
            assert!(replies.0.lock().is_empty());
            assert!(!error.to_string().contains(header));
        }
    });
}

#[test]
fn pinned_order_refresh_rejects_unsafe_retry_after_and_preserves_resumable_order() {
    block_on(async {
        let (memory, challenges, clock, _, installer) = setup();
        let (key_pkcs8, csr_der) = new_certificate_request(DNS).unwrap();
        let pending = PendingOrder {
            url: Some(ORDER.into()),
            replaces: None,
            key_pkcs8,
            csr_der,
            started_unix: NOW,
            expires_unix: Some(EXPIRY),
        };
        let record = StoredHost {
            host: host(),
            certificate: None,
            order: Some(pending.clone()),
            retry: RetryState {
                failures: 0,
                not_before_unix: 0,
            },
        };
        memory.records.lock().host = Some(record);
        let order=json!({"status":"processing","authorizations":[],"identifiers":[{"type":"dns","value":DNS}],"expires":"2027-01-15T10:46:40Z","finalize":"https://ca.example/finalize"}).to_string();
        let mut overflow = response(200, order.clone());
        overflow.headers_mut().insert(
            http::header::RETRY_AFTER,
            "18446744073709551615".parse().unwrap(),
        );
        let replies = Responses(Arc::new(PlMutex::new(VecDeque::from([
            ari_directory_response(),
            response(200, ""),
            response(200, order),
            overflow,
        ]))));
        let mut engine = Upstream::new(replies.clone(), DIRECTORY);
        let error = attempt(
            &memory,
            &challenges,
            &clock,
            &mut engine,
            host(),
            &installer,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind, FailureKind::Protocol);
        assert_eq!(error.status, Some(200));
        assert!(!error.terminal_order);
        assert!(installer.active.lock().is_empty());
        let records = memory.records.lock();
        let stored = records.host.as_ref().unwrap();
        assert_eq!(stored.order.as_ref().unwrap().url, pending.url);
        assert_eq!(stored.order.as_ref().unwrap().key_pkcs8, pending.key_pkcs8);
        assert_eq!(stored.retry.failures, 1);
        assert!(stored.retry.not_before_unix >= NOW + 60);
        assert!(replies.0.lock().is_empty());
    });
}

#[test]
fn response_boundary_preserves_accepted_retry_headers_status_and_bytes() {
    block_on(async {
        for header in [
            "0",
            "+120",
            "invalid",
            "-1",
            "18446744073709551616",
            "Sun, 06 Nov 1994 08:49:37 GMT",
        ] {
            let mut reply = response(202, Bytes::from_static(b"unchanged response"));
            reply
                .headers_mut()
                .insert(http::header::RETRY_AFTER, header.parse().unwrap());
            let headers = reply.headers().clone();
            let client = DirectoryClient {
                transport: Responses(Arc::new(PlMutex::new(VecDeque::from([reply])))),
                directory: DIRECTORY.parse().unwrap(),
                observations: Arc::new(PlMutex::new(Observations::default())),
            };
            let mut reply = client
                .request(request("GET", "https://ca.example/renewal/id"))
                .await
                .unwrap();
            assert_eq!(reply.parts.status, 202);
            assert_eq!(reply.parts.headers, headers);
            assert_eq!(
                reply.body.into_bytes().await.unwrap(),
                b"unchanged response".as_slice()
            );
        }
    });
}

#[test]
fn pinned_ari_classifies_actual_error_status_for_problem_and_non_json_bodies() {
    block_on(async {
        for (status, kind) in [(503, FailureKind::Network), (429, FailureKind::RateLimited)] {
            for body in [
                "",
                "<html>private server failure</html>",
                r#"{"type":"urn:ietf:params:acme:error:malformed","detail":"private server failure"}"#,
            ] {
                let replies = Responses(Arc::new(PlMutex::new(VecDeque::from([
                    ari_directory_response(),
                    response(status, body),
                ]))));
                let mut engine = Upstream::new(AriTransport(replies.clone()), DIRECTORY);
                engine.restore(restored_credentials()).await.unwrap();
                let error = engine
                    .renewal(&replacement_id(&ari_material()).unwrap())
                    .await
                    .err()
                    .unwrap();
                assert_eq!(error.status, Some(status));
                assert_eq!(error.kind, kind);
                assert!(!error.terminal_order);
                assert!(!error.to_string().contains("private"));
                assert!(replies.0.lock().is_empty());
            }
        }
    });
}

#[test]
fn pinned_ari_discards_directory_retry_hint_before_retaining_its_own_hint() {
    #[derive(Clone)]
    struct Hints {
        responses: Responses,
        hint: Arc<PlMutex<Option<SystemTime>>>,
    }
    impl AttemptTransport for Hints {
        fn reset_retry_hint(&self) {
            *self.hint.lock() = None;
        }
        fn retry_not_before(&self) -> Option<SystemTime> {
            *self.hint.lock()
        }
    }
    impl HttpClient for Hints {
        fn request(
            &self,
            request: http::Request<instant_acme::BodyWrapper<Bytes>>,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>>
                    + Send,
            >,
        > {
            let work = self.responses.request(request);
            let hint = self.hint.clone();
            Box::pin(async move {
                let response = work.await?;
                let seconds = response
                    .parts
                    .headers
                    .get(http::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
                let deadline = UNIX_EPOCH + Duration::from_secs(NOW + seconds);
                let mut current = hint.lock();
                *current = Some(current.map_or(deadline, |previous| previous.max(deadline)));
                Ok(response)
            })
        }
    }
    block_on(async {
        let mut directory = ari_directory_response();
        directory
            .headers_mut()
            .insert(http::header::RETRY_AFTER, "9000".parse().unwrap());
        let mut reply = response(503, "private remote failure");
        reply
            .headers_mut()
            .insert(http::header::RETRY_AFTER, "120".parse().unwrap());
        let transport = Hints {
            responses: Responses(Arc::new(PlMutex::new(VecDeque::from([directory, reply])))),
            hint: Arc::new(PlMutex::new(None)),
        };
        let mut engine = Upstream::new(AriTransport(transport.clone()), DIRECTORY);
        engine.restore(restored_credentials()).await.unwrap();
        assert_eq!(
            transport.retry_not_before(),
            Some(UNIX_EPOCH + Duration::from_secs(NOW + 9000))
        );
        let error = engine
            .renewal(&replacement_id(&ari_material()).unwrap())
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind, FailureKind::Network);
        assert_eq!(error.status, Some(503));
        assert_eq!(
            error.retry_not_before,
            Some(UNIX_EPOCH + Duration::from_secs(NOW + 120))
        );
    });
}
