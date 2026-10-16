// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use futures_util::future::{Either, select};
use http_body_util::Full;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier, ChallengeStatus,
    ChallengeType, HttpClient, Identifier, Key, NewOrder, Order, OrderStatus,
};
use parking_lot::Mutex as PlMutex;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Deserialize;
use x509_cert::Certificate;
use x509_cert::der::Decode;
use zeroize::Zeroizing;

use crate::crypto::CertificateSigner;
use crate::types::{validate_url, *};
use crate::{
    AcmeHttpClient, ChallengeLease, Challenges, StateStore, crypto_provider,
    new_certificate_request,
};

const ATTEMPT_BUDGET: Duration = Duration::from_secs(900);

pub struct Issuer {
    store: StateStore,
    challenges: Challenges,
    transport: AcmeHttpClient,
    directory_url: String,
}

impl Issuer {
    pub fn new(
        store: StateStore,
        challenges: Challenges,
        transport: AcmeHttpClient,
        directory_url: String,
    ) -> Result<Self, AttemptFailure> {
        validate_url(&directory_url)?;
        if store.directory_url() != directory_url {
            return Err(StateError::InvalidData.into());
        }
        Ok(Self {
            store,
            challenges,
            transport,
            directory_url,
        })
    }

    pub(crate) async fn validate_cached_account(&self) -> Result<(), AttemptFailure> {
        if let Some(account) = self.store.account().await? {
            drop(
                Key::from_pkcs8_der(
                    PrivatePkcs8KeyDer::from(account.key_pkcs8.as_slice()),
                    crypto_provider(),
                )
                .map_err(|_| StateError::CorruptData)?,
            );
            if account.credentials_json.is_some() {
                drop(
                    credentials(&account, &self.directory_url)
                        .map_err(|_| StateError::CorruptData)?,
                );
            }
        }
        Ok(())
    }

    pub(crate) async fn renewal_info(
        &self,
        host: &StoredHost,
    ) -> Result<Option<RenewalWindow>, AttemptFailure> {
        let transport = self.transport.for_attempt();
        let mut engine = Upstream::new(AriTransport(transport), &self.directory_url);
        renewal_request(&self.store, &SystemClock, &mut engine, host).await
    }

    /// The manager must serialize account initialization and recovery.
    pub async fn ensure_account(&self) -> Result<(), AttemptFailure> {
        let mut engine = Upstream::new(self.transport.for_attempt(), &self.directory_url);
        let outcome = {
            let work = pin!(ensure_account(
                &self.store,
                &SystemClock,
                &mut engine,
                &self.directory_url
            ));
            let timeout = pin!(compio::time::sleep(ATTEMPT_BUDGET));
            match select(timeout, work).await {
                Either::Left(_) => None,
                Either::Right((result, _)) => Some(result),
            }
        };
        outcome.unwrap_or_else(|| Err(engine.failure(FailureKind::Timeout)))
    }

    /// The manager must give one attempt exclusive ownership of each host record.
    pub async fn issue<I: Installer>(
        &self,
        host: ManagedHost,
        installer: &I,
        replaces: Option<CertificateIdentifier<'static>>,
    ) -> Result<AttemptSuccess, AttemptFailure> {
        let mut engine = Upstream::new(self.transport.for_attempt(), &self.directory_url);
        let outcome = {
            let work = pin!(attempt(
                &self.store,
                &self.challenges,
                &SystemClock,
                &mut engine,
                host,
                installer,
                replaces
            ));
            let timeout = pin!(compio::time::sleep(ATTEMPT_BUDGET));
            match select(timeout, work).await {
                Either::Left(_) => None,
                Either::Right((result, _)) => Some(result),
            }
        };
        outcome.unwrap_or_else(|| Err(engine.failure(FailureKind::Timeout)))
    }
}

trait Storage {
    async fn account(&self) -> Result<Option<StoredAccount>, StateError>;
    async fn save_account(&self, account: &StoredAccount) -> Result<(), StateError>;
    async fn host(&self, dns: &str) -> Result<Option<StoredHost>, StateError>;
    async fn save_host(&self, host: &StoredHost) -> Result<(), StateError>;
}

impl Storage for StateStore {
    async fn account(&self) -> Result<Option<StoredAccount>, StateError> {
        self.account().await
    }
    async fn save_account(&self, account: &StoredAccount) -> Result<(), StateError> {
        self.save_account(account.clone()).await
    }
    async fn host(&self, dns: &str) -> Result<Option<StoredHost>, StateError> {
        self.host(dns.into()).await
    }
    async fn save_host(&self, host: &StoredHost) -> Result<(), StateError> {
        self.save_host(host.clone()).await
    }
}

trait Clock {
    fn now(&self) -> SystemTime;
    fn monotonic(&self) -> Instant;
    fn uniform(&self, maximum: u64) -> Result<u64, AttemptFailure>;
    async fn sleep(&self, duration: Duration);
}

struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
    fn monotonic(&self) -> Instant {
        Instant::now()
    }
    fn uniform(&self, maximum: u64) -> Result<u64, AttemptFailure> {
        let range = maximum.checked_add(1).ok_or(StateError::InvalidData)?;
        let threshold = range.wrapping_neg() % range;
        loop {
            let mut bytes = [0; 8];
            getrandom::fill(&mut bytes).map_err(|_| failure(FailureKind::Material))?;
            let value = u64::from_ne_bytes(bytes);
            if value >= threshold {
                return Ok(value % range);
            }
        }
    }
    async fn sleep(&self, duration: Duration) {
        compio::time::sleep(duration).await
    }
}

struct Snapshot {
    status: OrderStatus,
    url: String,
    expires: Option<u64>,
    replaces: Option<CertificateIdentifier<'static>>,
    dns_name: String,
}

struct Authorization {
    dns_name: String,
    wildcard: bool,
    status: AuthorizationStatus,
    challenge: Option<HttpChallenge>,
}

struct HttpChallenge {
    token: String,
    authorization: String,
    status: ChallengeStatus,
}

trait Engine {
    fn directory(&self) -> &str;
    fn reset_hint(&self);
    fn hint(&self) -> Option<SystemTime>;
    fn supports_ari(&self) -> bool;
    async fn renewal(
        &mut self,
        identifier: &CertificateIdentifier<'_>,
    ) -> Result<RenewalWindow, AttemptFailure>;
    async fn register(&mut self, key: &[u8]) -> Result<Zeroizing<Vec<u8>>, AttemptFailure>;
    async fn restore(&mut self, credentials: AccountCredentials) -> Result<(), AttemptFailure>;
    async fn new_order(
        &mut self,
        dns: &str,
        replaces: Option<CertificateIdentifier<'static>>,
    ) -> Result<Snapshot, AttemptFailure>;
    async fn resume(&mut self, url: &str) -> Result<Snapshot, AttemptFailure>;
    async fn authorization(&mut self, refresh: bool) -> Result<Authorization, AttemptFailure>;
    async fn ready(&mut self) -> Result<(), AttemptFailure>;
    async fn refresh(&mut self) -> Result<Snapshot, AttemptFailure>;
    async fn finalize(&mut self, csr: &[u8]) -> Result<Snapshot, AttemptFailure>;
    async fn certificate(&mut self) -> Result<String, AttemptFailure>;
    fn failure(&self, kind: FailureKind) -> AttemptFailure {
        AttemptFailure {
            retry_not_before: self.hint(),
            ..failure(kind)
        }
    }
}

fn failure(kind: FailureKind) -> AttemptFailure {
    AttemptFailure {
        kind,
        status: None,
        state_error: None,
        retry_not_before: None,
        terminal_order: false,
    }
}

fn unix(time: SystemTime) -> Result<u64, AttemptFailure> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StateError::InvalidData)?
        .as_secs();
    if seconds > i64::MAX as u64 {
        return Err(StateError::InvalidData.into());
    }
    Ok(seconds)
}

fn wall(seconds: u64) -> Result<SystemTime, AttemptFailure> {
    if seconds > i64::MAX as u64 {
        return Err(StateError::InvalidData.into());
    }
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or(StateError::InvalidData.into())
}

fn reserve(retry: &mut RetryState, clock: &impl Clock) -> Result<u64, AttemptFailure> {
    if wall(retry.not_before_unix)? > clock.now() {
        return Err(AttemptFailure {
            retry_not_before: Some(wall(retry.not_before_unix)?),
            ..failure(FailureKind::Deferred)
        });
    }
    retry.failures = retry.failures.saturating_add(1);
    let base = match retry.failures {
        1 => 60,
        2 => 600,
        3 => 6000,
        _ => 86400,
    };
    let delay = base + clock.uniform(base / 10)?;
    refresh_retry(retry, clock, delay, None)?;
    Ok(delay)
}

fn refresh_retry(
    retry: &mut RetryState,
    clock: &impl Clock,
    delay: u64,
    hint: Option<SystemTime>,
) -> Result<(), AttemptFailure> {
    let next = unix(clock.now())?
        .checked_add(delay)
        .ok_or(StateError::InvalidData)?;
    retry.not_before_unix = retry.not_before_unix.max(next);
    if let Some(hint) = hint {
        let duration = hint
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StateError::InvalidData)?;
        let ceiling = duration
            .as_secs()
            .checked_add(u64::from(duration.subsec_nanos() != 0))
            .ok_or(StateError::InvalidData)?;
        retry.not_before_unix = retry.not_before_unix.max(ceiling);
    }
    wall(retry.not_before_unix)?;
    Ok(())
}

fn credentials(
    account: &StoredAccount,
    directory: &str,
) -> Result<AccountCredentials, AttemptFailure> {
    #[derive(Deserialize)]
    struct Namespace {
        directory: Option<String>,
    }
    let bytes = account
        .credentials_json
        .as_ref()
        .ok_or_else(|| failure(FailureKind::Account))?;
    let namespace: Namespace =
        serde_json::from_slice(bytes).map_err(|_| StateError::CorruptData)?;
    let credentials: AccountCredentials =
        serde_json::from_slice(bytes).map_err(|_| StateError::CorruptData)?;
    if namespace.directory.as_deref() != Some(directory)
        || credentials.private_key().secret_pkcs8_der() != account.key_pkcs8.as_slice()
    {
        return Err(StateError::CorruptData.into());
    }
    Key::from_pkcs8_der(
        PrivatePkcs8KeyDer::from(account.key_pkcs8.as_slice()),
        crypto_provider(),
    )
    .map_err(|_| AttemptFailure::from(StateError::CorruptData))?;
    Ok(credentials)
}

async fn renewal_request(
    store: &impl Storage,
    clock: &impl Clock,
    engine: &mut impl Engine,
    host: &StoredHost,
) -> Result<Option<RenewalWindow>, AttemptFailure> {
    let certificate = host.certificate.as_ref().ok_or(StateError::CorruptData)?;
    if unix(clock.now())? >= certificate.not_after_unix {
        return Ok(None);
    }
    let account = store.account().await?.ok_or(StateError::CorruptData)?;
    engine
        .restore(credentials(&account, engine.directory())?)
        .await?;
    let current = store.host(&host.host.dns_name).await?;
    let now = unix(clock.now())?;
    if !current
        .as_ref()
        .and_then(|host| host.certificate.as_ref())
        .is_some_and(|current| {
            current.material.chain == certificate.material.chain && now < current.not_after_unix
        })
    {
        return Ok(None);
    }
    let identifier = replacement_id(&certificate.material)?;
    engine.renewal(&identifier).await.map(Some)
}

async fn ensure_account(
    store: &impl Storage,
    clock: &impl Clock,
    engine: &mut impl Engine,
    directory: &str,
) -> Result<(), AttemptFailure> {
    let mut account = match store.account().await? {
        Some(account) => account,
        None => StoredAccount {
            key_pkcs8: CertificateSigner::generate()
                .and_then(|key| key.pkcs8())
                .map_err(|_| failure(FailureKind::Material))?,
            credentials_json: None,
            retry: RetryState {
                failures: 0,
                not_before_unix: 0,
            },
        },
    };
    if account.credentials_json.is_some() {
        drop(credentials(&account, directory)?);
        return Ok(());
    }
    Key::from_pkcs8_der(
        PrivatePkcs8KeyDer::from(account.key_pkcs8.as_slice()),
        crypto_provider(),
    )
    .map_err(|_| AttemptFailure::from(StateError::CorruptData))?;
    let delay = reserve(&mut account.retry, clock)?;
    store.save_account(&account).await?;
    engine.reset_hint();
    match engine.register(&account.key_pkcs8).await {
        Ok(bytes) => {
            account.credentials_json = Some(bytes);
            drop(credentials(&account, directory)?);
            account.retry = RetryState {
                failures: 0,
                not_before_unix: 0,
            };
            store.save_account(&account).await?;
            Ok(())
        }
        Err(mut error) => {
            refresh_retry(
                &mut account.retry,
                clock,
                delay,
                engine.hint().or(error.retry_not_before),
            )?;
            store.save_account(&account).await?;
            error.retry_not_before = Some(wall(account.retry.not_before_unix)?);
            Err(error)
        }
    }
}

struct Driver<'a, S, C, E> {
    store: &'a S,
    challenges: &'a Challenges,
    clock: &'a C,
    engine: &'a mut E,
    host: StoredHost,
    delay: u64,
    deadline: Instant,
}

async fn attempt<I: Installer>(
    store: &impl Storage,
    challenges: &Challenges,
    clock: &impl Clock,
    engine: &mut impl Engine,
    host: ManagedHost,
    installer: &I,
    replaces: Option<CertificateIdentifier<'static>>,
) -> Result<AttemptSuccess, AttemptFailure> {
    let deadline = clock
        .monotonic()
        .checked_add(ATTEMPT_BUDGET)
        .ok_or(StateError::InvalidData)?;
    let stored = store.host(&host.dns_name).await?;
    let existing = stored.is_some();
    let mut record = stored.unwrap_or(StoredHost {
        host,
        certificate: None,
        order: None,
        retry: RetryState {
            failures: 0,
            not_before_unix: 0,
        },
    });
    record.validate().map_err(|error| {
        if existing {
            StateError::CorruptData
        } else {
            error
        }
    })?;
    let delay = reserve(&mut record.retry, clock)?;
    store.save_host(&record).await?;
    let mut driver = Driver {
        store,
        challenges,
        clock,
        engine,
        host: record,
        delay,
        deadline,
    };
    match driver.run(installer, replaces).await {
        Ok(success) => Ok(success),
        Err(mut error) => {
            if error.kind == FailureKind::State {
                return Err(error);
            }
            let terminal = error.terminal_order;
            error.terminal_order = false;
            refresh_retry(
                &mut driver.host.retry,
                clock,
                delay,
                driver.engine.hint().or(error.retry_not_before),
            )?;
            if terminal {
                driver.host.order = None;
            }
            store.save_host(&driver.host).await?;
            error.retry_not_before = Some(wall(driver.host.retry.not_before_unix)?);
            error.terminal_order = terminal;
            Err(error)
        }
    }
}

impl<S: Storage, C: Clock, E: Engine> Driver<'_, S, C, E> {
    async fn persist_retry(&mut self) -> Result<(), AttemptFailure> {
        refresh_retry(
            &mut self.host.retry,
            self.clock,
            self.delay,
            self.engine.hint(),
        )?;
        self.store.save_host(&self.host).await?;
        Ok(())
    }

    async fn wait(&mut self, delay: Duration) -> Result<bool, AttemptFailure> {
        self.persist_retry().await?;
        let hint = self.engine.hint();
        let delay = delay.max(
            hint.and_then(|hint| hint.duration_since(self.clock.now()).ok())
                .unwrap_or_default(),
        );
        let remaining = self
            .deadline
            .saturating_duration_since(self.clock.monotonic());
        if delay >= remaining {
            return Err(self.engine.failure(FailureKind::Timeout));
        }
        if !delay.is_zero() {
            self.clock.sleep(delay).await;
        }
        Ok(!delay.is_zero())
    }

    async fn before(&mut self) -> Result<(), AttemptFailure> {
        if self.wait(Duration::ZERO).await? {
            self.persist_retry().await?;
        }
        self.engine.reset_hint();
        Ok(())
    }

    async fn run<I: Installer>(
        &mut self,
        installer: &I,
        supplied: Option<CertificateIdentifier<'static>>,
    ) -> Result<AttemptSuccess, AttemptFailure> {
        let account = self
            .store
            .account()
            .await?
            .ok_or_else(|| failure(FailureKind::Account))?;
        let credentials = credentials(&account, self.engine.directory())?;
        if wall(account.retry.not_before_unix)? > self.clock.now() {
            return Err(AttemptFailure {
                retry_not_before: Some(wall(account.retry.not_before_unix)?),
                ..failure(FailureKind::Account)
            });
        }
        if let Some(supplied) = &supplied {
            let current = self
                .host
                .certificate
                .as_ref()
                .map(|certificate| replacement_id(&certificate.material))
                .transpose()?;
            if current.as_ref() != Some(supplied) {
                return Err(failure(FailureKind::Material));
            }
        }
        let persisted = self
            .host
            .order
            .as_ref()
            .and_then(|order| order.replaces.as_ref());
        let original = if let Some(persisted) = persisted {
            let certificate = self
                .host
                .certificate
                .as_ref()
                .ok_or(StateError::CorruptData)?;
            let identifier =
                replacement_id(&certificate.material).map_err(|_| StateError::CorruptData)?;
            if identifier.to_string() != *persisted {
                return Err(StateError::CorruptData.into());
            }
            Some(identifier)
        } else {
            None
        };
        self.before().await?;
        self.engine.restore(credentials).await?;
        let replacement = if self.host.order.is_some() {
            original
        } else if self.engine.supports_ari() {
            self.host
                .certificate
                .as_ref()
                .map(|certificate| replacement_id(&certificate.material))
                .transpose()?
        } else {
            None
        };
        if self.host.order.is_none() {
            let (key_pkcs8, csr_der) = new_certificate_request(&self.host.host.dns_name)
                .map_err(|_| failure(FailureKind::Material))?;
            self.host.order = Some(PendingOrder {
                url: None,
                replaces: replacement.as_ref().map(ToString::to_string),
                key_pkcs8,
                csr_der,
                started_unix: unix(self.clock.now())?,
                expires_unix: None,
            });
        }
        let pending = self.host.order.as_ref().ok_or(StateError::CorruptData)?;
        let now = unix(self.clock.now())?;
        if pending.expires_unix.is_some_and(|expiry| expiry <= now) {
            return Err(AttemptFailure {
                terminal_order: true,
                ..failure(FailureKind::Protocol)
            });
        }
        let url = pending.url.clone();
        if url.is_none() && replacement.is_some() && !self.engine.supports_ari() {
            return Err(failure(FailureKind::Protocol));
        }
        self.before().await?;
        let mut snapshot = if let Some(url) = url {
            self.engine.resume(&url).await?
        } else {
            self.engine
                .new_order(&self.host.host.dns_name, replacement.clone())
                .await?
        };
        self.observe(&snapshot, replacement.as_ref()).await?;
        let mut lease: Option<ChallengeLease> = None;
        let mut acknowledged = false;
        let mut finalized = false;
        let mut interval = Duration::from_secs(2);
        loop {
            let now = unix(self.clock.now())?;
            if self
                .host
                .order
                .as_ref()
                .and_then(|order| order.expires_unix)
                .is_some_and(|expiry| expiry <= now)
            {
                return Err(AttemptFailure {
                    terminal_order: true,
                    ..failure(FailureKind::Protocol)
                });
            }
            match snapshot.status {
                OrderStatus::Invalid => {
                    return Err(AttemptFailure {
                        terminal_order: true,
                        ..failure(FailureKind::Protocol)
                    });
                }
                OrderStatus::Pending => {
                    self.before().await?;
                    let authorization = self.engine.authorization(acknowledged).await?;
                    if authorization.wildcard || authorization.dns_name != self.host.host.dns_name {
                        return Err(AttemptFailure {
                            terminal_order: true,
                            ..failure(FailureKind::Authorization)
                        });
                    }
                    match authorization.status {
                        AuthorizationStatus::Valid => {}
                        AuthorizationStatus::Pending => {
                            let challenge =
                                authorization.challenge.ok_or_else(|| AttemptFailure {
                                    terminal_order: true,
                                    ..failure(FailureKind::Authorization)
                                })?;
                            if challenge.status == ChallengeStatus::Invalid {
                                return Err(AttemptFailure {
                                    terminal_order: true,
                                    ..failure(FailureKind::Authorization)
                                });
                            }
                            if lease.is_none() {
                                lease = Some(
                                    self.challenges
                                        .publish(
                                            &self.host.host.dns_name,
                                            &challenge.token,
                                            &challenge.authorization,
                                        )
                                        .map_err(|_| failure(FailureKind::Authorization))?,
                                );
                            }
                            if !acknowledged && challenge.status == ChallengeStatus::Pending {
                                self.before().await?;
                                self.engine.ready().await?;
                            }
                            acknowledged = true;
                        }
                        _ => {
                            return Err(AttemptFailure {
                                terminal_order: true,
                                ..failure(FailureKind::Authorization)
                            });
                        }
                    }
                }
                OrderStatus::Ready if !finalized => {
                    self.before().await?;
                    let pending = self.host.order.as_ref().ok_or(StateError::CorruptData)?;
                    snapshot = self.engine.finalize(&pending.csr_der).await?;
                    self.observe(&snapshot, replacement.as_ref()).await?;
                    finalized = true;
                    continue;
                }
                OrderStatus::Valid => {
                    self.before().await?;
                    let pem = self.engine.certificate().await?;
                    let chain = parse_chain(&pem)?;
                    let pending = self.host.order.as_mut().ok_or(StateError::CorruptData)?;
                    let replaces = pending.replaces.clone();
                    let material = CertificateMaterial {
                        chain,
                        private_key_pkcs8: pending.key_pkcs8.clone(),
                    };
                    let prepared = installer
                        .prepare(&self.host.host, &material)
                        .map_err(|_| failure(FailureKind::Material))?;
                    let validity = prepared.validity;
                    let now = unix(self.clock.now())?;
                    if validity.not_before_unix > now || now >= validity.not_after_unix {
                        return Err(failure(FailureKind::Material));
                    }
                    let renew_at_unix = fallback(validity, self.clock)?;
                    self.host.certificate = Some(StoredCertificate {
                        replaces,
                        material,
                        not_before_unix: validity.not_before_unix,
                        not_after_unix: validity.not_after_unix,
                        renew_at_unix,
                        ari_check_at_unix: now,
                        fallback_at_unix: renew_at_unix,
                        ari_window: None,
                        ari_failures: 0,
                    });
                    self.host.order = None;
                    self.host.retry = RetryState {
                        failures: 0,
                        not_before_unix: 0,
                    };
                    self.store.save_host(&self.host).await?;
                    installer.activate(prepared.candidate);
                    return Ok(AttemptSuccess { validity });
                }
                _ => {}
            }
            self.wait(interval).await?;
            interval = (interval * 2).min(Duration::from_secs(30));
            self.before().await?;
            snapshot = self.engine.refresh().await?;
            self.observe(&snapshot, replacement.as_ref()).await?;
        }
    }

    async fn observe(
        &mut self,
        snapshot: &Snapshot,
        replacement: Option<&CertificateIdentifier<'static>>,
    ) -> Result<(), AttemptFailure> {
        validate_url(&snapshot.url).map_err(|_| failure(FailureKind::Protocol))?;
        if snapshot.dns_name != self.host.host.dns_name
            || snapshot.replaces.as_ref() != replacement
            || matches!(snapshot.status, OrderStatus::Pending | OrderStatus::Valid)
                && snapshot.expires.is_none()
        {
            return Err(failure(FailureKind::Protocol));
        }
        if let Some(expiry) = snapshot.expires {
            wall(expiry).map_err(|_| failure(FailureKind::Protocol))?;
        }
        let pending = self.host.order.as_mut().ok_or(StateError::CorruptData)?;
        if pending.url.as_ref().is_some_and(|url| url != &snapshot.url) {
            return Err(failure(FailureKind::Protocol));
        }
        pending.url = Some(snapshot.url.clone());
        pending.expires_unix = snapshot.expires.or(pending.expires_unix);
        self.store.save_host(&self.host).await?;
        Ok(())
    }
}

fn fallback(validity: CertificateValidity, clock: &impl Clock) -> Result<u64, AttemptFailure> {
    crate::schedule::fallback(validity, |maximum| {
        clock.uniform(maximum).map_err(|_| StateError::Other)
    })
    .map_err(Into::into)
}

fn parse_chain(pem: &str) -> Result<Vec<Vec<u8>>, AttemptFailure> {
    let invalid = || failure(FailureKind::Material);
    if pem.len() > 2 * 1024 * 1024 {
        return Err(invalid());
    }
    let mut text = pem.trim();
    let mut chain = Vec::new();
    let mut length = 0usize;
    while !text.is_empty() {
        if chain.len() == 16 {
            return Err(invalid());
        }
        let rest = text
            .strip_prefix("-----BEGIN CERTIFICATE-----")
            .ok_or_else(invalid)?;
        let (encoded, rest) = rest
            .split_once("-----END CERTIFICATE-----")
            .ok_or_else(invalid)?;
        let encoded: String = encoded
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .collect();
        let der = STANDARD.decode(encoded).map_err(|_| invalid())?;
        length = length.checked_add(der.len()).ok_or_else(invalid)?;
        if length > 1024 * 1024 {
            return Err(invalid());
        }
        Certificate::from_der(&der).map_err(|_| invalid())?;
        chain.push(der);
        text = rest.trim();
    }
    if chain.is_empty() {
        return Err(invalid());
    }
    Ok(chain)
}

fn replacement_id(
    material: &CertificateMaterial,
) -> Result<CertificateIdentifier<'static>, AttemptFailure> {
    crate::crypto::certificate_identifier(material).map_err(|_| failure(FailureKind::Material))
}

#[derive(Default)]
struct Observations {
    new_order: Option<http::Uri>,
    ari: bool,
    armed: Option<(http::Uri, MetadataSlot, bool)>,
    request: Option<Arc<()>>,
    response_status: Option<(u16, bool)>,
}

type MetadataSlot = Arc<PlMutex<Option<Result<OrderMetadata, AttemptFailure>>>>;

struct OrderMetadata {
    location: Option<String>,
    dns_name: String,
    expires_unix: Option<u64>,
}

#[derive(Default)]
enum Expiry {
    #[default]
    Missing,
    Present(u64),
}

impl<'de> Deserialize<'de> for Expiry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let time =
            time::OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339)
                .map_err(serde::de::Error::custom)?;
        let seconds = u64::try_from(time.unix_timestamp()).map_err(serde::de::Error::custom)?;
        wall(seconds).map_err(serde::de::Error::custom)?;
        Ok(Self::Present(seconds))
    }
}

fn order_metadata(bytes: &[u8]) -> Result<OrderMetadata, AttemptFailure> {
    #[derive(Deserialize)]
    struct Projection {
        identifiers: [Identifier; 1],
        #[serde(default)]
        expires: Expiry,
    }
    let projection: Projection =
        serde_json::from_slice(bytes).map_err(|_| failure(FailureKind::Protocol))?;
    let [Identifier::Dns(dns_name)] = projection.identifiers else {
        return Err(failure(FailureKind::Protocol));
    };
    crate::types::validate_dns(&dns_name).map_err(|_| failure(FailureKind::Protocol))?;
    Ok(OrderMetadata {
        location: None,
        dns_name,
        expires_unix: match projection.expires {
            Expiry::Missing => None,
            Expiry::Present(value) => Some(value),
        },
    })
}

fn new_order_location(headers: &http::HeaderMap) -> Result<String, AttemptFailure> {
    let mut locations = headers.get_all(http::header::LOCATION).iter();
    let location = locations
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| failure(FailureKind::Protocol))?;
    if locations.next().is_some() {
        return Err(failure(FailureKind::Protocol));
    }
    validate_url(location).map_err(|_| failure(FailureKind::Protocol))?;
    Ok(location.into())
}

struct DirectoryClient<T> {
    transport: T,
    directory: http::Uri,
    observations: Arc<PlMutex<Observations>>,
}

impl<T: HttpClient> HttpClient for DirectoryClient<T> {
    fn request(
        &self,
        request: http::Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> Pin<
        Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>,
    > {
        let is_directory =
            request.method() == http::Method::GET && request.uri() == &self.directory;
        let generation = Arc::new(());
        let (slot, operation, require_location) = {
            let mut observations = self.observations.lock();
            observations.request = Some(generation.clone());
            observations.response_status = None;
            let slot = observations
                .armed
                .as_ref()
                .filter(|(target, _, _)| {
                    request.method() == http::Method::POST && request.uri() == target
                })
                .map(|(_, slot, _)| slot.clone());
            (
                slot,
                observations.armed.as_ref().map(|(_, slot, _)| slot.clone()),
                observations
                    .armed
                    .as_ref()
                    .is_some_and(|(_, _, required)| *required),
            )
        };
        let work = self.transport.request(request);
        let observations = self.observations.clone();
        Box::pin(async move {
            let mut response = work.await?;
            {
                let mut observations = observations.lock();
                let current_operation = match (operation.as_ref(), observations.armed.as_ref()) {
                    (None, None) => true,
                    (Some(operation), Some((_, current, _))) => Arc::ptr_eq(operation, current),
                    _ => false,
                };
                if current_operation
                    && observations
                        .request
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &generation))
                {
                    observations.response_status =
                        Some((response.parts.status.as_u16(), slot.is_some()));
                }
            }
            if response.parts.status.is_success() && (is_directory || slot.is_some()) {
                let bytes = response
                    .body
                    .into_bytes()
                    .await
                    .map_err(instant_acme::Error::Other)?;
                if bytes.len() > 2 * 1024 * 1024 {
                    return Err(instant_acme::Error::Str("oversized metadata"));
                }
                if is_directory {
                    #[derive(Deserialize)]
                    #[serde(rename_all = "camelCase")]
                    struct Directory {
                        new_order: String,
                        #[serde(default)]
                        renewal_info: Endpoint,
                    }
                    let directory: Directory = serde_json::from_slice(&bytes)?;
                    validate_url(&directory.new_order)
                        .map_err(|_| instant_acme::Error::Str("invalid directory endpoint"))?;
                    let mut metadata = observations.lock();
                    metadata.new_order = Some(directory.new_order.parse()?);
                    metadata.ari = matches!(directory.renewal_info, Endpoint::Present);
                }
                if let Some(slot) = slot {
                    let observations = observations.lock();
                    if observations
                        .armed
                        .as_ref()
                        .is_some_and(|(_, active, _)| Arc::ptr_eq(active, &slot))
                    {
                        *slot.lock() = Some(order_metadata(&bytes).and_then(|mut metadata| {
                            if require_location {
                                metadata.location =
                                    Some(new_order_location(&response.parts.headers)?);
                            }
                            Ok(metadata)
                        }));
                    }
                }
                response = http::Response::from_parts(response.parts, Full::new(bytes)).into();
            }
            Ok(response)
        })
    }
}

#[derive(Default)]
enum Endpoint {
    #[default]
    Missing,
    Present,
}
impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        validate_url(&value).map_err(serde::de::Error::custom)?;
        Ok(Self::Present)
    }
}

trait AttemptTransport: HttpClient + Clone {
    fn reset_retry_hint(&self);
    fn retry_not_before(&self) -> Option<SystemTime>;
}

impl AttemptTransport for AcmeHttpClient {
    fn reset_retry_hint(&self) {
        AcmeHttpClient::reset_retry_hint(self);
    }
    fn retry_not_before(&self) -> Option<SystemTime> {
        AcmeHttpClient::retry_not_before(self)
    }
}

struct Upstream<T> {
    transport: T,
    directory: String,
    observations: Arc<PlMutex<Observations>>,
    account: Option<Account>,
    order: Option<Order>,
}

impl<T: AttemptTransport> Upstream<T> {
    fn new(transport: T, directory: &str) -> Self {
        Self {
            transport,
            directory: directory.into(),
            observations: Arc::new(PlMutex::new(Observations::default())),
            account: None,
            order: None,
        }
    }
    fn builder(&self) -> Result<instant_acme::AccountBuilder, AttemptFailure> {
        Account::builder(
            Box::new(DirectoryClient {
                transport: self.transport.clone(),
                directory: self
                    .directory
                    .parse()
                    .map_err(|_| failure(FailureKind::Protocol))?,
                observations: self.observations.clone(),
            }),
            crypto_provider(),
        )
        .map_err(classify)
    }
    fn order(&mut self) -> Result<&mut Order, AttemptFailure> {
        self.order
            .as_mut()
            .ok_or_else(|| failure(FailureKind::Protocol))
    }
    fn arm(&self, target: &str, require_location: bool) -> Result<(), AttemptFailure> {
        validate_url(target).map_err(|_| failure(FailureKind::Protocol))?;
        self.observations.lock().armed = Some((
            target.parse().map_err(|_| failure(FailureKind::Protocol))?,
            Arc::new(PlMutex::new(None)),
            require_location,
        ));
        Ok(())
    }
    fn snapshot(&mut self) -> Result<Snapshot, AttemptFailure> {
        let (_, slot, _) = self
            .observations
            .lock()
            .armed
            .take()
            .ok_or_else(|| failure(FailureKind::Protocol))?;
        let metadata = slot
            .lock()
            .take()
            .ok_or_else(|| failure(FailureKind::Protocol))??;
        let order = self.order()?;
        if metadata
            .location
            .as_ref()
            .is_some_and(|location| location != order.url())
        {
            return Err(failure(FailureKind::Protocol));
        }
        let url = order.url().into();
        let state = order.state();
        Ok(Snapshot {
            status: state.status,
            url,
            expires: metadata.expires_unix,
            replaces: state.replaces.clone(),
            dns_name: metadata.dns_name,
        })
    }
}

impl<T: AttemptTransport> Engine for Upstream<T> {
    fn directory(&self) -> &str {
        &self.directory
    }
    fn reset_hint(&self) {
        self.transport.reset_retry_hint();
        let mut observations = self.observations.lock();
        observations.request = None;
        observations.response_status = None;
    }
    fn hint(&self) -> Option<SystemTime> {
        self.transport.retry_not_before()
    }
    fn supports_ari(&self) -> bool {
        self.observations.lock().ari
    }
    async fn renewal(
        &mut self,
        identifier: &CertificateIdentifier<'_>,
    ) -> Result<RenewalWindow, AttemptFailure> {
        let account = self.account.as_ref().ok_or(StateError::CorruptData)?;
        let (info, delay) = account.renewal_info(identifier).await.map_err(|error| {
            let mut failure = classify(error);
            failure.retry_not_before = self.transport.retry_not_before();
            failure
        })?;
        Ok(RenewalWindow {
            start: window_second(info.suggested_window.start),
            end: window_second(info.suggested_window.end),
            delay: delay
                .as_secs()
                .saturating_add(u64::from(delay.subsec_nanos() != 0)),
        })
    }
    async fn register(&mut self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, AttemptFailure> {
        let observations = self.observations.clone();
        let der = PrivatePkcs8KeyDer::from(bytes.to_vec());
        let key = Key::from_pkcs8_der(der.clone_key(), crypto_provider()).map_err(classify)?;
        let (account, credentials) = self
            .builder()?
            .create_from_key((key, PrivateKeyDer::Pkcs8(der)), self.directory.clone())
            .await
            .map_err(|error| classify_observed(error, &observations, false))?;
        self.account = Some(account);
        serde_json::to_vec(&credentials)
            .map(Zeroizing::new)
            .map_err(|_| failure(FailureKind::Account))
    }
    async fn restore(&mut self, credentials: AccountCredentials) -> Result<(), AttemptFailure> {
        let observations = self.observations.clone();
        self.account = Some(
            self.builder()?
                .from_credentials(credentials)
                .await
                .map_err(|error| classify_observed(error, &observations, false))?,
        );
        Ok(())
    }
    async fn new_order(
        &mut self,
        dns: &str,
        replaces: Option<CertificateIdentifier<'static>>,
    ) -> Result<Snapshot, AttemptFailure> {
        let observations = self.observations.clone();
        let endpoint = self
            .observations
            .lock()
            .new_order
            .clone()
            .ok_or_else(|| failure(FailureKind::Protocol))?;
        self.arm(&endpoint.to_string(), true)?;
        let identifiers = [Identifier::Dns(dns.into())];
        let mut order = NewOrder::new(&identifiers);
        if let Some(replaces) = replaces {
            order = order.replaces(replaces);
        }
        self.order = Some(
            self.account
                .as_ref()
                .ok_or_else(|| failure(FailureKind::Account))?
                .new_order(&order)
                .await
                .map_err(|error| classify_observed(error, &observations, false))?,
        );
        self.snapshot()
    }
    async fn resume(&mut self, url: &str) -> Result<Snapshot, AttemptFailure> {
        let observations = self.observations.clone();
        self.arm(url, false)?;
        self.order = Some(
            self.account
                .as_ref()
                .ok_or_else(|| failure(FailureKind::Account))?
                .order(url.into())
                .await
                .map_err(|error| classify_observed(error, &observations, true))?,
        );
        self.snapshot()
    }
    async fn authorization(&mut self, refresh: bool) -> Result<Authorization, AttemptFailure> {
        let observations = self.observations.clone();
        let mut authorizations = self.order()?.authorizations();
        let mut authorization = authorizations
            .next()
            .await
            .ok_or_else(|| failure(FailureKind::Authorization))?
            .map_err(|error| classify_observed(error, &observations, false))?;
        if refresh {
            authorization
                .refresh()
                .await
                .map_err(|error| classify_observed(error, &observations, false))?;
        }
        let identifier = authorization.identifier();
        let dns_name = match identifier.identifier {
            Identifier::Dns(dns) => dns.clone(),
            _ => return Err(failure(FailureKind::Authorization)),
        };
        let wildcard = identifier.wildcard;
        let status = authorization.status;
        let challenge = authorization
            .challenge(ChallengeType::Http01)
            .map(|challenge| {
                Ok::<_, AttemptFailure>(HttpChallenge {
                    token: challenge.token.clone(),
                    authorization: challenge
                        .key_authorization()
                        .map_err(classify)?
                        .as_str()
                        .into(),
                    status: challenge.status,
                })
            })
            .transpose()?;
        let result = Authorization {
            dns_name,
            wildcard,
            status,
            challenge,
        };
        if authorizations.next().await.is_some() {
            return Err(failure(FailureKind::Authorization));
        }
        Ok(result)
    }
    async fn ready(&mut self) -> Result<(), AttemptFailure> {
        let observations = self.observations.clone();
        let mut authorizations = self.order()?.authorizations();
        let mut authorization = authorizations
            .next()
            .await
            .ok_or_else(|| failure(FailureKind::Authorization))?
            .map_err(|error| classify_observed(error, &observations, false))?;
        let mut challenge = authorization
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| failure(FailureKind::Authorization))?;
        challenge
            .set_ready()
            .await
            .map_err(|error| classify_observed(error, &observations, false))
    }
    async fn refresh(&mut self) -> Result<Snapshot, AttemptFailure> {
        let observations = self.observations.clone();
        let url = self.order()?.url().to_owned();
        self.arm(&url, false)?;
        self.order()?
            .refresh()
            .await
            .map_err(|error| classify_observed(error, &observations, true))?;
        self.snapshot()
    }
    async fn finalize(&mut self, csr: &[u8]) -> Result<Snapshot, AttemptFailure> {
        let observations = self.observations.clone();
        let url = self.order()?.state().finalize.clone();
        self.arm(&url, false)?;
        self.order()?
            .finalize_csr(csr)
            .await
            .map_err(|error| classify_observed(error, &observations, false))?;
        self.snapshot()
    }
    async fn certificate(&mut self) -> Result<String, AttemptFailure> {
        let observations = self.observations.clone();
        self.order()?
            .certificate()
            .await
            .map_err(|error| classify_observed(error, &observations, false))?
            .ok_or_else(|| failure(FailureKind::Protocol))
    }
}

fn classify(error: instant_acme::Error) -> AttemptFailure {
    let mut result = failure(FailureKind::Protocol);
    match error {
        instant_acme::Error::Api(problem) => {
            result.status = problem.status;
            result.kind = match problem.r#type.as_deref() {
                Some("urn:ietf:params:acme:error:rateLimited") => FailureKind::RateLimited,
                Some(
                    "urn:ietf:params:acme:error:accountDoesNotExist"
                    | "urn:ietf:params:acme:error:userActionRequired",
                ) => FailureKind::Account,
                Some("urn:ietf:params:acme:error:unauthorized") => FailureKind::Authorization,
                _ if problem.status == Some(429) => FailureKind::RateLimited,
                _ if problem.status.is_some_and(|status| status >= 500) => FailureKind::Network,
                _ => FailureKind::Protocol,
            };
        }
        instant_acme::Error::Other(source) => {
            if let Some(error) = source.downcast_ref::<AcmeError>() {
                result.status = error.status();
                result.kind = match error.kind() {
                    AcmeErrorKind::Timeout => FailureKind::Timeout,
                    AcmeErrorKind::Unavailable | AcmeErrorKind::Closed | AcmeErrorKind::Other => {
                        FailureKind::Network
                    }
                    _ => FailureKind::Protocol,
                };
            }
        }
        instant_acme::Error::Timeout(_) => result.kind = FailureKind::Timeout,
        _ => {}
    }
    if result.status == Some(429) {
        result.kind = FailureKind::RateLimited;
    }
    result
}

fn classify_observed(
    error: instant_acme::Error,
    observations: &PlMutex<Observations>,
    order_resource: bool,
) -> AttemptFailure {
    let api = matches!(&error, instant_acme::Error::Api(_));
    let mut result = classify(error);
    if let Some((status, target)) = observations.lock().response_status {
        result.status = Some(status);
        if status == 429 {
            result.kind = FailureKind::RateLimited;
        } else if status >= 500 {
            result.kind = FailureKind::Network;
        }
        result.terminal_order = api && order_resource && target && matches!(status, 404 | 410);
    } else if api {
        result.status = None;
    }
    result
}

fn window_second(time: time::OffsetDateTime) -> Option<u64> {
    u64::try_from(time.unix_timestamp())
        .ok()?
        .checked_add(u64::from(time.nanosecond() != 0))
}

#[derive(Clone, Copy)]
pub(crate) struct RenewalWindow {
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub delay: u64,
}

#[derive(Clone)]
struct AriTransport<T>(T);

impl<T: HttpClient> HttpClient for AriTransport<T> {
    fn request(
        &self,
        request: http::Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> Pin<
        Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>,
    > {
        let is_get = request.method() == http::Method::GET;
        let work = self.0.request(request);
        Box::pin(async move {
            let mut response = work.await?;
            if is_get
                && !response
                    .parts
                    .headers
                    .contains_key(http::header::RETRY_AFTER)
            {
                response.parts.headers.insert(
                    http::header::RETRY_AFTER,
                    http::HeaderValue::from_static("43200"),
                );
            }
            Ok(response)
        })
    }
}

impl<T: AttemptTransport> AttemptTransport for AriTransport<T> {
    fn reset_retry_hint(&self) {
        self.0.reset_retry_hint();
    }
    fn retry_not_before(&self) -> Option<SystemTime> {
        self.0.retry_not_before()
    }
}

#[cfg(test)]
mod tests;
