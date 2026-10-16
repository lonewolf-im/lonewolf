// SPDX-License-Identifier: Apache-2.0

use super::*;
use futures_executor::block_on;
use futures_util::future::{pending, poll_fn};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::task::Poll;
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const NOW: u64 = 1_800_000_000;

#[derive(Clone)]
struct Install {
    validity: CertificateValidity,
    error: Option<InstallError>,
    installed: Arc<PlMutex<usize>>,
}
impl Installer for Install {
    type Prepared = ();
    fn prepare(
        &self,
        _: &ManagedHost,
        _: &CertificateMaterial,
    ) -> Result<PreparedInstall<()>, InstallError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        Ok(PreparedInstall {
            candidate: (),
            validity: self.validity,
        })
    }
    fn activate(&self, _: ()) {
        *self.installed.lock() += 1;
    }
}
fn host(name: &str) -> StoredHost {
    StoredHost {
        host: ManagedHost {
            xmpp_domain: name.into(),
            dns_name: name.into(),
        },
        certificate: None,
        order: None,
        retry: RetryState {
            failures: 0,
            not_before_unix: 0,
        },
    }
}
fn cert(start: u64, end: u64) -> StoredCertificate {
    StoredCertificate {
        replaces: None,
        material: CertificateMaterial {
            chain: vec![vec![1]],
            private_key_pkcs8: Zeroizing::new(vec![2]),
        },
        not_before_unix: start,
        not_after_unix: end,
        renew_at_unix: start + (end - start) / 2,
        ari_check_at_unix: start,
        fallback_at_unix: start + (end - start) / 2,
        ari_window: None,
        ari_failures: 0,
    }
}
fn install(start: u64, end: u64) -> Install {
    Install {
        validity: CertificateValidity {
            not_before_unix: start,
            not_after_unix: end,
        },
        error: None,
        installed: Arc::new(PlMutex::new(0)),
    }
}
fn snapshots(hosts: &[StoredHost]) -> StatusHandle {
    StatusHandle {
        inner: Arc::new(PlMutex::new(
            hosts
                .iter()
                .map(|host| {
                    (
                        host.host.xmpp_domain.clone(),
                        HostStatus {
                            state: HostState::Pending,
                            not_after_unix: None,
                            next_attempt_unix: None,
                            attempts: 0,
                            successes: 0,
                            failures: [0; FAILURE_KIND_COUNT],
                            generation: 0,
                            last_event: HostEvent::InitialLoad,
                            events: [0; EVENT_COUNT],
                        },
                    )
                })
                .collect(),
        )),
    }
}

#[test]
fn cached_material_is_structurally_validated_before_time_or_metadata_admission() -> TestResult {
    for (start, end, expected) in [
        (NOW - 100, NOW + 100, true),
        (NOW - 200, NOW - 100, false),
        (NOW + 100, NOW + 200, false),
    ] {
        let mut record = host("example.com");
        record.certificate = Some(cert(start, end));
        let good = install(start, end);
        assert_eq!(prepare_cache(&record, &good, || Ok(NOW))?, expected);
        assert_eq!(*good.installed.lock(), usize::from(expected));
        let wrong = install(start + 1, end);
        assert_eq!(
            prepare_cache(&record, &wrong, || Ok(NOW)),
            Err(ManagerError::State(StateError::CorruptData))
        );
        for error in [
            InstallError::Invalid,
            InstallError::Expired,
            InstallError::NotYetValid,
        ] {
            let mut invalid = good.clone();
            invalid.error = Some(error);
            assert_eq!(
                prepare_cache(&record, &invalid, || Ok(NOW)),
                Err(ManagerError::State(StateError::CorruptData))
            );
        }
    }
    Ok(())
}

#[derive(Clone, Default)]
struct Memory {
    records: Rc<RefCell<BTreeMap<String, StoredHost>>>,
    account: Rc<RefCell<Option<StoredAccount>>>,
    hold_schedule: Rc<Cell<bool>>,
    schedule_submitted: Rc<Cell<bool>>,
    release_schedule: Rc<RefCell<Option<futures_channel::oneshot::Receiver<()>>>>,
    hold_account_read: Rc<Cell<bool>>,
    account_submitted: Rc<Cell<bool>>,
    release_account: Rc<RefCell<Option<futures_channel::oneshot::Receiver<()>>>>,
    hold_reload: Rc<Cell<bool>>,
    reload_submitted: Rc<Cell<bool>>,
    release_reload: Rc<RefCell<Option<futures_channel::oneshot::Receiver<()>>>>,
}
impl Storage for Memory {
    async fn account(&self) -> Result<Option<StoredAccount>, StateError> {
        if self.hold_account_read.get() && self.release_account.borrow().is_some() {
            self.account_submitted.set(true);
            let receiver = self.release_account.borrow_mut().take();
            if let Some(receiver) = receiver {
                let _ = receiver.await;
            }
        }
        Ok(self.account.borrow().clone())
    }
    async fn save_account(&self, account: StoredAccount) -> Result<(), StateError> {
        *self.account.borrow_mut() = Some(account);
        Ok(())
    }
    async fn host(&self, dns: String) -> Result<Option<StoredHost>, StateError> {
        let new_generation = self
            .records
            .borrow()
            .get(&dns)
            .and_then(|host| host.certificate.as_ref())
            .is_some_and(|cert| cert.material.chain == vec![vec![2]]);
        if self.hold_reload.get() && new_generation && self.release_reload.borrow().is_some() {
            self.reload_submitted.set(true);
            let receiver = self.release_reload.borrow_mut().take();
            if let Some(receiver) = receiver {
                let _ = receiver.await;
            }
        }
        Ok(self.records.borrow().get(&dns).cloned())
    }
    async fn save_host(&self, record: StoredHost) -> Result<(), StateError> {
        if self.hold_schedule.get()
            && record
                .certificate
                .as_ref()
                .is_some_and(|cert| cert.ari_window.is_some())
        {
            self.schedule_submitted.set(true);
            let receiver = self.release_schedule.borrow_mut().take();
            if let Some(receiver) = receiver {
                let _ = receiver.await;
            }
        }
        self.records
            .borrow_mut()
            .insert(record.host.dns_name.clone(), record);
        Ok(())
    }
}
#[derive(Clone)]
struct FakeClock {
    time: Rc<Cell<u64>>,
    sleeps: Rc<RefCell<Vec<u64>>>,
    stop: Rc<Cell<bool>>,
    jumps: Rc<RefCell<VecDeque<u64>>>,
    manual: Rc<Cell<bool>>,
    tick: Rc<Cell<bool>>,
}
impl Clock for FakeClock {
    fn now(&self) -> Result<u64, StateError> {
        Ok(self.time.get())
    }
    fn uniform(&self, _: u64) -> Result<u64, StateError> {
        Ok(0)
    }
    async fn sleep(&self, delay: Duration) {
        self.sleeps.borrow_mut().push(delay.as_secs());
        poll_fn(|cx| {
            if self.stop.get() {
                return Poll::Pending;
            }
            if self.manual.get() {
                return if self.tick.replace(false) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                };
            }
            let next = self
                .jumps
                .borrow_mut()
                .pop_front()
                .unwrap_or(self.time.get() + delay.as_secs());
            self.time.set(next);
            cx.waker().wake_by_ref();
            Poll::Ready(())
        })
        .await
    }
}
#[derive(Clone, Copy)]
enum Step {
    Success,
    Failure(FailureKind),
    Hold,
    Ari(u64, u64, u64),
    Replace,
    Expire,
    AriFailure(FailureKind, Option<u64>),
    State(StateError),
    Commit,
    Advance(u64),
}
struct Script {
    store: Memory,
    clock: FakeClock,
    steps: RefCell<VecDeque<Step>>,
    calls: RefCell<Vec<(String, bool, u64)>>,
    active: Rc<Cell<usize>>,
    peak: Rc<Cell<usize>>,
    limit: usize,
    published: Cell<usize>,
    account_calls: Cell<usize>,
    hold_account: Cell<bool>,
    stop_after_publications: Cell<Option<usize>>,
    commit: RefCell<Option<futures_channel::oneshot::Receiver<()>>>,
    committed: Cell<bool>,
    issued_installs: Cell<usize>,
}
struct Lease(Rc<Cell<usize>>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}
impl Script {
    async fn execute(
        &self,
        mut record: StoredHost,
        ari: bool,
    ) -> Result<Option<RenewalWindow>, AttemptFailure> {
        let active = self.active.get() + 1;
        self.active.set(active);
        self.peak.set(self.peak.get().max(active));
        let _lease = Lease(self.active.clone());
        self.calls
            .borrow_mut()
            .push((record.host.dns_name.clone(), ari, self.clock.time.get()));
        let step = self.steps.borrow_mut().pop_front().unwrap_or(Step::Hold);
        if self.calls.borrow().len() >= self.limit {
            self.clock.stop.set(true);
        }
        match step {
            Step::Advance(time) => {
                self.clock.time.set(time);
                Ok(Some(RenewalWindow {
                    start: Some(time + 100),
                    end: Some(time + 200),
                    delay: 43200,
                }))
            }
            Step::Commit => {
                record.certificate = Some(cert(NOW, NOW + 1000));
                self.store.save_host(record).await?;
                self.committed.set(true);
                let receiver = self.commit.borrow_mut().take();
                if let Some(receiver) = receiver {
                    let _ = receiver.await;
                }
                self.issued_installs.set(self.issued_installs.get() + 1);
                Ok(None)
            }
            Step::State(error) => Err(error.into()),
            Step::AriFailure(kind, hint) => Err(AttemptFailure {
                kind,
                status: None,
                state_error: None,
                retry_not_before: hint.map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds)),
                terminal_order: false,
            }),
            Step::Hold => pending().await,
            Step::Success => {
                record.certificate = Some(cert(
                    self.clock.time.get() - 10,
                    self.clock.time.get() + 1000,
                ));
                record
                    .certificate
                    .as_mut()
                    .ok_or(StateError::CorruptData)?
                    .material
                    .chain = vec![vec![2]];
                record.retry = RetryState {
                    failures: 0,
                    not_before_unix: 0,
                };
                self.store.save_host(record).await?;
                Ok(None)
            }
            Step::Failure(kind) => {
                record.retry.failures += 1;
                record.retry.not_before_unix = self.clock.time.get() + 600;
                self.store.save_host(record).await?;
                Err(AttemptFailure {
                    kind,
                    status: None,
                    state_error: None,
                    retry_not_before: None,
                    terminal_order: false,
                })
            }
            Step::Ari(start, end, delay) => Ok(Some(RenewalWindow {
                start: Some(start),
                end: Some(end),
                delay,
            })),
            Step::Expire => {
                self.clock.time.set(
                    record
                        .certificate
                        .as_ref()
                        .ok_or(StateError::CorruptData)?
                        .not_after_unix,
                );
                Ok(Some(RenewalWindow {
                    start: Some(10),
                    end: Some(20),
                    delay: 60,
                }))
            }
            Step::Replace => {
                record.certificate = Some(cert(NOW, NOW + 20000));
                record
                    .certificate
                    .as_mut()
                    .ok_or(StateError::CorruptData)?
                    .material
                    .chain = vec![vec![3]];
                self.store.save_host(record).await?;
                Ok(Some(RenewalWindow {
                    start: Some(10),
                    end: Some(20),
                    delay: 60,
                }))
            }
        }
    }
}
impl Engine for Script {
    fn publish_cache(&self, record: &StoredHost, now: u64) -> Result<bool, ManagerError> {
        let eligible = record
            .certificate
            .as_ref()
            .is_some_and(|cert| cert.not_before_unix <= now && now < cert.not_after_unix);
        if eligible {
            self.published.set(self.published.get() + 1);
            if self
                .stop_after_publications
                .get()
                .is_some_and(|limit| self.published.get() >= limit)
            {
                self.clock.stop.set(true);
            }
        }
        Ok(eligible)
    }
    async fn ensure_account(&self) -> Result<(), AttemptFailure> {
        self.account_calls.set(self.account_calls.get() + 1);
        if self.hold_account.get() {
            pending::<()>().await;
        }
        Ok(())
    }
    async fn issue(&self, host: StoredHost) -> Result<AttemptSuccess, AttemptFailure> {
        let name = host.host.dns_name.clone();
        self.execute(host, false).await?;
        let records = self.store.records.borrow();
        let certificate = records[&name]
            .certificate
            .as_ref()
            .ok_or(StateError::CorruptData)?;
        Ok(AttemptSuccess {
            validity: CertificateValidity {
                not_before_unix: certificate.not_before_unix,
                not_after_unix: certificate.not_after_unix,
            },
        })
    }
    async fn ari(&self, host: StoredHost) -> Result<Option<RenewalWindow>, AttemptFailure> {
        self.execute(host, true).await
    }
}
fn make_script(hosts: &[StoredHost], steps: Vec<Step>, limit: usize) -> Script {
    let store = Memory::default();
    for host in hosts {
        store
            .records
            .borrow_mut()
            .insert(host.host.dns_name.clone(), host.clone());
    }
    *store.account.borrow_mut() = Some(StoredAccount {
        key_pkcs8: Zeroizing::new(vec![1]),
        credentials_json: None,
        retry: RetryState {
            failures: 0,
            not_before_unix: 0,
        },
    });
    Script {
        store,
        clock: FakeClock {
            time: Rc::new(Cell::new(NOW)),
            sleeps: Rc::new(RefCell::new(Vec::new())),
            stop: Rc::new(Cell::new(false)),
            jumps: Rc::new(RefCell::new(VecDeque::new())),
            manual: Rc::new(Cell::new(false)),
            tick: Rc::new(Cell::new(false)),
        },
        steps: RefCell::new(steps.into()),
        calls: RefCell::new(Vec::new()),
        active: Rc::new(Cell::new(0)),
        peak: Rc::new(Cell::new(0)),
        limit,
        published: Cell::new(0),
        account_calls: Cell::new(0),
        hold_account: Cell::new(false),
        stop_after_publications: Cell::new(None),
        commit: RefCell::new(None),
        committed: Cell::new(false),
        issued_installs: Cell::new(0),
    }
}
fn run(script: &Script, hosts: Vec<StoredHost>) -> Result<StatusHandle, ManagerError> {
    let status = snapshots(&hosts);
    block_on(async {
        let driver = pin!(drive(&script.store, script, &script.clock, hosts, &status));
        let stop = pin!(poll_fn(|cx| {
            if script.clock.stop.get() {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }));
        match select(stop, driver).await {
            Either::Left(_) => Ok(()),
            Either::Right((result, _)) => result,
        }
    })?;
    Ok(status)
}

#[test]
fn two_slots_serialize_each_host_and_allow_progress_while_another_is_pending() -> TestResult {
    let hosts = vec![host("b.example"), host("a.example"), host("c.example")];
    let script = make_script(&hosts, vec![Step::Hold, Step::Success, Step::Hold], 3);
    run(&script, hosts)?;
    let calls = script.calls.borrow();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        ["a.example", "b.example", "c.example"]
    );
    assert_eq!(script.peak.get(), 2);
    assert_eq!(script.active.get(), 0);
    Ok(())
}

#[test]
fn host_backoff_is_not_incremented_twice_and_survives_restart() -> TestResult {
    let hosts = vec![host("example.com")];
    let script = make_script(
        &hosts,
        vec![Step::Failure(FailureKind::Network), Step::Hold],
        2,
    );
    let status = run(&script, hosts)?;
    assert_eq!(script.calls.borrow()[1].2, NOW + 600);
    assert_eq!(
        script.store.records.borrow()["example.com"].retry.failures,
        1
    );
    assert_eq!(
        status.snapshot()[0].1.failures[FailureKind::Network as usize],
        1
    );
    let restored = script.store.records.borrow()["example.com"].clone();
    let restart = make_script(std::slice::from_ref(&restored), vec![Step::Hold], 1);
    run(&restart, vec![restored])?;
    assert_eq!(restart.calls.borrow()[0].2, NOW + 600);
    assert!(
        restart
            .clock
            .sleeps
            .borrow()
            .iter()
            .all(|delay| *delay <= 60)
    );
    Ok(())
}

#[test]
fn ari_ignores_expired_and_replaced_responses_and_keeps_retry_floor() -> TestResult {
    for step in [Step::Expire, Step::Replace] {
        let mut host = host("example.com");
        host.certificate = Some(cert(NOW - 100, NOW + 1000));
        host.retry.not_before_unix = NOW + 2000;
        let script = make_script(&[host.clone()], vec![step, Step::Hold], 2);
        script
            .store
            .account
            .borrow_mut()
            .as_mut()
            .ok_or("account")?
            .retry
            .not_before_unix = 0;
        host.retry.not_before_unix = 0;
        script
            .store
            .records
            .borrow_mut()
            .insert(host.host.dns_name.clone(), host.clone());
        run(&script, vec![host])?;
        let record = script.store.records.borrow()["example.com"].clone();
        assert!(
            record
                .certificate
                .as_ref()
                .ok_or("certificate")?
                .ari_window
                .is_none()
        );
        if matches!(step, Step::Expire) {
            assert!(!script.calls.borrow()[1].1);
        }
    }
    let mut expired = host("example.com");
    expired.certificate = Some(cert(NOW - 200, NOW - 100));
    expired
        .certificate
        .as_mut()
        .ok_or("certificate")?
        .renew_at_unix = NOW + 10_000;
    expired.retry.not_before_unix = NOW + 600;
    let script = make_script(&[expired.clone()], vec![Step::Hold], 1);
    run(&script, vec![expired])?;
    assert_eq!(
        script.calls.borrow()[0],
        ("example.com".into(), false, NOW + 600)
    );
    Ok(())
}

#[test]
fn ari_persists_window_and_does_not_gate_an_earlier_renewal() -> TestResult {
    let mut record = host("example.com");
    record.certificate = Some(cert(NOW - 100, NOW + 1000));
    let script = make_script(
        &[record.clone()],
        vec![Step::Ari(NOW + 120, NOW + 180, 43200), Step::Hold],
        2,
    );
    run(&script, vec![record])?;
    assert_eq!(
        script.calls.borrow()[1],
        ("example.com".into(), false, NOW + 120)
    );
    let records = script.store.records.borrow();
    let certificate = records["example.com"]
        .certificate
        .as_ref()
        .ok_or("certificate")?;
    assert_eq!(
        certificate.ari_window.ok_or("window")?.selected_unix,
        NOW + 120
    );
    assert_eq!(certificate.ari_check_at_unix, NOW + 43200);
    Ok(())
}

#[test]
fn account_failure_blocks_all_hosts_and_old_success_cannot_reset_floor() -> TestResult {
    let hosts = vec![host("a.example"), host("b.example"), host("c.example")];
    let script = make_script(
        &hosts,
        vec![
            Step::Failure(FailureKind::Account),
            Step::Success,
            Step::Hold,
        ],
        3,
    );
    run(&script, hosts)?;
    let account = script.store.account.borrow();
    assert_eq!(account.as_ref().ok_or("account")?.retry.failures, 1);
    assert!(script.calls.borrow()[2].2 >= NOW + 60);
    Ok(())
}

#[test]
fn load_activates_valid_cache_without_network_and_shutdown_ready_never_dispatches() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.redb");
        let mut record = host("example.com");
        record.certificate = Some(cert(NOW - 100, NOW + 100));
        let now = schedule::now()?;
        record.certificate = Some(cert(now - 100, now + 100));
        let store =
            StateStore::open(path.clone(), "https://unreachable.invalid/directory".into()).await?;
        store.save_host(record.clone()).await?;
        drop(store);
        let installer = install(now - 100, now + 100);
        let installed = installer.installed.clone();
        let manager = Manager::load(
            ManagerOptions {
                directory_url: "https://unreachable.invalid/directory".into(),
                state_path: path,
                ca_certificates_path: None,
                hosts: vec![record.host.clone()],
            },
            Challenges::new(&[record.host])?,
            installer,
        )
        .await?;
        assert_eq!(*installed.lock(), 1);
        assert_eq!(manager.status().snapshot()[0].1.state, HostState::Ready);
        manager
            .run(async { Instant::now() + Duration::from_secs(1) })
            .await?;
        assert_eq!(*installed.lock(), 1);
        Ok(())
    })
}

#[test]
fn clock_jumps_recheck_within_a_minute_and_never_bypass_retry_floor() -> TestResult {
    let mut record = host("example.com");
    record.retry.not_before_unix = NOW + 120;
    let script = make_script(std::slice::from_ref(&record), vec![Step::Hold], 1);
    *script.clock.jumps.borrow_mut() = VecDeque::from([NOW - 1000, NOW + 1000]);
    run(&script, vec![record])?;
    assert_eq!(script.calls.borrow()[0].2, NOW + 1000);
    assert_eq!(&script.clock.sleeps.borrow()[..2], &[60, 60]);
    assert!(
        script
            .clock
            .sleeps
            .borrow()
            .iter()
            .all(|delay| *delay <= 60)
    );
    Ok(())
}

#[test]
fn ari_temporary_failure_obeys_retry_after_without_delaying_fallback() -> TestResult {
    let mut record = host("example.com");
    let mut certificate = cert(NOW - 100, NOW + 1000);
    certificate.renew_at_unix = NOW + 120;
    record.certificate = Some(certificate);
    let script = make_script(
        std::slice::from_ref(&record),
        vec![
            Step::AriFailure(FailureKind::RateLimited, Some(NOW + 600)),
            Step::Hold,
        ],
        2,
    );
    run(&script, vec![record])?;
    assert_eq!(
        script.calls.borrow()[1],
        ("example.com".into(), false, NOW + 120)
    );
    let records = script.store.records.borrow();
    let cert = records["example.com"]
        .certificate
        .as_ref()
        .ok_or("certificate")?;
    assert_eq!(cert.ari_check_at_unix, NOW + 600);
    assert_eq!(cert.ari_failures, 1);
    Ok(())
}

#[test]
fn ordinary_ari_failure_retains_schedule_and_malformed_window_restores_fallback() -> TestResult {
    for step in [
        Step::AriFailure(FailureKind::Network, None),
        Step::Ari(4, 3, 0),
        Step::AriFailure(FailureKind::Protocol, None),
    ] {
        let mut record = host("example.com");
        let mut cert = cert(NOW - 100, NOW + 1000);
        cert.renew_at_unix = NOW + 30;
        cert.fallback_at_unix = NOW + 120;
        cert.ari_window = Some(AriWindow {
            start_unix: NOW + 30,
            end_unix: NOW + 60,
            selected_unix: NOW + 30,
        });
        record.certificate = Some(cert);
        let script = make_script(std::slice::from_ref(&record), vec![step, Step::Hold], 2);
        run(&script, vec![record])?;
        let expected = if matches!(step, Step::Ari(..)) {
            NOW + 120
        } else {
            NOW + 30
        };
        assert_eq!(
            script.calls.borrow()[1],
            ("example.com".into(), false, expected)
        );
    }
    Ok(())
}

#[test]
fn durable_state_errors_are_fatal_during_normal_operation() -> TestResult {
    for error in [
        StateError::CorruptData,
        StateError::StateUncertain,
        StateError::Closed,
        StateError::DeadlineElapsed,
    ] {
        for ari in [false, true] {
            let mut record = host("example.com");
            if ari {
                record.certificate = Some(cert(NOW - 100, NOW + 1000));
            }
            let script = make_script(
                std::slice::from_ref(&record),
                vec![Step::State(error)],
                usize::MAX,
            );
            assert!(
                matches!(run(&script,vec![record]),Err(ManagerError::State(actual)) if actual==error)
            );
            assert_eq!(script.active.get(), 0);
        }
    }
    Ok(())
}

#[test]
fn future_cache_publishes_locally_once_without_bypassing_or_changing_durable_work() -> TestResult {
    let mut record = host("future.example");
    record.certificate = Some(cert(NOW + 120, NOW + 1000));
    record
        .certificate
        .as_mut()
        .ok_or("certificate")?
        .ari_check_at_unix = NOW + 20000;
    record.retry = RetryState {
        failures: 4,
        not_before_unix: NOW + 10000,
    };
    record.order = Some(PendingOrder {
        url: None,
        replaces: None,
        key_pkcs8: Zeroizing::new(vec![3]),
        csr_der: vec![4],
        started_unix: NOW,
        expires_unix: None,
    });
    let original = serde_json::to_value(&record)?;
    let script = make_script(std::slice::from_ref(&record), vec![], usize::MAX);
    script.stop_after_publications.set(Some(1));
    let status = run(&script, vec![record])?;
    assert_eq!(script.published.get(), 1);
    assert_eq!(script.account_calls.get(), 0);
    assert!(script.calls.borrow().is_empty());
    assert_eq!(
        serde_json::to_value(&script.store.records.borrow()["future.example"])?,
        original
    );
    let snapshot = &status.snapshot()[0].1;
    assert_eq!(snapshot.state, HostState::Ready);
    assert_eq!(snapshot.generation, 1);
    assert_eq!(snapshot.successes, 0);
    assert_eq!(snapshot.attempts, 0);
    assert_eq!(script.clock.time.get(), NOW + 120);
    Ok(())
}

#[test]
fn pending_account_and_two_busy_network_jobs_cannot_block_local_cache_activation() -> TestResult {
    for account_pending in [false, true] {
        let mut future = host("future.example");
        future.certificate = Some(cert(NOW + 120, NOW + 1000));
        future.retry.not_before_unix = NOW + 10000;
        let hosts = vec![host("a.example"), host("b.example"), future];
        let script = make_script(&hosts, vec![Step::Hold, Step::Hold], usize::MAX);
        script.hold_account.set(account_pending);
        script.stop_after_publications.set(Some(1));
        let status = run(&script, hosts)?;
        assert_eq!(script.published.get(), 1);
        assert_eq!(script.clock.time.get(), NOW + 120);
        assert_eq!(script.account_calls.get(), 1);
        assert_eq!(
            script.calls.borrow().len(),
            if account_pending { 0 } else { 2 }
        );
        assert!(
            script
                .clock
                .sleeps
                .borrow()
                .iter()
                .all(|delay| *delay <= 60)
        );
        assert_eq!(status.snapshot()[2].1.state, HostState::Ready);
        assert_eq!(script.active.get(), 0);
    }
    Ok(())
}

#[test]
fn newer_issuance_discards_unpublished_future_cache_before_it_becomes_valid() -> TestResult {
    let mut record = host("future.example");
    let mut certificate = cert(NOW + 120, NOW + 1000);
    certificate.renew_at_unix = NOW - 1;
    record.certificate = Some(certificate);
    let script = make_script(
        std::slice::from_ref(&record),
        vec![Step::Success, Step::Advance(NOW + 200), Step::Hold],
        3,
    );
    let status = run(&script, vec![record])?;
    assert_eq!(script.published.get(), 0);
    assert_eq!(status.snapshot()[0].1.generation, 1);
    assert_eq!(status.snapshot()[0].1.successes, 1);
    assert_eq!(
        script.store.records.borrow()["future.example"]
            .certificate
            .as_ref()
            .ok_or("certificate")?
            .material
            .chain,
        vec![vec![2]]
    );
    Ok(())
}

#[test]
fn shutdown_wins_when_commit_notification_and_stop_are_both_ready() -> TestResult {
    let hosts = vec![host("example.com")];
    let script = make_script(&hosts, vec![Step::Commit], usize::MAX);
    script.clock.manual.set(true);
    let (commit_tx, commit_rx) = futures_channel::oneshot::channel();
    *script.commit.borrow_mut() = Some(commit_rx);
    let (stop_tx, stop_rx) = futures_channel::oneshot::channel();
    let deadline = Instant::now() + Duration::from_secs(1);
    let status = snapshots(&hosts);
    let future = until_shutdown(
        drive(&script.store, &script, &script.clock, hosts, &status),
        async { stop_rx.await.unwrap_or(deadline) },
    );
    let mut future = Box::pin(future);
    assert!(future.as_mut().now_or_never().is_none());
    assert!(script.committed.get());
    commit_tx.send(()).map_err(|_| "commit receiver")?;
    stop_tx.send(deadline).map_err(|_| "stop receiver")?;
    assert_eq!(block_on(future)?, deadline);
    assert_eq!(script.issued_installs.get(), 0);
    assert_eq!(script.active.get(), 0);
    assert_eq!(status.snapshot()[0].1.successes, 0);
    Ok(())
}

#[test]
fn co_ready_stop_blocks_local_publication_and_clock_jumps_preserve_publication_identity()
-> TestResult {
    let mut record = host("future.example");
    record.certificate = Some(cert(NOW + 120, NOW + 180));
    record
        .certificate
        .as_mut()
        .ok_or("certificate")?
        .ari_check_at_unix = NOW + 20000;
    record.retry.not_before_unix = NOW + 10000;
    let script = make_script(std::slice::from_ref(&record), vec![], usize::MAX);
    let status = snapshots(std::slice::from_ref(&record));
    let (stop_tx, stop_rx) = futures_channel::oneshot::channel();
    let deadline = Instant::now() + Duration::from_secs(1);
    let future = until_shutdown(
        drive(
            &script.store,
            &script,
            &script.clock,
            vec![record.clone()],
            &status,
        ),
        async { stop_rx.await.unwrap_or(deadline) },
    );
    let mut future = Box::pin(future);
    script.clock.stop.set(true);
    assert!(future.as_mut().now_or_never().is_none());
    script.clock.time.set(NOW + 120);
    stop_tx.send(deadline).map_err(|_| "stop receiver")?;
    block_on(future)?;
    assert_eq!(script.published.get(), 0);
    let script = make_script(std::slice::from_ref(&record), vec![Step::Hold], 1);
    *script.clock.jumps.borrow_mut() = VecDeque::from([NOW + 200, NOW + 130, NOW + 110, NOW + 140]);
    let status = snapshots(std::slice::from_ref(&record));
    let driver = drive(&script.store, &script, &script.clock, vec![record], &status);
    let mut driver = Box::pin(driver);
    script.clock.manual.set(true);
    assert!(driver.as_mut().now_or_never().is_none());
    assert_eq!(script.published.get(), 0);
    script.clock.time.set(NOW + 200);
    script.clock.tick.set(true);
    assert!(driver.as_mut().now_or_never().is_none());
    assert_eq!(script.published.get(), 0);
    assert_eq!(status.snapshot()[0].1.state, HostState::Expired);
    script.clock.time.set(NOW + 130);
    script.clock.tick.set(true);
    assert!(driver.as_mut().now_or_never().is_none());
    assert_eq!(script.published.get(), 1);
    assert_eq!(status.snapshot()[0].1.state, HostState::Ready);
    script.clock.time.set(NOW + 110);
    script.clock.tick.set(true);
    assert!(driver.as_mut().now_or_never().is_none());
    assert_eq!(status.snapshot()[0].1.state, HostState::Pending);
    script.clock.time.set(NOW + 140);
    script.clock.tick.set(true);
    assert!(driver.as_mut().now_or_never().is_none());
    assert_eq!(script.published.get(), 1);
    assert_eq!(status.snapshot()[0].1.state, HostState::Ready);
    Ok(())
}

#[test]
fn shutdown_clears_leases_and_uses_the_same_absolute_deadline_for_both_drains() -> TestResult {
    use instant_acme::HttpClient as _;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = accepted_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(5));
                    drop(stream);
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(_) => return,
            }
        }
    });
    let result = compio::runtime::Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let host = host("example.com").host;
        let challenges = Challenges::new(std::slice::from_ref(&host))?;
        let manager = Manager::load(
            ManagerOptions {
                directory_url: format!("https://{address}/directory"),
                state_path: directory.path().join("state.redb"),
                ca_certificates_path: None,
                hosts: vec![host],
            },
            challenges.clone(),
            install(NOW, NOW + 1000),
        )
        .await?;
        let store = manager.store.clone();
        let transport = manager.transport.clone();
        let token = "B".repeat(43);
        let lease = challenges.publish(
            "example.com",
            &token,
            &format!("{token}.{}", "A".repeat(43)),
        )?;
        let request = http::Request::builder()
            .uri(format!("https://{address}/stalled"))
            .body(instant_acme::BodyWrapper::default())?;
        let mut request = transport.request(request);
        assert!(request.as_mut().now_or_never().is_none());
        let setup_deadline = Instant::now() + Duration::from_secs(5);
        while accepted_rx.try_recv().is_err() {
            if Instant::now() >= setup_deadline {
                return Err("HTTP request did not connect".into());
            }
            compio::time::sleep(Duration::from_millis(1)).await;
        }
        drop(request);
        let start = Instant::now();
        let deadline = start + Duration::from_millis(25);
        assert_eq!(
            manager.run(async { deadline }).await,
            Err(ManagerError::Deadline)
        );
        assert!(start.elapsed() < Duration::from_millis(500));
        assert!(challenges.lookup("example.com", &token).is_none());
        drop(lease);
        assert!(matches!(store.account().await, Err(StateError::Closed)));
        Ok(())
    });
    let _ = release_tx.send(());
    worker.join().map_err(|_| "HTTP stall thread failed")?;
    result
}

#[test]
fn pending_ari_is_cancelled_when_selected_issuance_becomes_due() -> TestResult {
    let mut record = host("example.com");
    let mut certificate = cert(NOW - 100, NOW + 1000);
    certificate.renew_at_unix = NOW + 120;
    record.certificate = Some(certificate);
    let script = make_script(
        std::slice::from_ref(&record),
        vec![Step::Hold, Step::Hold],
        2,
    );
    run(&script, vec![record])?;
    assert_eq!(
        *script.calls.borrow(),
        [
            ("example.com".into(), true, NOW),
            ("example.com".into(), false, NOW + 120)
        ]
    );
    assert_eq!(script.peak.get(), 1);
    assert_eq!(script.active.get(), 0);
    Ok(())
}

#[test]
fn submitted_ari_schedule_save_retains_host_ownership_until_commit_completes() -> TestResult {
    let mut record = host("example.com");
    let mut certificate = cert(NOW - 100, NOW + 1000);
    certificate.renew_at_unix = NOW + 120;
    record.certificate = Some(certificate);
    let mut second = host("future.example");
    second.certificate = Some(cert(NOW + 120, NOW + 1000));
    second
        .certificate
        .as_mut()
        .ok_or("certificate")?
        .ari_check_at_unix = NOW + 20000;
    second.retry.not_before_unix = NOW + 10000;
    let hosts = vec![record, second];
    let script = make_script(
        &hosts,
        vec![Step::Ari(NOW + 120, NOW + 180, 43200), Step::Hold],
        2,
    );
    script.clock.manual.set(true);
    script.store.hold_schedule.set(true);
    let (release_tx, release_rx) = futures_channel::oneshot::channel();
    *script.store.release_schedule.borrow_mut() = Some(release_rx);
    let status = snapshots(&hosts);
    let mut driver = Box::pin(drive(&script.store, &script, &script.clock, hosts, &status));
    assert!(driver.as_mut().now_or_never().is_none());
    assert!(script.store.schedule_submitted.get());
    assert_eq!(script.calls.borrow().len(), 1);
    script.clock.time.set(NOW + 120);
    script.clock.tick.set(true);
    assert!(driver.as_mut().now_or_never().is_none());
    assert_eq!(script.calls.borrow().len(), 1);
    assert_eq!(status.snapshot()[1].1.state, HostState::Ready);
    assert_eq!(status.snapshot()[1].1.generation, 1);
    assert!(
        script.store.records.borrow()["example.com"]
            .certificate
            .as_ref()
            .ok_or("certificate")?
            .ari_window
            .is_none()
    );
    release_tx
        .send(())
        .map_err(|_| "schedule commit receiver")?;
    assert!(driver.as_mut().now_or_never().is_none());
    assert_eq!(
        script.calls.borrow()[1],
        ("example.com".into(), false, NOW + 120)
    );
    assert_eq!(
        script.store.records.borrow()["example.com"]
            .certificate
            .as_ref()
            .ok_or("certificate")?
            .ari_window
            .ok_or("window")?
            .selected_unix,
        NOW + 120
    );
    drop(driver);
    assert_eq!(script.active.get(), 0);
    Ok(())
}

#[test]
fn failed_renewal_preserves_published_material_through_expiry_and_eventual_recovery() -> TestResult
{
    let mut record = host("example.com");
    let mut certificate = cert(NOW - 100, NOW + 120);
    certificate.renew_at_unix = NOW;
    certificate.ari_check_at_unix = NOW + 10000;
    record.certificate = Some(certificate);
    let script = make_script(
        std::slice::from_ref(&record),
        vec![
            Step::Failure(FailureKind::Network),
            Step::Success,
            Step::Hold,
        ],
        usize::MAX,
    );
    script.clock.manual.set(true);
    let status = snapshots(std::slice::from_ref(&record));
    let mut driver = Box::pin(drive(
        &script.store,
        &script,
        &script.clock,
        vec![record],
        &status,
    ));
    assert!(driver.as_mut().now_or_never().is_none());
    assert_eq!(status.snapshot()[0].1.state, HostState::Ready);
    assert_eq!(
        script.store.records.borrow()["example.com"]
            .certificate
            .as_ref()
            .ok_or("certificate")?
            .material
            .chain,
        vec![vec![1]]
    );
    assert_eq!(
        script.store.records.borrow()["example.com"]
            .retry
            .not_before_unix,
        NOW + 600
    );
    script.clock.time.set(NOW + 120);
    script.clock.tick.set(true);
    assert!(driver.as_mut().now_or_never().is_none());
    assert_eq!(status.snapshot()[0].1.state, HostState::Expired);
    assert_eq!(script.calls.borrow().len(), 1);
    assert_eq!(script.published.get(), 1);
    script.clock.time.set(NOW + 600);
    script.clock.tick.set(true);
    assert!(driver.as_mut().now_or_never().is_none());
    let snapshot = &status.snapshot()[0].1;
    assert_eq!(snapshot.state, HostState::Ready);
    assert_eq!(snapshot.successes, 1);
    assert_eq!(snapshot.generation, 2);
    assert_eq!(snapshot.failures[FailureKind::Network as usize], 1);
    assert_eq!(
        script.store.records.borrow()["example.com"]
            .certificate
            .as_ref()
            .ok_or("certificate")?
            .material
            .chain,
        vec![vec![2]]
    );
    drop(driver);
    assert_eq!(script.active.get(), 0);
    Ok(())
}

#[test]
fn success_suppresses_old_pending_cache_while_reload_and_other_host_validity_wait() -> TestResult {
    let mut original = host("a.example");
    let mut certificate = cert(NOW + 120, NOW + 1000);
    certificate.renew_at_unix = NOW;
    original.certificate = Some(certificate);
    let mut second = host("b.example");
    second.certificate = Some(cert(NOW + 120, NOW + 1000));
    second
        .certificate
        .as_mut()
        .ok_or("certificate")?
        .ari_check_at_unix = NOW + 20000;
    second.retry.not_before_unix = NOW + 10000;
    let hosts = vec![original, second];
    let script = make_script(&hosts, vec![Step::Success, Step::Hold], usize::MAX);
    script.clock.manual.set(true);
    script.store.hold_reload.set(true);
    let (release_tx, release_rx) = futures_channel::oneshot::channel();
    *script.store.release_reload.borrow_mut() = Some(release_rx);
    let status = snapshots(&hosts);
    let mut driver = Box::pin(drive(&script.store, &script, &script.clock, hosts, &status));
    assert!(driver.as_mut().now_or_never().is_none());
    assert!(script.store.reload_submitted.get());
    assert_eq!(status.snapshot()[0].1.state, HostState::Ready);
    assert_eq!(status.snapshot()[0].1.generation, 1);
    assert_eq!(
        status.snapshot()[0].1.events[HostEvent::Installed as usize],
        1
    );
    script.clock.time.set(NOW + 120);
    script.clock.tick.set(true);
    assert!(driver.as_mut().now_or_never().is_none());
    assert_eq!(script.published.get(), 1);
    assert_eq!(status.snapshot()[1].1.state, HostState::Ready);
    assert_eq!(
        status.snapshot()[0].1.events[HostEvent::Installed as usize],
        1
    );
    release_tx.send(()).map_err(|_| "reload receiver")?;
    assert!(driver.as_mut().now_or_never().is_none());
    assert_eq!(status.snapshot()[0].1.generation, 1);
    assert_eq!(status.snapshot()[0].1.successes, 1);
    assert_eq!(script.published.get(), 1);
    drop(driver);
    assert_eq!(script.active.get(), 0);
    Ok(())
}

#[test]
fn held_account_read_preserves_local_validity_wakes_and_stop_priority() -> TestResult {
    for stop_ready in [false, true] {
        let mut record = host("future.example");
        record.certificate = Some(cert(NOW + 120, NOW + 1000));
        record
            .certificate
            .as_mut()
            .ok_or("certificate")?
            .ari_check_at_unix = NOW + 20000;
        record.retry.not_before_unix = NOW + 10000;
        let hosts = vec![record];
        let script = make_script(&hosts, vec![], usize::MAX);
        script.clock.manual.set(true);
        script.store.hold_account_read.set(true);
        let (release_tx, release_rx) = futures_channel::oneshot::channel();
        *script.store.release_account.borrow_mut() = Some(release_rx);
        let (stop_tx, stop_rx) = futures_channel::oneshot::channel();
        let deadline = Instant::now() + Duration::from_secs(1);
        let status = snapshots(&hosts);
        let mut future = Box::pin(until_shutdown(
            drive(&script.store, &script, &script.clock, hosts, &status),
            async { stop_rx.await.unwrap_or(deadline) },
        ));
        assert!(future.as_mut().now_or_never().is_none());
        assert!(script.store.account_submitted.get());
        script.clock.time.set(NOW + 120);
        script.clock.tick.set(true);
        if stop_ready {
            stop_tx.send(deadline).map_err(|_| "stop receiver")?;
            assert_eq!(block_on(future)?, deadline);
            assert_eq!(script.published.get(), 0);
        } else {
            assert!(future.as_mut().now_or_never().is_none());
            assert_eq!(script.published.get(), 1);
            assert_eq!(status.snapshot()[0].1.state, HostState::Ready);
            assert!(script.calls.borrow().is_empty());
            assert_eq!(script.account_calls.get(), 0);
            release_tx.send(()).map_err(|_| "account receiver")?;
            stop_tx.send(deadline).map_err(|_| "stop receiver")?;
            block_on(future)?;
        }
    }
    Ok(())
}

#[test]
fn ari_error_classes_persist_backoff_without_resampling_schedule_or_changing_order() -> TestResult {
    for kind in [
        FailureKind::Network,
        FailureKind::RateLimited,
        FailureKind::Protocol,
    ] {
        for previous in 0..4 {
            let mut record = host("example.com");
            let mut certificate = cert(NOW - 100, NOW + 50000);
            let window = AriWindow {
                start_unix: NOW + 20000,
                end_unix: NOW + 21000,
                selected_unix: NOW + 20000,
            };
            certificate.ari_window = Some(window);
            certificate.renew_at_unix = window.selected_unix;
            certificate.fallback_at_unix = NOW + 25000;
            certificate.ari_failures = previous;
            record.certificate = Some(certificate);
            record.order = Some(PendingOrder {
                url: None,
                replaces: None,
                key_pkcs8: Zeroizing::new(vec![3]),
                csr_der: vec![4],
                started_unix: NOW,
                expires_unix: None,
            });
            let original_order = serde_json::to_value(&record.order)?;
            let script = make_script(
                std::slice::from_ref(&record),
                vec![Step::AriFailure(kind, None), Step::Hold],
                2,
            );
            run(&script, vec![record])?;
            let records = script.store.records.borrow();
            let record = &records["example.com"];
            let certificate = record.certificate.as_ref().ok_or("certificate")?;
            let expected = if kind == FailureKind::Protocol {
                43200
            } else {
                [60, 600, 6000, 43200][previous as usize]
            };
            assert_eq!(certificate.ari_failures, previous + 1);
            assert_eq!(certificate.ari_check_at_unix, NOW + expected);
            assert_eq!(certificate.renew_at_unix, window.selected_unix);
            assert_eq!(certificate.ari_window, Some(window));
            assert_eq!(certificate.fallback_at_unix, NOW + 25000);
            assert_eq!(serde_json::to_value(&record.order)?, original_order);
            assert_eq!(record.retry.failures, 0);
            let second = &script.calls.borrow()[1];
            assert_eq!(second.2, NOW + expected.min(20000));
            assert_eq!(second.1, expected < 20000);
        }
    }
    Ok(())
}
