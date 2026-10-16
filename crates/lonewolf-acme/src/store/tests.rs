// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs;
use std::future::Future;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::pin::Pin;
use std::sync::mpsc;
use std::task::{Context, Waker};
use std::time::Duration;

use futures_executor::block_on;
use zeroize::Zeroizing;

use super::*;
use crate::types::{
    CertificateMaterial, MAX_RECORD, ManagedHost, PendingOrder, RetryState, StoredCertificate,
};

type TestResult = Result<(), Box<dyn Error>>;
const DIRECTORY: &str = "https://ca.example/directory";
const TIMEOUT: Duration = Duration::from_secs(5);

fn open(path: &Path) -> Result<StateStore, StateError> {
    block_on(StateStore::open(path.to_owned(), DIRECTORY.into()))
}

fn account(byte: u8) -> StoredAccount {
    StoredAccount {
        key_pkcs8: Zeroizing::new(vec![byte; 8]),
        credentials_json: Some(Zeroizing::new(br#"{"account":"durable"}"#.to_vec())),
        retry: RetryState {
            failures: 7,
            not_before_unix: 1_900_000_000,
        },
    }
}

fn host(byte: u8) -> StoredHost {
    StoredHost {
        host: ManagedHost {
            xmpp_domain: "example.com".into(),
            dns_name: "example.com".into(),
        },
        certificate: Some(StoredCertificate {
            material: CertificateMaterial {
                chain: vec![vec![byte; 8]],
                private_key_pkcs8: Zeroizing::new(vec![byte; 8]),
            },
            not_before_unix: 10,
            not_after_unix: 20,
            renew_at_unix: 0,
            ari_check_at_unix: 30,
        }),
        order: Some(PendingOrder {
            url: None,
            key_pkcs8: Zeroizing::new(vec![byte + 1; 8]),
            csr_der: vec![byte + 2; 8],
            started_unix: 50,
            expires_unix: Some(40),
        }),
        retry: RetryState {
            failures: 3,
            not_before_unix: 1_900_000_000,
        },
    }
}

fn restored_host(store: &StateStore) -> Result<StoredHost, Box<dyn Error>> {
    block_on(store.host("example.com".into()))?.ok_or_else(|| "missing host".into())
}

fn assert_material(record: &StoredHost, byte: u8, pending: bool) -> TestResult {
    let certificate = record.certificate.as_ref().ok_or("missing certificate")?;
    assert_eq!(certificate.material.chain, vec![vec![byte; 8]]);
    assert_eq!(
        certificate.material.private_key_pkcs8.as_slice(),
        &[byte; 8]
    );
    assert_eq!(record.order.is_some(), pending);
    Ok(())
}

#[test]
fn restart_preserves_account_order_material_retry_and_atomic_activation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.redb");
    let sentinel = directory.path().join("accounts.redb");
    fs::write(&sentinel, b"untouched account database")?;
    let store = open(&path)?;
    assert!(block_on(store.account())?.is_none());
    assert!(block_on(store.host("example.com".into()))?.is_none());
    block_on(store.save_account(account(1)))?;
    block_on(store.save_host(host(2)))?;
    drop(store);

    let store = open(&path)?;
    let restored = block_on(store.account())?.ok_or("missing account")?;
    assert_eq!(restored.key_pkcs8.as_slice(), &[1; 8]);
    assert_eq!(
        restored.credentials_json.as_deref().map(Vec::as_slice),
        Some(br#"{"account":"durable"}"#.as_slice())
    );
    assert_eq!(restored.retry, account(1).retry);
    let mut restored = restored_host(&store)?;
    assert_material(&restored, 2, true)?;
    assert_eq!(restored.retry, host(2).retry);
    let order = restored.order.as_mut().ok_or("missing order")?;
    assert_eq!(order.key_pkcs8.as_slice(), &[3; 8]);
    assert_eq!(order.csr_der, vec![4; 8]);
    assert_eq!(order.url, None);
    order.url = Some("https://ca.example/order/1".into());
    block_on(store.save_host(restored))?;
    drop(store);

    let store = open(&path)?;
    let restored = restored_host(&store)?;
    assert_eq!(
        restored
            .order
            .as_ref()
            .and_then(|order| order.url.as_deref()),
        Some("https://ca.example/order/1")
    );
    let mut replacement = host(9);
    replacement.order = None;
    block_on(store.save_host(replacement))?;
    drop(store);
    assert_material(&restored_host(&open(&path)?)?, 9, false)?;
    assert_eq!(fs::read(sentinel)?, b"untouched account database");
    Ok(())
}

#[test]
fn directory_namespaces_and_clone_lifetimes_are_isolated() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.redb");
    let first = open(&path)?;
    block_on(first.save_account(account(1)))?;
    block_on(first.save_host(host(2)))?;
    let clone = first.clone();
    assert!(matches!(open(&path), Err(StateError::Unavailable)));
    drop(first);
    assert!(matches!(open(&path), Err(StateError::Unavailable)));
    drop(clone);
    let alternate = block_on(StateStore::open(
        path.clone(),
        "https://CA.example:443/directory".into(),
    ))?;
    assert!(block_on(alternate.account())?.is_none());
    assert!(block_on(alternate.host("example.com".into()))?.is_none());
    block_on(alternate.save_account(account(7)))?;
    block_on(alternate.save_host(host(8)))?;
    drop(alternate);
    let first = open(&path)?;
    assert_eq!(
        block_on(first.account())?
            .ok_or("missing account")?
            .key_pkcs8
            .as_slice(),
        &[1; 8]
    );
    assert_material(&restored_host(&first)?, 2, true)?;
    Ok(())
}

#[test]
fn creates_private_files_and_parents_without_changing_existing_parent_modes() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))?;
    let path = directory.path().join("new/nested/state.redb");
    let store = open(&path)?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    for parent in ["new", "new/nested"] {
        assert_eq!(
            fs::metadata(directory.path().join(parent))?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    assert_eq!(
        fs::metadata(directory.path())?.permissions().mode() & 0o777,
        0o755
    );
    drop(store);
    Ok(())
}

#[test]
fn rejects_insecure_symlink_and_nonregular_files_without_modifying_them() -> TestResult {
    let directory = tempfile::tempdir()?;
    let insecure = directory.path().join("insecure");
    fs::write(&insecure, b"preserve this")?;
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o640))?;
    assert!(matches!(open(&insecure), Err(StateError::UnsafePath)));
    assert_eq!(fs::read(&insecure)?, b"preserve this");
    assert_eq!(fs::metadata(&insecure)?.permissions().mode() & 0o777, 0o640);
    let target = directory.path().join("target");
    fs::write(&target, b"preserve symlink target")?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    let link = directory.path().join("link");
    symlink(&target, &link)?;
    assert!(open(&link).is_err());
    assert!(fs::symlink_metadata(&link)?.is_symlink());
    assert_eq!(fs::read(&target)?, b"preserve symlink target");
    let socket = directory.path().join("socket");
    let _listener = UnixListener::bind(&socket)?;
    assert!(open(&socket).is_err());
    assert!(open(directory.path()).is_err());
    Ok(())
}

#[test]
fn corrupt_database_is_preserved_and_invalid_url_creates_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("invalid.redb");
    fs::write(&path, b"not a redb database")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    assert!(open(&path).is_err());
    assert_eq!(fs::read(path)?, b"not a redb database");
    let absent = directory.path().join("absent/state.redb");
    assert!(matches!(
        block_on(StateStore::open(
            absent.clone(),
            "http://ca.example/".into()
        )),
        Err(StateError::InvalidData)
    ));
    assert!(!absent.parent().ok_or("missing parent")?.exists());
    Ok(())
}

fn inject(
    store: &StateStore,
    table: TableDefinition<'static, &[u8], &[u8]>,
    key: Vec<u8>,
    bytes: Zeroizing<Vec<u8>>,
) -> Result<(), StateError> {
    block_on(store.run(true, move |inner| {
        let transaction = begin_write(&inner.database)?;
        transaction
            .open_table(table)
            .map_err(backend_error)?
            .insert(key.as_slice(), bytes.as_slice())
            .map_err(backend_error)?;
        transaction.commit().map_err(commit_error)
    }))
}

#[test]
fn malformed_oversized_and_unknown_fields_are_not_missing_or_overwritten() -> TestResult {
    let directory = tempfile::tempdir()?;
    for (index, bytes) in [b"{".to_vec(), vec![0; MAX_RECORD + 1], br#"{"directory_url":"https://ca.example/directory","account":{"key_pkcs8":[1],"credentials_json":null,"retry":{"failures":0,"not_before_unix":0},"unexpected":true}}"#.to_vec()].into_iter().enumerate() {
        let path = directory.path().join(format!("{index}.redb"));
        let store = open(&path)?;
        inject(&store, ACCOUNTS, store.inner.namespace.to_vec(), Zeroizing::new(bytes))?;
        assert!(matches!(block_on(store.account()), Err(StateError::CorruptData)));
        assert_eq!(block_on(store.save_account(account(1))), Err(StateError::CorruptData));
        assert!(matches!(block_on(store.account()), Err(StateError::CorruptData)));
    }
    Ok(())
}

#[test]
fn namespace_collisions_and_record_host_disagreement_fail_closed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.redb");
    let store = open(&path)?;
    let wrong_url = "https://other.example/directory";
    let record = encode(&AccountWrite {
        directory_url: wrong_url,
        account: &account(1),
    })?;
    inject(&store, ACCOUNTS, store.inner.namespace.to_vec(), record)?;
    assert!(matches!(
        block_on(store.account()),
        Err(StateError::CorruptData)
    ));
    let record = encode(&HostWrite {
        directory_url: DIRECTORY,
        host: &host(1),
    })?;
    inject(&store, HOSTS, store.inner.host_key("other.example"), record)?;
    assert!(matches!(
        block_on(store.host("other.example".into())),
        Err(StateError::CorruptData)
    ));
    assert_eq!(
        block_on(store.save_host(StoredHost {
            host: ManagedHost {
                xmpp_domain: "other.example".into(),
                dns_name: "other.example".into()
            },
            certificate: None,
            order: None,
            retry: RetryState {
                failures: 0,
                not_before_unix: 0
            }
        })),
        Err(StateError::CorruptData)
    );
    assert!(matches!(
        block_on(store.host("Example.com".into())),
        Err(StateError::InvalidData)
    ));
    inject(
        &store,
        DIRECTORIES,
        store.inner.namespace.to_vec(),
        Zeroizing::new(wrong_url.as_bytes().to_vec()),
    )?;
    assert!(matches!(
        block_on(store.host("example.com".into())),
        Err(StateError::CorruptData)
    ));
    drop(store);
    assert!(matches!(open(&path), Err(StateError::CorruptData)));
    Ok(())
}

#[test]
fn failed_and_uncertain_commits_preserve_atomic_material_and_require_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    for (index, fault, expected, byte, pending) in [
        (0, Fault::PreCommit, StateError::Unavailable, 1, true),
        (
            1,
            Fault::UncertainBefore,
            StateError::StateUncertain,
            1,
            true,
        ),
        (
            2,
            Fault::UncertainAfter,
            StateError::StateUncertain,
            9,
            false,
        ),
    ] {
        let path = directory.path().join(format!("{index}.redb"));
        let store = open(&path)?;
        block_on(store.save_host(host(1)))?;
        *store.inner.fault.lock() = fault;
        let mut replacement = host(9);
        replacement.order = None;
        assert_eq!(block_on(store.save_host(replacement)), Err(expected));
        assert_material(&restored_host(&store)?, byte, pending)?;
        if expected == StateError::StateUncertain {
            assert_eq!(
                block_on(store.clone().save_account(account(1))),
                Err(StateError::StateUncertain)
            );
            assert_eq!(
                block_on(store.save_host(host(7))),
                Err(StateError::StateUncertain)
            );
        } else {
            block_on(store.save_account(account(1)))?;
        }
        drop(store);
        let reopened = open(&path)?;
        assert_material(&restored_host(&reopened)?, byte, pending)?;
        block_on(reopened.save_account(account(5)))?;
    }
    Ok(())
}

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn cancelled_admitted_work_and_drain_keep_admission_closed() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let store = open(&directory.path().join("state.redb"))?;
        let (entered, started) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let mut running = Box::pin(store.run(false, move |_| {
            let _ = entered.send(());
            gate.recv_timeout(TIMEOUT).map_err(|_| StateError::Other)
        }));
        assert!(poll(running.as_mut()).is_pending());
        started.recv_timeout(TIMEOUT)?;
        let mut queued = Box::pin(store.save_account(account(1)));
        assert!(poll(queued.as_mut()).is_pending());
        assert_eq!(store.inner.admission.lock().active, 2);
        drop(queued);
        assert_eq!(store.inner.admission.lock().active, 1);
        let mut drain = Box::pin(store.drain(Instant::now() + TIMEOUT));
        assert!(poll(drain.as_mut()).is_pending());
        drop(drain);
        assert!(matches!(
            store.clone().account().await,
            Err(StateError::Closed)
        ));
        release.send(())?;
        running.await?;
        store.drain(Instant::now() + TIMEOUT).await?;
        assert_eq!(store.inner.admission.lock().active, 0);
        Ok(())
    })
}

#[test]
fn submitted_work_retains_lock_after_cancellation_and_expired_drain() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.redb");
    let store = open(&path)?;
    let (entered, started) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let mut running = Box::pin(store.run(false, move |_| {
        let _ = entered.send(());
        gate.recv_timeout(TIMEOUT).map_err(|_| StateError::Other)
    }));
    assert!(poll(running.as_mut()).is_pending());
    started.recv_timeout(TIMEOUT)?;
    drop(running);
    assert_eq!(
        block_on(store.drain(Instant::now())),
        Err(StateError::DeadlineElapsed)
    );
    assert!(matches!(open(&path), Err(StateError::Unavailable)));
    assert!(matches!(block_on(store.account()), Err(StateError::Closed)));
    let weak = Arc::downgrade(&store.inner);
    let executor = store.inner.executor.clone();
    drop(store);
    assert!(matches!(open(&path), Err(StateError::Unavailable)));
    release.send(())?;
    compio::runtime::Runtime::new()?
        .block_on(async { compio::time::timeout(TIMEOUT, executor.run(|| ())).await })?;
    assert_eq!(weak.strong_count(), 0);
    let _reopened = open(&path)?;
    Ok(())
}

#[test]
fn drain_notifies_all_waiters_and_obeys_absolute_timeout() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let store = open(&directory.path().join("state.redb"))?;
        let (entered, started) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let mut running = Box::pin(store.run(false, move |_| {
            let _ = entered.send(());
            gate.recv_timeout(TIMEOUT).map_err(|_| StateError::Other)
        }));
        assert!(poll(running.as_mut()).is_pending());
        started.recv_timeout(TIMEOUT)?;
        let deadline = Instant::now() + Duration::from_millis(25);
        assert_eq!(
            store.drain(deadline).await,
            Err(StateError::DeadlineElapsed)
        );
        assert!(Instant::now().duration_since(deadline) < Duration::from_secs(1));
        let clone = store.clone();
        let mut first = Box::pin(store.drain(Instant::now() + TIMEOUT));
        let mut second = Box::pin(clone.drain(Instant::now() + TIMEOUT));
        assert!(poll(first.as_mut()).is_pending());
        assert!(poll(second.as_mut()).is_pending());
        release.send(())?;
        first.await?;
        second.await?;
        running.await?;
        Ok(())
    })
}

#[test]
fn panicking_operation_releases_admission_and_executor_capacity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = open(&directory.path().join("state.redb"))?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        block_on(store.run::<()>(false, |_| panic!("injected state operation panic")))
    }));
    assert!(result.is_err());
    assert_eq!(store.inner.admission.lock().active, 0);
    block_on(store.save_account(account(1)))?;
    block_on(store.drain(Instant::now() + TIMEOUT))?;
    Ok(())
}

#[test]
fn queued_mutations_stop_after_an_uncertain_commit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = open(&directory.path().join("state.redb"))?;
    *store.inner.fault.lock() = Fault::UncertainAfter;
    let (entered, started) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let mut first = Box::pin(store.run(true, move |inner| {
        let _ = entered.send(());
        gate.recv_timeout(TIMEOUT).map_err(|_| StateError::Other)?;
        inner.commit(inner.write()?)
    }));
    assert!(poll(first.as_mut()).is_pending());
    started.recv_timeout(TIMEOUT)?;
    let mut queued = Box::pin(store.save_account(account(1)));
    assert!(poll(queued.as_mut()).is_pending());
    release.send(())?;
    assert_eq!(block_on(first), Err(StateError::StateUncertain));
    assert_eq!(block_on(queued), Err(StateError::StateUncertain));
    assert!(block_on(store.account())?.is_none());
    Ok(())
}

#[test]
fn account_key_credentials_and_retry_commit_together() -> TestResult {
    let directory = tempfile::tempdir()?;
    for (index, fault, expected, byte) in [
        (0, Fault::PreCommit, StateError::Unavailable, 1),
        (1, Fault::UncertainBefore, StateError::StateUncertain, 1),
        (2, Fault::UncertainAfter, StateError::StateUncertain, 9),
    ] {
        let path = directory.path().join(format!("{index}.redb"));
        let store = open(&path)?;
        block_on(store.save_account(account(1)))?;
        let mut replacement = account(9);
        replacement.credentials_json = Some(Zeroizing::new(b"null".to_vec()));
        replacement.retry = RetryState {
            failures: 0,
            not_before_unix: 2_000_000_000,
        };
        *store.inner.fault.lock() = fault;
        assert_eq!(block_on(store.save_account(replacement)), Err(expected));
        drop(store);
        let reopened = open(&path)?;
        let restored = block_on(reopened.account())?.ok_or("missing account")?;
        assert_eq!(restored.key_pkcs8.as_slice(), &[byte; 8]);
        if byte == 9 {
            assert_eq!(
                restored.credentials_json.as_deref().map(Vec::as_slice),
                Some(b"null".as_slice())
            );
            assert_eq!(
                restored.retry,
                RetryState {
                    failures: 0,
                    not_before_unix: 2_000_000_000
                }
            );
        } else {
            assert_eq!(
                restored.credentials_json.as_deref().map(Vec::as_slice),
                account(1).credentials_json.as_deref().map(Vec::as_slice)
            );
            assert_eq!(restored.retry, account(1).retry);
        }
    }
    Ok(())
}

#[test]
fn initializes_only_acme_tables_without_rewriting_account_records() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.redb");
    const SENTINEL: TableDefinition<&[u8], &[u8]> = TableDefinition::new("accounts");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    let database = Database::builder().create_file(file)?;
    let transaction = begin_write(&database)?;
    transaction
        .open_table(SENTINEL)?
        .insert(b"account".as_slice(), b"original".as_slice())?;
    transaction.commit()?;
    drop(database);
    let store = open(&path)?;
    block_on(store.save_account(account(1)))?;
    block_on(store.run(false, |inner| {
        let transaction = inner.database.begin_read().map_err(backend_error)?;
        let table = transaction.open_table(SENTINEL).map_err(backend_error)?;
        let value = table
            .get(b"account".as_slice())
            .map_err(backend_error)?
            .ok_or(StateError::CorruptData)?;
        assert_eq!(value.value(), b"original");
        Ok(())
    }))?;
    Ok(())
}

#[test]
fn exclusive_lock_rejects_another_process() -> TestResult {
    const CHILD_PATH: &str = "LONEWOLF_ACME_LOCK_TEST_PATH";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        assert!(matches!(
            open(Path::new(&path)),
            Err(StateError::Unavailable)
        ));
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.redb");
    let _store = open(&path)?;
    let result = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "store::tests::exclusive_lock_rejects_another_process",
        ])
        .env(CHILD_PATH, path)
        .output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    Ok(())
}
