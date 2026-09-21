// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::sync::Barrier;
use std::task::{Context, Waker};
use std::thread;
use std::time::Duration;

use futures_executor::block_on;
use lonewolf_auth::scram::ScramHash;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::account::{AccountError, AccountRepository, NewAccount};
use lonewolf_storage::{RedbDatabase, StorageErrorKind};
use redb::Database;

use super::support::*;

#[test]
fn deletion_removes_all_credentials_and_survives_reopening() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("accounts.redb");
    let account = key("alice@example.com")?;
    let other = key("alice@example.org")?;
    {
        let repository = RedbAccountRepository::open(&path)?;
        for account in [&account, &other] {
            block_on(repository.create(NewAccount {
                key: account.clone(),
                credentials: credentials(10),
            }))?;
        }
        block_on(repository.delete(&key("ALICE@EXAMPLE.COM")?))?;
        assert!(matches!(
            block_on(repository.delete(&account)),
            Err(AccountError::NotFound)
        ));
    }
    let repository = RedbAccountRepository::open(&path)?;
    assert!(block_on(repository.get(&account))?.is_none());
    for hash in [ScramHash::Sha1, ScramHash::Sha256] {
        assert!(block_on(repository.get_scram(&account, hash))?.is_none());
        assert!(block_on(repository.get_scram(&other, hash))?.is_some());
    }
    assert!(matches!(
        block_on(repository.replace_credentials(&account, credentials(20))),
        Err(AccountError::NotFound)
    ));
    block_on(repository.create(NewAccount {
        key: account.clone(),
        credentials: credentials(20),
    }))?;
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha1))?,
        20,
    )?;
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha256))?,
        23,
    )?;
    Ok(())
}

#[test]
fn concurrent_deletion_has_one_successful_removal() -> TestResult {
    let database = database()?;
    let first = RedbAccountRepository::from_database(database.clone())?;
    let second = RedbAccountRepository::from_database(database)?;
    let account = key("alice@example.com")?;
    block_on(first.create(NewAccount {
        key: account.clone(),
        credentials: credentials(10),
    }))?;
    let barrier = Barrier::new(2);
    let (left, right) = thread::scope(|scope| {
        let left = scope.spawn(|| {
            barrier.wait();
            block_on(first.delete(&account))
        });
        barrier.wait();
        let right = block_on(second.delete(&account));
        (left.join(), right)
    });
    let left = left.map_err(|_| "account deletion thread panicked")?;
    assert!(matches!(
        (left, right),
        (Ok(()), Err(AccountError::NotFound)) | (Err(AccountError::NotFound), Ok(()))
    ));
    assert!(block_on(first.get(&account))?.is_none());
    Ok(())
}

#[test]
fn deletion_keeps_read_snapshots_available_and_serializes_credential_replacement() -> TestResult {
    let backend = ObservedBackend::default();
    let database = Database::builder()
        .set_cache_size(1024 * 1024)
        .create_with_backend(backend.clone())?;
    let repository = RedbAccountRepository::from_database(RedbDatabase::new(database))?;
    let account = key("alice@example.com")?;
    block_on(repository.create(NewAccount {
        key: account.clone(),
        credentials: credentials(10),
    }))?;
    let (entered, release) = backend.block_next_sync()?;
    let mut deletion = Box::pin(repository.delete(&account));
    assert!(
        deletion
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    entered.recv_timeout(Duration::from_secs(5))?;
    let mut replacement = Box::pin(repository.replace_credentials(&account, credentials(20)));
    assert!(
        replacement
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha256))?,
        13,
    )?;
    release.send(())?;
    block_on(deletion)?;
    assert!(matches!(block_on(replacement), Err(AccountError::NotFound)));
    assert!(block_on(repository.get(&account))?.is_none());
    Ok(())
}

#[test]
fn cancelling_started_deletion_preserves_writer_admission_until_commit() -> TestResult {
    let backend = ObservedBackend::default();
    let database = Database::builder()
        .set_cache_size(1024 * 1024)
        .create_with_backend(backend.clone())?;
    let repository = RedbAccountRepository::from_database(RedbDatabase::new(database))?;
    let account = key("alice@example.com")?;
    block_on(repository.create(NewAccount {
        key: account.clone(),
        credentials: credentials(10),
    }))?;
    let (entered, release) = backend.block_next_sync()?;
    let mut deletion = Box::pin(repository.delete(&account));
    assert!(
        deletion
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    entered.recv_timeout(Duration::from_secs(5))?;
    drop(deletion);

    let mut creation = Box::pin(repository.create(NewAccount {
        key: account.clone(),
        credentials: credentials(20),
    }));
    assert!(
        creation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    release.send(())?;
    block_on(creation)?;
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha1))?,
        20,
    )?;
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha256))?,
        23,
    )?;
    Ok(())
}

#[test]
fn failed_deletion_commit_recovers_either_the_complete_account_or_its_absence() -> TestResult {
    let backend = FailingSyncBackend::default();
    let account = key("alice@example.com")?;
    {
        let database = Database::builder()
            .set_cache_size(1024 * 1024)
            .create_with_backend(backend.clone())?;
        let repository = RedbAccountRepository::from_database(RedbDatabase::new(database))?;
        block_on(repository.create(NewAccount {
            key: account.clone(),
            credentials: credentials(10),
        }))?;
        backend.fail_next_sync();
        assert_storage_error(
            block_on(repository.delete(&account)),
            StorageErrorKind::CommitUnknown,
        );
    }
    let database = Database::builder()
        .set_cache_size(1024 * 1024)
        .create_with_backend(backend)?;
    let repository = RedbAccountRepository::from_database(RedbDatabase::new(database))?;
    if block_on(repository.get(&account))?.is_some() {
        assert_scram(
            block_on(repository.get_scram(&account, ScramHash::Sha1))?,
            10,
        )?;
        assert_scram(
            block_on(repository.get_scram(&account, ScramHash::Sha256))?,
            13,
        )?;
    } else {
        for hash in [ScramHash::Sha1, ScramHash::Sha256] {
            assert!(block_on(repository.get_scram(&account, hash))?.is_none());
        }
    }
    Ok(())
}
