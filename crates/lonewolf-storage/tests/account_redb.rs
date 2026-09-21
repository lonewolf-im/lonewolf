// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::sync::Barrier;
use std::task::{Context, Waker};
use std::thread;
use std::time::Duration;

use futures_executor::block_on;
use futures_util::TryStreamExt;
use lonewolf_auth::scram::{ScramCredentials, ScramHash, ScramVerifier};
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::account::{AccountError, AccountPageSize, AccountRepository, NewAccount};
use lonewolf_storage::{RedbDatabase, StorageErrorKind};
use redb::{Database, ReadableDatabase};

#[path = "account_redb/support.rs"]
mod support;

#[path = "account_redb/pagination.rs"]
mod pagination;

#[path = "account_redb/deletion.rs"]
mod deletion;

#[path = "account_redb/stream.rs"]
mod stream;

use support::*;

#[test]
fn accounts_and_all_verifier_fields_survive_reopening() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("accounts.redb");
    let account = key("alice@example.com")?;
    {
        let repository = RedbAccountRepository::open(&path)?;
        block_on(repository.create(NewAccount {
            key: account.clone(),
            credentials: credentials(10),
        }))?;
    }

    let repository = RedbAccountRepository::open(&path)?;
    assert_eq!(
        block_on(repository.get(&account))?
            .ok_or("missing account")?
            .key,
        account
    );
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha1))?,
        10,
    )?;
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha256))?,
        13,
    )?;
    Ok(())
}

#[test]
fn absent_accounts_and_absent_hashes_return_none() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    let account = key("alice@example.com")?;
    assert!(block_on(repository.get(&account))?.is_none());
    for hash in [ScramHash::Sha1, ScramHash::Sha256] {
        assert!(block_on(repository.get_scram(&account, hash))?.is_none());
    }

    for (present, absent) in [
        (ScramVerifier::Sha1(verifier(10)), ScramHash::Sha256),
        (ScramVerifier::Sha256(verifier(20)), ScramHash::Sha1),
    ] {
        let account = key(match absent {
            ScramHash::Sha1 => "sha256@example.com",
            ScramHash::Sha256 => "sha1@example.com",
        })?;
        let hash = present.hash();
        block_on(repository.create(NewAccount {
            key: account.clone(),
            credentials: ScramCredentials::new(present),
        }))?;
        assert!(block_on(repository.get(&account))?.is_some());
        assert!(block_on(repository.get_scram(&account, absent))?.is_none());
        assert_eq!(
            block_on(repository.get_scram(&account, hash))?
                .ok_or("missing verifier")?
                .hash(),
            hash
        );
    }
    Ok(())
}

#[test]
fn normalized_duplicate_does_not_replace_existing_credentials() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    block_on(repository.create(NewAccount {
        key: key("É@BÜCHER.EXAMPLE")?,
        credentials: credentials(10),
    }))?;
    let account = key("E\u{301}@xn--bcher-kva.example")?;
    assert!(matches!(
        block_on(repository.create(NewAccount {
            key: account.clone(),
            credentials: credentials(20),
        })),
        Err(AccountError::AlreadyExists)
    ));
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha1))?,
        10,
    )?;
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha256))?,
        13,
    )?;
    Ok(())
}

#[test]
fn usernames_and_domains_are_independent_storage_keys() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    for (input, marker) in [
        ("alice@example.com", 10),
        ("bob@example.com", 20),
        ("alice@example.org", 30),
    ] {
        block_on(repository.create(NewAccount {
            key: key(input)?,
            credentials: credentials(marker),
        }))?;
    }
    for (input, marker) in [
        ("alice@example.com", 10),
        ("bob@example.com", 20),
        ("alice@example.org", 30),
    ] {
        assert_scram(
            block_on(repository.get_scram(&key(input)?, ScramHash::Sha256))?,
            marker + 3,
        )?;
    }
    Ok(())
}

#[test]
fn replacement_removes_omitted_hashes_and_survives_reopening() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("accounts.redb");
    let account = key("alice@example.com")?;
    {
        let repository = RedbAccountRepository::open(&path)?;
        block_on(repository.create(NewAccount {
            key: account.clone(),
            credentials: credentials(10),
        }))?;
        block_on(repository.replace_credentials(
            &account,
            ScramCredentials::new(ScramVerifier::Sha256(verifier(20))),
        ))?;
    }
    let repository = RedbAccountRepository::open(&path)?;
    assert!(block_on(repository.get_scram(&account, ScramHash::Sha1))?.is_none());
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha256))?,
        20,
    )?;
    Ok(())
}

#[test]
fn replacement_does_not_create_an_account() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    let account = key("alice@example.com")?;
    assert!(matches!(
        block_on(repository.replace_credentials(&account, credentials(10))),
        Err(AccountError::NotFound)
    ));
    assert!(block_on(repository.get(&account))?.is_none());
    Ok(())
}

#[test]
fn concurrent_creation_has_one_winner_without_overwriting_credentials() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    let account = key("alice@example.com")?;
    let barrier = Barrier::new(2);
    let (first, second) = thread::scope(|scope| {
        let create = |marker| {
            barrier.wait();
            block_on(repository.create(NewAccount {
                key: account.clone(),
                credentials: credentials(marker),
            }))
        };
        let first = scope.spawn(move || create(10));
        let second = create(20);
        (first.join(), second)
    });
    let first = first.map_err(|_| "account creation thread panicked")?;
    let marker = match (first, second) {
        (Ok(()), Err(AccountError::AlreadyExists)) => 10,
        (Err(AccountError::AlreadyExists), Ok(())) => 20,
        _ => return Err("expected exactly one successful create".into()),
    };
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha1))?,
        marker,
    )?;
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha256))?,
        marker + 3,
    )?;
    Ok(())
}

#[test]
fn repositories_can_share_one_database() -> TestResult {
    let database = database()?;
    let first = RedbAccountRepository::from_database(database.clone())?;
    let second = RedbAccountRepository::from_database(database)?;
    let account = key("alice@example.com")?;
    block_on(first.create(NewAccount {
        key: account.clone(),
        credentials: credentials(10),
    }))?;
    block_on(second.replace_credentials(&account, credentials(20)))?;
    assert_scram(block_on(first.get_scram(&account, ScramHash::Sha256))?, 23)?;
    Ok(())
}

#[test]
fn opening_a_locked_database_reports_unavailable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("accounts.redb");
    let _repository = RedbAccountRepository::open(&path)?;
    match RedbAccountRepository::open(&path) {
        Err(error) => assert_eq!(error.kind(), StorageErrorKind::Unavailable),
        Ok(_) => return Err("opened database without exclusive ownership".into()),
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn new_database_files_are_private_to_the_owner() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("accounts.redb");
    let _repository = RedbAccountRepository::open(&path)?;
    assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o077, 0);
    Ok(())
}

#[test]
fn incompatible_schema_is_rejected_without_modifying_it() -> TestResult {
    let database = database()?;
    let transaction = database.as_ref().begin_write()?;
    transaction.open_table(METADATA)?.insert(SCHEMA_KEY, 2)?;
    transaction.open_table(ACCOUNTS)?;
    transaction.commit()?;

    match RedbAccountRepository::from_database(database.clone()) {
        Err(error) => assert_eq!(error.kind(), StorageErrorKind::UnsupportedVersion),
        Ok(_) => return Err("accepted incompatible schema".into()),
    }
    let transaction = database.as_ref().begin_read()?;
    assert_eq!(
        transaction
            .open_table(METADATA)?
            .get(SCHEMA_KEY)?
            .ok_or("missing schema")?
            .value(),
        2
    );
    Ok(())
}

#[test]
fn incomplete_schema_is_rejected_without_recreating_tables() -> TestResult {
    for accounts_exist in [false, true] {
        let database = database()?;
        let transaction = database.as_ref().begin_write()?;
        if accounts_exist {
            transaction.open_table(ACCOUNTS)?;
        } else {
            transaction.open_table(METADATA)?.insert(SCHEMA_KEY, 1)?;
        }
        transaction.commit()?;
        match RedbAccountRepository::from_database(database.clone()) {
            Err(error) => assert_eq!(error.kind(), StorageErrorKind::CorruptData),
            Ok(_) => return Err("accepted incomplete schema".into()),
        }
        assert_eq!(database.as_ref().begin_read()?.list_tables()?.count(), 1);
    }
    Ok(())
}

#[test]
fn malformed_records_fail_operations_without_modifying_data() -> TestResult {
    let database = database()?;
    let repository = RedbAccountRepository::from_database(database.clone())?;
    let account = key("alice@example.com")?;
    let size = AccountPageSize::new(1).ok_or("invalid page size")?;
    let mut zero_iterations = [0; 86];
    zero_iterations[..2].copy_from_slice(&[1, 2]);
    for bytes in [&[][..], &[1], &[1, 0], &[1, 4], &[1, 2], &zero_iterations] {
        insert_record(database.as_ref(), &account, bytes)?;
        assert_storage_error(
            block_on(repository.get(&account)),
            StorageErrorKind::CorruptData,
        );
        assert_storage_error(
            block_on(repository.get_scram(&account, ScramHash::Sha256)),
            StorageErrorKind::CorruptData,
        );
        assert_storage_error(
            block_on(repository.replace_credentials(&account, credentials(20))),
            StorageErrorKind::CorruptData,
        );
        assert_storage_error(
            block_on(repository.list(None, size).try_collect::<Vec<_>>()),
            StorageErrorKind::CorruptData,
        );
        assert_storage_error(
            block_on(repository.delete(&account)),
            StorageErrorKind::CorruptData,
        );
        assert_eq!(
            database
                .as_ref()
                .begin_read()?
                .open_table(ACCOUNTS)?
                .get(account.as_str())?
                .ok_or("missing record")?
                .value(),
            bytes
        );
    }
    Ok(())
}

#[test]
fn unsupported_record_versions_are_distinct_from_missing_accounts() -> TestResult {
    let database = database()?;
    let repository = RedbAccountRepository::from_database(database.clone())?;
    let account = key("alice@example.com")?;
    let size = AccountPageSize::new(1).ok_or("invalid page size")?;
    insert_record(database.as_ref(), &account, &[2, 2])?;
    assert_storage_error(
        block_on(repository.get(&account)),
        StorageErrorKind::UnsupportedVersion,
    );
    assert_storage_error(
        block_on(repository.get_scram(&account, ScramHash::Sha256)),
        StorageErrorKind::UnsupportedVersion,
    );
    assert_storage_error(
        block_on(repository.replace_credentials(&account, credentials(20))),
        StorageErrorKind::UnsupportedVersion,
    );
    assert_storage_error(
        block_on(repository.list(None, size).try_collect::<Vec<_>>()),
        StorageErrorKind::UnsupportedVersion,
    );
    assert_storage_error(
        block_on(repository.delete(&account)),
        StorageErrorKind::UnsupportedVersion,
    );
    assert_eq!(
        database
            .as_ref()
            .begin_read()?
            .open_table(ACCOUNTS)?
            .get(account.as_str())?
            .ok_or("missing record")?
            .value(),
        &[2, 2]
    );
    Ok(())
}

#[test]
fn truncated_and_extended_records_are_rejected_even_for_a_complete_first_hash() -> TestResult {
    let database = database()?;
    let repository = RedbAccountRepository::from_database(database.clone())?;
    let account = key("alice@example.com")?;
    block_on(repository.create(NewAccount {
        key: account.clone(),
        credentials: credentials(10),
    }))?;
    let mut bytes = database
        .as_ref()
        .begin_read()?
        .open_table(ACCOUNTS)?
        .get(account.as_str())?
        .ok_or("missing record")?
        .value()
        .to_vec();
    for len in 0..bytes.len() {
        insert_record(database.as_ref(), &account, &bytes[..len])?;
        assert_storage_error(
            block_on(repository.get_scram(&account, ScramHash::Sha1)),
            StorageErrorKind::CorruptData,
        );
    }
    bytes.push(0);
    insert_record(database.as_ref(), &account, &bytes)?;
    assert_storage_error(
        block_on(repository.get_scram(&account, ScramHash::Sha1)),
        StorageErrorKind::CorruptData,
    );
    Ok(())
}

#[test]
fn commit_failure_reports_unknown_outcome_and_recovers_a_complete_record() -> TestResult {
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
            block_on(repository.replace_credentials(&account, credentials(20))),
            StorageErrorKind::CommitUnknown,
        );
    }
    let database = Database::builder()
        .set_cache_size(1024 * 1024)
        .create_with_backend(backend)?;
    let repository = RedbAccountRepository::from_database(RedbDatabase::new(database))?;
    let Some(ScramVerifier::Sha1(value)) =
        block_on(repository.get_scram(&account, ScramHash::Sha1))?
    else {
        return Err("lost account during failed commit".into());
    };
    let marker = value.salt()[0];
    assert!(matches!(marker, 10 | 20));
    assert_verifier(&value, marker);
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha256))?,
        marker + 3,
    )?;
    Ok(())
}

#[test]
fn all_account_operations_do_database_io_off_the_callers_thread() -> TestResult {
    let backend = ObservedBackend::default();
    let database = Database::builder()
        .set_cache_size(0)
        .create_with_backend(backend.clone())?;
    let repository = RedbAccountRepository::from_database(RedbDatabase::new(database))?;
    let account = key("alice@example.com")?;
    backend.take_threads()?;

    block_on(repository.create(NewAccount {
        key: account.clone(),
        credentials: credentials(10),
    }))?;
    assert_worker_threads(&backend)?;
    assert!(block_on(repository.get(&account))?.is_some());
    assert_worker_threads(&backend)?;
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha256))?,
        13,
    )?;
    assert_worker_threads(&backend)?;
    block_on(repository.replace_credentials(&account, credentials(20)))?;
    assert_worker_threads(&backend)?;
    let size = AccountPageSize::new(1).ok_or("invalid page size")?;
    let accounts = block_on(repository.list(None, size).try_collect::<Vec<_>>())?;
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].key, account);
    assert_worker_threads(&backend)?;
    block_on(repository.delete(&account))?;
    assert_worker_threads(&backend)?;
    Ok(())
}

#[test]
fn queued_writers_from_a_shared_repository_do_not_block_reads() -> TestResult {
    let backend = ObservedBackend::default();
    let database = Database::builder()
        .set_cache_size(1024 * 1024)
        .create_with_backend(backend.clone())?;
    let database = RedbDatabase::new(database);
    let repository = RedbAccountRepository::from_database(database.clone())?;
    let shared = RedbAccountRepository::from_database(database)?;
    let existing = key("existing@example.com")?;
    let new = key("new@example.com")?;
    block_on(repository.create(NewAccount {
        key: existing.clone(),
        credentials: credentials(10),
    }))?;
    let (entered, release) = backend.block_next_sync()?;
    let mut write = Box::pin(repository.create(NewAccount {
        key: new.clone(),
        credentials: credentials(20),
    }));
    assert!(
        write
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    entered.recv_timeout(Duration::from_secs(5))?;

    let mut waiting = Vec::with_capacity(32);
    for _ in 0..32 {
        let mut queued = Box::pin(shared.replace_credentials(&existing, credentials(30)));
        assert!(
            queued
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        waiting.push(queued);
    }
    assert!(block_on(repository.get(&existing))?.is_some());
    assert_scram(
        block_on(repository.get_scram(&existing, ScramHash::Sha256))?,
        13,
    )?;
    assert!(block_on(repository.get(&new))?.is_none());
    release.send(())?;
    block_on(write)?;
    for queued in waiting {
        block_on(queued)?;
    }
    assert!(block_on(repository.get(&new))?.is_some());
    Ok(())
}

#[test]
fn a_blocked_writer_does_not_block_writes_to_another_database() -> TestResult {
    let backend = ObservedBackend::default();
    let database = Database::builder()
        .set_cache_size(1024 * 1024)
        .create_with_backend(backend.clone())?;
    let repository = RedbAccountRepository::from_database(RedbDatabase::new(database))?;
    let independent = RedbAccountRepository::from_database(support::database()?)?;
    let account = key("alice@example.com")?;
    let (entered, release) = backend.block_next_sync()?;
    let mut write = Box::pin(repository.create(NewAccount {
        key: account.clone(),
        credentials: credentials(10),
    }));
    assert!(
        write
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    entered.recv_timeout(Duration::from_secs(5))?;

    block_on(independent.create(NewAccount {
        key: account,
        credentials: credentials(20),
    }))?;
    release.send(())?;
    block_on(write)?;
    Ok(())
}

#[test]
fn cancelling_a_started_write_does_not_abort_its_commit() -> TestResult {
    let backend = ObservedBackend::default();
    let database = Database::builder()
        .set_cache_size(1024 * 1024)
        .create_with_backend(backend.clone())?;
    let repository = RedbAccountRepository::from_database(RedbDatabase::new(database))?;
    let account = key("alice@example.com")?;
    let (entered, release) = backend.block_next_sync()?;
    let mut write = Box::pin(repository.create(NewAccount {
        key: account.clone(),
        credentials: credentials(10),
    }));
    assert!(
        write
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    entered.recv_timeout(Duration::from_secs(5))?;
    drop(write);
    release.send(())?;

    block_on(repository.create(NewAccount {
        key: key("next@example.com")?,
        credentials: credentials(20),
    }))?;
    assert_scram(
        block_on(repository.get_scram(&account, ScramHash::Sha256))?,
        13,
    )?;
    Ok(())
}

fn assert_worker_threads(backend: &ObservedBackend) -> TestResult {
    let threads = backend.take_threads()?;
    assert!(!threads.is_empty());
    assert!(threads.iter().all(|id| *id != thread::current().id()));
    Ok(())
}
