// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Barrier};
use std::thread;

use futures_executor::block_on;
use lonewolf_auth::scram::{ScramCredentials, ScramHash, ScramVerifier};
use lonewolf_storage::StorageErrorKind;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::account::{AccountError, AccountRepository, NewAccount};
use redb::{Database, ReadableDatabase};

#[path = "account_redb/support.rs"]
mod support;

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
    let first = RedbAccountRepository::from_database(Arc::clone(&database))?;
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
    let transaction = database.begin_write()?;
    transaction.open_table(METADATA)?.insert(SCHEMA_KEY, 2)?;
    transaction.open_table(ACCOUNTS)?;
    transaction.commit()?;

    match RedbAccountRepository::from_database(Arc::clone(&database)) {
        Err(error) => assert_eq!(error.kind(), StorageErrorKind::UnsupportedVersion),
        Ok(_) => return Err("accepted incompatible schema".into()),
    }
    let transaction = database.begin_read()?;
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
        let transaction = database.begin_write()?;
        if accounts_exist {
            transaction.open_table(ACCOUNTS)?;
        } else {
            transaction.open_table(METADATA)?.insert(SCHEMA_KEY, 1)?;
        }
        transaction.commit()?;
        match RedbAccountRepository::from_database(Arc::clone(&database)) {
            Err(error) => assert_eq!(error.kind(), StorageErrorKind::CorruptData),
            Ok(_) => return Err("accepted incomplete schema".into()),
        }
        assert_eq!(database.begin_read()?.list_tables()?.count(), 1);
    }
    Ok(())
}

#[test]
fn malformed_records_fail_reads_and_replacements_without_overwriting_data() -> TestResult {
    let database = database()?;
    let repository = RedbAccountRepository::from_database(Arc::clone(&database))?;
    let account = key("alice@example.com")?;
    let mut zero_iterations = [0; 86];
    zero_iterations[..2].copy_from_slice(&[1, 2]);
    for bytes in [&[][..], &[1], &[1, 0], &[1, 4], &[1, 2], &zero_iterations] {
        insert_record(&database, &account, bytes)?;
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
        assert_eq!(
            database
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
    let repository = RedbAccountRepository::from_database(Arc::clone(&database))?;
    let account = key("alice@example.com")?;
    insert_record(&database, &account, &[2, 2])?;
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
    Ok(())
}

#[test]
fn truncated_and_extended_records_are_rejected_even_for_a_complete_first_hash() -> TestResult {
    let database = database()?;
    let repository = RedbAccountRepository::from_database(Arc::clone(&database))?;
    let account = key("alice@example.com")?;
    block_on(repository.create(NewAccount {
        key: account.clone(),
        credentials: credentials(10),
    }))?;
    let mut bytes = database
        .begin_read()?
        .open_table(ACCOUNTS)?
        .get(account.as_str())?
        .ok_or("missing record")?
        .value()
        .to_vec();
    for len in 0..bytes.len() {
        insert_record(&database, &account, &bytes[..len])?;
        assert_storage_error(
            block_on(repository.get_scram(&account, ScramHash::Sha1)),
            StorageErrorKind::CorruptData,
        );
    }
    bytes.push(0);
    insert_record(&database, &account, &bytes)?;
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
        let repository = RedbAccountRepository::from_database(Arc::new(database))?;
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
    let repository = RedbAccountRepository::from_database(Arc::new(database))?;
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
