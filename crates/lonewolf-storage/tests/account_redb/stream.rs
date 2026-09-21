// SPDX-License-Identifier: Apache-2.0

use std::pin::pin;
use std::thread;

use futures_executor::block_on;
use futures_util::TryStreamExt;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::account::{AccountPageSize, AccountRepository, NewAccount};
use lonewolf_storage::{RedbDatabase, StorageErrorKind};
use redb::Database;

use super::support::*;

#[test]
fn stream_reads_only_when_a_page_is_needed_and_stays_off_the_callers_thread() -> TestResult {
    let backend = ObservedBackend::default();
    let database = Database::builder()
        .set_cache_size(0)
        .create_with_backend(backend.clone())?;
    let repository = RedbAccountRepository::from_database(RedbDatabase::new(database))?;
    for input in ["alice@example.com", "bob@example.com", "carol@example.com"] {
        block_on(repository.create(NewAccount {
            key: key(input)?,
            credentials: credentials(10),
        }))?;
    }
    backend.take_threads()?;
    let size = AccountPageSize::new(2).ok_or("invalid page size")?;
    let mut accounts = pin!(repository.stream(None, size));
    assert!(backend.take_threads()?.is_empty());
    assert_eq!(
        block_on(accounts.try_next())?.ok_or("missing account")?.key,
        key("alice@example.com")?
    );
    let threads = backend.take_threads()?;
    assert!(!threads.is_empty());
    assert!(threads.iter().all(|id| *id != thread::current().id()));
    assert_eq!(
        block_on(accounts.try_next())?.ok_or("missing account")?.key,
        key("bob@example.com")?
    );
    assert!(backend.take_threads()?.is_empty());
    assert_eq!(
        block_on(accounts.try_next())?.ok_or("missing account")?.key,
        key("carol@example.com")?
    );
    let threads = backend.take_threads()?;
    assert!(!threads.is_empty());
    assert!(threads.iter().all(|id| *id != thread::current().id()));
    for _ in 0..2 {
        assert!(block_on(accounts.try_next())?.is_none());
    }
    assert!(backend.take_threads()?.is_empty());
    Ok(())
}

#[test]
fn stream_releases_each_snapshot_and_continues_after_a_deleted_cursor() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    for input in ["alice@example.com", "bob@example.com", "dave@example.com"] {
        block_on(repository.create(NewAccount {
            key: key(input)?,
            credentials: credentials(10),
        }))?;
    }
    let size = AccountPageSize::new(1).ok_or("invalid page size")?;
    let mut accounts = pin!(repository.stream(Some(key("alice@example.com")?), size));
    let first = block_on(accounts.try_next())?.ok_or("missing account")?;
    assert_eq!(first.key, key("bob@example.com")?);
    block_on(repository.delete(&first.key))?;
    block_on(repository.create(NewAccount {
        key: key("carol@example.com")?,
        credentials: credentials(10),
    }))?;
    assert_eq!(
        block_on(accounts.try_next())?.ok_or("missing account")?.key,
        key("carol@example.com")?
    );
    assert_eq!(
        block_on(accounts.try_next())?.ok_or("missing account")?.key,
        key("dave@example.com")?
    );
    assert!(block_on(accounts.try_next())?.is_none());
    Ok(())
}

#[test]
fn stream_yields_a_later_page_error_once_and_then_ends() -> TestResult {
    let database = database()?;
    let repository = RedbAccountRepository::from_database(database.clone())?;
    block_on(repository.create(NewAccount {
        key: key("alice@example.com")?,
        credentials: credentials(10),
    }))?;
    insert_record(database.as_ref(), &key("bob@example.com")?, &[2, 2])?;
    let size = AccountPageSize::new(1).ok_or("invalid page size")?;
    let mut accounts = pin!(repository.stream(None, size));
    assert_eq!(
        block_on(accounts.try_next())?.ok_or("missing account")?.key,
        key("alice@example.com")?
    );
    assert_storage_error(
        block_on(accounts.try_next()),
        StorageErrorKind::UnsupportedVersion,
    );
    assert!(block_on(accounts.try_next())?.is_none());
    Ok(())
}

#[test]
fn dropping_a_partly_consumed_stream_does_not_read_another_page() -> TestResult {
    let backend = ObservedBackend::default();
    let database = Database::builder()
        .set_cache_size(0)
        .create_with_backend(backend.clone())?;
    let repository = RedbAccountRepository::from_database(RedbDatabase::new(database))?;
    for input in ["alice@example.com", "bob@example.com"] {
        block_on(repository.create(NewAccount {
            key: key(input)?,
            credentials: credentials(10),
        }))?;
    }
    let size = AccountPageSize::new(1).ok_or("invalid page size")?;
    {
        let mut accounts = pin!(repository.stream(None, size));
        assert!(block_on(accounts.try_next())?.is_some());
        backend.take_threads()?;
    }
    assert!(backend.take_threads()?.is_empty());
    Ok(())
}

#[test]
fn empty_stream_remains_exhausted() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    let size = AccountPageSize::new(1).ok_or("invalid page size")?;
    let mut accounts = pin!(repository.stream(None, size));
    assert!(block_on(accounts.try_next())?.is_none());
    assert!(block_on(accounts.try_next())?.is_none());
    Ok(())
}
