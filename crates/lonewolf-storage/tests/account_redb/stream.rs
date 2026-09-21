// SPDX-License-Identifier: Apache-2.0

use std::pin::pin;
use std::thread;

use futures_executor::block_on;
use futures_util::TryStreamExt;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::account::{AccountRepository, NewAccount};
use lonewolf_storage::{RedbDatabase, StorageErrorKind};
use redb::Database;

use super::support::*;

#[test]
fn stream_reads_on_demand_and_stays_off_the_callers_thread() -> TestResult {
    let backend = ObservedBackend::default();
    let database = Database::builder()
        .set_cache_size(0)
        .create_with_backend(backend.clone())?;
    let repository = RedbAccountRepository::from_database(RedbDatabase::new(database))?;
    let suffix = "a".repeat(1019);
    for index in 0..32 {
        block_on(repository.create(NewAccount {
            key: key(&format!("{index:04}{suffix}@example.com"))?,
            credentials: credentials(10),
        }))?;
    }
    backend.take_threads()?;
    let mut accounts = pin!(repository.list(None));
    assert!(backend.take_threads()?.is_empty());
    let mut reads = 0;
    for index in 0..32 {
        let account = block_on(accounts.try_next())?.ok_or("missing account")?;
        assert_eq!(account.key.as_str()[..4].parse::<usize>()?, index);
        let threads = backend.take_threads()?;
        reads += usize::from(!threads.is_empty());
        assert!(threads.iter().all(|id| *id != thread::current().id()));
    }
    assert!(reads > 1);
    assert!(block_on(accounts.try_next())?.is_none());
    assert!(
        backend
            .take_threads()?
            .iter()
            .all(|id| *id != thread::current().id())
    );
    assert!(block_on(accounts.try_next())?.is_none());
    assert!(backend.take_threads()?.is_empty());
    Ok(())
}

#[test]
fn stream_keeps_one_snapshot_while_writes_continue() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    for input in ["alice@example.com", "bob@example.com", "dave@example.com"] {
        block_on(repository.create(NewAccount {
            key: key(input)?,
            credentials: credentials(10),
        }))?;
    }
    let mut accounts = pin!(repository.list(Some(key("alice@example.com")?)));
    let first = block_on(accounts.try_next())?.ok_or("missing account")?;
    assert_eq!(first.key, key("bob@example.com")?);
    block_on(repository.delete(&first.key))?;
    block_on(repository.delete(&key("dave@example.com")?))?;
    block_on(repository.create(NewAccount {
        key: key("carol@example.com")?,
        credentials: credentials(10),
    }))?;
    assert_eq!(
        block_on(accounts.try_next())?.ok_or("missing account")?.key,
        key("dave@example.com")?
    );
    assert!(block_on(accounts.try_next())?.is_none());
    let current = block_on(repository.list(Some(first.key)).try_collect::<Vec<_>>())?;
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].key, key("carol@example.com")?);
    Ok(())
}

#[test]
fn stream_yields_a_later_record_error_once_and_then_ends() -> TestResult {
    let database = database()?;
    let repository = RedbAccountRepository::from_database(database.clone())?;
    block_on(repository.create(NewAccount {
        key: key("alice@example.com")?,
        credentials: credentials(10),
    }))?;
    insert_record(database.as_ref(), &key("bob@example.com")?, &[2, 2])?;
    let mut accounts = pin!(repository.list(None));
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
fn dropping_a_partly_consumed_stream_does_not_read_another_record() -> TestResult {
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
    {
        let mut accounts = pin!(repository.list(None));
        assert!(block_on(accounts.try_next())?.is_some());
        backend.take_threads()?;
    }
    assert!(backend.take_threads()?.is_empty());
    Ok(())
}

#[test]
fn empty_stream_remains_exhausted() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    let mut accounts = pin!(repository.list(None));
    assert!(block_on(accounts.try_next())?.is_none());
    assert!(block_on(accounts.try_next())?.is_none());
    Ok(())
}

#[test]
fn stream_opens_its_snapshot_on_the_first_read() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    let mut accounts = pin!(repository.list(None));
    block_on(repository.create(NewAccount {
        key: key("alice@example.com")?,
        credentials: credentials(10),
    }))?;
    assert_eq!(
        block_on(accounts.try_next())?.ok_or("missing account")?.key,
        key("alice@example.com")?
    );
    assert!(block_on(accounts.try_next())?.is_none());
    Ok(())
}
