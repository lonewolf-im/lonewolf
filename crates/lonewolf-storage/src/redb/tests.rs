// SPDX-License-Identifier: Apache-2.0

mod backend;

use std::error::Error;
use std::fs;
use std::num::NonZeroUsize;
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;
use std::thread;

use ::redb::backends::InMemoryBackend;
use ::redb::{
    Database, ReadableDatabase, ReadableTableMetadata, StorageBackend, TableDefinition, TableHandle,
};
use futures_executor::block_on;
use lonewolf_auth::scram::{ScramCredentials, ScramHash, ScramVerifier};

use self::backend::{FailingSyncBackend, ObservedBackend};
use super::initialize;
use crate::account::redb::{ACCOUNTS, DECOY_SECRET, DECOY_SECRET_KEY};
use crate::account::{AccountReads, AccountWrites};
use crate::offline::OfflineReads;
use crate::offline::redb::{MESSAGES, SEQUENCES};
use crate::roster::redb::{ITEMS, PENDING, VERSIONS};
use crate::roster::{RosterReads, RosterSubscription, RosterWrites, SubscriptionState};
use crate::tests::{
    TIMEOUT, TestResult, assert_scram, assert_storage_error, assert_verifier, credentials,
    decoy_salt, item, item_with_subscription, jid, key, new_account, pending, poll, read, verifier,
    write,
};
use crate::{RedbStorage, Storage, StorageErrorKind, WriteTransaction};

const METADATA: TableDefinition<&str, u32> = TableDefinition::new("lonewolf_metadata");

pub(crate) fn storage() -> TestResult<RedbStorage> {
    Ok(RedbStorage::new(database(
        InMemoryBackend::new(),
        1024 * 1024,
    )?)?)
}

fn database(
    backend: impl StorageBackend,
    cache_size: usize,
) -> Result<Database, ::redb::DatabaseError> {
    Database::builder()
        .set_cache_size(cache_size)
        .create_with_backend(backend)
}

fn assert_worker_threads(backend: &ObservedBackend) -> TestResult {
    let threads = backend.take_threads()?;
    assert!(!threads.is_empty());
    assert!(threads.iter().all(|id| *id != thread::current().id()));
    Ok(())
}

crate::tests::storage_contract_tests!(storage);

#[test]
fn fresh_database_initializes_all_tables() -> TestResult {
    let database = database(InMemoryBackend::new(), 1024 * 1024)?;
    assert_eq!(database.begin_read()?.list_tables()?.count(), 0);

    let storage = RedbStorage::new(database)?;
    let transaction = storage.as_ref().begin_read()?;
    let tables: Vec<_> = transaction.list_tables()?.collect();
    assert_eq!(tables.len(), 7);
    for expected in [
        ACCOUNTS.name(),
        DECOY_SECRET.name(),
        ITEMS.name(),
        PENDING.name(),
        VERSIONS.name(),
        MESSAGES.name(),
        SEQUENCES.name(),
    ] {
        assert!(
            tables.iter().any(|table| table.name() == expected),
            "missing table {expected}"
        );
    }
    assert_eq!(
        transaction
            .open_table(DECOY_SECRET)?
            .get(DECOY_SECRET_KEY)?
            .ok_or("missing decoy secret")?
            .value()
            .len(),
        32
    );
    Ok(())
}

#[test]
fn unknown_tables_are_left_untouched() -> TestResult {
    let storage = storage()?;
    let before = decoy_salt(storage.scram_decoy())?;
    let transaction = storage.as_ref().begin_write()?;
    transaction
        .open_table(METADATA)?
        .insert("accounts_schema", 1)?;
    transaction.commit()?;

    let reinitialized = initialize(storage.as_ref())?;
    assert_eq!(decoy_salt(&reinitialized)?, before);
    let transaction = storage.as_ref().begin_read()?;
    assert_eq!(transaction.list_tables()?.count(), 8);
    assert_eq!(
        transaction
            .open_table(METADATA)?
            .get("accounts_schema")?
            .ok_or("missing metadata")?
            .value(),
        1
    );
    Ok(())
}

#[test]
fn existing_database_gains_offline_tables_without_changing_accounts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("storage.redb");
    let storage = RedbStorage::open(&path)?;
    let owner = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    let decoy = decoy_salt(storage.scram_decoy())?;
    block_on(write(&storage, async |tx| tx.create_account(account).await))?;
    let transaction = storage.as_ref().begin_write()?;
    assert!(transaction.delete_table(MESSAGES)?);
    assert!(transaction.delete_table(SEQUENCES)?);
    transaction.commit()?;
    drop(storage);

    let storage = RedbStorage::open(&path)?;
    assert_eq!(decoy_salt(storage.scram_decoy())?, decoy);
    block_on(async {
        let reader = storage.begin_read().await?;
        assert!(reader.account(&owner).await?.is_some());
        assert_scram(reader.scram(&owner, ScramHash::Sha1).await?, 10)?;
        assert_scram(reader.scram(&owner, ScramHash::Sha256).await?, 13)?;
        assert!(reader.offline_messages(&owner).await?.is_empty());
        assert_eq!(reader.offline_count(&owner).await?, 0);
        Ok::<_, Box<dyn Error>>(())
    })?;
    let reader = storage.as_ref().begin_read()?;
    assert_eq!(reader.list_tables()?.count(), 7);
    reader.open_table(MESSAGES)?;
    reader.open_table(SEQUENCES)?;
    Ok(())
}

#[test]
fn missing_decoy_table_is_rejected_for_an_empty_account_store() -> TestResult {
    let database = database(InMemoryBackend::new(), 1024 * 1024)?;
    let transaction = database.begin_write()?;
    transaction.open_table(ACCOUNTS)?;
    transaction.commit()?;

    assert_storage_error(initialize(&database), StorageErrorKind::CorruptData);
    let transaction = database.begin_read()?;
    assert_eq!(transaction.list_tables()?.count(), 1);
    assert!(transaction.open_table(ACCOUNTS)?.is_empty()?);
    drop(transaction);
    assert_storage_error(RedbStorage::new(database), StorageErrorKind::CorruptData);
    Ok(())
}

#[test]
fn missing_decoy_table_with_accounts_is_rejected() -> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(write(&storage, async |tx| tx.create_account(account).await))?;
    let transaction = storage.as_ref().begin_write()?;
    transaction.delete_table(DECOY_SECRET)?;
    transaction.commit()?;

    assert_storage_error(initialize(storage.as_ref()), StorageErrorKind::CorruptData);
    let transaction = storage.as_ref().begin_read()?;
    assert!(
        !transaction
            .list_tables()?
            .any(|table| table.name() == DECOY_SECRET.name())
    );
    drop(transaction);
    assert!(block_on(read(&storage, async |tx| tx.account(&alice).await))?.is_some());
    Ok(())
}

#[test]
fn missing_accounts_table_with_decoy_secret_is_rejected() -> TestResult {
    let storage = storage()?;
    let transaction = storage.as_ref().begin_write()?;
    transaction.delete_table(ACCOUNTS)?;
    transaction.commit()?;

    assert_storage_error(initialize(storage.as_ref()), StorageErrorKind::CorruptData);
    let transaction = storage.as_ref().begin_read()?;
    assert!(
        !transaction
            .list_tables()?
            .any(|table| table.name() == ACCOUNTS.name())
    );
    assert!(
        transaction
            .open_table(DECOY_SECRET)?
            .get(DECOY_SECRET_KEY)?
            .is_some()
    );
    Ok(())
}

#[test]
fn missing_or_invalid_persisted_decoy_secret_is_not_replaced() -> TestResult {
    for value in [None, Some(&[7][..]), Some(&[9; 32][..])] {
        let storage = storage()?;
        let transaction = storage.as_ref().begin_write()?;
        {
            let mut table = transaction.open_table(DECOY_SECRET)?;
            match value {
                Some(bytes) => {
                    table.insert(DECOY_SECRET_KEY, bytes)?;
                }
                None => {
                    table.remove(DECOY_SECRET_KEY)?;
                }
            }
            if value.is_some_and(|bytes| bytes.len() == 32) {
                table.insert("extra", &[1][..])?;
            }
        }
        transaction.commit()?;

        assert_storage_error(initialize(storage.as_ref()), StorageErrorKind::CorruptData);
        let transaction = storage.as_ref().begin_read()?;
        let table = transaction.open_table(DECOY_SECRET)?;
        assert_eq!(
            table
                .get(DECOY_SECRET_KEY)?
                .map(|stored| stored.value().to_vec()),
            value.map(<[u8]>::to_vec)
        );
    }
    Ok(())
}

#[test]
fn decoy_secret_survives_reopening_and_differs_between_databases() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lonewolf.redb");
    let initial = decoy_salt(RedbStorage::open(&path)?.scram_decoy())?;
    assert_eq!(
        decoy_salt(RedbStorage::open(&path)?.scram_decoy())?,
        initial
    );
    assert_ne!(
        decoy_salt(RedbStorage::open(directory.path().join("other.redb"))?.scram_decoy())?,
        initial
    );
    Ok(())
}

#[test]
fn committed_state_survives_reopening() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lonewolf.redb");
    let alice = key("alice@example.com")?;
    let other = key("alice@example.org")?;
    let deleted = key("deleted@example.com")?;
    let bob = item_with_subscription(
        "bob@example.com",
        Some("Bob"),
        &["Friends"],
        RosterSubscription {
            state: SubscriptionState::Both,
            pending_out: false,
            approved: true,
        },
    )?;
    let request = pending("bob@example.com", b"<presence/>")?;
    {
        let storage = RedbStorage::open(&path)?;
        block_on(async {
            let mut writer = storage.begin_write().await?;
            for input in [
                "alice@example.com",
                "alice@example.org",
                "deleted@example.com",
            ] {
                writer.create_account(new_account(input, 10)?).await?;
            }
            writer
                .replace_credentials(
                    &alice,
                    ScramCredentials::new(ScramVerifier::Sha256(verifier(20))),
                )
                .await?;
            writer.delete_account(&deleted).await?;
            writer.put_roster_item(&alice, &bob).await?;
            writer
                .put_pending_request(&alice, request.clone(), std::num::NonZeroUsize::MAX)
                .await?;
            writer.commit().await?;
            Ok::<(), Box<dyn Error>>(())
        })?;
    }

    let storage = RedbStorage::open(&path)?;
    block_on(async {
        let reader = storage.begin_read().await?;
        assert_eq!(
            reader.account(&alice).await?.ok_or("missing account")?.key,
            alice
        );
        assert!(reader.scram(&alice, ScramHash::Sha1).await?.is_none());
        assert_scram(reader.scram(&alice, ScramHash::Sha256).await?, 20)?;
        assert!(reader.account(&deleted).await?.is_none());
        for hash in [ScramHash::Sha1, ScramHash::Sha256] {
            assert!(reader.scram(&deleted, hash).await?.is_none());
            assert!(reader.scram(&other, hash).await?.is_some());
        }
        let snapshot = reader.roster(&alice).await?;
        assert_eq!(snapshot.version.get(), 1);
        assert_eq!(snapshot.items, [bob]);
        assert_eq!(reader.pending_requests(&alice).await?, [request]);
        Ok(())
    })
}

#[test]
fn opening_a_locked_database_reports_unavailable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lonewolf.redb");
    let _storage = RedbStorage::open(&path)?;
    assert_storage_error(RedbStorage::open(&path), StorageErrorKind::Unavailable);
    Ok(())
}

#[test]
fn new_database_files_are_private_to_the_owner() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lonewolf.redb");
    let _storage = RedbStorage::open(&path)?;
    assert_eq!(fs::metadata(path)?.permissions().mode() & 0o077, 0);
    Ok(())
}

#[test]
fn commit_failure_reports_unknown_outcome_and_recovers_a_complete_record() -> TestResult {
    let backend = FailingSyncBackend::default();
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    {
        let storage = RedbStorage::new(database(backend.clone(), 1024 * 1024)?)?;
        block_on(async {
            write(&storage, async |tx| tx.create_account(account).await).await?;
            let mut writer = storage.begin_write().await?;
            writer.replace_credentials(&alice, credentials(20)).await?;
            backend.fail_next_sync();
            assert_storage_error(writer.commit().await, StorageErrorKind::CommitUnknown);
            Ok::<(), Box<dyn Error>>(())
        })?;
    }

    let storage = RedbStorage::new(database(backend, 1024 * 1024)?)?;
    block_on(async {
        let reader = storage.begin_read().await?;
        let Some(ScramVerifier::Sha1(value)) = reader.scram(&alice, ScramHash::Sha1).await? else {
            return Err("lost account during failed commit".into());
        };
        let marker = value.salt()[0];
        assert!(matches!(marker, 10 | 20));
        assert_verifier(&value, marker);
        assert_scram(reader.scram(&alice, ScramHash::Sha256).await?, marker + 3)?;
        Ok(())
    })
}

#[test]
fn failed_deletion_commit_recovers_either_the_complete_account_or_its_absence() -> TestResult {
    let backend = FailingSyncBackend::default();
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    {
        let storage = RedbStorage::new(database(backend.clone(), 1024 * 1024)?)?;
        block_on(async {
            write(&storage, async |tx| tx.create_account(account).await).await?;
            let mut writer = storage.begin_write().await?;
            writer.delete_account(&alice).await?;
            backend.fail_next_sync();
            assert_storage_error(writer.commit().await, StorageErrorKind::CommitUnknown);
            Ok::<(), Box<dyn Error>>(())
        })?;
    }

    let storage = RedbStorage::new(database(backend, 1024 * 1024)?)?;
    block_on(async {
        let reader = storage.begin_read().await?;
        if reader.account(&alice).await?.is_some() {
            assert_scram(reader.scram(&alice, ScramHash::Sha1).await?, 10)?;
            assert_scram(reader.scram(&alice, ScramHash::Sha256).await?, 13)?;
        } else {
            for hash in [ScramHash::Sha1, ScramHash::Sha256] {
                assert!(reader.scram(&alice, hash).await?.is_none());
            }
        }
        Ok(())
    })
}

#[test]
fn all_operations_do_database_io_off_the_callers_thread() -> TestResult {
    let backend = ObservedBackend::default();
    let storage = RedbStorage::new(database(backend.clone(), 0)?)?;
    let alice = key("alice@example.com")?;
    let bob = jid("bob@example.com")?;
    backend.take_threads()?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        assert_worker_threads(&backend)?;
        assert!(writer.account(&alice).await?.is_some());
        assert_worker_threads(&backend)?;
        assert_scram(writer.scram(&alice, ScramHash::Sha256).await?, 13)?;
        assert_worker_threads(&backend)?;
        writer.replace_credentials(&alice, credentials(20)).await?;
        assert_worker_threads(&backend)?;
        assert_eq!(
            writer.accounts_after(None, NonZeroUsize::MAX).await?.len(),
            1
        );
        assert_worker_threads(&backend)?;
        writer
            .put_roster_item(&alice, &item("bob@example.com", None, &[])?)
            .await?;
        assert_worker_threads(&backend)?;
        writer
            .put_pending_request(
                &alice,
                pending("bob@example.com", b"<presence/>")?,
                std::num::NonZeroUsize::MAX,
            )
            .await?;
        assert_worker_threads(&backend)?;
        assert_eq!(writer.roster(&alice).await?.items.len(), 1);
        assert_worker_threads(&backend)?;
        assert!(writer.roster_item(&alice, &bob).await?.is_some());
        assert_worker_threads(&backend)?;
        assert_eq!(writer.pending_requests(&alice).await?.len(), 1);
        assert_worker_threads(&backend)?;
        assert!(writer.pending_request(&alice, &bob).await?.is_some());
        assert_worker_threads(&backend)?;
        writer.commit().await?;
        assert_worker_threads(&backend)?;

        let reader = storage.begin_read().await?;
        assert!(reader.account(&alice).await?.is_some());
        assert_worker_threads(&backend)?;
        assert_scram(reader.scram(&alice, ScramHash::Sha256).await?, 23)?;
        assert_worker_threads(&backend)?;
        assert_eq!(
            reader.accounts_after(None, NonZeroUsize::MAX).await?.len(),
            1
        );
        assert_worker_threads(&backend)?;
        assert_eq!(reader.roster(&alice).await?.items.len(), 1);
        assert_worker_threads(&backend)?;
        assert!(reader.roster_item(&alice, &bob).await?.is_some());
        assert_worker_threads(&backend)?;
        assert_eq!(reader.pending_requests(&alice).await?.len(), 1);
        assert_worker_threads(&backend)?;
        assert!(reader.pending_request(&alice, &bob).await?.is_some());
        assert_worker_threads(&backend)?;
        drop(reader);

        let mut writer = storage.begin_write().await?;
        assert!(writer.remove_pending_request(&alice, &bob).await?);
        assert_worker_threads(&backend)?;
        assert!(writer.remove_roster_item(&alice, &bob).await?.is_some());
        assert_worker_threads(&backend)?;
        writer.clear_roster(&alice).await?;
        assert_worker_threads(&backend)?;
        writer.delete_account(&alice).await?;
        assert_worker_threads(&backend)?;
        writer.commit().await?;
        assert_worker_threads(&backend)?;
        Ok(())
    })
}

#[test]
fn full_read_capacity_does_not_block_a_writer() -> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(async {
        let reader = storage.begin_read().await?;
        let mut blocked = Vec::with_capacity(32);
        for _ in 0..32 {
            let (entered, started) = mpsc::channel();
            let (release, gate) = mpsc::channel();
            let mut operation = Box::pin(reader.run(move |_| {
                let _ = entered.send(());
                gate.recv_timeout(TIMEOUT)
            }));
            assert!(poll(operation.as_mut()).is_pending());
            started.recv_timeout(TIMEOUT)?;
            blocked.push((operation, release));
        }
        let mut waiting = Box::pin(reader.run(|_| 42));
        assert!(poll(waiting.as_mut()).is_pending());

        write(&storage, async |tx| tx.create_account(account).await).await?;

        for (operation, release) in blocked {
            release.send(())?;
            operation.await?;
        }
        assert_eq!(waiting.await, 42);
        assert!(reader.account(&alice).await?.is_none());
        Ok(())
    })
}

#[test]
fn a_committing_writer_and_queued_writers_do_not_block_reads() -> TestResult {
    let backend = ObservedBackend::default();
    let storage = RedbStorage::new(database(backend.clone(), 1024 * 1024)?)?;
    let existing = key("existing@example.com")?;
    let new = key("new@example.com")?;
    let existing_account = new_account("existing@example.com", 10)?;
    let new_account = new_account("new@example.com", 20)?;
    block_on(async {
        write(&storage, async |tx| {
            tx.create_account(existing_account).await
        })
        .await?;
        let mut writer = storage.begin_write().await?;
        writer.create_account(new_account).await?;
        let (entered, release) = backend.block_next_sync()?;
        let mut commit = Box::pin(writer.commit());
        assert!(poll(commit.as_mut()).is_pending());
        entered.recv_timeout(TIMEOUT)?;

        let mut waiting = Vec::with_capacity(32);
        for _ in 0..32 {
            let mut queued = Box::pin(storage.begin_write());
            assert!(poll(queued.as_mut()).is_pending());
            waiting.push(queued);
        }
        let reader = storage.begin_read().await?;
        assert!(reader.account(&existing).await?.is_some());
        assert_scram(reader.scram(&existing, ScramHash::Sha256).await?, 13)?;
        assert!(reader.account(&new).await?.is_none());
        drop(reader);

        release.send(())?;
        commit.await?;
        for queued in waiting {
            let mut writer = queued.await?;
            writer
                .replace_credentials(&existing, credentials(30))
                .await?;
            writer.commit().await?;
        }
        let reader = storage.begin_read().await?;
        assert!(reader.account(&new).await?.is_some());
        assert_scram(reader.scram(&existing, ScramHash::Sha256).await?, 33)?;
        Ok(())
    })
}

#[test]
fn a_blocked_writer_does_not_block_writes_to_another_database() -> TestResult {
    let backend = ObservedBackend::default();
    let storage = RedbStorage::new(database(backend.clone(), 1024 * 1024)?)?;
    let independent = self::storage()?;
    let account = new_account("alice@example.com", 10)?;
    let other = new_account("alice@example.com", 20)?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer.create_account(account).await?;
        let (entered, release) = backend.block_next_sync()?;
        let mut commit = Box::pin(writer.commit());
        assert!(poll(commit.as_mut()).is_pending());
        entered.recv_timeout(TIMEOUT)?;

        write(&independent, async |tx| tx.create_account(other).await).await?;
        release.send(())?;
        commit.await?;
        Ok(())
    })
}

#[test]
fn cancelling_a_submitted_commit_still_persists_the_write() -> TestResult {
    let backend = ObservedBackend::default();
    let storage = RedbStorage::new(database(backend.clone(), 1024 * 1024)?)?;
    let alice = key("alice@example.com")?;
    let next = key("next@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    let next_account = new_account("next@example.com", 20)?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer.create_account(account).await?;
        let (entered, release) = backend.block_next_sync()?;
        let mut commit = Box::pin(writer.commit());
        assert!(poll(commit.as_mut()).is_pending());
        entered.recv_timeout(TIMEOUT)?;
        drop(commit);
        release.send(())?;

        write(&storage, async |tx| tx.create_account(next_account).await).await?;
        let reader = storage.begin_read().await?;
        assert_scram(reader.scram(&alice, ScramHash::Sha256).await?, 13)?;
        assert!(reader.account(&next).await?.is_some());
        Ok(())
    })
}

#[test]
fn commit_fails_while_a_cancelled_operation_still_holds_the_transaction() -> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(async {
        let writer = storage.begin_write().await?;
        let (entered, started) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let mut blocked = Box::pin(writer.run(move |_| {
            let _ = entered.send(());
            gate.recv_timeout(TIMEOUT)
        }));
        assert!(poll(blocked.as_mut()).is_pending());
        started.recv_timeout(TIMEOUT)?;
        drop(blocked);

        assert_storage_error(writer.commit().await, StorageErrorKind::Other);
        release.send(())?;
        write(&storage, async |tx| tx.create_account(account).await).await?;
        assert!(
            read(&storage, async |tx| tx.account(&alice).await)
                .await?
                .is_some()
        );
        Ok(())
    })
}

#[test]
fn pending_limit_serializes_simultaneous_writers() -> TestResult {
    let storage = storage()?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer.commit().await?;
        TestResult::Ok(())
    })?;
    let barrier = std::sync::Barrier::new(2);
    thread::scope(|scope| -> TestResult {
        let mut writers = Vec::new();
        for sender in ["bob@example.com", "carol@example.com"] {
            let storage = storage.clone();
            let barrier = &barrier;
            writers.push(scope.spawn(move || -> Result<bool, String> {
                let alice = key("alice@example.com").map_err(|error| error.to_string())?;
                let request = pending(sender, b"request").map_err(|error| error.to_string())?;
                barrier.wait();
                block_on(async {
                    let mut writer = storage
                        .begin_write()
                        .await
                        .map_err(|error| error.to_string())?;
                    match writer
                        .put_pending_request(&alice, request, NonZeroUsize::MIN)
                        .await
                    {
                        Ok(()) => {
                            writer.commit().await.map_err(|error| error.to_string())?;
                            Ok(true)
                        }
                        Err(crate::roster::RosterError::PendingLimitExceeded) => Ok(false),
                        Err(error) => Err(error.to_string()),
                    }
                })
            }));
        }
        let admitted = writers
            .into_iter()
            .map(|writer| writer.join().map_err(|_| "writer panicked")?)
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(admitted.iter().filter(|admitted| **admitted).count(), 1);
        Ok(())
    })?;
    block_on(async {
        assert_eq!(
            storage
                .begin_read()
                .await?
                .pending_requests(&key("alice@example.com")?)
                .await?
                .len(),
            1
        );
        TestResult::Ok(())
    })?;
    Ok(())
}

#[test]
fn reopened_pending_queue_preserves_rows_above_a_lower_limit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("pending.redb");
    let alice = key("alice@example.com")?;
    {
        let storage = RedbStorage::open(&path)?;
        block_on(async {
            let mut writer = storage.begin_write().await?;
            writer
                .create_account(new_account("alice@example.com", 10)?)
                .await?;
            for sender in ["bob@example.com", "carol@example.com", "dave@example.com"] {
                writer
                    .put_pending_request(
                        &alice,
                        pending(sender, sender.as_bytes())?,
                        NonZeroUsize::MAX,
                    )
                    .await?;
            }
            writer.commit().await?;
            TestResult::Ok(())
        })?;
    }
    let storage = RedbStorage::open(&path)?;
    block_on(async {
        let cap = NonZeroUsize::new(2).ok_or("invalid cap")?;
        let mut writer = storage.begin_write().await?;
        assert_eq!(writer.pending_requests(&alice).await?.len(), 3);
        writer
            .put_pending_request(&alice, pending("bob@example.com", b"updated")?, cap)
            .await?;
        assert!(matches!(
            writer
                .put_pending_request(&alice, pending("erin@example.com", b"new")?, cap)
                .await,
            Err(crate::roster::RosterError::PendingLimitExceeded)
        ));
        assert_eq!(
            writer.pending_requests(&alice).await?,
            [
                pending("bob@example.com", b"updated")?,
                pending("carol@example.com", b"carol@example.com")?,
                pending("dave@example.com", b"dave@example.com")?
            ]
        );
        writer
            .remove_pending_request(&alice, &jid("bob@example.com")?)
            .await?;
        assert!(matches!(
            writer
                .put_pending_request(&alice, pending("erin@example.com", b"new")?, cap)
                .await,
            Err(crate::roster::RosterError::PendingLimitExceeded)
        ));
        writer
            .remove_pending_request(&alice, &jid("carol@example.com")?)
            .await?;
        writer
            .put_pending_request(&alice, pending("erin@example.com", b"new")?, cap)
            .await?;
        writer.commit().await?;
        assert_eq!(
            storage.begin_read().await?.pending_requests(&alice).await?,
            [
                pending("dave@example.com", b"dave@example.com")?,
                pending("erin@example.com", b"new")?
            ]
        );
        TestResult::Ok(())
    })
}
