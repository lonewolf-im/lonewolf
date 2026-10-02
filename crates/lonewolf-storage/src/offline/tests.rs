// SPDX-License-Identifier: Apache-2.0

use ::redb::ReadableDatabase;
use futures_executor::block_on;

use super::redb::{MESSAGES, SEQUENCES};
use super::{OfflineError, OfflineReads, OfflineSequence, OfflineWrites, StoredMessage};
use crate::account::AccountWrites;
use crate::redb::tests::storage;
use crate::tests::{TestResult, assert_storage_error, key, new_account, read, write};
use crate::{RedbStorage, Storage, StorageErrorKind, WriteTransaction};

#[test]
fn stored_message_debug_omits_stanza_bytes() {
    let message = StoredMessage {
        sequence: OfflineSequence::new(1),
        stored_at: 100,
        stanza: Box::from(&b"private message"[..]),
    };
    assert_eq!(
        format!("{message:?}"),
        "StoredMessage { sequence: OfflineSequence(1), stored_at: 100, .. }"
    );
}

#[test]
fn stored_record_uses_a_big_endian_timestamp_followed_by_opaque_stanza_bytes() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    let stored_at = 0x0102_0304_0506_0708;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .push_offline_message(&owner, stored_at, b"opaque\0\xff")
            .await?;
        writer.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    let reader = storage.as_ref().begin_read()?;
    let table = reader.open_table(MESSAGES)?;
    let record = table.get((owner.as_str(), 1))?.ok_or("missing message")?;
    assert_eq!(
        record.value(),
        b"\x01\x02\x03\x04\x05\x06\x07\x08opaque\0\xff"
    );
    assert_eq!(
        reader
            .open_table(SEQUENCES)?
            .get(owner.as_str())?
            .ok_or("missing sequence")?
            .value(),
        1
    );
    Ok(())
}

#[test]
fn sequence_overflow_writes_neither_a_message_nor_a_counter_change() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(write(&storage, async |tx| tx.create_account(account).await))?;
    let transaction = storage.as_ref().begin_write()?;
    transaction
        .open_table(SEQUENCES)?
        .insert(owner.as_str(), u64::MAX)?;
    transaction.commit()?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        assert!(matches!(
            writer
                .push_offline_message(&owner, 100, b"<message/>")
                .await,
            Err(OfflineError::ValueTooLarge)
        ));
        assert_eq!(writer.offline_count(&owner).await?, 0);
        writer.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    let reader = storage.as_ref().begin_read()?;
    assert_eq!(
        reader
            .open_table(SEQUENCES)?
            .get(owner.as_str())?
            .ok_or("missing sequence")?
            .value(),
        u64::MAX
    );
    assert!(
        reader
            .open_table(MESSAGES)?
            .get((owner.as_str(), 0))?
            .is_none()
    );
    Ok(())
}

#[test]
fn offline_messages_and_empty_queue_counters_survive_reopening() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("offline.redb");
    let storage = RedbStorage::open(&path)?;
    let alice = key("alice@example.com")?;
    let bob = key("bob@example.com")?;
    let stanza = vec![0xff; 64 * 1024].into_boxed_slice();
    block_on(async {
        let mut writer = storage.begin_write().await?;
        for owner in ["alice@example.com", "bob@example.com"] {
            writer.create_account(new_account(owner, 10)?).await?;
        }
        writer.push_offline_message(&alice, 100, &stanza).await?;
        writer.push_offline_message(&alice, 110, b"second").await?;
        let sequence = writer.push_offline_message(&bob, 100, b"removed").await?;
        writer.remove_offline_message(&bob, sequence).await?;
        writer.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    drop(storage);

    let storage = RedbStorage::open(&path)?;
    block_on(async {
        let reader = storage.begin_read().await?;
        let messages = reader.offline_messages(&alice).await?;
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].sequence.get(), 1);
        assert_eq!(messages[0].stored_at, 100);
        assert_eq!(messages[0].stanza, stanza);
        assert_eq!(messages[1].sequence.get(), 2);
        assert_eq!(messages[1].stored_at, 110);
        assert_eq!(messages[1].stanza.as_ref(), b"second");
        assert_eq!(reader.offline_count(&bob).await?, 0);
        assert_eq!(
            write(&storage, async |tx| tx
                .push_offline_message(&bob, 120, b"new")
                .await)
            .await?
            .get(),
            2
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn missing_owner_does_not_create_a_sequence_counter() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        assert!(matches!(
            writer
                .push_offline_message(&owner, 100, b"<message/>")
                .await,
            Err(OfflineError::NoAccount)
        ));
        writer.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    let reader = storage.as_ref().begin_read()?;
    assert!(reader.open_table(SEQUENCES)?.get(owner.as_str())?.is_none());
    assert!(
        reader
            .open_table(MESSAGES)?
            .get((owner.as_str(), 1))?
            .is_none()
    );
    Ok(())
}

#[test]
fn truncated_timestamps_fail_reads_without_changing_records() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    for length in 0..size_of::<u64>() {
        let bytes = &[0; size_of::<u64>()][..length];
        let transaction = storage.as_ref().begin_write()?;
        transaction
            .open_table(MESSAGES)?
            .insert((owner.as_str(), 1), bytes)?;
        transaction.commit()?;
        block_on(async {
            assert_storage_error(
                read(&storage, async |tx| tx.offline_messages(&owner).await).await,
                StorageErrorKind::CorruptData,
            );
            let writer = storage.begin_write().await?;
            assert_storage_error(
                writer.offline_messages(&owner).await,
                StorageErrorKind::CorruptData,
            );
            assert_eq!(writer.offline_count(&owner).await?, 1);
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        let reader = storage.as_ref().begin_read()?;
        let table = reader.open_table(MESSAGES)?;
        assert_eq!(
            table
                .get((owner.as_str(), 1))?
                .ok_or("missing record")?
                .value(),
            bytes
        );
    }
    Ok(())
}
