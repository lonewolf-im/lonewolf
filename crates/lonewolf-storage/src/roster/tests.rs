// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use ::redb::ReadableDatabase;
use futures_executor::block_on;
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;

use super::redb::ITEMS;
use super::{RosterJid, RosterReads, RosterWrites};
use crate::redb::tests::storage;
use crate::tests::{TestResult, assert_storage_error, item, jid, key, read, write};
use crate::{RedbStorage, Storage, StorageErrorKind};

const ITEM_KEY: &str = "alice@example.com\0bob@example.com";

fn insert_item(storage: &RedbStorage, key: &str, bytes: &[u8]) -> TestResult {
    let transaction = storage.as_ref().begin_write()?;
    transaction.open_table(ITEMS)?.insert(key, bytes)?;
    transaction.commit()?;
    Ok(())
}

fn remove_item(storage: &RedbStorage, key: &str) -> TestResult {
    let transaction = storage.as_ref().begin_write()?;
    transaction.open_table(ITEMS)?.remove(key)?;
    transaction.commit()?;
    Ok(())
}

fn stored_item(storage: &RedbStorage, key: &str) -> TestResult<Option<Vec<u8>>> {
    let transaction = storage.as_ref().begin_read()?;
    let table = transaction.open_table(ITEMS)?;
    Ok(table.get(key)?.map(|record| record.value().to_vec()))
}

#[test]
fn roster_jids_are_owned_normalized_addresses() -> TestResult {
    let normalized = jid("É@BÜCHER.EXAMPLE")?;
    assert_eq!(normalized, jid("E\u{301}@xn--bcher-kva.example")?);
    assert_eq!(normalized.as_str(), "é@bücher.example");
    assert_eq!(format!("{normalized:?}"), "RosterJid { .. }");

    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let full = Jid::parse_in("alice@example.com/desktop", &mut arena)?;
    assert_eq!(
        RosterJid::from(full.resolve(&arena)?).as_str(),
        "alice@example.com/desktop"
    );
    assert_eq!(jid("example.com")?.as_str(), "example.com");
    Ok(())
}

#[test]
fn malformed_item_records_fail_operations_and_stay_unchanged_when_the_transaction_is_dropped()
-> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let bob = jid("bob@example.com")?;
    let update = item("bob@example.com", Some("Bob"), &[])?;
    for bytes in [
        &[][..],
        &[4, 0],
        &[0, 4],
        &[0, 0, 1, 0, 0, 0],
        &[0, 0, 1, 0, 0, 0, 0xff, 0, 0, 0, 0],
        &[0, 0, 255, 255, 255, 255, 1, 0, 0, 0],
        &[0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 1],
    ] {
        insert_item(&storage, ITEM_KEY, bytes)?;
        block_on(async {
            let mut writer = storage.begin_write().await?;
            assert_storage_error(writer.roster(&alice).await, StorageErrorKind::CorruptData);
            assert_storage_error(
                writer.roster_item(&alice, &bob).await,
                StorageErrorKind::CorruptData,
            );
            assert_storage_error(
                writer.upsert(&alice, update.clone()).await,
                StorageErrorKind::CorruptData,
            );
            assert_storage_error(
                writer.update_subscription(&alice, &bob, Some).await,
                StorageErrorKind::CorruptData,
            );
            assert_storage_error(
                writer.remove_roster_item(&alice, &bob).await,
                StorageErrorKind::CorruptData,
            );
            Ok::<(), Box<dyn Error>>(())
        })?;
        assert_eq!(stored_item(&storage, ITEM_KEY)?.as_deref(), Some(bytes));
    }
    Ok(())
}

#[test]
fn noncanonical_item_keys_are_rejected_when_reading_a_roster() -> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let update = item("bob@example.com", None, &[])?;
    block_on(write(&storage, async |tx| tx.upsert(&alice, update).await))?;
    let record = stored_item(&storage, ITEM_KEY)?.ok_or("missing item")?;
    for invalid in [
        "alice@example.com\0",
        "alice@example.com\0BOB@example.com",
        "alice@example.com\0bob@@example.com",
    ] {
        insert_item(&storage, invalid, &record)?;
        block_on(async {
            let reader = storage.begin_read().await?;
            assert_storage_error(reader.roster(&alice).await, StorageErrorKind::CorruptData);
            Ok::<(), Box<dyn Error>>(())
        })?;
        remove_item(&storage, invalid)?;
    }
    let snapshot = block_on(read(&storage, async |tx| tx.roster(&alice).await))?;
    assert_eq!(snapshot.items.len(), 1);
    Ok(())
}
