// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::num::NonZeroUsize;

use ::redb::ReadableDatabase;
use futures_executor::block_on;
use lonewolf_auth::scram::{ScramCredentials, ScramHash, ScramVerifier};

use super::ACCOUNTS;
use crate::account::{AccountKey, AccountReads, AccountWrites, NewAccount};
use crate::redb::tests::storage;
use crate::tests::{
    TestResult, assert_scram, assert_storage_error, credentials, key, new_account, read, verifier,
    write,
};
use crate::{RedbStorage, Storage, StorageErrorKind};

const PAGE: NonZeroUsize = const { NonZeroUsize::new(1000).unwrap() };

fn insert_record(storage: &RedbStorage, key: &str, bytes: &[u8]) -> TestResult {
    let transaction = storage.as_ref().begin_write()?;
    transaction.open_table(ACCOUNTS)?.insert(key, bytes)?;
    transaction.commit()?;
    Ok(())
}

fn remove_record(storage: &RedbStorage, key: &str) -> TestResult {
    let transaction = storage.as_ref().begin_write()?;
    transaction.open_table(ACCOUNTS)?.remove(key)?;
    transaction.commit()?;
    Ok(())
}

fn stored_record(storage: &RedbStorage, key: &str) -> TestResult<Option<Vec<u8>>> {
    let transaction = storage.as_ref().begin_read()?;
    let table = transaction.open_table(ACCOUNTS)?;
    Ok(table.get(key)?.map(|record| record.value().to_vec()))
}

#[test]
fn malformed_records_fail_operations_and_stay_unchanged_when_the_transaction_is_dropped()
-> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let mut zero_iterations = [0; 86];
    zero_iterations[..2].copy_from_slice(&[1, 2]);
    for bytes in [&[][..], &[1], &[1, 0], &[1, 4], &[1, 2], &zero_iterations] {
        insert_record(&storage, alice.as_str(), bytes)?;
        block_on(async {
            let mut writer = storage.begin_write().await?;
            assert_storage_error(writer.account(&alice).await, StorageErrorKind::CorruptData);
            assert_storage_error(
                writer.scram(&alice, ScramHash::Sha256).await,
                StorageErrorKind::CorruptData,
            );
            assert_storage_error(
                writer.accounts_after(None, NonZeroUsize::MAX).await,
                StorageErrorKind::CorruptData,
            );
            assert_storage_error(
                writer.replace_credentials(&alice, credentials(20)).await,
                StorageErrorKind::CorruptData,
            );
            assert_storage_error(
                writer.delete_account(&alice).await,
                StorageErrorKind::CorruptData,
            );
            Ok::<(), Box<dyn Error>>(())
        })?;
        assert_eq!(
            stored_record(&storage, alice.as_str())?.as_deref(),
            Some(bytes)
        );
    }
    Ok(())
}

#[test]
fn unsupported_record_versions_are_distinct_from_missing_accounts() -> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    insert_record(&storage, alice.as_str(), &[2, 2])?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        assert_storage_error(
            writer.account(&alice).await,
            StorageErrorKind::UnsupportedVersion,
        );
        assert_storage_error(
            writer.scram(&alice, ScramHash::Sha256).await,
            StorageErrorKind::UnsupportedVersion,
        );
        assert_storage_error(
            writer.accounts_after(None, NonZeroUsize::MAX).await,
            StorageErrorKind::UnsupportedVersion,
        );
        assert_storage_error(
            writer.replace_credentials(&alice, credentials(20)).await,
            StorageErrorKind::UnsupportedVersion,
        );
        assert_storage_error(
            writer.delete_account(&alice).await,
            StorageErrorKind::UnsupportedVersion,
        );
        Ok::<(), Box<dyn Error>>(())
    })?;
    assert_eq!(
        stored_record(&storage, alice.as_str())?.as_deref(),
        Some(&[2, 2][..])
    );
    Ok(())
}

#[test]
fn truncated_and_extended_records_are_rejected_even_for_a_complete_first_hash() -> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(write(&storage, async |tx| tx.create_account(account).await))?;
    let mut bytes = stored_record(&storage, alice.as_str())?.ok_or("missing record")?;
    block_on(async {
        for len in 0..bytes.len() {
            insert_record(&storage, alice.as_str(), &bytes[..len])?;
            let reader = storage.begin_read().await?;
            assert_storage_error(
                reader.scram(&alice, ScramHash::Sha1).await,
                StorageErrorKind::CorruptData,
            );
        }
        bytes.push(0);
        insert_record(&storage, alice.as_str(), &bytes)?;
        let reader = storage.begin_read().await?;
        assert_storage_error(
            reader.scram(&alice, ScramHash::Sha1).await,
            StorageErrorKind::CorruptData,
        );
        Ok(())
    })
}

#[test]
fn legacy_iteration_account_can_be_reset_to_policy() -> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let account = NewAccount {
        key: alice.clone(),
        credentials: ScramCredentials::new(ScramVerifier::Sha256(verifier(10))),
    };
    block_on(write(&storage, async |tx| tx.create_account(account).await))?;
    let mut record = stored_record(&storage, alice.as_str())?.ok_or("missing record")?;
    record[18..22].copy_from_slice(&4096_u32.to_le_bytes());
    insert_record(&storage, alice.as_str(), &record)?;
    block_on(async {
        let reader = storage.begin_read().await?;
        assert!(reader.account(&alice).await?.is_some());
        let legacy = reader
            .scram(&alice, ScramHash::Sha256)
            .await?
            .ok_or("missing legacy verifier")?;
        assert_eq!(legacy.iterations().get(), 4096);
        drop(reader);

        write(&storage, async |tx| {
            tx.replace_credentials(
                &alice,
                ScramCredentials::new(ScramVerifier::Sha256(verifier(20))),
            )
            .await
        })
        .await?;
        assert_scram(
            read(&storage, async |tx| {
                tx.scram(&alice, ScramHash::Sha256).await
            })
            .await?,
            20,
        )?;
        Ok(())
    })
}

#[test]
fn accounts_after_rejects_invalid_or_noncanonical_stored_keys() -> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(write(&storage, async |tx| tx.create_account(account).await))?;
    let record = stored_record(&storage, alice.as_str())?.ok_or("missing record")?;
    let long_key = format!("{}@example.com", "a".repeat(2048));
    for invalid in [
        "",
        "example.com",
        "alice@example.com/desktop",
        "ALICE@example.com",
        "alice@EXAMPLE.COM",
        "alice@xn--bcher-kva.example",
        "alice@@example.com",
        "a b@example.com",
        &long_key,
    ] {
        insert_record(&storage, invalid, &record)?;
        block_on(async {
            let reader = storage.begin_read().await?;
            assert_storage_error(
                reader.accounts_after(None, NonZeroUsize::MAX).await,
                StorageErrorKind::CorruptData,
            );
            Ok::<(), Box<dyn Error>>(())
        })?;
        remove_record(&storage, invalid)?;
    }
    let page = block_on(read(&storage, async |tx| {
        tx.accounts_after(None, NonZeroUsize::MAX).await
    }))?;
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].key, alice);
    Ok(())
}

#[test]
fn scoped_ipv6_account_records_survive_reopening_without_aliasing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("accounts.redb");
    let pure = key("alice@[FE80::1]")?;
    let legacy_keys = [
        "alice@[fe80::1%eth0]",
        "alice@[fe80::1%25eth0]",
        "alice@[fe80::1%25eth%32]",
    ];
    let record = {
        let storage = RedbStorage::open(&path)?;
        let account = NewAccount {
            key: pure.clone(),
            credentials: credentials(10),
        };
        block_on(write(&storage, async |tx| tx.create_account(account).await))?;
        let record = stored_record(&storage, pure.as_str())?.ok_or("missing record")?;
        for legacy in legacy_keys {
            insert_record(&storage, legacy, &record)?;
        }
        record
    };
    let storage = RedbStorage::open(&path)?;
    block_on(async {
        let reader = storage.begin_read().await?;
        assert_eq!(
            reader
                .account(&pure)
                .await?
                .ok_or("missing pure account")?
                .key,
            pure
        );
        assert_storage_error(
            reader.accounts_after(None, NonZeroUsize::MAX).await,
            StorageErrorKind::CorruptData,
        );
        Ok::<(), Box<dyn Error>>(())
    })?;
    for stored in legacy_keys.into_iter().chain([pure.as_str()]) {
        assert_eq!(
            stored_record(&storage, stored)?.as_deref(),
            Some(record.as_slice())
        );
    }
    Ok(())
}

#[test]
fn a_page_that_ends_before_a_malformed_record_succeeds() -> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(write(&storage, async |tx| tx.create_account(account).await))?;
    insert_record(&storage, "bob@example.com", &[2, 2])?;
    block_on(async {
        let reader = storage.begin_read().await?;
        let first = reader.accounts_after(None, NonZeroUsize::MIN).await?;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].key, alice);
        assert_storage_error(
            reader.accounts_after(Some(&alice), NonZeroUsize::MIN).await,
            StorageErrorKind::UnsupportedVersion,
        );
        assert_storage_error(
            reader.accounts_after(None, NonZeroUsize::MAX).await,
            StorageErrorKind::UnsupportedVersion,
        );
        Ok(())
    })
}

#[test]
fn paging_through_many_long_keys_preserves_order_and_count() -> TestResult {
    let storage = storage()?;
    let source = key("source@example.com")?;
    let account = new_account("source@example.com", 10)?;
    block_on(write(&storage, async |tx| tx.create_account(account).await))?;
    let record = stored_record(&storage, source.as_str())?.ok_or("missing record")?;
    let transaction = storage.as_ref().begin_write()?;
    {
        let mut table = transaction.open_table(ACCOUNTS)?;
        table.remove(source.as_str())?;
        let suffix = "a".repeat(1019);
        for index in 0..10_000 {
            let account = key(&format!("{index:04}{suffix}@example.com"))?;
            table.insert(account.as_str(), record.as_slice())?;
        }
    }
    transaction.commit()?;

    block_on(async {
        let reader = storage.begin_read().await?;
        let mut cursor: Option<AccountKey> = None;
        let mut count = 0;
        loop {
            let mut page = reader.accounts_after(cursor.as_ref(), PAGE).await?;
            if page.is_empty() {
                break;
            }
            assert!(page.len() <= PAGE.get());
            for account in &page {
                assert_eq!(account.key.username().len(), 1023);
                assert_eq!(account.key.as_str()[..4].parse::<usize>()?, count);
                count += 1;
            }
            cursor = page.pop().map(|account| account.key);
        }
        assert_eq!(count, 10_000);
        Ok(())
    })
}
