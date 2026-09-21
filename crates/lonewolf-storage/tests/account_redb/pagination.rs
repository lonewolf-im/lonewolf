// SPDX-License-Identifier: Apache-2.0

use std::pin::pin;

use futures_executor::block_on;
use futures_util::{StreamExt, TryStreamExt};
use lonewolf_storage::StorageErrorKind;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::account::{AccountRepository, NewAccount};
use redb::ReadableTable;

use super::support::*;

#[test]
fn caller_pagination_follows_canonical_key_order_without_skipping_lookahead() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    for input in [
        "bob@example.com",
        "É@BÜCHER.EXAMPLE",
        "alice@example.org",
        "ALICE@EXAMPLE.COM",
    ] {
        block_on(repository.create(NewAccount {
            key: key(input)?,
            credentials: credentials(10),
        }))?;
    }
    let first = block_on(repository.list(None).take(3).try_collect::<Vec<_>>())?;
    assert_eq!(first.len(), 3);
    assert_eq!(first[0].key, key("alice@example.com")?);
    assert_eq!(first[1].key, key("alice@example.org")?);
    assert_eq!(first[2].key, key("bob@example.com")?);

    let second = block_on(
        repository
            .list(Some(first[1].key.clone()))
            .take(3)
            .try_collect::<Vec<_>>(),
    )?;
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].key, first[2].key);
    assert_eq!(second[1].key, key("é@bücher.example")?);
    let end = block_on(
        repository
            .list(Some(second[1].key.clone()))
            .try_collect::<Vec<_>>(),
    )?;
    assert!(end.is_empty());
    Ok(())
}

#[test]
fn listing_ends_for_empty_and_single_account_stores() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    let empty = block_on(repository.list(None).try_collect::<Vec<_>>())?;
    assert!(empty.is_empty());

    block_on(repository.create(NewAccount {
        key: key("alice@example.com")?,
        credentials: credentials(10),
    }))?;
    let accounts = block_on(repository.list(None).try_collect::<Vec<_>>())?;
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].key, key("alice@example.com")?);
    Ok(())
}

#[test]
fn pagination_resumes_after_deleted_and_absent_keys() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    for input in ["alice@example.com", "carol@example.com", "erin@example.com"] {
        block_on(repository.create(NewAccount {
            key: key(input)?,
            credentials: credentials(10),
        }))?;
    }
    let first = block_on(repository.list(None).take(1).try_collect::<Vec<_>>())?;
    assert_eq!(first.len(), 1);
    let cursor = &first[0].key;
    block_on(repository.delete(cursor))?;
    for input in ["aaron@example.com", "bob@example.com"] {
        block_on(repository.create(NewAccount {
            key: key(input)?,
            credentials: credentials(10),
        }))?;
    }
    let second = block_on(
        repository
            .list(Some(cursor.clone()))
            .try_collect::<Vec<_>>(),
    )?;
    assert_eq!(second.len(), 3);
    assert_eq!(second[0].key, key("bob@example.com")?);
    assert_eq!(second[1].key, key("carol@example.com")?);
    assert_eq!(second[2].key, key("erin@example.com")?);

    let between = key("dan@example.com")?;
    let accounts = block_on(repository.list(Some(between)).try_collect::<Vec<_>>())?;
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].key, key("erin@example.com")?);
    Ok(())
}

#[test]
fn stopping_listing_does_not_decode_later_records() -> TestResult {
    let database = database()?;
    let repository = RedbAccountRepository::from_database(database.clone())?;
    block_on(repository.create(NewAccount {
        key: key("alice@example.com")?,
        credentials: credentials(10),
    }))?;
    insert_record(database.as_ref(), &key("bob@example.com")?, &[2, 2])?;
    let first = block_on(repository.list(None).take(1).try_collect::<Vec<_>>())?;
    assert_eq!(first.len(), 1);
    assert_storage_error(
        block_on(
            repository
                .list(Some(first[0].key.clone()))
                .try_collect::<Vec<_>>(),
        ),
        StorageErrorKind::UnsupportedVersion,
    );
    Ok(())
}

#[test]
fn listing_rejects_invalid_or_noncanonical_stored_keys() -> TestResult {
    let database = database()?;
    let repository = RedbAccountRepository::from_database(database.clone())?;
    let valid = key("alice@example.com")?;
    block_on(repository.create(NewAccount {
        key: valid.clone(),
        credentials: credentials(10),
    }))?;
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
        let transaction = database.as_ref().begin_write()?;
        {
            let mut table = transaction.open_table(ACCOUNTS)?;
            let record = table
                .get(valid.as_str())?
                .ok_or("missing record")?
                .value()
                .to_vec();
            table.insert(invalid, record.as_slice())?;
        }
        transaction.commit()?;
        assert_storage_error(
            block_on(repository.list(None).try_collect::<Vec<_>>()),
            StorageErrorKind::CorruptData,
        );
        let transaction = database.as_ref().begin_write()?;
        transaction.open_table(ACCOUNTS)?.remove(invalid)?;
        transaction.commit()?;
    }
    Ok(())
}

#[test]
fn long_scans_do_not_accumulate_key_decoding_scratch_memory() -> TestResult {
    let database = database()?;
    let repository = RedbAccountRepository::from_database(database.clone())?;
    let source = key("source@example.com")?;
    block_on(repository.create(NewAccount {
        key: source.clone(),
        credentials: credentials(10),
    }))?;
    let transaction = database.as_ref().begin_write()?;
    {
        let mut table = transaction.open_table(ACCOUNTS)?;
        let record = table
            .remove(source.as_str())?
            .ok_or("missing record")?
            .value()
            .to_vec();
        let suffix = "a".repeat(1019);
        for index in 0..10_000 {
            let account = key(&format!("{index:04}{suffix}@example.com"))?;
            table.insert(account.as_str(), record.as_slice())?;
        }
    }
    transaction.commit()?;
    let mut accounts = pin!(repository.list(None));
    let mut count = 0;
    while let Some(account) = block_on(accounts.try_next())? {
        assert_eq!(account.key.username().len(), 1023);
        assert_eq!(account.key.as_str()[..4].parse::<usize>()?, count);
        count += 1;
    }
    assert_eq!(count, 10_000);
    Ok(())
}
