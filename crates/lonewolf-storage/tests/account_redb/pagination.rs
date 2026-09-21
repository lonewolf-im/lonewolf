// SPDX-License-Identifier: Apache-2.0

use futures_executor::block_on;
use lonewolf_storage::StorageErrorKind;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::account::{AccountPageSize, AccountRepository, NewAccount};
use redb::ReadableTable;

use super::support::*;

#[test]
fn pages_follow_canonical_key_order_across_domains() -> TestResult {
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
    let size = AccountPageSize::new(2).ok_or("invalid page size")?;
    let first = block_on(repository.list(None, size))?;
    assert_eq!(first.accounts.len(), 2);
    assert_eq!(first.accounts[0].key, key("alice@example.com")?);
    assert_eq!(first.accounts[1].key, key("alice@example.org")?);
    assert!(first.has_more);

    let second = block_on(repository.list(Some(&first.accounts[1].key), size))?;
    assert_eq!(second.accounts.len(), 2);
    assert_eq!(second.accounts[0].key, key("bob@example.com")?);
    assert_eq!(second.accounts[1].key, key("é@bücher.example")?);
    assert!(!second.has_more);
    let end = block_on(repository.list(Some(&second.accounts[1].key), size))?;
    assert!(end.accounts.is_empty());
    assert!(!end.has_more);
    Ok(())
}

#[test]
fn empty_and_partial_pages_do_not_claim_more_accounts() -> TestResult {
    let repository = RedbAccountRepository::from_database(database()?)?;
    let size = AccountPageSize::new(2).ok_or("invalid page size")?;
    let empty = block_on(repository.list(None, size))?;
    assert!(empty.accounts.is_empty());
    assert!(!empty.has_more);

    block_on(repository.create(NewAccount {
        key: key("alice@example.com")?,
        credentials: credentials(10),
    }))?;
    let page = block_on(repository.list(None, size))?;
    assert_eq!(page.accounts.len(), 1);
    assert_eq!(page.accounts[0].key, key("alice@example.com")?);
    assert!(!page.has_more);
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
    let size = AccountPageSize::new(1).ok_or("invalid page size")?;
    let first = block_on(repository.list(None, size))?;
    assert_eq!(first.accounts.len(), 1);
    assert!(first.has_more);
    let cursor = &first.accounts[0].key;
    block_on(repository.delete(cursor))?;
    for input in ["aaron@example.com", "bob@example.com"] {
        block_on(repository.create(NewAccount {
            key: key(input)?,
            credentials: credentials(10),
        }))?;
    }
    let second = block_on(repository.list(Some(cursor), size))?;
    assert_eq!(second.accounts.len(), 1);
    assert_eq!(second.accounts[0].key, key("bob@example.com")?);
    assert!(second.has_more);

    let between = key("dan@example.com")?;
    let page = block_on(repository.list(Some(&between), size))?;
    assert_eq!(page.accounts.len(), 1);
    assert_eq!(page.accounts[0].key, key("erin@example.com")?);
    assert!(!page.has_more);
    Ok(())
}

#[test]
fn listing_does_not_decode_records_beyond_the_requested_page() -> TestResult {
    let database = database()?;
    let repository = RedbAccountRepository::from_database(database.clone())?;
    block_on(repository.create(NewAccount {
        key: key("alice@example.com")?,
        credentials: credentials(10),
    }))?;
    insert_record(database.as_ref(), &key("bob@example.com")?, &[2, 2])?;
    let size = AccountPageSize::new(1).ok_or("invalid page size")?;
    let first = block_on(repository.list(None, size))?;
    assert_eq!(first.accounts.len(), 1);
    assert!(first.has_more);
    assert_storage_error(
        block_on(repository.list(Some(&first.accounts[0].key), size)),
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
    let size = AccountPageSize::new(2).ok_or("invalid page size")?;
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
            block_on(repository.list(None, size)),
            StorageErrorKind::CorruptData,
        );
        let transaction = database.as_ref().begin_write()?;
        transaction.open_table(ACCOUNTS)?.remove(invalid)?;
        transaction.commit()?;
    }
    Ok(())
}

#[test]
fn maximum_size_pages_support_long_account_keys() -> TestResult {
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
        for index in 0..=AccountPageSize::MAX {
            let account = key(&format!("{index:04}{suffix}@example.com"))?;
            table.insert(account.as_str(), record.as_slice())?;
        }
    }
    transaction.commit()?;
    let size = AccountPageSize::new(AccountPageSize::MAX).ok_or("invalid page size")?;
    let first = block_on(repository.list(None, size))?;
    assert_eq!(first.accounts.len(), AccountPageSize::MAX);
    assert!(first.has_more);
    assert_eq!(first.accounts[0].key.username().len(), 1023);
    let cursor = &first.accounts.last().ok_or("empty page")?.key;
    let second = block_on(repository.list(Some(cursor), size))?;
    assert_eq!(second.accounts.len(), 1);
    assert!(!second.has_more);
    Ok(())
}
