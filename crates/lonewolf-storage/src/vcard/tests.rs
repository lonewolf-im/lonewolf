// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use ::redb::{ReadableDatabase, ReadableTableMetadata};
use futures_executor::block_on;

use super::redb::VCARDS;
use super::{MAX_VCARD_BYTES, StoredVCard, VCardError, VCardQuota, VCardReads, VCardWrites};
use crate::account::AccountWrites;
use crate::redb::tests::storage;
use crate::tests::{TestResult, key, new_account};
use crate::{Storage, StorageError, StorageErrorKind, WriteTransaction};

#[test]
fn vcard_debug_and_errors_omit_private_content() {
    let private = "private vCard document";
    let card = StoredVCard {
        xml: Box::from(private),
    };
    assert_eq!(format!("{card:?}"), "StoredVCard { .. }");
    assert_eq!(VCardQuota::default().max_bytes.get(), 262_144);
    for error in [
        VCardError::NoAccount,
        VCardError::QuotaExceeded,
        StorageError::with_source(
            StorageErrorKind::Unavailable,
            std::io::Error::other(private),
        )
        .into(),
    ] {
        assert!(!format!("{error:?}").contains(private));
        assert!(!error.to_string().contains(private));
        if let VCardError::Storage(_) = error {
            let source = error.source().expect("storage source");
            assert!(!format!("{source:?}").contains(private));
            assert_eq!(
                source.source().expect("backend source").to_string(),
                private
            );
        } else {
            assert!(error.source().is_none());
        }
    }
}

#[test]
fn vcard_record_is_only_utf8_document_bytes_under_the_canonical_owner() -> TestResult {
    let storage = storage()?;
    let owner = key("Alice@EXAMPLE.COM")?;
    let xml = "<vCard xmlns='vcard-temp'><FN>Ålice</FN></vCard>";
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .replace_vcard(&owner, xml, VCardQuota::default())
            .await?;
        writer.commit().await?;
        TestResult::Ok(())
    })?;
    let reader = storage.as_ref().begin_read()?;
    let table = reader.open_table(VCARDS)?;
    assert_eq!(table.len()?, 1);
    assert_eq!(
        table
            .get("alice@example.com")?
            .ok_or("missing vCard")?
            .value(),
        xml.as_bytes()
    );
    Ok(())
}

#[test]
fn vcard_corrupt_records_fail_on_both_transaction_handles_without_changing_bytes() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    for bytes in [
        vec![b'x'; MAX_VCARD_BYTES + 1],
        b"private document\xff".to_vec(),
    ] {
        let transaction = storage.as_ref().begin_write()?;
        transaction
            .open_table(VCARDS)?
            .insert(owner.as_str(), bytes.as_slice())?;
        transaction.commit()?;
        block_on(async {
            let reader = storage.begin_read().await?;
            let writer = storage.begin_write().await?;
            for result in [reader.vcard(&owner).await, writer.vcard(&owner).await] {
                let error = result.expect_err("corrupt record accepted");
                assert!(
                    matches!(&error, VCardError::Storage(error) if error.kind() == StorageErrorKind::CorruptData)
                );
                assert!(!format!("{error:?}").contains("private document"));
                assert!(!error.to_string().contains("private document"));
                assert!(
                    error
                        .source()
                        .ok_or("missing storage source")?
                        .source()
                        .is_none()
                );
            }
            writer.commit().await?;
            TestResult::Ok(())
        })?;
        let reader = storage.as_ref().begin_read()?;
        assert_eq!(
            reader
                .open_table(VCARDS)?
                .get(owner.as_str())?
                .ok_or("missing corrupt row")?
                .value(),
            bytes
        );
    }
    Ok(())
}

#[test]
fn vcard_reads_preserve_backend_error_kinds() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    let transaction = storage.as_ref().begin_write()?;
    transaction.delete_table(VCARDS)?;
    transaction.commit()?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        let transaction = storage.begin_read().await?;
        let error = transaction
            .vcard(&owner)
            .await
            .expect_err("missing table accepted");
        assert!(
            matches!(error, VCardError::Storage(error) if error.kind() == StorageErrorKind::CorruptData)
        );
        Ok(())
    })
}
