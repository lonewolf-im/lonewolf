// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use ::redb::{ReadableDatabase, ReadableTableMetadata};
use futures_executor::block_on;

use super::redb::ELEMENTS;
use super::{
    PrivateXmlChange, PrivateXmlError, PrivateXmlQuota, PrivateXmlReads, PrivateXmlWrites,
    StoredPrivateXml,
};
use crate::account::AccountWrites;
use crate::redb::tests::storage;
use crate::tests::{TestResult, key, new_account};
use crate::{Storage, StorageError, StorageErrorKind, WriteTransaction};

#[test]
fn private_xml_debug_and_errors_omit_private_content() {
    let private = "private settings document";
    let stored = StoredPrivateXml {
        xml: Box::from(private),
    };
    assert_eq!(format!("{stored:?}"), "StoredPrivateXml { .. }");
    let change = PrivateXmlChange {
        namespace: "urn:private-namespace",
        name: "private-name",
        xml: Some(private),
    };
    assert_eq!(format!("{change:?}"), "PrivateXmlChange { .. }");
    assert_eq!(PrivateXmlQuota::default().max_items.get(), 50);
    assert_eq!(PrivateXmlQuota::default().max_bytes.get(), 2_097_152);
    for error in [
        PrivateXmlError::NoAccount,
        PrivateXmlError::QuotaExceeded,
        StorageError::with_source(
            StorageErrorKind::Unavailable,
            std::io::Error::other(private),
        )
        .into(),
    ] {
        assert!(!format!("{error:?}").contains(private));
        assert!(!error.to_string().contains(private));
        if let PrivateXmlError::Storage(_) = error {
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
fn private_xml_record_is_utf8_bytes_under_the_owner_namespace_and_name() -> TestResult {
    let storage = storage()?;
    let owner = key("Alice@EXAMPLE.COM")?;
    let xml = "<prefs xmlns='urn:test:prefs' xml:lang='' xml:space='default'>Ålice</prefs>";
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .update_private_xml(
                &owner,
                &[PrivateXmlChange {
                    namespace: "urn:test:prefs",
                    name: "prefs",
                    xml: Some(xml),
                }],
                PrivateXmlQuota::default(),
            )
            .await?;
        writer.commit().await?;
        TestResult::Ok(())
    })?;
    let reader = storage.as_ref().begin_read()?;
    let table = reader.open_table(ELEMENTS)?;
    assert_eq!(table.len()?, 1);
    assert_eq!(
        table
            .get(("alice@example.com", "urn:test:prefs", "prefs"))?
            .ok_or("missing private XML")?
            .value(),
        xml.as_bytes()
    );
    Ok(())
}

#[test]
fn private_xml_corrupt_records_fail_on_both_transaction_handles_without_changing_bytes()
-> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    for bytes in [b"\xff\xfe".to_vec(), b"private document\xff".to_vec()] {
        let transaction = storage.as_ref().begin_write()?;
        transaction
            .open_table(ELEMENTS)?
            .insert((owner.as_str(), "urn:a", "a"), bytes.as_slice())?;
        transaction.commit()?;
        block_on(async {
            let reader = storage.begin_read().await?;
            let writer = storage.begin_write().await?;
            for result in [
                reader.private_xml(&owner, "urn:a", "a").await,
                writer.private_xml(&owner, "urn:a", "a").await,
            ] {
                let error = result.expect_err("corrupt record accepted");
                assert!(matches!(
                    &error,
                    PrivateXmlError::Storage(error) if error.kind() == StorageErrorKind::CorruptData
                ));
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
                .open_table(ELEMENTS)?
                .get((owner.as_str(), "urn:a", "a"))?
                .ok_or("missing corrupt row")?
                .value(),
            bytes
        );
    }
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer.clear_private_xml(&owner).await?;
        writer.commit().await?;
        TestResult::Ok(())
    })?;
    assert!(
        storage
            .as_ref()
            .begin_read()?
            .open_table(ELEMENTS)?
            .is_empty()?
    );
    Ok(())
}

#[test]
fn private_xml_reads_preserve_backend_error_kinds() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    let transaction = storage.as_ref().begin_write()?;
    transaction.delete_table(ELEMENTS)?;
    transaction.commit()?;
    block_on(async {
        let transaction = storage.begin_read().await?;
        let error = transaction
            .private_xml(&owner, "urn:a", "a")
            .await
            .expect_err("missing table accepted");
        assert!(matches!(
            error,
            PrivateXmlError::Storage(error) if error.kind() == StorageErrorKind::CorruptData
        ));
        Ok(())
    })
}
