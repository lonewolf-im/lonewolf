// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use ::redb::{ReadableTable, TableDefinition, WriteTransaction};

use super::{
    PrivateXmlChange, PrivateXmlError, PrivateXmlQuota, PrivateXmlReads, PrivateXmlWrites,
    StoredPrivateXml,
};
use crate::account::AccountKey;
use crate::account::redb::account_exists;
use crate::redb::{RedbRead, RedbWrite, storage_error};
use crate::{StorageError, StorageErrorKind};

pub(crate) const ELEMENTS: TableDefinition<(&str, &str, &str), &[u8]> =
    TableDefinition::new("lonewolf_private_xml");

pub(crate) fn initialize(transaction: &WriteTransaction) -> Result<(), StorageError> {
    transaction.open_table(ELEMENTS).map_err(storage_error)?;
    Ok(())
}

struct ElementKey {
    text: Box<str>,
    owner: usize,
    namespace: usize,
}

impl ElementKey {
    fn new(owner: &str, namespace: &str, name: &str) -> Self {
        let mut text = String::with_capacity(owner.len() + namespace.len() + name.len());
        text.push_str(owner);
        text.push_str(namespace);
        text.push_str(name);
        Self {
            text: text.into_boxed_str(),
            owner: owner.len(),
            namespace: owner.len() + namespace.len(),
        }
    }

    fn parts(&self) -> (&str, &str, &str) {
        (
            &self.text[..self.owner],
            &self.text[self.owner..self.namespace],
            &self.text[self.namespace..],
        )
    }
}

macro_rules! private_reads {
    ($handle:ty) => {
        impl PrivateXmlReads for $handle {
            async fn private_xml(
                &self,
                owner: &AccountKey,
                namespace: &str,
                name: &str,
            ) -> Result<Option<StoredPrivateXml>, PrivateXmlError> {
                let key = ElementKey::new(owner.as_str(), namespace, name);
                self.run(move |transaction| {
                    let table = transaction.open_table(ELEMENTS).map_err(storage_error)?;
                    table
                        .get(key.parts())
                        .map_err(storage_error)?
                        .map(|record| read_record(record.value()))
                        .transpose()
                })
                .await
            }
        }
    };
}

private_reads!(RedbRead);
private_reads!(RedbWrite);

impl PrivateXmlWrites for RedbWrite {
    async fn update_private_xml(
        &mut self,
        owner: &AccountKey,
        changes: &[PrivateXmlChange<'_>],
        quota: PrivateXmlQuota,
    ) -> Result<(), PrivateXmlError> {
        let owner = Box::<str>::from(owner.as_str());
        let changes = changes
            .iter()
            .map(|change| {
                (
                    ElementKey::new(&owner, change.namespace, change.name),
                    change.xml.map(Box::<str>::from),
                )
            })
            .collect::<Vec<_>>();
        self.run(move |transaction| {
            if !account_exists(transaction, &owner)? {
                return Err(PrivateXmlError::NoAccount);
            }
            let mut table = transaction.open_table(ELEMENTS).map_err(storage_error)?;
            let mut last = BTreeMap::new();
            for (key, xml) in &changes {
                last.insert(key.parts(), xml.as_deref());
            }
            let (before_items, before_bytes) = usage(&table, &owner)?;
            let (mut items, mut bytes) = (before_items, before_bytes);
            for (key, xml) in &last {
                if let Some(old) = table.get(*key).map_err(storage_error)? {
                    items = items.checked_sub(1).ok_or_else(corrupt)?;
                    bytes = bytes.checked_sub(old.value().len()).ok_or_else(corrupt)?;
                }
                if let Some(xml) = xml {
                    items = items.checked_add(1).ok_or(PrivateXmlError::QuotaExceeded)?;
                    bytes = bytes
                        .checked_add(xml.len())
                        .ok_or(PrivateXmlError::QuotaExceeded)?;
                }
            }
            if (items > quota.max_items.get() && items > before_items)
                || (bytes > quota.max_bytes.get() && bytes > before_bytes)
            {
                return Err(PrivateXmlError::QuotaExceeded);
            }
            for (key, xml) in last {
                match xml {
                    Some(xml) => {
                        table.insert(key, xml.as_bytes()).map_err(storage_error)?;
                    }
                    None => {
                        table.remove(key).map_err(storage_error)?;
                    }
                }
            }
            Ok(())
        })
        .await
    }

    async fn clear_private_xml(&mut self, owner: &AccountKey) -> Result<(), PrivateXmlError> {
        let owner = Box::<str>::from(owner.as_str());
        self.run(move |transaction| {
            let end = owner_end(&owner);
            transaction
                .open_table(ELEMENTS)
                .map_err(storage_error)?
                .retain_in((owner.as_ref(), "", "")..(end.as_str(), "", ""), |_, _| {
                    false
                })
                .map_err(storage_error)?;
            Ok(())
        })
        .await
    }
}

fn usage<T: ReadableTable<(&'static str, &'static str, &'static str), &'static [u8]>>(
    table: &T,
    owner: &str,
) -> Result<(usize, usize), PrivateXmlError> {
    let end = owner_end(owner);
    let mut items = 0usize;
    let mut bytes = 0usize;
    for entry in table
        .range((owner, "", "")..(end.as_str(), "", ""))
        .map_err(storage_error)?
    {
        let (_, value) = entry.map_err(storage_error)?;
        items = items.checked_add(1).ok_or_else(corrupt)?;
        bytes = bytes.checked_add(value.value().len()).ok_or_else(corrupt)?;
    }
    Ok((items, bytes))
}

/// Canonical JIDs never contain NUL, so this bound follows every key of `owner`
/// and precedes the keys of every other account.
fn owner_end(owner: &str) -> String {
    let mut end = String::with_capacity(owner.len() + 1);
    end.push_str(owner);
    end.push('\0');
    end
}

fn read_record(bytes: &[u8]) -> Result<StoredPrivateXml, PrivateXmlError> {
    let xml = std::str::from_utf8(bytes).map_err(|_| corrupt())?;
    Ok(StoredPrivateXml {
        xml: Box::from(xml),
    })
}

fn corrupt() -> PrivateXmlError {
    StorageError::new(StorageErrorKind::CorruptData).into()
}
