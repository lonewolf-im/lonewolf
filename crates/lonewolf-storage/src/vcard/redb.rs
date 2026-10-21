// SPDX-License-Identifier: Apache-2.0

use ::redb::{ReadableTable, TableDefinition, WriteTransaction};

use super::{MAX_VCARD_BYTES, StoredVCard, VCardError, VCardQuota, VCardReads, VCardWrites};
use crate::account::AccountKey;
use crate::account::redb::account_exists;
use crate::redb::{RedbRead, RedbWrite, storage_error};
use crate::{StorageError, StorageErrorKind};

pub(crate) const VCARDS: TableDefinition<&str, &[u8]> = TableDefinition::new("lonewolf_vcards");

pub(crate) fn initialize(transaction: &WriteTransaction) -> Result<(), StorageError> {
    transaction.open_table(VCARDS).map_err(storage_error)?;
    Ok(())
}

macro_rules! vcard_reads {
    ($handle:ty) => {
        impl VCardReads for $handle {
            async fn vcard(&self, owner: &AccountKey) -> Result<Option<StoredVCard>, VCardError> {
                let owner = Box::<str>::from(owner.as_str());
                self.run(move |transaction| {
                    let table = transaction.open_table(VCARDS).map_err(storage_error)?;
                    table
                        .get(owner.as_ref())
                        .map_err(storage_error)?
                        .map(|record| read_record(record.value()))
                        .transpose()
                })
                .await
            }
        }
    };
}

vcard_reads!(RedbRead);
vcard_reads!(RedbWrite);

impl VCardWrites for RedbWrite {
    async fn replace_vcard(
        &mut self,
        owner: &AccountKey,
        xml: &str,
        quota: VCardQuota,
    ) -> Result<(), VCardError> {
        if xml.len() > quota.max_bytes.get() || xml.len() > MAX_VCARD_BYTES {
            return Err(VCardError::QuotaExceeded);
        }
        let owner = Box::<str>::from(owner.as_str());
        let xml = Box::<str>::from(xml);
        self.run(move |transaction| {
            let mut table = transaction.open_table(VCARDS).map_err(storage_error)?;
            if !account_exists(transaction, &owner)? {
                return Err(VCardError::NoAccount);
            }
            table
                .insert(owner.as_ref(), xml.as_bytes())
                .map_err(vcard_storage_error)?;
            Ok(())
        })
        .await
    }

    async fn delete_vcard(&mut self, owner: &AccountKey) -> Result<(), VCardError> {
        let owner = Box::<str>::from(owner.as_str());
        self.run(move |transaction| {
            transaction
                .open_table(VCARDS)
                .map_err(storage_error)?
                .remove(owner.as_ref())
                .map_err(vcard_storage_error)?;
            Ok(())
        })
        .await
    }
}

fn read_record(bytes: &[u8]) -> Result<StoredVCard, VCardError> {
    if bytes.len() > MAX_VCARD_BYTES {
        return Err(StorageError::new(StorageErrorKind::CorruptData).into());
    }
    let xml =
        std::str::from_utf8(bytes).map_err(|_| StorageError::new(StorageErrorKind::CorruptData))?;
    Ok(StoredVCard {
        xml: Box::from(xml),
    })
}

fn vcard_storage_error(error: ::redb::StorageError) -> VCardError {
    match error {
        ::redb::StorageError::ValueTooLarge(_) => VCardError::QuotaExceeded,
        error => storage_error(error).into(),
    }
}
