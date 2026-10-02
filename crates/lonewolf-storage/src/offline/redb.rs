// SPDX-License-Identifier: Apache-2.0

use std::future::Future;

use ::redb::{ReadableTable, TableDefinition, WriteTransaction};

use super::{OfflineError, OfflineReads, OfflineSequence, OfflineWrites, StoredMessage};
use crate::account::AccountKey;
use crate::account::redb::account_exists;
use crate::redb::{RedbRead, RedbWrite, storage_error};
use crate::{StorageError, StorageErrorKind};

pub(crate) const MESSAGES: TableDefinition<(&str, u64), &[u8]> =
    TableDefinition::new("lonewolf_offline_messages");
pub(crate) const SEQUENCES: TableDefinition<&str, u64> =
    TableDefinition::new("lonewolf_offline_sequences");

pub(crate) fn initialize(transaction: &WriteTransaction) -> Result<(), StorageError> {
    transaction.open_table(MESSAGES).map_err(storage_error)?;
    transaction.open_table(SEQUENCES).map_err(storage_error)?;
    Ok(())
}

macro_rules! offline_reads {
    ($handle:ty) => {
        impl OfflineReads for $handle {
            fn offline_messages(
                &self,
                owner: &AccountKey,
            ) -> impl Future<Output = Result<Vec<StoredMessage>, OfflineError>> + Send {
                let owner = Box::<str>::from(owner.as_str());
                self.run(move |transaction| {
                    let table = transaction.open_table(MESSAGES).map_err(storage_error)?;
                    read_messages(&table, &owner)
                })
            }

            fn offline_count(
                &self,
                owner: &AccountKey,
            ) -> impl Future<Output = Result<usize, OfflineError>> + Send {
                let owner = Box::<str>::from(owner.as_str());
                self.run(move |transaction| {
                    let table = transaction.open_table(MESSAGES).map_err(storage_error)?;
                    let mut count = 0;
                    for entry in table
                        .range((owner.as_ref(), 0)..=(owner.as_ref(), u64::MAX))
                        .map_err(storage_error)?
                    {
                        entry.map_err(storage_error)?;
                        count += 1;
                    }
                    Ok(count)
                })
            }
        }
    };
}

offline_reads!(RedbRead);
offline_reads!(RedbWrite);

impl OfflineWrites for RedbWrite {
    fn push_offline_message(
        &mut self,
        owner: &AccountKey,
        stored_at: u64,
        stanza: &[u8],
    ) -> impl Future<Output = Result<OfflineSequence, OfflineError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        let stanza = Box::<[u8]>::from(stanza);
        self.run(move |transaction| {
            if !account_exists(transaction, &owner)? {
                return Err(OfflineError::NoAccount);
            }
            let mut sequences = transaction.open_table(SEQUENCES).map_err(storage_error)?;
            let current = sequences
                .get(owner.as_ref())
                .map_err(storage_error)?
                .map_or(0, |sequence| sequence.value());
            let next = current.checked_add(1).ok_or(OfflineError::ValueTooLarge)?;
            let length = size_of::<u64>()
                .checked_add(stanza.len())
                .ok_or(OfflineError::ValueTooLarge)?;
            let mut messages = transaction.open_table(MESSAGES).map_err(storage_error)?;
            {
                let mut record = messages
                    .insert_reserve((owner.as_ref(), next), length)
                    .map_err(offline_storage_error)?;
                let bytes = record.as_mut();
                bytes[..size_of::<u64>()].copy_from_slice(&stored_at.to_be_bytes());
                bytes[size_of::<u64>()..].copy_from_slice(&stanza);
            }
            sequences
                .insert(owner.as_ref(), next)
                .map_err(storage_error)?;
            Ok(OfflineSequence::new(next))
        })
    }

    fn remove_offline_messages_through(
        &mut self,
        owner: &AccountKey,
        through: OfflineSequence,
    ) -> impl Future<Output = Result<usize, OfflineError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        self.run(move |transaction| {
            let mut removed = 0;
            transaction
                .open_table(MESSAGES)
                .map_err(storage_error)?
                .retain_in(
                    (owner.as_ref(), 0)..=(owner.as_ref(), through.get()),
                    |_, _| {
                        removed += 1;
                        false
                    },
                )
                .map_err(storage_error)?;
            Ok(removed)
        })
    }

    fn remove_offline_message(
        &mut self,
        owner: &AccountKey,
        sequence: OfflineSequence,
    ) -> impl Future<Output = Result<bool, OfflineError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        self.run(move |transaction| {
            let removed = transaction
                .open_table(MESSAGES)
                .map_err(storage_error)?
                .remove((owner.as_ref(), sequence.get()))
                .map_err(storage_error)?
                .is_some();
            Ok(removed)
        })
    }

    fn clear_offline_messages(
        &mut self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<(), OfflineError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        self.run(move |transaction| {
            transaction
                .open_table(MESSAGES)
                .map_err(storage_error)?
                .retain_in((owner.as_ref(), 0)..=(owner.as_ref(), u64::MAX), |_, _| {
                    false
                })
                .map_err(storage_error)?;
            transaction
                .open_table(SEQUENCES)
                .map_err(storage_error)?
                .remove(owner.as_ref())
                .map_err(storage_error)?;
            Ok(())
        })
    }
}

fn read_messages<T: ReadableTable<(&'static str, u64), &'static [u8]>>(
    table: &T,
    owner: &str,
) -> Result<Vec<StoredMessage>, OfflineError> {
    let mut messages = Vec::new();
    for entry in table
        .range((owner, 0)..=(owner, u64::MAX))
        .map_err(storage_error)?
    {
        let (key, record) = entry.map_err(storage_error)?;
        let (stored_at, stanza) = record
            .value()
            .split_first_chunk::<{ size_of::<u64>() }>()
            .ok_or_else(|| StorageError::new(StorageErrorKind::CorruptData))?;
        messages.push(StoredMessage {
            sequence: OfflineSequence::new(key.value().1),
            stored_at: u64::from_be_bytes(*stored_at),
            stanza: Box::from(stanza),
        });
    }
    Ok(messages)
}

fn offline_storage_error(error: ::redb::StorageError) -> OfflineError {
    match error {
        ::redb::StorageError::ValueTooLarge(_) => OfflineError::ValueTooLarge,
        error => storage_error(error).into(),
    }
}
