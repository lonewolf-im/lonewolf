// SPDX-License-Identifier: Apache-2.0

use std::future::Future;

use ::redb::{ReadableTable, TableDefinition, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::{Jid, JidError, MAX_JID_LEN};

use super::{
    PendingSubscription, RosterError, RosterItem, RosterJid, RosterMutation, RosterReads,
    RosterSnapshot, RosterSubscription, RosterVersion, RosterWrites,
};
use crate::account::AccountKey;
use crate::account::redb::account_exists;
use crate::redb::{RedbRead, RedbWrite, storage_error};
use crate::{StorageError, StorageErrorKind};

pub(crate) const ITEMS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lonewolf_roster_items");
/// The roster version and the version of the last removal, per owner.
pub(crate) const VERSIONS: TableDefinition<&str, (u64, u64)> =
    TableDefinition::new("lonewolf_roster_versions");
pub(crate) const PENDING: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lonewolf_roster_pending_subscriptions");

/// Creates the roster tables.
pub(crate) fn initialize(transaction: &WriteTransaction) -> Result<(), StorageError> {
    transaction.open_table(ITEMS).map_err(storage_error)?;
    transaction.open_table(VERSIONS).map_err(storage_error)?;
    transaction.open_table(PENDING).map_err(storage_error)?;
    Ok(())
}

macro_rules! roster_reads {
    ($handle:ty) => {
        impl RosterReads for $handle {
            fn roster(
                &self,
                owner: &AccountKey,
            ) -> impl Future<Output = Result<RosterSnapshot, RosterError>> + Send {
                let owner = Box::<str>::from(owner.as_str());
                self.run(move |transaction| {
                    let versions = transaction.open_table(VERSIONS).map_err(storage_error)?;
                    let items = transaction.open_table(ITEMS).map_err(storage_error)?;
                    snapshot(&versions, &items, &owner)
                })
            }

            fn roster_item(
                &self,
                owner: &AccountKey,
                jid: &RosterJid,
            ) -> impl Future<Output = Result<Option<RosterItem>, RosterError>> + Send {
                let key = item_key(owner, jid);
                let jid = jid.clone();
                self.run(move |transaction| {
                    let table = transaction.open_table(ITEMS).map_err(storage_error)?;
                    Ok(read_item(&table, &key, jid)?.map(|entry| entry.value))
                })
            }

            fn pending_requests(
                &self,
                owner: &AccountKey,
            ) -> impl Future<Output = Result<Vec<PendingSubscription>, RosterError>> + Send {
                let owner = Box::<str>::from(owner.as_str());
                self.run(move |transaction| {
                    let table = transaction.open_table(PENDING).map_err(storage_error)?;
                    read_pending_requests(&table, &owner)
                })
            }

            fn pending_request(
                &self,
                owner: &AccountKey,
                sender: &RosterJid,
            ) -> impl Future<Output = Result<Option<PendingSubscription>, RosterError>> + Send {
                let key = item_key(owner, sender);
                let sender = sender.clone();
                self.run(move |transaction| {
                    let table = transaction.open_table(PENDING).map_err(storage_error)?;
                    read_pending_request(&table, &key, sender)
                })
            }
        }
    };
}

roster_reads!(RedbRead);
roster_reads!(RedbWrite);

impl RosterWrites for RedbWrite {
    fn put_roster_item(
        &mut self,
        owner: &AccountKey,
        item: &RosterItem,
    ) -> impl Future<Output = Result<RosterVersion, RosterError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, &item.jid);
        let encoded = encode_item(item);
        self.run(move |transaction| {
            if !account_exists(transaction, &owner)? {
                return Err(RosterError::NoAccount);
            }
            let mut record = encoded?;
            let version = advance_version(transaction, &owner, false)?;
            record.extend_from_slice(&version.get().to_le_bytes());
            transaction
                .open_table(ITEMS)
                .map_err(storage_error)?
                .insert(key.as_ref(), record.as_slice())
                .map_err(storage_error)?;
            Ok(version)
        })
    }

    fn remove_roster_item(
        &mut self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> impl Future<Output = Result<Option<RosterMutation<RosterItem>>, RosterError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, jid);
        let jid = jid.clone();
        self.run(move |transaction| remove(transaction, &owner, key, jid))
    }

    fn put_pending_request(
        &mut self,
        owner: &AccountKey,
        request: PendingSubscription,
    ) -> impl Future<Output = Result<(), RosterError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, &request.sender);
        self.run(move |transaction| {
            if !account_exists(transaction, &owner)? {
                return Err(RosterError::NoAccount);
            }
            transaction
                .open_table(PENDING)
                .map_err(storage_error)?
                .insert(key.as_ref(), request.stanza.as_ref())
                .map_err(storage_error)?;
            Ok(())
        })
    }

    fn remove_pending_request(
        &mut self,
        owner: &AccountKey,
        sender: &RosterJid,
    ) -> impl Future<Output = Result<bool, RosterError>> + Send {
        let key = item_key(owner, sender);
        self.run(move |transaction| {
            let removed = transaction
                .open_table(PENDING)
                .map_err(storage_error)?
                .remove(key.as_ref())
                .map_err(storage_error)?
                .is_some();
            Ok(removed)
        })
    }

    fn clear_roster(
        &mut self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<(), RosterError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        self.run(move |transaction| clear_roster(transaction, &owner))
    }
}

fn snapshot<V, I>(versions: &V, items: &I, owner: &str) -> Result<RosterSnapshot, RosterError>
where
    V: ReadableTable<&'static str, (u64, u64)>,
    I: ReadableTable<&'static str, &'static [u8]>,
{
    let (version, last_removal) = header(versions, owner)?;
    let (start, end) = owner_range(owner);
    let mut roster = Vec::new();
    for entry in items
        .range(start.as_ref()..end.as_ref())
        .map_err(storage_error)?
    {
        let (key, value) = entry.map_err(storage_error)?;
        let jid = decode_key(owner, key.value())?;
        roster.push(decode_item(jid, value.value())?);
    }
    Ok(RosterSnapshot {
        version: RosterVersion(version),
        last_removal: RosterVersion(last_removal),
        items: roster,
    })
}

fn header<V: ReadableTable<&'static str, (u64, u64)>>(
    versions: &V,
    owner: &str,
) -> Result<(u64, u64), RosterError> {
    Ok(versions
        .get(owner)
        .map_err(storage_error)?
        .map_or((0, 0), |header| header.value()))
}

fn read_item<T: ReadableTable<&'static str, &'static [u8]>>(
    table: &T,
    key: &str,
    jid: RosterJid,
) -> Result<Option<RosterMutation<RosterItem>>, RosterError> {
    table
        .get(key)
        .map_err(storage_error)?
        .map(|record| decode_item(jid, record.value()))
        .transpose()
        .map_err(Into::into)
}

fn read_pending_requests<T: ReadableTable<&'static str, &'static [u8]>>(
    table: &T,
    owner: &str,
) -> Result<Vec<PendingSubscription>, RosterError> {
    let (start, end) = owner_range(owner);
    let mut pending = Vec::new();
    for entry in table
        .range(start.as_ref()..end.as_ref())
        .map_err(storage_error)?
    {
        let (key, stanza) = entry.map_err(storage_error)?;
        pending.push(PendingSubscription {
            sender: decode_key(owner, key.value())?,
            stanza: Box::from(stanza.value()),
        });
    }
    Ok(pending)
}

fn read_pending_request<T: ReadableTable<&'static str, &'static [u8]>>(
    table: &T,
    key: &str,
    sender: RosterJid,
) -> Result<Option<PendingSubscription>, RosterError> {
    Ok(table
        .get(key)
        .map_err(storage_error)?
        .map(|stanza| PendingSubscription {
            sender,
            stanza: Box::from(stanza.value()),
        }))
}

fn clear_roster(transaction: &WriteTransaction, owner: &str) -> Result<(), RosterError> {
    let (start, end) = owner_range(owner);
    transaction
        .open_table(ITEMS)
        .map_err(storage_error)?
        .retain_in(start.as_ref()..end.as_ref(), |_, _| false)
        .map_err(storage_error)?;
    transaction
        .open_table(PENDING)
        .map_err(storage_error)?
        .retain_in(start.as_ref()..end.as_ref(), |_, _| false)
        .map_err(storage_error)?;
    transaction
        .open_table(VERSIONS)
        .map_err(storage_error)?
        .remove(owner)
        .map_err(storage_error)?;
    Ok(())
}

fn remove(
    transaction: &WriteTransaction,
    owner: &str,
    key: Box<str>,
    jid: RosterJid,
) -> Result<Option<RosterMutation<RosterItem>>, RosterError> {
    let item = {
        let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
        let Some(record) = table.remove(key.as_ref()).map_err(storage_error)? else {
            return Ok(None);
        };
        decode_item(jid, record.value())?.value
    };
    let version = advance_version(transaction, owner, true)?;
    Ok(Some(RosterMutation {
        version,
        value: item,
    }))
}

fn advance_version(
    transaction: &WriteTransaction,
    owner: &str,
    removal: bool,
) -> Result<RosterVersion, RosterError> {
    let mut versions = transaction.open_table(VERSIONS).map_err(storage_error)?;
    let (current, last_removal) = header(&versions, owner)?;
    let next = current.checked_add(1).ok_or(RosterError::ValueTooLarge)?;
    let last_removal = if removal { next } else { last_removal };
    versions
        .insert(owner, (next, last_removal))
        .map_err(storage_error)?;
    Ok(RosterVersion(next))
}

fn item_key(owner: &AccountKey, jid: &RosterJid) -> Box<str> {
    item_key_text(owner.as_str(), jid)
}

fn item_key_text(owner: &str, jid: &RosterJid) -> Box<str> {
    let mut key = String::with_capacity(owner.len() + 1 + jid.as_str().len());
    key.push_str(owner);
    key.push('\0');
    key.push_str(jid.as_str());
    key.into_boxed_str()
}

fn owner_range(owner: &str) -> (Box<str>, Box<str>) {
    let mut start = String::with_capacity(owner.len() + 1);
    start.push_str(owner);
    start.push('\0');
    let mut end = String::with_capacity(owner.len() + 1);
    end.push_str(owner);
    end.push('\u{1}');
    (start.into_boxed_str(), end.into_boxed_str())
}

fn decode_key(owner: &str, key: &str) -> Result<RosterJid, StorageError> {
    let jid = key
        .strip_prefix(owner)
        .and_then(|suffix| suffix.strip_prefix('\0'))
        .ok_or_else(|| StorageError::new(StorageErrorKind::CorruptData))?;
    decode_jid(jid)
}

fn decode_jid(text: &str) -> Result<RosterJid, StorageError> {
    if text.len() > MAX_JID_LEN {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    let mut arena = Arena::try_new(ArenaConfig::default())
        .map_err(|error| StorageError::with_source(StorageErrorKind::Other, error))?;
    let jid = Jid::parse_in(text, &mut arena).map_err(|error| {
        let kind = match error {
            JidError::AllocationFailed(_) | JidError::AccessFailed(_) => StorageErrorKind::Other,
            _ => StorageErrorKind::CorruptData,
        };
        StorageError::with_source(kind, error)
    })?;
    let jid = jid
        .resolve(&arena)
        .map_err(|error| StorageError::with_source(StorageErrorKind::Other, error))?;
    if jid.as_str() != text {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    Ok(RosterJid::from(jid))
}

fn encode_item(item: &RosterItem) -> Result<Vec<u8>, RosterError> {
    let name_bytes = item.name.as_deref().map(str::as_bytes);
    let groups_bytes = item.groups.iter().map(|group| group.as_bytes());
    let groups_len = item
        .groups
        .iter()
        .try_fold(0usize, |len, group| len.checked_add(4 + group.len()))
        .ok_or(RosterError::ValueTooLarge)?;
    let capacity = 18usize
        .checked_add(name_bytes.map_or(0, <[u8]>::len))
        .and_then(|len| len.checked_add(groups_len))
        .ok_or(RosterError::ValueTooLarge)?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.push(match item.subscription.state {
        super::SubscriptionState::None => 0,
        super::SubscriptionState::To => 1,
        super::SubscriptionState::From => 2,
        super::SubscriptionState::Both => 3,
    });
    encoded.push(
        u8::from(item.subscription.pending_out) | (u8::from(item.subscription.approved) << 1),
    );
    append_optional(&mut encoded, name_bytes)?;
    encoded.extend_from_slice(
        &u32::try_from(item.groups.len())
            .map_err(|_| RosterError::ValueTooLarge)?
            .to_le_bytes(),
    );
    for group in groups_bytes {
        append_bytes(&mut encoded, group)?;
    }
    Ok(encoded)
}

fn append_optional(encoded: &mut Vec<u8>, value: Option<&[u8]>) -> Result<(), RosterError> {
    match value {
        Some(value) if value.len() < u32::MAX as usize => append_bytes(encoded, value),
        Some(_) => Err(RosterError::ValueTooLarge),
        None => {
            encoded.extend_from_slice(&u32::MAX.to_le_bytes());
            Ok(())
        }
    }
}

fn append_bytes(encoded: &mut Vec<u8>, value: &[u8]) -> Result<(), RosterError> {
    let len = u32::try_from(value.len()).map_err(|_| RosterError::ValueTooLarge)?;
    encoded.extend_from_slice(&len.to_le_bytes());
    encoded.extend_from_slice(value);
    Ok(())
}

/// Decodes an item record into the item and the version that last changed it.
fn decode_item(
    jid: RosterJid,
    mut bytes: &[u8],
) -> Result<RosterMutation<RosterItem>, StorageError> {
    let state = match take_byte(&mut bytes)? {
        0 => super::SubscriptionState::None,
        1 => super::SubscriptionState::To,
        2 => super::SubscriptionState::From,
        3 => super::SubscriptionState::Both,
        _ => return Err(StorageError::new(StorageErrorKind::CorruptData)),
    };
    let flags = take_byte(&mut bytes)?;
    if flags & !0b11 != 0 {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    let name = take_optional_string(&mut bytes)?;
    let group_count = take_u32(&mut bytes)? as usize;
    let mut groups = Vec::with_capacity(group_count.min(bytes.len() / 4));
    for _ in 0..group_count {
        groups.push(take_string(&mut bytes)?);
    }
    let version = take_u64(&mut bytes)?;
    if !bytes.is_empty() {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    Ok(RosterMutation {
        version: RosterVersion(version),
        value: RosterItem {
            jid,
            name,
            groups,
            subscription: RosterSubscription {
                state,
                pending_out: flags & 1 != 0,
                approved: flags & 2 != 0,
            },
        },
    })
}

fn take_byte(bytes: &mut &[u8]) -> Result<u8, StorageError> {
    let (&value, remaining) = bytes
        .split_first()
        .ok_or_else(|| StorageError::new(StorageErrorKind::CorruptData))?;
    *bytes = remaining;
    Ok(value)
}

fn take_u32(bytes: &mut &[u8]) -> Result<u32, StorageError> {
    let (value, remaining) = bytes
        .split_first_chunk::<4>()
        .ok_or_else(|| StorageError::new(StorageErrorKind::CorruptData))?;
    *bytes = remaining;
    Ok(u32::from_le_bytes(*value))
}

fn take_u64(bytes: &mut &[u8]) -> Result<u64, StorageError> {
    let (value, remaining) = bytes
        .split_first_chunk::<8>()
        .ok_or_else(|| StorageError::new(StorageErrorKind::CorruptData))?;
    *bytes = remaining;
    Ok(u64::from_le_bytes(*value))
}

fn take_optional_string(bytes: &mut &[u8]) -> Result<Option<Box<str>>, StorageError> {
    let len = take_u32(bytes)?;
    if len == u32::MAX {
        Ok(None)
    } else {
        take_string_with_len(bytes, len as usize).map(Some)
    }
}

fn take_string(bytes: &mut &[u8]) -> Result<Box<str>, StorageError> {
    let len = take_u32(bytes)? as usize;
    take_string_with_len(bytes, len)
}

fn take_string_with_len(bytes: &mut &[u8], len: usize) -> Result<Box<str>, StorageError> {
    let (value, remaining) = bytes
        .split_at_checked(len)
        .ok_or_else(|| StorageError::new(StorageErrorKind::CorruptData))?;
    let value = str::from_utf8(value)
        .map_err(|error| StorageError::with_source(StorageErrorKind::CorruptData, error))?;
    *bytes = remaining;
    Ok(Box::from(value))
}
