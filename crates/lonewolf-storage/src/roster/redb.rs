// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::num::NonZeroUsize;

use ::redb::{ReadableTable, TableDefinition, WriteTransaction};
use lonewolf_xmpp::jid::MAX_JID_LEN;

use super::{
    MAX_GROUPS_PER_ITEM, PendingSubscription, RosterError, RosterItem, RosterJid, RosterMutation,
    RosterQuota, RosterReads, RosterSnapshot, RosterSubscription, RosterVersion, RosterWrites,
};
use crate::account::AccountKey;
use crate::account::redb::account_exists;
use crate::redb::{RedbRead, RedbWrite, storage_error, with_canonical_jid};
use crate::{StorageError, StorageErrorKind};

pub(crate) const ITEMS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lonewolf_roster_items");
pub(crate) const VERSIONS: TableDefinition<&str, u64> =
    TableDefinition::new("lonewolf_roster_versions");
pub(crate) const PENDING: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lonewolf_roster_pending_subscriptions");

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
                quota: RosterQuota,
            ) -> impl Future<Output = Result<RosterSnapshot, RosterError>> + Send {
                let owner = Box::<str>::from(owner.as_str());
                self.run(move |transaction| {
                    let versions = transaction.open_table(VERSIONS).map_err(storage_error)?;
                    let items = transaction.open_table(ITEMS).map_err(storage_error)?;
                    snapshot(&versions, &items, &owner, quota)
                })
            }

            fn roster_item(
                &self,
                owner: &AccountKey,
                jid: &RosterJid,
                quota: RosterQuota,
            ) -> impl Future<Output = Result<Option<RosterItem>, RosterError>> + Send {
                let key = item_key(owner, jid);
                let jid = jid.clone();
                self.run(move |transaction| {
                    let table = transaction.open_table(ITEMS).map_err(storage_error)?;
                    read_item(&table, &key, jid, quota)
                })
            }

            fn roster_version(&self, owner: &AccountKey) -> impl Future<Output = Result<RosterVersion, RosterError>> + Send {
                let owner = Box::<str>::from(owner.as_str());
                self.run(move |transaction| {
                    let table = transaction.open_table(VERSIONS).map_err(storage_error)?;
                    Ok(RosterVersion(table.get(owner.as_ref()).map_err(storage_error)?.map_or(0, |v|v.value())))
                })
            }

            fn roster_subscription(&self, owner: &AccountKey, jid: &RosterJid) -> impl Future<Output = Result<Option<RosterSubscription>, RosterError>> + Send {
                let key = item_key(owner, jid);
                self.run(move |transaction| {
                    let table = transaction.open_table(ITEMS).map_err(storage_error)?;
                    table.get(key.as_ref()).map_err(storage_error)?.map(|v| decode_subscription(v.value())).transpose()
                })
            }

            fn next_roster_subscription(&self, owner: &AccountKey, after: Option<&RosterJid>) -> impl Future<Output = Result<Option<(RosterJid,RosterSubscription)>, RosterError>> + Send {
                let owner = Box::<str>::from(owner.as_str());
                let after = after.map(|jid|item_key_text(&owner,jid));
                self.run(move |transaction| {
                    let table = transaction.open_table(ITEMS).map_err(storage_error)?;
                    let (start,end)=owner_range(&owner);
                    let lower=after.as_deref().map_or(std::ops::Bound::Included(start.as_ref()),std::ops::Bound::Excluded);
                    table.range::<&str>((lower,std::ops::Bound::Excluded(end.as_ref()))).map_err(storage_error)?.next().map(|entry| {
                        let (key,value)=entry.map_err(storage_error)?;
                        Ok((decode_key(&owner,key.value())?,decode_subscription(value.value())?))
                    }).transpose()
                })
            }

            fn next_pending_sender(&self, owner: &AccountKey, after: Option<&RosterJid>) -> impl Future<Output = Result<Option<RosterJid>, RosterError>> + Send {
                let owner = Box::<str>::from(owner.as_str());
                let after = after.map(|jid|item_key_text(&owner,jid));
                self.run(move |transaction| {
                    let table = transaction.open_table(PENDING).map_err(storage_error)?;
                    let (start,end)=owner_range(&owner);
                    let lower=after.as_deref().map_or(std::ops::Bound::Included(start.as_ref()),std::ops::Bound::Excluded);
                    table.range::<&str>((lower,std::ops::Bound::Excluded(end.as_ref()))).map_err(storage_error)?.next().map(|entry| {
                        let (key,_)=entry.map_err(storage_error)?;
                        decode_key(&owner,key.value()).map_err(Into::into)
                    }).transpose()
                })
            }

            fn pending_request_exists(&self, owner: &AccountKey, sender: &RosterJid) -> impl Future<Output = Result<bool, RosterError>> + Send {
                let key=item_key(owner,sender);
                self.run(move |transaction| {
                    let table=transaction.open_table(PENDING).map_err(storage_error)?;
                    Ok(table.get(key.as_ref()).map_err(storage_error)?.is_some())
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
    type Snapshot = RedbRead;
    async fn put_roster_item(
        &mut self,
        owner: &AccountKey,
        item: &RosterItem,
        quota: RosterQuota,
    ) -> Result<RosterVersion, RosterError> {
        if item.groups.len() > MAX_GROUPS_PER_ITEM {
            return Err(RosterError::QuotaExceeded);
        }
        let encoded_len = encoded_item_size(item)?;
        let key = item_key(owner, &item.jid);
        let owner_text = Box::<str>::from(owner.as_str());
        self.run(move |transaction| {
            if !account_exists(transaction, &owner_text)? {
                return Err(RosterError::NoAccount);
            }
            let table = transaction.open_table(ITEMS).map_err(storage_error)?;
            admit_item(&table, &owner_text, &key, encoded_len, quota)
        })
        .await?;
        let encoded = encode_item(item)?;
        let key = item_key(owner, &item.jid);
        let owner = Box::<str>::from(owner.as_str());
        self.run(move |transaction| {
            transaction
                .open_table(ITEMS)
                .map_err(storage_error)?
                .insert(key.as_ref(), encoded.as_slice())
                .map_err(storage_error)?;
            advance_version(transaction, &owner)
        })
        .await
    }

    fn set_roster_subscription(
        &mut self,
        before: &RedbRead,
        owner: &AccountKey,
        jid: &RosterJid,
        subscription: RosterSubscription,
    ) -> impl Future<Output = Result<Option<RosterVersion>, RosterError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, jid);
        let before = before.snapshot();
        self.run(move |transaction| {
            copy_subscription(transaction, &before, &owner, &key, None, subscription)
        })
    }

    fn transition_roster_subscription(
        &mut self,
        owner: &AccountKey,
        jid: &RosterJid,
        expected: RosterSubscription,
        subscription: RosterSubscription,
    ) -> impl Future<Output = Result<Option<RosterVersion>, RosterError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, jid);
        self.run_with_snapshot(move |transaction, before| {
            copy_subscription(
                transaction,
                before,
                &owner,
                &key,
                Some(expected),
                subscription,
            )
        })
    }

    fn remove_roster_subscription(
        &mut self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> impl Future<Output = Result<Option<RosterMutation<RosterSubscription>>, RosterError>> + Send
    {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, jid);
        self.run(move |transaction| {
            let value = {
                let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
                let Some(record) = table.remove(key.as_ref()).map_err(storage_error)? else {
                    return Ok(None);
                };
                decode_subscription(record.value())?
            };
            Ok(Some(RosterMutation {
                version: advance_version(transaction, &owner)?,
                value,
            }))
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
        max_pending_subscription_requests: NonZeroUsize,
    ) -> impl Future<Output = Result<(), RosterError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, &request.sender);
        self.run(move |transaction| {
            if !account_exists(transaction, &owner)? {
                return Err(RosterError::NoAccount);
            }
            let mut table = transaction.open_table(PENDING).map_err(storage_error)?;
            if table.get(key.as_ref()).map_err(storage_error)?.is_none() {
                let (start, end) = owner_range(&owner);
                for (index, entry) in table
                    .range(start.as_ref()..end.as_ref())
                    .map_err(storage_error)?
                    .take(max_pending_subscription_requests.get())
                    .enumerate()
                {
                    entry.map_err(storage_error)?;
                    if index + 1 == max_pending_subscription_requests.get() {
                        return Err(RosterError::PendingLimitExceeded);
                    }
                }
            }
            table
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

fn snapshot<V, I>(
    versions: &V,
    items: &I,
    owner: &str,
    quota: RosterQuota,
) -> Result<RosterSnapshot, RosterError>
where
    V: ReadableTable<&'static str, u64>,
    I: ReadableTable<&'static str, &'static [u8]>,
{
    let version = versions
        .get(owner)
        .map_err(storage_error)?
        .map_or(0, |version| version.value());
    let (start, end) = owner_range(owner);
    let mut roster = Vec::new();
    let mut bytes = 0usize;
    for entry in items
        .range(start.as_ref()..end.as_ref())
        .map_err(storage_error)?
    {
        let (key, value) = entry.map_err(storage_error)?;
        bytes = bytes
            .checked_add(key.value().len())
            .and_then(|n| n.checked_add(value.value().len()))
            .ok_or(RosterError::QuotaExceeded)?;
        if roster.len() >= quota.max_items.get() || bytes > quota.max_bytes.get() {
            return Err(RosterError::QuotaExceeded);
        }
        let jid = decode_key(owner, key.value())?;
        check_item(value.value(), quota)?;
        roster.push(decode_item(jid, value.value())?);
    }
    Ok(RosterSnapshot {
        version: RosterVersion(version),
        items: roster,
    })
}

fn read_item<T: ReadableTable<&'static str, &'static [u8]>>(
    table: &T,
    key: &str,
    jid: RosterJid,
    quota: RosterQuota,
) -> Result<Option<RosterItem>, RosterError> {
    table
        .get(key)
        .map_err(storage_error)?
        .map(|record| {
            if key.len().saturating_add(record.value().len()) > quota.max_bytes.get() {
                return Err(RosterError::QuotaExceeded);
            }
            check_item(record.value(), quota)?;
            decode_item(jid, record.value()).map_err(Into::into)
        })
        .transpose()
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
        decode_item(jid, record.value())?
    };
    let version = advance_version(transaction, owner)?;
    Ok(Some(RosterMutation {
        version,
        value: item,
    }))
}

fn advance_version(
    transaction: &WriteTransaction,
    owner: &str,
) -> Result<RosterVersion, RosterError> {
    let mut versions = transaction.open_table(VERSIONS).map_err(storage_error)?;
    let current = versions
        .get(owner)
        .map_err(storage_error)?
        .map_or(0, |version| version.value());
    let next = current.checked_add(1).ok_or(RosterError::ValueTooLarge)?;
    versions.insert(owner, next).map_err(storage_error)?;
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
    with_canonical_jid(text, MAX_JID_LEN, |jid| Ok(RosterJid::from(jid)))
}

fn copy_subscription(
    transaction: &WriteTransaction,
    before: &::redb::ReadTransaction,
    owner: &str,
    key: &str,
    expected: Option<RosterSubscription>,
    subscription: RosterSubscription,
) -> Result<Option<RosterVersion>, RosterError> {
    if !account_exists(transaction, owner)? {
        return Err(RosterError::NoAccount);
    }
    let source_table = before.open_table(ITEMS).map_err(storage_error)?;
    let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
    let Some(current) = table.get(key).map_err(storage_error)? else {
        return Ok(None);
    };
    let source = source_table
        .get(key)
        .map_err(storage_error)?
        .ok_or_else(|| StorageError::new(StorageErrorKind::CorruptData))?;
    let old = decode_subscription(current.value())?;
    decode_subscription(source.value())?;
    let matches = match expected {
        None => current.value() == source.value(),
        Some(expected) => old == expected && current.value()[2..] == source.value()[2..],
    };
    if !matches {
        return Err(StorageError::new(StorageErrorKind::CorruptData).into());
    }
    if old == subscription {
        return Ok(None);
    }
    drop(current);
    let mut reserved = table
        .insert_reserve(key, source.value().len())
        .map_err(storage_error)?;
    let bytes = reserved.as_mut();
    bytes.copy_from_slice(source.value());
    bytes[..2].copy_from_slice(&encode_subscription(subscription));
    drop(reserved);
    drop(table);
    advance_version(transaction, owner).map(Some)
}

fn admit_item<I: ReadableTable<&'static str, &'static [u8]>>(
    items: &I,
    owner: &str,
    key: &str,
    encoded_len: usize,
    quota: RosterQuota,
) -> Result<(), RosterError> {
    let old_bytes = items
        .get(key)
        .map_err(storage_error)?
        .map(|old| key.len() + old.value().len());
    let new_bytes = key
        .len()
        .checked_add(encoded_len)
        .ok_or(RosterError::QuotaExceeded)?;
    if old_bytes.is_some_and(|old| new_bytes <= old) {
        return Ok(());
    }
    if new_bytes > quota.max_bytes.get() {
        return Err(RosterError::QuotaExceeded);
    }
    let (start, end) = owner_range(owner);
    let mut count = 0usize;
    let mut bytes = 0usize;
    for entry in items
        .range(start.as_ref()..end.as_ref())
        .map_err(storage_error)?
    {
        let (existing_key, value) = entry.map_err(storage_error)?;
        count = count.checked_add(1).ok_or(RosterError::QuotaExceeded)?;
        bytes = bytes
            .checked_add(existing_key.value().len())
            .and_then(|n| n.checked_add(value.value().len()))
            .ok_or(RosterError::QuotaExceeded)?;
        if count > quota.max_items.get()
            || bytes.saturating_sub(old_bytes.unwrap_or(0)) > quota.max_bytes.get()
        {
            return Err(RosterError::QuotaExceeded);
        }
    }
    let next_count = count
        .checked_add(usize::from(old_bytes.is_none()))
        .ok_or(RosterError::QuotaExceeded)?;
    let next_bytes = bytes
        .checked_sub(old_bytes.unwrap_or(0))
        .and_then(|n| n.checked_add(new_bytes))
        .ok_or(RosterError::QuotaExceeded)?;
    if next_count > quota.max_items.get() || next_bytes > quota.max_bytes.get() {
        return Err(RosterError::QuotaExceeded);
    }
    Ok(())
}

fn encoded_item_size(item: &RosterItem) -> Result<usize, RosterError> {
    let groups_len = item
        .groups
        .iter()
        .try_fold(0usize, |len, group| {
            len.checked_add(4).and_then(|n| n.checked_add(group.len()))
        })
        .ok_or(RosterError::ValueTooLarge)?;
    10usize
        .checked_add(item.name.as_deref().map_or(0, str::len))
        .and_then(|n| n.checked_add(groups_len))
        .ok_or(RosterError::ValueTooLarge)
}

fn encode_subscription(subscription: RosterSubscription) -> [u8; 2] {
    [
        match subscription.state {
            super::SubscriptionState::None => 0,
            super::SubscriptionState::To => 1,
            super::SubscriptionState::From => 2,
            super::SubscriptionState::Both => 3,
        },
        u8::from(subscription.pending_out) | (u8::from(subscription.approved) << 1),
    ]
}

fn decode_subscription(bytes: &[u8]) -> Result<RosterSubscription, RosterError> {
    let mut bytes = bytes;
    let state = match take_byte(&mut bytes)? {
        0 => super::SubscriptionState::None,
        1 => super::SubscriptionState::To,
        2 => super::SubscriptionState::From,
        3 => super::SubscriptionState::Both,
        _ => return Err(StorageError::new(StorageErrorKind::CorruptData).into()),
    };
    let flags = take_byte(&mut bytes)?;
    if flags & !3 != 0 {
        return Err(StorageError::new(StorageErrorKind::CorruptData).into());
    }
    Ok(RosterSubscription {
        state,
        pending_out: flags & 1 != 0,
        approved: flags & 2 != 0,
    })
}

fn check_item(mut bytes: &[u8], quota: RosterQuota) -> Result<(), RosterError> {
    if bytes.len() > quota.max_bytes.get() {
        return Err(RosterError::QuotaExceeded);
    }
    take_byte(&mut bytes)?;
    take_byte(&mut bytes)?;
    let len = take_u32(&mut bytes)?;
    if len != u32::MAX {
        bytes = bytes
            .get(len as usize..)
            .ok_or_else(|| StorageError::new(StorageErrorKind::CorruptData))?;
    }
    if take_u32(&mut bytes)? as usize > MAX_GROUPS_PER_ITEM {
        return Err(RosterError::QuotaExceeded);
    }
    Ok(())
}

fn encode_item(item: &RosterItem) -> Result<Vec<u8>, RosterError> {
    let name_bytes = item.name.as_deref().map(str::as_bytes);
    let groups_bytes = item.groups.iter().map(|group| group.as_bytes());
    let capacity = encoded_item_size(item)?;
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

fn decode_item(jid: RosterJid, mut bytes: &[u8]) -> Result<RosterItem, StorageError> {
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
    if !bytes.is_empty() {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    Ok(RosterItem {
        jid,
        name,
        groups,
        subscription: RosterSubscription {
            state,
            pending_out: flags & 1 != 0,
            approved: flags & 2 != 0,
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
