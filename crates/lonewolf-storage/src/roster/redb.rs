// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use ::redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::{Jid, JidError, MAX_JID_LEN};

use super::{
    PendingResolution, PendingSubscription, RosterError, RosterItem, RosterItemUpdate, RosterJid,
    RosterMutation, RosterRepository, RosterSnapshot, RosterSubscription, RosterVersion,
    SubscriptionCancellation, SubscriptionRequestOutcome, SubscriptionState,
};
use crate::account::AccountKey;
use crate::redb::{begin_write, commit_error, storage_error};
use crate::{RedbDatabase, StorageError, StorageErrorKind};

const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("lonewolf_roster_items");
const VERSIONS: TableDefinition<&str, u64> = TableDefinition::new("lonewolf_roster_versions");
const PENDING: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lonewolf_roster_pending_subscriptions");

#[derive(Clone)]
pub struct RedbRosterRepository {
    database: RedbDatabase,
}

impl RedbRosterRepository {
    /// Opens the database and initializes the roster tables synchronously.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::from_database(RedbDatabase::open(path)?)
    }

    /// Initializes roster tables and shares the database operation limits.
    pub fn from_database(database: RedbDatabase) -> Result<Self, StorageError> {
        let transaction = begin_write(database.as_ref())?;
        transaction.open_table(ITEMS).map_err(storage_error)?;
        transaction.open_table(VERSIONS).map_err(storage_error)?;
        transaction.open_table(PENDING).map_err(storage_error)?;
        transaction.commit().map_err(commit_error)?;
        Ok(Self { database })
    }
}

impl RosterRepository for RedbRosterRepository {
    async fn snapshot(&self, owner: &AccountKey) -> Result<RosterSnapshot, RosterError> {
        let owner = Box::<str>::from(owner.as_str());
        self.database
            .read(move |database| {
                let transaction = database.begin_read().map_err(storage_error)?;
                let versions = transaction.open_table(VERSIONS).map_err(storage_error)?;
                let version = versions
                    .get(owner.as_ref())
                    .map_err(storage_error)?
                    .map_or(0, |version| version.value());
                let items = transaction.open_table(ITEMS).map_err(storage_error)?;
                let (start, end) = owner_range(&owner);
                let mut roster = Vec::new();
                for entry in items
                    .range(start.as_ref()..end.as_ref())
                    .map_err(storage_error)?
                {
                    let (key, value) = entry.map_err(storage_error)?;
                    let jid = decode_key(&owner, key.value())?;
                    roster.push(decode_item(jid, value.value())?);
                }
                Ok::<_, StorageError>(RosterSnapshot {
                    version: RosterVersion(version),
                    items: roster,
                })
            })
            .await
            .map_err(Into::into)
    }

    async fn get(
        &self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> Result<Option<RosterItem>, RosterError> {
        let key = item_key(owner, jid);
        let jid = jid.clone();
        self.database
            .read(move |database| {
                let transaction = database.begin_read().map_err(storage_error)?;
                let table = transaction.open_table(ITEMS).map_err(storage_error)?;
                table
                    .get(key.as_ref())
                    .map_err(storage_error)?
                    .map(|record| decode_item(jid, record.value()))
                    .transpose()
            })
            .await
            .map_err(Into::into)
    }

    async fn upsert(
        &self,
        owner: &AccountKey,
        item: RosterItemUpdate,
    ) -> Result<RosterMutation<RosterItem>, RosterError> {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, &item.jid);
        self.database
            .write(move |database| upsert(database, &owner, key, item))
            .await
    }

    async fn update_subscription<F>(
        &self,
        owner: &AccountKey,
        jid: &RosterJid,
        update: F,
    ) -> Result<Option<RosterMutation<RosterItem>>, RosterError>
    where
        F: FnOnce(RosterSubscription) -> Option<RosterSubscription> + Send + 'static,
    {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, jid);
        let jid = jid.clone();
        self.database
            .write(move |database| update_subscription(database, &owner, key, jid, update))
            .await
    }

    async fn request_subscription(
        &self,
        subscriber: &AccountKey,
        contact: &RosterJid,
        recipient: &AccountKey,
        request: PendingSubscription,
    ) -> Result<SubscriptionRequestOutcome, RosterError> {
        let subscriber = Box::<str>::from(subscriber.as_str());
        let roster_key = item_key_text(&subscriber, contact);
        let contact = contact.clone();
        let pending_key = item_key(recipient, &request.sender);
        self.database
            .write(move |database| {
                request_subscription(
                    database,
                    &subscriber,
                    roster_key,
                    contact,
                    pending_key,
                    request,
                )
            })
            .await
    }

    async fn cancel_subscription(
        &self,
        grantor: &AccountKey,
        contact: &RosterJid,
        subscriber: &AccountKey,
        grantor_jid: &RosterJid,
    ) -> Result<SubscriptionCancellation, RosterError> {
        let grantor = Box::<str>::from(grantor.as_str());
        let subscriber = Box::<str>::from(subscriber.as_str());
        let grantor_key = item_key_text(&grantor, contact);
        let subscriber_key = item_key_text(&subscriber, grantor_jid);
        let contact = contact.clone();
        let grantor_jid = grantor_jid.clone();
        self.database
            .write(move |database| {
                cancel_subscription(
                    database,
                    &grantor,
                    grantor_key,
                    contact,
                    &subscriber,
                    subscriber_key,
                    grantor_jid,
                )
            })
            .await
    }

    async fn remove(
        &self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> Result<Option<RosterMutation<RosterItem>>, RosterError> {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, jid);
        let jid = jid.clone();
        self.database
            .write(move |database| remove(database, &owner, key, jid))
            .await
    }

    async fn put_pending(
        &self,
        owner: &AccountKey,
        subscription: PendingSubscription,
    ) -> Result<(), RosterError> {
        let key = item_key(owner, &subscription.sender);
        self.database
            .write(move |database| {
                let transaction = begin_write(database)?;
                transaction
                    .open_table(PENDING)
                    .map_err(storage_error)?
                    .insert(key.as_ref(), subscription.stanza.as_ref())
                    .map_err(storage_error)?;
                transaction.commit().map_err(commit_error)?;
                Ok(())
            })
            .await
    }

    async fn pending(&self, owner: &AccountKey) -> Result<Vec<PendingSubscription>, RosterError> {
        let owner = Box::<str>::from(owner.as_str());
        self.database
            .read(move |database| {
                let transaction = database.begin_read().map_err(storage_error)?;
                let table = transaction.open_table(PENDING).map_err(storage_error)?;
                let (start, end) = owner_range(&owner);
                let mut pending = Vec::new();
                for entry in table
                    .range(start.as_ref()..end.as_ref())
                    .map_err(storage_error)?
                {
                    let (key, stanza) = entry.map_err(storage_error)?;
                    pending.push(PendingSubscription {
                        sender: decode_key(&owner, key.value())?,
                        stanza: Box::from(stanza.value()),
                    });
                }
                Ok::<_, StorageError>(pending)
            })
            .await
            .map_err(Into::into)
    }

    async fn resolve_pending<F>(
        &self,
        owner: &AccountKey,
        sender: &RosterJid,
        update: F,
    ) -> Result<Option<PendingResolution>, RosterError>
    where
        F: FnOnce(RosterSubscription) -> Option<RosterSubscription> + Send + 'static,
    {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, sender);
        let sender = sender.clone();
        self.database
            .write(move |database| resolve_pending(database, &owner, key, sender, update))
            .await
    }

    async fn remove_pending(
        &self,
        owner: &AccountKey,
        sender: &RosterJid,
    ) -> Result<bool, RosterError> {
        let key = item_key(owner, sender);
        self.database
            .write(move |database| {
                let transaction = begin_write(database)?;
                let removed = transaction
                    .open_table(PENDING)
                    .map_err(storage_error)?
                    .remove(key.as_ref())
                    .map_err(storage_error)?
                    .is_some();
                if removed {
                    transaction.commit().map_err(commit_error)?;
                }
                Ok(removed)
            })
            .await
    }

    async fn delete_all(&self, owner: &AccountKey) -> Result<(), RosterError> {
        let owner = Box::<str>::from(owner.as_str());
        self.database
            .write(move |database| {
                let transaction = begin_write(database)?;
                let (start, end) = owner_range(&owner);
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
                    .remove(owner.as_ref())
                    .map_err(storage_error)?;
                transaction.commit().map_err(commit_error)?;
                Ok(())
            })
            .await
    }
}

fn remove(
    database: &::redb::Database,
    owner: &str,
    key: Box<str>,
    jid: RosterJid,
) -> Result<Option<RosterMutation<RosterItem>>, RosterError> {
    let transaction = begin_write(database)?;
    let item = {
        let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
        let Some(record) = table.remove(key.as_ref()).map_err(storage_error)? else {
            return Ok(None);
        };
        decode_item(jid, record.value())?
    };
    let version = advance_version(&transaction, owner)?;
    transaction.commit().map_err(commit_error)?;
    Ok(Some(RosterMutation {
        version,
        value: item,
    }))
}

fn update_subscription<F>(
    database: &::redb::Database,
    owner: &str,
    key: Box<str>,
    jid: RosterJid,
    update: F,
) -> Result<Option<RosterMutation<RosterItem>>, RosterError>
where
    F: FnOnce(RosterSubscription) -> Option<RosterSubscription>,
{
    let transaction = begin_write(database)?;
    let item = {
        let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
        let mut item = table
            .get(key.as_ref())
            .map_err(storage_error)?
            .map(|record| decode_item(jid.clone(), record.value()))
            .transpose()?
            .unwrap_or(RosterItem {
                jid,
                name: None,
                groups: Vec::new(),
                subscription: RosterSubscription::default(),
            });
        let Some(subscription) = update(item.subscription) else {
            return Ok(None);
        };
        item.subscription = subscription;
        let encoded = encode_item(&item)?;
        table
            .insert(key.as_ref(), encoded.as_slice())
            .map_err(storage_error)?;
        item
    };
    let version = advance_version(&transaction, owner)?;
    transaction.commit().map_err(commit_error)?;
    Ok(Some(RosterMutation {
        version,
        value: item,
    }))
}

fn request_subscription(
    database: &::redb::Database,
    subscriber: &str,
    roster_key: Box<str>,
    contact: RosterJid,
    pending_key: Box<str>,
    request: PendingSubscription,
) -> Result<SubscriptionRequestOutcome, RosterError> {
    let transaction = begin_write(database)?;
    let auto_approve = transaction
        .open_table(ITEMS)
        .map_err(storage_error)?
        .get(pending_key.as_ref())
        .map_err(storage_error)?
        .map(|record| decode_item(request.sender.clone(), record.value()))
        .transpose()?
        .is_some_and(|item| {
            matches!(
                item.subscription.state,
                SubscriptionState::From | SubscriptionState::Both
            )
        });
    if auto_approve {
        let item = {
            let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
            let item = table
                .get(roster_key.as_ref())
                .map_err(storage_error)?
                .map(|record| decode_item(contact, record.value()))
                .transpose()?;
            match item {
                Some(mut item) => {
                    if let Some(subscription) = item.subscription.approve_pending_out() {
                        item.subscription = subscription;
                        let encoded = encode_item(&item)?;
                        table
                            .insert(roster_key.as_ref(), encoded.as_slice())
                            .map_err(storage_error)?;
                        Some(item)
                    } else {
                        None
                    }
                }
                None => None,
            }
        };
        let mutation = match item {
            Some(value) => Some(RosterMutation {
                version: advance_version(&transaction, subscriber)?,
                value,
            }),
            None => None,
        };
        if mutation.is_some() {
            transaction.commit().map_err(commit_error)?;
        }
        return Ok(SubscriptionRequestOutcome::AutoApprove { mutation });
    }
    transaction
        .open_table(PENDING)
        .map_err(storage_error)?
        .insert(pending_key.as_ref(), request.stanza.as_ref())
        .map_err(storage_error)?;
    let item = {
        let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
        let mut item = table
            .get(roster_key.as_ref())
            .map_err(storage_error)?
            .map(|record| decode_item(contact.clone(), record.value()))
            .transpose()?
            .unwrap_or(RosterItem {
                jid: contact,
                name: None,
                groups: Vec::new(),
                subscription: RosterSubscription::default(),
            });
        if item.subscription.pending_out
            || matches!(
                item.subscription.state,
                SubscriptionState::To | SubscriptionState::Both
            )
        {
            None
        } else {
            item.subscription.pending_out = true;
            let encoded = encode_item(&item)?;
            table
                .insert(roster_key.as_ref(), encoded.as_slice())
                .map_err(storage_error)?;
            Some(item)
        }
    };
    let mutation = match item {
        Some(value) => Some(RosterMutation {
            version: advance_version(&transaction, subscriber)?,
            value,
        }),
        None => None,
    };
    transaction.commit().map_err(commit_error)?;
    Ok(SubscriptionRequestOutcome::Pending { mutation })
}

fn cancel_subscription(
    database: &::redb::Database,
    grantor: &str,
    grantor_key: Box<str>,
    contact: RosterJid,
    subscriber: &str,
    subscriber_key: Box<str>,
    grantor_jid: RosterJid,
) -> Result<SubscriptionCancellation, RosterError> {
    let transaction = begin_write(database)?;
    let pending = transaction
        .open_table(PENDING)
        .map_err(storage_error)?
        .remove(grantor_key.as_ref())
        .map_err(storage_error)?
        .is_some();
    let grantor_state = transaction
        .open_table(ITEMS)
        .map_err(storage_error)?
        .get(grantor_key.as_ref())
        .map_err(storage_error)?
        .map(|record| decode_item(contact.clone(), record.value()))
        .transpose()?
        .map(|item| item.subscription);
    let send_unavailable = grantor_state.is_some_and(|subscription| {
        matches!(
            subscription.state,
            SubscriptionState::From | SubscriptionState::Both
        )
    });
    let route = pending || send_unavailable;
    let grantor_mutation = update_existing_subscription(
        &transaction,
        grantor,
        grantor_key.as_ref(),
        contact,
        |mut subscription| {
            subscription.state = match subscription.state {
                SubscriptionState::From => SubscriptionState::None,
                SubscriptionState::Both => SubscriptionState::To,
                state => state,
            };
            subscription.approved = false;
            (Some(subscription) != grantor_state).then_some(subscription)
        },
    )?;
    let subscriber_mutation = if route {
        update_existing_subscription(
            &transaction,
            subscriber,
            subscriber_key.as_ref(),
            grantor_jid,
            |mut subscription| {
                let old = subscription;
                subscription.state = match subscription.state {
                    SubscriptionState::To => SubscriptionState::None,
                    SubscriptionState::Both => SubscriptionState::From,
                    state => state,
                };
                subscription.pending_out = false;
                (subscription != old).then_some(subscription)
            },
        )?
    } else {
        None
    };
    if pending || grantor_mutation.is_some() || subscriber_mutation.is_some() {
        transaction.commit().map_err(commit_error)?;
    }
    Ok(SubscriptionCancellation {
        route,
        send_unavailable,
        grantor: grantor_mutation,
        subscriber: subscriber_mutation,
    })
}

fn update_existing_subscription(
    transaction: &WriteTransaction,
    owner: &str,
    key: &str,
    jid: RosterJid,
    update: impl FnOnce(RosterSubscription) -> Option<RosterSubscription>,
) -> Result<Option<RosterMutation<RosterItem>>, RosterError> {
    let item = {
        let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
        let mut item = {
            let Some(record) = table.get(key).map_err(storage_error)? else {
                return Ok(None);
            };
            decode_item(jid, record.value())?
        };
        let Some(subscription) = update(item.subscription) else {
            return Ok(None);
        };
        item.subscription = subscription;
        let encoded = encode_item(&item)?;
        table
            .insert(key, encoded.as_slice())
            .map_err(storage_error)?;
        item
    };
    let version = advance_version(transaction, owner)?;
    Ok(Some(RosterMutation {
        version,
        value: item,
    }))
}

fn resolve_pending<F>(
    database: &::redb::Database,
    owner: &str,
    key: Box<str>,
    sender: RosterJid,
    update: F,
) -> Result<Option<PendingResolution>, RosterError>
where
    F: FnOnce(RosterSubscription) -> Option<RosterSubscription>,
{
    let transaction = begin_write(database)?;
    let existed = transaction
        .open_table(PENDING)
        .map_err(storage_error)?
        .remove(key.as_ref())
        .map_err(storage_error)?
        .is_some();
    if !existed {
        return Ok(None);
    }
    let item = {
        let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
        let mut item = match table.get(key.as_ref()).map_err(storage_error)? {
            Some(record) => decode_item(sender, record.value())?,
            None => RosterItem {
                jid: sender,
                name: None,
                groups: Vec::new(),
                subscription: RosterSubscription::default(),
            },
        };
        match update(item.subscription) {
            Some(subscription) => {
                item.subscription = subscription;
                let encoded = encode_item(&item)?;
                table
                    .insert(key.as_ref(), encoded.as_slice())
                    .map_err(storage_error)?;
                Some(item)
            }
            None => None,
        }
    };
    let mutation = match item {
        Some(value) => Some(RosterMutation {
            version: advance_version(&transaction, owner)?,
            value,
        }),
        None => None,
    };
    transaction.commit().map_err(commit_error)?;
    Ok(Some(PendingResolution { mutation }))
}

fn upsert(
    database: &::redb::Database,
    owner: &str,
    key: Box<str>,
    update: RosterItemUpdate,
) -> Result<RosterMutation<RosterItem>, RosterError> {
    let transaction = begin_write(database)?;
    let item = {
        let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
        let subscription = table
            .get(key.as_ref())
            .map_err(storage_error)?
            .map(|record| decode_item(update.jid.clone(), record.value()))
            .transpose()?
            .map_or_else(RosterSubscription::default, |item| item.subscription);
        let item = RosterItem {
            jid: update.jid,
            name: update.name,
            groups: update.groups,
            subscription,
        };
        let encoded = encode_item(&item)?;
        table
            .insert(key.as_ref(), encoded.as_slice())
            .map_err(storage_error)?;
        item
    };
    let version = advance_version(&transaction, owner)?;
    transaction.commit().map_err(commit_error)?;
    Ok(RosterMutation {
        version,
        value: item,
    })
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
    let capacity = 10usize
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
