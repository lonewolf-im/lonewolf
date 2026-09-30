// SPDX-License-Identifier: Apache-2.0

use std::future::Future;

use ::redb::{ReadableTable, TableDefinition, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::{Jid, JidError, MAX_JID_LEN};

use super::{
    ItemRemoval, PendingResolution, PendingSubscription, RosterError, RosterItem, RosterItemUpdate,
    RosterJid, RosterMutation, RosterReads, RosterSnapshot, RosterSubscription, RosterVersion,
    RosterWrites, SubscriptionCancellation, SubscriptionRequestOutcome, SubscriptionState,
    SubscriptionWithdrawal,
};
use crate::account::AccountKey;
use crate::redb::{RedbRead, RedbWrite, storage_error};
use crate::{StorageError, StorageErrorKind};

pub(crate) const ITEMS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lonewolf_roster_items");
pub(crate) const VERSIONS: TableDefinition<&str, u64> =
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
                    read_item(&table, &key, jid)
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
    fn upsert(
        &mut self,
        owner: &AccountKey,
        item: RosterItemUpdate,
    ) -> impl Future<Output = Result<RosterMutation<RosterItem>, RosterError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, &item.jid);
        self.run(move |transaction| upsert(transaction, &owner, key, item))
    }

    fn update_subscription<F>(
        &mut self,
        owner: &AccountKey,
        jid: &RosterJid,
        update: F,
    ) -> impl Future<Output = Result<Option<RosterMutation<RosterItem>>, RosterError>> + Send
    where
        F: FnOnce(RosterSubscription) -> Option<RosterSubscription> + Send + 'static,
    {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, jid);
        let jid = jid.clone();
        self.run(move |transaction| update_subscription(transaction, &owner, key, jid, update))
    }

    fn request_subscription(
        &mut self,
        subscriber: &AccountKey,
        contact: &RosterJid,
        recipient: &AccountKey,
        request: PendingSubscription,
    ) -> impl Future<Output = Result<SubscriptionRequestOutcome, RosterError>> + Send {
        let subscriber = Box::<str>::from(subscriber.as_str());
        let roster_key = item_key_text(&subscriber, contact);
        let contact = contact.clone();
        let pending_key = item_key(recipient, &request.sender);
        self.run(move |transaction| {
            request_subscription(
                transaction,
                &subscriber,
                roster_key,
                contact,
                pending_key,
                request,
            )
        })
    }

    fn cancel_subscription(
        &mut self,
        grantor: &AccountKey,
        contact: &RosterJid,
        subscriber: Option<(&AccountKey, &RosterJid)>,
    ) -> impl Future<Output = Result<SubscriptionCancellation, RosterError>> + Send {
        let grantor = Box::<str>::from(grantor.as_str());
        let grantor_key = item_key_text(&grantor, contact);
        let contact = contact.clone();
        let subscriber = subscriber.map(|(account, jid)| {
            let account = Box::<str>::from(account.as_str());
            let key = item_key_text(&account, jid);
            (account, key, jid.clone())
        });
        self.run(move |transaction| {
            cancel_subscription(transaction, &grantor, grantor_key, contact, subscriber)
        })
    }

    fn unsubscribe(
        &mut self,
        subscriber: &AccountKey,
        contact: &RosterJid,
        recipient: Option<(&AccountKey, &RosterJid)>,
    ) -> impl Future<Output = Result<SubscriptionWithdrawal, RosterError>> + Send {
        let subscriber = Box::<str>::from(subscriber.as_str());
        let subscriber_key = item_key_text(&subscriber, contact);
        let contact = contact.clone();
        let recipient = recipient.map(|(account, jid)| {
            let account = Box::<str>::from(account.as_str());
            let key = item_key_text(&account, jid);
            (account, key, jid.clone())
        });
        self.run(move |transaction| {
            unsubscribe(transaction, &subscriber, subscriber_key, contact, recipient)
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

    fn remove_item(
        &mut self,
        owner: &AccountKey,
        contact: &RosterJid,
        contact_account: Option<(&AccountKey, &RosterJid)>,
    ) -> impl Future<Output = Result<Option<ItemRemoval>, RosterError>> + Send {
        let owner = Box::<str>::from(owner.as_str());
        let owner_key = item_key_text(&owner, contact);
        let contact = contact.clone();
        let contact_side = contact_account.map(|(account, owner_jid)| {
            let account = Box::<str>::from(account.as_str());
            let key = item_key_text(&account, owner_jid);
            (account, key, owner_jid.clone())
        });
        self.run(move |transaction| {
            remove_item(transaction, &owner, owner_key, contact, contact_side)
        })
    }

    fn put_pending_request(
        &mut self,
        owner: &AccountKey,
        request: PendingSubscription,
    ) -> impl Future<Output = Result<(), RosterError>> + Send {
        let key = item_key(owner, &request.sender);
        self.run(move |transaction| {
            transaction
                .open_table(PENDING)
                .map_err(storage_error)?
                .insert(key.as_ref(), request.stanza.as_ref())
                .map_err(storage_error)?;
            Ok(())
        })
    }

    fn resolve_pending<F>(
        &mut self,
        owner: &AccountKey,
        sender: &RosterJid,
        update: F,
    ) -> impl Future<Output = Result<Option<PendingResolution>, RosterError>> + Send
    where
        F: FnOnce(RosterSubscription) -> Option<RosterSubscription> + Send + 'static,
    {
        let owner = Box::<str>::from(owner.as_str());
        let key = item_key_text(&owner, sender);
        let sender = sender.clone();
        self.run(move |transaction| resolve_pending(transaction, &owner, key, sender, update))
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
    V: ReadableTable<&'static str, u64>,
    I: ReadableTable<&'static str, &'static [u8]>,
{
    let version = versions
        .get(owner)
        .map_err(storage_error)?
        .map_or(0, |version| version.value());
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
        items: roster,
    })
}

fn read_item<T: ReadableTable<&'static str, &'static [u8]>>(
    table: &T,
    key: &str,
    jid: RosterJid,
) -> Result<Option<RosterItem>, RosterError> {
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
        decode_item(jid, record.value())?
    };
    let version = advance_version(transaction, owner)?;
    Ok(Some(RosterMutation {
        version,
        value: item,
    }))
}

fn remove_item(
    transaction: &WriteTransaction,
    owner: &str,
    owner_key: Box<str>,
    contact: RosterJid,
    contact_side: Option<(Box<str>, Box<str>, RosterJid)>,
) -> Result<Option<ItemRemoval>, RosterError> {
    let removed = {
        let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
        let Some(record) = table.remove(owner_key.as_ref()).map_err(storage_error)? else {
            return Ok(None);
        };
        decode_item(contact, record.value())?
    };
    let pending_request = transaction
        .open_table(PENDING)
        .map_err(storage_error)?
        .remove(owner_key.as_ref())
        .map_err(storage_error)?
        .is_some();
    let version = advance_version(transaction, owner)?;
    let mut contact_before = None;
    let contact_mutation = match contact_side {
        Some((account, key, owner_jid)) if key.as_ref() != owner_key.as_ref() => {
            transaction
                .open_table(PENDING)
                .map_err(storage_error)?
                .remove(key.as_ref())
                .map_err(storage_error)?;
            update_existing_subscription(transaction, &account, key.as_ref(), owner_jid, |old| {
                contact_before = Some(old);
                // The pre-approval is the contact's own decision, so only the contact clears it.
                let cleared = RosterSubscription {
                    state: SubscriptionState::None,
                    pending_out: false,
                    approved: old.approved,
                };
                (old != cleared).then_some(cleared)
            })?
        }
        _ => None,
    };
    Ok(Some(ItemRemoval {
        version,
        subscription: removed.subscription,
        pending_request,
        contact_before,
        contact: contact_mutation,
    }))
}

fn update_subscription<F>(
    transaction: &WriteTransaction,
    owner: &str,
    key: Box<str>,
    jid: RosterJid,
    update: F,
) -> Result<Option<RosterMutation<RosterItem>>, RosterError>
where
    F: FnOnce(RosterSubscription) -> Option<RosterSubscription>,
{
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
    let version = advance_version(transaction, owner)?;
    Ok(Some(RosterMutation {
        version,
        value: item,
    }))
}

fn request_subscription(
    transaction: &WriteTransaction,
    subscriber: &str,
    roster_key: Box<str>,
    contact: RosterJid,
    pending_key: Box<str>,
    request: PendingSubscription,
) -> Result<SubscriptionRequestOutcome, RosterError> {
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
                version: advance_version(transaction, subscriber)?,
                value,
            }),
            None => None,
        };
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
            version: advance_version(transaction, subscriber)?,
            value,
        }),
        None => None,
    };
    Ok(SubscriptionRequestOutcome::Pending { mutation })
}

fn cancel_subscription(
    transaction: &WriteTransaction,
    grantor: &str,
    grantor_key: Box<str>,
    contact: RosterJid,
    subscriber: Option<(Box<str>, Box<str>, RosterJid)>,
) -> Result<SubscriptionCancellation, RosterError> {
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
    let granted = grantor_state.is_some_and(|subscription| {
        matches!(
            subscription.state,
            SubscriptionState::From | SubscriptionState::Both
        )
    });
    let route = subscriber.is_some() && (pending || granted);
    let send_unavailable = route && granted;
    let same_item = subscriber
        .as_ref()
        .is_some_and(|(_, key, _)| key.as_ref() == grantor_key.as_ref());
    let grantor_mutation = update_existing_subscription(
        transaction,
        grantor,
        grantor_key.as_ref(),
        contact,
        |mut subscription| {
            let old = subscription;
            subscription.state = match subscription.state {
                SubscriptionState::From => SubscriptionState::None,
                SubscriptionState::Both => SubscriptionState::To,
                state => state,
            };
            subscription.approved = false;
            if same_item && route {
                subscription.state = match subscription.state {
                    SubscriptionState::To => SubscriptionState::None,
                    SubscriptionState::Both => SubscriptionState::From,
                    state => state,
                };
                subscription.pending_out = false;
            }
            (subscription != old).then_some(subscription)
        },
    )?;
    let subscriber_mutation = if let Some((subscriber, subscriber_key, grantor_jid)) = subscriber
        && route
        && !same_item
    {
        update_existing_subscription(
            transaction,
            &subscriber,
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
    Ok(SubscriptionCancellation {
        route,
        send_unavailable,
        grantor: grantor_mutation,
        subscriber: subscriber_mutation,
    })
}

fn unsubscribe(
    transaction: &WriteTransaction,
    subscriber: &str,
    subscriber_key: Box<str>,
    contact: RosterJid,
    recipient: Option<(Box<str>, Box<str>, RosterJid)>,
) -> Result<SubscriptionWithdrawal, RosterError> {
    let same_item = recipient
        .as_ref()
        .is_some_and(|(_, key, _)| key.as_ref() == subscriber_key.as_ref());
    let notify_contact = if let Some((_, key, jid)) = recipient.as_ref() {
        transaction
            .open_table(ITEMS)
            .map_err(storage_error)?
            .get(key.as_ref())
            .map_err(storage_error)?
            .map(|record| decode_item(jid.clone(), record.value()))
            .transpose()?
            .is_some_and(|item| {
                matches!(
                    item.subscription.state,
                    SubscriptionState::From | SubscriptionState::Both
                )
            })
    } else {
        false
    };
    if let Some((_, key, _)) = recipient.as_ref() {
        transaction
            .open_table(PENDING)
            .map_err(storage_error)?
            .remove(key.as_ref())
            .map_err(storage_error)?;
    }
    let subscriber_mutation = update_existing_subscription(
        transaction,
        subscriber,
        subscriber_key.as_ref(),
        contact,
        |mut subscription| {
            let old = subscription;
            subscription.state = match subscription.state {
                SubscriptionState::To => SubscriptionState::None,
                SubscriptionState::Both => SubscriptionState::From,
                state => state,
            };
            subscription.pending_out = false;
            if same_item && notify_contact {
                subscription.state = match subscription.state {
                    SubscriptionState::From => SubscriptionState::None,
                    SubscriptionState::Both => SubscriptionState::To,
                    state => state,
                };
            }
            (subscription != old).then_some(subscription)
        },
    )?;
    let contact_mutation = if let Some((owner, key, jid)) = recipient
        && notify_contact
        && !same_item
    {
        update_existing_subscription(
            transaction,
            &owner,
            key.as_ref(),
            jid,
            |mut subscription| {
                let old = subscription;
                subscription.state = match subscription.state {
                    SubscriptionState::From => SubscriptionState::None,
                    SubscriptionState::Both => SubscriptionState::To,
                    state => state,
                };
                (subscription != old).then_some(subscription)
            },
        )?
    } else {
        None
    };
    Ok(SubscriptionWithdrawal {
        notify_contact,
        subscriber: subscriber_mutation,
        contact: contact_mutation,
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
    transaction: &WriteTransaction,
    owner: &str,
    key: Box<str>,
    sender: RosterJid,
    update: F,
) -> Result<Option<PendingResolution>, RosterError>
where
    F: FnOnce(RosterSubscription) -> Option<RosterSubscription>,
{
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
            version: advance_version(transaction, owner)?,
            value,
        }),
        None => None,
    };
    Ok(Some(PendingResolution { mutation }))
}

fn upsert(
    transaction: &WriteTransaction,
    owner: &str,
    key: Box<str>,
    update: RosterItemUpdate,
) -> Result<RosterMutation<RosterItem>, RosterError> {
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
    let version = advance_version(transaction, owner)?;
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
