// SPDX-License-Identifier: Apache-2.0

//! RFC 6121 subscription state transitions, applied through one write transaction.

use lonewolf_storage::WriteTransaction;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::{
    PendingSubscription, RosterError, RosterItem, RosterJid, RosterMutation, RosterSubscription,
    RosterVersion, SubscriptionState,
};

pub(super) type ItemMutation = Option<RosterMutation<RosterItem>>;

/// How a subscription request was filed.
pub(super) enum RequestOutcome {
    /// The contact already grants the requester; `approved` is the requester's item once
    /// its outstanding request resolved, or `None` when it recorded none.
    AutoApproved { approved: ItemMutation },
    /// The contact had pre-approved the requester, so the request is answered on the
    /// contact's behalf: `grantor` is the contact's item, now granting without the
    /// pre-approval, and `requester` the requester's item once it sees the contact.
    PreApproved {
        grantor: ItemMutation,
        requester: ItemMutation,
    },
    /// The request waits for the contact; `push` is the requester's item when it newly
    /// records the outstanding request.
    Pending { push: ItemMutation },
    /// The contact's account is gone, so the request cannot be stored for it.
    ContactMissing,
}

/// The effects of a grantor cancelling a contact's subscription.
pub(super) struct Cancellation {
    /// Whether the cancellation reaches the contact: it held a grant or a pending request.
    pub route: bool,
    /// Whether the grantor's presence was visible to the contact until now.
    pub send_unavailable: bool,
    pub grantor: ItemMutation,
    pub subscriber: ItemMutation,
}

/// The effects of a subscriber withdrawing from a contact.
pub(super) struct Withdrawal {
    /// Whether the contact granted the subscriber and so learns of the withdrawal.
    pub notify_contact: bool,
    pub subscriber: ItemMutation,
    pub contact: ItemMutation,
}

/// The effects of removing a roster item.
pub(super) struct Removal {
    /// The owner's roster version after the removal.
    pub version: RosterVersion,
    /// The removed item's subscription, the owner's own grant to the contact.
    pub subscription: RosterSubscription,
    /// Whether the contact had a subscription request pending with the owner.
    pub pending_request: bool,
    /// The contact's subscription to the owner before the removal, when it held an item.
    pub contact_before: Option<RosterSubscription>,
    /// The contact's item after losing every subscription to the owner.
    pub contact: ItemMutation,
}

pub(super) fn grants(state: SubscriptionState) -> bool {
    matches!(state, SubscriptionState::From | SubscriptionState::Both)
}

fn subscribed_to(state: SubscriptionState) -> bool {
    matches!(state, SubscriptionState::To | SubscriptionState::Both)
}

pub(super) fn bare_item(jid: RosterJid) -> RosterItem {
    RosterItem {
        jid,
        name: None,
        groups: Vec::new(),
        subscription: RosterSubscription::default(),
    }
}

/// Resolves the owner's outstanding request: the owner now sees the contact.
pub(super) fn approve_pending_out(
    mut subscription: RosterSubscription,
) -> Option<RosterSubscription> {
    if !subscription.pending_out {
        return None;
    }
    subscription.state = match subscription.state {
        SubscriptionState::None => SubscriptionState::To,
        SubscriptionState::From => SubscriptionState::Both,
        SubscriptionState::To | SubscriptionState::Both => return None,
    };
    subscription.pending_out = false;
    Some(subscription)
}

/// Notes the owner's pre-approval of a contact it does not grant yet (RFC 6121 §3.4.2).
pub(super) fn pre_approve(mut subscription: RosterSubscription) -> Option<RosterSubscription> {
    if grants(subscription.state) || subscription.approved {
        return None;
    }
    subscription.approved = true;
    Some(subscription)
}

/// Grants the contact the owner's presence.
pub(super) fn grant(mut subscription: RosterSubscription) -> Option<RosterSubscription> {
    subscription.state = match subscription.state {
        SubscriptionState::None => SubscriptionState::From,
        SubscriptionState::To => SubscriptionState::Both,
        SubscriptionState::From | SubscriptionState::Both => return None,
    };
    Some(subscription)
}

/// Applies `update` to the owner's item for `jid`, creating a bare item when absent, and
/// writes the item when `update` returns a new subscription.
pub(super) async fn update_subscription<W: WriteTransaction>(
    transaction: &mut W,
    owner: &AccountKey,
    jid: &RosterJid,
    update: impl FnOnce(RosterSubscription) -> Option<RosterSubscription>,
) -> Result<ItemMutation, RosterError> {
    let item = transaction
        .roster_item(owner, jid)
        .await?
        .unwrap_or_else(|| bare_item(jid.clone()));
    write_subscription(transaction, owner, item, update).await
}

/// Like [`update_subscription`], but leaves an absent item absent.
pub(super) async fn update_existing_subscription<W: WriteTransaction>(
    transaction: &mut W,
    owner: &AccountKey,
    jid: &RosterJid,
    update: impl FnOnce(RosterSubscription) -> Option<RosterSubscription>,
) -> Result<ItemMutation, RosterError> {
    let Some(item) = transaction.roster_item(owner, jid).await? else {
        return Ok(None);
    };
    write_subscription(transaction, owner, item, update).await
}

async fn write_subscription<W: WriteTransaction>(
    transaction: &mut W,
    owner: &AccountKey,
    mut item: RosterItem,
    update: impl FnOnce(RosterSubscription) -> Option<RosterSubscription>,
) -> Result<ItemMutation, RosterError> {
    let Some(subscription) = update(item.subscription) else {
        return Ok(None);
    };
    item.subscription = subscription;
    let version = transaction.put_roster_item(owner, &item).await?;
    Ok(Some(RosterMutation {
        version,
        value: item,
    }))
}

/// Removes the request `sender` left with the owner and applies `update` to the owner's
/// item for it. Returns `None` without writing when no request was pending.
pub(super) async fn resolve_pending<W: WriteTransaction>(
    transaction: &mut W,
    owner: &AccountKey,
    sender: &RosterJid,
    update: impl FnOnce(RosterSubscription) -> Option<RosterSubscription>,
) -> Result<ItemMutation, RosterError> {
    if !transaction.remove_pending_request(owner, sender).await? {
        return Ok(None);
    }
    update_subscription(transaction, owner, sender, update).await
}

/// Files `requester`'s request to see `contact`, a stored local account.
pub(super) async fn request_subscription<W: WriteTransaction>(
    transaction: &mut W,
    requester: &AccountKey,
    requester_jid: RosterJid,
    contact: &AccountKey,
    contact_jid: &RosterJid,
    stanza: Box<[u8]>,
) -> Result<RequestOutcome, RosterError> {
    let contact_view = transaction
        .roster_item(contact, &requester_jid)
        .await?
        .map(|item| item.subscription);
    if contact_view.is_some_and(|subscription| grants(subscription.state)) {
        let approved =
            update_existing_subscription(transaction, requester, contact_jid, approve_pending_out)
                .await?;
        return Ok(RequestOutcome::AutoApproved { approved });
    }
    if contact_view.is_some_and(|subscription| subscription.approved) {
        let grantor =
            update_existing_subscription(transaction, contact, &requester_jid, |subscription| {
                let mut granted = grant(subscription)?;
                granted.approved = false;
                Some(granted)
            })
            .await?;
        let requester =
            update_subscription(transaction, requester, contact_jid, |mut subscription| {
                subscription.state = match subscription.state {
                    SubscriptionState::None => SubscriptionState::To,
                    SubscriptionState::From => SubscriptionState::Both,
                    SubscriptionState::To | SubscriptionState::Both => return None,
                };
                subscription.pending_out = false;
                Some(subscription)
            })
            .await?;
        return Ok(RequestOutcome::PreApproved { grantor, requester });
    }
    let stored = transaction
        .put_pending_request(
            contact,
            PendingSubscription {
                sender: requester_jid,
                stanza,
            },
        )
        .await;
    match stored {
        Ok(()) => {}
        Err(RosterError::NoAccount) => return Ok(RequestOutcome::ContactMissing),
        Err(error) => return Err(error),
    }
    let push = update_subscription(transaction, requester, contact_jid, |mut subscription| {
        if subscription.pending_out || subscribed_to(subscription.state) {
            return None;
        }
        subscription.pending_out = true;
        Some(subscription)
    })
    .await?;
    Ok(RequestOutcome::Pending { push })
}

/// Cancels the grant `grantor` gave `contact`, or denies the contact's pending request.
/// `subscriber` names the contact's local account and its view of the grantor, when stored.
pub(super) async fn cancel_subscription<W: WriteTransaction>(
    transaction: &mut W,
    grantor: &AccountKey,
    contact: &RosterJid,
    subscriber: Option<(&AccountKey, &RosterJid)>,
) -> Result<Cancellation, RosterError> {
    let pending = transaction.remove_pending_request(grantor, contact).await?;
    let granted = transaction
        .roster_item(grantor, contact)
        .await?
        .is_some_and(|item| grants(item.subscription.state));
    let route = subscriber.is_some() && (pending || granted);
    let send_unavailable = route && granted;
    let same_item = subscriber.is_some_and(|(account, _)| account == grantor);
    let grantor_mutation =
        update_existing_subscription(transaction, grantor, contact, |mut subscription| {
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
        })
        .await?;
    let subscriber_mutation = match subscriber {
        Some((account, grantor_jid)) if route && !same_item => {
            update_existing_subscription(transaction, account, grantor_jid, |mut subscription| {
                let old = subscription;
                subscription.state = match subscription.state {
                    SubscriptionState::To => SubscriptionState::None,
                    SubscriptionState::Both => SubscriptionState::From,
                    state => state,
                };
                subscription.pending_out = false;
                (subscription != old).then_some(subscription)
            })
            .await?
        }
        _ => None,
    };
    Ok(Cancellation {
        route,
        send_unavailable,
        grantor: grantor_mutation,
        subscriber: subscriber_mutation,
    })
}

/// Withdraws `subscriber` from `contact`, or retracts its pending request.
/// `recipient` names the contact's local account and its view of the subscriber, when stored.
pub(super) async fn unsubscribe<W: WriteTransaction>(
    transaction: &mut W,
    subscriber: &AccountKey,
    contact: &RosterJid,
    recipient: Option<(&AccountKey, &RosterJid)>,
) -> Result<Withdrawal, RosterError> {
    let same_item = recipient.is_some_and(|(account, _)| account == subscriber);
    let notify_contact = match recipient {
        Some((account, subscriber_jid)) => {
            transaction
                .remove_pending_request(account, subscriber_jid)
                .await?;
            transaction
                .roster_item(account, subscriber_jid)
                .await?
                .is_some_and(|item| grants(item.subscription.state))
        }
        None => false,
    };
    let subscriber_mutation =
        update_existing_subscription(transaction, subscriber, contact, |mut subscription| {
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
        })
        .await?;
    let contact_mutation = match recipient {
        Some((account, subscriber_jid)) if notify_contact && !same_item => {
            update_existing_subscription(
                transaction,
                account,
                subscriber_jid,
                |mut subscription| {
                    let old = subscription;
                    subscription.state = match subscription.state {
                        SubscriptionState::From => SubscriptionState::None,
                        SubscriptionState::Both => SubscriptionState::To,
                        state => state,
                    };
                    (subscription != old).then_some(subscription)
                },
            )
            .await?
        }
        _ => None,
    };
    Ok(Withdrawal {
        notify_contact,
        subscriber: subscriber_mutation,
        contact: contact_mutation,
    })
}

/// Removes the owner's item for `contact`, drops pending requests in both directions, and
/// clears the local contact's subscription to the owner. Returns `None` without writing
/// when the item is absent.
pub(super) async fn remove_item<W: WriteTransaction>(
    transaction: &mut W,
    owner: &AccountKey,
    owner_jid: &RosterJid,
    contact: &RosterJid,
    contact_account: Option<&AccountKey>,
) -> Result<Option<Removal>, RosterError> {
    let Some(removed) = transaction.remove_roster_item(owner, contact).await? else {
        return Ok(None);
    };
    let pending_request = transaction.remove_pending_request(owner, contact).await?;
    let mut contact_before = None;
    let contact_mutation = match contact_account {
        Some(account) if account != owner => {
            transaction
                .remove_pending_request(account, owner_jid)
                .await?;
            update_existing_subscription(transaction, account, owner_jid, |old| {
                contact_before = Some(old);
                // The pre-approval is the contact's own decision, so only the contact clears it.
                let cleared = RosterSubscription {
                    state: SubscriptionState::None,
                    pending_out: false,
                    approved: old.approved,
                };
                (old != cleared).then_some(cleared)
            })
            .await?
        }
        _ => None,
    };
    Ok(Some(Removal {
        version: removed.version,
        subscription: removed.value.subscription,
        pending_request,
        contact_before,
        contact: contact_mutation,
    }))
}
