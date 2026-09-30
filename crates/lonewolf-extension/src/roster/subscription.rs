// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::WriteTransaction;
use lonewolf_storage::account::{AccountKey, AccountReads};
use lonewolf_storage::roster::RosterJid;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaErrorCondition};

use super::state::{self, Cancellation, Removal, RequestOutcome, grants};
use super::{account_exists, push_removal, push_roster, require_account, xml};
use crate::Effects;
use crate::delivery::{Delivery, DeliveryError, HandlerError, HostLookup, SessionTag};
use crate::presence::PresenceRequest;

pub(super) struct Parties {
    sender: AccountKey,
    target: AccountKey,
    sender_jid: RosterJid,
    target_jid: RosterJid,
}

impl Parties {
    /// A domain-only target cannot hold a roster, so it is reported as unavailable.
    pub(super) fn new<A: ChunkAllocator>(
        request: &PresenceRequest<'_, A>,
    ) -> Result<Self, StanzaErrorCondition> {
        let sender = request.sender.bare();
        let target = request.target.bare();
        Ok(Self {
            sender: AccountKey::try_from(sender)
                .map_err(|_| StanzaErrorCondition::InternalServerError)?,
            target: AccountKey::try_from(target)
                .map_err(|_| StanzaErrorCondition::ServiceUnavailable)?,
            sender_jid: RosterJid::from(sender),
            target_jid: RosterJid::from(target),
        })
    }

    fn accounts(&self) -> Vec<AccountKey> {
        vec![self.sender.clone(), self.target.clone()]
    }
}

/// Refuses a sender whose account is gone and reports whether the target is stored.
async fn check_parties(
    transaction: &impl AccountReads,
    parties: &Parties,
) -> Result<bool, StanzaErrorCondition> {
    require_account(transaction, &parties.sender).await?;
    account_exists(transaction, &parties.target).await
}

pub(super) async fn request_subscription<A: ChunkAllocator, W: WriteTransaction>(
    transaction: &mut W,
    parties: Parties,
    stanza: &RoutedStanza<A>,
) -> Result<Effects<A>, HandlerError> {
    if !check_parties(transaction, &parties).await? {
        return Err(StanzaErrorCondition::ServiceUnavailable.into());
    }
    let mut request = String::new();
    stanza
        .resolve()
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
        .write_xml(&mut request)
        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    let accounts = parties.accounts();
    let Parties {
        sender,
        target,
        sender_jid,
        target_jid,
    } = parties;
    let outcome = match state::request_subscription(
        transaction,
        &sender,
        sender_jid,
        &target,
        &target_jid,
        request.into_bytes().into_boxed_slice(),
    )
    .await?
    {
        RequestOutcome::ContactMissing => {
            return Err(StanzaErrorCondition::ServiceUnavailable.into());
        }
        outcome => outcome,
    };
    let stanza = stanza.clone();
    Ok(Effects::new(accounts, move |delivery| {
        Box::pin(async move {
            match outcome {
                RequestOutcome::Pending { push } => {
                    delivery.to_available(stanza).await?;
                    if let Some(mutation) = push {
                        push_roster(&sender, mutation, delivery).await?;
                    }
                    Ok(())
                }
                RequestOutcome::AutoApproved {
                    approved: Some(mutation),
                } => {
                    let approval = xml::approval_reply(&stanza, delivery.arena()?)?;
                    delivery.to_tagged(SessionTag::Interested, approval).await?;
                    push_roster(&sender, mutation, delivery).await?;
                    delivery.current_presence(&target, &sender).await
                }
                RequestOutcome::AutoApproved { approved: None }
                | RequestOutcome::ContactMissing => Ok(()),
            }
        })
    }))
}

pub(super) async fn approve_subscription<A: ChunkAllocator, W: WriteTransaction>(
    transaction: &mut W,
    parties: Parties,
    stanza: &RoutedStanza<A>,
) -> Result<Effects<A>, HandlerError> {
    if !check_parties(transaction, &parties).await? {
        return Ok(Effects::none());
    }
    let accounts = parties.accounts();
    let Parties {
        sender,
        target,
        sender_jid,
        target_jid,
    } = parties;
    let target_mutation = state::update_subscription(
        transaction,
        &target,
        &sender_jid,
        state::approve_pending_out,
    )
    .await?;
    let sender_mutation =
        state::resolve_pending(transaction, &sender, &target_jid, state::grant).await?;
    let stanza = stanza.clone();
    Ok(Effects::new(accounts, move |delivery| {
        Box::pin(async move {
            if let Some(mutation) = target_mutation {
                delivery.to_tagged(SessionTag::Interested, stanza).await?;
                push_roster(&target, mutation, delivery).await?;
            }
            if let Some(mutation) = sender_mutation {
                push_roster(&sender, mutation, delivery).await?;
                delivery.current_presence(&sender, &target).await?;
            }
            Ok(())
        })
    }))
}

pub(super) async fn cancel_subscription<A: ChunkAllocator, W: WriteTransaction>(
    transaction: &mut W,
    parties: Parties,
    stanza: &RoutedStanza<A>,
) -> Result<Effects<A>, HandlerError> {
    let subscriber_exists = check_parties(transaction, &parties).await?;
    let accounts = parties.accounts();
    let Parties {
        sender,
        target,
        sender_jid,
        target_jid,
    } = parties;
    let outcome = state::cancel_subscription(
        transaction,
        &sender,
        &target_jid,
        subscriber_exists.then_some((&target, &sender_jid)),
    )
    .await?;
    let stanza = stanza.clone();
    Ok(Effects::new(accounts, move |delivery| {
        Box::pin(async move {
            if outcome.send_unavailable {
                delivery.unavailable_presence(&sender, &target).await?;
            }
            if outcome.route {
                delivery.to_tagged(SessionTag::Interested, stanza).await?;
            }
            if let Some(mutation) = outcome.subscriber {
                push_roster(&target, mutation, delivery).await?;
            }
            if let Some(mutation) = outcome.grantor {
                push_roster(&sender, mutation, delivery).await?;
            }
            Ok(())
        })
    }))
}

pub(super) async fn withdraw_subscription<A: ChunkAllocator, W: WriteTransaction>(
    transaction: &mut W,
    parties: Parties,
    stanza: &RoutedStanza<A>,
) -> Result<Effects<A>, HandlerError> {
    let contact_exists = check_parties(transaction, &parties).await?;
    let accounts = parties.accounts();
    let Parties {
        sender,
        target,
        sender_jid,
        target_jid,
    } = parties;
    let outcome = state::unsubscribe(
        transaction,
        &sender,
        &target_jid,
        contact_exists.then_some((&target, &sender_jid)),
    )
    .await?;
    let stanza = stanza.clone();
    Ok(Effects::new(accounts, move |delivery| {
        Box::pin(async move {
            if outcome.notify_contact {
                delivery.to_tagged(SessionTag::Interested, stanza).await?;
            }
            if let Some(mutation) = outcome.contact {
                push_roster(&target, mutation, delivery).await?;
            }
            if let Some(mutation) = outcome.subscriber {
                push_roster(&sender, mutation, delivery).await?;
            }
            if outcome.notify_contact {
                delivery.unavailable_presence(&target, &sender).await?;
            }
            Ok(())
        })
    }))
}

/// Removes an item and, for a local contact, withdraws and cancels the subscriptions
/// the two rosters record, in the order the separate presence flows use.
pub(super) async fn remove_item<A: ChunkAllocator, W: WriteTransaction>(
    transaction: &mut W,
    owner: AccountKey,
    contact: RosterJid,
    owner_jid: RosterJid,
    hosts: &dyn HostLookup,
) -> Result<Effects<A>, HandlerError> {
    require_account(transaction, &owner).await?;
    let contact_account = stored_local_account(transaction, &contact, hosts).await?;
    let removal = state::remove_item(
        transaction,
        &owner,
        &owner_jid,
        &contact,
        contact_account.as_ref(),
    )
    .await?
    .ok_or(StanzaErrorCondition::ItemNotFound)?;
    let mut accounts = vec![owner.clone()];
    accounts.extend(contact_account.clone());
    Ok(Effects::new(accounts, move |delivery| {
        Box::pin(async move {
            push_removal(&owner, contact, removal.version, delivery).await?;
            if let Some(contact_account) = contact_account {
                let contact_granted =
                    notify_removed_contact(&owner, &contact_account, removal, delivery).await?;
                if contact_granted {
                    delivery
                        .unavailable_presence(&contact_account, &owner)
                        .await?;
                }
            }
            Ok(())
        })
    }))
}

/// Clears every trace of a deleted account inside the deletion's transaction: its own
/// roster and pending requests, and the subscriptions and requests its local contacts
/// held with it. The effects tell every contact what it lost; a failed delivery does
/// not stop the others, and the first failure is reported at the end.
pub(super) async fn forget_account<A: ChunkAllocator, W: WriteTransaction>(
    transaction: &mut W,
    account: &AccountKey,
    hosts: &dyn HostLookup,
) -> Result<Effects<A>, HandlerError> {
    let account_jid = RosterJid::from(account);
    let items = transaction.roster(account).await?.items;
    let requests = transaction.pending_requests(account).await?;
    let mut removals = Vec::new();
    for item in items {
        let contact = stored_local_account(transaction, &item.jid, hosts).await?;
        let removal = state::remove_item(
            transaction,
            account,
            &account_jid,
            &item.jid,
            contact.as_ref(),
        )
        .await?;
        if let (Some(removal), Some(contact)) = (removal, contact) {
            removals.push((contact, removal));
        }
    }
    let mut cancellations = Vec::new();
    for request in requests {
        let sender = stored_local_account(transaction, &request.sender, hosts).await?;
        let cancellation = state::cancel_subscription(
            transaction,
            account,
            &request.sender,
            sender.as_ref().map(|sender| (sender, &account_jid)),
        )
        .await?;
        if let Some(sender) = sender {
            cancellations.push((sender, cancellation));
        }
    }
    transaction.clear_roster(account).await?;
    let mut accounts = Vec::with_capacity(1 + removals.len() + cancellations.len());
    accounts.push(account.clone());
    accounts.extend(removals.iter().map(|(contact, _)| contact.clone()));
    accounts.extend(cancellations.iter().map(|(sender, _)| sender.clone()));
    let owner = account.clone();
    Ok(Effects::new(accounts, move |delivery| {
        Box::pin(async move {
            let mut failure = None;
            for (contact, removal) in removals {
                if let Err(error) =
                    notify_removed_contact(&owner, &contact, removal, delivery).await
                {
                    failure.get_or_insert(error);
                }
            }
            for (sender, cancellation) in cancellations {
                if let Err(error) =
                    notify_cancelled_requester(&owner, &sender, cancellation, delivery).await
                {
                    failure.get_or_insert(error);
                }
            }
            failure.map_or(Ok(()), Err)
        })
    }))
}

/// The stored local account a roster JID names, if any.
async fn stored_local_account(
    transaction: &impl AccountReads,
    jid: &RosterJid,
    hosts: &dyn HostLookup,
) -> Result<Option<AccountKey>, StanzaErrorCondition> {
    match local_candidate(jid, hosts) {
        Some(candidate) if account_exists(transaction, &candidate).await? => Ok(Some(candidate)),
        _ => Ok(None),
    }
}

/// Tells a requester that its pending request ended with the grantor's deletion.
async fn notify_cancelled_requester<A: ChunkAllocator>(
    owner: &AccountKey,
    sender: &AccountKey,
    cancellation: Cancellation,
    delivery: &dyn Delivery<A>,
) -> Result<(), DeliveryError> {
    if cancellation.route {
        let (_, cancelled) = xml::subscription_withdrawals(owner, sender, delivery.arena()?)?;
        delivery
            .to_tagged(SessionTag::Interested, cancelled)
            .await?;
    }
    if let Some(mutation) = cancellation.subscriber {
        push_roster(sender, mutation, delivery).await?;
    }
    Ok(())
}

/// Sends the contact what losing the owner implies and returns whether the contact
/// had granted the owner its presence.
/// Each side's resource addresses are only revealed under that side's own grant.
async fn notify_removed_contact<A: ChunkAllocator>(
    owner: &AccountKey,
    contact: &AccountKey,
    removal: Removal,
    delivery: &dyn Delivery<A>,
) -> Result<bool, DeliveryError> {
    let owner_granted = grants(removal.subscription.state);
    let contact_granted = grants(removal.contact_before.unwrap_or_default().state);
    let cancel = owner_granted || removal.pending_request;
    if owner_granted {
        delivery.unavailable_presence(owner, contact).await?;
    }
    if contact_granted || cancel {
        let (withdrawal, cancellation) =
            xml::subscription_withdrawals(owner, contact, delivery.arena()?)?;
        if contact_granted {
            delivery
                .to_tagged(SessionTag::Interested, withdrawal)
                .await?;
        }
        if cancel {
            delivery
                .to_tagged(SessionTag::Interested, cancellation)
                .await?;
        }
    }
    if let Some(mutation) = removal.contact {
        push_roster(contact, mutation, delivery).await?;
    }
    Ok(contact_granted)
}

/// The account a roster JID would name on this server, whether or not it is stored.
fn local_candidate(jid: &RosterJid, hosts: &dyn HostLookup) -> Option<AccountKey> {
    AccountKey::try_from(jid)
        .ok()
        .filter(|account| hosts.is_local_host(account.domain()))
}
