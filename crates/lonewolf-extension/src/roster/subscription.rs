// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::account::{AccountKey, AccountReads};
use lonewolf_storage::roster::{RosterError, RosterJid};
use lonewolf_storage::{Storage, WriteTransaction};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaErrorCondition};

use super::state::{self, Cancellation, Removal, RequestOutcome, grants};
use super::{Roster, account_exists, push_removal, push_roster, require_account, xml};
use crate::delivery::{Delivery, DeliveryError, HandlerError, HostLookup, SessionTag};
use crate::order::OrderGuard;
use crate::presence::PresenceRequest;
use crate::{Aftermath, aftermath};

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
}

impl<S: Storage> Roster<S> {
    /// Orders both parties, opens the write transaction, refuses a sender whose account
    /// is gone, and reports whether the target is stored, so the checks and the writes
    /// that follow share one transaction under one guard.
    async fn lock_parties(
        &self,
        parties: &Parties,
    ) -> Result<(OrderGuard, S::Write, bool), HandlerError> {
        let order = self.order.lock_pair(&parties.sender, &parties.target).await;
        let transaction = self.begin_write().await?;
        require_account(&transaction, &parties.sender).await?;
        let target_exists = account_exists(&transaction, &parties.target).await?;
        Ok((order, transaction, target_exists))
    }

    /// Orders the owner with the account a contact JID names on this server, if any,
    /// opens the write transaction, and resolves that account through it.
    async fn lock_with_contact<A: ChunkAllocator>(
        &self,
        owner: &AccountKey,
        contact: &RosterJid,
        delivery: &dyn Delivery<A>,
    ) -> Result<(OrderGuard, S::Write, Option<AccountKey>), HandlerError> {
        let candidate = local_candidate(contact, delivery);
        let order = match &candidate {
            Some(candidate) => self.order.lock_pair(owner, candidate).await,
            None => self.order.lock(owner).await,
        };
        let transaction = self.begin_write().await?;
        let contact = match candidate {
            Some(candidate) if account_exists(&transaction, &candidate).await? => Some(candidate),
            _ => None,
        };
        Ok((order, transaction, contact))
    }

    pub(super) async fn request_subscription<A: ChunkAllocator>(
        &self,
        parties: Parties,
        stanza: &RoutedStanza<A>,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let (_order, mut transaction, target_exists) = self.lock_parties(&parties).await?;
        if !target_exists {
            return Err(StanzaErrorCondition::ServiceUnavailable.into());
        }
        let mut request = String::new();
        stanza
            .resolve()
            .map_err(|_| StanzaErrorCondition::InternalServerError)?
            .write_xml(&mut request)
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
        let outcome = match state::request_subscription(
            &mut transaction,
            &parties.sender,
            parties.sender_jid,
            &parties.target,
            &parties.target_jid,
            request.into_bytes().into_boxed_slice(),
        )
        .await?
        {
            RequestOutcome::ContactMissing => {
                return Err(StanzaErrorCondition::ServiceUnavailable.into());
            }
            outcome => outcome,
        };
        transaction.commit().await.map_err(RosterError::from)?;
        match outcome {
            RequestOutcome::Pending { push } => {
                delivery.to_available(stanza.clone()).await?;
                if let Some(mutation) = push {
                    push_roster(&parties.sender, mutation, delivery).await?;
                }
            }
            RequestOutcome::AutoApproved {
                approved: Some(mutation),
            } => {
                let approval = xml::approval_reply(stanza, delivery.arena()?)?;
                delivery.to_tagged(SessionTag::Interested, approval).await?;
                push_roster(&parties.sender, mutation, delivery).await?;
                delivery
                    .current_presence(&parties.target, &parties.sender)
                    .await?;
            }
            RequestOutcome::AutoApproved { approved: None } | RequestOutcome::ContactMissing => {}
        }
        Ok(())
    }

    pub(super) async fn approve_subscription<A: ChunkAllocator>(
        &self,
        parties: Parties,
        stanza: &RoutedStanza<A>,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let (_order, mut transaction, target_exists) = self.lock_parties(&parties).await?;
        if !target_exists {
            return Ok(());
        }
        let target = state::update_subscription(
            &mut transaction,
            &parties.target,
            &parties.sender_jid,
            state::approve_pending_out,
        )
        .await?;
        let sender = state::resolve_pending(
            &mut transaction,
            &parties.sender,
            &parties.target_jid,
            state::grant,
        )
        .await?;
        transaction.commit().await.map_err(RosterError::from)?;
        if let Some(mutation) = target {
            delivery
                .to_tagged(SessionTag::Interested, stanza.clone())
                .await?;
            push_roster(&parties.target, mutation, delivery).await?;
        }
        if let Some(mutation) = sender {
            push_roster(&parties.sender, mutation, delivery).await?;
            delivery
                .current_presence(&parties.sender, &parties.target)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn cancel_subscription<A: ChunkAllocator>(
        &self,
        parties: Parties,
        stanza: &RoutedStanza<A>,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let (_order, mut transaction, subscriber_exists) = self.lock_parties(&parties).await?;
        let outcome = state::cancel_subscription(
            &mut transaction,
            &parties.sender,
            &parties.target_jid,
            subscriber_exists.then_some((&parties.target, &parties.sender_jid)),
        )
        .await?;
        transaction.commit().await.map_err(RosterError::from)?;
        if outcome.send_unavailable {
            delivery
                .unavailable_presence(&parties.sender, &parties.target)
                .await?;
        }
        if outcome.route {
            delivery
                .to_tagged(SessionTag::Interested, stanza.clone())
                .await?;
        }
        if let Some(mutation) = outcome.subscriber {
            push_roster(&parties.target, mutation, delivery).await?;
        }
        if let Some(mutation) = outcome.grantor {
            push_roster(&parties.sender, mutation, delivery).await?;
        }
        Ok(())
    }

    pub(super) async fn withdraw_subscription<A: ChunkAllocator>(
        &self,
        parties: Parties,
        stanza: &RoutedStanza<A>,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let (_order, mut transaction, contact_exists) = self.lock_parties(&parties).await?;
        let outcome = state::unsubscribe(
            &mut transaction,
            &parties.sender,
            &parties.target_jid,
            contact_exists.then_some((&parties.target, &parties.sender_jid)),
        )
        .await?;
        transaction.commit().await.map_err(RosterError::from)?;
        if outcome.notify_contact {
            delivery
                .to_tagged(SessionTag::Interested, stanza.clone())
                .await?;
        }
        if let Some(mutation) = outcome.contact {
            push_roster(&parties.target, mutation, delivery).await?;
        }
        if let Some(mutation) = outcome.subscriber {
            push_roster(&parties.sender, mutation, delivery).await?;
        }
        if outcome.notify_contact {
            delivery
                .unavailable_presence(&parties.target, &parties.sender)
                .await?;
        }
        Ok(())
    }
}

impl<S: Storage> Roster<S> {
    /// Removes an item and, for a local contact, withdraws and cancels the subscriptions
    /// the two rosters record, in the order the separate presence flows use.
    pub(super) async fn remove_item<A: ChunkAllocator>(
        &self,
        owner: AccountKey,
        contact: RosterJid,
        owner_jid: RosterJid,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let (_order, mut transaction, contact_account) =
            self.lock_with_contact(&owner, &contact, delivery).await?;
        require_account(&transaction, &owner).await?;
        let removal = state::remove_item(
            &mut transaction,
            &owner,
            &owner_jid,
            &contact,
            contact_account.as_ref(),
        )
        .await?
        .ok_or(StanzaErrorCondition::ItemNotFound)?;
        transaction.commit().await.map_err(RosterError::from)?;
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
    }
}

/// Clears every trace of a deleted account inside the deletion's transaction: its own
/// roster and pending requests, and the subscriptions and requests its local contacts
/// held with it. Returns what the contacts receive once the deletion commits.
pub(super) async fn forget_account<A: ChunkAllocator, W: WriteTransaction>(
    transaction: &mut W,
    account: &AccountKey,
    hosts: &dyn HostLookup,
) -> Result<Aftermath<A>, HandlerError> {
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
    let owner = account.clone();
    Ok(aftermath(move |delivery| {
        Box::pin(async move {
            let mut failure = None;
            for (contact, removal) in removals {
                let result = notify_removed_contact(&owner, &contact, removal, delivery).await;
                record_delivery_failure(result.map(|_| ()), &mut failure)?;
            }
            for (sender, cancellation) in cancellations {
                let result =
                    notify_cancelled_requester(&owner, &sender, cancellation, delivery).await;
                record_delivery_failure(result, &mut failure)?;
            }
            failure.map_or(Ok(()), |error| Err(HandlerError::Delivery(error)))
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
) -> Result<(), HandlerError> {
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
) -> Result<bool, HandlerError> {
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

/// Keeps the first delivery failure for later and surfaces every other error at once.
fn record_delivery_failure(
    result: Result<(), HandlerError>,
    failure: &mut Option<DeliveryError>,
) -> Result<(), HandlerError> {
    match result {
        Ok(()) => Ok(()),
        Err(HandlerError::Delivery(error)) => {
            failure.get_or_insert(error);
            Ok(())
        }
        Err(error) => Err(error),
    }
}
