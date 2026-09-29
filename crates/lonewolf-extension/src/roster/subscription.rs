// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::account::{AccountKey, AccountRepository};
use lonewolf_storage::roster::{
    ItemRemoval, PendingSubscription, RosterJid, RosterRepository, RosterSubscription,
    SubscriptionRequestOutcome, SubscriptionState,
};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaErrorCondition};

use super::{Roster, push_removal, push_roster, xml};
use crate::delivery::{Delivery, DeliveryError, HandlerError, SessionTag};
use crate::order::OrderGuard;
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
}

impl<R: RosterRepository, C: AccountRepository> Roster<R, C> {
    /// Orders both parties, refuses a sender whose account is gone, and reports whether
    /// the target is stored, all under the guard the following writes run under.
    async fn lock_parties(
        &self,
        parties: &Parties,
    ) -> Result<(OrderGuard, bool), StanzaErrorCondition> {
        let order = self.order.lock_pair(&parties.sender, &parties.target).await;
        self.require_account(&parties.sender).await?;
        let target_exists = self.account_exists(&parties.target).await?;
        Ok((order, target_exists))
    }

    /// Orders the owner with the account a contact JID names on this server, if any, and
    /// resolves that account only while the guard is held.
    async fn lock_with_contact<A: ChunkAllocator>(
        &self,
        owner: &AccountKey,
        contact: &RosterJid,
        delivery: &dyn Delivery<A>,
    ) -> Result<(OrderGuard, Option<AccountKey>), StanzaErrorCondition> {
        let Some(candidate) = local_candidate(contact, delivery) else {
            return Ok((self.order.lock(owner).await, None));
        };
        let order = self.order.lock_pair(owner, &candidate).await;
        let contact = self.account_exists(&candidate).await?.then_some(candidate);
        Ok((order, contact))
    }

    pub(super) async fn request_subscription<A: ChunkAllocator>(
        &self,
        parties: Parties,
        stanza: &RoutedStanza<A>,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let (_order, target_exists) = self.lock_parties(&parties).await?;
        if !target_exists {
            return Err(StanzaErrorCondition::ServiceUnavailable.into());
        }
        let mut request = String::new();
        stanza
            .resolve()
            .map_err(|_| StanzaErrorCondition::InternalServerError)?
            .write_xml(&mut request)
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
        let outcome = self
            .repository
            .request_subscription(
                &parties.sender,
                &parties.target_jid,
                &parties.target,
                PendingSubscription {
                    sender: parties.sender_jid,
                    stanza: request.into_bytes().into_boxed_slice(),
                },
            )
            .await?;
        match outcome {
            SubscriptionRequestOutcome::Pending { mutation } => {
                delivery.to_available(stanza.clone()).await?;
                if let Some(mutation) = mutation {
                    push_roster(&parties.sender, mutation, delivery).await?;
                }
            }
            SubscriptionRequestOutcome::AutoApprove {
                mutation: Some(mutation),
            } => {
                let approval = xml::approval_reply(stanza, delivery.arena()?)?;
                delivery.to_tagged(SessionTag::Interested, approval).await?;
                push_roster(&parties.sender, mutation, delivery).await?;
                delivery
                    .current_presence(&parties.target, &parties.sender)
                    .await?;
            }
            SubscriptionRequestOutcome::AutoApprove { mutation: None } => {}
        }
        Ok(())
    }

    pub(super) async fn approve_subscription<A: ChunkAllocator>(
        &self,
        parties: Parties,
        stanza: &RoutedStanza<A>,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let (_order, target_exists) = self.lock_parties(&parties).await?;
        if !target_exists {
            return Ok(());
        }
        let target = self
            .repository
            .update_subscription(
                &parties.target,
                &parties.sender_jid,
                RosterSubscription::approve_pending_out,
            )
            .await?;
        let sender = self
            .repository
            .resolve_pending(
                &parties.sender,
                &parties.target_jid,
                approve_outbound_subscription,
            )
            .await?
            .and_then(|resolution| resolution.mutation);
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
        let (_order, subscriber_exists) = self.lock_parties(&parties).await?;
        let outcome = self
            .repository
            .cancel_subscription(
                &parties.sender,
                &parties.target_jid,
                subscriber_exists.then_some((&parties.target, &parties.sender_jid)),
            )
            .await?;
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
        let (_order, contact_exists) = self.lock_parties(&parties).await?;
        let outcome = self
            .repository
            .unsubscribe(
                &parties.sender,
                &parties.target_jid,
                contact_exists.then_some((&parties.target, &parties.sender_jid)),
            )
            .await?;
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

fn approve_outbound_subscription(
    mut subscription: RosterSubscription,
) -> Option<RosterSubscription> {
    subscription.state = match subscription.state {
        SubscriptionState::None => SubscriptionState::From,
        SubscriptionState::To => SubscriptionState::Both,
        SubscriptionState::From | SubscriptionState::Both => return None,
    };
    Some(subscription)
}

impl<R: RosterRepository, C: AccountRepository> Roster<R, C> {
    /// Removes an item and, for a local contact, withdraws and cancels the subscriptions
    /// the two rosters record, in the order the separate presence flows use.
    pub(super) async fn remove_item<A: ChunkAllocator>(
        &self,
        owner: AccountKey,
        contact: RosterJid,
        owner_jid: RosterJid,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let (_order, contact_account) = self.lock_with_contact(&owner, &contact, delivery).await?;
        self.require_account(&owner).await?;
        let removal = self
            .repository
            .remove_item(
                &owner,
                &contact,
                contact_account
                    .as_ref()
                    .map(|account| (account, &owner_jid)),
            )
            .await?
            .ok_or(StanzaErrorCondition::ItemNotFound)?;
        push_removal(&owner, contact, removal.version, delivery).await?;
        if let Some(contact_account) = contact_account {
            let contact_granted = self
                .notify_removed_contact(&owner, &contact_account, removal, delivery)
                .await?;
            if contact_granted {
                delivery
                    .unavailable_presence(&contact_account, &owner)
                    .await?;
            }
        }
        Ok(())
    }

    /// Clears every trace of a deleted account: its own roster and pending requests,
    /// and the subscriptions and requests its local contacts held with it. Storage is
    /// cleaned even when a notification fails; the first delivery failure is returned
    /// afterwards.
    pub(super) async fn forget_account<A: ChunkAllocator>(
        &self,
        account: &AccountKey,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let account_jid = RosterJid::from(account);
        let mut failure = None;
        // Every mutation checks the account under its order, so a scan under that order
        // that finds nothing proves no write can still arrive, and each pass removes
        // what the previous scan found.
        loop {
            let (items, requests) = {
                let _order = self.order.lock(account).await;
                let items = self.repository.snapshot(account).await?.items;
                let requests = self.repository.pending(account).await?;
                if items.is_empty() && requests.is_empty() {
                    self.repository.delete_all(account).await?;
                    break;
                }
                (items, requests)
            };
            for item in items {
                let result = self
                    .forget_contact(account, &account_jid, &item.jid, delivery)
                    .await;
                record_delivery_failure(result, &mut failure)?;
            }
            for request in requests {
                let result = self
                    .forget_requester(account, &account_jid, &request.sender, delivery)
                    .await;
                record_delivery_failure(result, &mut failure)?;
            }
        }
        failure.map_or(Ok(()), |error| Err(HandlerError::Delivery(error)))
    }

    async fn forget_contact<A: ChunkAllocator>(
        &self,
        account: &AccountKey,
        account_jid: &RosterJid,
        contact: &RosterJid,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let (_order, contact_account) = self.lock_with_contact(account, contact, delivery).await?;
        let removal = self
            .repository
            .remove_item(
                account,
                contact,
                contact_account
                    .as_ref()
                    .map(|contact_account| (contact_account, account_jid)),
            )
            .await?;
        if let (Some(removal), Some(contact_account)) = (removal, contact_account) {
            self.notify_removed_contact(account, &contact_account, removal, delivery)
                .await?;
        }
        Ok(())
    }

    async fn forget_requester<A: ChunkAllocator>(
        &self,
        account: &AccountKey,
        account_jid: &RosterJid,
        sender: &RosterJid,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let (_order, sender_account) = self.lock_with_contact(account, sender, delivery).await?;
        let outcome = self
            .repository
            .cancel_subscription(
                account,
                sender,
                sender_account
                    .as_ref()
                    .map(|sender_account| (sender_account, account_jid)),
            )
            .await?;
        let Some(sender_account) = sender_account else {
            return Ok(());
        };
        if outcome.route {
            let (_, cancellation) =
                xml::subscription_withdrawals(account, &sender_account, delivery.arena()?)?;
            delivery
                .to_tagged(SessionTag::Interested, cancellation)
                .await?;
        }
        if let Some(mutation) = outcome.subscriber {
            push_roster(&sender_account, mutation, delivery).await?;
        }
        Ok(())
    }

    /// Sends the contact what losing the owner implies and returns whether the contact
    /// had granted the owner its presence.
    /// Each side's resource addresses are only revealed under that side's own grant.
    async fn notify_removed_contact<A: ChunkAllocator>(
        &self,
        owner: &AccountKey,
        contact: &AccountKey,
        removal: ItemRemoval,
        delivery: &dyn Delivery<A>,
    ) -> Result<bool, HandlerError> {
        let owner_granted = matches!(
            removal.subscription.state,
            SubscriptionState::From | SubscriptionState::Both
        );
        let contact_granted = matches!(
            removal.contact_before.unwrap_or_default().state,
            SubscriptionState::From | SubscriptionState::Both
        );
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
}

/// The account a roster JID would name on this server, whether or not it is stored.
fn local_candidate<A: ChunkAllocator>(
    jid: &RosterJid,
    delivery: &dyn Delivery<A>,
) -> Option<AccountKey> {
    AccountKey::try_from(jid)
        .ok()
        .filter(|account| delivery.is_local_host(account.domain()))
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
