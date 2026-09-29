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
    pub(super) async fn request_subscription<A: ChunkAllocator>(
        &self,
        parties: Parties,
        stanza: &RoutedStanza<A>,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        if !self.account_exists(&parties.target).await? {
            return Err(StanzaErrorCondition::ServiceUnavailable.into());
        }
        let _order = self.order.lock_pair(&parties.sender, &parties.target).await;
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
        if !self.account_exists(&parties.target).await? {
            return Ok(());
        }
        let _order = self.order.lock_pair(&parties.sender, &parties.target).await;
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
        let subscriber_exists = self.account_exists(&parties.target).await?;
        let _order = self.order.lock_pair(&parties.sender, &parties.target).await;
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
        let contact_exists = self.account_exists(&parties.target).await?;
        let _order = self.order.lock_pair(&parties.sender, &parties.target).await;
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
        let contact_account = self.local_account(&contact, delivery).await?;
        let _order = match &contact_account {
            Some(account) => self.order.lock_pair(&owner, account).await,
            None => self.order.lock(&owner).await,
        };
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

    /// Clears every trace of an account about to be deleted: its own roster and
    /// pending requests, and the subscriptions and requests its local contacts held
    /// with it. Storage is cleaned even when a notification fails; the first delivery
    /// failure is returned afterwards.
    pub(super) async fn forget_account<A: ChunkAllocator>(
        &self,
        account: &AccountKey,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let account_jid = RosterJid::from(account);
        let mut failure = None;
        let snapshot = self.repository.snapshot(account).await?;
        for item in snapshot.items {
            let result = self
                .forget_contact(account, &account_jid, &item.jid, delivery)
                .await;
            record_delivery_failure(result, &mut failure)?;
        }
        for request in self.repository.pending(account).await? {
            let result = self
                .forget_requester(account, &account_jid, &request.sender, delivery)
                .await;
            record_delivery_failure(result, &mut failure)?;
        }
        let _order = self.order.lock(account).await;
        self.repository.delete_all(account).await?;
        failure.map_or(Ok(()), |error| Err(HandlerError::Delivery(error)))
    }

    async fn forget_contact<A: ChunkAllocator>(
        &self,
        account: &AccountKey,
        account_jid: &RosterJid,
        contact: &RosterJid,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), HandlerError> {
        let Some(contact_account) = self.local_account(contact, delivery).await? else {
            return Ok(());
        };
        let _order = self.order.lock_pair(account, &contact_account).await;
        let removal = self
            .repository
            .remove_item(account, contact, Some((&contact_account, account_jid)))
            .await?;
        if let Some(removal) = removal {
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
        let Some(sender_account) = self.local_account(sender, delivery).await? else {
            return Ok(());
        };
        let _order = self.order.lock_pair(account, &sender_account).await;
        let outcome = self
            .repository
            .cancel_subscription(account, sender, Some((&sender_account, account_jid)))
            .await?;
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

    /// Resolves a roster JID to an account this server hosts and stores.
    async fn local_account<A: ChunkAllocator>(
        &self,
        jid: &RosterJid,
        delivery: &dyn Delivery<A>,
    ) -> Result<Option<AccountKey>, StanzaErrorCondition> {
        match AccountKey::try_from(jid) {
            Ok(account) if delivery.is_local_host(account.domain()) => {
                Ok(self.account_exists(&account).await?.then_some(account))
            }
            _ => Ok(None),
        }
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
