// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::account::{AccountKey, AccountRepository};
use lonewolf_storage::roster::{
    PendingSubscription, RosterJid, RosterRepository, RosterSubscription,
    SubscriptionRequestOutcome, SubscriptionState,
};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaErrorCondition};

use super::{Roster, push_roster, xml};
use crate::delivery::{Delivery, HandlerError, SessionTag};
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
