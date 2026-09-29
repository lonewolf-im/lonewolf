// SPDX-License-Identifier: Apache-2.0

mod subscription;
mod xml;

use lonewolf_storage::account::{AccountKey, AccountRepository};
use lonewolf_storage::roster::{
    RosterError, RosterItem, RosterJid, RosterMutation, RosterRepository, RosterSnapshot,
    SubscriptionState,
};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::StanzaErrorCondition;

use crate::Extension;
use crate::delivery::{Delivery, DeliveryError, HandlerError, SessionTag};
use crate::iq::{IqFuture, IqHandler, IqRequest, IqRequestType, IqRoute, IqScope};
use crate::order::Sequencer;
use crate::presence::{
    PresenceAudience, PresenceFuture, PresenceHandler, PresenceRequest, PresenceRequestType,
    PresenceUpdate, ReceiveFuture,
};
use subscription::Parties;

pub const NAME: &str = "roster";
pub const NAMESPACE: &str = "jabber:iq:roster";

const IQ_ROUTES: [IqRoute; 2] = [
    IqRoute {
        scope: IqScope::Account,
        kind: IqRequestType::Get,
        namespace: NAMESPACE,
        name: "query",
    },
    IqRoute {
        scope: IqScope::Account,
        kind: IqRequestType::Set,
        namespace: NAMESPACE,
        name: "query",
    },
];

pub struct Roster<R, C> {
    repository: R,
    accounts: C,
    order: Sequencer,
}

impl<R: RosterRepository, C: AccountRepository> Roster<R, C> {
    pub fn new(repository: R, accounts: C) -> Self {
        Self {
            repository,
            accounts,
            order: Sequencer::new(),
        }
    }

    async fn account_exists(&self, account: &AccountKey) -> Result<bool, StanzaErrorCondition> {
        self.accounts
            .get(account)
            .await
            .map(|account| account.is_some())
            .map_err(|_| StanzaErrorCondition::InternalServerError)
    }
}

impl<A, R, C> Extension<A> for Roster<R, C>
where
    A: ChunkAllocator,
    R: RosterRepository,
    C: AccountRepository,
{
    fn name(&self) -> &'static str {
        NAME
    }

    fn iq_routes(&self) -> &'static [IqRoute] {
        &IQ_ROUTES
    }

    fn presence_kinds(&self) -> &'static [PresenceRequestType] {
        &PresenceRequestType::ALL
    }
}

impl<A, R, C> IqHandler<A> for Roster<R, C>
where
    A: ChunkAllocator,
    R: RosterRepository,
    C: AccountRepository,
{
    fn handle<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        response: &'a mut Arena<A>,
        delivery: &'a dyn Delivery<A>,
    ) -> IqFuture<'a> {
        Box::pin(async move {
            if request.target != request.sender.bare() {
                return Err(StanzaErrorCondition::Forbidden.into());
            }
            let owner = AccountKey::try_from(request.sender.bare())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            match request.kind {
                IqRequestType::Get => {
                    xml::validate_get(request.payload)?;
                    let _order = self.order.lock(&owner).await;
                    let snapshot = self.repository.snapshot(&owner).await?;
                    let payload = xml::build_response(snapshot, response)?;
                    delivery.tag_session(SessionTag::Interested).await?;
                    Ok(Some(payload))
                }
                IqRequestType::Set => {
                    let update = xml::parse_update(request.payload, response)?;
                    let _order = self.order.lock(&owner).await;
                    let mutation = self.repository.upsert(&owner, update).await?;
                    push_roster(&owner, mutation, delivery).await?;
                    Ok(None)
                }
            }
        })
    }
}

impl<A, R, C> PresenceHandler<A> for Roster<R, C>
where
    A: ChunkAllocator,
    R: RosterRepository,
    C: AccountRepository,
{
    fn audience<'a>(
        &'a self,
        update: PresenceUpdate<'a>,
    ) -> PresenceFuture<'a, Option<PresenceAudience>> {
        Box::pin(async move {
            let owner = AccountKey::try_from(update.sender.bare())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            let order = self.order.lock(&owner).await;
            let snapshot = self
                .repository
                .snapshot(&owner)
                .await
                .map_err(roster_error)?;
            let pending = if update.available {
                self.repository
                    .pending(&owner)
                    .await
                    .map_err(roster_error)?
            } else {
                Vec::new()
            };
            Ok(Some(PresenceAudience::new(
                Some(order),
                presence_subscribers(snapshot, &owner),
                pending,
            )))
        })
    }

    fn authorize<'a>(&'a self, request: PresenceRequest<'a, A>) -> PresenceFuture<'a, ()> {
        Box::pin(async move {
            if request.kind != PresenceRequestType::Subscribe {
                return Ok(());
            }
            let contact = AccountKey::try_from(request.target.bare())
                .map_err(|_| StanzaErrorCondition::BadRequest)?;
            if self.account_exists(&contact).await? {
                Ok(())
            } else {
                Err(StanzaErrorCondition::ServiceUnavailable)
            }
        })
    }

    fn receive<'a>(
        &'a self,
        request: PresenceRequest<'a, A>,
        delivery: &'a dyn Delivery<A>,
    ) -> ReceiveFuture<'a> {
        Box::pin(async move {
            let parties = Parties::new(&request)?;
            match request.kind {
                PresenceRequestType::Subscribe => {
                    self.request_subscription(parties, request.stanza, delivery)
                        .await
                }
                PresenceRequestType::Subscribed => {
                    self.approve_subscription(parties, request.stanza, delivery)
                        .await
                }
                PresenceRequestType::Unsubscribed => {
                    self.cancel_subscription(parties, request.stanza, delivery)
                        .await
                }
                PresenceRequestType::Unsubscribe => {
                    self.withdraw_subscription(parties, request.stanza, delivery)
                        .await
                }
                PresenceRequestType::Available | PresenceRequestType::Unavailable => {
                    Err(StanzaErrorCondition::ServiceUnavailable.into())
                }
            }
        })
    }
}

async fn push_roster<A: ChunkAllocator>(
    owner: &AccountKey,
    mutation: RosterMutation<RosterItem>,
    delivery: &dyn Delivery<A>,
) -> Result<(), DeliveryError> {
    delivery
        .push_to_tagged(
            owner,
            SessionTag::Interested,
            Box::new(move |to, arena| xml::build_push(to, &mutation, arena)),
        )
        .await
}

fn presence_subscribers(snapshot: RosterSnapshot, owner: &AccountKey) -> Vec<RosterJid> {
    snapshot
        .items
        .into_iter()
        .filter(|item| {
            matches!(
                item.subscription.state,
                SubscriptionState::From | SubscriptionState::Both
            ) && item.jid.as_str() != owner.as_str()
        })
        .map(|item| item.jid)
        .collect()
}

fn roster_error(error: RosterError) -> StanzaErrorCondition {
    match error {
        RosterError::ValueTooLarge => StanzaErrorCondition::NotAcceptable,
        RosterError::Storage(_) => StanzaErrorCondition::InternalServerError,
    }
}

impl From<RosterError> for HandlerError {
    fn from(error: RosterError) -> Self {
        Self::Stanza(roster_error(error))
    }
}

#[cfg(test)]
mod tests;
