// SPDX-License-Identifier: Apache-2.0

mod state;
mod subscription;
mod xml;

use lonewolf_storage::account::{AccountKey, AccountReads};
use lonewolf_storage::roster::{
    RosterError, RosterItem, RosterJid, RosterMutation, RosterReads, RosterSnapshot,
    RosterSubscription, RosterVersion, RosterWrites, SubscriptionState,
};
use lonewolf_storage::{Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::StanzaErrorCondition;

use crate::delivery::{Delivery, DeliveryError, HandlerError, SessionTag};
use crate::iq::{IqFuture, IqHandler, IqRequest, IqRequestType, IqRoute, IqScope};
use crate::order::Sequencer;
use crate::presence::{
    PresenceAudience, PresenceFuture, PresenceHandler, PresenceRequest, PresenceRequestType,
    PresenceTransition, PresenceUpdate, ReceiveFuture,
};
use crate::{Extension, ExtensionFuture};
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

pub struct Roster<S> {
    storage: S,
    order: Sequencer,
}

impl<S: Storage> Roster<S> {
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            order: Sequencer::new(),
        }
    }

    async fn begin_read(&self) -> Result<S::Read, RosterError> {
        self.storage.begin_read().await.map_err(RosterError::from)
    }

    async fn begin_write(&self) -> Result<S::Write, RosterError> {
        self.storage.begin_write().await.map_err(RosterError::from)
    }
}

async fn account_exists(
    transaction: &impl AccountReads,
    account: &AccountKey,
) -> Result<bool, StanzaErrorCondition> {
    transaction
        .account(account)
        .await
        .map(|account| account.is_some())
        .map_err(|_| StanzaErrorCondition::InternalServerError)
}

/// Refuses a mutation for an account whose record is gone, so a session that outlives
/// its account cannot repopulate roster state. Read it through the transaction the
/// writes run in, under the account's order.
async fn require_account(
    transaction: &impl AccountReads,
    account: &AccountKey,
) -> Result<(), StanzaErrorCondition> {
    if account_exists(transaction, account).await? {
        Ok(())
    } else {
        Err(StanzaErrorCondition::Forbidden)
    }
}

/// Keeps only the contacts whose own roster grants `owner` their presence, so a
/// one-sided `to` item cannot expose a contact that never approved.
async fn granting_contacts(
    transaction: &impl RosterReads,
    owner: RosterJid,
    watched: Vec<RosterJid>,
) -> Result<Vec<AccountKey>, StanzaErrorCondition> {
    let mut contacts = Vec::with_capacity(watched.len());
    for contact in &watched {
        let Ok(account) = AccountKey::try_from(contact) else {
            continue;
        };
        let granted = transaction
            .roster_item(&account, &owner)
            .await
            .map_err(roster_error)?
            .is_some_and(|item| {
                matches!(
                    item.subscription.state,
                    SubscriptionState::From | SubscriptionState::Both
                )
            });
        if granted {
            contacts.push(account);
        }
    }
    Ok(contacts)
}

impl<A, S> Extension<A> for Roster<S>
where
    A: ChunkAllocator,
    S: Storage,
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

    fn account_deleted<'a>(
        &'a self,
        account: &'a AccountKey,
        delivery: &'a dyn Delivery<A>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(self.forget_account(account, delivery))
    }
}

impl<A, S> IqHandler<A> for Roster<S>
where
    A: ChunkAllocator,
    S: Storage,
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
                    let snapshot = self.begin_read().await?.roster(&owner).await?;
                    let payload = xml::build_response(snapshot, response)?;
                    delivery.tag_session(SessionTag::Interested).await?;
                    Ok(Some(payload))
                }
                IqRequestType::Set => match xml::parse_set(request.payload, response)? {
                    xml::RosterSet::Update(update) => {
                        let _order = self.order.lock(&owner).await;
                        let mut transaction = self.begin_write().await?;
                        require_account(&transaction, &owner).await?;
                        let subscription = transaction
                            .roster_item(&owner, &update.jid)
                            .await?
                            .map_or_else(RosterSubscription::default, |item| item.subscription);
                        let item = RosterItem {
                            jid: update.jid,
                            name: update.name,
                            groups: update.groups,
                            subscription,
                        };
                        let version = transaction.put_roster_item(&owner, &item).await?;
                        transaction.commit().await.map_err(RosterError::from)?;
                        push_roster(
                            &owner,
                            RosterMutation {
                                version,
                                value: item,
                            },
                            delivery,
                        )
                        .await?;
                        Ok(None)
                    }
                    xml::RosterSet::Remove(contact) => {
                        let owner_jid = RosterJid::from(request.sender.bare());
                        self.remove_item(owner, contact, owner_jid, delivery)
                            .await?;
                        Ok(None)
                    }
                },
            }
        })
    }
}

impl<A, S> PresenceHandler<A> for Roster<S>
where
    A: ChunkAllocator,
    S: Storage,
{
    fn audience<'a>(
        &'a self,
        update: PresenceUpdate<'a>,
    ) -> PresenceFuture<'a, Option<PresenceAudience>> {
        Box::pin(async move {
            let owner = AccountKey::try_from(update.sender.bare())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            let order = self.order.lock(&owner).await;
            let transaction = self.begin_read().await.map_err(roster_error)?;
            let snapshot = transaction.roster(&owner).await.map_err(roster_error)?;
            let (subscribers, watched) = split_subscriptions(snapshot, &owner);
            let (pending, contacts) = if update.transition == PresenceTransition::Initial {
                let pending = transaction
                    .pending_requests(&owner)
                    .await
                    .map_err(roster_error)?;
                let contacts =
                    granting_contacts(&transaction, RosterJid::from(update.sender.bare()), watched)
                        .await?;
                (pending, contacts)
            } else {
                (Vec::new(), Vec::new())
            };
            Ok(Some(PresenceAudience::new(
                Some(order),
                subscribers,
                pending,
                contacts,
            )))
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
            Box::new(move |to, arena| {
                let item = xml::build_item(&mutation.value, arena)?;
                xml::build_push(to, item, mutation.version, arena)
            }),
        )
        .await
}

async fn push_removal<A: ChunkAllocator>(
    owner: &AccountKey,
    contact: RosterJid,
    version: RosterVersion,
    delivery: &dyn Delivery<A>,
) -> Result<(), DeliveryError> {
    delivery
        .push_to_tagged(
            owner,
            SessionTag::Interested,
            Box::new(move |to, arena| {
                let item = xml::build_removed_item(&contact, arena)?;
                xml::build_push(to, item, version, arena)
            }),
        )
        .await
}

/// Splits the roster into the contacts that see the owner and the contacts the owner sees.
fn split_subscriptions(
    snapshot: RosterSnapshot,
    owner: &AccountKey,
) -> (Vec<RosterJid>, Vec<RosterJid>) {
    let mut subscribers = Vec::new();
    let mut watched = Vec::new();
    for item in snapshot.items {
        if item.jid.as_str() == owner.as_str() {
            continue;
        }
        match item.subscription.state {
            SubscriptionState::From => subscribers.push(item.jid),
            SubscriptionState::To => watched.push(item.jid),
            SubscriptionState::Both => {
                subscribers.push(item.jid.clone());
                watched.push(item.jid);
            }
            SubscriptionState::None => {}
        }
    }
    (subscribers, watched)
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
