// SPDX-License-Identifier: Apache-2.0

mod state;
mod subscription;
mod versioning;
mod xml;

use lonewolf_storage::Storage;
use lonewolf_storage::account::{AccountKey, AccountReads};
use lonewolf_storage::roster::{
    RosterError, RosterItem, RosterJid, RosterMutation, RosterReads, RosterSnapshot,
    RosterSubscription, RosterVersion, RosterWrites, SubscriptionState,
};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::StanzaErrorCondition;

use crate::delivery::{Delivery, DeliveryError, HandlerError, HostLookup, SessionTag};
use crate::iq::{IqFuture, IqHandler, IqReply, IqRequest, IqRequestType, IqRoute, IqScope};
use crate::presence::{
    PresenceAudience, PresenceFuture, PresenceHandler, PresenceRequest, PresenceRequestType,
    PresenceTransition, PresenceUpdate, ReceiveFuture,
};
use crate::{Effects, Extension, ExtensionFuture};
use subscription::Parties;

pub const NAME: &str = "roster";
pub const NAMESPACE: &str = "jabber:iq:roster";
pub const VERSIONING_FEATURE: &str = "<ver xmlns='urn:xmpp:features:rosterver'/>";

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

/// The RFC 6121 roster and subscription extension.
///
/// It keeps no state of its own: every request works on the transaction the server
/// hands it and returns the deliveries that follow as effects.
#[derive(Default)]
pub struct Roster;

impl Roster {
    pub const fn new() -> Self {
        Self
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
/// its account cannot repopulate roster state.
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

/// The account a roster IQ addresses, which must be the sender's own.
fn owner_of<A: ChunkAllocator>(
    request: &IqRequest<'_, A>,
) -> Result<AccountKey, StanzaErrorCondition> {
    if request.target != request.sender.bare() {
        return Err(StanzaErrorCondition::Forbidden);
    }
    AccountKey::try_from(request.sender.bare())
        .map_err(|_| StanzaErrorCondition::InternalServerError)
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

impl<A, S> Extension<A, S> for Roster
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

    fn stream_features(&self) -> &'static [&'static str] {
        &[VERSIONING_FEATURE]
    }

    fn forget_account<'a>(
        &'a self,
        transaction: &'a mut S::Write,
        account: &'a AccountKey,
        hosts: &'a dyn HostLookup,
    ) -> ExtensionFuture<'a, Result<Effects<A>, HandlerError>> {
        Box::pin(subscription::forget_account(transaction, account, hosts))
    }
}

impl<A, S> IqHandler<A, S> for Roster
where
    A: ChunkAllocator,
    S: Storage,
{
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a S::Read,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let owner = owner_of(&request)?;
            let known = xml::parse_get(request.payload)?;
            let snapshot = transaction.roster(&owner).await?;
            let payload = match versioning::answer(known, &snapshot) {
                versioning::Answer::Full { stamped } => {
                    let version = stamped.then_some(snapshot.version);
                    Some(xml::build_response(snapshot.items, version, response)?)
                }
                versioning::Answer::Unchanged => None,
            };
            let effects = Effects::new(vec![owner], |delivery| {
                delivery.tag_session(SessionTag::Interested)
            });
            Ok(IqReply::new(payload, effects))
        })
    }

    fn set<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a mut S::Write,
        hosts: &'a dyn HostLookup,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let owner = owner_of(&request)?;
            match xml::parse_set(request.payload, response)? {
                xml::RosterSet::Update(update) => {
                    require_account(transaction, &owner).await?;
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
                    let mutation = RosterMutation {
                        version,
                        value: item,
                    };
                    let effects = Effects::new(vec![owner.clone()], move |delivery| {
                        Box::pin(async move { push_roster(&owner, mutation, delivery).await })
                    });
                    Ok(IqReply::new(None, effects))
                }
                xml::RosterSet::Remove(contact) => {
                    let owner_jid = RosterJid::from(request.sender.bare());
                    let effects =
                        subscription::remove_item(transaction, owner, contact, owner_jid, hosts)
                            .await?;
                    Ok(IqReply::new(None, effects))
                }
            }
        })
    }
}

impl<A, S> PresenceHandler<A, S> for Roster
where
    A: ChunkAllocator,
    S: Storage,
{
    fn audience<'a>(
        &'a self,
        update: PresenceUpdate<'a>,
        transaction: &'a S::Read,
    ) -> PresenceFuture<'a, Option<PresenceAudience>> {
        Box::pin(async move {
            let owner = AccountKey::try_from(update.sender.bare())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            let snapshot = transaction.roster(&owner).await.map_err(roster_error)?;
            let (subscribers, watched) = split_subscriptions(snapshot, &owner);
            let (pending, contacts) = if update.transition == PresenceTransition::Initial {
                let pending = transaction
                    .pending_requests(&owner)
                    .await
                    .map_err(roster_error)?;
                let contacts =
                    granting_contacts(transaction, RosterJid::from(update.sender.bare()), watched)
                        .await?;
                (pending, contacts)
            } else {
                (Vec::new(), Vec::new())
            };
            Ok(Some(PresenceAudience {
                subscribers,
                pending,
                contacts,
            }))
        })
    }

    fn receive<'a>(
        &'a self,
        request: PresenceRequest<'a, A>,
        transaction: &'a mut S::Write,
        _hosts: &'a dyn HostLookup,
    ) -> ReceiveFuture<'a, A> {
        Box::pin(async move {
            let parties = Parties::new(&request)?;
            match request.kind {
                PresenceRequestType::Subscribe => {
                    subscription::request_subscription(transaction, parties, request.stanza).await
                }
                PresenceRequestType::Subscribed => {
                    subscription::approve_subscription(transaction, parties, request.stanza).await
                }
                PresenceRequestType::Unsubscribed => {
                    subscription::cancel_subscription(transaction, parties, request.stanza).await
                }
                PresenceRequestType::Unsubscribe => {
                    subscription::withdraw_subscription(transaction, parties, request.stanza).await
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
    for entry in snapshot.items {
        let item = entry.value;
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
        RosterError::NoAccount => StanzaErrorCondition::Forbidden,
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
