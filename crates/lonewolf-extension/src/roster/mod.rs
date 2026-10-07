// SPDX-License-Identifier: Apache-2.0

mod state;
mod subscription;
mod versioning;
mod xml;

use std::collections::BTreeMap;
use std::num::NonZeroUsize;

use lonewolf_storage::Storage;
use lonewolf_storage::account::{AccountError, AccountKey, AccountReads};
use lonewolf_storage::roster::{
    RosterError, RosterItem, RosterJid, RosterMutation, RosterReads, RosterSnapshot,
    RosterSubscription, RosterVersion, RosterWrites, SubscriptionState,
};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::StanzaErrorCondition;

use crate::delivery::{
    Delivery, DeliveryError, Failure, FailureKind, HandlerError, HostLookup, SessionTag,
};
use crate::iq::{IqFuture, IqHandler, IqReply, IqRequest, IqRequestType, IqRoute, IqScope};
use crate::message::MessageHandler;
use crate::presence::{
    PresenceAudience, PresenceFuture, PresenceHandler, PresenceRequest, PresenceRequestType,
    PresenceTransition, PresenceUpdate, ReceiveFuture,
};
use crate::{Effects, Extension, ExtensionFuture};
use subscription::Parties;

pub const NAME: &str = "roster";
pub const NAMESPACE: &str = "jabber:iq:roster";
pub const VERSIONING_FEATURE: &str = "<ver xmlns='urn:xmpp:features:rosterver'/>";
pub const PRE_APPROVAL_FEATURE: &str = "<sub xmlns='urn:xmpp:features:pre-approval'/>";

const DEFAULT_MAX_PENDING_SUBSCRIPTION_REQUESTS: NonZeroUsize = NonZeroUsize::new(100).unwrap();

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterLimits {
    pub max_pending_subscription_requests: NonZeroUsize,
}

impl Default for RosterLimits {
    fn default() -> Self {
        Self {
            max_pending_subscription_requests: DEFAULT_MAX_PENDING_SUBSCRIPTION_REQUESTS,
        }
    }
}

#[derive(Default)]
pub struct Roster {
    limits: BTreeMap<Box<str>, RosterLimits>,
}

impl Roster {
    /// Hosts without a limits entry use the default.
    pub fn new(limits: BTreeMap<Box<str>, RosterLimits>) -> Self {
        Self { limits }
    }
}

async fn account_exists(
    transaction: &impl AccountReads,
    account: &AccountKey,
    operation: &'static str,
) -> Result<bool, HandlerError> {
    transaction
        .account(account)
        .await
        .map(|account| account.is_some())
        .map_err(|error| match error {
            AccountError::Storage(error) => storage_error(error, operation),
            _ => StanzaErrorCondition::InternalServerError.into(),
        })
}

/// A session that outlives its account must not repopulate roster state.
async fn require_account(
    transaction: &impl AccountReads,
    account: &AccountKey,
) -> Result<(), HandlerError> {
    if account_exists(transaction, account, "roster_write").await? {
        Ok(())
    } else {
        Err(StanzaErrorCondition::Forbidden.into())
    }
}

fn owner_of<A: ChunkAllocator>(
    request: &IqRequest<'_, A>,
) -> Result<AccountKey, StanzaErrorCondition> {
    if request.target != request.sender.bare() {
        return Err(StanzaErrorCondition::Forbidden);
    }
    AccountKey::try_from(request.sender.bare())
        .map_err(|_| StanzaErrorCondition::InternalServerError)
}

/// A one-sided `to` item must not expose a contact that never approved.
async fn granting_contacts(
    transaction: &impl RosterReads,
    owner: RosterJid,
    watched: Vec<RosterJid>,
) -> Result<Vec<AccountKey>, HandlerError> {
    let mut contacts = Vec::with_capacity(watched.len());
    for contact in &watched {
        let Ok(account) = AccountKey::try_from(contact) else {
            continue;
        };
        let granted = transaction
            .roster_item(&account, &owner)
            .await
            .map_err(|error| roster_error(error, "roster_read"))?
            .is_some_and(|item| state::grants(item.subscription.state));
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
        &[VERSIONING_FEATURE, PRE_APPROVAL_FEATURE]
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

impl<A: ChunkAllocator, S: Storage> MessageHandler<A, S> for Roster {}

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
            let snapshot = transaction
                .roster(&owner)
                .await
                .map_err(|error| roster_error(error, "roster_read"))?;
            let item_count = snapshot.items.len();
            let outcome;
            let payload = match versioning::answer(known, &snapshot) {
                versioning::Answer::Full { stamped } => {
                    outcome = "full";
                    let version = stamped.then_some(snapshot.version);
                    Some(xml::build_response(snapshot.items, version, response)?)
                }
                versioning::Answer::Unchanged => {
                    outcome = "unchanged";
                    None
                }
            };
            tracing::info!(
                operation = "get",
                outcome,
                item_count = if payload.is_some() { item_count } else { 0 },
                owner_jid = ?owner.as_str(),
                "roster response prepared"
            );
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
                        .await
                        .map_err(|error| roster_error(error, "roster_write"))?
                        .map_or_else(RosterSubscription::default, |item| item.subscription);
                    let item = RosterItem {
                        jid: update.jid,
                        name: update.name,
                        groups: update.groups,
                        subscription,
                    };
                    let version = transaction
                        .put_roster_item(&owner, &item)
                        .await
                        .map_err(|error| roster_error(error, "roster_write"))?;
                    let mutation = RosterMutation {
                        version,
                        value: item,
                    };
                    let effects = Effects::new(vec![owner.clone()], move |delivery| {
                        tracing::info!(
                            operation = "upsert",
                            outcome = "upserted",
                            item_count = 1,
                            owner_jid = ?owner.as_str(),
                            contact_jid = ?mutation.value.jid.as_str(),
                            "roster operation committed"
                        );
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
    fn visibility<'a>(
        &'a self,
        owner: &'a AccountKey,
        observer: JidRef<'a>,
        transaction: &'a S::Read,
    ) -> PresenceFuture<'a, bool> {
        Box::pin(async move {
            Ok(transaction
                .roster_item(owner, &RosterJid::from(observer.bare()))
                .await
                .map_err(|error| roster_error(error, "roster_read"))?
                .is_some_and(|item| state::grants(item.subscription.state)))
        })
    }

    fn audience<'a>(
        &'a self,
        update: PresenceUpdate<'a>,
        transaction: &'a S::Read,
    ) -> PresenceFuture<'a, Option<PresenceAudience>> {
        Box::pin(async move {
            let owner = AccountKey::try_from(update.sender.bare())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            let snapshot = transaction
                .roster(&owner)
                .await
                .map_err(|error| roster_error(error, "roster_read"))?;
            let (subscribers, watched) = split_subscriptions(snapshot, &owner);
            let (pending, contacts) = if update.transition == PresenceTransition::Initial {
                let pending = transaction
                    .pending_requests(&owner)
                    .await
                    .map_err(|error| roster_error(error, "roster_read"))?;
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
                    let limits = self
                        .limits
                        .get(request.target.domainpart())
                        .copied()
                        .unwrap_or_default();
                    subscription::request_subscription(
                        transaction,
                        parties,
                        request.stanza,
                        limits.max_pending_subscription_requests,
                    )
                    .await
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
                PresenceRequestType::Available
                | PresenceRequestType::Unavailable
                | PresenceRequestType::Probe => {
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

fn storage_error(error: lonewolf_storage::StorageError, operation: &'static str) -> HandlerError {
    HandlerError::Internal {
        condition: StanzaErrorCondition::InternalServerError,
        failure: Failure {
            kind: FailureKind::Storage(error.kind()),
            operation,
        },
    }
}

fn roster_error(error: RosterError, operation: &'static str) -> HandlerError {
    match error {
        RosterError::ValueTooLarge => StanzaErrorCondition::NotAcceptable.into(),
        RosterError::PendingLimitExceeded => StanzaErrorCondition::ResourceConstraint.into(),
        RosterError::NoAccount => StanzaErrorCondition::Forbidden.into(),
        RosterError::Storage(error) => storage_error(error, operation),
    }
}

#[cfg(test)]
mod tests;
