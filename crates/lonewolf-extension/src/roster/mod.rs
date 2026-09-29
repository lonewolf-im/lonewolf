// SPDX-License-Identifier: Apache-2.0

use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;

use async_lock::{Mutex, MutexGuardArc};
use lonewolf_storage::account::{AccountKey, AccountRepository};
use lonewolf_storage::roster::{
    PendingSubscription, RosterError, RosterItem, RosterItemUpdate, RosterJid, RosterMutation,
    RosterRepository, RosterSnapshot, RosterSubscription, SubscriptionRequestOutcome,
    SubscriptionState,
};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidError};
use lonewolf_xmpp::stanza::{
    BuildError, Element, ElementRef, IqType, NodeRef, PresenceType, RoutedStanza, Stanza,
    StanzaErrorCondition, StanzaNamespace, StanzaType,
};

use crate::delivery::{Delivery, DeliveryError, HandlerError, SessionTag};
use crate::iq::{IqFuture, IqHandler, IqRegistration, IqRequest, IqRequestType, IqRoute, IqScope};
use crate::presence::{
    PresenceAudience, PresenceFuture, PresenceHandler, PresenceRegistration, PresenceRequest,
    PresenceRequestType, PresenceUpdate, ReceiveFuture,
};

pub const NAME: &str = "roster";
pub const NAMESPACE: &str = "jabber:iq:roster";
const ORDER_SHARDS: usize = 64;

/// Serializes roster deliveries for one or two accounts while it is alive.
pub struct RosterOrder {
    _first: MutexGuardArc<()>,
    _second: Option<MutexGuardArc<()>>,
}

pub struct RosterRegistrations<A: ChunkAllocator> {
    pub iq: [IqRegistration<A>; 2],
    pub presence: [PresenceRegistration<A>; 6],
}

pub fn registrations<A, R, C>(repository: R, accounts: C) -> RosterRegistrations<A>
where
    A: ChunkAllocator,
    R: RosterRepository + 'static,
    C: AccountRepository + 'static,
{
    let roster = Arc::new(Roster {
        repository,
        accounts,
        order: RosterSequencer::new(),
    });
    let iq: Arc<dyn IqHandler<A>> = roster.clone();
    let presence: Arc<dyn PresenceHandler<A>> = roster;
    RosterRegistrations {
        iq: [IqRequestType::Get, IqRequestType::Set].map(|kind| {
            IqRegistration::new(
                IqRoute {
                    scope: IqScope::Account,
                    kind,
                    namespace: NAMESPACE,
                    name: "query",
                },
                Arc::clone(&iq),
            )
        }),
        presence: PresenceRequestType::ALL
            .map(|kind| PresenceRegistration::new(kind, Arc::clone(&presence))),
    }
}

struct Roster<R, C> {
    repository: R,
    accounts: C,
    order: RosterSequencer,
}

struct RosterSequencer {
    hash_state: RandomState,
    shards: [Arc<Mutex<()>>; ORDER_SHARDS],
}

impl RosterSequencer {
    fn new() -> Self {
        Self {
            hash_state: RandomState::new(),
            shards: std::array::from_fn(|_| Arc::new(Mutex::new(()))),
        }
    }

    async fn lock(&self, owner: &AccountKey) -> RosterOrder {
        RosterOrder {
            _first: self.lock_shard(self.shard_index(owner)).await,
            _second: None,
        }
    }

    async fn lock_pair(&self, first: &AccountKey, second: &AccountKey) -> RosterOrder {
        let first_index = self.shard_index(first);
        let second_index = self.shard_index(second);
        if first_index == second_index {
            return self.lock(first).await;
        }
        let (first_index, second_index) = if first_index < second_index {
            (first_index, second_index)
        } else {
            (second_index, first_index)
        };
        RosterOrder {
            _first: self.lock_shard(first_index).await,
            _second: Some(self.lock_shard(second_index).await),
        }
    }

    async fn lock_shard(&self, index: usize) -> MutexGuardArc<()> {
        Arc::clone(&self.shards[index]).lock_arc().await
    }

    fn shard_index(&self, owner: &AccountKey) -> usize {
        (self.hash_state.hash_one(owner) as usize) % self.shards.len()
    }
}

impl<R: RosterRepository, C: AccountRepository> Roster<R, C> {
    async fn account_exists(&self, account: &AccountKey) -> Result<bool, StanzaErrorCondition> {
        self.accounts
            .get(account)
            .await
            .map(|account| account.is_some())
            .map_err(|_| StanzaErrorCondition::InternalServerError)
    }

    async fn request_subscription<A: ChunkAllocator>(
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
            .await
            .map_err(roster_error)?;
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
                let approval = approval_reply(stanza, delivery.arena()?)?;
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

    async fn approve_subscription<A: ChunkAllocator>(
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
            .await
            .map_err(roster_error)?;
        let sender = self
            .repository
            .resolve_pending(
                &parties.sender,
                &parties.target_jid,
                approve_outbound_subscription,
            )
            .await
            .map_err(roster_error)?
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

    async fn cancel_subscription<A: ChunkAllocator>(
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
            .await
            .map_err(roster_error)?;
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

    async fn withdraw_subscription<A: ChunkAllocator>(
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
            .await
            .map_err(roster_error)?;
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

struct Parties {
    sender: AccountKey,
    target: AccountKey,
    sender_jid: RosterJid,
    target_jid: RosterJid,
}

impl Parties {
    /// A domain-only target cannot hold a roster, so it is reported as unavailable.
    fn new<A: ChunkAllocator>(
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
                    validate_get(request.payload)?;
                    let _order = self.order.lock(&owner).await;
                    let snapshot = self
                        .repository
                        .snapshot(&owner)
                        .await
                        .map_err(roster_error)?;
                    let payload = build_response(snapshot, response)?;
                    delivery.tag_session(SessionTag::Interested).await?;
                    Ok(Some(payload))
                }
                IqRequestType::Set => {
                    let update = parse_update(request.payload, response)?;
                    let _order = self.order.lock(&owner).await;
                    let mutation = self
                        .repository
                        .upsert(&owner, update)
                        .await
                        .map_err(roster_error)?;
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
            Box::new(move |to, arena| build_push(to, &mutation, arena)),
        )
        .await
}

fn build_push<A: ChunkAllocator>(
    to: Jid,
    mutation: &RosterMutation<RosterItem>,
    arena: &mut Arena<A>,
) -> Result<Stanza, DeliveryError> {
    let item = build_item_in(&mutation.value, arena)?;
    let query = Element::builder_in("query", NAMESPACE, arena)?
        .child(item)?
        .build()?;
    let id = format!("roster-{}", mutation.version.get());
    let push = Stanza::builder_in(StanzaType::Iq(IqType::Set), StanzaNamespace::Client, arena)
        .id(Some(&id))?
        .to(Some(to))?
        .child(query)?
        .build()?;
    Ok(push)
}

/// Builds the `subscribed` reply the server sends on behalf of the request target.
fn approval_reply<A: ChunkAllocator>(
    request: &RoutedStanza<A>,
    mut arena: Arena<A>,
) -> Result<RoutedStanza<A>, DeliveryError> {
    let view = request.resolve()?;
    let from = view.to()?.ok_or(DeliveryError)?.clone_in(&mut arena)?;
    let to = view.from()?.ok_or(DeliveryError)?.clone_in(&mut arena)?;
    let approval = Stanza::builder_in(
        StanzaType::Presence(PresenceType::Subscribed),
        StanzaNamespace::Client,
        &mut arena,
    )
    .id(view.id()?)?
    .lang(view.lang()?)?
    .from(Some(from))?
    .to(Some(to))?
    .build()?;
    Ok(RoutedStanza::from_parts(approval, arena))
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

fn validate_get<A: ChunkAllocator>(
    payload: ElementRef<'_, Arena<A>>,
) -> Result<(), StanzaErrorCondition> {
    for child in payload
        .children()
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
    {
        if let NodeRef::Element(child) =
            child.map_err(|_| StanzaErrorCondition::InternalServerError)?
            && child.name() == "item"
            && child.namespace() == NAMESPACE
        {
            return Err(StanzaErrorCondition::BadRequest);
        }
    }
    Ok(())
}

fn parse_update<A: ChunkAllocator>(
    payload: ElementRef<'_, Arena<A>>,
    response: &mut Arena<A>,
) -> Result<RosterItemUpdate, StanzaErrorCondition> {
    let mut item = None;
    for child in payload
        .children()
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
    {
        if let NodeRef::Element(child) =
            child.map_err(|_| StanzaErrorCondition::InternalServerError)?
            && child.name() == "item"
            && child.namespace() == NAMESPACE
        {
            if item.is_some() {
                return Err(StanzaErrorCondition::BadRequest);
            }
            item = Some(child);
        }
    }
    let item = item.ok_or(StanzaErrorCondition::BadRequest)?;
    if item
        .attribute("subscription", "")
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
        == Some("remove")
    {
        return Err(StanzaErrorCondition::NotAllowed);
    }
    let jid = item
        .attribute("jid", "")
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
        .ok_or(StanzaErrorCondition::BadRequest)?;
    let jid = Jid::parse_in(jid, response).map_err(jid_error)?;
    if jid.is_full() {
        return Err(StanzaErrorCondition::BadRequest);
    }
    let jid = RosterJid::from(
        jid.resolve(response)
            .map_err(|_| StanzaErrorCondition::InternalServerError)?,
    );
    let name = item
        .attribute("name", "")
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
        .filter(|name| !name.is_empty())
        .map(Box::from);
    let mut groups: Vec<Box<str>> = Vec::new();
    for child in item
        .children()
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
    {
        let NodeRef::Element(group) =
            child.map_err(|_| StanzaErrorCondition::InternalServerError)?
        else {
            continue;
        };
        if group.name() != "group" || group.namespace() != NAMESPACE {
            continue;
        }
        let group = group
            .text()
            .map_err(|_| StanzaErrorCondition::InternalServerError)?
            .filter(|group| !group.is_empty())
            .ok_or(StanzaErrorCondition::NotAcceptable)?;
        if groups.iter().any(|existing| existing.as_ref() == group) {
            return Err(StanzaErrorCondition::BadRequest);
        }
        groups.push(Box::from(group));
    }
    Ok(RosterItemUpdate { jid, name, groups })
}

const fn jid_error(error: JidError) -> StanzaErrorCondition {
    match error {
        JidError::AllocationFailed(_) | JidError::AccessFailed(_) => {
            StanzaErrorCondition::InternalServerError
        }
        JidError::EmptyPart(_) | JidError::PartTooLong(_) | JidError::InvalidPart(_) => {
            StanzaErrorCondition::BadRequest
        }
    }
}

fn roster_error(error: RosterError) -> StanzaErrorCondition {
    match error {
        RosterError::ValueTooLarge => StanzaErrorCondition::NotAcceptable,
        RosterError::Storage(_) => StanzaErrorCondition::InternalServerError,
    }
}

fn build_response<A: ChunkAllocator>(
    snapshot: RosterSnapshot,
    response: &mut Arena<A>,
) -> Result<Element, StanzaErrorCondition> {
    let mut items = Vec::with_capacity(snapshot.items.len());
    for item in snapshot.items {
        items.push(
            build_item_in(&item, response)
                .map_err(|_| StanzaErrorCondition::InternalServerError)?,
        );
    }
    let mut query = Element::builder_in("query", NAMESPACE, response)
        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    for item in items {
        query = query
            .child(item)
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    }
    query
        .build()
        .map_err(|_| StanzaErrorCondition::InternalServerError)
}

fn build_item_in<A: ChunkAllocator>(
    item: &RosterItem,
    response: &mut Arena<A>,
) -> Result<Element, BuildError> {
    let mut groups = Vec::with_capacity(item.groups.len());
    for group in &item.groups {
        groups.push(
            Element::builder_in("group", NAMESPACE, response)
                .and_then(|builder| builder.text(group))
                .and_then(|builder| builder.build())?,
        );
    }
    let mut builder = Element::builder_in("item", NAMESPACE, response)
        .and_then(|builder| builder.attribute("jid", "", item.jid.as_str()))
        .and_then(|builder| match item.name.as_deref() {
            Some(name) => builder.attribute("name", "", name),
            None => Ok(builder),
        })
        .and_then(|builder| {
            builder.attribute(
                "subscription",
                "",
                subscription_name(item.subscription.state),
            )
        })?;
    if item.subscription.pending_out {
        builder = builder.attribute("ask", "", "subscribe")?;
    }
    if item.subscription.approved {
        builder = builder.attribute("approved", "", "true")?;
    }
    for group in groups {
        builder = builder.child(group)?;
    }
    builder.build()
}

const fn subscription_name(state: SubscriptionState) -> &'static str {
    match state {
        SubscriptionState::None => "none",
        SubscriptionState::To => "to",
        SubscriptionState::From => "from",
        SubscriptionState::Both => "both",
    }
}

#[cfg(test)]
mod tests;
