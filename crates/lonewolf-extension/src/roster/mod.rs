// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;

use async_lock::{Mutex, MutexGuardArc};
use lonewolf_storage::account::{AccountKey, AccountRepository};
use lonewolf_storage::roster::{
    PendingSubscription, RosterError, RosterItem, RosterItemUpdate, RosterJid, RosterMutation,
    RosterRepository, RosterSnapshot, RosterSubscription, RosterVersion, SubscriptionCancellation,
    SubscriptionRequestOutcome, SubscriptionState, SubscriptionWithdrawal,
};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidError};
use lonewolf_xmpp::stanza::{BuildError, Element, ElementRef, NodeRef, StanzaErrorCondition};

use crate::iq::{
    IqEffect, IqFuture, IqHandler, IqRegistration, IqRequest, IqRequestType, IqResponse, IqRoute,
    IqScope,
};
use crate::presence::{
    AcceptedPresence, PresenceDirection, PresenceEffect, PresenceFuture, PresenceHandler,
    PresenceRegistration, PresenceRequest, PresenceRequestType, PresenceRoute,
};

pub const NAME: &str = "roster";
pub const NAMESPACE: &str = "jabber:iq:roster";
const ORDER_SHARDS: usize = 64;

pub struct RosterOrder {
    _first: MutexGuardArc<()>,
    _second: Option<MutexGuardArc<()>>,
}

impl RosterOrder {
    fn new(guard: MutexGuardArc<()>) -> Self {
        Self {
            _first: guard,
            _second: None,
        }
    }

    fn pair(first: MutexGuardArc<()>, second: MutexGuardArc<()>) -> Self {
        Self {
            _first: first,
            _second: Some(second),
        }
    }
}

pub struct RosterDelivery {
    order: RosterOrder,
    mutation: Option<RosterMutation<RosterItem>>,
}

impl RosterDelivery {
    fn new(order: RosterOrder, mutation: Option<RosterMutation<RosterItem>>) -> Self {
        Self { order, mutation }
    }

    pub fn into_push(self) -> Option<RosterPush> {
        self.mutation
            .map(|mutation| RosterPush::new(self.order, mutation.value, mutation.version))
    }
}

pub struct RosterCancellation {
    order: RosterOrder,
    outcome: SubscriptionCancellation,
}

impl RosterCancellation {
    fn new(order: RosterOrder, outcome: SubscriptionCancellation) -> Self {
        Self { order, outcome }
    }

    pub fn into_parts(self) -> (RosterOrder, SubscriptionCancellation) {
        (self.order, self.outcome)
    }
}

pub struct RosterWithdrawal {
    order: RosterOrder,
    outcome: SubscriptionWithdrawal,
}

impl RosterWithdrawal {
    fn new(order: RosterOrder, outcome: SubscriptionWithdrawal) -> Self {
        Self { order, outcome }
    }

    pub fn into_parts(self) -> (RosterOrder, SubscriptionWithdrawal) {
        (self.order, self.outcome)
    }
}

pub struct RosterPush {
    _order: RosterOrder,
    item: RosterItem,
    version: RosterVersion,
}

impl RosterPush {
    fn new(order: RosterOrder, item: RosterItem, version: RosterVersion) -> Self {
        Self {
            _order: order,
            item,
            version,
        }
    }

    pub fn item(&self) -> &RosterItem {
        &self.item
    }

    pub fn version(&self) -> RosterVersion {
        self.version
    }

    pub fn into_parts(self) -> (RosterOrder, RosterMutation<RosterItem>) {
        (
            self._order,
            RosterMutation {
                version: self.version,
                value: self.item,
            },
        )
    }

    pub async fn with_mutation<T, F, O>(self, operation: O) -> T
    where
        F: Future<Output = T>,
        O: FnOnce(RosterMutation<RosterItem>) -> F,
    {
        let (order, mutation) = self.into_parts();
        let result = operation(mutation).await;
        drop(order);
        result
    }
}

pub struct RosterRegistrations<A: ChunkAllocator> {
    pub iq: [IqRegistration<A>; 2],
    pub presence: [PresenceRegistration<A>; 10],
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
        iq: [
            IqRegistration::new(
                IqRoute {
                    scope: IqScope::Account,
                    kind: IqRequestType::Get,
                    namespace: NAMESPACE,
                    name: "query",
                },
                Arc::clone(&iq),
            ),
            IqRegistration::new(
                IqRoute {
                    scope: IqScope::Account,
                    kind: IqRequestType::Set,
                    namespace: NAMESPACE,
                    name: "query",
                },
                iq,
            ),
        ],
        presence: [
            PresenceRegistration::new(
                PresenceRoute {
                    direction: PresenceDirection::Outbound,
                    kind: PresenceRequestType::Subscribe,
                },
                Arc::clone(&presence),
            ),
            PresenceRegistration::new(
                PresenceRoute {
                    direction: PresenceDirection::Inbound,
                    kind: PresenceRequestType::Subscribe,
                },
                Arc::clone(&presence),
            ),
            PresenceRegistration::new(
                PresenceRoute {
                    direction: PresenceDirection::Outbound,
                    kind: PresenceRequestType::Subscribed,
                },
                Arc::clone(&presence),
            ),
            PresenceRegistration::new(
                PresenceRoute {
                    direction: PresenceDirection::Inbound,
                    kind: PresenceRequestType::Subscribed,
                },
                Arc::clone(&presence),
            ),
            PresenceRegistration::new(
                PresenceRoute {
                    direction: PresenceDirection::Outbound,
                    kind: PresenceRequestType::Unsubscribed,
                },
                Arc::clone(&presence),
            ),
            PresenceRegistration::new(
                PresenceRoute {
                    direction: PresenceDirection::Inbound,
                    kind: PresenceRequestType::Unsubscribed,
                },
                Arc::clone(&presence),
            ),
            PresenceRegistration::new(
                PresenceRoute {
                    direction: PresenceDirection::Outbound,
                    kind: PresenceRequestType::Unsubscribe,
                },
                Arc::clone(&presence),
            ),
            PresenceRegistration::new(
                PresenceRoute {
                    direction: PresenceDirection::Inbound,
                    kind: PresenceRequestType::Unsubscribe,
                },
                Arc::clone(&presence),
            ),
            PresenceRegistration::new(
                PresenceRoute {
                    direction: PresenceDirection::Outbound,
                    kind: PresenceRequestType::Available,
                },
                Arc::clone(&presence),
            ),
            PresenceRegistration::new(
                PresenceRoute {
                    direction: PresenceDirection::Outbound,
                    kind: PresenceRequestType::Unavailable,
                },
                presence,
            ),
        ],
    }
}

struct Roster<R, C> {
    repository: R,
    accounts: C,
    order: RosterSequencer,
}

impl<R: RosterRepository, C> Roster<R, C> {
    async fn subscriber_snapshot(
        &self,
        owner: &AccountKey,
    ) -> Result<(RosterOrder, Vec<RosterJid>), StanzaErrorCondition> {
        let order = RosterOrder::new(self.order.lock(owner).await);
        let subscribers = presence_subscribers(
            self.repository
                .snapshot(owner)
                .await
                .map_err(roster_error)?,
            owner,
        );
        Ok((order, subscribers))
    }
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

    async fn lock(&self, owner: &AccountKey) -> MutexGuardArc<()> {
        let index = self.shard_index(owner);
        Arc::clone(&self.shards[index]).lock_arc().await
    }

    async fn lock_pair(&self, first: &AccountKey, second: &AccountKey) -> RosterOrder {
        let first_index = self.shard_index(first);
        let second_index = self.shard_index(second);
        if first_index == second_index {
            return RosterOrder::new(Arc::clone(&self.shards[first_index]).lock_arc().await);
        }
        let (first_index, second_index) = if first_index < second_index {
            (first_index, second_index)
        } else {
            (second_index, first_index)
        };
        let first = Arc::clone(&self.shards[first_index]).lock_arc().await;
        let second = Arc::clone(&self.shards[second_index]).lock_arc().await;
        RosterOrder::pair(first, second)
    }

    fn shard_index(&self, owner: &AccountKey) -> usize {
        (self.hash_state.hash_one(owner) as usize) % self.shards.len()
    }
}

impl<A, R, C> IqHandler<A> for Roster<R, C>
where
    A: ChunkAllocator,
    R: RosterRepository,
    C: AccountRepository,
{
    fn handle<'a>(&'a self, request: IqRequest<'a, A>, response: &'a mut Arena<A>) -> IqFuture<'a> {
        Box::pin(async move {
            if request.target != request.sender.bare() {
                return Err(StanzaErrorCondition::Forbidden);
            }
            let owner = AccountKey::try_from(request.sender.bare())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            match request.kind {
                IqRequestType::Get => {
                    validate_get(request.payload)?;
                    let order = RosterOrder::new(self.order.lock(&owner).await);
                    let snapshot = self
                        .repository
                        .snapshot(&owner)
                        .await
                        .map_err(roster_error)?;
                    build_response(snapshot, order, response)
                }
                IqRequestType::Set => {
                    let update = parse_update(request.payload, response)?;
                    let order = RosterOrder::new(self.order.lock(&owner).await);
                    let mutation = self
                        .repository
                        .upsert(&owner, update)
                        .await
                        .map_err(roster_error)?;
                    Ok(
                        IqResponse::new(None).with_effect(IqEffect::PushRoster(RosterPush::new(
                            order,
                            mutation.value,
                            mutation.version,
                        ))),
                    )
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
    fn handle<'a>(&'a self, request: PresenceRequest<'a, A>) -> PresenceFuture<'a> {
        Box::pin(async move {
            match (request.direction, request.kind) {
                (PresenceDirection::Outbound, PresenceRequestType::Subscribe) => {
                    let contact_account = AccountKey::try_from(request.target.bare())
                        .map_err(|_| StanzaErrorCondition::BadRequest)?;
                    if self
                        .accounts
                        .get(&contact_account)
                        .await
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?
                        .is_none()
                    {
                        return Err(StanzaErrorCondition::ServiceUnavailable);
                    }
                    Ok(PresenceEffect::Route)
                }
                (
                    PresenceDirection::Outbound,
                    PresenceRequestType::Subscribed | PresenceRequestType::Unsubscribed,
                ) => Ok(PresenceEffect::Route),
                (PresenceDirection::Outbound, PresenceRequestType::Unsubscribe) => {
                    Ok(PresenceEffect::Route)
                }
                (PresenceDirection::Inbound, PresenceRequestType::Subscribe) => {
                    let recipient = AccountKey::try_from(request.target.bare())
                        .map_err(|_| StanzaErrorCondition::ServiceUnavailable)?;
                    if self
                        .accounts
                        .get(&recipient)
                        .await
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?
                        .is_none()
                    {
                        return Err(StanzaErrorCondition::ServiceUnavailable);
                    }
                    let subscriber = AccountKey::try_from(request.sender.bare())
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    let contact = RosterJid::from(request.target.bare());
                    let sender = RosterJid::from(request.sender.bare());
                    let order = self.order.lock_pair(&subscriber, &recipient).await;
                    let mut stanza = String::new();
                    request
                        .stanza
                        .write_xml(&mut stanza)
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    let outcome = self
                        .repository
                        .request_subscription(
                            &subscriber,
                            &contact,
                            &recipient,
                            PendingSubscription {
                                sender,
                                stanza: stanza.into_bytes().into_boxed_slice(),
                            },
                        )
                        .await
                        .map_err(roster_error)?;
                    Ok(match outcome {
                        SubscriptionRequestOutcome::Pending { mutation } => {
                            PresenceEffect::DeliverThenPushSenderRoster(RosterDelivery::new(
                                order, mutation,
                            ))
                        }
                        SubscriptionRequestOutcome::AutoApprove { mutation } => {
                            PresenceEffect::AutoApproveSubscription(RosterDelivery::new(
                                order, mutation,
                            ))
                        }
                    })
                }
                (PresenceDirection::Inbound, PresenceRequestType::Subscribed) => {
                    let owner = AccountKey::try_from(request.target.bare())
                        .map_err(|_| StanzaErrorCondition::ServiceUnavailable)?;
                    if self
                        .accounts
                        .get(&owner)
                        .await
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?
                        .is_none()
                    {
                        return Ok(PresenceEffect::None);
                    }
                    let contact = RosterJid::from(request.sender.bare());
                    let order = RosterOrder::new(self.order.lock(&owner).await);
                    let mutation = self
                        .repository
                        .update_subscription(
                            &owner,
                            &contact,
                            RosterSubscription::approve_pending_out,
                        )
                        .await
                        .map_err(roster_error)?;
                    Ok(mutation.map_or(PresenceEffect::Accept, |mutation| {
                        PresenceEffect::DeliverThenPushRoster(RosterPush::new(
                            order,
                            mutation.value,
                            mutation.version,
                        ))
                    }))
                }
                (PresenceDirection::Inbound, PresenceRequestType::Unsubscribed) => {
                    let grantor = AccountKey::try_from(request.sender.bare())
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    let subscriber = AccountKey::try_from(request.target.bare())
                        .map_err(|_| StanzaErrorCondition::ServiceUnavailable)?;
                    let subscriber_exists = self
                        .accounts
                        .get(&subscriber)
                        .await
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?
                        .is_some();
                    let order = self.order.lock_pair(&grantor, &subscriber).await;
                    let contact = RosterJid::from(request.target.bare());
                    let grantor_jid =
                        subscriber_exists.then(|| RosterJid::from(request.sender.bare()));
                    let outcome = self
                        .repository
                        .cancel_subscription(
                            &grantor,
                            &contact,
                            grantor_jid.as_ref().map(|jid| (&subscriber, jid)),
                        )
                        .await
                        .map_err(roster_error)?;
                    Ok(PresenceEffect::CancelSubscription(RosterCancellation::new(
                        order, outcome,
                    )))
                }
                (PresenceDirection::Inbound, PresenceRequestType::Unsubscribe) => {
                    let subscriber = AccountKey::try_from(request.sender.bare())
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    let recipient = AccountKey::try_from(request.target.bare())
                        .map_err(|_| StanzaErrorCondition::ServiceUnavailable)?;
                    let recipient_exists = self
                        .accounts
                        .get(&recipient)
                        .await
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?
                        .is_some();
                    let order = self.order.lock_pair(&subscriber, &recipient).await;
                    let contact = RosterJid::from(request.target.bare());
                    let subscriber_jid =
                        recipient_exists.then(|| RosterJid::from(request.sender.bare()));
                    let outcome = self
                        .repository
                        .unsubscribe(
                            &subscriber,
                            &contact,
                            subscriber_jid.as_ref().map(|jid| (&recipient, jid)),
                        )
                        .await
                        .map_err(roster_error)?;
                    Ok(PresenceEffect::WithdrawSubscription(RosterWithdrawal::new(
                        order, outcome,
                    )))
                }
                (PresenceDirection::Outbound, PresenceRequestType::Available) => {
                    let owner = AccountKey::try_from(request.sender.bare())
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    let (order, subscribers) = self.subscriber_snapshot(&owner).await?;
                    let pending = self
                        .repository
                        .pending(&owner)
                        .await
                        .map_err(roster_error)?;
                    Ok(PresenceEffect::Replay {
                        order,
                        pending,
                        subscribers,
                    })
                }
                (PresenceDirection::Outbound, PresenceRequestType::Unavailable) => {
                    let owner = AccountKey::try_from(request.sender.bare())
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    let (order, subscribers) = self.subscriber_snapshot(&owner).await?;
                    Ok(PresenceEffect::Broadcast { order, subscribers })
                }
                _ => Err(StanzaErrorCondition::ServiceUnavailable),
            }
        })
    }

    fn accepted<'a>(&'a self, request: AcceptedPresence<'a>) -> PresenceFuture<'a> {
        Box::pin(async move {
            match (request.direction, request.kind) {
                (PresenceDirection::Outbound, PresenceRequestType::Unavailable) => {
                    let owner = AccountKey::try_from(request.sender.bare())
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    let (order, subscribers) = self.subscriber_snapshot(&owner).await?;
                    Ok(PresenceEffect::Broadcast { order, subscribers })
                }
                (PresenceDirection::Outbound, PresenceRequestType::Subscribed) => {
                    let owner = AccountKey::try_from(request.sender.bare())
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    let contact = RosterJid::from(request.target.bare());
                    let order = self.order.lock(&owner).await;
                    let resolution = self
                        .repository
                        .resolve_pending(&owner, &contact, approve_outbound_subscription)
                        .await
                        .map_err(roster_error)?;
                    Ok(PresenceEffect::PushRoster(
                        resolution
                            .and_then(|resolution| resolution.mutation)
                            .map(|mutation| {
                                RosterPush::new(
                                    RosterOrder::new(order),
                                    mutation.value,
                                    mutation.version,
                                )
                            }),
                    ))
                }
                _ => Err(StanzaErrorCondition::ServiceUnavailable),
            }
        })
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
    order: RosterOrder,
    response: &mut Arena<A>,
) -> Result<IqResponse, StanzaErrorCondition> {
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
        .map(|query| {
            IqResponse::new(Some(query)).with_effect(IqEffect::MarkRosterInterested(order))
        })
        .map_err(|_| StanzaErrorCondition::InternalServerError)
}

pub fn build_item_in<A: ChunkAllocator>(
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
