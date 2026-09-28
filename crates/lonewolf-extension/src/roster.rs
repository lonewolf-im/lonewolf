// SPDX-License-Identifier: Apache-2.0

use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;

use async_lock::{Mutex, MutexGuardArc};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::{
    RosterError, RosterItem, RosterItemUpdate, RosterJid, RosterRepository, RosterSnapshot,
    RosterVersion, SubscriptionState,
};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidError};
use lonewolf_xmpp::stanza::{BuildError, Element, ElementRef, NodeRef, StanzaErrorCondition};

use crate::iq::{
    IqEffect, IqFuture, IqHandler, IqRegistration, IqRequest, IqRequestType, IqResponse, IqRoute,
    IqScope,
};

pub const NAME: &str = "roster";
pub const NAMESPACE: &str = "jabber:iq:roster";
const ORDER_SHARDS: usize = 64;

pub struct RosterOrder {
    _guard: MutexGuardArc<()>,
}

impl RosterOrder {
    fn new(guard: MutexGuardArc<()>) -> Self {
        Self { _guard: guard }
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
}

pub fn registrations<A, R>(repository: R) -> [IqRegistration<A>; 2]
where
    A: ChunkAllocator,
    R: RosterRepository + 'static,
{
    let handler: Arc<dyn IqHandler<A>> = Arc::new(Roster {
        repository,
        order: RosterSequencer::new(),
    });
    [
        IqRegistration::new(
            IqRoute {
                scope: IqScope::Account,
                kind: IqRequestType::Get,
                namespace: NAMESPACE,
                name: "query",
            },
            Arc::clone(&handler),
        ),
        IqRegistration::new(
            IqRoute {
                scope: IqScope::Account,
                kind: IqRequestType::Set,
                namespace: NAMESPACE,
                name: "query",
            },
            handler,
        ),
    ]
}

struct Roster<R> {
    repository: R,
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

    async fn lock(&self, owner: &AccountKey) -> MutexGuardArc<()> {
        let index = (self.hash_state.hash_one(owner) as usize) % self.shards.len();
        Arc::clone(&self.shards[index]).lock_arc().await
    }
}

impl<A, R> IqHandler<A> for Roster<R>
where
    A: ChunkAllocator,
    R: RosterRepository,
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
