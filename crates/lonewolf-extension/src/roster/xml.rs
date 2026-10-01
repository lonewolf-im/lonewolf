// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::{RosterItem, RosterJid, RosterVersion, SubscriptionState};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidError};
use lonewolf_xmpp::stanza::{
    BuildError, Element, ElementRef, IqType, NodeRef, PresenceType, RoutedStanza, Stanza,
    StanzaErrorCondition, StanzaNamespace, StanzaType,
};

use super::NAMESPACE;
use crate::delivery::DeliveryError;

/// The user-managed fields of one item, as a roster set carries them.
pub(super) struct RosterItemUpdate {
    pub(super) jid: RosterJid,
    pub(super) name: Option<Box<str>>,
    pub(super) groups: Vec<Box<str>>,
}

pub(super) enum RosterSet {
    Update(RosterItemUpdate),
    Remove(RosterJid),
}

/// Checks a roster get and returns the version the client holds, when it sent one.
pub(super) fn parse_get<'a, A: ChunkAllocator>(
    payload: ElementRef<'a, Arena<A>>,
) -> Result<Option<&'a str>, StanzaErrorCondition> {
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
    payload
        .attribute("ver", "")
        .map_err(|_| StanzaErrorCondition::InternalServerError)
}

pub(super) fn parse_set<A: ChunkAllocator>(
    payload: ElementRef<'_, Arena<A>>,
    response: &mut Arena<A>,
) -> Result<RosterSet, StanzaErrorCondition> {
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
    if item
        .attribute("subscription", "")
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
        == Some("remove")
    {
        return Ok(RosterSet::Remove(jid));
    }
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
    Ok(RosterSet::Update(RosterItemUpdate { jid, name, groups }))
}

/// Builds the full roster, stamped with `version` when the client asked for versioning.
pub(super) fn build_response<A: ChunkAllocator>(
    items: Vec<RosterItem>,
    version: Option<RosterVersion>,
    response: &mut Arena<A>,
) -> Result<Element, StanzaErrorCondition> {
    let mut built = Vec::with_capacity(items.len());
    for item in items {
        built.push(
            build_item(&item, response).map_err(|_| StanzaErrorCondition::InternalServerError)?,
        );
    }
    let mut query = Element::builder_in("query", NAMESPACE, response)
        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    if let Some(version) = version {
        query = query
            .attribute("ver", "", &version.get().to_string())
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    }
    for item in built {
        query = query
            .child(item)
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    }
    query
        .build()
        .map_err(|_| StanzaErrorCondition::InternalServerError)
}

/// Wraps one roster item in the push addressed to `to`, stamped with the version the
/// change produced.
pub(super) fn build_push<A: ChunkAllocator>(
    to: Jid,
    item: Element,
    version: RosterVersion,
    arena: &mut Arena<A>,
) -> Result<Stanza, DeliveryError> {
    let version = version.get().to_string();
    let query = Element::builder_in("query", NAMESPACE, arena)?
        .attribute("ver", "", &version)?
        .child(item)?
        .build()?;
    let id = format!("roster-{version}");
    let push = Stanza::builder_in(StanzaType::Iq(IqType::Set), StanzaNamespace::Client, arena)
        .id(Some(&id))?
        .to(Some(to))?
        .child(query)?
        .build()?;
    Ok(push)
}

pub(super) fn build_removed_item<A: ChunkAllocator>(
    contact: &RosterJid,
    arena: &mut Arena<A>,
) -> Result<Element, BuildError> {
    Element::builder_in("item", NAMESPACE, arena)?
        .attribute("jid", "", contact.as_str())?
        .attribute("subscription", "", "remove")?
        .build()
}

/// Builds the `unsubscribe` and `unsubscribed` presence from `owner` to `contact`.
pub(super) fn subscription_withdrawals<A: ChunkAllocator>(
    owner: &AccountKey,
    contact: &AccountKey,
    mut arena: Arena<A>,
) -> Result<(RoutedStanza<A>, RoutedStanza<A>), DeliveryError> {
    let from = Jid::parse_in(owner.as_str(), &mut arena)?;
    let to = Jid::parse_in(contact.as_str(), &mut arena)?;
    let withdrawal = Stanza::builder_in(
        StanzaType::Presence(PresenceType::Unsubscribe),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(from))?
    .to(Some(to))?
    .build()?;
    let cancellation = Stanza::builder_in(
        StanzaType::Presence(PresenceType::Unsubscribed),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(from))?
    .to(Some(to))?
    .build()?;
    Ok(RoutedStanza::from_parts_pair(
        withdrawal,
        cancellation,
        arena,
    ))
}

/// Builds the `subscribed` reply the server sends on behalf of the request target.
pub(super) fn approval_reply<A: ChunkAllocator>(
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

pub(super) fn build_item<A: ChunkAllocator>(
    item: &RosterItem,
    arena: &mut Arena<A>,
) -> Result<Element, BuildError> {
    let mut groups = Vec::with_capacity(item.groups.len());
    for group in &item.groups {
        groups.push(
            Element::builder_in("group", NAMESPACE, arena)
                .and_then(|builder| builder.text(group))
                .and_then(|builder| builder.build())?,
        );
    }
    let mut builder = Element::builder_in("item", NAMESPACE, arena)
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
