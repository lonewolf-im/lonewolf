// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::{
    MAX_GROUP_NAME_BYTES, MAX_ITEM_NAME_BYTES, RosterItem, RosterJid, RosterVersion,
    SubscriptionState,
};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidError};
use lonewolf_xmpp::stanza::{
    BuildError, Element, ElementRef, IqType, NodeRef, PresenceType, RoutedStanza, Stanza,
    StanzaErrorCondition, StanzaErrorText, StanzaNamespace, StanzaType,
};

use super::NAMESPACE;
use crate::delivery::{DeliveryError, HandlerError};

pub(super) struct RosterItemUpdate {
    pub(super) jid: RosterJid,
    pub(super) name: Option<Box<str>>,
    pub(super) groups: Vec<Box<str>>,
}

pub(super) enum RosterSet {
    Update(RosterItemUpdate),
    Remove(RosterJid),
}

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
) -> Result<RosterSet, HandlerError> {
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
                return Err(StanzaErrorCondition::BadRequest.into());
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
        return Err(StanzaErrorCondition::BadRequest.into());
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
        .filter(|name| !name.is_empty());
    if name.is_some_and(|name| name.len() > MAX_ITEM_NAME_BYTES) {
        return Err(oversized(
            "A roster contact name can have at most ",
            MAX_ITEM_NAME_BYTES,
            " bytes. Shorten the contact name.",
        ));
    }
    let name = name.map(Box::from);
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
        if group.len() > MAX_GROUP_NAME_BYTES {
            return Err(oversized(
                "A roster group name can have at most ",
                MAX_GROUP_NAME_BYTES,
                " bytes. Shorten the group name.",
            ));
        }
        if groups.iter().any(|existing| existing.as_ref() == group) {
            return Err(StanzaErrorCondition::BadRequest.into());
        }
        groups.push(Box::from(group));
    }
    Ok(RosterSet::Update(RosterItemUpdate { jid, name, groups }))
}

const fn oversized(prefix: &'static str, max: usize, suffix: &'static str) -> HandlerError {
    HandlerError::described(
        StanzaErrorCondition::NotAcceptable,
        StanzaErrorText::Limit {
            prefix,
            max,
            suffix,
        },
    )
}

pub(super) fn build_response<A: ChunkAllocator>(
    items: Vec<RosterItem>,
    version: Option<RosterVersion>,
    response: &mut Arena<A>,
) -> Result<Element, StanzaErrorCondition> {
    let mut built = Vec::with_capacity(items.len());
    for item in items {
        built.push(
            build_item(&item, response).map_err(|_| StanzaErrorCondition::ResourceConstraint)?,
        );
    }
    let mut query = Element::builder_in("query", NAMESPACE, response)
        .map_err(|_| StanzaErrorCondition::ResourceConstraint)?;
    if let Some(version) = version {
        query = query
            .attribute("ver", "", &version.get().to_string())
            .map_err(|_| StanzaErrorCondition::ResourceConstraint)?;
    }
    for item in built {
        query = query
            .child(item)
            .map_err(|_| StanzaErrorCondition::ResourceConstraint)?;
    }
    query
        .build()
        .map_err(|_| StanzaErrorCondition::ResourceConstraint)
}

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

pub(super) fn subscription_withdrawals<A: ChunkAllocator>(
    owner: &AccountKey,
    contact: &str,
    mut arena: Arena<A>,
) -> Result<(RoutedStanza<A>, RoutedStanza<A>), DeliveryError> {
    let from = Jid::parse_in(owner.as_str(), &mut arena)?;
    let to = Jid::parse_in(contact, &mut arena)?;
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

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::num::NonZeroUsize;

    use futures_executor::block_on;
    use lonewolf_storage::roster::{MAX_GROUP_NAME_BYTES, MAX_ITEM_NAME_BYTES};
    use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
    use lonewolf_xmpp::parser::{ParserConfig, parse_element};
    use lonewolf_xmpp::stanza::{StanzaErrorCondition, StanzaErrorText};

    use super::{RosterItemUpdate, RosterSet, parse_set};
    use crate::delivery::HandlerError;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    const NAME_TOO_LONG: HandlerError = HandlerError::described(
        StanzaErrorCondition::NotAcceptable,
        StanzaErrorText::Limit {
            prefix: "A roster contact name can have at most ",
            max: MAX_ITEM_NAME_BYTES,
            suffix: " bytes. Shorten the contact name.",
        },
    );

    const GROUP_TOO_LONG: HandlerError = HandlerError::described(
        StanzaErrorCondition::NotAcceptable,
        StanzaErrorText::Limit {
            prefix: "A roster group name can have at most ",
            max: MAX_GROUP_NAME_BYTES,
            suffix: " bytes. Shorten the group name.",
        },
    );

    fn parse_item(item: &str) -> TestResult<Result<RosterItemUpdate, HandlerError>> {
        let query = format!("<query xmlns='jabber:iq:roster'>{item}</query>");
        let parsed = block_on(parse_element(
            query.as_bytes(),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(65_536).ok_or("zero maximum")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        ))?;
        let mut response = Arena::try_new(ArenaConfig::default())?;
        let payload = parsed.value().resolve(parsed.arena())?;
        match parse_set(payload, &mut response) {
            Ok(RosterSet::Update(update)) => Ok(Ok(update)),
            Ok(RosterSet::Remove(_)) => Err("unexpected roster removal".into()),
            Err(error) => Ok(Err(error)),
        }
    }

    #[test]
    fn name_longer_than_the_byte_limit_is_not_acceptable() -> TestResult {
        for name in [
            "n".repeat(MAX_ITEM_NAME_BYTES + 1),
            "é".repeat(MAX_ITEM_NAME_BYTES / 2 + 1),
        ] {
            let item = format!("<item jid='bob@example.com' name='{name}'><group>g</group></item>");
            assert_eq!(parse_item(&item)?.err(), Some(NAME_TOO_LONG));
        }
        Ok(())
    }

    #[test]
    fn group_longer_than_the_byte_limit_is_not_acceptable() -> TestResult {
        let long = "g".repeat(MAX_GROUP_NAME_BYTES + 1);
        let multibyte = "é".repeat(MAX_GROUP_NAME_BYTES / 2 + 1);
        for groups in [
            format!("<group>{long}</group>"),
            format!("<group>{multibyte}</group>"),
            format!("<group>short</group><group>{long}</group>"),
            format!("<group>{long}</group><group>{long}</group>"),
        ] {
            let item = format!("<item jid='bob@example.com'>{groups}</item>");
            assert_eq!(parse_item(&item)?.err(), Some(GROUP_TOO_LONG), "{groups}");
        }
        Ok(())
    }

    #[test]
    fn empty_group_is_reported_before_an_oversized_group() -> TestResult {
        let long = "g".repeat(MAX_GROUP_NAME_BYTES + 1);
        let item = format!("<item jid='bob@example.com'><group/><group>{long}</group></item>");
        assert_eq!(
            parse_item(&item)?.err(),
            Some(HandlerError::Stanza(StanzaErrorCondition::NotAcceptable))
        );
        Ok(())
    }

    #[test]
    fn name_and_groups_at_the_byte_limit_are_accepted() -> TestResult {
        let name = "n".repeat(MAX_ITEM_NAME_BYTES);
        let first = "a".repeat(MAX_GROUP_NAME_BYTES);
        let second = format!("{}b", "é".repeat((MAX_GROUP_NAME_BYTES - 1) / 2));
        let item = format!(
            "<item jid='bob@example.com' name='{name}'><group>{first}</group><group>{second}</group></item>"
        );
        let update = parse_item(&item)?.map_err(|error| format!("{error:?}"))?;
        assert_eq!(update.name.as_deref(), Some(name.as_str()));
        assert_eq!(
            update.groups,
            [first.into_boxed_str(), second.into_boxed_str()]
        );
        Ok(())
    }
}
