// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::roster::RosterJid;
use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidError};
use lonewolf_xmpp::stanza::{
    BuildError, Element, ElementRef, IqType, NodeRef, Stanza, StanzaErrorCondition,
    StanzaNamespace, StanzaType,
};

use super::{BLOCK, BLOCKLIST, NAMESPACE, UNBLOCK};
use crate::delivery::DeliveryError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ChangeKind {
    Block,
    Unblock,
}

pub(super) fn validate_get<R: ArenaRead>(
    payload: ElementRef<'_, R>,
) -> Result<(), StanzaErrorCondition> {
    if payload.name() != BLOCKLIST {
        return Err(StanzaErrorCondition::BadRequest);
    }
    validate_command(&payload)?;
    validate_empty(&payload)
}

pub(super) fn parse_change<A: ChunkAllocator, R: ArenaRead>(
    payload: ElementRef<'_, R>,
    arena: &mut Arena<A>,
) -> Result<(ChangeKind, Vec<RosterJid>), StanzaErrorCondition> {
    let command = match payload.name() {
        BLOCK => ChangeKind::Block,
        UNBLOCK => ChangeKind::Unblock,
        _ => return Err(StanzaErrorCondition::BadRequest),
    };
    validate_command(&payload)?;
    let internal = StanzaErrorCondition::InternalServerError;
    let mut items = Vec::new();
    for child in payload.children().map_err(|_| internal)? {
        match child.map_err(|_| internal)? {
            NodeRef::Text(text) if is_xml_whitespace(text) => {}
            NodeRef::Element(item) if item.name() == "item" && item.namespace() == NAMESPACE => {
                let mut attributes = item.attributes().map_err(|_| internal)?;
                let attribute = attributes
                    .next()
                    .transpose()
                    .map_err(|_| internal)?
                    .ok_or(StanzaErrorCondition::BadRequest)?;
                if attribute.name != "jid"
                    || !attribute.namespace.is_empty()
                    || attribute.value.is_empty()
                    || attributes
                        .next()
                        .transpose()
                        .map_err(|_| internal)?
                        .is_some()
                {
                    return Err(StanzaErrorCondition::BadRequest);
                }
                validate_empty(&item)?;
                let jid = Jid::parse_in(attribute.value, arena).map_err(|error| match error {
                    JidError::AllocationFailed(_) => StanzaErrorCondition::ResourceConstraint,
                    JidError::AccessFailed(_) => internal,
                    _ => StanzaErrorCondition::JidMalformed,
                })?;
                items.push(RosterJid::from(jid.resolve(arena).map_err(|_| internal)?));
            }
            _ => return Err(StanzaErrorCondition::BadRequest),
        }
    }
    if command == ChangeKind::Block && items.is_empty() {
        return Err(StanzaErrorCondition::BadRequest);
    }
    items.sort_unstable();
    items.dedup();
    Ok((command, items))
}

fn validate_command<R: ArenaRead>(payload: &ElementRef<'_, R>) -> Result<(), StanzaErrorCondition> {
    let internal = StanzaErrorCondition::InternalServerError;
    if payload.namespace() != NAMESPACE
        || payload
            .attributes()
            .map_err(|_| internal)?
            .next()
            .transpose()
            .map_err(|_| internal)?
            .is_some()
    {
        return Err(StanzaErrorCondition::BadRequest);
    }
    Ok(())
}

fn validate_empty<R: ArenaRead>(payload: &ElementRef<'_, R>) -> Result<(), StanzaErrorCondition> {
    let internal = StanzaErrorCondition::InternalServerError;
    for child in payload.children().map_err(|_| internal)? {
        if !matches!(child.map_err(|_| internal)?, NodeRef::Text(text) if is_xml_whitespace(text)) {
            return Err(StanzaErrorCondition::BadRequest);
        }
    }
    Ok(())
}

fn is_xml_whitespace(text: &str) -> bool {
    text.bytes()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

pub(super) fn build_items<A: ChunkAllocator>(
    command: &'static str,
    rules: &[RosterJid],
    response: &mut Arena<A>,
) -> Result<Element, BuildError> {
    let mut items = Vec::with_capacity(rules.len());
    for rule in rules {
        let item = Element::builder_in("item", NAMESPACE, response)?
            .attribute("jid", "", rule.as_str())?
            .build()?;
        items.push(item);
    }
    let mut blocklist = Element::builder_in(command, NAMESPACE, response)?;
    for item in items {
        blocklist = blocklist.child(item)?;
    }
    blocklist.build()
}

pub(super) fn build_push<A: ChunkAllocator>(
    to: Jid,
    id: &str,
    command: ChangeKind,
    items: &[RosterJid],
    arena: &mut Arena<A>,
) -> Result<Stanza, DeliveryError> {
    let name = match command {
        ChangeKind::Block => BLOCK,
        ChangeKind::Unblock => UNBLOCK,
    };
    let payload = build_items(name, items, arena)?;
    Ok(
        Stanza::builder_in(StanzaType::Iq(IqType::Set), StanzaNamespace::Client, arena)
            .id(Some(id))?
            .to(Some(to))?
            .child(payload)?
            .build()?,
    )
}
