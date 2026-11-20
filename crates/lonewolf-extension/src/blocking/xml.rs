// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::roster::RosterJid;
use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator};
use lonewolf_xmpp::stanza::{BuildError, Element, ElementRef, NodeRef, StanzaErrorCondition};

use super::{BLOCKLIST, NAMESPACE};

pub(super) fn validate_get<R: ArenaRead>(
    payload: ElementRef<'_, R>,
) -> Result<(), StanzaErrorCondition> {
    let internal = StanzaErrorCondition::InternalServerError;
    if payload.name() != BLOCKLIST
        || payload.namespace() != NAMESPACE
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
    for child in payload.children().map_err(|_| internal)? {
        match child.map_err(|_| internal)? {
            NodeRef::Text(text)
                if text
                    .bytes()
                    .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n')) => {}
            _ => return Err(StanzaErrorCondition::BadRequest),
        }
    }
    Ok(())
}

pub(super) fn build_blocklist<A: ChunkAllocator>(
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
    let mut blocklist = Element::builder_in(BLOCKLIST, NAMESPACE, response)?;
    for item in items {
        blocklist = blocklist.child(item)?;
    }
    blocklist.build()
}
