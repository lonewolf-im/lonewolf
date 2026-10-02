// SPDX-License-Identifier: Apache-2.0

use std::time::UNIX_EPOCH;

use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator};
use lonewolf_xmpp::stanza::{CLIENT_NAMESPACE, Element, StanzaErrorCondition, StanzaRef};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::message::UndeliverableMessage;

const CHAT_STATES_NAMESPACE: &str = "http://jabber.org/protocol/chatstates";
const DELAY_NAMESPACE: &str = "urn:xmpp:delay";

pub(super) fn chat_state_only<R: ArenaRead>(
    stanza: &StanzaRef<'_, R>,
) -> Result<bool, StanzaErrorCondition> {
    let mut has_chat_state = false;
    for child in stanza
        .children()
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
    {
        let child = child.map_err(|_| StanzaErrorCondition::InternalServerError)?;
        if child.namespace() == CHAT_STATES_NAMESPACE {
            has_chat_state = true;
        } else if child.namespace() != CLIENT_NAMESPACE || child.name() != "thread" {
            return Ok(false);
        }
    }
    Ok(has_chat_state)
}

pub(super) fn stamped<A: ChunkAllocator>(
    message: &UndeliverableMessage<'_, A>,
    scratch: &mut Arena<A>,
) -> Result<(u64, String), StanzaErrorCondition> {
    let condition = StanzaErrorCondition::InternalServerError;
    let stored_at = message
        .received_at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| condition)?
        .as_secs();
    let seconds = i64::try_from(stored_at).map_err(|_| condition)?;
    let received_at = OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| condition)?;
    let mut stamp = [0; 20];
    let written = received_at
        .format_into(&mut stamp.as_mut_slice(), &Rfc3339)
        .map_err(|_| condition)?;
    let stamp = std::str::from_utf8(&stamp[..written]).map_err(|_| condition)?;
    let delay = Element::builder_in("delay", DELAY_NAMESPACE, scratch)
        .and_then(|builder| builder.attribute("from", "", message.recipient.domain()))
        .and_then(|builder| builder.attribute("stamp", "", stamp))
        .and_then(|builder| builder.build())
        .map_err(|_| condition)?;
    let stanza = message
        .stanza
        .resolve()
        .map_err(|_| condition)?
        .to_builder_in_filtered(scratch, |child| {
            Ok(child.name() != "delay"
                || child.namespace() != DELAY_NAMESPACE
                || child.attribute("from", "")? != Some(message.recipient.domain()))
        })
        .and_then(|builder| builder.child(delay))
        .and_then(|builder| builder.build())
        .map_err(|_| condition)?;
    let mut xml = String::new();
    stanza
        .resolve(scratch)
        .map_err(|_| condition)?
        .write_xml(&mut xml)
        .map_err(|_| condition)?;
    Ok((stored_at, xml))
}
