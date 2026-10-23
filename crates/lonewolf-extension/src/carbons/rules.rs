// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{ArenaRead, HandleError};
use lonewolf_xmpp::stanza::{MessageType, StanzaRef, StanzaType};

use super::NAMESPACE;
use crate::observer::MessageRole;

pub const HINTS_NAMESPACE: &str = "urn:xmpp:hints";
pub const MUC_USER_NAMESPACE: &str = "http://jabber.org/protocol/muc#user";
pub const CONFERENCE_NAMESPACE: &str = "jabber:x:conference";
pub const RECEIPTS_NAMESPACE: &str = "urn:xmpp:receipts";
pub const CHAT_STATES_NAMESPACE: &str = "http://jabber.org/protocol/chatstates";
pub const MARKERS_NAMESPACE: &str = "urn:xmpp:chat-markers:0";

/// Applies the XEP-0280 §6.1 copying rules to a message observed for `owner`.
pub fn eligible<R: ArenaRead>(
    message: &StanzaRef<'_, R>,
    role: MessageRole,
    owner: &AccountKey,
) -> Result<bool, HandleError> {
    let StanzaType::Message(kind) = message.stanza_type() else {
        return Ok(false);
    };
    if message.child("private", NAMESPACE)?.is_some() {
        return Ok(false);
    }
    if message.child("sent", NAMESPACE)?.is_some()
        || message.child("received", NAMESPACE)?.is_some()
    {
        return Ok(false);
    }
    if kind == MessageType::Groupchat {
        return Ok(false);
    }
    if kind != MessageType::Error && message.child("no-copy", HINTS_NAMESPACE)?.is_some() {
        return Ok(false);
    }
    for child in message.children()? {
        let child = child?;
        if child.name() == "x"
            && child.namespace() == MUC_USER_NAMESPACE
            && (kind == MessageType::Error
                || (role == MessageRole::Received
                    && message.from()?.is_some_and(|from| from.is_full())
                    && child.child("invite", MUC_USER_NAMESPACE)?.is_none()))
        {
            return Ok(false);
        }
    }
    if kind == MessageType::Error {
        return Ok(message.to()?.map(|to| to.as_str()) != Some(owner.as_str()));
    }
    if kind == MessageType::Chat {
        return Ok(true);
    }
    if kind == MessageType::Normal
        && message
            .child("body", message.namespace().as_str())?
            .is_some()
    {
        return Ok(true);
    }
    for child in message.children()? {
        if matches!(
            child?.namespace(),
            RECEIPTS_NAMESPACE | CHAT_STATES_NAMESPACE | MARKERS_NAMESPACE
        ) {
            return Ok(true);
        }
    }
    if message.child("x", CONFERENCE_NAMESPACE)?.is_some() {
        return Ok(true);
    }
    for child in message.children()? {
        let child = child?;
        if child.name() == "x"
            && child.namespace() == MUC_USER_NAMESPACE
            && child.child("invite", MUC_USER_NAMESPACE)?.is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}
