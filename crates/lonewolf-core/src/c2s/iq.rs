// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::iq::{IqRequestType, IqScope};
use lonewolf_util::arena::{Arena, ArenaError, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{Jid, JidError, JidRef};
use lonewolf_xmpp::stanza::{
    BuildError, Element, IqType, Stanza, StanzaErrorCondition, StanzaRef, StanzaType,
};

use super::stream::CloseOutcome;
use crate::router::{Registration, RouterError};

pub(super) struct ReplyError;

impl From<ReplyError> for CloseOutcome {
    fn from(_: ReplyError) -> Self {
        Self::InternalError
    }
}

impl From<BuildError> for ReplyError {
    fn from(_: BuildError) -> Self {
        Self
    }
}

impl From<RouterError> for ReplyError {
    fn from(_: RouterError) -> Self {
        Self
    }
}

impl From<ArenaError> for ReplyError {
    fn from(_: ArenaError) -> Self {
        Self
    }
}

impl From<HandleError> for ReplyError {
    fn from(_: HandleError) -> Self {
        Self
    }
}

impl From<JidError> for ReplyError {
    fn from(_: JidError) -> Self {
        Self
    }
}

/// What a request's envelope decides before any handler runs.
pub(super) struct Route {
    /// The authenticated full JID, allocated in the request's arena.
    pub(super) sender: Jid,
    pub(super) kind: IqRequestType,
    /// `None` when the destination has a resource, which no handler serves.
    pub(super) scope: Option<IqScope>,
}

pub(super) fn route<A: ChunkAllocator>(
    request: &Stanza,
    arena: &mut Arena<A>,
    registration: &Registration<A>,
) -> Result<Route, ReplyError> {
    let account = registration.account();
    let sender = Jid::from_trusted_parts_in(
        Some(account.username()),
        account.domain(),
        Some(registration.resource()),
        arena,
    )?;
    let stanza = request.resolve(arena)?;
    let kind = match stanza.stanza_type() {
        StanzaType::Iq(IqType::Get) => IqRequestType::Get,
        StanzaType::Iq(IqType::Set) => IqRequestType::Set,
        _ => return Err(BuildError::NotIqRequest.into()),
    };
    let target = stanza.to()?;
    let scope = match target {
        None => Some(IqScope::Account),
        Some(target) => match (target.localpart(), target.resourcepart()) {
            (None, None) => Some(IqScope::Server),
            (Some(_), None) => Some(IqScope::Account),
            (_, Some(_)) => None,
        },
    };
    Ok(Route {
        sender,
        kind,
        scope,
    })
}

/// Answers the request with `condition`, addressed to `to` when given.
pub(super) fn error_reply<A: ChunkAllocator>(
    request: &Stanza,
    arena: &mut Arena<A>,
    condition: StanzaErrorCondition,
    to: Option<Jid>,
) -> Result<Stanza, ReplyError> {
    Ok(request.error_reply_in(arena, condition)?.to(to)?.build()?)
}

/// Builds the result for `request` in `response`, carrying `payload` when given.
pub(super) fn result_reply<A: ChunkAllocator>(
    request: &StanzaRef<'_, Arena<A>>,
    sender: JidRef<'_>,
    payload: Option<Element>,
    response: &mut Arena<A>,
) -> Result<Stanza, ReplyError> {
    let recipient = sender.clone_in(response)?;
    let from = request
        .to()?
        .map(|from| from.clone_in(response))
        .transpose()?;
    let mut builder = Stanza::builder_in(
        StanzaType::Iq(IqType::Result),
        request.namespace(),
        response,
    )
    .id(request.id()?)?
    .from(from)?
    .to(Some(recipient))?;
    if let Some(payload) = payload {
        builder = builder.child(payload)?;
    }
    Ok(builder.build()?)
}
