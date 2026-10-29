// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::iq::IqRequestType;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{
    ApplicationCondition, BuildError, IqType, Stanza, StanzaErrorCondition, StanzaType,
};

use super::stream::CloseOutcome;
use crate::router::{Destination, Registration, RouterHandle};
pub(super) use crate::stages::iq::{ReplyError, error_reply_omitting_payload, result_reply};

impl From<ReplyError> for CloseOutcome {
    fn from(_: ReplyError) -> Self {
        Self::InternalError
    }
}

pub(super) struct Route {
    pub(super) sender: Jid,
    pub(super) kind: IqType,
    pub(super) destination: Destination,
}

impl Route {
    pub(super) fn request_type(&self) -> Option<IqRequestType> {
        match self.kind {
            IqType::Get => Some(IqRequestType::Get),
            IqType::Set => Some(IqRequestType::Set),
            IqType::Result | IqType::Error => None,
        }
    }
}

pub(super) fn route<A: ChunkAllocator + Clone>(
    request: &Stanza,
    arena: &mut Arena<A>,
    registration: &Registration<A>,
    router: &RouterHandle<A>,
) -> Result<Route, ReplyError> {
    let account = registration.account();
    let sender = Jid::from_trusted_parts_in(
        Some(account.username()),
        account.domain(),
        Some(registration.resource()),
        arena,
    )?;
    let stanza = request.resolve(arena)?;
    let StanzaType::Iq(kind) = stanza.stanza_type() else {
        return Err(BuildError::NotIqRequest.into());
    };
    let destination = match stanza.to()? {
        None => Destination::Account,
        Some(target) => router.destination(target),
    };
    Ok(Route {
        sender,
        kind,
        destination,
    })
}

pub(super) fn error_reply<A: ChunkAllocator>(
    request: &Stanza,
    arena: &mut Arena<A>,
    condition: StanzaErrorCondition,
    to: Option<Jid>,
) -> Result<Stanza, ReplyError> {
    error_reply_with(request, arena, condition, None, to)
}

pub(super) fn error_reply_with<A: ChunkAllocator>(
    request: &Stanza,
    arena: &mut Arena<A>,
    condition: StanzaErrorCondition,
    application: Option<ApplicationCondition>,
    to: Option<Jid>,
) -> Result<Stanza, ReplyError> {
    Ok(request
        .error_reply_with_in(arena, condition, application)?
        .to(to)?
        .build()?)
}
