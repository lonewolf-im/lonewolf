// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::iq::IqRequestType;
use lonewolf_util::arena::{Arena, ArenaError, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{Jid, JidError, JidRef};
use lonewolf_xmpp::stanza::{
    ApplicationCondition, BuildError, Element, IqType, Stanza, StanzaErrorCondition,
    StanzaErrorText, StanzaRef, StanzaType, error_element_in,
};

use super::stream::CloseOutcome;
use crate::router::{Destination, Registration, RouterError, RouterHandle};

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

pub(super) fn error_reply_omitting_payload<A: ChunkAllocator>(
    request: &StanzaRef<'_, Arena<A>>,
    sender: JidRef<'_>,
    condition: StanzaErrorCondition,
    text: StanzaErrorText,
    response: &mut Arena<A>,
) -> Result<Stanza, ReplyError> {
    if !matches!(
        request.stanza_type(),
        StanzaType::Iq(IqType::Get | IqType::Set)
    ) {
        return Err(BuildError::NotIqRequest.into());
    }
    let recipient = sender.clone_in(response)?;
    let from = request
        .to()?
        .map(|from| from.clone_in(response))
        .transpose()?;
    let error = error_element_in(request.namespace(), condition, None, text, response)?;
    Ok(
        Stanza::builder_in(StanzaType::Iq(IqType::Error), request.namespace(), response)
            .id(request.id()?)?
            .lang(request.lang()?)?
            .from(from)?
            .to(Some(recipient))?
            .child(error)?
            .build()?,
    )
}
