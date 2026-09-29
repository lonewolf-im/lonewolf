// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::iq::{IqRequest, IqRequestType, IqScope};
use lonewolf_util::arena::{Arena, ArenaError, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{Jid, JidError};
use lonewolf_xmpp::parser::Parsed;
use lonewolf_xmpp::stanza::{BuildError, IqType, Stanza, StanzaErrorCondition, StanzaType};

use crate::delivery::RouterDelivery;
use crate::router::{Registration, RouterError, RouterHandle};

pub(super) struct ReplyError;

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

pub(super) async fn reply<A: ChunkAllocator + Clone>(
    parsed: Parsed<Stanza, A>,
    registration: &Registration<A>,
    router: &RouterHandle<A>,
    allocator: &A,
) -> Result<(Stanza, Arena<A>), ReplyError> {
    let (request, mut arena) = parsed.into_parts();
    let account = registration.account();
    let sender_jid = Jid::from_trusted_parts_in(
        Some(account.username()),
        account.domain(),
        Some(registration.resource()),
        &mut arena,
    )?;
    let sender = sender_jid.resolve(&arena)?;
    let stanza = request.resolve(&arena)?;
    let kind = match stanza.stanza_type() {
        StanzaType::Iq(IqType::Get) => IqRequestType::Get,
        StanzaType::Iq(IqType::Set) => IqRequestType::Set,
        _ => return Err(BuildError::NotIqRequest.into()),
    };
    let target = stanza.to()?.unwrap_or_else(|| sender.bare());
    let scope = match (target.localpart(), target.resourcepart()) {
        (None, None) => Some(IqScope::Server),
        (Some(_), None) => Some(IqScope::Account),
        (_, Some(_)) => None,
    };
    let payload = stanza
        .children()?
        .next()
        .transpose()?
        .ok_or(BuildError::InvalidIqPayload)?;
    let handler = scope.and_then(|scope| {
        router.iq_handlers(target.domainpart())?.find(
            scope,
            kind,
            payload.namespace(),
            payload.name(),
        )
    });
    let Some(handler) = handler else {
        let reply = request
            .error_reply_in(&mut arena, StanzaErrorCondition::ServiceUnavailable)?
            .to(None)?
            .build()?;
        return Ok((reply, arena));
    };
    let mut response = Arena::try_new_in(Default::default(), allocator.clone())?;
    let delivery = RouterDelivery {
        router,
        allocator,
        session: Some(registration),
    };
    let result = handler
        .handle(
            IqRequest {
                sender,
                target,
                kind,
                payload,
            },
            &mut response,
            &delivery,
        )
        .await;
    let payload = match result {
        Ok(payload) => payload,
        Err(HandlerError::Stanza(condition)) => {
            let reply = request
                .error_reply_in(&mut arena, condition)?
                .to(Some(sender_jid))?
                .build()?;
            return Ok((reply, arena));
        }
        Err(HandlerError::Delivery(_)) => return Err(ReplyError),
    };
    let recipient = sender.clone_in(&mut response)?;
    let from = stanza
        .to()?
        .map(|from| from.clone_in(&mut response))
        .transpose()?;
    let mut builder = Stanza::builder_in(
        StanzaType::Iq(IqType::Result),
        stanza.namespace(),
        &mut response,
    )
    .id(stanza.id()?)?
    .from(from)?
    .to(Some(recipient))?;
    if let Some(payload) = payload {
        builder = builder.child(payload)?;
    }
    let reply = builder.build()?;
    Ok((reply, response))
}
