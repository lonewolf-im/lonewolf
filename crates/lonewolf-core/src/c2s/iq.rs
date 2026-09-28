// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::iq::{IqEffect, IqRequest, IqRequestType, IqScope};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::Parsed;
use lonewolf_xmpp::stanza::{BuildError, IqType, Stanza, StanzaErrorCondition, StanzaType};

use crate::router::{Registration, RouterHandle};

pub(super) async fn reply<A: ChunkAllocator + Clone>(
    parsed: Parsed<Stanza, A>,
    registration: &Registration<A>,
    router: &RouterHandle<A>,
    allocator: &A,
) -> Result<(Stanza, Arena<A>, IqEffect), BuildError> {
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
        _ => return Err(BuildError::NotIqRequest),
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
        return Ok((reply, arena, IqEffect::None));
    };
    let mut response = Arena::try_new_in(Default::default(), allocator.clone())?;
    let result = handler
        .handle(
            IqRequest {
                sender,
                target,
                kind,
                payload,
            },
            &mut response,
        )
        .await;
    let outcome = match result {
        Ok(response) => response,
        Err(condition) => {
            let reply = request
                .error_reply_in(&mut arena, condition)?
                .to(Some(sender_jid))?
                .build()?;
            return Ok((reply, arena, IqEffect::None));
        }
    };
    let (payload, effect) = outcome.into_parts();
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
    Ok((reply, response, effect))
}
