// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::iq::{IqEffect, IqRequest, IqRequestType, IqScope};
use lonewolf_extension::roster::RosterPush;
use lonewolf_util::arena::{Arena, ArenaError, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{Jid, JidError};
use lonewolf_xmpp::parser::Parsed;
use lonewolf_xmpp::stanza::{
    BuildError, IqType, Stanza, StanzaErrorCondition, StanzaNamespace, StanzaType,
};

use crate::router::{Registration, RoutedStanza, RouterError, RouterHandle};

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
            return Ok((reply, arena));
        }
    };
    let (payload, effect) = outcome.into_parts();
    apply_effect(effect, registration, router, allocator).await?;
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

async fn apply_effect<A: ChunkAllocator + Clone>(
    effect: IqEffect,
    registration: &Registration<A>,
    router: &RouterHandle<A>,
    allocator: &A,
) -> Result<(), RouterError> {
    match effect {
        IqEffect::None => Ok(()),
        IqEffect::MarkRosterInterested(_order) => registration.mark_roster_interested().await,
        IqEffect::PushRoster(push) => {
            let allocator = allocator.clone();
            router
                .route_roster_push(registration.account(), move |to| {
                    build_roster_push(to, &push, &allocator)
                })
                .await
        }
    }
}

fn build_roster_push<A: ChunkAllocator + Clone>(
    to: &str,
    push: &RosterPush,
    allocator: &A,
) -> Result<RoutedStanza<A>, RouterError> {
    let mut arena = Arena::try_new_in(Default::default(), allocator.clone())
        .map_err(|_| RouterError::Unavailable)?;
    let item = lonewolf_extension::roster::build_item_in(push.item(), &mut arena)
        .map_err(|_| RouterError::Unavailable)?;
    let query = lonewolf_xmpp::stanza::Element::builder_in(
        "query",
        lonewolf_extension::roster::NAMESPACE,
        &mut arena,
    )
    .map_err(|_| RouterError::Unavailable)?
    .child(item)
    .map_err(|_| RouterError::Unavailable)?
    .build()
    .map_err(|_| RouterError::Unavailable)?;
    let to = Jid::parse_in(to, &mut arena).map_err(|_| RouterError::InvalidTarget)?;
    let id = format!("roster-{}", push.version().get());
    let stanza = Stanza::builder_in(
        StanzaType::Iq(IqType::Set),
        StanzaNamespace::Client,
        &mut arena,
    )
    .id(Some(&id))
    .map_err(|_| RouterError::Unavailable)?
    .to(Some(to))
    .map_err(|_| RouterError::Unavailable)?
    .child(query)
    .map_err(|_| RouterError::Unavailable)?
    .build()
    .map_err(|_| RouterError::Unavailable)?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}
