// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::Extensions;
use lonewolf_extension::iq::{
    IqFuture, IqHandler, IqRegistration, IqRequest, IqRequestType, IqResponse, IqRoute, IqScope,
};
use lonewolf_extension::presence::{
    PresenceDirection, PresenceFuture, PresenceHandler, PresenceRegistration, PresenceRequest,
    PresenceRequestType, PresenceRoute,
};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_util::pool::PooledChunkAllocator;
use lonewolf_xmpp::stanza::{Element, PresenceType, StanzaErrorCondition, StanzaType};

use super::TestResult;

pub fn catalog() -> TestResult<Extensions<Arc<PooledChunkAllocator>>> {
    let mut extensions = Extensions::default();
    let identity: Arc<dyn IqHandler<Arc<PooledChunkAllocator>>> = Arc::new(Identity);
    extensions.register(
        "test-conflicting-iq",
        [IqRegistration::new(
            IqRoute {
                scope: IqScope::Account,
                kind: IqRequestType::Get,
                namespace: "urn:lonewolf:test:iq",
                name: "query",
            },
            Arc::new(Empty),
        )],
        [],
    )?;
    extensions.register(
        "test-iq",
        [
            IqRegistration::new(
                IqRoute {
                    scope: IqScope::Account,
                    kind: IqRequestType::Get,
                    namespace: "urn:lonewolf:test:iq",
                    name: "query",
                },
                Arc::clone(&identity),
            ),
            IqRegistration::new(
                IqRoute {
                    scope: IqScope::Account,
                    kind: IqRequestType::Set,
                    namespace: "urn:lonewolf:test:iq",
                    name: "query",
                },
                Arc::new(Empty),
            ),
        ],
        [],
    )?;
    extensions.register(
        "test-server-iq",
        [IqRegistration::new(
            IqRoute {
                scope: IqScope::Server,
                kind: IqRequestType::Get,
                namespace: "urn:lonewolf:test:iq",
                name: "query",
            },
            Arc::clone(&identity),
        )],
        [],
    )?;
    extensions.register(
        "test-error-iq",
        [IqRegistration::new(
            IqRoute {
                scope: IqScope::Account,
                kind: IqRequestType::Set,
                namespace: "urn:lonewolf:test:iq",
                name: "deny",
            },
            Arc::new(Deny),
        )],
        [],
    )?;
    extensions.register(
        "test-presence",
        [],
        [
            PresenceRequestType::Subscribe,
            PresenceRequestType::Subscribed,
            PresenceRequestType::Unsubscribe,
            PresenceRequestType::Unsubscribed,
        ]
        .map(|kind| {
            PresenceRegistration::new(
                PresenceRoute {
                    direction: PresenceDirection::Outbound,
                    kind,
                },
                Arc::new(VerifyPresence),
            )
        }),
    )?;
    extensions.register(
        "test-conflicting-presence",
        [],
        [PresenceRegistration::new(
            PresenceRoute {
                direction: PresenceDirection::Outbound,
                kind: PresenceRequestType::Subscribe,
            },
            Arc::new(VerifyPresence),
        )],
    )?;
    Ok(extensions)
}

struct Identity;

struct Empty;

struct Deny;

struct VerifyPresence;

impl<A: ChunkAllocator> PresenceHandler<A> for VerifyPresence {
    fn handle<'a>(&'a self, request: PresenceRequest<'a, A>) -> PresenceFuture<'a> {
        Box::pin(async move {
            compio::time::sleep(std::time::Duration::from_millis(1)).await;
            let stanza_sender = request
                .stanza
                .from()
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .ok_or(StanzaErrorCondition::InternalServerError)?;
            let stanza_target = request
                .stanza
                .to()
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .ok_or(StanzaErrorCondition::InternalServerError)?;
            let stanza_kind = match request.kind {
                PresenceRequestType::Available => PresenceType::Available,
                PresenceRequestType::Unavailable => PresenceType::Unavailable,
                PresenceRequestType::Subscribe => PresenceType::Subscribe,
                PresenceRequestType::Subscribed => PresenceType::Subscribed,
                PresenceRequestType::Unsubscribe => PresenceType::Unsubscribe,
                PresenceRequestType::Unsubscribed => PresenceType::Unsubscribed,
            };
            if request.direction == PresenceDirection::Outbound
                && request.sender.as_str() == "alice@localhost/desk"
                && stanza_sender == request.sender
                && stanza_target == request.target
                && request.stanza.stanza_type() == StanzaType::Presence(stanza_kind)
            {
                Err(StanzaErrorCondition::NotAllowed)
            } else {
                Err(StanzaErrorCondition::InternalServerError)
            }
        })
    }
}

impl<A: ChunkAllocator> IqHandler<A> for Deny {
    fn handle<'a>(&'a self, _: IqRequest<'a, A>, _: &'a mut Arena<A>) -> IqFuture<'a> {
        Box::pin(async { Err(StanzaErrorCondition::NotAllowed) })
    }
}

impl<A: ChunkAllocator> IqHandler<A> for Empty {
    fn handle<'a>(&'a self, _: IqRequest<'a, A>, _: &'a mut Arena<A>) -> IqFuture<'a> {
        Box::pin(async { Ok(IqResponse::new(None)) })
    }
}

impl<A: ChunkAllocator> IqHandler<A> for Identity {
    fn handle<'a>(&'a self, request: IqRequest<'a, A>, response: &'a mut Arena<A>) -> IqFuture<'a> {
        Box::pin(async move {
            compio::time::sleep(std::time::Duration::from_millis(1)).await;
            let value = request
                .payload
                .attribute("value", "")
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            let result = Element::builder_in("query", "urn:lonewolf:test:iq", response)
                .and_then(|builder| builder.attribute("sender", "", request.sender.as_str()))
                .and_then(|builder| builder.attribute("target", "", request.target.as_str()))
                .and_then(|builder| match value {
                    Some(value) => builder.attribute("value", "", value),
                    None => Ok(builder),
                })
                .and_then(|builder| builder.build());
            result
                .map(|payload| IqResponse::new(Some(payload)))
                .map_err(|_| StanzaErrorCondition::InternalServerError)
        })
    }
}
