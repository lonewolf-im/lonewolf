// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::delivery::{HandlerError, HostLookup};
use lonewolf_extension::iq::{
    IqFuture, IqHandler, IqReply, IqRequest, IqRequestType, IqRoute, IqScope,
};
use lonewolf_extension::presence::{
    PresenceFuture, PresenceHandler, PresenceRequest, PresenceRequestType,
};
use lonewolf_extension::{Effects, Extension, Extensions};
use lonewolf_storage::{RedbRead, RedbStorage, RedbWrite};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_util::pool::PooledChunkAllocator;
use lonewolf_xmpp::stanza::{Element, PresenceType, StanzaErrorCondition, StanzaType};

use super::TestResult;

const NAMESPACE: &str = "urn:lonewolf:test:iq";

const ACCOUNT_GET: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Get,
    namespace: NAMESPACE,
    name: "query",
};

const ACCOUNT_SET: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Set,
    namespace: NAMESPACE,
    name: "query",
};

const SERVER_GET: IqRoute = IqRoute {
    scope: IqScope::Server,
    kind: IqRequestType::Get,
    namespace: NAMESPACE,
    name: "query",
};

const ACCOUNT_DENY: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Set,
    namespace: NAMESPACE,
    name: "deny",
};

const SUBSCRIPTION_KINDS: [PresenceRequestType; 4] = [
    PresenceRequestType::Subscribe,
    PresenceRequestType::Subscribed,
    PresenceRequestType::Unsubscribe,
    PresenceRequestType::Unsubscribed,
];

pub fn catalog() -> TestResult<Extensions<Arc<PooledChunkAllocator>, RedbStorage>> {
    let mut extensions = Extensions::default();
    extensions.register(Arc::new(ConflictingIq))?;
    extensions.register(Arc::new(TestIq))?;
    extensions.register(Arc::new(ServerIq))?;
    extensions.register(Arc::new(ErrorIq))?;
    extensions.register(Arc::new(TestPresence))?;
    extensions.register(Arc::new(ConflictingPresence))?;
    Ok(extensions)
}

struct ConflictingIq;

struct TestIq;

struct ServerIq;

struct ErrorIq;

struct TestPresence;

struct ConflictingPresence;

impl<A: ChunkAllocator> Extension<A, RedbStorage> for ConflictingIq {
    fn name(&self) -> &'static str {
        "test-conflicting-iq"
    }

    fn iq_routes(&self) -> &'static [IqRoute] {
        &[ACCOUNT_GET]
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for ConflictingIq {
    fn get<'a>(
        &'a self,
        _: IqRequest<'a, A>,
        _: &'a RedbRead,
        _: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async { Ok(IqReply::new(None, Effects::none())) })
    }
}

impl<A: ChunkAllocator> PresenceHandler<A, RedbStorage> for ConflictingIq {}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestIq {
    fn name(&self) -> &'static str {
        "test-iq"
    }

    fn iq_routes(&self) -> &'static [IqRoute] {
        &[ACCOUNT_GET, ACCOUNT_SET]
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for TestIq {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move { identity(&request, response).await })
    }

    fn set<'a>(
        &'a self,
        _: IqRequest<'a, A>,
        _: &'a mut RedbWrite,
        _: &'a dyn HostLookup,
        _: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async { Ok(IqReply::new(None, Effects::none())) })
    }
}

impl<A: ChunkAllocator> PresenceHandler<A, RedbStorage> for TestIq {}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for ServerIq {
    fn name(&self) -> &'static str {
        "test-server-iq"
    }

    fn iq_routes(&self) -> &'static [IqRoute] {
        &[SERVER_GET]
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for ServerIq {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move { identity(&request, response).await })
    }
}

impl<A: ChunkAllocator> PresenceHandler<A, RedbStorage> for ServerIq {}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for ErrorIq {
    fn name(&self) -> &'static str {
        "test-error-iq"
    }

    fn iq_routes(&self) -> &'static [IqRoute] {
        &[ACCOUNT_DENY]
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for ErrorIq {
    fn set<'a>(
        &'a self,
        _: IqRequest<'a, A>,
        _: &'a mut RedbWrite,
        _: &'a dyn HostLookup,
        _: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async { Err(StanzaErrorCondition::NotAllowed.into()) })
    }
}

impl<A: ChunkAllocator> PresenceHandler<A, RedbStorage> for ErrorIq {}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestPresence {
    fn name(&self) -> &'static str {
        "test-presence"
    }

    fn presence_kinds(&self) -> &'static [PresenceRequestType] {
        &SUBSCRIPTION_KINDS
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for TestPresence {}

impl<A: ChunkAllocator> PresenceHandler<A, RedbStorage> for TestPresence {
    fn authorize<'a>(&'a self, request: PresenceRequest<'a, A>) -> PresenceFuture<'a, ()> {
        Box::pin(async move { verify_authorization(&request).await })
    }
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for ConflictingPresence {
    fn name(&self) -> &'static str {
        "test-conflicting-presence"
    }

    fn presence_kinds(&self) -> &'static [PresenceRequestType] {
        &[PresenceRequestType::Subscribe]
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for ConflictingPresence {}

impl<A: ChunkAllocator> PresenceHandler<A, RedbStorage> for ConflictingPresence {
    fn authorize<'a>(&'a self, request: PresenceRequest<'a, A>) -> PresenceFuture<'a, ()> {
        Box::pin(async move { verify_authorization(&request).await })
    }
}

async fn identity<A: ChunkAllocator>(
    request: &IqRequest<'_, A>,
    response: &mut Arena<A>,
) -> Result<IqReply<A>, HandlerError> {
    compio::time::sleep(std::time::Duration::from_millis(1)).await;
    let value = request
        .payload
        .attribute("value", "")
        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    Element::builder_in("query", NAMESPACE, response)
        .and_then(|builder| builder.attribute("sender", "", request.sender.as_str()))
        .and_then(|builder| builder.attribute("target", "", request.target.as_str()))
        .and_then(|builder| match value {
            Some(value) => builder.attribute("value", "", value),
            None => Ok(builder),
        })
        .and_then(|builder| builder.build())
        .map(|payload| IqReply::new(Some(payload), Effects::none()))
        .map_err(|_| StanzaErrorCondition::InternalServerError.into())
}

async fn verify_authorization<A: ChunkAllocator>(
    request: &PresenceRequest<'_, A>,
) -> Result<(), StanzaErrorCondition> {
    compio::time::sleep(std::time::Duration::from_millis(1)).await;
    let stanza = request
        .stanza
        .resolve()
        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    let stanza_sender = stanza
        .from()
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
        .ok_or(StanzaErrorCondition::InternalServerError)?;
    let stanza_target = stanza
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
    if request.sender.as_str() == "alice@localhost/desk"
        && stanza_sender == request.sender
        && stanza_target == request.target
        && stanza.stanza_type() == StanzaType::Presence(stanza_kind)
    {
        Err(StanzaErrorCondition::NotAllowed)
    } else {
        Err(StanzaErrorCondition::InternalServerError)
    }
}
