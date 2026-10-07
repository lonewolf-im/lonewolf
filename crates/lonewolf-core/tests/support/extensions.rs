// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use lonewolf_extension::delivery::{Failure, FailureKind, HandlerError, HostLookup, SessionTag};
use lonewolf_extension::iq::{
    IqFuture, IqHandler, IqReply, IqRequest, IqRequestType, IqRoute, IqScope,
};
use lonewolf_extension::message::{MessageHandler, StoreFuture, UndeliverableMessage};
use lonewolf_extension::offline::Offline;
use lonewolf_extension::presence::{
    PresenceAudience, PresenceFuture, PresenceHandler, PresenceRequest, PresenceRequestType,
    PresenceTransition, PresenceUpdate,
};
use lonewolf_extension::{Effects, Extension, Extensions};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::{OfflineReads, OfflineWrites};
use lonewolf_storage::roster::{RosterJid, RosterWrites};
use lonewolf_storage::{RedbRead, RedbStorage, RedbWrite};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_util::pool::PooledChunkAllocator;
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{
    Element, IqType, PresenceType, Stanza, StanzaErrorCondition, StanzaNamespace, StanzaType,
};

use super::TestResult;

const NAMESPACE: &str = "urn:lonewolf:test:iq";
const OFFLINE_ROUTE: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Get,
    namespace: "urn:lonewolf:test:offline",
    name: "query",
};
const OFFLINE_PUSH: IqRoute = IqRoute {
    kind: IqRequestType::Set,
    name: "push",
    ..OFFLINE_ROUTE
};
const OFFLINE_RELEASE: IqRoute = IqRoute {
    scope: IqScope::Server,
    name: "release",
    ..OFFLINE_ROUTE
};

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

const ACCOUNT_SLOW: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Set,
    namespace: NAMESPACE,
    name: "slow",
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
    extensions.register(Arc::new(FailureIq))?;
    extensions.register(Arc::new(PrecommitIq {
        release: async_lock::Semaphore::new(0),
    }))?;
    extensions.register(Arc::new(TestPresence))?;
    extensions.register(Arc::new(ConflictingPresence))?;
    extensions.register(Arc::new(OfflineInspect))?;
    extensions.register(Arc::new(SlowOffline {
        offline: Offline::new(Default::default()),
        ready: async_lock::Semaphore::new(0),
        entered: AtomicUsize::new(0),
        block_ack: false,
        acknowledge: async_lock::Semaphore::new(0),
        fail_ack: AtomicBool::new(false),
    }))?;
    extensions.register(Arc::new(SlowOffline {
        offline: Offline::new(Default::default()),
        ready: async_lock::Semaphore::new(0),
        entered: AtomicUsize::new(0),
        block_ack: true,
        acknowledge: async_lock::Semaphore::new(0),
        fail_ack: AtomicBool::new(false),
    }))?;
    Ok(extensions)
}

struct ConflictingIq;

struct TestIq;

struct ServerIq;

struct ErrorIq;

struct TestPresence;

struct ConflictingPresence;

struct OfflineInspect;

struct SlowOffline {
    offline: Offline,
    ready: async_lock::Semaphore,
    entered: AtomicUsize,
    block_ack: bool,
    acknowledge: async_lock::Semaphore,
    fail_ack: AtomicBool,
}

const PRECOMMIT_ROUTE: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Set,
    namespace: "urn:lonewolf:test:precommit",
    name: "stall",
};

struct PrecommitIq {
    release: async_lock::Semaphore,
}

struct PrecommitCancellation(bool);

impl Drop for PrecommitCancellation {
    fn drop(&mut self) {
        if !self.0 {
            tracing::info!("test precommit handler cancelled");
        }
    }
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for PrecommitIq {
    fn name(&self) -> &'static str {
        "test-precommit-iq"
    }

    fn iq_routes(&self) -> &'static [IqRoute] {
        &[
            PRECOMMIT_ROUTE,
            IqRoute {
                name: "write",
                ..PRECOMMIT_ROUTE
            },
            IqRoute {
                scope: IqScope::Server,
                kind: IqRequestType::Get,
                name: "release",
                ..PRECOMMIT_ROUTE
            },
        ]
    }

    fn presence_kinds(&self) -> &'static [PresenceRequestType] {
        &[PresenceRequestType::Available]
    }

    fn stores_messages(&self) -> bool {
        true
    }
}

impl<A: ChunkAllocator> PresenceHandler<A, RedbStorage> for PrecommitIq {
    fn audience<'a>(
        &'a self,
        _update: PresenceUpdate<'a>,
        _transaction: &'a RedbRead,
    ) -> PresenceFuture<'a, Option<PresenceAudience>> {
        Box::pin(async move {
            tracing::info!("test precommit audience waiting");
            self.release.acquire().await.forget();
            Ok(None)
        })
    }
}

impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for PrecommitIq {
    fn backlog<'a>(
        &'a self,
        _account: &'a AccountKey,
        _transaction: &'a RedbRead,
    ) -> PresenceFuture<'a, Option<lonewolf_extension::message::Backlog>> {
        Box::pin(async move {
            tracing::info!("test precommit backlog waiting");
            self.release.acquire().await.forget();
            Ok(None)
        })
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for PrecommitIq {
    fn get<'a>(
        &'a self,
        _request: IqRequest<'a, A>,
        _transaction: &'a RedbRead,
        _response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            self.release.add_permits(1);
            Ok(IqReply::new(None, Effects::none()))
        })
    }

    fn set<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a mut RedbWrite,
        _hosts: &'a dyn HostLookup,
        _response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let account = AccountKey::try_from(request.target.bare())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            transaction
                .push_offline_message(&account, 0, b"<message xmlns='jabber:client'/>")
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            if request.payload.name() == "stall" {
                let mut cancellation = PrecommitCancellation(false);
                tracing::info!(account_jid = ?account.as_str(), "test precommit handler waiting");
                self.release.acquire().await.forget();
                cancellation.0 = true;
            }
            tracing::info!(account_jid = ?account.as_str(), "test precommit handler completed");
            Ok(IqReply::new(
                None,
                Effects::new(vec![account], |_| {
                    Box::pin(async {
                        tracing::info!("test precommit effects delivered");
                        Ok(())
                    })
                }),
            ))
        })
    }
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for OfflineInspect {
    fn name(&self) -> &'static str {
        "test-offline-inspect"
    }
    fn iq_routes(&self) -> &'static [IqRoute] {
        &[OFFLINE_ROUTE, OFFLINE_PUSH]
    }
}

impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for OfflineInspect {}
impl<A: ChunkAllocator> PresenceHandler<A, RedbStorage> for OfflineInspect {}
impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for OfflineInspect {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(inspect_offline(request, transaction, response))
    }
    fn set<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a mut RedbWrite,
        _hosts: &'a dyn HostLookup,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            if request.sender.bare() != request.target {
                return Err(StanzaErrorCondition::Forbidden.into());
            }
            let condition = StanzaErrorCondition::InternalServerError;
            let owner = AccountKey::try_from(request.target).map_err(|_| condition)?;
            let sequence = transaction
                .push_offline_message(&owner, 0, b"<message xmlns='jabber:client'/>")
                .await
                .map_err(|_| condition)?
                .get()
                .to_string();
            let payload = Element::builder_in("pushed", OFFLINE_ROUTE.namespace, response)
                .and_then(|builder| builder.attribute("sequence", "", &sequence))
                .and_then(|builder| builder.build())
                .map_err(|_| condition)?;
            Ok(IqReply::new(
                Some(payload),
                Effects::new(vec![owner], |_| Box::pin(async { Ok(()) })),
            ))
        })
    }
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for SlowOffline {
    fn name(&self) -> &'static str {
        if self.block_ack {
            "test-blocked-offline-ack"
        } else {
            "test-slow-offline"
        }
    }
    fn iq_routes(&self) -> &'static [IqRoute] {
        if self.block_ack {
            &[OFFLINE_ROUTE, OFFLINE_RELEASE]
        } else {
            &[]
        }
    }
    fn stores_messages(&self) -> bool {
        true
    }
    fn presence_kinds(&self) -> &'static [PresenceRequestType] {
        &[PresenceRequestType::Available]
    }
}
impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for SlowOffline {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            if request.payload.name() == "release" {
                let fail = request
                    .payload
                    .attribute("fail", "")
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?
                    == Some("true");
                self.fail_ack.store(fail, Ordering::Release);
                self.acknowledge.add_permits(1);
                let released = Element::builder_in("released", OFFLINE_ROUTE.namespace, response)
                    .and_then(|builder| builder.build())
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                return Ok(IqReply::new(Some(released), Effects::none()));
            }
            inspect_offline(request, transaction, response).await
        })
    }
}
impl<A: ChunkAllocator> PresenceHandler<A, RedbStorage> for SlowOffline {
    fn audience<'a>(
        &'a self,
        update: PresenceUpdate<'a>,
        _transaction: &'a RedbRead,
    ) -> PresenceFuture<'a, Option<PresenceAudience>> {
        if update.transition == PresenceTransition::Initial
            && self.entered.load(Ordering::Acquire) > 0
        {
            self.ready.add_permits(1);
        }
        Box::pin(async { Ok(None) })
    }
}
impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for SlowOffline {
    fn backlog<'a>(
        &'a self,
        account: &'a AccountKey,
        transaction: &'a RedbRead,
    ) -> PresenceFuture<'a, Option<lonewolf_extension::message::Backlog>> {
        <Offline as MessageHandler<A, RedbStorage>>::backlog(&self.offline, account, transaction)
    }
    fn acknowledge<'a>(
        &'a self,
        account: &'a AccountKey,
        through: lonewolf_storage::offline::OfflineSequence,
        transaction: &'a mut RedbWrite,
    ) -> lonewolf_extension::ExtensionFuture<'a, Result<(), HandlerError>> {
        <Offline as MessageHandler<A, RedbStorage>>::acknowledge(
            &self.offline,
            account,
            through,
            transaction,
        )
    }
    fn store<'a>(
        &'a self,
        message: UndeliverableMessage<'a, A>,
        transaction: &'a mut RedbWrite,
        scratch: &'a mut Arena<A>,
    ) -> StoreFuture<'a> {
        Box::pin(async move {
            self.entered.fetch_add(1, Ordering::Release);
            tracing::info!("test offline store waiting");
            let _ready = self.ready.acquire().await;
            <Offline as MessageHandler<A, RedbStorage>>::store(
                &self.offline,
                message,
                transaction,
                scratch,
            )
            .await
        })
    }
    fn acknowledge_one<'a>(
        &'a self,
        account: &'a AccountKey,
        sequence: lonewolf_storage::offline::OfflineSequence,
        transaction: &'a mut RedbWrite,
    ) -> lonewolf_extension::ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            if self.block_ack {
                tracing::info!("test offline acknowledgement waiting");
                let _ready = self.acknowledge.acquire().await;
                if self.fail_ack.load(Ordering::Acquire) {
                    return Err(HandlerError::Internal {
                        condition: StanzaErrorCondition::InternalServerError,
                        failure: Failure {
                            kind: FailureKind::Storage(
                                lonewolf_storage::StorageErrorKind::Unavailable,
                            ),
                            operation: "offline_acknowledge",
                        },
                    });
                }
            }
            <Offline as MessageHandler<A, RedbStorage>>::acknowledge_one(
                &self.offline,
                account,
                sequence,
                transaction,
            )
            .await
        })
    }
}

async fn inspect_offline<A: ChunkAllocator>(
    request: IqRequest<'_, A>,
    transaction: &RedbRead,
    response: &mut Arena<A>,
) -> Result<IqReply<A>, HandlerError> {
    let condition = StanzaErrorCondition::InternalServerError;
    if request.sender.bare() != request.target {
        return Err(StanzaErrorCondition::Forbidden.into());
    }
    let owner = AccountKey::try_from(request.target).map_err(|_| condition)?;
    let messages = transaction
        .offline_messages(&owner)
        .await
        .map_err(|_| condition)?;
    let target = match messages.last() {
        None => None,
        Some(message) => {
            let mut parser = quick_xml::Reader::from_reader(message.stanza.as_ref());
            let start = match parser.read_event().map_err(|_| condition)? {
                quick_xml::events::Event::Start(start) | quick_xml::events::Event::Empty(start) => {
                    start
                }
                _ => return Err(condition.into()),
            };
            start
                .attributes()
                .find_map(|attribute| match attribute {
                    Ok(attribute) if attribute.key.as_ref() == "to" => Some(
                        attribute
                            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                            .map(|value| value.into_owned())
                            .map_err(|_| condition),
                    ),
                    Ok(_) => None,
                    Err(_) => Some(Err(condition)),
                })
                .transpose()?
        }
    };
    let count = messages.len().to_string();
    let through = messages
        .last()
        .map_or(0, |message| message.sequence.get())
        .to_string();
    let mut query = Element::builder_in("query", OFFLINE_ROUTE.namespace, response)
        .and_then(|builder| builder.attribute("count", "", &count))
        .and_then(|builder| builder.attribute("through", "", &through))
        .map_err(|_| condition)?;
    if let Some(target) = target {
        query = query
            .attribute("last_to", "", &target)
            .map_err(|_| condition)?;
    }
    Ok(IqReply::new(
        Some(query.build().map_err(|_| condition)?),
        Effects::none(),
    ))
}

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

impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for ConflictingIq {}

impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for TestIq {}

impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for ServerIq {}

impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for ErrorIq {}

impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for TestPresence {}

impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for ConflictingPresence {}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestIq {
    fn name(&self) -> &'static str {
        "test-iq"
    }

    fn iq_routes(&self) -> &'static [IqRoute] {
        &[ACCOUNT_GET, ACCOUNT_SET, ACCOUNT_SLOW]
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
        request: IqRequest<'a, A>,
        transaction: &'a mut RedbWrite,
        _: &'a dyn HostLookup,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            if request.payload.name() != ACCOUNT_SLOW.name {
                return Ok(IqReply::new(None, Effects::none()));
            }
            let millis = request
                .payload
                .attribute("millis", "")
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .and_then(|value| value.parse().ok())
                .ok_or(StanzaErrorCondition::BadRequest)?;
            let account = AccountKey::try_from(request.target.bare())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            if let Some(observer) = request
                .payload
                .attribute("revoke", "")
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
            {
                let observer = Jid::parse_in(observer, response)
                    .map_err(|_| StanzaErrorCondition::BadRequest)?;
                let observer = RosterJid::from(
                    observer
                        .resolve(response)
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?
                        .bare(),
                );
                transaction
                    .remove_roster_item(&account, &observer)
                    .await
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            }
            let effects = Effects::new(vec![account.clone()], move |delivery| {
                Box::pin(async move {
                    delivery
                        .push_to_tagged(
                            &account,
                            SessionTag::Interested,
                            Box::new(|to, arena| {
                                let marker =
                                    Element::builder_in("slow", NAMESPACE, arena)?.build()?;
                                Ok(Stanza::builder_in(
                                    StanzaType::Iq(IqType::Set),
                                    StanzaNamespace::Client,
                                    arena,
                                )
                                .id(Some("slow"))?
                                .to(Some(to))?
                                .child(marker)?
                                .build()?)
                            }),
                        )
                        .await?;
                    compio::time::sleep(Duration::from_millis(millis)).await;
                    Ok(())
                })
            });
            Ok(IqReply::new(None, effects))
        })
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
        Box::pin(async move { verify_authorization(&request).await.map_err(Into::into) })
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
        Box::pin(async move { verify_authorization(&request).await.map_err(Into::into) })
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
        PresenceRequestType::Probe => PresenceType::Probe,
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

struct FailureIq;

const FAILURE_GET: IqRoute = IqRoute {
    namespace: "urn:lonewolf:test:failure",
    name: "fail",
    ..ACCOUNT_GET
};
const FAILURE_SET: IqRoute = IqRoute {
    kind: IqRequestType::Set,
    ..FAILURE_GET
};

impl<A: ChunkAllocator> Extension<A, RedbStorage> for FailureIq {
    fn name(&self) -> &'static str {
        "test-failure-iq"
    }
    fn iq_routes(&self) -> &'static [IqRoute] {
        &[FAILURE_GET, FAILURE_SET]
    }
}

fn injected_handler_error(
    kind: lonewolf_storage::StorageErrorKind,
    operation: &'static str,
) -> HandlerError {
    let error = lonewolf_storage::StorageError::with_source(
        kind,
        std::io::Error::other("sensitive-seeded-storage-source"),
    );
    HandlerError::Internal {
        condition: StanzaErrorCondition::InternalServerError,
        failure: Failure {
            kind: FailureKind::Storage(error.kind()),
            operation,
        },
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for FailureIq {
    fn get<'a>(
        &'a self,
        _request: IqRequest<'a, A>,
        _transaction: &'a RedbRead,
        _response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async {
            Err(injected_handler_error(
                lonewolf_storage::StorageErrorKind::CorruptData,
                "roster_read",
            ))
        })
    }
    fn set<'a>(
        &'a self,
        _request: IqRequest<'a, A>,
        _transaction: &'a mut RedbWrite,
        _hosts: &'a dyn HostLookup,
        _response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async {
            Err(injected_handler_error(
                lonewolf_storage::StorageErrorKind::Unavailable,
                "roster_write",
            ))
        })
    }
}
impl<A: ChunkAllocator> PresenceHandler<A, RedbStorage> for FailureIq {}
impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for FailureIq {}
