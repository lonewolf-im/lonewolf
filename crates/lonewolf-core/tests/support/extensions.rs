// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use lonewolf_extension::archive::{
    ArchiveDirection, ArchiveFuture, ArchiveHandler, ArchiveId, ArchiveOutcome, ArchiveRequest,
};
use lonewolf_extension::delivery::{
    Delivery, DeliveryError, DeliveryFuture, Failure, FailureKind, HandlerError, HostLookup,
    SessionTag,
};
use lonewolf_extension::discovery::{
    DiscoScope, INFO_NAMESPACE, Identity, Query, QueryKind, info_in,
};
use lonewolf_extension::iq::{
    IqFuture, IqHandler, IqReply, IqRequest, IqRequestType, IqRoute, IqScope, Requester,
};
use lonewolf_extension::message::{MessageHandler, StoreFuture, UndeliverableMessage};
use lonewolf_extension::observer::{
    MessageEvent, MessageObserver, MessageOutcome, MessageRole, SessionChange, SessionEvent,
    SessionObserver,
};
use lonewolf_extension::offline::Offline;
use lonewolf_extension::policy::{Direction, PolicyFuture, PolicyHandler, PolicyRequest, Verdict};
use lonewolf_extension::presence::{
    PresenceAudience, PresenceDecorator, PresenceFuture, PresenceHandler, PresenceRequest,
    PresenceRequestType, PresenceTransition, PresenceUpdate,
};
use lonewolf_extension::service::{ServiceContext, ServiceHandler};
use lonewolf_extension::{
    Effects, Extension, ExtensionFuture, Extensions, RegistrationError, Slots,
};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::{OfflineReads, OfflineWrites};
use lonewolf_storage::roster::{RosterJid, RosterWrites};
use lonewolf_storage::{RedbRead, RedbStorage, RedbWrite};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_util::pool::PooledChunkAllocator;
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{
    ApplicationCondition, Element, IqType, MessageType, PresenceType, RoutedStanza, Stanza,
    StanzaErrorCondition, StanzaNamespace, StanzaType,
};
use parking_lot::Mutex as PlMutex;

use super::TestResult;

const NAMESPACE: &str = "urn:lonewolf:test:iq";
const SERVICE_NAMESPACE: &str = "urn:lonewolf:test:service";
const DISCOVERY_ROUTE: IqRoute = IqRoute {
    scope: IqScope::Server,
    kind: IqRequestType::Get,
    namespace: "urn:lonewolf:test:discovery",
    name: "query",
};
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
    extensions.register(Arc::new(TestService {
        joined: PlMutex::new(BTreeSet::new()),
    }))?;
    extensions.register(Arc::new(TestHostService))?;
    extensions.register(Arc::new(TestArchive {
        next: AtomicU64::new(1),
        entries: PlMutex::new(Vec::new()),
    }))?;
    extensions.register(Arc::new(TestMessageObserver {
        events: PlMutex::new(Vec::new()),
    }))?;
    extensions.register(Arc::new(TestSessionObserver {
        events: PlMutex::new(Vec::new()),
    }))?;
    for kind in [
        DecorationKind::Valid,
        DecorationKind::Failing,
        DecorationKind::Conflicting,
    ] {
        extensions.register(Arc::new(TestDecoration(kind)))?;
    }
    extensions.register(Arc::new(TestSecondArchive))?;
    extensions.register(Arc::new(TestDiscovery))?;
    extensions.register(Arc::new(TestPolicy {
        enabled: AtomicBool::new(true),
    }))?;
    for kind in [
        ServiceLifecycleKind::OfflineWithdrawal,
        ServiceLifecycleKind::DelayedAvailable,
        ServiceLifecycleKind::DelayedUnavailable,
    ] {
        extensions.register(Arc::new(ServiceLifecycle {
            inner: TestService {
                joined: PlMutex::new(BTreeSet::new()),
            },
            kind,
            delay: AtomicBool::new(true),
            release: async_lock::Semaphore::new(0),
        }))?;
    }
    extensions.register(Arc::new(ConflictingIq))?;
    extensions.register(Arc::new(TestIq {
        gets: AtomicUsize::new(0),
        sets: AtomicUsize::new(0),
    }))?;
    extensions.register(Arc::new(TestAccountAccess))?;
    extensions.register(Arc::new(TestIqResults))?;
    extensions.register(Arc::new(TestIqRequester {
        outcome: Arc::new(PlMutex::new(None)),
    }))?;
    extensions.register(Arc::new(ServerIq))?;
    extensions.register(Arc::new(ErrorIq))?;
    extensions.register(Arc::new(FailureIq))?;
    extensions.register(Arc::new(RouterFailureIq))?;
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

struct TestService {
    joined: PlMutex<BTreeSet<String>>,
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestService {
    fn name(&self) -> &'static str {
        "test-service"
    }

    fn register(
        self: Arc<Self>,
        host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.service(&format!("echo.{host}"), self)
    }
}

impl<A: ChunkAllocator> ServiceHandler<A, RedbStorage> for TestService {
    fn route<'a>(
        &'a self,
        stanza: RoutedStanza<A>,
        context: ServiceContext<'a, A, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            let view = stanza
                .resolve()
                .map_err(|_| HandlerError::Stanza(StanzaErrorCondition::InternalServerError))?;
            if view.stanza_type() == StanzaType::Iq(IqType::Set) {
                return Err(StanzaErrorCondition::BadRequest.into());
            }
            let result = async {
                match view.stanza_type() {
                    StanzaType::Iq(IqType::Get) => {
                        let Some(query) = view.children()?.next().transpose()? else {
                            return Ok(());
                        };
                        let mut arena = context.outbound.arena()?;
                        let payload =
                            if query.name() == "query" && query.namespace() == SERVICE_NAMESPACE {
                                let count = self.joined.lock().len().to_string();
                                let count =
                                    Element::builder_in("count", SERVICE_NAMESPACE, &mut arena)?
                                        .text(&count)?
                                        .build()?;
                                Element::builder_in("query", SERVICE_NAMESPACE, &mut arena)?
                                    .child(count)?
                                    .build()?
                            } else if matches!(
                                Query::parse(query)?,
                                Some(Query {
                                    kind: QueryKind::Info,
                                    node: None,
                                })
                            ) {
                                info_in(
                                    None,
                                    &[Identity {
                                        category: "component",
                                        kind: "generic",
                                        name: Some("Echo"),
                                    }],
                                    &[INFO_NAMESPACE],
                                    &mut arena,
                                )?
                            } else {
                                return Ok(());
                            };
                        let request = view.to_builder_in(&mut arena)?.build()?;
                        let reply = request.reply_in(&mut arena)?.child(payload)?.build()?;
                        context
                            .outbound
                            .route(RoutedStanza::from_parts(reply, arena))
                            .await
                    }
                    StanzaType::Message(kind) if kind != MessageType::Error => {
                        let mut arena = context.outbound.arena()?;
                        let reply = view.to_builder_in(&mut arena)?.swap_addresses().build()?;
                        context
                            .outbound
                            .route(RoutedStanza::from_parts(reply, arena))
                            .await
                    }
                    StanzaType::Presence(PresenceType::Available | PresenceType::Unavailable) => {
                        let from = view.from()?.ok_or(DeliveryError)?;
                        if view.stanza_type() == StanzaType::Presence(PresenceType::Available) {
                            self.joined.lock().insert(from.as_str().into());
                        } else {
                            self.joined.lock().remove(from.as_str());
                        }
                        Ok(())
                    }
                    _ => Ok(()),
                }
            };
            result.await.map_err(|_: DeliveryError| {
                HandlerError::Stanza(StanzaErrorCondition::InternalServerError)
            })
        })
    }
}

struct TestHostService;

struct TestDiscovery;

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestDiscovery {
    fn name(&self) -> &'static str {
        "test-discovery"
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.disco_feature(DiscoScope::Server, "urn:lonewolf:test:b");
        slots.disco_feature(DiscoScope::Server, "urn:lonewolf:test:a");
        slots.disco_identity(
            DiscoScope::Server,
            Identity {
                category: "server",
                kind: "im",
                name: None,
            },
        );
        slots.iq(DISCOVERY_ROUTE, self)
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for TestDiscovery {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _transaction: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let result = (|| {
                let features = request.discovery.features(DiscoScope::Server);
                let services = request.discovery.services();
                let mut children = Vec::with_capacity(features.len() + services.len());
                for feature in features {
                    children.push(
                        Element::builder_in("feature", DISCOVERY_ROUTE.namespace, response)?
                            .attribute("var", "", feature)?
                            .build()?,
                    );
                }
                for service in services {
                    children.push(
                        Element::builder_in("service", DISCOVERY_ROUTE.namespace, response)?
                            .attribute("jid", "", service)?
                            .build()?,
                    );
                }
                let mut query = Element::builder_in("query", DISCOVERY_ROUTE.namespace, response)?;
                for child in children {
                    query = query.child(child)?;
                }
                query.build()
            })();
            result
                .map(|payload| IqReply::new(Some(payload), Effects::none()))
                .map_err(|_| StanzaErrorCondition::InternalServerError.into())
        })
    }
}

#[derive(Clone, Copy)]
enum ServiceLifecycleKind {
    OfflineWithdrawal,
    DelayedAvailable,
    DelayedUnavailable,
}

struct ServiceLifecycle {
    inner: TestService,
    kind: ServiceLifecycleKind,
    delay: AtomicBool,
    release: async_lock::Semaphore,
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for ServiceLifecycle {
    fn name(&self) -> &'static str {
        match self.kind {
            ServiceLifecycleKind::OfflineWithdrawal => "test-service-offline-withdrawal",
            ServiceLifecycleKind::DelayedAvailable => "test-service-delayed-available",
            ServiceLifecycleKind::DelayedUnavailable => "test-service-delayed-unavailable",
        }
    }

    fn register(
        self: Arc<Self>,
        host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.service(&format!("echo.{host}"), self)
    }
}

impl<A: ChunkAllocator> ServiceHandler<A, RedbStorage> for ServiceLifecycle {
    fn route<'a>(
        &'a self,
        stanza: RoutedStanza<A>,
        context: ServiceContext<'a, A, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            let result = async {
                let view = stanza.resolve()?;
                let kind = view.stanza_type();
                if kind == StanzaType::Iq(IqType::Get)
                    && view.children()?.next().transpose()?.is_some_and(|child| {
                        child.name() == "release" && child.namespace() == SERVICE_NAMESPACE
                    })
                {
                    self.release.add_permits(1);
                    let mut arena = context.outbound.arena()?;
                    let request = view.to_builder_in(&mut arena)?.build()?;
                    let reply = request.reply_in(&mut arena)?.build()?;
                    context
                        .outbound
                        .route(RoutedStanza::from_parts(reply, arena))
                        .await?;
                    return Ok(true);
                }
                let delayed = matches!(
                    (self.kind, kind),
                    (
                        ServiceLifecycleKind::DelayedAvailable,
                        StanzaType::Presence(PresenceType::Available)
                    ) | (
                        ServiceLifecycleKind::DelayedUnavailable,
                        StanzaType::Presence(PresenceType::Unavailable)
                    )
                );
                if delayed && self.delay.swap(false, Ordering::Relaxed) {
                    tracing::info!("test service presence waiting");
                    self.release.acquire().await.forget();
                    tracing::info!("test service presence released");
                }
                if matches!(self.kind, ServiceLifecycleKind::OfflineWithdrawal)
                    && kind == StanzaType::Presence(PresenceType::Unavailable)
                {
                    let mut arena = context.outbound.arena()?;
                    let from = Jid::parse_in(context.domain, &mut arena)?;
                    let to = Jid::parse_in(
                        view.from()?.ok_or(DeliveryError)?.bare().as_str(),
                        &mut arena,
                    )?;
                    let body = Element::builder_in("body", "jabber:client", &mut arena)?
                        .text("withdrawn")?
                        .build()?;
                    let notice = Stanza::builder_in(
                        StanzaType::Message(MessageType::Chat),
                        StanzaNamespace::Client,
                        &mut arena,
                    )
                    .from(Some(from))?
                    .to(Some(to))?
                    .child(body)?
                    .build()?;
                    context
                        .outbound
                        .route(RoutedStanza::from_parts(notice, arena))
                        .await?;
                    tracing::info!("test service withdrawal message stored");
                }
                Ok(false)
            }
            .await
            .map_err(|_: DeliveryError| {
                HandlerError::Stanza(StanzaErrorCondition::InternalServerError)
            })?;
            if result {
                return Ok(());
            }
            let unavailable = stanza
                .resolve()
                .map_err(|_| HandlerError::Stanza(StanzaErrorCondition::InternalServerError))?
                .stanza_type()
                == StanzaType::Presence(PresenceType::Unavailable);
            self.inner.route(stanza, context).await?;
            if unavailable {
                tracing::info!("test service withdrawal handled");
            }
            Ok(())
        })
    }
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestHostService {
    fn name(&self) -> &'static str {
        "test-host-service"
    }

    fn register(
        self: Arc<Self>,
        host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.service(
            host,
            Arc::new(TestService {
                joined: PlMutex::new(BTreeSet::new()),
            }),
        )
    }
}

struct ConflictingIq;

struct TestIq {
    gets: AtomicUsize,
    sets: AtomicUsize,
}

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

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        for route in [
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
        ] {
            slots.iq(route, self.clone())?;
        }
        slots.presence(PresenceRequestType::Available, self.clone())?;
        slots.offline(self)
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

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        for route in [OFFLINE_ROUTE, OFFLINE_PUSH] {
            slots.iq(route, self.clone())?;
        }
        Ok(())
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for OfflineInspect {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            inspect_offline(request, transaction, response)
                .await
                .map_err(Into::into)
        })
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

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        if self.block_ack {
            for route in [OFFLINE_ROUTE, OFFLINE_RELEASE] {
                slots.iq(route, self.clone())?;
            }
        }
        slots.presence(PresenceRequestType::Available, self.clone())?;
        slots.offline(self)
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
            inspect_offline(request, transaction, response)
                .await
                .map_err(Into::into)
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

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq(ACCOUNT_GET, self)
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

struct TestIqRequester {
    outcome: Arc<PlMutex<Option<&'static str>>>,
}

const REQUESTER_ASK: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Set,
    namespace: "urn:lonewolf:test:requester",
    name: "ask",
};

const REQUESTER_OUTCOME: IqRoute = IqRoute {
    scope: IqScope::Server,
    kind: IqRequestType::Get,
    name: "outcome",
    ..REQUESTER_ASK
};

impl<A: ChunkAllocator + 'static> Extension<A, RedbStorage> for TestIqRequester {
    fn name(&self) -> &'static str {
        "test-iq-requester"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq(REQUESTER_ASK, self.clone())?;
        slots.iq(REQUESTER_OUTCOME, self)
    }
}

impl<A: ChunkAllocator + 'static> IqHandler<A, RedbStorage> for TestIqRequester {
    fn set<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _: &'a mut RedbWrite,
        _: &'a dyn HostLookup,
        _: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let jid: Box<str> = request
                .payload
                .attribute("jid", "")
                .map_err(|_| StanzaErrorCondition::BadRequest)?
                .ok_or(StanzaErrorCondition::BadRequest)?
                .into();
            let timeout = request
                .payload
                .attribute("timeout", "")
                .map_err(|_| StanzaErrorCondition::BadRequest)?
                .and_then(|value| value.parse().ok())
                .ok_or(StanzaErrorCondition::BadRequest)?;
            *self.outcome.lock() = None;
            let outcome = Arc::clone(&self.outcome);
            let effects = Effects::new(Vec::new(), move |delivery| {
                Box::pin(async move {
                    delivery.detach(Box::new(move |delivery| {
                        Box::pin(async move {
                            let mut arena = delivery.arena()?;
                            let from = Jid::parse_in("localhost", &mut arena)?;
                            let to = Jid::parse_in(&jid, &mut arena)?;
                            let ping = Element::builder_in("ping", "urn:xmpp:ping", &mut arena)?
                                .build()?;
                            let stanza = Stanza::builder_in(
                                StanzaType::Iq(IqType::Get),
                                StanzaNamespace::Client,
                                &mut arena,
                            )
                            .id(Some("request"))?
                            .from(Some(from))?
                            .to(Some(to))?
                            .child(ping)?
                            .build()?;
                            let result = delivery
                                .request_iq(
                                    RoutedStanza::from_parts(stanza, arena),
                                    Duration::from_secs(timeout),
                                )
                                .await;
                            *outcome.lock() = Some(match result {
                                Ok(response) => match response.resolve()?.stanza_type() {
                                    StanzaType::Iq(IqType::Result) => "answered:result",
                                    StanzaType::Iq(IqType::Error) => "answered:error",
                                    _ => return Err(DeliveryError),
                                },
                                Err(_) => "failed",
                            });
                            Ok(())
                        })
                    }))
                })
            });
            Ok(IqReply::new(None, effects))
        })
    }

    fn get<'a>(
        &'a self,
        _: IqRequest<'a, A>,
        _: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let outcome = *self.outcome.lock();
            let payload = outcome
                .map(|value| {
                    Element::builder_in("outcome", REQUESTER_OUTCOME.namespace, response)
                        .and_then(|builder| builder.attribute("value", "", value))
                        .and_then(|builder| builder.build())
                })
                .transpose()
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            Ok(IqReply::new(payload, Effects::none()))
        })
    }
}

struct TestAccountAccess;

const ACCESS_ROUTE: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Get,
    namespace: "urn:lonewolf:test:access",
    name: "query",
};

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestAccountAccess {
    fn name(&self) -> &'static str {
        "test-account-access"
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq(ACCESS_ROUTE, self.clone())?;
        slots.iq(
            IqRoute {
                kind: IqRequestType::Set,
                ..ACCESS_ROUTE
            },
            self,
        )
    }
}

impl TestAccountAccess {
    async fn reply<A: ChunkAllocator>(
        request: IqRequest<'_, A>,
        response: &mut Arena<A>,
    ) -> Result<IqReply<A>, HandlerError> {
        let requester = match request.requester {
            Some(Requester::Owner) => "owner",
            Some(Requester::PresenceAuthorized) => "presence-authorized",
            Some(Requester::Other) => "other",
            None => "none",
        };
        let condition = StanzaErrorCondition::InternalServerError;
        let resources = if request
            .payload
            .attribute("resources", "")
            .map_err(|_| condition)?
            == Some("true")
        {
            let account = AccountKey::try_from(request.target.bare()).map_err(|_| condition)?;
            request
                .sessions
                .resources(&account)
                .await
                .map_err(|_| condition)?
        } else {
            Vec::new()
        };
        let mut children = Vec::with_capacity(resources.len());
        for resource in resources {
            children.push(
                Element::builder_in("resource", ACCESS_ROUTE.namespace, response)
                    .and_then(|builder| builder.attribute("name", "", &resource.resource))
                    .and_then(|builder| {
                        builder.attribute(
                            "available",
                            "",
                            if resource.available { "true" } else { "false" },
                        )
                    })
                    .and_then(|builder| builder.build())
                    .map_err(|_| condition)?,
            );
        }
        let mut builder = Element::builder_in("query", ACCESS_ROUTE.namespace, response)
            .and_then(|builder| builder.attribute("requester", "", requester))
            .map_err(|_| condition)?;
        for child in children {
            builder = builder.child(child).map_err(|_| condition)?;
        }
        let payload = builder.build().map_err(|_| condition)?;
        Ok(IqReply::new(Some(payload), Effects::none()))
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for TestAccountAccess {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move { Self::reply(request, response).await.map_err(Into::into) })
    }

    fn get_missing_account(
        &self,
        _: IqRequest<'_, A>,
        response: &mut Arena<A>,
    ) -> Result<Option<Element>, lonewolf_extension::iq::IqError> {
        Element::builder_in("query", ACCESS_ROUTE.namespace, response)
            .and_then(|builder| builder.attribute("missing", "", "true"))
            .and_then(|builder| builder.build())
            .map(Some)
            .map_err(|_| StanzaErrorCondition::InternalServerError.into())
    }

    fn set<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _: &'a mut RedbWrite,
        _: &'a dyn HostLookup,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move { Self::reply(request, response).await.map_err(Into::into) })
    }
}

struct TestIqResults;

const RESULTS_ROUTE: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Get,
    namespace: "urn:lonewolf:test:results",
    name: "query",
};

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestIqResults {
    fn name(&self) -> &'static str {
        "test-iq-results"
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq(RESULTS_ROUTE, self)
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for TestIqResults {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let condition = StanzaErrorCondition::InternalServerError;
            let misaddressed = request
                .payload
                .attribute("misaddressed", "")
                .map_err(|_| condition)?
                == Some("true");
            let count = if misaddressed {
                1
            } else {
                request
                    .payload
                    .attribute("count", "")
                    .map_err(|_| condition)?
                    .and_then(|count| count.parse::<usize>().ok())
                    .ok_or(StanzaErrorCondition::BadRequest)?
            };
            let from =
                Jid::parse_in(request.sender.domainpart(), response).map_err(|_| condition)?;
            let to = Jid::parse_in(
                if misaddressed {
                    "nobody@localhost/x"
                } else {
                    request.sender.as_str()
                },
                response,
            )
            .map_err(|_| condition)?;
            let mut results = Vec::new();
            for index in 0..count {
                let result = Element::builder_in("result", RESULTS_ROUTE.namespace, response)
                    .and_then(|builder| builder.attribute("index", "", &index.to_string()))
                    .and_then(|builder| builder.build())
                    .map_err(|_| condition)?;
                results.push(
                    Stanza::builder_in(
                        StanzaType::Message(MessageType::Normal),
                        StanzaNamespace::Client,
                        response,
                    )
                    .from(Some(from))
                    .and_then(|builder| builder.to(Some(to)))
                    .and_then(|builder| builder.child(result))
                    .and_then(|builder| builder.build())
                    .map_err(|_| condition)?,
                );
            }
            Ok(IqReply::new(None, Effects::none()).with_results(results))
        })
    }
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestIq {
    fn name(&self) -> &'static str {
        "test-iq"
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        for route in [ACCOUNT_GET, ACCOUNT_SET, ACCOUNT_SLOW] {
            slots.iq(route, self.clone())?;
        }
        Ok(())
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for TestIq {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            if request
                .payload
                .attribute("calls", "")
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                == Some("true")
            {
                let payload = Element::builder_in("calls", NAMESPACE, response)
                    .and_then(|builder| {
                        builder.attribute("gets", "", &self.gets.load(Ordering::SeqCst).to_string())
                    })
                    .and_then(|builder| {
                        builder.attribute("sets", "", &self.sets.load(Ordering::SeqCst).to_string())
                    })
                    .and_then(|builder| builder.build())
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                return Ok(IqReply::new(Some(payload), Effects::none()));
            }
            self.gets.fetch_add(1, Ordering::SeqCst);
            identity(&request, response).await.map_err(Into::into)
        })
    }

    fn set<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a mut RedbWrite,
        _: &'a dyn HostLookup,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            self.sets.fetch_add(1, Ordering::SeqCst);
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

impl<A: ChunkAllocator> Extension<A, RedbStorage> for ServerIq {
    fn name(&self) -> &'static str {
        "test-server-iq"
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq(SERVER_GET, self)
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for ServerIq {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move { identity(&request, response).await.map_err(Into::into) })
    }
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for ErrorIq {
    fn name(&self) -> &'static str {
        "test-error-iq"
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq(ACCOUNT_DENY, self)
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

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestPresence {
    fn name(&self) -> &'static str {
        "test-presence"
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        for kind in SUBSCRIPTION_KINDS {
            slots.presence(kind, self.clone())?;
        }
        Ok(())
    }
}

impl<A: ChunkAllocator> PresenceHandler<A, RedbStorage> for TestPresence {
    fn authorize<'a>(&'a self, request: PresenceRequest<'a, A>) -> PresenceFuture<'a, ()> {
        Box::pin(async move { verify_authorization(&request).await.map_err(Into::into) })
    }
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for ConflictingPresence {
    fn name(&self) -> &'static str {
        "test-conflicting-presence"
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.presence(PresenceRequestType::Subscribe, self)
    }
}

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

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        for route in [FAILURE_GET, FAILURE_SET] {
            slots.iq(route, self.clone())?;
        }
        Ok(())
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
            )
            .into())
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
            )
            .into())
        })
    }
}

struct RouterFailureIq;

const ROUTER_FAILURE_SET: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Set,
    namespace: "urn:lonewolf:test:router-failure",
    name: "crash",
};
const CONNECTION_FAILURE_SET: IqRoute = IqRoute {
    name: "connection",
    ..ROUTER_FAILURE_SET
};

impl<A: ChunkAllocator> Extension<A, RedbStorage> for RouterFailureIq {
    fn name(&self) -> &'static str {
        "test-router-failure"
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        for route in [ROUTER_FAILURE_SET, CONNECTION_FAILURE_SET] {
            slots.iq(route, self.clone())?;
        }
        Ok(())
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for RouterFailureIq {
    fn set<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _: &'a mut RedbWrite,
        _: &'a dyn HostLookup,
        _: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            if request.payload.name() == CONNECTION_FAILURE_SET.name {
                panic!("seeded-sensitive-connection-payload");
            }
            let account = AccountKey::try_from(request.target.bare())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            let effects = Effects::new(vec![account.clone()], move |delivery| {
                Box::pin(async move {
                    delivery
                        .push_to_tagged(
                            &account,
                            SessionTag::Interested,
                            Box::new(|_, _| panic!("seeded-sensitive-router-payload")),
                        )
                        .await?;
                    Ok(())
                })
            });
            Ok(IqReply::new(None, effects))
        })
    }
}

struct TestPolicy {
    enabled: AtomicBool,
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestPolicy {
    fn name(&self) -> &'static str {
        "test-policy"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.policy(self.clone());
        slots.iq(
            IqRoute {
                scope: IqScope::Server,
                kind: IqRequestType::Set,
                namespace: "urn:lonewolf:test:policy",
                name: "toggle",
            },
            self,
        )?;
        Ok(())
    }
}

impl PolicyHandler<RedbStorage> for TestPolicy {
    fn check<'a>(&'a self, request: PolicyRequest<'a>, _: &'a RedbRead) -> PolicyFuture<'a> {
        Box::pin(async move {
            if !self.enabled.load(Ordering::Relaxed) {
                return Ok(Verdict::Allow);
            }
            Ok(match (request.peer.localpart(), request.direction) {
                (Some("blocked"), Direction::Outbound) => Verdict::Reject {
                    condition: StanzaErrorCondition::NotAcceptable,
                    application: Some(ApplicationCondition {
                        name: "blocked",
                        namespace: "urn:lonewolf:test:policy",
                    }),
                    text: None,
                },
                (Some("spammer"), Direction::Inbound) => Verdict::Drop,
                (Some("rejecter"), Direction::Inbound) => Verdict::Reject {
                    condition: StanzaErrorCondition::ServiceUnavailable,
                    application: None,
                    text: None,
                },
                (Some("broken"), _) => {
                    return Err(HandlerError::Internal {
                        condition: StanzaErrorCondition::InternalServerError,
                        failure: Failure {
                            kind: FailureKind::Delivery,
                            operation: "test_policy",
                        },
                    });
                }
                _ => Verdict::Allow,
            })
        })
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for TestPolicy {
    fn set<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _: &'a mut RedbWrite,
        _: &'a dyn HostLookup,
        _: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let enabled = match request
                .payload
                .attribute("enabled", "")
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
            {
                Some("true") => true,
                Some("false") => false,
                _ => return Err(StanzaErrorCondition::BadRequest.into()),
            };
            self.enabled.store(enabled, Ordering::Relaxed);
            Ok(IqReply::new(None, Effects::none()))
        })
    }
}

const ARCHIVE_ROUTE: IqRoute = IqRoute {
    scope: IqScope::Server,
    kind: IqRequestType::Get,
    namespace: "urn:lonewolf:test:archive",
    name: "entries",
};

struct TestArchive {
    next: AtomicU64,
    entries: PlMutex<Vec<(String, ArchiveDirection, u64)>>,
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestArchive {
    fn name(&self) -> &'static str {
        "test-archive"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq(ARCHIVE_ROUTE, self.clone())?;
        slots.archive(self)
    }
}

impl<A: ChunkAllocator> ArchiveHandler<A, RedbStorage> for TestArchive {
    fn selects(&self, request: &ArchiveRequest<'_, A>) -> bool {
        request.stanza.resolve().is_ok_and(|view| {
            matches!(
                view.stanza_type(),
                StanzaType::Message(MessageType::Chat | MessageType::Normal)
            )
        })
    }

    fn archive<'a>(
        &'a self,
        request: ArchiveRequest<'a, A>,
        _: &'a mut RedbWrite,
        _: &'a mut Arena<A>,
    ) -> ArchiveFuture<'a> {
        Box::pin(async move {
            let view = request
                .stanza
                .resolve()
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            if let Some(body) = view
                .child("body", "jabber:client")
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                && body
                    .text()
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?
                    == Some("reject")
            {
                return Err(StanzaErrorCondition::ResourceConstraint.into());
            }
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            self.entries
                .lock()
                .push((request.owner.as_str().into(), request.direction, id));
            Ok(ArchiveOutcome::Archived(ArchiveId::new(id)))
        })
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for TestArchive {
    fn get<'a>(
        &'a self,
        _: IqRequest<'a, A>,
        _: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let entries = self
                .entries
                .lock()
                .iter()
                .map(|(owner, direction, id)| {
                    let mut buffer = [0; 20];
                    let mut output = buffer.as_mut_slice();
                    write!(&mut output, "{id}")
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    let written = 20 - output.len();
                    let id = std::str::from_utf8(&buffer[..written])
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    Element::builder_in("entry", ARCHIVE_ROUTE.namespace, response)
                        .and_then(|builder| builder.attribute("owner", "", owner))
                        .and_then(|builder| {
                            builder.attribute(
                                "direction",
                                "",
                                match direction {
                                    ArchiveDirection::Sent => "sent",
                                    ArchiveDirection::Received => "received",
                                },
                            )
                        })
                        .and_then(|builder| builder.attribute("id", "", id))
                        .and_then(|builder| builder.build())
                        .map_err(|_| StanzaErrorCondition::InternalServerError)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut builder =
                Element::builder_in(ARCHIVE_ROUTE.name, ARCHIVE_ROUTE.namespace, response)
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            for entry in entries {
                builder = builder
                    .child(entry)
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            }
            let payload = builder
                .build()
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            Ok(IqReply::new(Some(payload), Effects::none()))
        })
    }
}

struct TestSecondArchive;

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestSecondArchive {
    fn name(&self) -> &'static str {
        "test-second-archive"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.archive(self)
    }
}

impl<A: ChunkAllocator> ArchiveHandler<A, RedbStorage> for TestSecondArchive {
    fn selects(&self, _: &ArchiveRequest<'_, A>) -> bool {
        false
    }

    fn archive<'a>(
        &'a self,
        _: ArchiveRequest<'a, A>,
        _: &'a mut RedbWrite,
        _: &'a mut Arena<A>,
    ) -> ArchiveFuture<'a> {
        Box::pin(async { Ok(ArchiveOutcome::Skipped) })
    }
}

const OBSERVER_ROUTE: IqRoute = IqRoute {
    scope: IqScope::Server,
    kind: IqRequestType::Get,
    namespace: "urn:lonewolf:test:observer",
    name: "messages",
};

type ObservedMessage = (String, MessageRole, MessageOutcome, Option<ArchiveId>);

struct TestMessageObserver {
    events: PlMutex<Vec<ObservedMessage>>,
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestMessageObserver {
    fn name(&self) -> &'static str {
        "test-message-observer"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq(OBSERVER_ROUTE, self.clone())?;
        slots.message_observer(self);
        Ok(())
    }
}

impl<A: ChunkAllocator> MessageObserver<A, RedbStorage> for TestMessageObserver {
    fn observe<'a>(
        &'a self,
        event: MessageEvent<'a, A>,
        _: &'a RedbStorage,
        delivery: &'a dyn Delivery<A>,
    ) -> DeliveryFuture<'a> {
        Box::pin(async move {
            self.events.lock().push((
                event.account.as_str().into(),
                event.role,
                event.outcome,
                event.archived,
            ));
            if event.role == MessageRole::Sent
                && event.outcome == MessageOutcome::Routed
                && event
                    .stanza
                    .resolve()?
                    .child("body", "jabber:client")?
                    .is_some_and(|body| body.text().is_ok_and(|text| text == Some("copy")))
            {
                let domain = event.account.domain().to_owned();
                delivery
                    .push_to_tagged(
                        event.account,
                        SessionTag::Interested,
                        Box::new(move |full, arena| {
                            let from = Jid::from_parts_in(None, &domain, None, arena)?;
                            let copied =
                                Element::builder_in("copied", OBSERVER_ROUTE.namespace, arena)?
                                    .build()?;
                            Ok(Stanza::builder_in(
                                StanzaType::Message(MessageType::Headline),
                                StanzaNamespace::Client,
                                arena,
                            )
                            .from(Some(from))?
                            .to(Some(full))?
                            .child(copied)?
                            .build()?)
                        }),
                    )
                    .await?;
            }
            Ok(())
        })
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for TestMessageObserver {
    fn get<'a>(
        &'a self,
        _: IqRequest<'a, A>,
        _: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let events = self
                .events
                .lock()
                .iter()
                .map(|(account, role, outcome, archived)| {
                    let mut builder =
                        Element::builder_in("event", OBSERVER_ROUTE.namespace, response)
                            .map_err(|_| StanzaErrorCondition::InternalServerError)?
                            .attribute("account", "", account)
                            .map_err(|_| StanzaErrorCondition::InternalServerError)?
                            .attribute(
                                "role",
                                "",
                                match role {
                                    MessageRole::Sent => "sent",
                                    MessageRole::Received => "received",
                                },
                            )
                            .map_err(|_| StanzaErrorCondition::InternalServerError)?
                            .attribute(
                                "outcome",
                                "",
                                match outcome {
                                    MessageOutcome::Routed => "routed",
                                    MessageOutcome::Stored => "stored",
                                    MessageOutcome::Forwarded => "forwarded",
                                    MessageOutcome::Rejected => "rejected",
                                    MessageOutcome::Discarded => "discarded",
                                },
                            )
                            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    if let Some(id) = archived {
                        let mut buffer = [0; 20];
                        let mut output = buffer.as_mut_slice();
                        write!(&mut output, "{id}")
                            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                        let written = 20 - output.len();
                        let id = std::str::from_utf8(&buffer[..written])
                            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                        builder = builder
                            .attribute("archived", "", id)
                            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                    }
                    builder
                        .build()
                        .map_err(|_| HandlerError::from(StanzaErrorCondition::InternalServerError))
                })
                .collect::<Result<Vec<_>, HandlerError>>()?;
            let mut builder =
                Element::builder_in(OBSERVER_ROUTE.name, OBSERVER_ROUTE.namespace, response)
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            for event in events {
                builder = builder
                    .child(event)
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            }
            Ok(IqReply::new(
                Some(
                    builder
                        .build()
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?,
                ),
                Effects::none(),
            ))
        })
    }
}

const SESSION_ROUTE: IqRoute = IqRoute {
    scope: IqScope::Server,
    kind: IqRequestType::Get,
    namespace: "urn:lonewolf:test:sessions",
    name: "events",
};

struct TestSessionObserver {
    events: PlMutex<Vec<(String, &'static str)>>,
}

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestSessionObserver {
    fn name(&self) -> &'static str {
        "test-session-observer"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq(SESSION_ROUTE, self.clone())?;
        slots.session_observer(self);
        Ok(())
    }
}

impl<A: ChunkAllocator> SessionObserver<A, RedbStorage> for TestSessionObserver {
    fn session_changed<'a>(
        &'a self,
        change: SessionChange<'a, A>,
        _: &'a RedbStorage,
        _: &'a dyn Delivery<A>,
    ) -> DeliveryFuture<'a> {
        Box::pin(async move {
            let kind = match change.event {
                SessionEvent::Bound => "bound",
                SessionEvent::Presence {
                    transition: PresenceTransition::Initial,
                    ..
                } => "presence:initial",
                SessionEvent::Presence {
                    transition: PresenceTransition::Update,
                    ..
                } => "presence:update",
                SessionEvent::Presence {
                    transition: PresenceTransition::Unavailable,
                    ..
                } => "presence:unavailable",
                SessionEvent::Ended => "ended",
            };
            self.events
                .lock()
                .push((change.session.as_str().into(), kind));
            Ok(())
        })
    }
}

impl<A: ChunkAllocator> IqHandler<A, RedbStorage> for TestSessionObserver {
    fn get<'a>(
        &'a self,
        _: IqRequest<'a, A>,
        _: &'a RedbRead,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let result = (|| {
                let children = self
                    .events
                    .lock()
                    .iter()
                    .map(|(session, kind)| {
                        Element::builder_in("event", SESSION_ROUTE.namespace, response)?
                            .attribute("session", "", session)?
                            .attribute("kind", "", kind)?
                            .build()
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut builder =
                    Element::builder_in(SESSION_ROUTE.name, SESSION_ROUTE.namespace, response)?;
                for child in children {
                    builder = builder.child(child)?;
                }
                builder.build()
            })();
            result
                .map(|payload| IqReply::new(Some(payload), Effects::none()))
                .map_err(|_| StanzaErrorCondition::InternalServerError.into())
        })
    }
}

#[derive(Clone, Copy)]
enum DecorationKind {
    Valid,
    Failing,
    Conflicting,
}

struct TestDecoration(DecorationKind);

impl<A: ChunkAllocator> Extension<A, RedbStorage> for TestDecoration {
    fn name(&self) -> &'static str {
        match self.0 {
            DecorationKind::Valid => "test-decoration",
            DecorationKind::Failing => "test-failing-decoration",
            DecorationKind::Conflicting => "test-conflicting-decoration",
        }
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        let (name, namespace) = match self.0 {
            DecorationKind::Valid | DecorationKind::Conflicting => {
                ("x", "urn:lonewolf:test:decoration")
            }
            DecorationKind::Failing => ("y", "urn:lonewolf:test:failing"),
        };
        slots.presence_decoration(name, namespace, self)
    }
}

impl<A: ChunkAllocator> PresenceDecorator<A, RedbStorage> for TestDecoration {
    fn decorate<'a>(
        &'a self,
        _: &'a AccountKey,
        _: &'a RedbRead,
        arena: &'a mut Arena<A>,
    ) -> PresenceFuture<'a, Option<Element>> {
        Box::pin(async move {
            if matches!(self.0, DecorationKind::Failing) {
                return Err(HandlerError::Internal {
                    condition: StanzaErrorCondition::InternalServerError,
                    failure: Failure {
                        kind: FailureKind::Delivery,
                        operation: "test_decoration",
                    },
                });
            }
            Element::builder_in("x", "urn:lonewolf:test:decoration", arena)
                .and_then(|builder| builder.attribute("n", "", "1"))
                .and_then(|builder| builder.build())
                .map(Some)
                .map_err(|_| StanzaErrorCondition::InternalServerError.into())
        })
    }
}
