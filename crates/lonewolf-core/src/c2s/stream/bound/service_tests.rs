// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use compio::runtime::Runtime;
use futures_util::poll;
use lonewolf_extension::blocking::Blocking;
use lonewolf_extension::delivery::DeliveryError;
use lonewolf_extension::offline::Offline;
use lonewolf_extension::roster::Roster;
use lonewolf_extension::service::{ServiceContext, ServiceHandler};
use lonewolf_extension::{ExtensionFuture, Extensions};
use lonewolf_storage::blocking::{BlockChange, BlockingWrites};
use lonewolf_storage::roster::{
    RosterItem, RosterJid, RosterReads, RosterSubscription, RosterWrites, SubscriptionState,
};
use lonewolf_util::arena::GlobalChunkAllocator;
use parking_lot::Mutex as PlMutex;

use super::tests::{ControlledWriter, Fixture};
use super::*;
use crate::component::metrics::ComponentMetrics;
use crate::component::{
    credentials,
    registry::{ComponentLink, ComponentRegistry},
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type TestSession<'a> = BoundSession<'a, GlobalChunkAllocator, ControlledWriter>;
type Barrier = (oneshot::Sender<()>, oneshot::Receiver<()>);

#[derive(Default)]
struct TestService {
    delayed: Option<PresenceType>,
    barrier: PlMutex<Option<Barrier>>,
    events: PlMutex<Vec<PresenceType>>,
    subscriptions: PlMutex<Vec<RoutedStanza<GlobalChunkAllocator>>>,
    withdrawn: PlMutex<Vec<RosterJid>>,
    joined: AtomicBool,
    offline: bool,
}

impl TestService {
    fn delayed(kind: PresenceType) -> (Arc<Self>, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (notice, entered) = oneshot::channel();
        let (release, blocked) = oneshot::channel();
        (
            Arc::new(Self {
                delayed: Some(kind),
                barrier: PlMutex::new(Some((notice, blocked))),
                ..Self::default()
            }),
            entered,
            release,
        )
    }
}

impl ServiceHandler<GlobalChunkAllocator, RedbStorage> for TestService {
    fn route<'a>(
        &'a self,
        stanza: RoutedStanza<GlobalChunkAllocator>,
        context: ServiceContext<'a, GlobalChunkAllocator, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            let result = async {
                let view = stanza.resolve()?;
                let StanzaType::Presence(kind) = view.stanza_type() else {
                    return Ok(());
                };
                if PresenceRequestType::from_subscription_stanza(kind).is_some() {
                    self.subscriptions.lock().push(stanza.clone());
                }
                let barrier = (self.delayed == Some(kind))
                    .then(|| self.barrier.lock().take())
                    .flatten();
                if let Some((notice, blocked)) = barrier {
                    let _ = notice.send(());
                    blocked.await.map_err(|_| DeliveryError)?;
                }
                if self.offline && kind == PresenceType::Unavailable {
                    let mut arena = context.outbound.arena()?;
                    let from = Jid::parse_in(context.domain, &mut arena)?;
                    let to = Jid::parse_in(
                        view.from()?.ok_or(DeliveryError)?.bare().as_str(),
                        &mut arena,
                    )?;
                    let message = Stanza::builder_in(
                        StanzaType::Message(MessageType::Chat),
                        StanzaNamespace::Client,
                        &mut arena,
                    )
                    .from(Some(from))?
                    .to(Some(to))?
                    .build()?;
                    context
                        .outbound
                        .route(RoutedStanza::from_parts(message, arena))
                        .await?;
                }
                if kind == PresenceType::Unavailable
                    && let Some(target) = view.to()?
                {
                    self.withdrawn.lock().push(RosterJid::from(target));
                }
                self.events.lock().push(kind);
                self.joined
                    .store(kind == PresenceType::Available, Ordering::Relaxed);
                Ok(())
            }
            .await;
            result.map_err(|_: DeliveryError| StanzaErrorCondition::InternalServerError.into())
        })
    }
}

async fn fixture(service: Arc<TestService>) -> TestResult<Fixture> {
    fixture_with_route(ServiceRoute::extension(
        Arc::from("echo.localhost"),
        service,
    ))
    .await
}

async fn fixture_with_route(route: ServiceRoute<GlobalChunkAllocator>) -> TestResult<Fixture> {
    let mut fixture = Fixture::new(&[]).await?;
    let mut catalog = Extensions::default();
    catalog.register(Arc::new(Offline::new(Default::default())))?;
    catalog.register(Arc::new(Roster::default()))?;
    fixture.router = fixture
        .router
        .with_services(BTreeMap::from([(route.domain.to_string(), route)]))
        .with_extensions(BTreeMap::from([(
            "localhost".into(),
            catalog.enable_host("localhost", ["offline", "roster"])?,
        )]));
    Ok(fixture)
}

async fn session(fixture: &Fixture) -> TestResult<TestSession<'_>> {
    let registration = fixture
        .router
        .handle()
        .register(
            fixture.registration.account(),
            Some("desk"),
            NonZeroUsize::new(2).ok_or("zero resource limit")?,
        )
        .await?;
    let mut outbox = fixture.outbox(GlobalChunkAllocator, ControlledWriter::default());
    outbox.liveness = registration.liveness();
    Ok(BoundSession {
        registration,
        router: fixture.router.handle(),
        storage: fixture.storage.clone(),
        allocator: GlobalChunkAllocator,
        work: fixture.work.handle(),
        service_presence: None,
        service_pending: None,
        recipients: RecipientLimiter::new(
            NonZeroUsize::MIN,
            NonZeroUsize::new(100).ok_or("zero burst")?,
            Instant::now(),
            crate::c2s::metrics::C2sWorkerMetrics::detached(),
        ),
        available: false,
        priority: None,
        incoming: async_channel::bounded(1).1,
        outbox,
    })
}

async fn observer(fixture: &Fixture) -> TestResult<Registration<GlobalChunkAllocator>> {
    let mut arena = Arena::try_new(Default::default())?;
    let account =
        AccountKey::try_from(Jid::parse_in("alice@localhost", &mut arena)?.resolve(&arena)?)?;
    Ok(fixture
        .router
        .handle()
        .register(&account, Some("phone"), NonZeroUsize::MIN)
        .await?)
}

async fn parsed(xml: &str) -> TestResult<Parsed<Stanza, GlobalChunkAllocator>> {
    let input = tokio::io::AsyncReadExt::chain(STORED_STANZA_STREAM_HEADER, xml.as_bytes());
    let mut parser = XmppParser::new(
        input,
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4096).ok_or("zero stanza limit")?,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    );
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    match parser.next_event().await? {
        Some(StreamEvent::Stanza(parsed)) => Ok(parsed),
        _ => Err("missing stanza".into()),
    }
}

async fn handle(session: &mut TestSession<'_>, xml: &str) -> TestResult {
    session
        .handle_stanza(parsed(xml).await?)
        .await
        .map_err(|error| format!("{error:?}").into())
}

async fn entered(
    operation: &mut std::pin::Pin<Box<impl Future<Output = Result<(), CloseOutcome>>>>,
    notice: oneshot::Receiver<()>,
) -> TestResult {
    match select(operation, notice).await {
        Either::Right((result, _)) => Ok(result?),
        Either::Left((result, _)) => Err(format!("callback did not pause: {result:?}").into()),
    }
}

#[test]
fn service_withdrawal_releases_account_ticket_before_offline_reply() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        for terminal in [false, true] {
            let service = Arc::new(TestService {
                offline: true,
                ..TestService::default()
            });
            let mut fixture = fixture(service.clone()).await?;
            let mut session = session(&fixture).await?;
            handle(&mut session, "<presence/>").await?;
            handle(&mut session, "<presence to='room@echo.localhost/a'/>").await?;
            let mut arena = Arena::try_new(Default::default())?;
            let alice = AccountKey::try_from(
                Jid::parse_in("alice@localhost", &mut arena)?.resolve(&arena)?,
            )?;
            let observer = fixture
                .router
                .handle()
                .register(&alice, Some("phone"), NonZeroUsize::MIN)
                .await?;
            handle(&mut session, "<presence to='alice@localhost/phone'/>").await?;
            assert_eq!(observer.take_queued().len(), 1);
            if terminal {
                session.end().await.map_err(|error| format!("{error:?}"))?;
            } else {
                handle(&mut session, "<presence type='unavailable'/>").await?;
            }
            assert_eq!(fixture.count().await?, 1);
            assert_eq!(
                *service.events.lock(),
                [PresenceType::Available, PresenceType::Unavailable]
            );
            let withdrawal = observer.recv().await.ok_or("missing local withdrawal")?;
            assert_eq!(
                withdrawal.stanza.resolve()?.stanza_type(),
                StanzaType::Presence(PresenceType::Unavailable)
            );
            assert!(observer.take_queued().is_empty());
            if !terminal {
                session.end().await.map_err(|error| format!("{error:?}"))?;
            }
            drop(session);
            drop(observer);
            fixture.work.drain().await;
            fixture.finish().await?;
        }
        Ok(())
    }))?
}

#[test]
fn service_withdrawal_checks_the_directed_recipient_policy() -> TestResult {
    Runtime::new()?.block_on(async {
        for terminal in [false, true] {
            let service = Arc::new(TestService::default());
            let mut fixture = fixture(service.clone()).await?;
            let mut catalog = Extensions::default();
            catalog.register(Arc::new(Blocking))?;
            fixture.router = fixture.router.with_extensions(BTreeMap::from([(
                "localhost".into(),
                catalog.enable_host("localhost", ["blocking"])?,
            )]));
            let mut client = session(&fixture).await?;
            handle(&mut client, "<presence to='room@echo.localhost/blocked'/>").await?;
            handle(&mut client, "<presence to='room@echo.localhost/allowed'/>").await?;
            assert_eq!(*service.events.lock(), [PresenceType::Available; 2]);

            let mut arena = Arena::try_new(Default::default())?;
            let target = Jid::parse_in("room@echo.localhost/blocked", &mut arena)?;
            let mut write = fixture.storage.begin_write().await?;
            write
                .change_blocklist(
                    client.registration.account(),
                    BlockChange::Block(&[RosterJid::from(target.resolve(&arena)?)]),
                )
                .await?;
            write.commit().await?;

            if !terminal {
                handle(&mut client, "<presence type='unavailable'/>").await?;
            }
            client.end().await.map_err(|error| format!("{error:?}"))?;
            assert_eq!(
                *service.events.lock(),
                [
                    PresenceType::Available,
                    PresenceType::Available,
                    PresenceType::Unavailable
                ],
            );
            {
                let recipients = service.withdrawn.lock();
                assert_eq!(recipients.len(), 1);
                assert_eq!(recipients[0].as_str(), "room@echo.localhost/allowed");
            }
            drop(client);
            fixture.work.drain().await;
            fixture.finish().await?;
        }
        Ok(())
    })
}

async fn canceled_unavailable(directed: bool) -> TestResult {
    let (service, notice, release) = TestService::delayed(PresenceType::Unavailable);
    let mut fixture = fixture(service.clone()).await?;
    let mut session = session(&fixture).await?;
    handle(&mut session, "<presence/>").await?;
    handle(&mut session, "<presence to='room@echo.localhost/a'/>").await?;
    let observer = observer(&fixture).await?;
    handle(&mut session, "<presence to='alice@localhost/phone'/>").await?;
    assert_eq!(observer.take_queued().len(), 1);
    let request = parsed(if directed {
        "<presence type='unavailable' to='room@echo.localhost/a'/>"
    } else {
        "<presence type='unavailable'/>"
    })
    .await?;
    let mut operation = Box::pin(session.handle_stanza(request));
    entered(&mut operation, notice).await?;
    drop(operation);
    let mut ending = Box::pin(session.end());
    assert!(poll!(&mut ending).is_pending());
    let withdrawal = observer.recv().await.ok_or("missing local withdrawal")?;
    assert_eq!(
        withdrawal.stanza.resolve()?.stanza_type(),
        StanzaType::Presence(PresenceType::Unavailable)
    );
    assert!(poll!(&mut ending).is_pending());
    assert!(service.joined.load(Ordering::Relaxed));
    release.send(()).map_err(|_| "callback canceled")?;
    ending.await.map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        *service.events.lock(),
        [PresenceType::Available, PresenceType::Unavailable]
    );
    assert!(!service.joined.load(Ordering::Relaxed));
    drop(session);
    drop(observer);
    fixture.work.drain().await;
    fixture.finish().await
}

#[test]
fn canceled_directed_service_unavailable_remains_tracked_until_completion() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(
        Duration::from_secs(5),
        canceled_unavailable(true),
    ))?
}

#[test]
fn canceled_broadcast_service_unavailable_remains_tracked_until_completion() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(
        Duration::from_secs(5),
        canceled_unavailable(false),
    ))?
}

#[test]
fn delayed_service_available_finishes_before_terminal_withdrawal_and_replacement_join() -> TestResult
{
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let (service, notice, release) = TestService::delayed(PresenceType::Available);
        let mut fixture = fixture(service.clone()).await?;
        let mut old = session(&fixture).await?;
        handle(&mut old, "<presence/>").await?;
        let observer = observer(&fixture).await?;
        handle(&mut old, "<presence to='alice@localhost/phone'/>").await?;
        assert_eq!(observer.take_queued().len(), 1);
        let request = parsed("<presence to='room@echo.localhost/a'/>").await?;
        let mut operation = Box::pin(old.handle_stanza(request));
        entered(&mut operation, notice).await?;
        drop(operation);
        let mut ending = Box::pin(old.end());
        assert!(poll!(&mut ending).is_pending());
        let withdrawal = observer.recv().await.ok_or("missing local withdrawal")?;
        assert_eq!(
            withdrawal.stanza.resolve()?.stanza_type(),
            StanzaType::Presence(PresenceType::Unavailable)
        );
        let ((), mut later) = fixture
            .router
            .handle()
            .order()
            .fix(vec![fixture.registration.account().clone()], async {
                Ok::<_, RouterError>(())
            })
            .await?;
        later.turn().await;
        drop(later);
        assert!(poll!(&mut ending).is_pending());
        let mut replacement = session(&fixture).await?;
        let request = parsed("<presence to='room@echo.localhost/a'/>").await?;
        let mut joining = Box::pin(replacement.handle_stanza(request));
        assert!(poll!(&mut joining).is_pending());
        assert!(service.events.lock().is_empty());
        release
            .send(())
            .map_err(|_| "available callback canceled")?;
        let (ended, joined) = join(ending, joining).await;
        ended.map_err(|error| format!("{error:?}"))?;
        joined.map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            *service.events.lock(),
            [
                PresenceType::Available,
                PresenceType::Unavailable,
                PresenceType::Available
            ]
        );
        assert!(service.joined.load(Ordering::Relaxed));
        let mut arena = Arena::try_new(Default::default())?;
        let recipient = Jid::parse_in("room@echo.localhost/a", &mut arena)?.resolve(&arena)?;
        assert!(
            fixture
                .router
                .handle()
                .has_directed_grant(fixture.registration.account(), "desk", recipient,)
                .await?
        );
        replacement
            .end()
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert!(!service.joined.load(Ordering::Relaxed));
        drop(replacement);
        drop(old);
        drop(observer);
        fixture.work.drain().await;
        fixture.finish().await
    }))?
}

const COMPONENT_CONTACT: &str = "bot@echo.localhost";

async fn component_fixture(
    service: Arc<TestService>,
) -> TestResult<(Fixture, ComponentLink<GlobalChunkAllocator>)> {
    let config: crate::Config = toml::from_str(
        "[components.domains.'echo.localhost']\nsecret='component-test-secret-0001'",
    )?;
    let registry = ComponentRegistry::new(
        &config.components,
        credentials::load(&config.components)?,
        &config.limits.components,
        ComponentMetrics::new(1, 1),
    );
    let link = registry.attach("echo.localhost").map_err(|_| "attach")?;
    let route = ServiceRoute {
        domain: Arc::from("echo.localhost"),
        handler: service,
        component: Some(registry),
    };
    let fixture = fixture_with_route(route).await?;
    let mut arena = Arena::try_new(Default::default())?;
    let jid = Jid::parse_in(COMPONENT_CONTACT, &mut arena)?;
    let item = RosterItem {
        jid: RosterJid::from(jid.resolve(&arena)?),
        name: None,
        groups: Vec::new(),
        subscription: RosterSubscription {
            state: SubscriptionState::From,
            ..Default::default()
        },
    };
    let mut transaction = fixture.storage.begin_write().await?;
    transaction
        .put_roster_item(fixture.registration.account(), &item, Default::default())
        .await?;
    transaction.commit().await?;
    Ok((fixture, link))
}

fn assert_component_presence(
    link: &mut ComponentLink<GlobalChunkAllocator>,
    kind: PresenceType,
) -> TestResult {
    let stanza = link.try_next().ok_or("missing component presence")?;
    let view = stanza.resolve()?;
    assert_eq!(view.stanza_type(), StanzaType::Presence(kind));
    assert_eq!(view.from()?.ok_or("sender")?.as_str(), "bob@localhost/desk");
    assert_eq!(view.to()?.ok_or("recipient")?.as_str(), COMPONENT_CONTACT);
    Ok(())
}

async fn hold_directed_component_presence(
    old: &mut TestSession<'_>,
    observer: &Registration<GlobalChunkAllocator>,
    notice: oneshot::Receiver<()>,
) -> TestResult {
    handle(old, "<presence to='alice@localhost/phone'/>").await?;
    assert_eq!(observer.take_queued().len(), 1);
    let request = parsed("<presence to='bot@echo.localhost'/>").await?;
    let mut operation = Box::pin(old.handle_stanza(request));
    entered(&mut operation, notice).await
}

async fn wait_for_account_turn(fixture: &Fixture) -> TestResult {
    let ((), mut ticket) = fixture
        .router
        .handle()
        .order()
        .fix(vec![fixture.registration.account().clone()], async {
            Ok::<_, RouterError>(())
        })
        .await?;
    ticket.turn().await;
    Ok(())
}

async fn run_terminal_component_broadcast(replace: bool) -> TestResult {
    let (service, notice, release) = TestService::delayed(PresenceType::Available);
    let (mut fixture, mut link) = component_fixture(service.clone()).await?;
    let mut old = session(&fixture).await?;
    handle(&mut old, "<presence/>").await?;
    assert_component_presence(&mut link, PresenceType::Available)?;
    let observer = observer(&fixture).await?;
    hold_directed_component_presence(&mut old, &observer, notice).await?;
    let mut ending = Box::pin(old.end());
    assert!(poll!(&mut ending).is_pending());
    let local = observer.recv().await.ok_or("missing local withdrawal")?;
    assert_eq!(
        local.stanza.resolve()?.stanza_type(),
        StanzaType::Presence(PresenceType::Unavailable)
    );
    wait_for_account_turn(&fixture).await?;
    assert!(poll!(&mut ending).is_pending());
    assert!(link.try_next().is_none());
    if replace {
        let mut replacement = session(&fixture).await?;
        let request = parsed("<presence/>").await?;
        let mut joining = Box::pin(replacement.handle_stanza(request));
        assert!(poll!(&mut joining).is_pending());
        match select(joining.as_mut(), Box::pin(wait_for_account_turn(&fixture))).await {
            Either::Left(_) => {
                return Err("replacement published before the terminal broadcast".into());
            }
            Either::Right((result, _)) => result?,
        }
        assert!(link.try_next().is_none());
        release
            .send(())
            .map_err(|_| "available callback canceled")?;
        let (ended, joined) = join(ending, joining).await;
        ended.map_err(|error| format!("{error:?}"))?;
        joined.map_err(|error| format!("{error:?}"))?;
        assert_component_presence(&mut link, PresenceType::Unavailable)?;
        assert_component_presence(&mut link, PresenceType::Available)?;
        assert!(link.try_next().is_none());
        replacement
            .end()
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_component_presence(&mut link, PresenceType::Unavailable)?;
    } else {
        release
            .send(())
            .map_err(|_| "available callback canceled")?;
        ending.await.map_err(|error| format!("{error:?}"))?;
        assert_component_presence(&mut link, PresenceType::Unavailable)?;
    }
    assert!(link.try_next().is_none());
    assert_eq!(*service.events.lock(), [PresenceType::Available]);
    drop((old, observer, link));
    fixture.work.drain().await;
    fixture.finish().await
}

#[test]
fn terminal_component_broadcast_waits_for_in_flight_directed_service_presence() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(
        Duration::from_secs(5),
        run_terminal_component_broadcast(false),
    ))?
}

#[test]
fn replacement_roster_presence_waits_for_terminal_component_broadcast() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(
        Duration::from_secs(5),
        run_terminal_component_broadcast(true),
    ))?
}

#[test]
fn domain_lookup_ignores_at_signs_in_resourceparts() {
    for (jid, domain) in [
        ("echo.localhost", "echo.localhost"),
        ("echo.localhost/nick@other", "echo.localhost"),
        ("room@echo.localhost/nick@other", "echo.localhost"),
    ] {
        assert_eq!(domain_of(jid), domain);
    }
}

#[test]
fn subscriptions_to_extension_services_bypass_the_roster() -> TestResult {
    Runtime::new()?.block_on(async {
        let service = Arc::new(TestService::default());
        let mut fixture = fixture(service.clone()).await?;
        let mut session = session(&fixture).await?;
        for kind in ["subscribe", "subscribed", "unsubscribe", "unsubscribed"] {
            handle(
                &mut session,
                &format!("<presence type='{kind}' to='bot@echo.localhost/inbox' id='{kind}'/>"),
            )
            .await?;
        }
        let subscriptions = std::mem::take(&mut *service.subscriptions.lock());
        assert_eq!(subscriptions.len(), 4);
        for (stanza, kind) in subscriptions.iter().zip([
            PresenceType::Subscribe,
            PresenceType::Subscribed,
            PresenceType::Unsubscribe,
            PresenceType::Unsubscribed,
        ]) {
            let stanza = stanza.resolve()?;
            assert_eq!(stanza.stanza_type(), StanzaType::Presence(kind));
            assert_eq!(stanza.id()?, stanza.stanza_type().as_str());
            assert_eq!(
                stanza.from()?.ok_or("sender")?.as_str(),
                "bob@localhost/desk"
            );
            assert_eq!(
                stanza.to()?.ok_or("target")?.as_str(),
                "bot@echo.localhost/inbox"
            );
        }
        let owner = fixture.registration.account();
        let read = fixture.storage.begin_read().await?;
        let roster = read.roster(owner, Default::default()).await?;
        assert!(roster.items.is_empty());
        assert_eq!(roster.version.get(), 0);
        assert!(read.pending_requests(owner).await?.is_empty());
        drop(read);
        drop(session);
        fixture.work.drain().await;
        fixture.finish().await
    })
}
