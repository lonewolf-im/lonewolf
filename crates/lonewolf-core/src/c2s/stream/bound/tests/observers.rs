// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use lonewolf_extension::delivery::{Delivery, DeliveryError, DeliveryFuture, SessionId};
use lonewolf_extension::observer::MessageObserver;
use lonewolf_extension::service::{ServiceContext, ServiceHandler};
use lonewolf_extension::{Extension, ExtensionFuture, Extensions, RegistrationError, Slots};

use super::*;
use crate::router::ServiceRoute;

#[derive(Debug, Eq, PartialEq)]
struct RecordedEvent {
    account: String,
    role: MessageRole,
    outcome: MessageOutcome,
    holders: Vec<SessionId>,
    rejection: Option<String>,
}

#[derive(Default)]
struct Recorder(PlMutex<Vec<RecordedEvent>>);

impl Extension<GlobalChunkAllocator, RedbStorage> for Recorder {
    fn name(&self) -> &'static str {
        "recording"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.message_observer(self);
        Ok(())
    }
}

impl MessageObserver<GlobalChunkAllocator, RedbStorage> for Recorder {
    fn observe<'a>(
        &'a self,
        event: MessageEvent<'a, GlobalChunkAllocator>,
        _: &'a RedbStorage,
        _: &'a dyn Delivery<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        Box::pin(async move {
            let rejection = if let Some(reply) = event.rejection {
                let mut xml = String::new();
                reply
                    .resolve()?
                    .write_xml(&mut xml)
                    .map_err(|_| DeliveryError)?;
                Some(xml)
            } else {
                None
            };
            self.0.lock().push(RecordedEvent {
                account: event.account.as_str().into(),
                role: event.role,
                outcome: event.outcome,
                holders: event.holders.to_vec(),
                rejection,
            });
            Ok(())
        })
    }
}

struct TestService {
    reply: Option<RoutedStanza<GlobalChunkAllocator>>,
}

struct GatedService {
    accepted: PlMutex<Option<oneshot::Sender<RoutedStanza<GlobalChunkAllocator>>>>,
    release: PlMutex<Option<oneshot::Receiver<()>>>,
    reply: RoutedStanza<GlobalChunkAllocator>,
}

impl ServiceHandler<GlobalChunkAllocator, RedbStorage> for GatedService {
    fn route<'a>(
        &'a self,
        stanza: RoutedStanza<GlobalChunkAllocator>,
        context: ServiceContext<'a, GlobalChunkAllocator, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        let accepted = self.accepted.lock().take();
        let release = self.release.lock().take();
        Box::pin(async move {
            accepted
                .ok_or(StanzaErrorCondition::InternalServerError)?
                .send(stanza)
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            release
                .ok_or(StanzaErrorCondition::InternalServerError)?
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            context
                .outbound
                .route(self.reply.clone())
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            Ok(())
        })
    }
}

impl ServiceHandler<GlobalChunkAllocator, RedbStorage> for TestService {
    fn route<'a>(
        &'a self,
        stanza: RoutedStanza<GlobalChunkAllocator>,
        context: ServiceContext<'a, GlobalChunkAllocator, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            if stanza
                .resolve()
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .id()
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                == Some("reject")
            {
                return Err(HandlerError::described(
                    StanzaErrorCondition::BadRequest,
                    lonewolf_xmpp::stanza::StanzaErrorText::Static("Unsupported service message."),
                ));
            }
            if let Some(reply) = &self.reply {
                context
                    .outbound
                    .route(reply.clone())
                    .await
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            }
            Ok(())
        })
    }
}

async fn fixture(offline: bool) -> TestResult<(Fixture, Arc<Recorder>)> {
    let mut fixture = Fixture::new(&[]).await?;
    let recorder = Arc::new(Recorder::default());
    let mut extensions = Extensions::default();
    extensions.register(recorder.clone())?;
    let enabled = if offline {
        extensions.register(Arc::new(Offline::new(Default::default())))?;
        &["recording", "offline"][..]
    } else {
        &["recording"][..]
    };
    fixture.router = fixture.router.with_extensions(BTreeMap::from([(
        "localhost".into(),
        extensions.enable_host("localhost", enabled.iter().copied())?,
    )]));
    let mut arena = Arena::try_new(Default::default())?;
    let alice =
        AccountKey::try_from(Jid::parse_in("alice@localhost", &mut arena)?.resolve(&arena)?)?;
    let mut transaction = fixture.storage.begin_write().await?;
    transaction
        .create_account(NewAccount {
            key: alice,
            credentials: credentials(),
        })
        .await?;
    transaction.commit().await?;
    Ok((fixture, recorder))
}

async fn register(
    fixture: &Fixture,
    owner: &str,
    resource: &str,
) -> TestResult<Registration<GlobalChunkAllocator>> {
    let mut arena = Arena::try_new(Default::default())?;
    let owner = AccountKey::try_from(Jid::parse_in(owner, &mut arena)?.resolve(&arena)?)?;
    Ok(fixture
        .router
        .handle()
        .register(
            &owner,
            Some(resource),
            NonZeroUsize::new(4).ok_or("resource limit")?,
        )
        .await?)
}

fn bound<'a>(
    fixture: &'a Fixture,
    registration: Registration<GlobalChunkAllocator>,
) -> TestResult<BoundSession<'a, GlobalChunkAllocator, ControlledWriter>> {
    let (_, incoming) = async_channel::bounded(1);
    let mut session = fixture.bound_session(
        GlobalChunkAllocator,
        registration,
        fixture.router.handle(),
        incoming,
    )?;
    session.outbox.account = session.registration.account().clone();
    Ok(session)
}

async fn parsed(xml: &str) -> TestResult<Parsed<Stanza, GlobalChunkAllocator>> {
    let input = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>{xml}"
    );
    let mut parser = XmppParser::new(
        input.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4096).ok_or("stanza limit")?,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    );
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    match parser.next_event().await? {
        Some(StreamEvent::Stanza(stanza)) => Ok(stanza),
        _ => Err("expected stanza".into()),
    }
}

async fn presence(registration: &Registration<GlobalChunkAllocator>, priority: i8) -> TestResult {
    let xml = format!("<presence from='{}'/>", registration.full_jid());
    registration
        .handle()
        .set_presence(
            Some(priority),
            RoutedStanza::from_parsed(parsed(&xml).await?),
            None,
        )
        .await?;
    Ok(())
}

fn event(
    account: &str,
    role: MessageRole,
    outcome: MessageOutcome,
    holders: &[SessionId],
) -> RecordedEvent {
    RecordedEvent {
        account: account.into(),
        role,
        outcome,
        holders: holders.to_vec(),
        rejection: None,
    }
}

#[test]
fn sent_events_hold_only_the_sending_session() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let (fixture, recorder) = fixture(false).await?;
        presence(&fixture.registration, 0).await?;
        let desk = register(&fixture, "alice@localhost", "desk").await?;
        let sender = desk.session_id();
        let recipient = fixture.registration.session_id();
        let mut session = bound(&fixture, desk)?;
        session
            .handle_stanza(parsed("<message to='bob@localhost' type='chat'/>").await?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            *recorder.0.lock(),
            [
                event(
                    "alice@localhost",
                    MessageRole::Sent,
                    MessageOutcome::Routed,
                    &[sender]
                ),
                event(
                    "bob@localhost",
                    MessageRole::Received,
                    MessageOutcome::Routed,
                    &[recipient]
                ),
            ]
        );
        assert_eq!(fixture.registration.take_queued().len(), 1);
        drop(session);
        fixture.finish().await
    }))?
}

#[test]
fn received_events_hold_the_bare_message_recipient() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let (fixture, recorder) = fixture(false).await?;
        let laptop = register(&fixture, "bob@localhost", "laptop").await?;
        presence(&laptop, 1).await?;
        presence(&fixture.registration, 5).await?;
        fixture.registration.take_queued();
        laptop.take_queued();
        let desk = register(&fixture, "alice@localhost", "desk").await?;
        let sender = desk.session_id();
        let phone = fixture.registration.session_id();
        let mut session = bound(&fixture, desk)?;
        session
            .handle_stanza(parsed("<message to='bob@localhost' type='chat'/>").await?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            *recorder.0.lock(),
            [
                event(
                    "alice@localhost",
                    MessageRole::Sent,
                    MessageOutcome::Routed,
                    &[sender]
                ),
                event(
                    "bob@localhost",
                    MessageRole::Received,
                    MessageOutcome::Routed,
                    &[phone]
                ),
            ]
        );
        assert_eq!(fixture.registration.take_queued().len(), 1);
        assert!(laptop.take_queued().is_empty());
        drop((session, laptop));
        fixture.finish().await
    }))?
}

#[test]
fn same_account_events_hold_the_sender_and_the_recipient() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let (fixture, recorder) = fixture(false).await?;
        let desk = register(&fixture, "alice@localhost", "desk").await?;
        let phone = register(&fixture, "alice@localhost", "phone").await?;
        presence(&phone, 5).await?;
        let holders = [desk.session_id(), phone.session_id()];
        let mut session = bound(&fixture, desk)?;
        session
            .handle_stanza(parsed("<message to='alice@localhost' type='chat'/>").await?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            *recorder.0.lock(),
            [
                event(
                    "alice@localhost",
                    MessageRole::Sent,
                    MessageOutcome::Routed,
                    &holders
                ),
                event(
                    "alice@localhost",
                    MessageRole::Received,
                    MessageOutcome::Routed,
                    &holders
                ),
            ]
        );
        assert_eq!(phone.take_queued().len(), 1);
        drop((session, phone));
        fixture.finish().await
    }))?
}

#[test]
fn stored_events_hold_no_session() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let (fixture, recorder) = fixture(true).await?;
        let desk = register(&fixture, "alice@localhost", "desk").await?;
        let sender = desk.session_id();
        let mut session = bound(&fixture, desk)?;
        session
            .handle_stanza(parsed("<message to='bob@localhost' type='chat'/>").await?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            *recorder.0.lock(),
            [
                event(
                    "alice@localhost",
                    MessageRole::Sent,
                    MessageOutcome::Stored,
                    &[sender]
                ),
                event(
                    "bob@localhost",
                    MessageRole::Received,
                    MessageOutcome::Stored,
                    &[]
                ),
            ]
        );
        assert_eq!(fixture.count().await?, 1);
        assert!(fixture.registration.take_queued().is_empty());
        drop(session);
        fixture.finish().await
    }))?
}

#[test]
fn rejected_sent_events_carry_the_queued_error() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let (fixture, recorder) = fixture(false).await?;
        let desk = register(&fixture, "alice@localhost", "desk").await?;
        let sender = desk.session_id();
        let mut session = bound(&fixture, desk)?;
        session.handle_stanza(parsed(
            "<message to='bob@localhost/absent' type='normal' id='rejected'><body>payload</body></message>"
        ).await?).await.map_err(|error| format!("{error:?}"))?;
        session.outbox.flush().await.map_err(|error| format!("{error:?}"))?;
        let written = &session.outbox.writer.written;
        assert_eq!(written.len(), 1);
        assert_eq!(*recorder.0.lock(), [RecordedEvent {
            rejection: Some(written[0].clone()),
            ..event("alice@localhost", MessageRole::Sent, MessageOutcome::Rejected, &[sender])
        }]);
        assert!(written[0].contains("type=\"error\""));
        let reply = parsed(&written[0]).await?;
        let body = reply.value().resolve(reply.arena())?.children()?.next().transpose()?
            .ok_or("missing rejection payload")?;
        assert_eq!((body.name(), body.namespace()), ("body", CLIENT_NAMESPACE));
        assert_eq!(body.text()?, Some("payload"));
        assert!(written[0].contains("service-unavailable"));
        assert!(fixture.registration.take_queued().is_empty());
        drop(session);
        fixture.finish().await
    }))?
}

#[test]
fn service_work_and_callback_progress_during_a_separate_client_flush() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        use lonewolf_extension::blocking::{Blocking, NAME};

        let (mut fixture, recorder) = fixture(false).await?;
        let mut extensions = Extensions::default();
        extensions.register(Arc::new(Blocking))?;
        extensions.register(recorder.clone())?;
        let (accepted, admitted) = oneshot::channel();
        let (resume_handler, release) = oneshot::channel();
        let reply = RoutedStanza::from_parsed(
            parsed("<message type='chat' from='echo.localhost' to='alice@localhost/phone' id='callback'/>").await?,
        );
        let service = Arc::new(GatedService {
            accepted: PlMutex::new(Some(accepted)),
            release: PlMutex::new(Some(release)),
            reply,
        });
        fixture.router = fixture.router.with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", [NAME, "recording"])?,
        )])).with_services(BTreeMap::from([(
            "echo.localhost".into(),
            ServiceRoute::extension(Arc::from("echo.localhost"), service),
        )]));
        let desk = register(&fixture, "alice@localhost", "desk").await?;
        let phone = register(&fixture, "alice@localhost", "phone").await?;
        let account = desk.account().clone();
        let mut session = bound(&fixture, desk)?;
        let (flushing, flushing_started) = oneshot::channel();
        let (finish_flush, flush_release) = oneshot::channel();
        session.outbox.writer.flush_entered = Some(flushing);
        session.outbox.writer.flush_release = Some(flush_release);
        let router = fixture.router.handle();
        let ((), preceding) = router.order().fix(vec![account], async { Ok::<_, RouterError>(()) }).await?;
        router.route_full(RoutedStanza::from_parsed(parsed(
            "<message from='bob@localhost/desk' to='alice@localhost/desk' id='already-queued'/>",
        ).await?)).await?;
        let request = parsed("<message type='chat' to='echo.localhost' id='request'/>").await?;
        {
            let mut dispatch = pin!(session.handle_stanza(request));
            match select(flushing_started, dispatch.as_mut()).await {
                Either::Left((entered, _)) => entered?,
                Either::Right(_) => return Err("the scheduled delivery did not start".into()),
            }
            drop(preceding);
            let accepted = match select(admitted, dispatch.as_mut()).await {
                Either::Left((admitted, _)) => admitted?,
                Either::Right(_) => return Err("service work did not start".into()),
            };
            let view = accepted.resolve()?;
            assert_eq!(view.from()?.ok_or("stamped sender")?.as_str(), "alice@localhost/desk");
            assert_eq!(view.to()?.ok_or("service destination")?.as_str(), "echo.localhost");
            assert_eq!(view.id()?, Some("request"));
            resume_handler.send(()).map_err(|_| "service stopped")?;
            let delivered = phone.recv().await.ok_or("service callback")?;
            assert_eq!(delivered.stanza.resolve()?.id()?, Some("callback"));
            finish_flush.send(()).map_err(|_| "writer stopped")?;
            dispatch.await.map_err(|error| format!("{error:?}"))?;
        }
        assert_eq!(session.outbox.writer.written.len(), 1);
        assert!(recorder.0.lock().iter().any(|event| event.role == MessageRole::Sent
            && event.outcome == MessageOutcome::Forwarded && event.account == "alice@localhost"));
        drop((phone, session));
        fixture.finish().await
    }))?
}

#[test]
fn service_events_report_holders_and_rejections() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let (mut fixture, recorder) = fixture(false).await?;
        fixture.router = fixture.router.with_services(BTreeMap::from([(
            "echo.localhost".into(),
            ServiceRoute::extension(
                Arc::from("echo.localhost"),
                Arc::new(TestService { reply: None }),
            ),
        )]));
        let desk = register(&fixture, "alice@localhost", "desk").await?;
        let sender = desk.session_id();
        let mut session = bound(&fixture, desk)?;
        session
            .handle_stanza(
                parsed("<message to='echo.localhost' type='chat' id='accepted'/>").await?,
            )
            .await
            .map_err(|error| format!("{error:?}"))?;
        session
            .handle_stanza(parsed("<message to='echo.localhost' type='chat' id='reject'/>").await?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        session
            .outbox
            .flush()
            .await
            .map_err(|error| format!("{error:?}"))?;
        let written = &session.outbox.writer.written;
        assert_eq!(written.len(), 1);
        assert_eq!(
            *recorder.0.lock(),
            [
                event(
                    "alice@localhost",
                    MessageRole::Sent,
                    MessageOutcome::Forwarded,
                    &[sender]
                ),
                RecordedEvent {
                    rejection: Some(written[0].clone()),
                    ..event(
                        "alice@localhost",
                        MessageRole::Sent,
                        MessageOutcome::Rejected,
                        &[sender]
                    )
                },
            ]
        );
        assert!(written[0].contains("bad-request"));
        assert!(written[0].contains("Unsupported service message."));
        drop(session);
        fixture.finish().await
    }))?
}

#[test]
fn service_received_events_hold_the_admitted_session() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let (mut fixture, recorder) = fixture(false).await?;
        let reply = RoutedStanza::from_parsed(
            parsed("<message from='echo.localhost' to='bob@localhost/phone' type='chat'/>").await?,
        );
        fixture.router = fixture.router.with_services(BTreeMap::from([(
            "echo.localhost".into(),
            ServiceRoute::extension(
                Arc::from("echo.localhost"),
                Arc::new(TestService { reply: Some(reply) }),
            ),
        )]));
        let desk = register(&fixture, "alice@localhost", "desk").await?;
        let sender = desk.session_id();
        let recipient = fixture.registration.session_id();
        let mut session = bound(&fixture, desk)?;
        session
            .handle_stanza(parsed("<message to='echo.localhost' type='chat'/>").await?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            *recorder.0.lock(),
            [
                event(
                    "bob@localhost",
                    MessageRole::Received,
                    MessageOutcome::Routed,
                    &[recipient]
                ),
                event(
                    "alice@localhost",
                    MessageRole::Sent,
                    MessageOutcome::Forwarded,
                    &[sender]
                ),
            ]
        );
        assert_eq!(fixture.registration.take_queued().len(), 1);
        drop(session);
        fixture.finish().await
    }))?
}
