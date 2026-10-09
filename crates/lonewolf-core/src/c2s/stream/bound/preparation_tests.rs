// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use compio::runtime::Runtime;
use futures_channel::oneshot;
use futures_util::poll;
use lonewolf_extension::delivery::{FailureKind, HostLookup};
use lonewolf_extension::iq::IqFuture;
use lonewolf_extension::message::StoreFuture;
use lonewolf_extension::presence::{PresenceFuture, PresenceHandler};
use lonewolf_extension::{Effects, Extension, Extensions};
use lonewolf_storage::offline::{OfflineReads, OfflineWrites};
use lonewolf_util::arena::GlobalChunkAllocator;
use parking_lot::Mutex as PlMutex;

use super::tests::{ControlledWriter, Fixture, routed_presence};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type TestSession<'a> = BoundSession<'a, GlobalChunkAllocator, ControlledWriter>;

#[derive(Clone, Copy)]
enum Outcome {
    Commit,
    Reject,
    Discard,
}

#[derive(Clone, Copy)]
enum Workflow {
    Iq,
    Offline,
    Subscription,
}

struct Gate {
    entered: PlMutex<Option<oneshot::Sender<()>>>,
    release: PlMutex<Option<oneshot::Receiver<()>>>,
    completed: AtomicBool,
    outcome: Outcome,
    acknowledged: PlMutex<Option<oneshot::Sender<()>>>,
}

impl Gate {
    fn new(outcome: Outcome) -> (Arc<Self>, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (notice, entered) = oneshot::channel();
        let (release, blocked) = oneshot::channel();
        (
            Arc::new(Self {
                entered: PlMutex::new(Some(notice)),
                release: PlMutex::new(Some(blocked)),
                completed: AtomicBool::new(false),
                outcome,
                acknowledged: PlMutex::new(None),
            }),
            entered,
            release,
        )
    }

    async fn wait(&self) {
        let entered = self.entered.lock().take();
        let release = self.release.lock().take();
        if let Some(entered) = entered {
            let _ = entered.send(());
        }
        if let Some(release) = release {
            let _ = release.await;
        }
        self.completed.store(true, Ordering::Release);
    }

    fn error(operation: &'static str) -> HandlerError {
        HandlerError::Internal {
            condition: StanzaErrorCondition::InternalServerError,
            failure: Failure {
                kind: FailureKind::Storage(lonewolf_storage::StorageErrorKind::Unavailable),
                operation,
            },
        }
    }

    async fn stage(
        &self,
        transaction: &mut RedbWrite,
        account: &AccountKey,
    ) -> Result<OfflineSequence, HandlerError> {
        let sequence = transaction
            .push_offline_message(
                account,
                0,
                b"<message xmlns='jabber:client' type='chat' id='staged'/>",
            )
            .await
            .map_err(|_| Self::error("offline_push"))?;
        self.wait().await;
        Ok(sequence)
    }
}

impl Extension<GlobalChunkAllocator, RedbStorage> for Gate {
    fn name(&self) -> &'static str {
        "controlled-preparation"
    }
    fn presence_kinds(&self) -> &'static [PresenceRequestType] {
        &[
            PresenceRequestType::Subscribe,
            PresenceRequestType::Available,
        ]
    }
    fn stores_messages(&self) -> bool {
        true
    }
}

impl IqHandler<GlobalChunkAllocator, RedbStorage> for Gate {
    fn get<'a>(
        &'a self,
        _: IqRequest<'a, GlobalChunkAllocator>,
        _: &'a RedbRead,
        _: &'a mut Arena<GlobalChunkAllocator>,
    ) -> IqFuture<'a, GlobalChunkAllocator> {
        Box::pin(async move {
            self.completed.store(true, Ordering::Release);
            Ok(IqReply::new(None, Effects::none()))
        })
    }
    fn set<'a>(
        &'a self,
        request: IqRequest<'a, GlobalChunkAllocator>,
        transaction: &'a mut RedbWrite,
        _: &'a dyn HostLookup,
        _: &'a mut Arena<GlobalChunkAllocator>,
    ) -> IqFuture<'a, GlobalChunkAllocator> {
        Box::pin(async move {
            let account = AccountKey::try_from(request.target.bare())
                .map_err(|_| Self::error("roster_write"))?;
            self.stage(transaction, &account).await?;
            match self.outcome {
                Outcome::Commit => Ok(IqReply::new(
                    None,
                    Effects::new(vec![account], |_| Box::pin(async { Ok(()) })),
                )),
                _ => Err(Self::error("roster_write")),
            }
        })
    }
}

impl MessageHandler<GlobalChunkAllocator, RedbStorage> for Gate {
    fn store<'a>(
        &'a self,
        message: UndeliverableMessage<'a, GlobalChunkAllocator>,
        transaction: &'a mut RedbWrite,
        _: &'a mut Arena<GlobalChunkAllocator>,
    ) -> StoreFuture<'a> {
        Box::pin(async move {
            let sequence = self.stage(transaction, message.recipient).await?;
            match self.outcome {
                Outcome::Commit => Ok(StoreOutcome::Stored(sequence)),
                Outcome::Discard => Ok(StoreOutcome::Discarded),
                Outcome::Reject => Err(Self::error("offline_push")),
            }
        })
    }
    fn backlog<'a>(
        &'a self,
        account: &'a AccountKey,
        transaction: &'a RedbRead,
    ) -> PresenceFuture<'a, Option<Backlog>> {
        Box::pin(async move {
            let messages = transaction
                .offline_messages(account)
                .await
                .map_err(|_| Self::error("offline_backlog"))?;
            let through = messages.last().map(|last| last.sequence);
            Ok(through.map(|through| Backlog { through, messages }))
        })
    }
    fn acknowledge<'a>(
        &'a self,
        account: &'a AccountKey,
        through: OfflineSequence,
        transaction: &'a mut RedbWrite,
    ) -> lonewolf_extension::ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            <lonewolf_extension::offline::Offline as MessageHandler<
                GlobalChunkAllocator,
                RedbStorage,
            >>::acknowledge(
                &lonewolf_extension::offline::Offline::new(Default::default()),
                account,
                through,
                transaction,
            )
            .await?;
            if let Some(notice) = self.acknowledged.lock().take() {
                let _ = notice.send(());
            }
            Ok(())
        })
    }
}

impl PresenceHandler<GlobalChunkAllocator, RedbStorage> for Gate {
    fn receive<'a>(
        &'a self,
        request: PresenceRequest<'a, GlobalChunkAllocator>,
        transaction: &'a mut RedbWrite,
        _: &'a dyn HostLookup,
    ) -> PresenceFuture<'a, Effects<GlobalChunkAllocator>> {
        Box::pin(async move {
            let account = AccountKey::try_from(request.target.bare())
                .map_err(|_| Self::error("roster_write"))?;
            self.stage(transaction, &account).await?;
            match self.outcome {
                Outcome::Commit => Ok(Effects::new(vec![account], |_| Box::pin(async { Ok(()) }))),
                _ => Err(Self::error("roster_write")),
            }
        })
    }
    fn audience<'a>(
        &'a self,
        _: PresenceUpdate<'a>,
        _: &'a RedbRead,
    ) -> PresenceFuture<'a, Option<PresenceAudience>> {
        Box::pin(async move {
            self.wait().await;
            Ok(None)
        })
    }
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
        _ => Err("missing test stanza".into()),
    }
}

async fn session<'a>(
    fixture: &'a Fixture,
    partial: bool,
) -> TestResult<(TestSession<'a>, oneshot::Receiver<()>, oneshot::Sender<()>)> {
    let registration = fixture
        .router
        .handle()
        .register(
            fixture.registration.account(),
            Some("preparing"),
            NonZeroUsize::new(2).ok_or("zero limit")?,
        )
        .await?;
    let (notice, entered) = oneshot::channel();
    let (release, blocked) = oneshot::channel();
    let mut writer = ControlledWriter::default();
    if partial {
        writer.partial_entered = Some(notice);
        writer.partial_release = Some(blocked);
    } else {
        writer.flush_entered = Some(notice);
        writer.flush_release = Some(blocked);
    }
    let mut outbox = fixture.outbox(GlobalChunkAllocator, writer);
    outbox.liveness = registration.liveness();
    Ok((
        BoundSession {
            registration,
            router: fixture.router.handle(),
            storage: fixture.storage.clone(),
            allocator: GlobalChunkAllocator,
            available: false,
            priority: None,
            incoming: async_channel::bounded(1).1,
            outbox,
        },
        entered,
        release,
    ))
}

fn enable(mut fixture: Fixture, gate: &Arc<Gate>) -> TestResult<Fixture> {
    let mut catalog = Extensions::default();
    catalog.register(gate.clone())?;
    fixture.router = fixture
        .router
        .with_extensions(std::collections::BTreeMap::from([(
            "localhost".into(),
            catalog.enable(["controlled-preparation"])?,
        )]));
    Ok(fixture)
}

async fn drive<F, G>(operation: Pin<&mut F>, checkpoint: G) -> TestResult<G::Output>
where
    F: Future<Output = Result<(), CloseOutcome>>,
    G: Future,
{
    match compio::time::timeout(Duration::from_secs(5), select(operation, pin!(checkpoint))).await?
    {
        Either::Left((result, _)) => Err(format!(
            "operation completed before blocked output was released: {result:?}"
        )
        .into()),
        Either::Right((result, _)) => Ok(result),
    }
}

async fn queue_delivery(fixture: &Fixture) -> TestResult {
    fixture
        .router
        .handle()
        .route_full(routed_presence(
            "alice@localhost/desk",
            Some("bob@localhost/preparing"),
            PresenceType::Available,
        )?)
        .await?;
    Ok(())
}

#[test]
fn guarded_preparations_release_writer_before_blocked_output_resumes() -> TestResult {
    Runtime::new()?.block_on(async {
        for (workflow, outcome) in [(Workflow::Iq, Outcome::Commit), (Workflow::Iq, Outcome::Reject), (Workflow::Offline, Outcome::Commit), (Workflow::Offline, Outcome::Reject), (Workflow::Offline, Outcome::Discard), (Workflow::Subscription, Outcome::Commit), (Workflow::Subscription, Outcome::Reject)] {
            let capture = crate::delivery::failure_tests::Capture::default();
            let _subscriber = tracing::subscriber::set_default(capture.clone());
            let fixture = Fixture::new(&[]).await?;
            let (gate, entered, release) = Gate::new(outcome);
            let fixture = enable(fixture, &gate)?;
            let (mut session, output_entered, output_release) = session(&fixture, matches!(workflow, Workflow::Iq) && matches!(outcome, Outcome::Commit)).await?;
            let request = parsed(match workflow { Workflow::Iq => "<iq type='set' id='reply'><query xmlns='urn:test:iq'/></iq>", Workflow::Offline => "<message from='bob@localhost/preparing' to='bob@localhost' type='chat' id='store'/>", Workflow::Subscription => "<presence to='bob@localhost' type='subscribe' id='subscription'/>" }).await?;
            let mut operation = Box::pin(async {
                match workflow {
                    Workflow::Iq => {
                        let (request, mut arena) = request.into_parts();
                        let sender = Jid::parse_in("bob@localhost/preparing", &mut arena)?;
                        session.handle_iq_set(request, sender, arena, Arena::try_new(Default::default())?, gate.clone()).await
                    }
                    Workflow::Offline => { let (stanza, arena) = request.into_parts(); session.store_message(RoutedStanza::from_parts(stanza, arena)).await }
                    Workflow::Subscription => session.handle_subscription(request, PresenceRequestType::Subscribe).await,
                }
            });
            drive(operation.as_mut(), entered).await??;
            queue_delivery(&fixture).await?;
            drive(operation.as_mut(), output_entered).await??;
            release.send(()).map_err(|_| "preparation cancelled")?;
            drop(drive(operation.as_mut(), fixture.storage.begin_write()).await??);
            assert!(gate.completed.load(Ordering::Acquire));
            assert_eq!(fixture.count().await?, usize::from(matches!(outcome, Outcome::Commit)));
            if matches!(outcome, Outcome::Reject) {
                capture.assert_one(FailureKind::Storage(lonewolf_storage::StorageErrorKind::Unavailable), if matches!(workflow, Workflow::Offline) { "offline_push" } else { "roster_write" });
            }
            output_release.send(()).map_err(|_| "active output was replaced")?;
            operation.await.map_err(|e| format!("{e:?}"))?;
            session.outbox.flush().await.map_err(|e| format!("{e:?}"))?;
            assert_eq!(session.outbox.writer.bytes, session.outbox.writer.written.concat());
            assert_eq!(session.outbox.writer.written.len(), if matches!(workflow, Workflow::Iq) || matches!(outcome, Outcome::Reject) { 2 } else { 1 });
            assert!(session.outbox.writer.written[0].contains("alice@localhost/desk"));
            if matches!(outcome, Outcome::Reject) {
                capture.assert_one(FailureKind::Storage(lonewolf_storage::StorageErrorKind::Unavailable), if matches!(workflow, Workflow::Offline) { "offline_push" } else { "roster_write" });
            }
            drop(session);
            fixture.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn availability_handoff_releases_ticket_before_blocked_output_and_preserves_replay_order()
-> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[
            b"<message xmlns='jabber:client' to='bob@localhost' type='chat' id='replay'/>",
        ])
        .await?;
        let (gate, entered, release) = Gate::new(Outcome::Commit);
        let (acknowledged, acknowledgement) = oneshot::channel();
        *gate.acknowledged.lock() = Some(acknowledged);
        let fixture = enable(fixture, &gate)?;
        let (mut session, output_entered, output_release) = session(&fixture, true).await?;
        let request = parsed("<presence id='echo'/>").await?;
        let mut operation = Box::pin(session.handle_availability(request, true));
        drive(operation.as_mut(), entered).await??;
        queue_delivery(&fixture).await?;
        drive(operation.as_mut(), output_entered).await??;
        release.send(()).map_err(|_| "preparation cancelled")?;
        let router = fixture.router.handle();
        drive(operation.as_mut(), async {
            let ((), mut ticket) = router
                .order()
                .fix(vec![fixture.registration.account().clone()], async {
                    Ok::<_, RouterError>(())
                })
                .await?;
            ticket.turn().await;
            Ok::<_, RouterError>(())
        })
        .await??;
        assert!(gate.completed.load(Ordering::Acquire));
        assert_eq!(fixture.count().await?, 1);
        output_release
            .send(())
            .map_err(|_| "partial output was replaced")?;
        operation.await.map_err(|e| format!("{e:?}"))?;
        session.outbox.flush().await.map_err(|e| format!("{e:?}"))?;
        assert_eq!(session.outbox.writer.written.len(), 3);
        assert!(session.outbox.writer.written[0].contains("alice@localhost/desk"));
        assert!(session.outbox.writer.written[1].contains("id=\"echo\""));
        assert!(session.outbox.writer.written[2].contains("id=\"replay\""));
        assert_eq!(
            session.outbox.writer.bytes,
            session.outbox.writer.written.concat()
        );
        compio::time::timeout(Duration::from_secs(5), acknowledgement).await??;
        drop(fixture.storage.begin_write().await?);
        assert_eq!(fixture.count().await?, 0);
        drop(session);
        fixture.finish().await
    })
}

#[test]
fn cancellation_during_blocked_output_obeys_the_precommit_handoff_boundary() -> TestResult {
    Runtime::new()?.block_on(async {
        for handoff in [false, true] {
            let fixture = Fixture::new(&[]).await?;
            let (gate, entered, release) = Gate::new(Outcome::Commit);
            let (mut session, output_entered, output_release) = session(&fixture, false).await?;
            let (request, mut arena) =
                parsed("<iq type='set' id='cancelled'><query xmlns='urn:test:iq'/></iq>")
                    .await?
                    .into_parts();
            let sender = Jid::parse_in("bob@localhost/preparing", &mut arena)?;
            let mut operation = Box::pin(session.handle_iq_set(
                request,
                sender,
                arena,
                Arena::try_new(Default::default())?,
                gate.clone(),
            ));
            drive(operation.as_mut(), entered).await??;
            queue_delivery(&fixture).await?;
            drive(operation.as_mut(), output_entered).await??;
            if handoff {
                release.send(()).map_err(|_| "preparation cancelled")?;
                drop(drive(operation.as_mut(), fixture.storage.begin_write()).await??);
                drop(operation);
            } else {
                drop(operation);
                assert!(release.send(()).is_err());
                assert!(!gate.completed.load(Ordering::Acquire));
            }
            assert!(output_release.send(()).is_err());
            drop(fixture.storage.begin_write().await?);
            assert_eq!(fixture.count().await?, usize::from(handoff));
            assert!(session.outbox.queue.is_empty());
            drop(session);
            fixture.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn iq_snapshot_handoff_and_global_fixing_progress_while_output_is_blocked() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let (gate, _, _) = Gate::new(Outcome::Commit);
        let router = fixture.router.handle();
        let (release_fix, blocked_fix) = oneshot::channel();
        let mut fixing = Box::pin(router.order().fix(Vec::new(), async {
            blocked_fix.await.map_err(|_| RouterError::Stopped)
        }));
        assert!(poll!(fixing.as_mut()).is_pending());
        let (mut session, output_entered, output_release) = session(&fixture, false).await?;
        let (request, mut arena) =
            parsed("<iq type='get' id='snapshot'><query xmlns='urn:test:iq'/></iq>")
                .await?
                .into_parts();
        let sender = Jid::parse_in("bob@localhost/preparing", &mut arena)?;
        let mut operation = Box::pin(session.handle_iq_get(
            request,
            sender,
            arena,
            Arena::try_new(Default::default())?,
            gate.clone(),
            vec![fixture.registration.account().clone()],
        ));
        queue_delivery(&fixture).await?;
        drive(operation.as_mut(), output_entered).await??;
        release_fix.send(()).map_err(|_| "fix cancelled")?;
        drop(fixing.await?);
        drive(operation.as_mut(), async {
            let ((), mut ticket) = router
                .order()
                .fix(vec![fixture.registration.account().clone()], async {
                    Ok::<_, RouterError>(())
                })
                .await?;
            ticket.turn().await;
            Ok::<_, RouterError>(())
        })
        .await??;
        assert!(gate.completed.load(Ordering::Acquire));
        output_release.send(()).map_err(|_| "flush cancelled")?;
        operation.await.map_err(|e| format!("{e:?}"))?;
        session.outbox.flush().await.map_err(|e| format!("{e:?}"))?;
        assert_eq!(session.outbox.writer.written.len(), 2);
        assert!(session.outbox.writer.written[1].contains("id=\"snapshot\""));
        drop(session);
        fixture.finish().await
    })
}
