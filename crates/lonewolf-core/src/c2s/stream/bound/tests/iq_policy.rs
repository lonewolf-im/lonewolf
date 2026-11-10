// SPDX-License-Identifier: Apache-2.0

use super::*;
use lonewolf_extension::policy::{PolicyFuture, PolicyHandler, PolicyRequest};
use lonewolf_extension::presence::{PresenceFuture, PresenceHandler};
use lonewolf_extension::{Extension, Extensions, RegistrationError, Slots};
use lonewolf_storage::vcard::{VCardQuota, VCardReads, VCardWrites};
use std::collections::BTreeMap;

type Gate = (oneshot::Sender<()>, oneshot::Receiver<()>);
type Snapshot = (usize, Option<Box<str>>);

struct PolicyVisibility {
    policies: PlMutex<Vec<Snapshot>>,
    visibility: PlMutex<Vec<Snapshot>>,
    policy_gate: PlMutex<Option<Gate>>,
    visibility_done: PlMutex<Option<oneshot::Sender<()>>>,
    fail_visibility: bool,
}

impl PolicyVisibility {
    fn new(fail_visibility: bool) -> Self {
        Self {
            policies: PlMutex::default(),
            visibility: PlMutex::default(),
            policy_gate: PlMutex::default(),
            visibility_done: PlMutex::default(),
            fail_visibility,
        }
    }
}

impl Extension<GlobalChunkAllocator, RedbStorage> for PolicyVisibility {
    fn name(&self) -> &'static str {
        "policy-visibility"
    }
    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.policy(self.clone());
        slots.presence(PresenceRequestType::Available, self)
    }
}

impl PolicyHandler<RedbStorage> for PolicyVisibility {
    fn check<'a>(
        &'a self,
        request: PolicyRequest<'a>,
        transaction: &'a RedbRead,
    ) -> PolicyFuture<'a> {
        Box::pin(async move {
            let card = transaction
                .vcard(request.account)
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .map(|card| card.xml);
            self.policies
                .lock()
                .push((std::ptr::from_ref(transaction) as usize, card));
            let gate = self.policy_gate.lock().take();
            if let Some((entered, release)) = gate {
                let _ = entered.send(());
                release
                    .await
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            }
            Ok(Verdict::Allow)
        })
    }
}

impl PresenceHandler<GlobalChunkAllocator, RedbStorage> for PolicyVisibility {
    fn visibility<'a>(
        &'a self,
        owner: &'a AccountKey,
        observer: JidRef<'a>,
        transaction: &'a RedbRead,
    ) -> PresenceFuture<'a, bool> {
        Box::pin(async move {
            assert_eq!(observer.as_str(), "bob@localhost/desk");
            let card = transaction
                .vcard(owner)
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .map(|card| card.xml);
            self.visibility
                .lock()
                .push((std::ptr::from_ref(transaction) as usize, card));
            if let Some(done) = self.visibility_done.lock().take() {
                let _ = done.send(());
            }
            if self.fail_visibility {
                Err(StanzaErrorCondition::InternalServerError.into())
            } else {
                Ok(true)
            }
        })
    }
}

async fn setup<'a>(
    fixture: &'a Fixture,
    handler: Arc<PolicyVisibility>,
    same_account: bool,
) -> TestResult<(
    Router<GlobalChunkAllocator>,
    BoundSession<'a, GlobalChunkAllocator, ControlledWriter>,
    Registration<GlobalChunkAllocator>,
)> {
    let mut extensions = Extensions::default();
    extensions.register(handler)?;
    let router = Router::new(
        Hosts::new(&Config::default().hosts, None)?,
        LocalRouter::new(GlobalChunkAllocator),
    )
    .with_extensions(BTreeMap::from([(
        "localhost".into(),
        extensions.enable_host("localhost", ["policy-visibility"])?,
    )]));
    let source = router
        .handle()
        .register(
            fixture.registration.account(),
            Some("desk"),
            NonZeroUsize::new(2).ok_or("limit")?,
        )
        .await?;
    let mut arena = Arena::try_new(Default::default())?;
    let target = AccountKey::try_from(
        Jid::parse_in(
            if same_account {
                "bob@localhost"
            } else {
                "alice@localhost"
            },
            &mut arena,
        )?
        .resolve(&arena)?,
    )?;
    if !same_account {
        let mut transaction = fixture.storage.begin_write().await?;
        transaction
            .create_account(NewAccount {
                key: target.clone(),
                credentials: credentials(),
            })
            .await?;
        transaction.commit().await?;
    }
    let target = router
        .handle()
        .register(&target, Some("phone"), NonZeroUsize::new(2).ok_or("limit")?)
        .await?;
    let (_sender, incoming) = async_channel::bounded(1);
    let session = fixture.bound_session(GlobalChunkAllocator, source, router.handle(), incoming)?;
    Ok((router, session, target))
}

async fn request(target: &str) -> TestResult<Parsed<Stanza, GlobalChunkAllocator>> {
    let xml = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><iq type='get' id='forward' from='mallory@remote.test/spoof' to='{target}'><query xmlns='urn:test:forward'/></iq>"
    );
    let mut parser = XmppParser::new(
        xml.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4096).ok_or("limit")?,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    );
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    let Some(StreamEvent::Stanza(parsed)) = parser.next_event().await? else {
        return Err("request".into());
    };
    Ok(parsed)
}

#[test]
fn c2s_full_iq_policy_and_visibility_share_ordered_snapshot_and_target_ticket() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let handler = Arc::new(PolicyVisibility::new(false));
        let (entered, reached) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        *handler.policy_gate.lock() = Some((entered, resume));
        let (visible, visibility_done) = oneshot::channel();
        *handler.visibility_done.lock() = Some(visible);
        let (router, mut session, phone) = setup(&fixture, handler.clone(), false).await?;
        let handle = router.handle();
        let ((), blocker) = handle
            .order()
            .fix(vec![phone.account().clone()], async {
                Ok::<_, RouterError>(())
            })
            .await?;
        let parsed = request("alice@localhost/phone").await?;
        let mut dispatch = Box::pin(session.handle_iq(parsed));
        match futures_util::future::select(reached, dispatch.as_mut()).await {
            Either::Left((entered, _)) => entered?,
            Either::Right(_) => return Err("dispatch preceded policy".into()),
        }
        let mut transaction = fixture.storage.begin_write().await?;
        transaction
            .replace_vcard(
                phone.account(),
                "<vCard xmlns='vcard-temp'/>",
                VCardQuota::default(),
            )
            .await?;
        transaction.commit().await?;
        release.send(()).map_err(|_| "policy cancelled")?;
        match futures_util::future::select(visibility_done, dispatch.as_mut()).await {
            Either::Left((done, _)) => done?,
            Either::Right(_) => return Err("dispatch preceded visibility".into()),
        }
        assert!(poll!(&mut dispatch).is_pending());
        assert_eq!(handler.policies.lock().len(), 2);
        {
            let visibility = handler.visibility.lock();
            assert_eq!(visibility.len(), 1);
            for policy in handler.policies.lock().iter() {
                assert_eq!(policy.0, visibility[0].0);
                assert!(policy.1.is_none());
            }
            assert!(visibility[0].1.is_none());
        }
        assert!(phone.take_queued().is_empty());
        drop(blocker);
        dispatch.await.map_err(|error| format!("{error:?}"))?;
        let delivered = phone.recv().await.ok_or("forwarded")?;
        assert_eq!(
            delivered.stanza.resolve()?.from()?.ok_or("from")?.as_str(),
            "bob@localhost/desk"
        );
        assert_eq!(
            delivered.stanza.resolve()?.to()?.ok_or("to")?.as_str(),
            "alice@localhost/phone"
        );
        assert!(session.outbox.queue.is_empty());
        drop((session, phone, delivered));
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn same_account_full_iq_calls_visibility_and_preserves_its_failure() -> TestResult {
    Runtime::new()?.block_on(async {
        for fail in [false, true] {
            let fixture = Fixture::new(&[]).await?;
            let handler = Arc::new(PolicyVisibility::new(fail));
            let (router, mut session, phone) = setup(&fixture, handler.clone(), true).await?;
            let result = session
                .handle_iq(request("bob@localhost/phone").await?)
                .await;
            assert!(handler.policies.lock().is_empty());
            assert_eq!(handler.visibility.lock().len(), 1);
            if fail {
                assert_eq!(result, Err(CloseOutcome::InternalError));
                assert!(phone.take_queued().is_empty());
            } else {
                result.map_err(|error| format!("{error:?}"))?;
                assert_eq!(phone.take_queued().len(), 1);
            }
            drop((session, phone));
            router.shutdown().await?;
            fixture.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn full_iq_completion_drains_mailbox_in_order_until_resource_admission_finishes() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let handler = Arc::new(PolicyVisibility::new(false));
        let (visible, visibility_done) = oneshot::channel();
        *handler.visibility_done.lock() = Some(visible);
        let (router, mut session, phone) = setup(&fixture, handler, false).await?;
        let handle = router.handle();
        let ((), blocker) = handle
            .order()
            .fix(vec![phone.account().clone()], async {
                Ok::<_, RouterError>(())
            })
            .await?;
        let (flushed, written) = oneshot::channel();
        session.outbox.writer.flush_entered = Some(flushed);
        let parsed = request("alice@localhost/phone").await?;
        let mut dispatch = Box::pin(session.handle_iq(parsed));
        match futures_util::future::select(visibility_done, dispatch.as_mut()).await {
            Either::Left((done, _)) => done?,
            Either::Right(_) => return Err("dispatch preceded visibility".into()),
        }
        for id in ["first", "second"] {
            let mut arena = Arena::try_new(Default::default())?;
            let to = Jid::parse_in("bob@localhost/desk", &mut arena)?;
            let stanza = Stanza::builder_in(
                StanzaType::Message(MessageType::Chat),
                StanzaNamespace::Client,
                &mut arena,
            )
            .to(Some(to))?
            .id(Some(id))?
            .build()?;
            handle
                .route_full(RoutedStanza::from_parts(stanza, arena))
                .await?;
        }
        match futures_util::future::select(written, dispatch.as_mut()).await {
            Either::Left((done, _)) => done?,
            Either::Right(_) => return Err("resource completion stopped mailbox drain".into()),
        }
        assert!(poll!(&mut dispatch).is_pending());
        assert!(phone.take_queued().is_empty());
        drop(blocker);
        dispatch.await.map_err(|error| format!("{error:?}"))?;
        assert_eq!(session.outbox.writer.written.len(), 2);
        assert!(session.outbox.writer.written[0].contains("id=\"first\""));
        assert!(session.outbox.writer.written[1].contains("id=\"second\""));
        assert_eq!(phone.take_queued().len(), 1);
        drop((session, phone));
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn detached_full_iq_rechecks_source_liveness_after_ticket_wait() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::new(&[]).await?;
        let handler = Arc::new(PolicyVisibility::new(false));
        let (visible, visibility_done) = oneshot::channel();
        *handler.visibility_done.lock() = Some(visible);
        let (router, mut session, phone) = setup(&fixture, handler, false).await?;
        let handle = router.handle();
        let source = session.registration.account().clone();
        let ((), blocker) = handle
            .order()
            .fix(vec![phone.account().clone()], async {
                Ok::<_, RouterError>(())
            })
            .await?;
        let parsed = request("alice@localhost/phone").await?;
        let mut dispatch = Box::pin(session.handle_iq(parsed));
        match futures_util::future::select(visibility_done, dispatch.as_mut()).await {
            Either::Left((done, _)) => done?,
            Either::Right(_) => return Err("dispatch preceded visibility".into()),
        }
        handle.retire_account(&source).await?;
        assert_eq!(dispatch.await, Err(CloseOutcome::InternalError));
        drop(session);
        drop(blocker);
        fixture.work.drain().await;
        assert!(phone.take_queued().is_empty());
        drop(phone);
        router.shutdown().await?;
        fixture.finish().await
    }))?
}
