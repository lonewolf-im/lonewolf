// SPDX-License-Identifier: Apache-2.0

use super::*;
use lonewolf_extension::vcard::VCard;
use lonewolf_storage::vcard::{VCardQuota, VCardReads, VCardWrites};

fn get_work(fixture: &Fixture, transaction: RedbRead) -> TestResult<GetWork<GlobalChunkAllocator>> {
    let mut arena = Arena::try_new(Default::default())?;
    let sender = Jid::parse_in("bob@localhost/phone", &mut arena)?;
    let payload = Element::builder_in("vCard", "vcard-temp", &mut arena)?.build()?;
    let request = Stanza::builder_in(
        StanzaType::Iq(IqType::Get),
        StanzaNamespace::Client,
        &mut arena,
    )
    .id(Some("vcard-snapshot"))?
    .child(payload)?
    .build()?;
    Ok(GetWork {
        account: fixture.registration.account().clone(),
        target_account: Some(fixture.registration.account().clone()),
        transaction,
        handler: Arc::new(VCard::new(Default::default())),
        discovery: Arc::new(Discovery::default()),
        arena,
        request,
        sender,
        response: Arena::try_new(Default::default())?,
        delivery: RouterDelivery::new(
            &fixture.router.handle(),
            &GlobalChunkAllocator,
            Some(&fixture.registration),
        ),
    })
}

#[test]
fn vcard_get_keeps_account_and_card_snapshot_during_deletion_and_recreation() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let owner = fixture.registration.account();
        let old = "<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'><FN>snapshot old</FN></vCard>";
        let mut transaction = fixture.storage.begin_write().await?;
        transaction.replace_vcard(owner, old, VCardQuota::default()).await?;
        transaction.commit().await?;
        let (snapshot,ticket) = fixture.router.handle().order().fix(vec![owner.clone()],fixture.storage.begin_read()).await?;
        let fixed = get_work(&fixture,snapshot)?;
        drop(ticket);
        let mut deletion = fixture.storage.begin_write().await?;
        deletion.delete_vcard(owner).await?;
        deletion.delete_account(owner).await?;
        deletion.commit().await?;
        let missing = get_work(&fixture,fixture.storage.begin_read().await?)?;
        let outcome = fixed.run(Vec::new()).await.map_err(|e|format!("{e:?}"))?;
        let payload = outcome.reply.map_err(|e|format!("{e:?}"))?.ok_or("missing snapshot payload")?;
        let root = payload.resolve(&outcome.response)?;
        assert_eq!(root.child("FN","vcard-temp")?.ok_or("missing FN")?.text()?,Some("snapshot old"));
        assert!(outcome.results.is_empty());
        let mut recreated = fixture.storage.begin_write().await?;
        recreated.create_account(NewAccount {key:owner.clone(),credentials:credentials()}).await?;
        recreated.replace_vcard(owner,"<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'><FN>new account</FN></vCard>",VCardQuota::default()).await?;
        recreated.commit().await?;
        let missing = missing.run(Vec::new()).await.map_err(|e|format!("{e:?}"))?;
        let error = missing.reply.err().ok_or("missing account accepted")?;
        assert_eq!(error.condition(),StanzaErrorCondition::ServiceUnavailable);
        assert_eq!(error.payload(),lonewolf_extension::iq::IqErrorPayload::Omit);
        assert!(missing.results.is_empty());
        let fresh = get_work(&fixture,fixture.storage.begin_read().await?)?.run(Vec::new()).await.map_err(|e|format!("{e:?}"))?;
        let payload = fresh.reply.map_err(|e|format!("{e:?}"))?.ok_or("missing new card")?;
        assert_eq!(payload.resolve(&fresh.response)?.child("FN","vcard-temp")?.ok_or("missing FN")?.text()?,Some("new account"));
        assert!(fixture.storage.begin_read().await?.vcard(owner).await?.ok_or("missing durable card")?.xml.contains("new account"));
        fixture.finish().await
    })
}

#[test]
fn vcard_submitted_commit_finishes_after_the_pending_request_is_dropped() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut fixture = Fixture::new(&[]).await?;
        let owner = fixture.registration.account().clone();
        let old = "<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'><FN>old</FN></vCard>";
        let mut initial = fixture.storage.begin_write().await?;
        initial
            .replace_vcard(&owner, old, VCardQuota::default())
            .await?;
        initial.commit().await?;
        let snapshot = fixture.storage.begin_read().await?;
        let mut arena = Arena::try_new(Default::default())?;
        let sender = Jid::parse_in("bob@localhost/phone", &mut arena)?;
        let name = Element::builder_in("FN", "vcard-temp", &mut arena)?
            .text("submitted")?
            .build()?;
        let payload = Element::builder_in("vCard", "vcard-temp", &mut arena)?
            .child(name)?
            .build()?;
        let delivery = RouterDelivery::new(
            &fixture.router.handle(),
            &GlobalChunkAllocator,
            Some(&fixture.registration),
        );
        let mut transaction = fixture.storage.begin_write().await?;
        let mut response = Arena::try_new(Default::default())?;
        let handler: &dyn IqHandler<GlobalChunkAllocator, RedbStorage> =
            &VCard::new(Default::default());
        let reply = handler
            .set(
                IqRequest {
                    sender: sender.resolve(&arena)?,
                    target: sender.resolve(&arena)?.bare(),
                    discovery: &Discovery::default(),
                    sessions: &delivery,
                    requester: None,
                    lang: None,
                    space: None,
                    payload: payload.resolve(&arena)?,
                },
                &mut transaction,
                &delivery,
                &mut response,
            )
            .await
            .map_err(|e| format!("{e:?}"))?;
        assert!(reply.payload.is_none());
        assert_eq!(
            snapshot
                .vcard(&owner)
                .await?
                .ok_or("missing old card")?
                .xml
                .as_ref(),
            old
        );
        assert!(
            transaction
                .vcard(&owner)
                .await?
                .ok_or("missing staged card")?
                .xml
                .contains("submitted")
        );
        let pending = commit_and_deliver(
            fixture.work.start(),
            Arc::clone(fixture.router.handle().order()),
            transaction,
            reply.effects,
            delivery,
            None,
            EffectsDiagnostics {
                identity: crate::delivery::EffectsIdentity::Account(owner.clone()),
                commit_operation: "iq_set_commit",
                delivery_operation: "iq_set_effects",
            },
        );
        drop(pending);
        compio::time::timeout(Duration::from_secs(5), fixture.work.drain()).await?;
        assert!(
            fixture
                .storage
                .begin_read()
                .await?
                .vcard(&owner)
                .await?
                .ok_or("missing committed card")?
                .xml
                .contains("submitted")
        );
        assert_eq!(
            snapshot
                .vcard(&owner)
                .await?
                .ok_or("missing old snapshot")?
                .xml
                .as_ref(),
            old
        );
        drop(snapshot);
        fixture.finish().await
    })
}

#[derive(Clone, Debug, Default)]
struct UncertainCommitBackend {
    inner: Arc<redb::backends::InMemoryBackend>,
    fail_next_sync: Arc<AtomicBool>,
}

impl redb::StorageBackend for UncertainCommitBackend {
    fn len(&self) -> std::io::Result<u64> {
        self.inner.len()
    }
    fn read(&self, offset: u64, output: &mut [u8]) -> std::io::Result<()> {
        self.inner.read(offset, output)
    }
    fn set_len(&self, length: u64) -> std::io::Result<()> {
        self.inner.set_len(length)
    }
    fn write(&self, offset: u64, input: &[u8]) -> std::io::Result<()> {
        self.inner.write(offset, input)
    }
    fn sync_data(&self) -> std::io::Result<()> {
        self.inner.sync_data()?;
        if self.fail_next_sync.swap(false, Ordering::SeqCst) {
            Err(std::io::Error::other(
                crate::delivery::failure_tests::SENSITIVE_SOURCE,
            ))
        } else {
            Ok(())
        }
    }
}

fn memory_storage(backend: UncertainCommitBackend) -> TestResult<RedbStorage> {
    Ok(RedbStorage::new(
        redb::Database::builder()
            .set_cache_size(1024 * 1024)
            .create_with_backend(backend)?,
    )?)
}

#[test]
fn vcard_uncertain_commit_closes_without_success_or_payload_and_recovers_whole_state() -> TestResult
{
    use crate::delivery::failure_tests::Capture;
    use lonewolf_extension::delivery::FailureKind;
    use lonewolf_storage::StorageErrorKind;

    let backend = UncertainCommitBackend::default();
    Runtime::new()?.block_on(async {
        let mut fixture=Fixture::new(&[]).await?;
        let owner=fixture.registration.account().clone();
        let old="<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'><FN>old</FN><NICKNAME>old</NICKNAME></vCard>";
        let storage=memory_storage(backend.clone())?;
        let mut initial=storage.begin_write().await?;
        initial.create_account(NewAccount {key:owner.clone(),credentials:credentials()}).await?;
        initial.replace_vcard(&owner,old,VCardQuota::default()).await?;
        initial.commit().await?;
        fixture.storage=storage;
        fixture.router=fixture.router.with_extensions(std::collections::BTreeMap::from([("localhost".into(),Default::default())]));
        let registration=fixture.router.handle().register(&owner,Some("committing"),NonZeroUsize::new(2).ok_or("resource limit")?).await?;
        let (_,incoming)=async_channel::bounded(1);
        let mut outbox=fixture.outbox(GlobalChunkAllocator,ControlledWriter::default());
        outbox.liveness=registration.liveness();
        let mut session=BoundSession {
            registration,router:fixture.router.handle(),storage:fixture.storage.clone(),allocator:GlobalChunkAllocator,work:fixture.work.handle(),service_presence:None,service_pending:None,
            recipients:RecipientLimiter::new(NonZeroUsize::MIN,NonZeroUsize::MIN,Instant::now(),crate::c2s::metrics::C2sWorkerMetrics::detached()),
            available:false,priority:None,incoming,outbox,
        };
        let mut arena=Arena::try_new(Default::default())?;
        let sender=Jid::parse_in("bob@localhost/committing",&mut arena)?;
        let name=Element::builder_in("FN","vcard-temp",&mut arena)?.text("new")?.build()?;
        let nick=Element::builder_in("NICKNAME","vcard-temp",&mut arena)?.text("new")?.build()?;
        let payload=Element::builder_in("vCard","vcard-temp",&mut arena)?.child(name)?.child(nick)?.build()?;
        let request=Stanza::builder_in(StanzaType::Iq(IqType::Set),StanzaNamespace::Client,&mut arena).id(Some("uncertain"))?.child(payload)?.build()?;
        let handler=Arc::new(VCard::new(Default::default()));
        let capture=Capture::default();
        let _subscriber=tracing::subscriber::set_default(capture.clone());
        backend.fail_next_sync.store(true,Ordering::SeqCst);
        let outcome=session.handle_iq_set(request,sender,arena,Arena::try_new(Default::default())?,handler,Some(owner.clone())).await;
        assert!(matches!(outcome,Err(CloseOutcome::InternalError)));
        assert!(session.outbox.queue.is_empty());
        assert!(session.outbox.writer.written.is_empty());
        capture.assert_one(FailureKind::Storage(StorageErrorKind::CommitUnknown),"iq_set_commit");
        drop(session);
        fixture.finish().await?;
        let recovered=memory_storage(backend)?;
        let snapshot=recovered.begin_read().await?;
        assert!(snapshot.account(&owner).await?.is_some());
        let card=snapshot.vcard(&owner).await?.ok_or("missing recovered card")?;
        assert!(card.xml.as_ref()==old || (card.xml.contains("<FN>new</FN>") && card.xml.contains("<NICKNAME>new</NICKNAME>") && !card.xml.contains(">old<")));
        Ok(())
    })
}
