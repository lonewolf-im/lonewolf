// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use lonewolf_extension::Extensions;
use lonewolf_extension::blocking::{Blocking, NAME, NAMESPACE};
use lonewolf_extension::delivery::SessionTag;
use lonewolf_extension::iq::IqErrorPayload;
use lonewolf_storage::blocking::{BlockChange, BlockingReads, BlockingWrites};
use lonewolf_storage::roster::RosterJid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::STANZA_ERROR_NAMESPACE;

use crate::delivery::failure_tests::fail_commit;
use crate::delivery::{EffectsDiagnostics, EffectsIdentity, RouterDelivery, commit_and_deliver};
use crate::stages::ingress::iq::{IqDisposition, IqPending, prepare_get, prepare_set};

use super::*;

fn router() -> TestResult<Router<GlobalChunkAllocator>> {
    let mut extensions = Extensions::default();
    extensions.register(Arc::new(Blocking))?;
    Ok(Router::new(
        Hosts::new(&Config::default().hosts, Some("localhost"))?,
        LocalRouter::new(GlobalChunkAllocator),
    )
    .with_extensions(BTreeMap::from([(
        "localhost".into(),
        extensions.enable_host("localhost", [NAME])?,
    )])))
}

async fn blocklist_get(
    target: Option<&str>,
    contents: &str,
) -> TestResult<Parsed<Stanza, GlobalChunkAllocator>> {
    let to = target.map(|to| format!(" to='{to}'")).unwrap_or_default();
    let xml = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><iq type='get' id='list'{to}><blocklist xmlns='{NAMESPACE}'>{contents}</blocklist></iq>"
    );
    let mut parser = XmppParser::new(
        xml.as_bytes(),
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
    let Some(StreamEvent::Stanza(parsed)) = parser.next_event().await? else {
        return Err("missing GET".into());
    };
    Ok(parsed)
}

async fn route_tagged(router: &RouterHandle<GlobalChunkAllocator>, tag: SessionTag) -> TestResult {
    router
        .route_presence_to_tagged(
            tag,
            routed_presence("localhost", Some("bob@localhost"), PresenceType::Available)?,
        )
        .await?;
    Ok(())
}

#[test]
fn get_lists_prepared_items_and_tags_only_fetcher() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let router = router()?;
        let handle = router.handle();
        let owner = fixture.registration.account();
        let limit = NonZeroUsize::new(4).ok_or("resource limit")?;
        let desk = handle.register(owner, Some("desk"), limit).await?;
        let phone = handle.register(owner, Some("phone"), limit).await?;
        let laptop = handle.register(owner, Some("laptop"), limit).await?;
        desk.handle().tag(SessionTag::Interested).await?;
        phone.handle().tag(SessionTag::Carbons).await?;
        let (_input, incoming) = async_channel::bounded(1);
        let mut session =
            fixture.bound_session(GlobalChunkAllocator, desk, handle.clone(), incoming)?;

        let mut arena = Arena::try_new(ArenaConfig::default())?;
        let john = Jid::parse_in("John@EXAMPLE.TEST/Desk", &mut arena)?;
        let domain = Jid::parse_in("ABUSE.example", &mut arena)?;
        let rules = [
            RosterJid::from(john.resolve(&arena)?),
            RosterJid::from(domain.resolve(&arena)?),
        ];
        for expected in [&[][..], &["abuse.example", "john@example.test/Desk"][..]] {
            if !expected.is_empty() {
                let mut tx = fixture.storage.begin_write().await?;
                tx.change_blocklist(owner, BlockChange::Block(&rules))
                    .await?;
                tx.commit().await?;
            }
            session
                .handle_stanza(blocklist_get(None, "").await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            session
                .outbox
                .flush()
                .await
                .map_err(|error| format!("{error:?}"))?;
            let reply = session
                .outbox
                .writer
                .written
                .pop()
                .ok_or("missing result")?;
            let expected = if expected.is_empty() {
                format!("<blocklist xmlns=\"{NAMESPACE}\"/>")
            } else {
                let items = expected
                    .iter()
                    .map(|item| format!("<item jid=\"{item}\"/>"))
                    .collect::<String>();
                format!("<blocklist xmlns=\"{NAMESPACE}\">{items}</blocklist>")
            };
            assert!(reply.contains("type=\"result\""), "{reply}");
            assert!(reply.contains(&expected), "{reply}");
            route_tagged(&handle, SessionTag::Blocklist).await?;
            assert_eq!(session.registration.take_queued().len(), 1);
            assert!(phone.take_queued().is_empty());
            assert!(laptop.take_queued().is_empty());
        }

        route_tagged(&handle, SessionTag::Interested).await?;
        assert_eq!(session.registration.take_queued().len(), 1);
        assert!(phone.take_queued().is_empty());
        assert!(laptop.take_queued().is_empty());
        route_tagged(&handle, SessionTag::Carbons).await?;
        assert!(session.registration.take_queued().is_empty());
        assert_eq!(phone.take_queued().len(), 1);
        assert!(laptop.take_queued().is_empty());

        let full_jid = session.registration.full_jid();
        let retirement = session.registration.wait_retired();
        drop(session);
        retirement.await?;
        let replacement = handle.register(owner, Some("desk"), limit).await?;
        assert_eq!(replacement.full_jid(), full_jid);
        route_tagged(&handle, SessionTag::Blocklist).await?;
        assert!(replacement.take_queued().is_empty());
        assert!(phone.take_queued().is_empty());
        assert!(laptop.take_queued().is_empty());
        drop((replacement, phone, laptop));
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn failed_or_foreign_get_never_marks_interest() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let router = router()?;
        let handle = router.handle();
        let owner = fixture.registration.account();
        let desk = handle
            .register(owner, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let (_input, incoming) = async_channel::bounded(1);
        let mut session =
            fixture.bound_session(GlobalChunkAllocator, desk, handle.clone(), incoming)?;
        session
            .handle_stanza(blocklist_get(None, "<item jid='peer.example'/>").await?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_blocklist_error(&mut session, StanzaErrorCondition::BadRequest)?;

        let (_value, mut ticket) = handle
            .order()
            .fix(vec![owner.clone()], async { Ok::<_, RouterError>(()) })
            .await?;
        ticket.turn().await;
        for target in ["bob@localhost/desk", "other@localhost"] {
            let request = blocklist_get(Some(target), "").await?;
            session
                .handle_stanza(request)
                .now_or_never()
                .ok_or("invalid destination started asynchronous target work")?
                .map_err(|error| format!("{error:?}"))?;
            assert_blocklist_error(&mut session, StanzaErrorCondition::Forbidden)?;
        }
        for kind in [StanzaNamespace::Server, StanzaNamespace::ComponentAccept] {
            let mut arena = Arena::try_new(ArenaConfig::default())?;
            let payload = Element::builder_in("blocklist", NAMESPACE, &mut arena)?.build()?;
            let target = Jid::parse_in(owner.as_str(), &mut arena)?;
            let sender = Jid::parse_in("reader@external.test/desk", &mut arena)?;
            let stanza = Stanza::builder_in(StanzaType::Iq(IqType::Get), kind, &mut arena)
                .id(Some("list"))?
                .from(Some(sender))?
                .to(Some(target))?
                .child(payload)?
                .build()?;
            let view = stanza.resolve(&arena)?;
            let error = crate::stages::iq::destination_error(&handle, None, &view)
                .map_err(|_| "destination check failed")?
                .ok_or("external origin reached account lookup")?;
            assert_eq!(error.condition(), StanzaErrorCondition::Forbidden);
            assert_eq!(error.payload(), IqErrorPayload::Omit);
        }
        drop(ticket);
        route_tagged(&handle, SessionTag::Blocklist).await?;
        assert!(session.registration.take_queued().is_empty());
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

fn assert_blocklist_error(
    session: &mut BoundSession<'_, GlobalChunkAllocator, ControlledWriter>,
    condition: StanzaErrorCondition,
) -> TestResult {
    let Some(Output::Owned { stanza, arena }) = session.outbox.queue.pop_front() else {
        return Err("missing blocklist error".into());
    };
    let reply = stanza.resolve(&arena)?;
    assert_eq!(reply.stanza_type(), StanzaType::Iq(IqType::Error));
    let mut children = reply.children()?;
    let error = children.next().transpose()?.ok_or("missing stanza error")?;
    assert_eq!(error.name(), "error");
    assert!(
        error
            .child(condition.as_str(), STANZA_ERROR_NAMESPACE)?
            .is_some()
    );
    assert!(children.next().is_none());
    assert!(session.outbox.queue.is_empty());
    Ok(())
}

fn blocklist_answer(
    registration: &Registration<GlobalChunkAllocator>,
    kind: IqType,
    command: &str,
    item: Option<&str>,
    namespace: StanzaNamespace,
) -> TestResult<IqAnswer<GlobalChunkAllocator>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let sender = Jid::parse_in(&registration.full_jid(), &mut arena)?;
    let target = Jid::parse_in(registration.account().as_str(), &mut arena)?;
    let item = item
        .map(|jid| {
            Element::builder_in("item", NAMESPACE, &mut arena)?
                .attribute("jid", "", jid)?
                .build()
        })
        .transpose()?;
    let mut payload = Element::builder_in(command, NAMESPACE, &mut arena)?;
    if let Some(item) = item {
        payload = payload.child(item)?;
    }
    let payload = payload.build()?;
    let request = Stanza::builder_in(StanzaType::Iq(kind), namespace, &mut arena)
        .id(Some("list"))?
        .from(Some(sender))?
        .to(Some(target))?
        .child(payload)?
        .build()?;
    Ok(IqAnswer {
        request,
        arena,
        sender: Some(sender),
        response: Arena::try_new(ArenaConfig::default())?,
        reply: Ok(None),
        results: Vec::new(),
    })
}

async fn pending_set(
    stage: &Stage<'_, GlobalChunkAllocator>,
    writer: &Registration<GlobalChunkAllocator>,
) -> TestResult<IqPending<GlobalChunkAllocator>> {
    let set = blocklist_answer(
        writer,
        IqType::Set,
        "block",
        Some("Peer.EXAMPLE"),
        StanzaNamespace::Client,
    )?;
    let IqDisposition::Ordered(pending) = prepare_set(
        stage,
        &Origin::Session(writer),
        set,
        Arc::new(Blocking),
        Some(writer.account().clone()),
    )
    .await
    .map_err(|_| "SET admission failed")?
    else {
        return Err("SET failed to stage ordered work".into());
    };
    Ok(pending)
}

async fn pending_get(
    stage: &Stage<'_, GlobalChunkAllocator>,
    reader: &Registration<GlobalChunkAllocator>,
) -> TestResult<IqPending<GlobalChunkAllocator>> {
    let get = blocklist_answer(
        reader,
        IqType::Get,
        "blocklist",
        None,
        StanzaNamespace::Client,
    )?;
    let IqDisposition::Ordered(pending) = prepare_get(
        stage,
        &Origin::Session(reader),
        get,
        Arc::new(Blocking),
        Some(reader.account().clone()),
    )
    .await
    .map_err(|_| "GET admission failed")?
    else {
        return Err("GET failed to stage ordered work".into());
    };
    Ok(pending)
}

async fn assert_block_committed(storage: &RedbStorage, owner: &AccountKey) -> TestResult {
    let transaction = storage.begin_write().await?;
    let list = transaction.blocklist(owner).await?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].as_str(), "peer.example");
    Ok(())
}

fn assert_block_push(entry: &MailboxEntry<GlobalChunkAllocator>, recipient: &str) -> TestResult {
    let push = entry.stanza.resolve()?;
    assert_eq!(push.stanza_type(), StanzaType::Iq(IqType::Set));
    assert_eq!(push.to()?.ok_or("missing recipient")?.as_str(), recipient);
    let payload = push
        .children()?
        .next()
        .transpose()?
        .ok_or("missing payload")?;
    assert_eq!(payload.name(), "block");
    assert_eq!(payload.namespace(), NAMESPACE);
    let item = payload
        .child("item", NAMESPACE)?
        .ok_or("missing block item")?;
    assert_eq!(item.attribute("jid", "")?, Some("peer.example"));
    Ok(())
}

#[test]
fn get_and_set_never_lose_a_delta() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        for snapshot_first in [true, false] {
            let fixture = Fixture::new(&[]).await?;
            let router = router()?;
            let handle = router.handle();
            let owner = fixture.registration.account();
            let limit = NonZeroUsize::new(2).ok_or("resource limit")?;
            let writer = handle.register(owner, Some("writer"), limit).await?;
            let reader = handle.register(owner, Some("reader"), limit).await?;
            let stage = Stage {
                router: &handle,
                storage: &fixture.storage,
                allocator: &GlobalChunkAllocator,
                work: &fixture.work.handle(),
            };
            let (_, mut delivery_barrier) = handle
                .order()
                .fix(vec![owner.clone()], async { Ok::<_, RouterError>(()) })
                .await?;
            delivery_barrier.turn().await;
            let (get, set) = if snapshot_first {
                let get = pending_get(&stage, &reader).await?;
                let set = pending_set(&stage, &writer).await?;
                assert_block_committed(&fixture.storage, owner).await?;
                (get, set)
            } else {
                let set = pending_set(&stage, &writer).await?;
                assert_block_committed(&fixture.storage, owner).await?;
                let get = pending_get(&stage, &reader).await?;
                (get, set)
            };

            drop(delivery_barrier);
            let get = get
                .finished()
                .await
                .ok_or("GET was cancelled")?
                .map_err(|_| "GET did not complete")?;
            assert!(get.queued.is_empty());
            let list = get
                .answer
                .reply
                .map_err(|_| "GET failed")?
                .ok_or("missing list")?;
            let has_item = list
                .resolve(&get.answer.response)?
                .child("item", NAMESPACE)?
                .is_some();
            assert_eq!(has_item, !snapshot_first);
            let set = set
                .finished()
                .await
                .ok_or("SET was cancelled")?
                .map_err(|_| "SET did not complete")?;
            assert!(matches!(set.answer.reply, Ok(None)));
            let pushes = reader.take_queued();
            assert_eq!(pushes.len(), usize::from(snapshot_first));
            if let Some(push) = pushes.first() {
                assert_block_push(push, &reader.full_jid())?;
            }
            drop((writer, reader));
            router.shutdown().await?;
            fixture.finish().await?;
        }
        Ok(())
    }))?
}

#[test]
fn disappearing_fetcher_does_not_undo_a_committed_block() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let router = router()?;
        let handle = router.handle();
        let owner = fixture.registration.account();
        let limit = NonZeroUsize::new(3).ok_or("resource limit")?;
        let writer = handle.register(owner, Some("writer"), limit).await?;
        let reader = handle.register(owner, Some("reader"), limit).await?;
        let other_reader = handle.register(owner, Some("other"), limit).await?;
        reader.handle().tag(SessionTag::Blocklist).await?;
        other_reader.handle().tag(SessionTag::Blocklist).await?;
        let stage = Stage {
            router: &handle,
            storage: &fixture.storage,
            allocator: &GlobalChunkAllocator,
            work: &fixture.work.handle(),
        };
        let (_, mut delivery_barrier) = handle
            .order()
            .fix(vec![owner.clone()], async { Ok::<_, RouterError>(()) })
            .await?;
        delivery_barrier.turn().await;
        let set = pending_set(&stage, &writer).await?;
        assert_block_committed(&fixture.storage, owner).await?;

        let old_mailbox = reader.mailbox();
        let retirement = reader.wait_retired();
        drop(reader);
        retirement.await?;
        let replacement = handle.register(owner, Some("reader"), limit).await?;
        assert_eq!(replacement.full_jid(), "bob@localhost/reader");
        drop(delivery_barrier);
        let set = set
            .finished()
            .await
            .ok_or("SET was cancelled")?
            .map_err(|_| "SET did not complete")?;
        assert!(matches!(set.answer.reply, Ok(None)));
        assert!(old_mailbox.take_queued().is_empty());
        assert!(replacement.take_queued().is_empty());
        let pushes = other_reader.take_queued();
        assert_eq!(pushes.len(), 1);
        assert_block_push(&pushes[0], &other_reader.full_jid())?;
        assert_block_committed(&fixture.storage, owner).await?;
        drop((writer, replacement, other_reader));
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn failed_block_commit_returns_no_success_or_push() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let router = router()?;
        let handle = router.handle();
        let owner = fixture.registration.account();
        let limit = NonZeroUsize::new(2).ok_or("resource limit")?;
        let writer = handle.register(owner, Some("writer"), limit).await?;
        let reader = handle.register(owner, Some("reader"), limit).await?;
        reader.handle().tag(SessionTag::Blocklist).await?;
        let delivery = RouterDelivery::new(&handle, &GlobalChunkAllocator, Some(&writer));
        let mut answer = blocklist_answer(
            &writer,
            IqType::Set,
            "block",
            Some("Peer.EXAMPLE"),
            StanzaNamespace::Client,
        )?;
        let view = answer.request.resolve(&answer.arena)?;
        let discovery = handle
            .discovery(owner.domain())
            .ok_or("missing discovery")?;
        let request = lonewolf_extension::iq::IqRequest {
            sender: view.from()?.ok_or("missing sender")?,
            target: view.to()?.ok_or("missing target")?,
            discovery,
            sessions: &delivery,
            requester: None,
            lang: None,
            space: None,
            payload: view
                .children()?
                .next()
                .transpose()?
                .ok_or("missing command")?,
        };
        let mut transaction = fixture.storage.begin_write().await?;
        let reply = <Blocking as IqHandler<_, RedbStorage>>::set(
            &Blocking,
            request,
            &mut transaction,
            &delivery,
            &mut answer.response,
        )
        .await
        .map_err(|_| "block write was not staged")?;
        assert_eq!(transaction.blocklist(owner).await?.len(), 1);
        answer.reply = Ok(reply.payload);
        answer.results = reply.results;
        let (transaction, release) = fail_commit(transaction);
        let pending = commit_and_deliver(
            fixture.work.handle().start(),
            Arc::clone(handle.order()),
            transaction,
            reply.effects,
            delivery,
            Some(writer.mailbox()),
            EffectsDiagnostics {
                identity: EffectsIdentity::Account(owner.clone()),
                commit_operation: "iq_set_commit",
                delivery_operation: "iq_set_effects",
            },
        );
        release.send(()).map_err(|_| "commit was cancelled")?;
        let result = IqPending::Set { pending, answer }.finished().await;
        assert!(matches!(result, Some(Err(_))));
        assert!(writer.take_queued().is_empty());
        assert!(reader.take_queued().is_empty());
        assert!(
            fixture
                .storage
                .begin_read()
                .await?
                .blocklist(owner)
                .await?
                .is_empty()
        );
        drop((writer, reader));
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn owner_only_mutations_reject_external_origins_at_admission() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let router = router()?;
        let handle = router.handle();
        let owner = fixture.registration.account();
        for command in ["block", "unblock"] {
            for (namespace, origin) in [
                (
                    StanzaNamespace::Server,
                    Origin::<GlobalChunkAllocator>::Remote {
                        local: "localhost",
                        remote: "external.test",
                    },
                ),
                (
                    StanzaNamespace::ComponentAccept,
                    Origin::Service {
                        domain: "external.test",
                    },
                ),
            ] {
                let answer = blocklist_answer(
                    &fixture.registration,
                    IqType::Set,
                    command,
                    Some("peer.example"),
                    namespace,
                )?;
                let view = answer.request.resolve(&answer.arena)?;
                assert!(
                    crate::stages::iq::destination_error(&handle, Some(owner), &view)
                        .map_err(|_| "destination check failed")?
                        .is_none()
                );
                let error = crate::stages::iq::destination_error(&handle, origin.sender(), &view)
                    .map_err(|_| "destination check failed")?
                    .ok_or("external origin reached account lookup")?;
                assert_eq!(error.condition(), StanzaErrorCondition::Forbidden);
                assert_eq!(error.payload(), IqErrorPayload::Omit);
            }
        }
        router.shutdown().await?;
        fixture.finish().await
    })
}
