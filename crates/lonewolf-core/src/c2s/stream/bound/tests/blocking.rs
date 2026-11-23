// SPDX-License-Identifier: Apache-2.0

mod addressed;

use std::collections::BTreeMap;

use lonewolf_extension::blocking::{Blocking, NAME, NAMESPACE};
use lonewolf_extension::delivery::SessionTag;
use lonewolf_extension::iq::IqErrorPayload;
use lonewolf_extension::policy::{PolicyFuture, PolicyHandler, PolicyRequest};
use lonewolf_extension::roster::{Roster, RosterLimits};
use lonewolf_extension::{Extension, Extensions, RegistrationError, Slots};
use lonewolf_storage::blocking::{BlockChange, BlockingReads, BlockingWrites};
use lonewolf_storage::roster::{
    RosterItem, RosterJid, RosterSubscription, RosterWrites, SubscriptionState,
};
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::STANZA_ERROR_NAMESPACE;

use crate::component::{
    credentials as component_credentials, metrics::ComponentMetrics, registry::ComponentRegistry,
};
use crate::config::{ComponentLimits, ComponentsConfig};
use crate::delivery::failure_tests::fail_commit;
use crate::delivery::{
    EffectsDiagnostics, EffectsError, EffectsIdentity, RouterDelivery, commit_and_deliver,
};
use crate::order::Ticket;
use crate::router::ServiceRoute;
use crate::stages::ingress::iq::{IqDisposition, IqPending, prepare_get, prepare_set};

use super::*;

fn router() -> TestResult<Router<GlobalChunkAllocator>> {
    blocking_router(None)
}

fn blocking_router(
    presence_extension: Option<Arc<dyn Extension<GlobalChunkAllocator, RedbStorage>>>,
) -> TestResult<Router<GlobalChunkAllocator>> {
    let mut extensions = Extensions::default();
    extensions.register(Arc::new(Blocking))?;
    let mut names = vec![NAME];
    if let Some(extension) = presence_extension {
        names.push(extension.name());
        extensions.register(extension)?;
    }
    Ok(Router::new(
        Hosts::new(&Config::default().hosts, Some("localhost"))?,
        LocalRouter::new(GlobalChunkAllocator),
    )
    .with_extensions(BTreeMap::from([(
        "localhost".into(),
        extensions.enable_host("localhost", names)?,
    )])))
}

struct BlockPresenceGate(PlMutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>);

impl Extension<GlobalChunkAllocator, RedbStorage> for BlockPresenceGate {
    fn name(&self) -> &'static str {
        "block-presence-gate"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.policy(self);
        Ok(())
    }
}

impl PolicyHandler<RedbStorage> for BlockPresenceGate {
    fn check<'a>(&'a self, request: PolicyRequest<'a>, _: &'a RedbRead) -> PolicyFuture<'a> {
        Box::pin(async move {
            if request.kind == StanzaType::Presence(PresenceType::Unavailable) {
                let gate = self.0.lock().take();
                if let Some((entered, release)) = gate {
                    let _ = entered.send(());
                    release
                        .await
                        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                }
            }
            Ok(Verdict::Allow)
        })
    }
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
    items: &[&str],
    namespace: StanzaNamespace,
) -> TestResult<IqAnswer<GlobalChunkAllocator>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let sender = Jid::parse_in(&registration.full_jid(), &mut arena)?;
    let target = Jid::parse_in(registration.account().as_str(), &mut arena)?;
    let items = items
        .iter()
        .map(|jid| {
            Element::builder_in("item", NAMESPACE, &mut arena)?
                .attribute("jid", "", jid)?
                .build()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut payload = Element::builder_in(command, NAMESPACE, &mut arena)?;
    for item in items {
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
    pending_change(stage, writer, "block", &["Peer.EXAMPLE"]).await
}

async fn pending_change(
    stage: &Stage<'_, GlobalChunkAllocator>,
    writer: &Registration<GlobalChunkAllocator>,
    command: &str,
    items: &[&str],
) -> TestResult<IqPending<GlobalChunkAllocator>> {
    let set = blocklist_answer(writer, IqType::Set, command, items, StanzaNamespace::Client)?;
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
        &[],
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

fn assert_block_push(
    entry: &MailboxEntry<GlobalChunkAllocator>,
    recipient: &str,
    rule: &str,
) -> TestResult {
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
    assert_eq!(item.attribute("jid", "")?, Some(rule));
    Ok(())
}

fn test_account(jid: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    Ok(AccountKey::try_from(
        Jid::parse_in(jid, &mut arena)?.resolve(&arena)?,
    )?)
}

async fn account_turn(
    router: &RouterHandle<GlobalChunkAllocator>,
    accounts: &[&AccountKey],
) -> TestResult<Ticket> {
    let ((), ticket) = router
        .order()
        .fix(
            accounts.iter().map(|account| (*account).clone()).collect(),
            async { Ok::<_, RouterError>(()) },
        )
        .await?;
    Ok(ticket)
}

async fn assert_committed_rule(
    storage: &RedbStorage,
    owner: &AccountKey,
    rule: &str,
    present: bool,
) -> TestResult {
    let writer = storage.begin_write().await?;
    let rules = writer.blocklist(owner).await?;
    assert_eq!(rules.iter().any(|item| item.as_str() == rule), present);
    Ok(())
}

async fn assert_successful_change(pending: IqPending<GlobalChunkAllocator>) -> TestResult {
    let done = pending
        .finished()
        .await
        .ok_or("SET was cancelled")?
        .map_err(|_| "SET did not complete")?;
    assert!(matches!(done.answer.reply, Ok(None)));
    Ok(())
}

#[test]
fn reciprocal_exact_blocks_reserve_authorized_accounts_in_either_commit_order() -> TestResult {
    const ABSENT_RESOURCE: &str = "absent@localhost/desk";
    const UNGRANTED: &str = "carol@localhost";
    const OTHER_RESOURCE: &str = "dave@localhost/other";
    const DIRECTED_ADDRESS: &str = "dave@localhost/Desk/second";
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        for bob_first in [true, false] {
            let fixture = Fixture::new(&[]).await?;
            let router = blocking_router(Some(Arc::new(Roster::default())))?;
            let handle = router.handle();
            let bob = fixture.registration.account();
            let alice = test_account("alice@localhost")?;
            let ungranted = test_account(UNGRANTED)?;
            let different_grant = test_account("dave@localhost")?;
            let absent = test_account("absent@localhost")?;
            let mut write = fixture.storage.begin_write().await?;
            write
                .create_account(NewAccount {
                    key: alice.clone(),
                    credentials: credentials(),
                })
                .await?;
            for (owner, peer) in [(bob, &alice), (&alice, bob)] {
                for subscriber in [peer, &absent] {
                    write
                        .put_roster_item(
                            owner,
                            &RosterItem {
                                jid: RosterJid::from(subscriber),
                                name: None,
                                groups: Vec::new(),
                                subscription: RosterSubscription {
                                    state: SubscriptionState::From,
                                    ..Default::default()
                                },
                            },
                            RosterQuota::default(),
                        )
                        .await?;
                }
            }
            write.commit().await?;
            let bob = handle
                .register(bob, Some("phone"), NonZeroUsize::MIN)
                .await?;
            let alice = handle
                .register(&alice, Some("desk"), NonZeroUsize::MIN)
                .await?;
            for source in [&alice, &bob] {
                let from = source.full_jid();
                source
                    .handle()
                    .set_presence(
                        Some(0),
                        routed_presence(&from, None, PresenceType::Available)?,
                        None,
                    )
                    .await?;
                source
                    .handle()
                    .directed_presence(
                        routed_presence(&from, Some(DIRECTED_ADDRESS), PresenceType::Available)?,
                        true,
                    )
                    .await?;
            }
            let stage = Stage {
                router: &handle,
                storage: &fixture.storage,
                allocator: &GlobalChunkAllocator,
                work: &fixture.work.handle(),
            };
            let (first, second, first_rules, second_rules) = if bob_first {
                (
                    &bob,
                    &alice,
                    &[
                        "alice@localhost/desk",
                        "alice@localhost",
                        ABSENT_RESOURCE,
                        UNGRANTED,
                        OTHER_RESOURCE,
                    ][..],
                    &["bob@localhost"][..],
                )
            } else {
                (
                    &alice,
                    &bob,
                    &["bob@localhost", ABSENT_RESOURCE, UNGRANTED, OTHER_RESOURCE][..],
                    &["alice@localhost/desk"][..],
                )
            };
            let mut older = account_turn(&handle, &[first.account()]).await?;
            older.turn().await;
            let first_change = pending_change(&stage, first, "block", first_rules).await?;
            assert_committed_rule(&fixture.storage, first.account(), first_rules[0], true).await?;
            let mut second_line = account_turn(&handle, &[second.account()]).await?;
            assert!(second_line.turn().now_or_never().is_none());
            let mut absent_line = account_turn(&handle, &[&absent]).await?;
            assert!(absent_line.turn().now_or_never().is_none());
            let mut independent = account_turn(&handle, &[&ungranted, &different_grant]).await?;
            assert!(independent.turn().now_or_never().is_some());
            drop((second_line, absent_line, independent));
            let second_change = pending_change(&stage, second, "block", second_rules).await?;
            assert_committed_rule(&fixture.storage, second.account(), second_rules[0], true)
                .await?;
            drop(older);
            assert_successful_change(first_change).await?;
            let completed = second_change
                .finished()
                .await
                .ok_or("second SET was cancelled")?
                .map_err(|_| "second SET did not complete")?;
            assert!(matches!(completed.answer.reply, Ok(None)));
            assert!(first.take_queued().is_empty());
            let notices = completed.queued;
            assert_eq!(notices.len(), 1);
            let notice = notices[0].stanza.resolve()?;
            assert_eq!(
                notice.stanza_type(),
                StanzaType::Presence(PresenceType::Unavailable)
            );
            assert_eq!(
                notice.from()?.ok_or("missing notice sender")?.as_str(),
                first.full_jid()
            );
            drop((bob, alice));
            router.shutdown().await?;
            fixture.finish().await?;
        }
        Ok(())
    }))?
}

#[test]
fn domain_block_orders_queued_grants_and_finishes_with_an_undrained_component() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let component = "gateway.example.test";
        let config: ComponentsConfig = toml::from_str(
            "[domains.'gateway.example.test']\nsecret = 'fixture-component-secret'",
        )?;
        let limits = ComponentLimits {
            max_queued_stanzas: NonZeroUsize::MIN,
            ..ComponentLimits::default()
        };
        let registry = ComponentRegistry::new(
            &config,
            component_credentials::load(&config)?,
            &limits,
            ComponentMetrics::new(1, 1),
        );
        let (report_policy, in_policy) = oneshot::channel();
        let (release_policy, resume_policy) = oneshot::channel();
        let gate = BlockPresenceGate(PlMutex::new(Some((report_policy, resume_policy))));
        let router = blocking_router(Some(Arc::new(gate)))?.with_services(BTreeMap::from([(
            component.into(),
            ServiceRoute::component(Arc::from(component), registry.clone()),
        )]));
        let handle = router.handle();
        let owner = fixture.registration.account();
        let peer = test_account("alice@localhost")?;
        let unrelated = test_account("carol@localhost")?;
        let mut write = fixture.storage.begin_write().await?;
        write
            .create_account(NewAccount {
                key: peer.clone(),
                credentials: credentials(),
            })
            .await?;
        write.commit().await?;
        let limit = NonZeroUsize::new(2).ok_or("resource limit")?;
        let source = handle.register(owner, Some("phone"), limit).await?;
        let editor = handle.register(owner, Some("editor"), limit).await?;
        let observer = handle
            .register(&peer, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let mut link = registry.attach(component).map_err(|_| "attach component")?;
        let mut arena = Arena::try_new(ArenaConfig::default())?;
        let address = Jid::parse_in(component, &mut arena)?.resolve(&arena)?;
        let from = source.full_jid();
        let to = observer.full_jid();
        source
            .handle()
            .record_service_presence(address, true)
            .await?;
        handle.route_to_component(routed_presence(
            &from,
            Some(component),
            PresenceType::Available,
        )?)?;
        let stage = Stage {
            router: &handle,
            storage: &fixture.storage,
            allocator: &GlobalChunkAllocator,
            work: &fixture.work.handle(),
        };
        let mut older = account_turn(&handle, &[&peer]).await?;
        older.turn().await;
        let ((), mut grant) = handle
            .order()
            .fix_directed_grant(
                owner.clone(),
                peer.clone(),
                Some(to.clone().into()),
                async { Ok::<_, RouterError>(()) },
            )
            .await?;
        let change = pending_change(&stage, &source, "block", &["localhost", component]).await?;
        assert_committed_rule(&fixture.storage, owner, "localhost", true).await?;
        drop(older);
        grant.turn().await;
        source
            .handle()
            .directed_presence(
                routed_presence(&from, Some(&to), PresenceType::Available)?,
                true,
            )
            .await?;
        drop(grant);
        in_policy.await?;
        let duplicate = pending_change(&stage, &editor, "block", &["localhost", component]).await?;
        let clear = pending_change(&stage, &editor, "unblock", &[]).await?;
        assert_committed_rule(&fixture.storage, owner, "localhost", false).await?;
        let mut independent = account_turn(&handle, &[&unrelated]).await?;
        assert!(independent.turn().now_or_never().is_some());
        let mut affected = account_turn(&handle, &[&peer]).await?;
        assert!(affected.turn().now_or_never().is_none());
        release_policy.send(()).map_err(|_| "policy gate dropped")?;
        assert_successful_change(change).await?;
        assert_successful_change(duplicate).await?;
        assert_successful_change(clear).await?;
        affected.turn().await;
        drop(affected);
        let entries = observer.take_queued();
        assert_eq!(entries.len(), 2);
        for (entry, kind) in entries
            .iter()
            .zip([PresenceType::Available, PresenceType::Unavailable])
        {
            let view = entry.stanza.resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Presence(kind));
            assert_eq!(view.from()?.ok_or("sender")?.as_str(), from);
            assert_eq!(view.to()?.ok_or("recipient")?.as_str(), to);
        }
        let original = link.try_next().ok_or("missing queued presence")?;
        assert_eq!(
            original.resolve()?.stanza_type(),
            StanzaType::Presence(PresenceType::Available)
        );
        assert!(link.try_next().is_none());

        let domain_resource = pending_change(&stage, &source, "block", &["localhost/desk"]).await?;
        assert_successful_change(domain_resource).await?;
        assert!(observer.take_queued().is_empty());
        drop((independent, link, source, editor, observer));
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn roster_quota_failure_keeps_the_committed_blocklist_push() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let roster = Roster::new(BTreeMap::from([(
            "localhost".into(),
            RosterLimits {
                max_items: NonZeroUsize::MIN,
                ..RosterLimits::default()
            },
        )]));
        let router = blocking_router(Some(Arc::new(roster)))?;
        let handle = router.handle();
        let owner = fixture.registration.account();
        let mut write = fixture.storage.begin_write().await?;
        for contact in ["alice@localhost", "carol@localhost"] {
            write
                .put_roster_item(
                    owner,
                    &RosterItem {
                        jid: RosterJid::from(&test_account(contact)?),
                        name: None,
                        groups: Vec::new(),
                        subscription: RosterSubscription {
                            state: SubscriptionState::From,
                            ..Default::default()
                        },
                    },
                    RosterQuota::default(),
                )
                .await?;
        }
        write.commit().await?;
        let limit = NonZeroUsize::new(2).ok_or("resource limit")?;
        let writer = handle.register(owner, Some("writer"), limit).await?;
        let reader = handle.register(owner, Some("reader"), limit).await?;
        reader.handle().tag(SessionTag::Blocklist).await?;
        writer
            .handle()
            .set_presence(
                Some(0),
                routed_presence(&writer.full_jid(), None, PresenceType::Available)?,
                None,
            )
            .await?;
        let stage = Stage {
            router: &handle,
            storage: &fixture.storage,
            allocator: &GlobalChunkAllocator,
            work: &fixture.work.handle(),
        };

        let pending = pending_change(&stage, &writer, "block", &["localhost"]).await?;
        let IqPending::Set { pending, .. } = pending else {
            return Err("block did not stage a SET".into());
        };
        assert!(matches!(
            pending.finished().await,
            Some(Err(EffectsError::Delivery(_)))
        ));

        assert_committed_rule(&fixture.storage, owner, "localhost", true).await?;
        let pushes = reader.take_queued();
        assert_eq!(pushes.len(), 1);
        assert_block_push(&pushes[0], &reader.full_jid(), "localhost")?;
        let mut next = account_turn(&handle, &[owner]).await?;
        assert!(next.turn().now_or_never().is_some());
        drop((next, reader, writer));
        router.shutdown().await?;
        fixture.finish().await
    }))?
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
                assert_block_push(push, &reader.full_jid(), "peer.example")?;
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
        assert_block_push(&pushes[0], &other_reader.full_jid(), "peer.example")?;
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
            &["Peer.EXAMPLE"],
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
                    &["peer.example"],
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
