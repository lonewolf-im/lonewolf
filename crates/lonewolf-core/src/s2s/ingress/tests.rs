// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::s2s::log_domain;
use lonewolf_extension::archive::{
    ArchiveDirection, ArchiveFuture, ArchiveHandler, ArchiveId, ArchiveOutcome, ArchiveRequest,
};
use lonewolf_extension::delivery::{Delivery, DeliveryFuture, HandlerError, SessionId, SessionTag};
use lonewolf_extension::observer::{MessageEvent, MessageObserver, MessageOutcome, MessageRole};
use lonewolf_extension::policy::{Direction, PolicyFuture, PolicyHandler, PolicyRequest, Verdict};
use lonewolf_extension::{Extension, Extensions, RegistrationError, Slots};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::offline::OfflineReads;
use lonewolf_storage::{RedbRead, RedbWrite, Storage, WriteTransaction};
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{PresenceType, StanzaNamespace};
use parking_lot::Mutex as PlMutex;

use super::*;
use crate::delivery::WorkGroup;
use crate::router::{Router, local::LocalRouter};
use crate::s2s::outbound::test_support::{AdmissionState, Fixture as RemoteFixture};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    _directory: tempfile::TempDir,
    context: IngressContext<GlobalChunkAllocator>,
    router: Router<GlobalChunkAllocator>,
    remote: RemoteFixture,
    work: WorkGroup,
}

impl Fixture {
    fn new(
        extensions: Extensions<GlobalChunkAllocator, RedbStorage>,
        names: &[&str],
    ) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let remote = RemoteFixture::new(AdmissionState::Link)?;
        let router = Router::new(remote.hosts(), LocalRouter::new(GlobalChunkAllocator))
            .with_remote(remote.remote())
            .with_extensions(BTreeMap::from([(
                "example.com".into(),
                extensions.enable_host("example.com", names.iter().copied())?,
            )]));
        let work = WorkGroup::new();
        Ok(Self {
            _directory: directory,
            context: IngressContext {
                router: router.handle(),
                storage,
                allocator: GlobalChunkAllocator,
                work: work.handle(),
            },
            router,
            remote,
            work,
        })
    }

    async fn dispatch(&self, xml: &str) -> TestResult {
        dispatch(
            &self.context,
            &InboundPeer {
                local: "example.com".into(),
                remote: "remote.test".into(),
                connection_id: 1,
            },
            parsed(xml).await?,
        )
        .await
        .map_err(|_| "dispatch failed".into())
    }

    async fn finish(mut self) -> TestResult {
        self.work.drain().await;
        self.remote
            .finish(Instant::now() + Duration::from_secs(5))
            .await?;
        self.router.shutdown().await?;
        Ok(())
    }
}

fn account() -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    Ok(AccountKey::try_from(
        Jid::parse_in("bob@example.com", &mut arena)?.resolve(&arena)?,
    )?)
}

async fn parsed(xml: &str) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let input = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>{xml}"
    );
    let mut parser = XmppParser::new(
        input.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(65536).ok_or("size")?,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    );
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    match parser.next_event().await? {
        Some(StreamEvent::Stanza(stanza)) => Ok(RoutedStanza::from_parsed(stanza)),
        _ => Err("expected stanza".into()),
    }
}

fn default_text(condition: StanzaErrorCondition) -> &'static str {
    match condition.default_text() {
        StanzaErrorText::Static(text) => text,
        _ => panic!("expected static default text"),
    }
}

fn error_reply(
    fixture: &Fixture,
    to: &str,
    id: &str,
    condition: &str,
    text: &str,
) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    assert_eq!(fixture.remote.occupancy().0, 1);
    let reply = fixture.remote.receive()?.ok_or("missing reply")?;
    let view = reply.resolve()?;
    assert_eq!(view.namespace(), StanzaNamespace::Client);
    assert!(view.stanza_type().is_error());
    assert_eq!(view.from()?.ok_or("from")?.as_str(), to);
    assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@remote.test/desk");
    assert_eq!(view.id()?, Some(id));
    let error = view.child("error", "jabber:client")?.ok_or("error")?;
    assert!(
        error
            .child(condition, "urn:ietf:params:xml:ns:xmpp-stanzas")?
            .is_some()
    );
    assert_eq!(
        error
            .child("text", "urn:ietf:params:xml:ns:xmpp-stanzas")?
            .ok_or("text")?
            .text()?,
        Some(text)
    );
    assert_eq!(fixture.remote.occupancy(), (0, 0));
    Ok(reply)
}

#[test]
fn reply_eligibility_preserves_addresses_ids_and_payload() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let fixture = Fixture::new(Extensions::default(), &[])?;
        for (xml, bounceable) in [
            ("<message type='chat'><body>body</body></message>", true),
            ("<message/>", true),
            ("<message type='headline'/>", true),
            ("<message type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>", false),
            ("<iq type='get'><query xmlns='urn:test'/></iq>", true),
            ("<iq type='set'><query xmlns='urn:test'/></iq>", true),
            ("<iq type='result'/>", false),
            ("<iq type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>", false),
            ("<presence type='subscribe'/>", false),
            ("<presence type='subscribed'/>", false),
            ("<presence type='unsubscribe'/>", false),
            ("<presence type='unsubscribed'/>", false),
            ("<presence type='probe'/>", false),
            ("<presence type='unavailable'/>", false),
            ("<presence/>", false),
            ("<presence type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>", false),
        ] {
            let (prefix, tail) = xml.split_once('>').ok_or("element")?;
            let insertion = prefix.trim_end_matches('/');
            let ending = if prefix.ends_with('/') { "/>" } else { ">" };
            let stanza = parsed(&format!("{insertion} from='alice@remote.test/desk' to='bob@example.com/phone' id='reply'{ending}{tail}")).await?;
            let condition = StanzaErrorCondition::ServiceUnavailable;
            reply_error(&fixture.context, &stanza, condition, None, condition.default_text()).map_err(|_| "reply")?;
            assert_eq!(fixture.remote.occupancy().0, usize::from(bounceable));
            if bounceable {
                let response = error_reply(&fixture, "bob@example.com/phone", "reply", "service-unavailable", default_text(condition))?;
                let view = response.resolve()?;
                if xml.contains("body") { assert_eq!(view.child("body", "jabber:client")?.ok_or("body")?.text()?, Some("body")); }
                if xml.contains("query") { assert!(view.child("query", "urn:test")?.is_some()); }
            } else { assert!(fixture.remote.receive()?.is_none()); }
        }
        fixture.finish().await
    })
}

#[test]
fn reply_admission_failures_do_not_fail_completed_ingress() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let mut fixture = Fixture::new(Extensions::default(), &[])?;
        let stanza = parsed("<iq type='get' from='alice@remote.test/desk' to='example.com' id='admission'><query xmlns='urn:test'/></iq>").await?;
        let condition = StanzaErrorCondition::ServiceUnavailable;
        for _ in 0..2 {
            reply_error(&fixture.context, &stanza, condition, None, condition.default_text()).map_err(|_| "reply failed on full queue")?;
        }
        error_reply(&fixture, "example.com", "admission", "service-unavailable", default_text(condition))?;
        fixture.remote.finish(Instant::now() + Duration::from_secs(5)).await?;
        reply_error(&fixture.context, &stanza, condition, None, condition.default_text()).map_err(|_| "reply failed after stop")?;
        assert_eq!(fixture.remote.occupancy(), (0, 0));
        fixture.finish().await
    })
}

#[derive(Debug, PartialEq)]
enum Step {
    Policy,
    Archive,
    Observe(MessageOutcome, Vec<SessionId>, Option<ArchiveId>),
}

struct Messages {
    verdict: Verdict,
    archive_reject: bool,
    steps: PlMutex<Vec<Step>>,
}

impl Extension<GlobalChunkAllocator, RedbStorage> for Messages {
    fn name(&self) -> &'static str {
        "messages"
    }
    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.policy(self.clone());
        slots.archive(self.clone())?;
        slots.message_observer(self);
        Ok(())
    }
}

impl PolicyHandler<RedbStorage> for Messages {
    fn check<'a>(&'a self, request: PolicyRequest<'a>, _: &'a RedbRead) -> PolicyFuture<'a> {
        assert_eq!(request.account.as_str(), "bob@example.com");
        assert_eq!(request.peer.as_str(), "alice@remote.test/desk");
        assert_eq!(request.direction, Direction::Inbound);
        self.steps.lock().push(Step::Policy);
        Box::pin(async move { Ok(self.verdict) })
    }
}

impl ArchiveHandler<GlobalChunkAllocator, RedbStorage> for Messages {
    fn selects(&self, _: &ArchiveRequest<'_, GlobalChunkAllocator>) -> bool {
        true
    }
    fn archive<'a>(
        &'a self,
        request: ArchiveRequest<'a, GlobalChunkAllocator>,
        _: &'a mut RedbWrite,
        _: &'a mut Arena<GlobalChunkAllocator>,
    ) -> ArchiveFuture<'a> {
        assert_eq!(request.owner.as_str(), "bob@example.com");
        assert_eq!(request.peer.as_str(), "alice@remote.test/desk");
        assert_eq!(request.direction, ArchiveDirection::Received);
        self.steps.lock().push(Step::Archive);
        Box::pin(async move {
            if self.archive_reject {
                Err(HandlerError::described(
                    StanzaErrorCondition::NotAcceptable,
                    StanzaErrorText::Static("Archive rejected request."),
                ))
            } else {
                Ok(ArchiveOutcome::Archived(ArchiveId::new(7)))
            }
        })
    }
}

impl MessageObserver<GlobalChunkAllocator, RedbStorage> for Messages {
    fn observe<'a>(
        &'a self,
        event: MessageEvent<'a, GlobalChunkAllocator>,
        _: &'a RedbStorage,
        _: &'a dyn Delivery<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        assert_eq!(event.account.as_str(), "bob@example.com");
        assert_eq!(event.role, MessageRole::Received);
        assert!(event.rejection.is_none());
        let view = event.stanza.resolve();
        assert!(view.is_ok());
        let stamped = view.and_then(|view| view.child("stanza-id", "urn:xmpp:sid:0"));
        assert!(
            matches!(stamped, Ok(Some(stamp)) if stamp.attribute("id", "") == Ok(Some("7")) && stamp.attribute("by", "") == Ok(Some("bob@example.com")))
        );
        self.steps.lock().push(Step::Observe(
            event.outcome,
            event.holders.to_vec(),
            event.archived,
        ));
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn inbound_delivery_archives_and_observes_actual_holders_and_received_carbons() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let messages = Arc::new(Messages { verdict: Verdict::Allow, archive_reject: false, steps: PlMutex::new(Vec::new()) });
        let mut extensions = Extensions::default();
        extensions.register(messages.clone())?;
        extensions.register(Arc::new(lonewolf_extension::carbons::Carbons))?;
        let fixture = Fixture::new(extensions, &["messages", "carbons"])?;
        let owner = account()?;
        let phone = fixture.context.router.register(&owner, Some("phone"), NonZeroUsize::new(4).ok_or("capacity")?).await?;
        phone.handle().set_presence(Some(0), parsed("<presence from='bob@example.com/phone'/>").await?, None).await?;
        let sibling = fixture.context.router.register(&owner, Some("tablet"), NonZeroUsize::new(4).ok_or("capacity")?).await?;
        sibling.handle().tag(SessionTag::Carbons).await?;
        for target in ["bob@example.com", "bob@example.com/phone"] {
            messages.steps.lock().clear();
            fixture.dispatch(&format!("<message type='chat' from='alice@remote.test/desk' to='{target}' id='delivered'><body>Hello</body></message>")).await?;
            let delivered = phone.recv().await.ok_or("message")?;
            let view = delivered.stanza.resolve()?;
            assert_eq!(view.from()?.ok_or("from")?.as_str(), "alice@remote.test/desk");
            assert_eq!(view.to()?.ok_or("to")?.as_str(), target);
            assert_eq!(view.id()?, Some("delivered"));
            assert_eq!(view.child("body", "jabber:client")?.ok_or("body")?.text()?, Some("Hello"));
            let carbon = sibling.recv().await.ok_or("carbon")?;
            let copy = carbon.stanza.resolve()?;
            let received = copy.child("received", "urn:xmpp:carbons:2")?.ok_or("received")?;
            let forwarded = received.child("forwarded", "urn:xmpp:forward:0")?.ok_or("forwarded")?;
            let original = forwarded.child("message", "jabber:client")?.ok_or("original")?;
            assert_eq!(original.attribute("id", "")?, Some("delivered"));
            assert_eq!(original.attribute("from", "")?, Some("alice@remote.test/desk"));
            assert!(original.child("stanza-id", "urn:xmpp:sid:0")?.is_some());
            assert_eq!(*messages.steps.lock(), [Step::Policy, Step::Archive, Step::Observe(MessageOutcome::Routed, vec![phone.session_id()], Some(ArchiveId::new(7)))]);
            assert!(fixture.remote.receive()?.is_none());
            assert_eq!(fixture.remote.occupancy(), (0, 0));
        }
        drop(phone); drop(sibling);
        fixture.finish().await
    }))?
}

#[test]
fn policy_rejections_keep_application_and_text_and_drop_stops_later_stages() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        for (verdict, archive_reject) in [
            (Verdict::Reject { condition: StanzaErrorCondition::Forbidden, application: Some(ApplicationCondition { name: "blocked", namespace: "urn:test:policy" }), text: Some(StanzaErrorText::Static("Policy rejected request.")) }, false),
            (Verdict::Reject { condition: StanzaErrorCondition::Forbidden, application: None, text: None }, false),
            (Verdict::Drop, false),
            (Verdict::Allow, true),
        ] {
            for kind in ["chat", "headline", "error"] {
                let messages = Arc::new(Messages { verdict, archive_reject, steps: PlMutex::new(Vec::new()) });
                let mut extensions = Extensions::default(); extensions.register(messages.clone())?;
                let fixture = Fixture::new(extensions, &["messages"])?;
                let error = if kind == "error" { "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" } else { "" };
                fixture.dispatch(&format!("<message type='{kind}' from='alice@remote.test/desk' to='bob@example.com' id='policy'><body>payload</body>{error}</message>")).await?;
                let mut expected = vec![Step::Policy];
                if kind != "error" && (archive_reject || matches!(verdict, Verdict::Reject { .. })) {
                    let (condition, text) = if archive_reject { expected.push(Step::Archive); ("not-acceptable", "Archive rejected request.") } else if matches!(verdict, Verdict::Reject { text: Some(_), .. }) { ("forbidden", "Policy rejected request.") } else { ("forbidden", default_text(StanzaErrorCondition::Forbidden)) };
                    let reply = error_reply(&fixture, "bob@example.com", "policy", condition, text)?;
                    let error = reply.resolve()?.child("error", "jabber:client")?.ok_or("error")?;
                    assert_eq!(error.child("blocked", "urn:test:policy")?.is_some(), matches!(verdict, Verdict::Reject { application: Some(_), .. }));
                } else { assert!(fixture.remote.receive()?.is_none()); }
                assert_eq!(*messages.steps.lock(), expected);
                assert_eq!(fixture.remote.occupancy(), (0, 0));
                fixture.finish().await?;
            }
        }
        Ok(())
    })
}

#[test]
fn dispatch_uses_shared_delivery_outcomes_and_retains_interim_iq() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        for offline in [false, true] {
            let mut extensions = Extensions::default();
            if offline { extensions.register(Arc::new(lonewolf_extension::offline::Offline::new(BTreeMap::new())))?; }
            let fixture = Fixture::new(extensions, if offline { &["offline"] } else { &[] })?;
            for (element, kind, target, rejected) in [
                ("message", "chat", "bob@example.com", !offline),
                ("message", "groupchat", "bob@example.com", true),
                ("message", "error", "bob@example.com/missing", false),
                ("message", "headline", "bob@example.com", false),
                ("message", "headline", "example.com", false),
                ("message", "headline", "example.com/resource", true),
                ("iq", "get", "bob@example.com", true),
                ("iq", "set", "bob@example.com", true),
                ("iq", "result", "bob@example.com", false),
                ("iq", "error", "bob@example.com", false),
            ] {
                let payload = if element == "message" { "<body>payload</body>" } else { "<query xmlns='urn:test'/>" };
                let error = if kind == "error" { "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" } else { "" };
                fixture.dispatch(&format!("<{element} type='{kind}' from='alice@remote.test/desk' to='{target}' id='outcome'>{payload}{error}</{element}>")).await?;
                if rejected { error_reply(&fixture, target, "outcome", "service-unavailable", default_text(StanzaErrorCondition::ServiceUnavailable))?; }
                else { assert!(fixture.remote.receive()?.is_none()); }
                assert_eq!(fixture.remote.occupancy(), (0, 0));
            }
            fixture.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn discarded_and_rejected_delivery_emit_no_received_event() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        for kind in ["headline", "groupchat", "error"] {
            let messages = Arc::new(Messages { verdict: Verdict::Allow, archive_reject: false, steps: PlMutex::new(Vec::new()) });
            let mut extensions = Extensions::default(); extensions.register(messages.clone())?;
            let fixture = Fixture::new(extensions, &["messages"])?;
            let error = if kind == "error" { "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" } else { "" };
            fixture.dispatch(&format!("<message type='{kind}' from='alice@remote.test/desk' to='bob@example.com' id='unobserved'><body>payload</body>{error}</message>")).await?;
            if kind == "groupchat" { error_reply(&fixture, "bob@example.com", "unobserved", "service-unavailable", default_text(StanzaErrorCondition::ServiceUnavailable))?; }
            else { assert!(fixture.remote.receive()?.is_none()); }
            let expected = if kind == "error" { vec![Step::Policy] } else { vec![Step::Policy, Step::Archive] };
            assert_eq!(*messages.steps.lock(), expected);
            assert_eq!(fixture.remote.occupancy(), (0, 0));
            fixture.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn existing_offline_account_stores_before_received_observation() -> TestResult {
    use lonewolf_auth::scram::{
        SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
    };
    compio::runtime::Runtime::new()?.block_on(async {
        let messages = Arc::new(Messages { verdict: Verdict::Allow, archive_reject: false, steps: PlMutex::new(Vec::new()) });
        let mut extensions = Extensions::default();
        extensions.register(messages.clone())?;
        extensions.register(Arc::new(lonewolf_extension::offline::Offline::new(BTreeMap::new())))?;
        let fixture = Fixture::new(extensions, &["messages", "offline"])?;
        let mut transaction = fixture.context.storage.begin_write().await?;
        transaction.create_account(NewAccount { key: account()?, credentials: ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new([11; 16], SCRAM_POLICY_ITERATIONS, [12; 20], [13; 20]))) }).await?;
        transaction.commit().await?;
        fixture.dispatch("<message type='headline' from='alice@remote.test/desk' to='bob@example.com' id='headline'><body>offline headline</body></message>").await?;
        assert_eq!(fixture.context.storage.begin_read().await?.offline_count(&account()?).await?, 0);
        assert_eq!(*messages.steps.lock(), [Step::Policy, Step::Archive]);
        assert!(fixture.remote.receive()?.is_none());
        assert_eq!(fixture.remote.occupancy(), (0, 0));
        messages.steps.lock().clear();
        fixture.dispatch("<message type='chat' from='alice@remote.test/desk' to='bob@example.com' id='stored'><body>offline</body></message>").await?;
        assert_eq!(fixture.context.storage.begin_read().await?.offline_count(&account()?).await?, 1);
        assert_eq!(*messages.steps.lock(), [Step::Policy, Step::Archive, Step::Observe(MessageOutcome::Stored, vec![], Some(ArchiveId::new(7)))]);
        assert!(fixture.remote.receive()?.is_none());
        assert_eq!(fixture.remote.occupancy(), (0, 0));
        fixture.finish().await
    })
}

#[test]
fn domain_fields_omit_literals_and_bound_control_characters() {
    for domain in ["127.0.0.1", "::1", "[::1]", "2001:db8::1", "[2001:db8::1]"] {
        assert_eq!(log_domain(domain), "<literal>");
    }
    assert!(matches!(
        log_domain("peer.test"),
        std::borrow::Cow::Borrowed("peer.test")
    ));
    assert_eq!(log_domain("bad\nname\r"), "bad?name?");
    assert_eq!(log_domain(&"a".repeat(300)).len(), 253);
    assert_eq!(log_domain(&"é".repeat(300)).chars().count(), 253);
}

use futures_channel::oneshot;
use futures_util::poll;
use lonewolf_extension::Effects;
use lonewolf_extension::iq::{
    IqFuture, IqHandler, IqReply, IqRequest, IqRequestType, IqRoute, IqScope, Requester,
};
use lonewolf_extension::presence::{PresenceFuture, PresenceHandler, PresenceRequestType};
use lonewolf_storage::vcard::{VCardQuota, VCardReads, VCardWrites};
use lonewolf_xmpp::stanza::Stanza;
use std::sync::atomic::{AtomicUsize, Ordering};

type Gate = (oneshot::Sender<()>, oneshot::Receiver<()>);
type PolicySnapshot = (StanzaType, usize, Option<Box<str>>);

struct Iqs {
    verdict: Verdict,
    subscribed: bool,
    calls: AtomicUsize,
    effects: Arc<AtomicUsize>,
    policies: PlMutex<Vec<PolicySnapshot>>,
    visibility: PlMutex<Vec<(usize, Option<Box<str>>)>>,
    visibility_done: PlMutex<Option<oneshot::Sender<()>>>,
    policy_gate: PlMutex<Option<Gate>>,
    effect_gate: PlMutex<Option<Gate>>,
    bad_results: bool,
    additional: bool,
    fail_effect: bool,
}

impl Iqs {
    fn new(verdict: Verdict, subscribed: bool) -> Self {
        Self {
            verdict,
            subscribed,
            calls: AtomicUsize::new(0),
            effects: Arc::new(AtomicUsize::new(0)),
            policies: PlMutex::new(Vec::new()),
            visibility: PlMutex::new(Vec::new()),
            visibility_done: PlMutex::new(None),
            policy_gate: PlMutex::new(None),
            effect_gate: PlMutex::new(None),
            bad_results: false,
            additional: false,
            fail_effect: false,
        }
    }
}

impl Extension<GlobalChunkAllocator, RedbStorage> for Iqs {
    fn name(&self) -> &'static str {
        "iqs"
    }
    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        for kind in [IqRequestType::Get, IqRequestType::Set] {
            slots.iq_destination(
                lonewolf_extension::iq::IqRequestKey {
                    kind,
                    namespace: "urn:test:private",
                    name: "query",
                },
                lonewolf_extension::iq::IqDestinationRule::SenderBare,
            )?;
        }
        slots.policy(self.clone());
        slots.presence(PresenceRequestType::Available, self.clone())?;
        slots.presence(PresenceRequestType::Probe, self.clone())?;
        for scope in [IqScope::Account, IqScope::Server] {
            for kind in [IqRequestType::Get, IqRequestType::Set] {
                slots.iq(
                    IqRoute {
                        scope,
                        kind,
                        namespace: "urn:test:iq",
                        name: "query",
                    },
                    self.clone(),
                )?;
            }
        }
        Ok(())
    }
}

impl PolicyHandler<RedbStorage> for Iqs {
    fn check<'a>(
        &'a self,
        request: PolicyRequest<'a>,
        transaction: &'a RedbRead,
    ) -> PolicyFuture<'a> {
        Box::pin(async move {
            assert_eq!(request.account.as_str(), "bob@example.com");
            assert_eq!(request.peer.as_str(), "alice@remote.test/desk");
            assert_eq!(request.direction, Direction::Inbound);
            let card = transaction
                .vcard(request.account)
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .map(|card| card.xml);
            self.policies.lock().push((
                request.kind,
                std::ptr::from_ref(transaction) as usize,
                card,
            ));
            let gate = self.policy_gate.lock().take();
            if let Some((entered, release)) = gate {
                let _ = entered.send(());
                release
                    .await
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            }
            Ok(self.verdict)
        })
    }
}

impl PresenceHandler<GlobalChunkAllocator, RedbStorage> for Iqs {
    fn visibility<'a>(
        &'a self,
        owner: &'a AccountKey,
        observer: lonewolf_xmpp::jid::JidRef<'a>,
        transaction: &'a RedbRead,
    ) -> PresenceFuture<'a, bool> {
        Box::pin(async move {
            assert_eq!(owner.as_str(), "bob@example.com");
            assert_eq!(observer.as_str(), "alice@remote.test/desk");
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
            Ok(self.subscribed)
        })
    }
}

impl Iqs {
    fn answer(
        &self,
        request: IqRequest<'_, GlobalChunkAllocator>,
        response: &mut Arena<GlobalChunkAllocator>,
    ) -> Result<IqReply<GlobalChunkAllocator>, lonewolf_extension::iq::IqError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_ne!(request.requester, Some(Requester::Owner));
        let effects = Arc::clone(&self.effects);
        let gate = self.effect_gate.lock().take();
        let fail = self.fail_effect;
        let mut reply = IqReply::new(
            None,
            Effects {
                accounts: Vec::new(),
                deliver: Box::new(move |_| {
                    Box::pin(async move {
                        if let Some((entered, release)) = gate {
                            let _ = entered.send(());
                            release
                                .await
                                .map_err(|_| lonewolf_extension::delivery::DeliveryError)?;
                        }
                        effects.fetch_add(1, Ordering::SeqCst);
                        if fail {
                            Err(lonewolf_extension::delivery::DeliveryError)
                        } else {
                            Ok(())
                        }
                    })
                }),
            },
        );
        if self.bad_results || self.additional {
            for (index, target) in [
                request.sender.as_str(),
                if self.bad_results {
                    "alice@remote.test/wrong"
                } else {
                    request.sender.as_str()
                },
            ]
            .into_iter()
            .enumerate()
            {
                let to = Jid::parse_in(target, response)
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                let from = request
                    .target
                    .clone_in(response)
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                reply.results.push(
                    Stanza::builder_in(
                        StanzaType::Iq(IqType::Result),
                        StanzaNamespace::Client,
                        response,
                    )
                    .id(Some(if index == 0 {
                        "additional-first"
                    } else {
                        "additional-second"
                    }))
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?
                    .from(Some(from))
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?
                    .to(Some(to))
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?
                    .build()
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?,
                );
            }
        }
        Ok(reply)
    }
}

impl IqHandler<GlobalChunkAllocator, RedbStorage> for Iqs {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, GlobalChunkAllocator>,
        _: &'a RedbRead,
        response: &'a mut Arena<GlobalChunkAllocator>,
    ) -> IqFuture<'a, GlobalChunkAllocator> {
        Box::pin(async move { self.answer(request, response) })
    }
    fn set<'a>(
        &'a self,
        request: IqRequest<'a, GlobalChunkAllocator>,
        transaction: &'a mut RedbWrite,
        _: &'a dyn lonewolf_extension::delivery::HostLookup,
        response: &'a mut Arena<GlobalChunkAllocator>,
    ) -> IqFuture<'a, GlobalChunkAllocator> {
        Box::pin(async move {
            let mut arena = Arena::try_new(Default::default())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            let owner = AccountKey::try_from(
                Jid::parse_in("bob@example.com", &mut arena)
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?
                    .resolve(&arena)
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?,
            )
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            transaction
                .replace_vcard(
                    &owner,
                    "<vCard xmlns='vcard-temp'><FN>Committed</FN></vCard>",
                    VCardQuota::default(),
                )
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            self.answer(request, response)
        })
    }
}

async fn create_iq_account(fixture: &Fixture) -> TestResult {
    use lonewolf_auth::scram::{
        SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
    };
    let mut transaction = fixture.context.storage.begin_write().await?;
    transaction
        .create_account(NewAccount {
            key: account()?,
            credentials: ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
                [11; 16],
                SCRAM_POLICY_ITERATIONS,
                [12; 20],
                [13; 20],
            ))),
        })
        .await?;
    transaction.commit().await?;
    Ok(())
}

fn iq_xml(kind: &str, target: &str, payload: &str) -> String {
    format!(
        "<iq type='{kind}' from='alice@remote.test/desk' to='{target}' id='iq' xml:lang='fr'>{payload}</iq>"
    )
}

#[test]
fn inbound_iq_builtin_handlers_keep_remote_non_owner_rules() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(10), async {
        let mut extensions = Extensions::default();
        extensions.register(Arc::new(lonewolf_extension::disco::Disco))?;
        extensions.register(Arc::new(lonewolf_extension::ping::Ping))?;
        extensions.register(Arc::new(lonewolf_extension::vcard::VCard::default()))?;
        extensions.register(Arc::new(lonewolf_extension::roster::Roster::new(BTreeMap::new())))?;
        extensions.register(Arc::new(lonewolf_extension::carbons::Carbons))?;
        let fixture = Fixture::new(extensions, &["disco", "ping", "vcard", "roster", "carbons"])?;
        create_iq_account(&fixture).await?;
        for (kind, target, payload, result) in [
            ("get", "example.com", "<query xmlns='http://jabber.org/protocol/disco#info'/>", true),
            ("get", "example.com", "<query xmlns='http://jabber.org/protocol/disco#items'/>", true),
            ("get", "missing@example.com", "<query xmlns='http://jabber.org/protocol/disco#items'/>", true),
            ("get", "example.com", "<ping xmlns='urn:xmpp:ping'/>", true),
            ("get", "bob@example.com", "<query xmlns='http://jabber.org/protocol/disco#info'/>", false),
            ("get", "bob@example.com", "<ping xmlns='urn:xmpp:ping'/>", false),
            ("get", "bob@example.com", "<vCard xmlns='vcard-temp'/>", false),
            ("get", "bob@example.com", "<query xmlns='jabber:iq:roster'/>", false),
            ("set", "bob@example.com", "<enable xmlns='urn:xmpp:carbons:2'/>", false),
            ("get", "example.com", "<query xmlns='urn:unknown'/>", false),
        ] {
            fixture.dispatch(&iq_xml(kind, target, payload)).await?;
            let reply = fixture.remote.receive()?.ok_or("reply")?;
            let view = reply.resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Iq(if result { IqType::Result } else { IqType::Error }));
            assert_eq!(view.from()?.ok_or("from")?.as_str(), target);
            assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@remote.test/desk");
            assert_eq!(view.id()?, Some("iq"));
            if result && payload.contains("disco#items") { assert_eq!(view.child("query", "http://jabber.org/protocol/disco#items")?.ok_or("query")?.children()?.count(), 0); }
            if !result { assert!(view.child("error", "jabber:client")?.ok_or("error")?.child(if payload.contains("jabber:iq:roster") { "forbidden" } else { "service-unavailable" }, "urn:ietf:params:xml:ns:xmpp-stanzas")?.is_some()); }
        }
        let mut transaction = fixture.context.storage.begin_write().await?;
        transaction.replace_vcard(&account()?, "<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'><FN>Bob</FN></vCard>", VCardQuota::default()).await?;
        transaction.commit().await?;
        fixture.dispatch(&iq_xml("get", "bob@example.com", "<vCard xmlns='vcard-temp'/>")).await?;
        let reply = fixture.remote.receive()?.ok_or("vcard")?;
        assert_eq!(reply.resolve()?.child("vCard", "vcard-temp")?.ok_or("vcard")?.child("FN", "vcard-temp")?.ok_or("FN")?.text()?, Some("Bob"));
        {
            use lonewolf_storage::roster::{RosterItem, RosterJid, RosterQuota, RosterSubscription, RosterWrites, SubscriptionState};
            let mut arena = Arena::try_new(Default::default())?;
            let remote = Jid::parse_in("alice@remote.test", &mut arena)?;
            let mut transaction = fixture.context.storage.begin_write().await?;
            transaction.put_roster_item(&account()?, &RosterItem { jid: RosterJid::from(remote.resolve(&arena)?), name: None, groups: Vec::new(), subscription: RosterSubscription { state: SubscriptionState::From, pending_out: false, approved: false } }, RosterQuota::default()).await?;
            transaction.commit().await?;
        }
        for payload in ["<query xmlns='http://jabber.org/protocol/disco#info'/>", "<ping xmlns='urn:xmpp:ping'/>"] {
            fixture.dispatch(&iq_xml("get", "bob@example.com", payload)).await?;
            let reply = fixture.remote.receive()?.ok_or("subscribed reply")?;
            assert_eq!(reply.resolve()?.stanza_type(), StanzaType::Iq(IqType::Result));
        }
        for target in ["bob@example.com", "bob@example.com/phone"] {
            fixture.dispatch(&iq_xml("set", target, "<vCard xmlns='vcard-temp'><FN>Wrong</FN></vCard>")).await?;
            let reply = error_reply(&fixture, target, "iq", "forbidden", "This operation requires an omitted destination or your authenticated bare JID without a resource.")?;
            assert!(reply.resolve()?.child("vCard", "vcard-temp")?.is_none());
            assert_eq!(reply.resolve()?.lang()?, Some("fr"));
        }
        fixture.finish().await
    }))?
}

#[test]
fn inbound_iq_normalizes_one_recipient_policy_for_every_type_and_target() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(10), async {
        for verdict in [Verdict::Drop, Verdict::Reject { condition: StanzaErrorCondition::Forbidden, application: Some(ApplicationCondition { name: "blocked", namespace: "urn:test:policy" }), text: Some(StanzaErrorText::Static("Blocked IQ.")) }] {
            let handler = Arc::new(Iqs::new(verdict, true));
            let mut extensions = Extensions::default(); extensions.register(handler.clone())?;
            let fixture = Fixture::new(extensions, &["iqs"])?;
            for target in ["bob@example.com", "bob@example.com/phone"] {
                for (kind, typed) in [("get", IqType::Get), ("set", IqType::Set), ("result", IqType::Result), ("error", IqType::Error)] {
                    handler.policies.lock().clear();
                    let payload = if kind == "error" { "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" } else if kind == "result" { "" } else { "<query xmlns='urn:test:iq'/>" };
                    fixture.dispatch(&iq_xml(kind, target, payload)).await?;
                    assert_eq!(handler.policies.lock().len(), 1);
                    assert_eq!(handler.policies.lock()[0].0, StanzaType::Iq(typed));
                    assert!(handler.visibility.lock().is_empty());
                    assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
                    if matches!(typed, IqType::Get | IqType::Set) {
                        let condition = if verdict == Verdict::Drop { StanzaErrorCondition::ServiceUnavailable } else { StanzaErrorCondition::Forbidden };
                        let reply = error_reply(&fixture, target, "iq", if verdict == Verdict::Drop { "service-unavailable" } else { "forbidden" }, if verdict == Verdict::Drop { default_text(condition) } else { "Blocked IQ." })?;
                        if verdict != Verdict::Drop { assert!(reply.resolve()?.child("error", "jabber:client")?.ok_or("error")?.child("blocked", "urn:test:policy")?.is_some()); }
                    } else { assert!(fixture.remote.receive()?.is_none()); }
                }
            }
            fixture.finish().await?;
        }
        Ok(())
    }))?
}

#[test]
fn full_iq_policy_and_visibility_share_snapshot_and_wait_for_target_ticket() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(
        Duration::from_secs(5),
        async {
            let handler = Arc::new(Iqs::new(Verdict::Allow, true));
            let (entered, reached) = oneshot::channel();
            let (release, resume) = oneshot::channel();
            *handler.policy_gate.lock() = Some((entered, resume));
            let mut extensions = Extensions::default();
            extensions.register(handler.clone())?;
            let fixture = Fixture::new(extensions, &["iqs"])?;
            create_iq_account(&fixture).await?;
            let (visible, visibility_done) = oneshot::channel();
            *handler.visibility_done.lock() = Some(visible);
            let owner = account()?;
            let phone = fixture
                .context
                .router
                .register(&owner, Some("phone"), NonZeroUsize::MIN)
                .await?;
            let ((), blocker) = fixture
                .context
                .router
                .order()
                .fix(vec![owner.clone()], async { Ok::<_, IngressFailure>(()) })
                .await
                .map_err(|_| "ticket")?;
            let xml = iq_xml(
                "get",
                "bob@example.com/phone",
                "<query xmlns='urn:test:iq'/>",
            );
            let mut dispatch = Box::pin(fixture.dispatch(&xml));
            assert!(poll!(&mut dispatch).is_pending());
            match futures_util::future::select(reached, dispatch.as_mut()).await {
                futures_util::future::Either::Left((entered, _)) => entered?,
                futures_util::future::Either::Right(_) => {
                    return Err("dispatch preceded policy".into());
                }
            }
            let mut transaction = fixture.context.storage.begin_write().await?;
            transaction
                .replace_vcard(&owner, "<vCard xmlns='vcard-temp'/>", VCardQuota::default())
                .await?;
            transaction.commit().await?;
            release.send(()).map_err(|_| "policy cancelled")?;
            match futures_util::future::select(visibility_done, dispatch.as_mut()).await {
                futures_util::future::Either::Left((done, _)) => done?,
                futures_util::future::Either::Right(_) => {
                    return Err("dispatch preceded visibility".into());
                }
            }
            assert!(poll!(&mut dispatch).is_pending());
            assert_eq!(handler.visibility.lock().len(), 1);
            assert_eq!(handler.policies.lock()[0].1, handler.visibility.lock()[0].0);
            assert!(handler.visibility.lock()[0].1.is_none());
            assert!(phone.mailbox().take_queued().is_empty());
            drop(blocker);
            dispatch.await?;
            let delivered = phone.recv().await.ok_or("request")?;
            assert_eq!(
                delivered.stanza.resolve()?.stanza_type(),
                StanzaType::Iq(IqType::Get)
            );
            assert_eq!(
                delivered.stanza.resolve()?.to()?.ok_or("to")?.as_str(),
                "bob@example.com/phone"
            );
            assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
            assert!(fixture.remote.receive()?.is_none());
            drop(phone);
            fixture.finish().await
        },
    ))?
}

#[test]
fn full_iq_requests_map_unknown_and_full_mailbox_and_responses_are_silent() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(
        Duration::from_secs(5),
        async {
            let handler = Arc::new(Iqs::new(Verdict::Allow, true));
            let mut extensions = Extensions::default();
            extensions.register(handler.clone())?;
            let fixture = Fixture::new(extensions, &["iqs"])?;
            let phone = fixture
                .context
                .router
                .register(&account()?, Some("phone"), NonZeroUsize::MIN)
                .await?;
            fixture
                .dispatch(&iq_xml(
                    "get",
                    "bob@example.com/missing",
                    "<query xmlns='urn:test:iq'/>",
                ))
                .await?;
            error_reply(
                &fixture,
                "bob@example.com/missing",
                "iq",
                "service-unavailable",
                default_text(StanzaErrorCondition::ServiceUnavailable),
            )?;
            for _ in 0..64 {
                fixture
                    .dispatch(&iq_xml(
                        "get",
                        "bob@example.com/phone",
                        "<query xmlns='urn:test:iq'/>",
                    ))
                    .await?;
            }
            fixture
                .dispatch(&iq_xml(
                    "get",
                    "bob@example.com/phone",
                    "<query xmlns='urn:test:iq'/>",
                ))
                .await?;
            error_reply(
                &fixture,
                "bob@example.com/phone",
                "iq",
                "resource-constraint",
                default_text(StanzaErrorCondition::ResourceConstraint),
            )?;
            assert_eq!(phone.mailbox().take_queued().len(), 64);
            drop(phone);
            let phone = fixture
                .context
                .router
                .register(&account()?, Some("phone"), NonZeroUsize::MIN)
                .await?;
            for target in [
                "bob@example.com/phone",
                "bob@example.com",
                "bob@example.com/missing",
            ] {
                let before = handler.visibility.lock().len();
                fixture.dispatch(&iq_xml("result", target, "")).await?;
                assert_eq!(handler.visibility.lock().len(), before);
                if target == "bob@example.com/phone" {
                    assert_eq!(
                        phone
                            .recv()
                            .await
                            .ok_or("response")?
                            .stanza
                            .resolve()?
                            .stanza_type(),
                        StanzaType::Iq(IqType::Result)
                    );
                }
                assert!(fixture.remote.receive()?.is_none());
            }
            drop(phone);
            fixture.finish().await
        },
    ))?
}

#[test]
fn full_iq_responses_without_policies_need_no_visibility_and_ignore_stopped_router() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(Extensions::default(), &[])?;
        let phone = fixture.context.router.register(&account()?, Some("phone"), NonZeroUsize::MIN).await?;
        for _ in 0..65 { fixture.dispatch(&iq_xml("result", "bob@example.com/phone", "")).await?; }
        let delivered = phone.mailbox().take_queued();
        assert_eq!(delivered.len(), 64);
        assert!(delivered.iter().all(|entry| entry.stanza.resolve().map(|view| view.stanza_type()) == Ok(StanzaType::Iq(IqType::Result))));
        drop(phone);
        let Fixture { _directory, context, router, mut remote, mut work } = fixture;
        router.shutdown().await?;
        let peer = InboundPeer { local: "example.com".into(), remote: "remote.test".into(), connection_id: 1 };
        for kind in ["result", "error"] {
            let payload = if kind == "error" { "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" } else { "" };
            assert!(dispatch(&context, &peer, parsed(&iq_xml(kind, "bob@example.com/phone", payload)).await?).await.is_ok());
        }
        assert!(dispatch(&context, &peer, parsed(&iq_xml("get", "bob@example.com/phone", "<query xmlns='urn:test:iq'/>")).await?).await.is_err());
        work.drain().await;
        assert!(remote.receive()?.is_none());
        remote.finish(Instant::now()+Duration::from_secs(5)).await?;
        drop(_directory);
        Ok(())
    }))?
}

#[test]
fn sender_bare_precedes_recipient_policy_and_full_resource_forwarding() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let handler = Arc::new(Iqs::new(Verdict::Drop, true));
        let mut extensions = Extensions::default(); extensions.register(handler.clone())?;
        extensions.register(Arc::new(lonewolf_extension::vcard::VCard::default()))?;
        let fixture = Fixture::new(extensions, &["iqs", "vcard"])?;
        let phone = fixture.context.router.register(&account()?, Some("phone"), NonZeroUsize::MIN).await?;
        for target in ["bob@example.com", "bob@example.com/phone"] {
            fixture.dispatch(&iq_xml("set", target, "<vCard xmlns='vcard-temp'/>")).await?;
            let reply = error_reply(&fixture, target, "iq", "forbidden", "This operation requires an omitted destination or your authenticated bare JID without a resource.")?;
            assert_eq!(reply.resolve()?.children()?.count(), 1);
            assert_eq!(reply.resolve()?.lang()?, Some("fr"));
        }
        assert!(handler.policies.lock().is_empty());
        assert!(handler.visibility.lock().is_empty());
        assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
        assert!(phone.mailbox().take_queued().is_empty());
        drop(phone);
        fixture.finish().await
    })
}

#[test]
fn invalid_tail_result_suppresses_valid_prefix_after_get_and_committed_set() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let mut handler = Iqs::new(Verdict::Allow, true);
        handler.bad_results = true;
        let handler = Arc::new(handler);
        let mut extensions = Extensions::default();
        extensions.register(handler.clone())?;
        let fixture = Fixture::new(extensions, &["iqs"])?;
        create_iq_account(&fixture).await?;
        for kind in ["get", "set"] {
            fixture
                .dispatch(&iq_xml(kind, "example.com", "<query xmlns='urn:test:iq'/>"))
                .await?;
            error_reply(
                &fixture,
                "example.com",
                "iq",
                "internal-server-error",
                default_text(StanzaErrorCondition::InternalServerError),
            )?;
            assert!(fixture.remote.receive()?.is_none());
        }
        assert_eq!(handler.effects.load(Ordering::SeqCst), 2);
        assert!(
            fixture
                .context
                .storage
                .begin_read()
                .await?
                .vcard(&account()?)
                .await?
                .ok_or("committed")?
                .xml
                .contains("Committed")
        );
        fixture.finish().await
    })
}

#[test]
fn server_iq_set_waits_for_effects_and_keeps_committed_work_on_cancellation() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        for cancel in [false, true] {
            let handler = Arc::new(Iqs::new(Verdict::Allow, true));
            let (entered, reached) = oneshot::channel(); let (release, resume) = oneshot::channel();
            *handler.effect_gate.lock() = Some((entered, resume));
            let mut extensions = Extensions::default(); extensions.register(handler.clone())?;
            let mut fixture = Fixture::new(extensions, &["iqs"])?;
            create_iq_account(&fixture).await?;
            let xml = "<iq type='set' from='remote.test' to='example.com' id='server'><query xmlns='urn:test:iq'/></iq>";
            let mut pending = Box::pin(fixture.dispatch(xml));
            assert!(poll!(&mut pending).is_pending());
            match futures_util::future::select(reached, pending.as_mut()).await {
                futures_util::future::Either::Left((entered, _)) => entered?,
                futures_util::future::Either::Right(_) => return Err("reply preceded effects".into()),
            }
            assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
            assert_eq!(handler.effects.load(Ordering::SeqCst), 0);
            assert!(fixture.context.storage.begin_read().await?.vcard(&account()?).await?.ok_or("committed")?.xml.contains("Committed"));
            assert!(fixture.remote.receive()?.is_none());
            if cancel { drop(pending); } else {
                release.send(()).map_err(|_| "effect cancelled")?;
                pending.await?;
                let reply = fixture.remote.receive()?.ok_or("reply")?;
                assert_eq!(reply.resolve()?.stanza_type(), StanzaType::Iq(IqType::Result));
                assert_eq!(reply.resolve()?.to()?.ok_or("to")?.as_str(), "remote.test");
                fixture.work.drain().await;
                assert_iq_commits(&fixture, 2)?;
                assert_eq!(handler.effects.load(Ordering::SeqCst), 1);
                fixture.finish().await?;
                continue;
            }
            release.send(()).map_err(|_| "effect cancelled")?;
            fixture.work.drain().await;
            assert_iq_commits(&fixture, 2)?;
            assert_eq!(handler.effects.load(Ordering::SeqCst), 1);
            assert!(fixture.remote.receive()?.is_none());
            fixture.finish().await?;
        }
        Ok(())
    }))?
}

#[test]
fn server_iq_effect_failure_propagates_after_one_commit_without_account_sender() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let mut handler = Iqs::new(Verdict::Allow, false); handler.fail_effect = true;
        let handler = Arc::new(handler);
        let mut extensions = Extensions::default(); extensions.register(handler.clone())?;
        let mut fixture = Fixture::new(extensions, &["iqs"])?;
        create_iq_account(&fixture).await?;
        assert!(fixture.dispatch("<iq type='set' from='remote.test' to='example.com' id='server'><query xmlns='urn:test:iq'/></iq>").await.is_err());
        fixture.work.drain().await;
        assert_iq_commits(&fixture, 2)?;
        assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
        assert_eq!(handler.effects.load(Ordering::SeqCst), 1);
        assert!(fixture.context.storage.begin_read().await?.vcard(&account()?).await?.is_some());
        assert!(fixture.remote.receive()?.is_none());
        fixture.finish().await
    })
}

#[test]
fn full_iq_response_policy_keeps_target_ticket_without_visibility() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(
        Duration::from_secs(5),
        async {
            let handler = Arc::new(Iqs::new(Verdict::Allow, false));
            let (entered, reached) = oneshot::channel();
            let (release, resume) = oneshot::channel();
            *handler.policy_gate.lock() = Some((entered, resume));
            let mut extensions = Extensions::default();
            extensions.register(handler.clone())?;
            let fixture = Fixture::new(extensions, &["iqs"])?;
            let owner = account()?;
            let phone = fixture
                .context
                .router
                .register(&owner, Some("phone"), NonZeroUsize::MIN)
                .await?;
            let ((), blocker) = fixture
                .context
                .router
                .order()
                .fix(vec![owner], async { Ok::<_, IngressFailure>(()) })
                .await
                .map_err(|_| "ticket")?;
            let xml = iq_xml("result", "bob@example.com/phone", "");
            let mut pending = Box::pin(fixture.dispatch(&xml));
            match futures_util::future::select(reached, pending.as_mut()).await {
                futures_util::future::Either::Left((entered, _)) => entered?,
                futures_util::future::Either::Right(_) => {
                    return Err("response preceded policy".into());
                }
            }
            release.send(()).map_err(|_| "policy cancelled")?;
            assert!(poll!(&mut pending).is_pending());
            assert!(phone.mailbox().take_queued().is_empty());
            assert!(handler.visibility.lock().is_empty());
            drop(blocker);
            pending.await?;
            assert_eq!(
                phone
                    .recv()
                    .await
                    .ok_or("response")?
                    .stanza
                    .resolve()?
                    .stanza_type(),
                StanzaType::Iq(IqType::Result)
            );
            assert!(fixture.remote.receive()?.is_none());
            drop(phone);
            fixture.finish().await
        },
    ))?
}

#[test]
fn sender_bare_get_and_set_rules_precede_policy_and_handler_lookup() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let handler = Arc::new(Iqs::new(Verdict::Drop, true));
        let mut extensions = Extensions::default(); extensions.register(handler.clone())?;
        let fixture = Fixture::new(extensions, &["iqs"])?;
        for kind in ["get", "set"] {
            for target in ["bob@example.com", "bob@example.com/phone"] {
                fixture.dispatch(&iq_xml(kind, target, "<query xmlns='urn:test:private'/>")).await?;
                let reply = error_reply(&fixture, target, "iq", "forbidden", "This operation requires an omitted destination or your authenticated bare JID without a resource.")?;
                assert!(reply.resolve()?.child("query", "urn:test:private")?.is_none());
            }
        }
        assert!(handler.policies.lock().is_empty());
        assert!(handler.visibility.lock().is_empty());
        assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
        fixture.finish().await
    })
}

#[test]
fn additional_iq_results_keep_list_order_shared_arena_and_final_reply() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let mut handler = Iqs::new(Verdict::Allow, false);
        handler.additional = true;
        let handler = Arc::new(handler);
        let mut extensions = Extensions::default();
        extensions.register(handler.clone())?;
        let remote = RemoteFixture::with_capacity(
            AdmissionState::Link,
            NonZeroUsize::new(3).ok_or("capacity")?,
        )?;
        let router = Router::new(remote.hosts(), LocalRouter::new(GlobalChunkAllocator))
            .with_remote(remote.remote())
            .with_extensions(BTreeMap::from([(
                "example.com".into(),
                extensions.enable_host("example.com", ["iqs"])?,
            )]));
        let work = WorkGroup::new();
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let fixture = Fixture {
            _directory: directory,
            context: IngressContext {
                router: router.handle(),
                storage,
                allocator: GlobalChunkAllocator,
                work: work.handle(),
            },
            router,
            remote,
            work,
        };
        fixture
            .dispatch(&iq_xml(
                "get",
                "example.com",
                "<query xmlns='urn:test:iq'/>",
            ))
            .await?;
        assert_eq!(fixture.remote.occupancy().0, 3);
        let first = fixture.remote.receive()?.ok_or("first")?;
        let second = fixture.remote.receive()?.ok_or("second")?;
        let final_reply = fixture.remote.receive()?.ok_or("final")?;
        for (reply, id) in [
            (&first, "additional-first"),
            (&second, "additional-second"),
            (&final_reply, "iq"),
        ] {
            let view = reply.resolve()?;
            assert_eq!(view.id()?, Some(id));
            assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@remote.test/desk");
            assert_eq!(view.stanza_type(), StanzaType::Iq(IqType::Result));
        }
        assert_eq!(handler.effects.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.remote.occupancy(), (0, 0));
        fixture.finish().await
    })
}

#[test]
fn guarded_get_effects_finish_once_after_foreground_cancellation() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(
        Duration::from_secs(5),
        async {
            let handler = Arc::new(Iqs::new(Verdict::Allow, false));
            let (entered, reached) = oneshot::channel();
            let (release, resume) = oneshot::channel();
            *handler.effect_gate.lock() = Some((entered, resume));
            let mut extensions = Extensions::default();
            extensions.register(handler.clone())?;
            let mut fixture = Fixture::new(extensions, &["iqs"])?;
            let xml = iq_xml("get", "example.com", "<query xmlns='urn:test:iq'/>");
            let mut pending = Box::pin(fixture.dispatch(&xml));
            match futures_util::future::select(reached, pending.as_mut()).await {
                futures_util::future::Either::Left((entered, _)) => entered?,
                futures_util::future::Either::Right(_) => return Err("get preceded effects".into()),
            }
            drop(pending);
            assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
            assert_eq!(handler.effects.load(Ordering::SeqCst), 0);
            let mut drain = Box::pin(fixture.work.drain());
            assert!(poll!(&mut drain).is_pending());
            release.send(()).map_err(|_| "effect cancelled")?;
            drain.await;
            assert_eq!(handler.effects.load(Ordering::SeqCst), 1);
            assert!(fixture.remote.receive()?.is_none());
            fixture.finish().await
        },
    ))?
}

fn assert_iq_commits(fixture: &Fixture, count: u64) -> TestResult {
    let mut registry = prometheus_client::registry::Registry::default();
    registry.register(
        "commits",
        "Committed transactions.",
        fixture.context.storage.metrics().commit_duration().clone(),
    );
    let mut output = String::new();
    prometheus_client::encoding::text::encode(&mut output, &registry)?;
    assert!(
        output
            .lines()
            .any(|line| line == format!("commits_count {count}")),
        "{output}"
    );
    Ok(())
}

#[test]
fn inbound_presence_routes_available_unavailable_full_offline_and_errors() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let handler = Arc::new(Iqs::new(Verdict::Allow, false));
        let mut extensions = Extensions::default();
        extensions.register(handler.clone())?;
        let mut fixture = Fixture::new(extensions, &["iqs"])?;
        create_iq_account(&fixture).await?;
        let owner = account()?;
        let phone = fixture.context.router.register(&owner, Some("phone"), NonZeroUsize::new(8).ok_or("capacity")?).await?;
        let desk = fixture.context.router.register(&owner, Some("desk"), NonZeroUsize::new(8).ok_or("capacity")?).await?;
        for (registration, resource) in [(&phone, "phone"), (&desk, "desk")] {
            registration.handle().set_presence(Some(0), parsed(&format!("<presence from='bob@example.com/{resource}'/>")).await?, None).await?;
        }
        let sibling = phone.recv().await.ok_or("setup sibling presence")?;
        assert_eq!(sibling.stanza.resolve()?.from()?.ok_or("from")?.as_str(), "bob@example.com/desk");
        for kind in ["", " type='unavailable'"] {
            fixture.dispatch(&format!("<presence from='alice@remote.test/desk' to='bob@example.com'{kind}/>")).await?;
            for registration in [&phone, &desk] {
                let received = registration.recv().await.ok_or("presence")?;
                let view = received.stanza.resolve()?;
                assert_eq!(view.namespace(), StanzaNamespace::Client);
                assert_eq!(view.from()?.ok_or("from")?.as_str(), "alice@remote.test/desk");
                assert_eq!(view.to()?.ok_or("to")?.as_str(), "bob@example.com");
                assert_eq!(view.stanza_type(), StanzaType::Presence(if kind.is_empty() { PresenceType::Available } else { PresenceType::Unavailable }));
            }
        }
        fixture.dispatch("<presence from='alice@remote.test/desk' to='bob@example.com/phone'/>").await?;
        assert_eq!(phone.recv().await.ok_or("full presence")?.stanza.resolve()?.to()?.ok_or("to")?.as_str(), "bob@example.com/phone");
        assert!(desk.mailbox().take_queued().is_empty());
        fixture.dispatch("<presence type='error' from='alice@remote.test/desk' to='bob@example.com/phone'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>").await?;
        let error = phone.recv().await.ok_or("presence error")?;
        assert_eq!(error.stanza.resolve()?.stanza_type(), StanzaType::Presence(PresenceType::Error));
        assert_eq!(error.stanza.resolve()?.to()?.ok_or("to")?.as_str(), "bob@example.com/phone");
        for target in ["bob@example.com/missing", "example.com", "example.com/resource"] {
            fixture.dispatch(&format!("<presence from='alice@remote.test/desk' to='{target}'/>")).await?;
        }
        phone.handle().set_presence(None, parsed("<presence type='unavailable' from='bob@example.com/phone'/>").await?, None).await?;
        desk.handle().set_presence(None, parsed("<presence type='unavailable' from='bob@example.com/desk'/>").await?, None).await?;
        fixture.dispatch("<presence from='alice@remote.test/desk' to='bob@example.com'/>").await?;
        fixture.work.drain().await;
        assert!(phone.mailbox().take_queued().is_empty());
        assert!(desk.mailbox().take_queued().is_empty());
        assert!(fixture.remote.receive()?.is_none());
        assert_eq!(handler.policies.lock().len(), 5);
        assert!(handler.visibility.lock().is_empty());
        drop((phone, desk));
        fixture.finish().await
    })
}

#[test]
fn inbound_probes_preserve_authorization_availability_and_directed_privacy() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let handler = Arc::new(Iqs::new(Verdict::Allow, true));
        let mut extensions = Extensions::default();
        extensions.register(handler.clone())?;
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let remote = RemoteFixture::with_capacity(AdmissionState::Link, NonZeroUsize::new(8).ok_or("capacity")?)?;
        let router = Router::new(remote.hosts(), LocalRouter::new(GlobalChunkAllocator)).with_remote(remote.remote()).with_extensions(BTreeMap::from([("example.com".into(), extensions.enable_host("example.com", ["iqs"])?) ]));
        let work = WorkGroup::new();
        let fixture = Fixture { _directory: directory, context: IngressContext { router: router.handle(), storage, allocator: GlobalChunkAllocator, work: work.handle() }, router, remote, work };
        create_iq_account(&fixture).await?;
        let owner = account()?;
        fixture.dispatch("<presence type='probe' from='alice@remote.test/desk' to='bob@example.com' id='offline'/>").await?;
        let unavailable = fixture.remote.receive()?.ok_or("offline reply")?;
        let view = unavailable.resolve()?;
        assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Unavailable));
        assert_eq!(view.from()?.ok_or("from")?.as_str(), "bob@example.com");
        assert!(view.children()?.next().is_none());
        let phone = fixture.context.router.register(&owner, Some("phone"), NonZeroUsize::new(2).ok_or("resource limit")?).await?;
        let desk = fixture.context.router.register(&owner, Some("desk"), NonZeroUsize::new(2).ok_or("resource limit")?).await?;
        for (registration, resource) in [(&phone, "phone"), (&desk, "desk")] {
            registration.handle().set_presence(Some(0), parsed(&format!("<presence from='bob@example.com/{resource}' id='{resource}'><show>away</show><status>private</status></presence>")).await?, None).await?;
        }
        fixture.dispatch("<presence type='probe' from='alice@remote.test/desk' to='bob@example.com' id='bare'/>").await?;
        assert_eq!(fixture.remote.occupancy().0, 2);
        let mut senders = Vec::new();
        for _ in 0..2 {
            let stanza = fixture.remote.receive()?.ok_or("available reply")?;
            let view = stanza.resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Available));
            senders.push(view.from()?.ok_or("from")?.as_str().to_owned());
            assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@remote.test/desk");
            assert_eq!(view.child("status", "jabber:client")?.ok_or("status")?.text()?, Some("private"));
        }
        senders.sort();
        assert_eq!(senders, ["bob@example.com/desk", "bob@example.com/phone"]);
        fixture.dispatch("<presence type='probe' from='alice@remote.test/desk' to='bob@example.com/phone' id='full'/>").await?;
        let stanza = fixture.remote.receive()?.ok_or("full reply")?;
        let view = stanza.resolve()?;
        assert_eq!(view.from()?.ok_or("from")?.as_str(), "bob@example.com/phone");
        assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Available));
        assert_eq!(view.id()?, Some("phone"));
        assert!(view.children()?.next().is_none());
        for registration in [&phone, &desk] {
            registration.end_presence().await?;
        }
        drop((phone, desk));
        fixture.dispatch("<presence type='probe' from='alice@remote.test/desk' to='bob@example.com'/>").await?;
        let stanza = fixture.remote.receive()?.ok_or("last unavailable")?;
        let view = stanza.resolve()?;
        assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Unavailable));
        assert_eq!(view.from()?.ok_or("from")?.as_str(), "bob@example.com");
        assert!(view.child("delay", "urn:xmpp:delay")?.is_some());
        assert_eq!(handler.visibility.lock().len(), 4);
        fixture.finish().await?;

        let mut fixture = Fixture::new(Extensions::default(), &[])?;
        create_iq_account(&fixture).await?;
        let phone = fixture.context.router.register(&account()?, Some("phone"), NonZeroUsize::MIN).await?;
        phone.handle().set_presence(Some(0), parsed("<presence from='bob@example.com/phone'><status>secret</status></presence>").await?, None).await?;
        for target in ["bob@example.com", "missing@example.com"] {
            fixture.dispatch(&format!("<presence type='probe' from='alice@remote.test/desk' to='{target}'/>")).await?;
            let stanza = fixture.remote.receive()?.ok_or("unsubscribed")?;
            let view = stanza.resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Unsubscribed));
            assert_eq!(view.from()?.ok_or("from")?.as_str(), target);
            assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@remote.test/desk");
            assert!(view.children()?.next().is_none());
        }
        let directed = parsed("<presence from='alice@remote.test/desk'/>").await?;
        phone.handle().record_service_presence(directed.resolve()?.from()?.ok_or("from")?, true).await?;
        for target in ["bob@example.com", "bob@example.com/phone"] {
            fixture.dispatch(&format!("<presence type='probe' from='alice@remote.test/desk' to='{target}'/>")).await?;
            let stanza = fixture.remote.receive()?.ok_or("directed reply")?;
            let view = stanza.resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Available));
            assert_eq!(view.from()?.ok_or("from")?.as_str(), "bob@example.com/phone");
            assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@remote.test/desk");
            assert!(view.children()?.next().is_none());
        }
        fixture.work.drain().await;
        assert_eq!(fixture.remote.occupancy(), (0, 0));
        drop(phone);
        fixture.finish().await
    })
}

#[test]
fn inbound_presence_policy_drops_before_delivery_and_probe_admission() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        for verdict in [
            Verdict::Drop,
            Verdict::Reject {
                condition: StanzaErrorCondition::Forbidden,
                application: None,
                text: None,
            },
        ] {
            let handler = Arc::new(Iqs::new(verdict, true));
            let mut extensions = Extensions::default();
            extensions.register(handler.clone())?;
            let mut fixture = Fixture::new(extensions, &["iqs"])?;
            create_iq_account(&fixture).await?;
            let phone = fixture
                .context
                .router
                .register(&account()?, Some("phone"), NonZeroUsize::MIN)
                .await?;
            phone
                .handle()
                .set_presence(
                    Some(0),
                    parsed("<presence from='bob@example.com/phone'/>").await?,
                    None,
                )
                .await?;
            for target in ["bob@example.com", "bob@example.com/phone"] {
                for kind in ["", " type='unavailable'", " type='probe'"] {
                    fixture
                        .dispatch(&format!(
                            "<presence from='alice@remote.test/desk' to='{target}'{kind}/>"
                        ))
                        .await?;
                }
            }
            fixture.work.drain().await;
            assert!(phone.mailbox().take_queued().is_empty());
            assert!(fixture.remote.receive()?.is_none());
            assert_eq!(handler.policies.lock().len(), 6);
            assert_eq!(handler.visibility.lock().len(), 2);
            drop(phone);
            fixture.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn inbound_probe_visibility_and_policy_share_ordered_snapshot() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(
        Duration::from_secs(5),
        async {
            let handler = Arc::new(Iqs::new(Verdict::Allow, true));
            let (entered, reached) = oneshot::channel();
            let (release, resume) = oneshot::channel();
            *handler.policy_gate.lock() = Some((entered, resume));
            let mut extensions = Extensions::default();
            extensions.register(handler.clone())?;
            let mut fixture = Fixture::new(extensions, &["iqs"])?;
            create_iq_account(&fixture).await?;
            let owner = account()?;
            let ((), blocker) = fixture
                .context
                .router
                .order()
                .fix(vec![owner.clone()], async { Ok::<_, IngressFailure>(()) })
                .await
                .map_err(|_| "ticket")?;
            let mut dispatch = Box::pin(fixture.dispatch(
                "<presence type='probe' from='alice@remote.test/desk' to='bob@example.com'/>",
            ));
            match futures_util::future::select(reached, dispatch.as_mut()).await {
                futures_util::future::Either::Left((entered, _)) => entered?,
                futures_util::future::Either::Right(_) => {
                    return Err("dispatch preceded policy".into());
                }
            }
            assert_eq!(handler.visibility.lock().len(), 1);
            assert_eq!(handler.policies.lock()[0].1, handler.visibility.lock()[0].0);
            let mut transaction = fixture.context.storage.begin_write().await?;
            transaction
                .replace_vcard(&owner, "<vCard xmlns='vcard-temp'/>", VCardQuota::default())
                .await?;
            transaction.commit().await?;
            release.send(()).map_err(|_| "policy cancelled")?;
            assert!(poll!(&mut dispatch).is_pending());
            assert!(fixture.remote.receive()?.is_none());
            assert!(handler.visibility.lock()[0].1.is_none());
            assert!(handler.policies.lock()[0].2.is_none());
            drop(blocker);
            dispatch.await?;
            fixture.work.drain().await;
            let stanza = fixture.remote.receive()?.ok_or("reply after turn")?;
            assert_eq!(
                stanza.resolve()?.stanza_type(),
                StanzaType::Presence(PresenceType::Unavailable)
            );
            assert_eq!(fixture.remote.occupancy(), (0, 0));
            fixture.finish().await
        },
    ))?
}

#[test]
fn missing_probe_account_cannot_gain_visibility_and_subscriptions_are_dropped() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let handler = Arc::new(Iqs::new(Verdict::Allow, true));
        let mut extensions = Extensions::default();
        extensions.register(handler.clone())?;
        let mut fixture = Fixture::new(extensions, &["iqs"])?;
        fixture
            .dispatch("<presence type='probe' from='alice@remote.test/desk' to='bob@example.com'/>")
            .await?;
        let stanza = fixture.remote.receive()?.ok_or("missing-account reply")?;
        let view = stanza.resolve()?;
        assert_eq!(
            view.stanza_type(),
            StanzaType::Presence(PresenceType::Unsubscribed)
        );
        assert_eq!(view.from()?.ok_or("from")?.as_str(), "bob@example.com");
        assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@remote.test/desk");
        assert!(view.children()?.next().is_none());
        assert!(handler.visibility.lock().is_empty());
        assert_eq!(handler.policies.lock().len(), 1);
        for kind in ["subscribe", "subscribed", "unsubscribe", "unsubscribed"] {
            fixture
                .dispatch(&format!(
                    "<presence type='{kind}' from='alice@remote.test/desk' to='bob@example.com'/>"
                ))
                .await?;
        }
        fixture.work.drain().await;
        assert_eq!(handler.policies.lock().len(), 1);
        assert!(fixture.remote.receive()?.is_none());
        fixture.finish().await
    })
}
