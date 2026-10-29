// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use lonewolf_xmpp::stanza::StanzaNamespace;
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
