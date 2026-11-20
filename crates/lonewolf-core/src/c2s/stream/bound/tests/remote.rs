// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::s2s::outbound::{
    RemoteFailure,
    test_support::{AdmissionState, Fixture as RemoteFixture},
};
use lonewolf_extension::policy::{PolicyFuture, PolicyHandler, PolicyRequest};
use lonewolf_extension::{Extension, Extensions, RegistrationError, Slots};

use super::*;

#[derive(Debug, PartialEq)]
struct Check {
    account: String,
    peer: String,
    direction: Direction,
    kind: StanzaType,
}

struct Policy {
    verdict: Verdict,
    fail: bool,
    checks: PlMutex<Vec<Check>>,
}

impl Extension<GlobalChunkAllocator, RedbStorage> for Policy {
    fn name(&self) -> &'static str {
        "remote-policy"
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

impl PolicyHandler<RedbStorage> for Policy {
    fn check<'a>(&'a self, request: PolicyRequest<'a>, _: &'a RedbRead) -> PolicyFuture<'a> {
        self.checks.lock().push(Check {
            account: request.account.as_str().into(),
            peer: request.peer.as_str().into(),
            direction: request.direction,
            kind: request.kind,
        });
        Box::pin(async move {
            if self.fail {
                Err(HandlerError::described(
                    StanzaErrorCondition::NotAcceptable,
                    lonewolf_xmpp::stanza::StanzaErrorText::Static("Handler rejected request."),
                ))
            } else {
                Ok(self.verdict)
            }
        })
    }
}

async fn parsed(xml: &str) -> TestResult<Parsed<Stanza, GlobalChunkAllocator>> {
    let xml = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>{xml}"
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
    match parser.next_event().await? {
        Some(StreamEvent::Stanza(stanza)) => Ok(stanza),
        _ => Err("missing stanza".into()),
    }
}

async fn session<'a>(
    fixture: &'a Fixture,
    remote: &RemoteFixture,
    enabled: bool,
    policy: Option<Arc<Policy>>,
) -> TestResult<(
    Router<GlobalChunkAllocator>,
    BoundSession<'a, GlobalChunkAllocator, ControlledWriter>,
)> {
    let mut router = Router::new(remote.hosts(), LocalRouter::new(GlobalChunkAllocator));
    if enabled {
        router = router.with_remote(remote.remote());
    }
    if let Some(policy) = policy {
        let mut extensions = Extensions::default();
        extensions.register(policy)?;
        router = router.with_extensions(BTreeMap::from([(
            "example.com".into(),
            extensions.enable_host("example.com", ["remote-policy"])?,
        )]));
    }
    let mut arena = Arena::try_new(Default::default())?;
    let owner =
        AccountKey::try_from(Jid::parse_in("alice@example.com", &mut arena)?.resolve(&arena)?)?;
    let registration = router
        .handle()
        .register(&owner, Some("desk"), NonZeroUsize::new(4).ok_or("limit")?)
        .await?;
    let (_, incoming) = async_channel::bounded(1);
    let mut session = fixture.bound_session(
        GlobalChunkAllocator,
        registration,
        router.handle(),
        incoming,
    )?;
    session.outbox.account = owner;
    Ok((router, session))
}

fn rejection(application: bool, text: bool) -> Verdict {
    Verdict::Reject {
        condition: StanzaErrorCondition::Forbidden,
        application: application.then_some(ApplicationCondition {
            name: "blocked",
            namespace: "urn:test:policy",
        }),
        text: text.then_some(lonewolf_xmpp::stanza::StanzaErrorText::Static(
            "Policy rejected request.",
        )),
    }
}

const BLOCKING_ERRORS: &str = "urn:xmpp:blocking:errors";

fn assert_blocked<E: ArenaRead>(view: &StanzaRef<'_, E>) -> TestResult {
    let error = view
        .child("error", CLIENT_NAMESPACE)?
        .ok_or("missing error")?;
    assert_eq!(error.attribute("type", "")?, Some("cancel"));
    assert!(
        error
            .child("not-acceptable", "urn:ietf:params:xml:ns:xmpp-stanzas")?
            .is_some()
    );
    let blocked = error
        .child("blocked", BLOCKING_ERRORS)?
        .ok_or("missing blocked")?;
    assert_eq!(blocked.children()?.count(), 0);
    assert_eq!(blocked.attributes()?.count(), 0);
    Ok(())
}

#[test]
fn outbound_block_uses_cancel_without_changing_generic_not_acceptable() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        for verdict in [
            Verdict::Reject {
                condition: StanzaErrorCondition::NotAcceptable,
                application: None,
                text: None,
            },
            Verdict::OutboundBlocked,
        ] {
            let mut remote = RemoteFixture::new(AdmissionState::Link)?;
            let policy = Arc::new(Policy { verdict, fail: false, checks: PlMutex::new(Vec::new()) });
            let (router, mut session) = session(&fixture, &remote, true, Some(policy)).await?;
            let source = parsed("<message type='chat' from='ignored@example.com' to='bob@remote.test/phone' id='example-9' xml:lang='es'><body>Hola &amp; adiós</body></message>").await?;
            session.handle_stanza(source).await.map_err(|error| format!("{error:?}"))?;
            session.outbox.flush().await.map_err(|error| format!("{error:?}"))?;
            let [serialized] = session.outbox.writer.written.as_slice() else {
                return Err("expected one reply".into());
            };
            let reply = RoutedStanza::from_parsed(parsed(serialized).await?);
            let view = reply.resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Message(MessageType::Error));
            assert_eq!(view.from()?.ok_or("from")?.as_str(), "bob@remote.test/phone");
            assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@example.com/desk");
            assert_eq!(view.id()?, Some("example-9"));
            assert_eq!(view.lang()?, Some("es"));
            assert_eq!(view.child("body", CLIENT_NAMESPACE)?.ok_or("body")?.text()?, Some("Hola & adiós"));
            assert!(serialized.contains("Hola &amp; adiós"), "{serialized}");
            if verdict == Verdict::OutboundBlocked {
                assert_blocked(&view)?;
                assert!(serialized.contains("<blocked xmlns=\"urn:xmpp:blocking:errors\"/>"), "{serialized}");
            } else {
                let error = view.child("error", CLIENT_NAMESPACE)?.ok_or("missing error")?;
                assert_eq!(error.attribute("type", "")?, Some("modify"));
                assert!(error.child("not-acceptable", "urn:ietf:params:xml:ns:xmpp-stanzas")?.is_some());
                assert!(error.child("blocked", BLOCKING_ERRORS)?.is_none());
            }
            assert_eq!(remote.occupancy(), (0, 0));
            drop(session);
            remote.finish(Instant::now() + Duration::from_secs(5)).await?;
            router.shutdown().await?;
        }
        fixture.finish().await
    }))?
}

#[test]
fn outbound_blocked_iq_and_directed_presence_keep_the_requesting_resource() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let mut remote = RemoteFixture::new(AdmissionState::Link)?;
        let policy = Arc::new(Policy {
            verdict: Verdict::OutboundBlocked,
            fail: false,
            checks: PlMutex::new(Vec::new()),
        });
        let (router, mut session) = session(&fixture, &remote, true, Some(policy)).await?;
        let target = "bob@remote.test/phone";
        for (kind, answer) in [
            (StanzaType::Iq(IqType::Get), Some(StanzaType::Iq(IqType::Error))),
            (StanzaType::Iq(IqType::Set), Some(StanzaType::Iq(IqType::Error))),
            (StanzaType::Iq(IqType::Result), None),
            (StanzaType::Iq(IqType::Error), None),
            (StanzaType::Presence(PresenceType::Available), Some(StanzaType::Presence(PresenceType::Error))),
            (StanzaType::Presence(PresenceType::Unavailable), Some(StanzaType::Presence(PresenceType::Error))),
            (StanzaType::Presence(PresenceType::Subscribe), Some(StanzaType::Presence(PresenceType::Error))),
            (StanzaType::Presence(PresenceType::Subscribed), Some(StanzaType::Presence(PresenceType::Error))),
            (StanzaType::Presence(PresenceType::Unsubscribe), Some(StanzaType::Presence(PresenceType::Error))),
            (StanzaType::Presence(PresenceType::Unsubscribed), Some(StanzaType::Presence(PresenceType::Error))),
            (StanzaType::Presence(PresenceType::Probe), Some(StanzaType::Presence(PresenceType::Error))),
            (StanzaType::Message(MessageType::Error), None),
        ] {
            let name = kind.kind().as_str();
            let type_attr = kind.as_str().map_or_else(String::new, |value| format!(" type='{value}'"));
            let payload = match kind {
                StanzaType::Iq(_) => "<query xmlns='urn:test'/>",
                StanzaType::Presence(_) => "<status>test</status>",
                _ => "<body>test</body>",
            };
            let original_error = if kind.is_error() {
                "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
            } else { "" };
            let xml = format!("<{name}{type_attr} from='ignored@example.com' to='{target}' id='blocked' xml:lang='es'>{payload}{original_error}</{name}>");
            session.handle_stanza(parsed(&xml).await?).await.map_err(|error| format!("{kind:?}: {error:?}"))?;
            session.outbox.flush().await.map_err(|error| format!("{error:?}"))?;
            let replies = std::mem::take(&mut session.outbox.writer.written);
            if let Some(expected) = answer {
                let [serialized] = replies.as_slice() else { return Err(format!("expected one reply for {kind:?}").into()); };
                let reply = RoutedStanza::from_parsed(parsed(serialized).await?);
                let view = reply.resolve()?;
                assert_eq!(view.stanza_type(), expected, "{kind:?}");
                assert_eq!(view.id()?, Some("blocked"));
                assert_eq!(view.lang()?, Some("es"));
                assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@example.com/desk");
                assert_eq!(view.from()?.ok_or("from")?.as_str(), target);
                assert_blocked(&view)?;
            } else {
                assert!(replies.is_empty(), "{kind:?}");
            }
            assert!(remote.receive()?.is_none(), "{kind:?}");
        }
        drop(session);
        remote.finish(Instant::now() + Duration::from_secs(5)).await?;
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn outbound_block_hides_mutual_block() -> TestResult {
    use lonewolf_storage::blocking::{BlockChange, BlockingReads, BlockingWrites};
    use lonewolf_storage::roster::RosterJid;

    struct Blocklists;

    impl Extension<GlobalChunkAllocator, RedbStorage> for Blocklists {
        fn name(&self) -> &'static str {
            "test-blocklists"
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

    impl PolicyHandler<RedbStorage> for Blocklists {
        fn check<'a>(
            &'a self,
            request: PolicyRequest<'a>,
            transaction: &'a RedbRead,
        ) -> PolicyFuture<'a> {
            Box::pin(async move {
                if !transaction
                    .is_blocked(request.account, request.peer)
                    .await
                    .map_err(|_| HandlerError::from(StanzaErrorCondition::InternalServerError))?
                {
                    return Ok(Verdict::Allow);
                }
                Ok(match request.direction {
                    Direction::Outbound => Verdict::OutboundBlocked,
                    Direction::Inbound => Verdict::Reject {
                        condition: StanzaErrorCondition::ServiceUnavailable,
                        application: None,
                        text: None,
                    },
                })
            })
        }
    }

    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let mut arena = Arena::try_new(Default::default())?;
        let alice = Jid::parse_in("alice@localhost", &mut arena)?.resolve(&arena)?;
        let alice = AccountKey::try_from(alice)?;
        let bob = fixture.registration.account();
        let mut transaction = fixture.storage.begin_write().await?;
        transaction
            .create_account(NewAccount {
                key: alice.clone(),
                credentials: credentials(),
            })
            .await?;
        transaction
            .change_blocklist(&alice, BlockChange::Block(&[RosterJid::from(bob)]))
            .await?;
        transaction
            .change_blocklist(bob, BlockChange::Block(&[RosterJid::from(&alice)]))
            .await?;
        transaction.commit().await?;

        let mut extensions = Extensions::default();
        extensions.register(Arc::new(Blocklists))?;
        let router = Router::new(
            Hosts::new(&Config::default().hosts, None)?,
            LocalRouter::new(GlobalChunkAllocator),
        )
        .with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", ["test-blocklists"])?,
        )]));
        let handle = router.handle();
        let registration = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let recipient = handle
            .register(bob, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let (_, incoming) = async_channel::bounded(1);
        let mut session =
            fixture.bound_session(GlobalChunkAllocator, registration, handle, incoming)?;
        session.outbox.account = alice.clone();
        let chat =
            "<message type='chat' to='bob@localhost/phone' id='chat'><body>Hello</body></message>";
        for owner_block in [true, false] {
            if !owner_block {
                let mut transaction = fixture.storage.begin_write().await?;
                transaction
                    .change_blocklist(&alice, BlockChange::Unblock(&[RosterJid::from(bob)]))
                    .await?;
                transaction.commit().await?;
            }
            session
                .handle_stanza(parsed(chat).await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            session
                .outbox
                .flush()
                .await
                .map_err(|error| format!("{error:?}"))?;
            let serialized = std::mem::take(&mut session.outbox.writer.written);
            let [serialized] = serialized.as_slice() else {
                return Err("expected one reply".into());
            };
            let reply = RoutedStanza::from_parsed(parsed(serialized).await?);
            let view = reply.resolve()?;
            assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@localhost/desk");
            let error = view
                .child("error", CLIENT_NAMESPACE)?
                .ok_or("missing error")?;
            let unavailable =
                error.child("service-unavailable", "urn:ietf:params:xml:ns:xmpp-stanzas")?;
            if owner_block {
                assert_blocked(&view)?;
                assert!(unavailable.is_none());
            } else {
                assert!(unavailable.is_some());
                assert!(error.child("blocked", BLOCKING_ERRORS)?.is_none());
            }
            assert!(recipient.take_queued().is_empty());
        }
        drop(recipient);
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn remote_iq_policy_matrix_uses_authenticated_outbound_identity() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        for enabled in [true, false] {
            for kind in [IqType::Get, IqType::Set, IqType::Result, IqType::Error] {
                for mode in ["allow", "reject", "default_text", "drop", "failure", "no_policy"] {
                    let mut remote = RemoteFixture::new(AdmissionState::Link)?;
                    let policy = Arc::new(Policy { verdict: match mode { "reject" => rejection(true, true), "default_text" => rejection(true, false), "drop" => Verdict::Drop, _ => Verdict::Allow }, fail: mode == "failure", checks: PlMutex::new(Vec::new()) });
                    let (router, mut session) = session(&fixture, &remote, enabled, (mode != "no_policy").then(|| policy.clone())).await?;
                    let error = if kind == IqType::Error { "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" } else { "" };
                    let xml = format!("<iq type='{}' from='mallory@elsewhere/spy' to='bob@remote.test/phone' id='remote-iq'><query xmlns='urn:test'/>{error}</iq>", StanzaType::Iq(kind).as_str().ok_or("IQ type")?);
                    session.handle_iq(parsed(&xml).await?).await.map_err(|error| format!("{error:?}"))?;
                    session.outbox.flush().await.map_err(|error| format!("{error:?}"))?;
                    assert!(session.outbox.queue.is_empty());
                    {
                        let checks = policy.checks.lock();
                        if enabled && mode != "no_policy" {
                            assert_eq!(*checks, [Check { account: "alice@example.com".into(), peer: "bob@remote.test/phone".into(), direction: Direction::Outbound, kind: StanzaType::Iq(kind) }]);
                        } else { assert!(checks.is_empty()); }
                    }
                    let admitted = enabled && matches!(mode, "allow" | "no_policy");
                    if admitted {
                        let stanza = remote.receive()?.ok_or("IQ was not admitted")?;
                        let view = stanza.resolve()?;
                        assert_eq!(view.stanza_type(), StanzaType::Iq(kind));
                        assert_eq!(view.from()?.ok_or("from")?.as_str(), "alice@example.com/desk");
                        assert_eq!(view.to()?.ok_or("to")?.as_str(), "bob@remote.test/phone");
                        assert_eq!(view.id()?, Some("remote-iq"));
                        assert!(session.outbox.writer.written.is_empty());
                    } else if matches!(kind, IqType::Get | IqType::Set) {
                        assert_eq!(session.outbox.writer.written.len(), 1, "{enabled} {kind:?} {mode}");
                        let xml = &session.outbox.writer.written[0];
                        let reply = RoutedStanza::from_parsed(parsed(xml).await?);
                        let view = reply.resolve()?;
                        assert_eq!(view.stanza_type(), StanzaType::Iq(IqType::Error));
                        assert_eq!(view.id()?, Some("remote-iq"));
                        let error = view.child("error", "jabber:client")?.ok_or("missing error")?;
                        let condition = if !enabled { StanzaErrorCondition::RemoteServerNotFound } else { match mode { "drop" => StanzaErrorCondition::ServiceUnavailable, "failure" => StanzaErrorCondition::NotAcceptable, _ => StanzaErrorCondition::Forbidden } };
                        assert!(error.child(condition.as_str(), "urn:ietf:params:xml:ns:xmpp-stanzas")?.is_some(), "{xml}");
                        assert_eq!(error.child("blocked", "urn:test:policy")?.is_some(), enabled && matches!(mode, "reject" | "default_text"));
                        let text = error.child("text", "urn:ietf:params:xml:ns:xmpp-stanzas")?.ok_or("missing error text")?;
                        let expected = if enabled && mode == "reject" { "Policy rejected request." } else if enabled && mode == "failure" { "Handler rejected request." } else { match condition.default_text() { lonewolf_xmpp::stanza::StanzaErrorText::Static(text) => text, _ => return Err("unexpected dynamic error text".into()) } };
                        assert_eq!(text.text()?, Some(expected));
                    } else {
                        assert!(session.outbox.writer.written.is_empty(), "{enabled} {kind:?} {mode}");
                    }
                    assert!(remote.receive()?.is_none());
                    assert_eq!(remote.occupancy(), (0, 0));
                    drop(session);
                    remote.finish(Instant::now() + Duration::from_secs(5)).await?;
                    assert_eq!(remote.occupancy(), (0, 0));
                    router.shutdown().await?;
                }
            }
        }
        fixture.finish().await
    }))?
}

#[test]
fn remote_iq_admission_failures_answer_only_requests() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        for kind in [IqType::Get, IqType::Set, IqType::Result, IqType::Error] {
            for mode in ["busy", "not_found", "timeout", "stopped"] {
                let mut remote = RemoteFixture::new(match mode { "not_found" => AdmissionState::Backoff(RemoteFailure::NotFound), "timeout" => AdmissionState::Backoff(RemoteFailure::Timeout), _ => AdmissionState::Link })?;
                let (router, mut session) = session(&fixture, &remote, true, None).await?;
                if mode == "busy" {
                    router.handle().route_remote(RoutedStanza::from_parsed(parsed("<message from='alice@example.com/desk' to='bob@remote.test' id='filler'/>").await?))?;
                } else if mode == "stopped" { remote.remote().stop(); }
                let before = remote.occupancy();
                let error = if kind == IqType::Error { "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" } else { "" };
                let xml = format!("<iq type='{}' to='bob@remote.test' id='failure'><query xmlns='urn:test'/>{error}</iq>", StanzaType::Iq(kind).as_str().ok_or("IQ type")?);
                session.handle_iq(parsed(&xml).await?).await.map_err(|error| format!("{error:?}"))?;
                session.outbox.flush().await.map_err(|error| format!("{error:?}"))?;
                if matches!(kind, IqType::Get | IqType::Set) {
                    assert_eq!(session.outbox.writer.written.len(), 1);
                    let expected = match mode { "busy" => "resource-constraint", "not_found" => "remote-server-not-found", "timeout" => "remote-server-timeout", _ => "internal-server-error" };
                    assert!(session.outbox.writer.written[0].contains(expected));
                } else { assert!(session.outbox.writer.written.is_empty()); }
                assert_eq!(remote.occupancy(), before);
                if mode == "busy" { assert_eq!(remote.receive()?.ok_or("filler")?.resolve()?.id()?, Some("filler")); }
                assert_eq!(remote.occupancy(), (0, 0));
                drop(session);
                remote.finish(Instant::now() + Duration::from_secs(5)).await?;
                router.shutdown().await?;
            }
        }
        fixture.finish().await
    }))?
}

#[derive(Debug, PartialEq)]
enum MessageStep {
    Policy,
    Archive(
        String,
        lonewolf_extension::archive::ArchiveDirection,
        String,
    ),
    Observe(
        MessageRole,
        MessageOutcome,
        Vec<lonewolf_extension::delivery::SessionId>,
        Option<lonewolf_extension::archive::ArchiveId>,
    ),
}

struct Messages {
    verdict: Verdict,
    steps: PlMutex<Vec<MessageStep>>,
}

impl Extension<GlobalChunkAllocator, RedbStorage> for Messages {
    fn name(&self) -> &'static str {
        "remote-messages"
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
        assert_eq!(request.account.as_str(), "alice@example.com");
        assert_eq!(request.peer.as_str(), "bob@remote.test");
        assert_eq!(request.direction, Direction::Outbound);
        self.steps.lock().push(MessageStep::Policy);
        Box::pin(async move { Ok(self.verdict) })
    }
}

impl lonewolf_extension::archive::ArchiveHandler<GlobalChunkAllocator, RedbStorage> for Messages {
    fn selects(
        &self,
        _: &lonewolf_extension::archive::ArchiveRequest<'_, GlobalChunkAllocator>,
    ) -> bool {
        true
    }
    fn archive<'a>(
        &'a self,
        request: lonewolf_extension::archive::ArchiveRequest<'a, GlobalChunkAllocator>,
        _: &'a mut RedbWrite,
        _: &'a mut Arena<GlobalChunkAllocator>,
    ) -> lonewolf_extension::archive::ArchiveFuture<'a> {
        self.steps.lock().push(MessageStep::Archive(
            request.owner.as_str().into(),
            request.direction,
            request.peer.as_str().into(),
        ));
        Box::pin(async {
            Ok(lonewolf_extension::archive::ArchiveOutcome::Archived(
                lonewolf_extension::archive::ArchiveId::new(7),
            ))
        })
    }
}

impl lonewolf_extension::observer::MessageObserver<GlobalChunkAllocator, RedbStorage> for Messages {
    fn observe<'a>(
        &'a self,
        event: MessageEvent<'a, GlobalChunkAllocator>,
        _: &'a RedbStorage,
        _: &'a dyn lonewolf_extension::delivery::Delivery<GlobalChunkAllocator>,
    ) -> lonewolf_extension::delivery::DeliveryFuture<'a> {
        assert_eq!(event.account.as_str(), "alice@example.com");
        self.steps.lock().push(MessageStep::Observe(
            event.role,
            event.outcome,
            event.holders.to_vec(),
            event.archived,
        ));
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn remote_messages_keep_sender_policy_archive_sent_observers_and_carbons() -> TestResult {
    use lonewolf_extension::archive::ArchiveDirection;
    use lonewolf_extension::delivery::SessionTag;

    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        for kind in [MessageType::Chat, MessageType::Headline, MessageType::Error] {
            for verdict in [Verdict::Allow, rejection(true, true), Verdict::Drop] {
                let mut remote = RemoteFixture::new(AdmissionState::Link)?;
                let messages = Arc::new(Messages { verdict, steps: PlMutex::new(Vec::new()) });
                let mut extensions = Extensions::default();
                extensions.register(messages.clone())?;
                extensions.register(Arc::new(lonewolf_extension::carbons::Carbons))?;
                let router = Router::new(remote.hosts(), LocalRouter::new(GlobalChunkAllocator))
                    .with_remote(remote.remote())
                    .with_extensions(BTreeMap::from([("example.com".into(), extensions.enable_host("example.com", ["remote-messages", "carbons"])?)]));
                let mut arena = Arena::try_new(Default::default())?;
                let owner = AccountKey::try_from(Jid::parse_in("alice@example.com", &mut arena)?.resolve(&arena)?)?;
                let registration = router.handle().register(&owner, Some("desk"), NonZeroUsize::new(4).ok_or("limit")?).await?;
                let sender = registration.session_id();
                let sibling = router.handle().register(&owner, Some("phone"), NonZeroUsize::new(4).ok_or("limit")?).await?;
                sibling.handle().tag(SessionTag::Carbons).await?;
                let (_, incoming) = async_channel::bounded(1);
                let mut session = fixture.bound_session(GlobalChunkAllocator, registration, router.handle(), incoming)?;
                session.outbox.account = owner;
                let error = if kind == MessageType::Error { "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" } else { "" };
                let xml = format!("<message from='mallory@elsewhere/spy' to='bob@remote.test' type='{}' id='observed'><body>Hello</body>{error}</message>", StanzaType::Message(kind).as_str().ok_or("type")?);
                session.handle_message(parsed(&xml).await?, kind).await.map_err(|error| format!("{error:?}"))?;
                session.outbox.flush().await.map_err(|error| format!("{error:?}"))?;
                let mut expected = vec![MessageStep::Policy];
                if verdict == Verdict::Allow {
                    if kind != MessageType::Error { expected.push(MessageStep::Archive("alice@example.com".into(), ArchiveDirection::Sent, "bob@remote.test".into())); }
                    expected.push(MessageStep::Observe(MessageRole::Sent, MessageOutcome::Routed, vec![sender], (kind != MessageType::Error).then_some(lonewolf_extension::archive::ArchiveId::new(7))));
                    let delivered = remote.receive()?.ok_or("missing message")?;
                    let view = delivered.resolve()?;
                    assert_eq!(view.from()?.ok_or("from")?.as_str(), "alice@example.com/desk");
                    assert_eq!(view.stanza_type(), StanzaType::Message(kind));
                    assert!(view.child("stanza-id", "urn:xmpp:sid:0")?.is_none());
                    assert!(session.outbox.writer.written.is_empty());
                    let copies = sibling.take_queued();
                    if matches!(kind, MessageType::Chat | MessageType::Error) {
                        assert_eq!(copies.len(), 1);
                        let copy = copies[0].stanza.resolve()?;
                        let sent = copy.child("sent", "urn:xmpp:carbons:2")?.ok_or("missing sent carbon")?;
                        let forwarded = sent.child("forwarded", "urn:xmpp:forward:0")?.ok_or("forwarded")?;
                        let message = forwarded.child("message", "jabber:client")?.ok_or("message")?;
                        assert_eq!(message.attribute("from", "")?, Some("alice@example.com/desk"));
                        assert_eq!(message.attribute("to", "")?, Some("bob@remote.test"));
                        if kind == MessageType::Chat {
                            let archived = message.child("stanza-id", "urn:xmpp:sid:0")?.ok_or("missing sender archive stamp in carbon")?;
                            assert_eq!(archived.attribute("by", "")?, Some("alice@example.com"));
                            assert_eq!(archived.attribute("id", "")?, Some("7"));
                        } else {
                            assert!(message.child("stanza-id", "urn:xmpp:sid:0")?.is_none());
                            assert!(message.child("error", "jabber:client")?.is_some());
                        }
                    } else { assert!(copies.is_empty()); }
                } else {
                    assert!(sibling.take_queued().is_empty());
                    assert_eq!(session.outbox.writer.written.len(), usize::from(matches!(verdict, Verdict::Reject { .. }) && kind != MessageType::Error));
                }
                assert_eq!(*messages.steps.lock(), expected);
                assert!(remote.receive()?.is_none());
                assert_eq!(remote.occupancy(), (0, 0));
                drop(session);
                drop(sibling);
                remote.finish(Instant::now() + Duration::from_secs(5)).await?;
                router.shutdown().await?;
            }
        }
        fixture.finish().await
    }))?
}

#[test]
fn remote_client_probes_apply_normalized_owner_policy() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(10), async {
        let fixture = Fixture::new(&[]).await?;
        for enabled in [false, true] {
            for mode in ["allow", "reject", "drop", "failure"] {
                let mut remote = RemoteFixture::new(AdmissionState::Link)?;
                let policy = Arc::new(Policy { verdict: match mode { "reject" => rejection(false, false), "drop" => Verdict::Drop, _ => Verdict::Allow }, fail: mode == "failure", checks: PlMutex::new(Vec::new()) });
                let (router, mut session) = session(&fixture, &remote, enabled, Some(policy.clone())).await?;
                session.handle_probe(parsed("<presence type='probe' to='bob@remote.test/phone' from='mallory@third.test/spy' id='probe'/>").await?).await.map_err(|error| format!("{error:?}"))?;
                session.outbox.flush().await.map_err(|error| format!("{error:?}"))?;
                let expected = if enabled { vec![Check { account: "alice@example.com".into(), peer: "bob@remote.test/phone".into(), direction: Direction::Outbound, kind: StanzaType::Presence(PresenceType::Probe) }] } else { Vec::new() };
                assert_eq!(*policy.checks.lock(), expected);
                if enabled && mode == "allow" {
                    let stanza = remote.receive()?.ok_or("probe not admitted")?;
                    let view = stanza.resolve()?;
                    assert_eq!(view.from()?.ok_or("from")?.as_str(), "alice@example.com/desk");
                    assert_eq!(view.to()?.ok_or("to")?.as_str(), "bob@remote.test/phone");
                    assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Probe));
                }
                assert_eq!(session.outbox.writer.written.len(), usize::from(!enabled));
                if !enabled { assert!(session.outbox.writer.written[0].contains("remote-server-not-found")); }
                assert!(remote.receive()?.is_none());
                assert_eq!(remote.occupancy(), (0, 0));
                drop(session);
                remote.finish(Instant::now() + Duration::from_secs(5)).await?;
                router.shutdown().await?;
            }
        }
        fixture.finish().await
    }))?
}

#[test]
fn remote_client_probe_admission_failures_do_not_bounce() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(10), async {
        let fixture = Fixture::new(&[]).await?;
        for mode in ["busy", "not_found", "timeout", "stopped"] {
            let mut remote = RemoteFixture::new(match mode {
                "not_found" => AdmissionState::Backoff(RemoteFailure::NotFound),
                "timeout" => AdmissionState::Backoff(RemoteFailure::Timeout),
                _ => AdmissionState::Link,
            })?;
            let (router, mut session) = session(&fixture, &remote, true, None).await?;
            if mode == "busy" {
                router.handle().route_remote(RoutedStanza::from_parsed(
                    parsed(
                        "<message from='alice@example.com/desk' to='bob@remote.test' id='filler'/>",
                    )
                    .await?,
                ))?;
            }
            if mode == "stopped" {
                remote.remote().stop();
            }
            let before = remote.occupancy();
            let result = session
                .handle_probe(parsed("<presence type='probe' to='bob@remote.test'/>").await?)
                .await;
            assert_eq!(
                result,
                if mode == "stopped" {
                    Err(CloseOutcome::InternalError)
                } else {
                    Ok(())
                }
            );
            session
                .outbox
                .flush()
                .await
                .map_err(|error| format!("{error:?}"))?;
            assert!(session.outbox.writer.written.is_empty());
            assert_eq!(remote.occupancy(), before);
            if mode == "busy" {
                assert_eq!(
                    remote.receive()?.ok_or("filler")?.resolve()?.id()?,
                    Some("filler")
                );
            }
            assert_eq!(remote.occupancy(), (0, 0));
            drop(session);
            remote
                .finish(Instant::now() + Duration::from_secs(5))
                .await?;
            router.shutdown().await?;
        }
        fixture.finish().await
    }))?
}

struct ProbePolicy {
    fail: bool,
    checks: PlMutex<Vec<Check>>,
    snapshots: PlMutex<Vec<usize>>,
}

impl Extension<GlobalChunkAllocator, RedbStorage> for ProbePolicy {
    fn name(&self) -> &'static str {
        "probe-policy"
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

impl PolicyHandler<RedbStorage> for ProbePolicy {
    fn check<'a>(
        &'a self,
        request: PolicyRequest<'a>,
        transaction: &'a RedbRead,
    ) -> PolicyFuture<'a> {
        self.checks.lock().push(Check {
            account: request.account.as_str().into(),
            peer: request.peer.as_str().into(),
            direction: request.direction,
            kind: request.kind,
        });
        self.snapshots
            .lock()
            .push(std::ptr::from_ref(transaction) as usize);
        Box::pin(async move {
            Ok(
                if request.kind == StanzaType::Presence(PresenceType::Probe)
                    && request.peer.as_str() == "carol@remote.test"
                {
                    if self.fail {
                        return Err(StanzaErrorCondition::NotAcceptable.into());
                    }
                    rejection(false, false)
                } else {
                    Verdict::Allow
                },
            )
        })
    }
}

#[test]
fn initial_remote_probes_follow_broadcast_fifo_and_original_policy_snapshot() -> TestResult {
    use lonewolf_storage::roster::RosterJid;

    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(10), async {
        let fixture = Fixture::new(&[]).await?;
        for enabled in [false, true] {
            for mode in ["none", "reject", "handler"] {
                let policies = mode != "none";
                let mut remote = RemoteFixture::with_capacity(
                    AdmissionState::Link,
                    NonZeroUsize::new(8).ok_or("capacity")?,
                )?;
                let policy = Arc::new(ProbePolicy {
                    fail: mode == "handler",
                    checks: PlMutex::new(Vec::new()),
                    snapshots: PlMutex::new(Vec::new()),
                });
                let mut extensions = Extensions::default();
                extensions.register(policy.clone())?;
                let mut router =
                    Router::new(remote.hosts(), LocalRouter::new(GlobalChunkAllocator));
                if enabled {
                    router = router.with_remote(remote.remote());
                }
                if policies {
                    router = router.with_extensions(BTreeMap::from([(
                        "example.com".into(),
                        extensions.enable_host("example.com", ["probe-policy"])?,
                    )]));
                }
                let handle = router.handle();
                let mut arena = Arena::try_new(Default::default())?;
                let owner = AccountKey::try_from(
                    Jid::parse_in("alice@example.com", &mut arena)?.resolve(&arena)?,
                )?;
                let local = AccountKey::try_from(
                    Jid::parse_in("bob@example.com", &mut arena)?.resolve(&arena)?,
                )?;
                let bob = handle
                    .register(
                        &local,
                        Some("phone"),
                        NonZeroUsize::new(8).ok_or("capacity")?,
                    )
                    .await?;
                bob.handle()
                    .set_presence(
                        Some(0),
                        routed_presence("bob@example.com/phone", None, PresenceType::Available)?,
                        Some(routed_presence(
                            "bob@example.com/phone",
                            None,
                            PresenceType::Unavailable,
                        )?),
                    )
                    .await?;
                let registration = handle
                    .register(
                        &owner,
                        Some("desk"),
                        NonZeroUsize::new(8).ok_or("capacity")?,
                    )
                    .await?;
                for initial in [true, false] {
                    let routed =
                        routed_presence("alice@example.com/desk", None, PresenceType::Available)?;
                    let mut audience = PresenceAudience {
                        subscribers: ["bob@example.com", "bob@remote.test", "carol@remote.test"]
                            .into_iter()
                            .map(|jid| {
                                Ok(RosterJid::from(
                                    Jid::parse_in(jid, &mut arena)?.resolve(&arena)?,
                                ))
                            })
                            .collect::<TestResult<Vec<_>>>()?,
                        contacts: if initial {
                            vec![local.clone()]
                        } else {
                            Vec::new()
                        },
                        pending: None,
                        probes: if initial {
                            ["bob@remote.test", "carol@remote.test", "bob@example.com"]
                                .into_iter()
                                .map(|jid| {
                                    Ok(RosterJid::from(
                                        Jid::parse_in(jid, &mut arena)?.resolve(&arena)?,
                                    ))
                                })
                                .collect::<TestResult<Vec<_>>>()?
                        } else {
                            Vec::new()
                        },
                    };
                    let (transaction, mut ticket) = handle
                        .order()
                        .fix(vec![owner.clone()], fixture.storage.begin_read())
                        .await?;
                    let snapshot = std::ptr::from_ref(&transaction) as usize;
                    policy::filter_audience(
                        &handle,
                        &transaction,
                        &GlobalChunkAllocator,
                        &owner,
                        routed.resolve()?.from()?.ok_or("from")?,
                        StanzaType::Presence(PresenceType::Available),
                        &mut audience,
                    )
                    .await
                    .map_err(|_| "filter")?;
                    if policies {
                        assert!(
                            policy
                                .snapshots
                                .lock()
                                .iter()
                                .all(|pointer| *pointer == snapshot)
                        );
                    }
                    drop(transaction);
                    ticket.turn().await;
                    let outcome = PresenceWork {
                        session: registration.handle(),
                        router: handle.clone(),
                        storage: fixture.storage.clone(),
                        allocator: GlobalChunkAllocator,
                        work: fixture.work.handle(),
                        service_presence: None,
                        completion: None,
                        account: owner.clone(),
                        priority: Some(0),
                        available: true,
                        routed,
                        unavailable: Some(routed_presence(
                            "alice@example.com/desk",
                            None,
                            PresenceType::Unavailable,
                        )?),
                        audience: Some(audience),
                        backlog: None,
                    }
                    .run(ticket)
                    .await
                    .map_err(|error| format!("{error:?}"))?;
                    assert_eq!(outcome.change.became_available, initial);
                    assert_eq!(outcome.replay.len(), usize::from(initial));
                    assert_eq!(
                        outcome.echo.resolve()?.from()?.ok_or("echo from")?.as_str(),
                        "alice@example.com/desk"
                    );
                    if initial {
                        assert_eq!(
                            outcome.replay[0]
                                .resolve()?
                                .to()?
                                .ok_or("replay to")?
                                .as_str(),
                            "alice@example.com"
                        );
                    }
                    let local_delivery = bob.take_queued();
                    assert_eq!(local_delivery.len(), 1);
                    assert_eq!(
                        local_delivery[0]
                            .stanza
                            .resolve()?
                            .from()?
                            .ok_or("broadcast from")?
                            .as_str(),
                        "alice@example.com/desk"
                    );
                    let mut expected = Vec::new();
                    if enabled {
                        for target in ["bob@remote.test", "carol@remote.test"] {
                            expected.push((
                                PresenceType::Available,
                                "alice@example.com/desk",
                                target,
                            ));
                        }
                        if initial {
                            expected.push((
                                PresenceType::Probe,
                                "alice@example.com",
                                "bob@remote.test",
                            ));
                            if !policies {
                                expected.push((
                                    PresenceType::Probe,
                                    "alice@example.com",
                                    "carol@remote.test",
                                ));
                            }
                        }
                    }
                    assert_eq!(remote.occupancy().0, expected.len());
                    for (kind, from, to) in expected {
                        let stanza = remote.receive()?.ok_or("missing FIFO stanza")?;
                        let view = stanza.resolve()?;
                        assert_eq!(view.stanza_type(), StanzaType::Presence(kind));
                        assert_eq!(view.from()?.ok_or("from")?.as_str(), from);
                        assert_eq!(view.to()?.ok_or("to")?.as_str(), to);
                    }
                    assert!(remote.receive()?.is_none());
                    assert_eq!(remote.occupancy(), (0, 0));
                    let checks = std::mem::take(&mut *policy.checks.lock());
                    let probe_checks: Vec<_> = checks
                        .into_iter()
                        .filter(|check| check.kind == StanzaType::Presence(PresenceType::Probe))
                        .collect();
                    let expected = if policies && enabled && initial {
                        ["bob@remote.test", "carol@remote.test"]
                            .into_iter()
                            .map(|peer| Check {
                                account: "alice@example.com".into(),
                                direction: Direction::Outbound,
                                peer: peer.into(),
                                kind: StanzaType::Presence(PresenceType::Probe),
                            })
                            .collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    };
                    assert_eq!(probe_checks, expected);
                    policy.snapshots.lock().clear();
                }
                drop((registration, bob));
                remote
                    .finish(Instant::now() + Duration::from_secs(5))
                    .await?;
                router.shutdown().await?;
            }
        }
        fixture.finish().await
    }))?
}

#[test]
fn remote_directed_limits_explicit_and_terminal_withdrawals_use_real_queue() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(10), async {
        let fixture = Fixture::new(&[]).await?;
        for terminal in [false, true] {
            let mut remote = RemoteFixture::with_capacity(
                AdmissionState::Link,
                NonZeroUsize::new(8).ok_or("capacity")?,
            )?;
            let mut router = Router::new(
                remote.hosts(),
                LocalRouter::with_options(
                    GlobalChunkAllocator,
                    NonZeroUsize::new(2).ok_or("limit")?,
                    NonZeroUsize::MIN,
                ),
            )
            .with_remote(remote.remote());
            let policy = Arc::new(Policy {
                verdict: Verdict::Allow,
                fail: false,
                checks: PlMutex::new(Vec::new()),
            });
            let mut extensions = Extensions::default();
            extensions.register(policy.clone())?;
            router = router.with_extensions(BTreeMap::from([(
                "example.com".into(),
                extensions.enable_host("example.com", ["remote-policy"])?,
            )]));
            let handle = router.handle();
            let mut arena = Arena::try_new(Default::default())?;
            let owner = AccountKey::try_from(
                Jid::parse_in("alice@example.com", &mut arena)?.resolve(&arena)?,
            )?;
            let registration = handle
                .register(
                    &owner,
                    Some("desk"),
                    NonZeroUsize::new(8).ok_or("capacity")?,
                )
                .await?;
            let (_, incoming) = async_channel::bounded(1);
            let mut session = fixture.bound_session(
                GlobalChunkAllocator,
                registration,
                handle.clone(),
                incoming,
            )?;
            session.outbox.account = owner.clone();
            for target in [
                "bob@remote.test/phone",
                "carol@remote.test",
                "dave@remote.test",
            ] {
                session
                    .handle_directed(
                        parsed(&format!(
                            "<presence to='{target}' from='mallory@elsewhere/spy'/>"
                        ))
                        .await?,
                        true,
                    )
                    .await
                    .map_err(|error| format!("{error:?}"))?;
            }
            session
                .outbox
                .flush()
                .await
                .map_err(|error| format!("{error:?}"))?;
            assert_eq!(session.outbox.writer.written.len(), 1);
            assert!(session.outbox.writer.written[0].contains("resource-constraint"));
            assert_eq!(remote.occupancy().0, 2);
            for target in ["bob@remote.test/phone", "carol@remote.test"] {
                let stanza = remote.receive()?.ok_or("directed available")?;
                assert_eq!(stanza.resolve()?.to()?.ok_or("to")?.as_str(), target);
                assert_eq!(
                    stanza.resolve()?.from()?.ok_or("from")?.as_str(),
                    "alice@example.com/desk"
                );
            }
            session
                .handle_directed(
                    parsed("<presence type='unavailable' to='bob@remote.test/phone'/>").await?,
                    false,
                )
                .await
                .map_err(|error| format!("{error:?}"))?;
            let explicit = remote.receive()?.ok_or("explicit unavailable")?;
            assert_eq!(
                explicit.resolve()?.stanza_type(),
                StanzaType::Presence(PresenceType::Unavailable)
            );
            assert_eq!(
                explicit.resolve()?.to()?.ok_or("to")?.as_str(),
                "bob@remote.test/phone"
            );
            session
                .handle_directed(parsed("<presence to='dave@remote.test'/>").await?, true)
                .await
                .map_err(|error| format!("{error:?}"))?;
            assert_eq!(
                remote
                    .receive()?
                    .ok_or("new recipient")?
                    .resolve()?
                    .to()?
                    .ok_or("to")?
                    .as_str(),
                "dave@remote.test"
            );
            if terminal {
                TerminalPresenceWork {
                    session: session.registration.handle(),
                    router: handle.clone(),
                    storage: fixture.storage.clone(),
                    allocator: GlobalChunkAllocator,
                    work: fixture.work.handle(),
                    service_presence: None,
                    service_pending: None,
                    account: owner,
                    fallback: routed_presence(
                        "alice@example.com/desk",
                        None,
                        PresenceType::Unavailable,
                    )?,
                }
                .run()
                .await
                .map_err(|error| format!("{error:?}"))?;
            } else {
                session
                    .handle_availability(parsed("<presence type='unavailable'/>").await?, false)
                    .await
                    .map_err(|error| format!("{error:?}"))?;
                session
                    .outbox
                    .flush()
                    .await
                    .map_err(|error| format!("{error:?}"))?;
            }
            assert_eq!(remote.occupancy().0, 2);
            let mut withdrawn = Vec::new();
            for _ in 0..2 {
                let stanza = remote.receive()?.ok_or("withdrawal")?;
                let view = stanza.resolve()?;
                assert_eq!(
                    view.stanza_type(),
                    StanzaType::Presence(PresenceType::Unavailable)
                );
                assert_eq!(
                    view.from()?.ok_or("from")?.as_str(),
                    "alice@example.com/desk"
                );
                withdrawn.push(view.to()?.ok_or("to")?.as_str().to_owned());
            }
            withdrawn.sort_unstable();
            assert_eq!(withdrawn, ["carol@remote.test", "dave@remote.test"]);
            assert_eq!(policy.checks.lock().len(), 5);
            assert!(
                policy
                    .checks
                    .lock()
                    .iter()
                    .all(|check| check.account == "alice@example.com"
                        && check.direction == Direction::Outbound)
            );
            assert_eq!(remote.occupancy(), (0, 0));
            drop(session);
            remote
                .finish(Instant::now() + Duration::from_secs(5))
                .await?;
            assert_eq!(remote.snapshot().ready, 0);
            assert_eq!(remote.occupancy(), (0, 0));
            router.shutdown().await?;
        }
        fixture.finish().await
    }))?
}

#[test]
fn remote_presence_errors_and_trusted_snapshots_do_not_apply_policy() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(10), async {
        let fixture = Fixture::new(&[]).await?;
        let mut remote = RemoteFixture::with_capacity(AdmissionState::Link, NonZeroUsize::new(4).ok_or("capacity")?)?;
        let policy = Arc::new(Policy { verdict: Verdict::Drop, fail: true, checks: PlMutex::new(Vec::new()) });
        let (router, mut session) = session(&fixture, &remote, true, Some(policy.clone())).await?;
        session.handle_presence(parsed("<presence type='error' to='bob@remote.test/phone' from='mallory@third.test/spy'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>").await?, PresenceType::Error, true).await.map_err(|error| format!("{error:?}"))?;
        let error = remote.receive()?.ok_or("presence error")?;
        assert_eq!(error.resolve()?.stanza_type(), StanzaType::Presence(PresenceType::Error));
        assert_eq!(error.resolve()?.from()?.ok_or("from")?.as_str(), "alice@example.com/desk");
        session.registration.handle().set_presence(Some(0), routed_presence("alice@example.com/desk", None, PresenceType::Available)?, Some(routed_presence("alice@example.com/desk", None, PresenceType::Unavailable)?)).await?;
        let mut arena = Arena::try_new(Default::default())?;
        let target = AccountKey::try_from(Jid::parse_in("bob@remote.test", &mut arena)?.resolve(&arena)?)?;
        router.handle().route_current_presence(session.registration.account(), target.as_str(), crate::router::DeliveryScope::ComponentAware).await?;
        router.handle().route_unavailable_presence(session.registration.account(), target.as_str(), crate::router::DeliveryScope::ComponentAware).await?;
        for kind in [PresenceType::Available, PresenceType::Unavailable] {
            let stanza = remote.receive()?.ok_or("trusted snapshot")?;
            assert_eq!(stanza.resolve()?.stanza_type(), StanzaType::Presence(kind));
            assert_eq!(stanza.resolve()?.to()?.ok_or("to")?.as_str(), "bob@remote.test");
        }
        assert!(policy.checks.lock().is_empty());
        session.outbox.flush().await.map_err(|error| format!("{error:?}"))?;
        assert!(session.outbox.writer.written.is_empty());
        assert_eq!(remote.occupancy(), (0, 0));
        drop(session);
        remote.finish(Instant::now() + Duration::from_secs(5)).await?;
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn stopped_initial_broadcast_or_probe_releases_ticket_and_completion() -> TestResult {
    use lonewolf_storage::roster::RosterJid;

    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(10), async {
        let fixture = Fixture::new(&[]).await?;
        for broadcast_fails in [false, true] {
            let mut remote = RemoteFixture::with_capacity(
                AdmissionState::Link,
                NonZeroUsize::new(4).ok_or("capacity")?,
            )?;
            let (router, session) = session(&fixture, &remote, true, None).await?;
            let handle = router.handle();
            let mut arena = Arena::try_new(Default::default())?;
            let local = AccountKey::try_from(
                Jid::parse_in("bob@example.com", &mut arena)?.resolve(&arena)?,
            )?;
            let observer = handle
                .register(&local, Some("phone"), NonZeroUsize::MIN)
                .await?;
            observer
                .handle()
                .set_presence(
                    Some(0),
                    routed_presence("bob@example.com/phone", None, PresenceType::Available)?,
                    Some(routed_presence(
                        "bob@example.com/phone",
                        None,
                        PresenceType::Unavailable,
                    )?),
                )
                .await?;
            let target =
                RosterJid::from(Jid::parse_in("bob@remote.test", &mut arena)?.resolve(&arena)?);
            let mut subscribers = vec![RosterJid::from(&local)];
            if broadcast_fails {
                subscribers.push(target.clone());
            }
            let ((), mut ticket) = handle
                .order()
                .fix(vec![session.registration.account().clone()], async {
                    Ok::<_, RouterError>(())
                })
                .await?;
            ticket.turn().await;
            let (completion, completed) = oneshot::channel();
            remote.remote().stop();
            let result = PresenceWork {
                session: session.registration.handle(),
                router: handle.clone(),
                storage: fixture.storage.clone(),
                allocator: GlobalChunkAllocator,
                work: fixture.work.handle(),
                service_presence: None,
                completion: Some(completion),
                account: session.registration.account().clone(),
                priority: Some(0),
                available: true,
                routed: routed_presence("alice@example.com/desk", None, PresenceType::Available)?,
                unavailable: Some(routed_presence(
                    "alice@example.com/desk",
                    None,
                    PresenceType::Unavailable,
                )?),
                audience: Some(PresenceAudience {
                    subscribers,
                    contacts: Vec::new(),
                    pending: None,
                    probes: vec![target],
                }),
                backlog: None,
            }
            .run(ticket)
            .await;
            assert!(matches!(result, Err(CloseOutcome::InternalError)));
            assert!(completed.await.is_err());
            assert_eq!(observer.take_queued().len(), 1);
            let ((), mut after) = handle
                .order()
                .fix(vec![session.registration.account().clone()], async {
                    Ok::<_, RouterError>(())
                })
                .await?;
            after.turn().await;
            drop(after);
            assert_eq!(remote.occupancy(), (0, 0));
            drop((session, observer));
            remote
                .finish(Instant::now() + Duration::from_secs(5))
                .await?;
            router.shutdown().await?;
        }
        fixture.finish().await
    }))?
}

#[derive(Default)]
struct SubscriptionSender {
    calls: PlMutex<Vec<&'static str>>,
    sending: PlMutex<Option<SubscriptionSendGate>>,
}

type SubscriptionSendGate = (oneshot::Sender<()>, oneshot::Receiver<()>);

impl Extension<GlobalChunkAllocator, RedbStorage> for SubscriptionSender {
    fn name(&self) -> &'static str {
        "subscription-sender"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        for kind in [
            PresenceRequestType::Subscribe,
            PresenceRequestType::Subscribed,
            PresenceRequestType::Unsubscribe,
            PresenceRequestType::Unsubscribed,
        ] {
            slots.presence(kind, self.clone())?;
        }
        Ok(())
    }
}

impl lonewolf_extension::presence::PresenceHandler<GlobalChunkAllocator, RedbStorage>
    for SubscriptionSender
{
    fn authorize<'a>(
        &'a self,
        request: PresenceRequest<'a, GlobalChunkAllocator>,
    ) -> lonewolf_extension::presence::PresenceFuture<'a, ()> {
        assert_eq!(request.sender.as_str(), "alice@example.com/desk");
        assert_eq!(request.target.as_str(), "bob@remote.test/phone");
        self.calls.lock().push("authorize");
        Box::pin(async { Ok(()) })
    }

    fn send<'a>(
        &'a self,
        _: PresenceRequest<'a, GlobalChunkAllocator>,
        _: &'a mut RedbWrite,
        _: &'a dyn lonewolf_extension::delivery::HostLookup,
    ) -> lonewolf_extension::presence::SendFuture<'a, GlobalChunkAllocator> {
        self.calls.lock().push("send");
        let gate = self.sending.lock().take();
        Box::pin(async move {
            if let Some((entered, resume)) = gate {
                let _ = entered.send(());
                resume
                    .await
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            }
            Ok(PresenceSend::Continue)
        })
    }
}

async fn subscription_session<'a>(
    fixture: &'a Fixture,
    remote: &RemoteFixture,
    enabled: bool,
    mode: &str,
    policy: Arc<Policy>,
    sender: Arc<SubscriptionSender>,
) -> TestResult<(
    Router<GlobalChunkAllocator>,
    BoundSession<'a, GlobalChunkAllocator, ControlledWriter>,
)> {
    use lonewolf_extension::delivery::SessionTag;
    let mut extensions = Extensions::default();
    extensions.register(policy)?;
    extensions.register(sender)?;
    extensions.register(Arc::new(lonewolf_extension::roster::Roster::default()))?;
    let mut names = vec!["remote-policy"];
    if mode == "continue" {
        names.push("subscription-sender");
    }
    if mode == "roster" {
        names.push("roster");
    }
    let mut router = Router::new(remote.hosts(), LocalRouter::new(GlobalChunkAllocator))
        .with_extensions(BTreeMap::from([(
            "example.com".into(),
            extensions.enable_host("example.com", names)?,
        )]));
    if enabled {
        router = router.with_remote(remote.remote());
    }
    let mut arena = Arena::try_new(Default::default())?;
    let owner =
        AccountKey::try_from(Jid::parse_in("alice@example.com", &mut arena)?.resolve(&arena)?)?;
    let registration = router
        .handle()
        .register(
            &owner,
            Some("desk"),
            NonZeroUsize::new(8).ok_or("capacity")?,
        )
        .await?;
    registration.handle().tag(SessionTag::Interested).await?;
    let (_, incoming) = async_channel::bounded(1);
    let mut session = fixture.bound_session(
        GlobalChunkAllocator,
        registration,
        router.handle(),
        incoming,
    )?;
    session.outbox.account = owner;
    Ok((router, session))
}

#[test]
fn subscription_handoff_checks_the_original_session_after_sender_work() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let mut remote = RemoteFixture::new(AdmissionState::Link)?;
        let sender = Arc::new(SubscriptionSender::default());
        let (entered, waiting) = oneshot::channel();
        let (resume, released) = oneshot::channel();
        *sender.sending.lock() = Some((entered, released));
        let policy = Arc::new(Policy {
            verdict: Verdict::Allow,
            fail: false,
            checks: PlMutex::new(Vec::new()),
        });
        let (router, mut session) =
            subscription_session(&fixture, &remote, true, "continue", policy, sender.clone())
                .await?;
        let handle = router.handle();
        let owner = session.registration.account().clone();
        let original_jid = session.registration.full_jid();
        let retired = session.registration.wait_retired();
        let stanza = parsed("<presence type='subscribe' to='bob@remote.test/phone'/>").await?;
        let replacement;
        {
            let mut forwarding =
                pin!(session.handle_subscription(stanza, PresenceRequestType::Subscribe));
            match select(waiting, forwarding.as_mut()).await {
                Either::Left((entered, _)) => entered?,
                Either::Right(_) => return Err("subscription finished before sender work".into()),
            }
            handle.retire_account(&owner).await?;
            retired.await?;
            replacement = handle
                .register(&owner, Some("desk"), NonZeroUsize::MIN)
                .await?;
            assert_eq!(replacement.full_jid(), original_jid);
            resume.send(()).map_err(|_| "sender work canceled")?;
            forwarding.await.map_err(|error| format!("{error:?}"))?;
        }
        assert_eq!(*sender.calls.lock(), ["authorize", "send"]);
        assert_eq!(remote.occupancy(), (0, 0));
        assert!(remote.receive()?.is_none());
        drop((replacement, session));
        remote
            .finish(Instant::now() + Duration::from_secs(5))
            .await?;
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn remote_subscription_direct_branches_keep_policy_and_admission_errors() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(15), async {
        let fixture = Fixture::new(&[]).await?;
        for branch in ["none", "continue"] {
            for mode in ["allow", "reject", "drop", "busy", "not_found", "timeout", "stopped", "disabled"] {
                let mut remote = RemoteFixture::new(match mode {
                    "not_found" => AdmissionState::Backoff(RemoteFailure::NotFound),
                    "timeout" => AdmissionState::Backoff(RemoteFailure::Timeout),
                    _ => AdmissionState::Link,
                })?;
                let policy = Arc::new(Policy { verdict: match mode { "reject" => rejection(true, true), "drop" => Verdict::Drop, _ => Verdict::Allow }, fail: false, checks: PlMutex::new(Vec::new()) });
                let sender = Arc::new(SubscriptionSender::default());
                let (router, mut session) = subscription_session(&fixture, &remote, mode != "disabled", branch, policy.clone(), sender.clone()).await?;
                if mode == "busy" {
                    router.handle().route_remote(RoutedStanza::from_parsed(parsed("<message from='alice@example.com/desk' to='bob@remote.test' id='filler'/>").await?))?;
                }
                if mode == "stopped" { remote.remote().stop(); }
                let before = remote.occupancy();
                let result = session.handle_subscription(parsed("<presence type='subscribe' from='mallory@elsewhere/spy' to='bob@remote.test/phone' id='subscription'><status>Request</status></presence>").await?, PresenceRequestType::Subscribe).await;
                assert_eq!(result, if mode == "stopped" { Err(CloseOutcome::InternalError) } else { Ok(()) }, "{branch} {mode}");
                session.outbox.flush().await.map_err(|e| format!("{e:?}"))?;
                assert_eq!(*policy.checks.lock(), [Check { account: "alice@example.com".into(), peer: "bob@remote.test".into(), direction: Direction::Outbound, kind: StanzaType::Presence(PresenceType::Subscribe) }]);
                assert_eq!(*sender.calls.lock(), if branch == "continue" && !matches!(mode, "reject" | "drop") { vec!["authorize", "send"] } else { Vec::new() });
                if mode == "allow" {
                    let queued = remote.receive()?.ok_or("subscription not queued")?;
                    let view = queued.resolve()?;
                    assert_eq!(view.from()?.ok_or("from")?.as_str(), "alice@example.com");
                    assert_eq!(view.to()?.ok_or("to")?.as_str(), "bob@remote.test");
                    assert_eq!(view.id()?, Some("subscription"));
                    assert!(view.child("status", "jabber:client")?.is_some());
                    assert!(session.outbox.writer.written.is_empty());
                } else if matches!(mode, "stopped" | "drop" | "reject") {
                    assert!(session.outbox.writer.written.is_empty());
                    assert_eq!(remote.occupancy(), before);
                } else {
                    assert_eq!(session.outbox.writer.written.len(), 1, "{branch} {mode}");
                    let reply = RoutedStanza::from_parsed(parsed(&session.outbox.writer.written[0]).await?);
                    let view = reply.resolve()?;
                    assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Error));
                    assert_eq!(view.to()?.ok_or("reply to")?.as_str(), "alice@example.com/desk");
                    assert_eq!(view.from()?.ok_or("reply from")?.as_str(), "bob@remote.test/phone");
                    assert_eq!(view.id()?, Some("subscription"));
                    assert!(view.child("status", "jabber:client")?.is_some());
                    let error = view.child("error", "jabber:client")?.ok_or("error")?;
                    let condition = match mode { "busy" => StanzaErrorCondition::ResourceConstraint, "timeout" => StanzaErrorCondition::RemoteServerTimeout, _ => StanzaErrorCondition::RemoteServerNotFound };
                    assert!(error.child(condition.as_str(), "urn:ietf:params:xml:ns:xmpp-stanzas")?.is_some());
                    assert_eq!(error.attribute("type", "")?, Some(condition.error_type()));
                    let lonewolf_xmpp::stanza::StanzaErrorText::Static(expected_text) = condition.default_text() else { return Err("non-static default error text".into()); };
                    let text = error.child("text", "urn:ietf:params:xml:ns:xmpp-stanzas")?.ok_or("text")?;
                    assert_eq!(text.text()?, Some(expected_text));
                    assert_eq!(text.attribute("lang", "http://www.w3.org/XML/1998/namespace")?, Some("en"));
                    assert_eq!(remote.occupancy(), before);
                }
                if mode == "busy" { assert_eq!(remote.receive()?.ok_or("filler")?.resolve()?.id()?, Some("filler")); }
                assert_eq!(remote.occupancy(), (0, 0));
                drop(session);
                remote.finish(Instant::now() + Duration::from_secs(5)).await?;
                router.shutdown().await?;
            }
        }
        fixture.finish().await
    }))?
}

#[test]
fn remote_subscription_commits_pending_out_and_pushes_after_queue_admission() -> TestResult {
    use lonewolf_storage::roster::{RosterReads, SubscriptionState};
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(10), async {
        for enabled in [true, false] {
            let fixture = Fixture::new(&[]).await?;
            let mut remote = RemoteFixture::new(AdmissionState::Link)?;
            let policy = Arc::new(Policy {
                verdict: Verdict::Allow,
                fail: false,
                checks: PlMutex::new(Vec::new()),
            });
            let (router, mut session) = subscription_session(
                &fixture,
                &remote,
                enabled,
                "roster",
                policy,
                Arc::new(SubscriptionSender::default()),
            )
            .await?;
            let owner = session.registration.account().clone();
            let mut tx = fixture.storage.begin_write().await?;
            tx.create_account(NewAccount {
                key: owner.clone(),
                credentials: credentials(),
            })
            .await?;
            tx.commit().await?;
            session
                .handle_subscription(
                    parsed(
                        "<presence type='subscribe' to='bob@remote.test/phone' id='pending-out'/>",
                    )
                    .await?,
                    PresenceRequestType::Subscribe,
                )
                .await
                .map_err(|e| format!("{e:?}"))?;
            if enabled {
                let push = session
                    .registration
                    .recv()
                    .await
                    .ok_or("roster push mailbox")?;
                session
                    .outbox
                    .drain_mailbox(&session.registration, push)
                    .await
                    .map_err(|e| format!("{e:?}"))?;
            }
            session.outbox.flush().await.map_err(|e| format!("{e:?}"))?;
            let snapshot = fixture
                .storage
                .begin_read()
                .await?
                .roster(&owner, Default::default())
                .await?;
            assert_eq!(session.outbox.writer.written.len(), 1);
            if enabled {
                assert_eq!(snapshot.version.get(), 1);
                assert_eq!(snapshot.items.len(), 1);
                assert_eq!(snapshot.items[0].jid.as_str(), "bob@remote.test");
                assert_eq!(
                    snapshot.items[0].subscription.state,
                    SubscriptionState::None
                );
                assert!(snapshot.items[0].subscription.pending_out);
                assert!(!snapshot.items[0].subscription.approved);
                let stanza = remote.receive()?.ok_or("subscription admission")?;
                let view = stanza.resolve()?;
                assert_eq!(
                    view.stanza_type(),
                    StanzaType::Presence(PresenceType::Subscribe)
                );
                assert_eq!(view.from()?.ok_or("from")?.as_str(), "alice@example.com");
                assert_eq!(view.to()?.ok_or("to")?.as_str(), "bob@remote.test");
                assert_eq!(view.id()?, Some("pending-out"));
                let push =
                    RoutedStanza::from_parsed(parsed(&session.outbox.writer.written[0]).await?);
                let view = push.resolve()?;
                assert_eq!(
                    view.to()?.ok_or("push to")?.as_str(),
                    "alice@example.com/desk"
                );
                let item = view
                    .child("query", "jabber:iq:roster")?
                    .ok_or("query")?
                    .child("item", "jabber:iq:roster")?
                    .ok_or("item")?;
                assert_eq!(item.attribute("jid", "")?, Some("bob@remote.test"));
                assert_eq!(item.attribute("subscription", "")?, Some("none"));
                assert_eq!(item.attribute("ask", "")?, Some("subscribe"));
            } else {
                assert_eq!(snapshot.version.get(), 0);
                assert!(snapshot.items.is_empty());
                assert!(session.outbox.writer.written[0].contains("remote-server-not-found"));
            }
            assert_eq!(remote.occupancy(), (0, 0));
            drop(session);
            remote
                .finish(Instant::now() + Duration::from_secs(5))
                .await?;
            router.shutdown().await?;
            fixture.finish().await?;
        }
        Ok(())
    }))?
}

const PENDING_REQUEST: &[u8] =
    b"<presence xmlns='jabber:client' from='alice@localhost' to='bob@localhost' type='subscribe' id='pending'/>";

async fn pending_replay_fixture(stored: Option<&[u8]>, blocked: bool) -> TestResult<Fixture> {
    use lonewolf_extension::roster::Roster;
    use lonewolf_storage::roster::{PendingSubscription, RosterWrites};

    let mut fixture = Fixture::new(&[]).await?;
    if let Some(stanza) = stored {
        let mut arena = Arena::try_new(Default::default())?;
        let sender = Jid::parse_in("alice@localhost", &mut arena)?;
        let mut transaction = fixture.storage.begin_write().await?;
        transaction
            .put_pending_request(
                fixture.registration.account(),
                PendingSubscription {
                    sender: RosterJid::from(sender.resolve(&arena)?),
                    stanza: Box::from(stanza),
                },
                NonZeroUsize::MAX,
            )
            .await?;
        transaction.commit().await?;
    }
    let mut extensions = Extensions::default();
    extensions.register(Arc::new(Roster::default()))?;
    let mut enabled = vec!["roster"];
    if blocked {
        extensions.register(Arc::new(Policy {
            verdict: Verdict::Drop,
            fail: false,
            checks: PlMutex::new(Vec::new()),
        }))?;
        enabled.push("remote-policy");
    }
    fixture.router = fixture.router.with_extensions(BTreeMap::from([(
        "localhost".into(),
        extensions.enable_host("localhost", enabled)?,
    )]));
    Ok(fixture)
}

async fn pending_replay_session<'a>(
    fixture: &'a Fixture,
    metrics: &crate::c2s::metrics::C2sMetrics,
) -> TestResult<BoundSession<'a, GlobalChunkAllocator, ControlledWriter>> {
    let router = fixture.router.handle();
    let registration = router
        .register(
            fixture.registration.account(),
            Some("desk"),
            NonZeroUsize::new(2).ok_or("mailbox capacity")?,
        )
        .await?;
    let (_sender, incoming) = async_channel::bounded(1);
    let mut session =
        fixture.bound_session(GlobalChunkAllocator, registration, router, incoming)?;
    session.outbox.metrics = metrics.worker(0, 0);
    Ok(session)
}

fn assert_pending_replay_counters(
    metrics: &Arc<crate::c2s::metrics::C2sMetrics>,
    bytes: usize,
    blocked: usize,
    delivered: usize,
) -> TestResult {
    let body = metrics.render()?;
    for sample in [
        r#"lonewolf_c2s_replay_pages_total{listener="0",kind="subscription_request"} 1"#.to_owned(),
        format!(
            r#"lonewolf_c2s_replay_bytes_total{{listener="0",kind="subscription_request"}} {bytes}"#
        ),
        format!(
            r#"lonewolf_c2s_replay_records_total{{listener="0",kind="subscription_request",outcome="delivered"}} {delivered}"#
        ),
        format!(
            r#"lonewolf_c2s_replay_records_total{{listener="0",kind="subscription_request",outcome="blocked"}} {blocked}"#
        ),
    ] {
        assert!(body.lines().any(|line| line == sample), "{body}");
    }
    Ok(())
}

#[test]
fn initial_empty_pending_page_counts_once_and_presence_update_does_not_read() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = pending_replay_fixture(None, false).await?;
        let metrics = crate::c2s::metrics::C2sMetrics::detached();
        let mut session = pending_replay_session(&fixture, &metrics).await?;

        for xml in ["<presence id='initial'/>", "<presence id='update'/>"] {
            session
                .handle_availability(parsed(xml).await?, true)
                .await
                .map_err(|error| format!("{error:?}"))?;
            session
                .outbox
                .flush()
                .await
                .map_err(|error| format!("{error:?}"))?;
            assert_pending_replay_counters(&metrics, 0, 0, 0)?;
        }
        assert_eq!(session.outbox.writer.written.len(), 2);
        for (xml, id) in session
            .outbox
            .writer
            .written
            .iter()
            .zip(["initial", "update"])
        {
            let stanza = parsed(xml).await?;
            assert_eq!(stanza.value().resolve(stanza.arena())?.id()?, Some(id));
        }
        drop(session);
        fixture.finish().await
    })
}

#[test]
fn completely_blocked_pending_page_counts_its_bytes_and_blocked_records() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = pending_replay_fixture(Some(PENDING_REQUEST), true).await?;
        let metrics = crate::c2s::metrics::C2sMetrics::detached();
        let mut session = pending_replay_session(&fixture, &metrics).await?;

        session
            .handle_availability(parsed("<presence id='echo'/>").await?, true)
            .await
            .map_err(|error| format!("{error:?}"))?;
        session
            .outbox
            .flush()
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(session.outbox.writer.written.len(), 1);
        let echo = parsed(&session.outbox.writer.written[0]).await?;
        assert_eq!(echo.value().resolve(echo.arena())?.id()?, Some("echo"));
        assert_pending_replay_counters(&metrics, PENDING_REQUEST.len(), 1, 0)?;
        drop(session);
        fixture.finish().await
    })
}

#[test]
fn first_pending_page_is_counted_when_the_presence_echo_write_fails() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = pending_replay_fixture(Some(PENDING_REQUEST), false).await?;
        let metrics = crate::c2s::metrics::C2sMetrics::detached();
        let mut session = pending_replay_session(&fixture, &metrics).await?;
        session.outbox.writer.fail_write = true;

        session
            .handle_availability(parsed("<presence id='echo'/>").await?, true)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            session.outbox.flush().await,
            Err(CloseOutcome::TransportError)
        );
        assert!(session.outbox.writer.written.is_empty());
        assert_pending_replay_counters(&metrics, PENDING_REQUEST.len(), 0, 0)?;
        drop(session);
        fixture.finish().await
    })
}

#[test]
fn retired_session_stops_pending_replay_before_the_next_page() -> TestResult {
    use lonewolf_storage::roster::{PendingSubscription, RosterReads, RosterWrites};

    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let close = b"</status></presence>";
        let mut first = b"<presence xmlns='jabber:client' from='alice@localhost' to='bob@localhost' type='subscribe' id='pending'><status>".to_vec();
        first.resize(REPLAY_PAGE_BYTES.get() - close.len(), b'x');
        first.extend_from_slice(close);

        let fixture = pending_replay_fixture(Some(&first), false).await?;
        let account = fixture.registration.account();
        let mut arena = Arena::try_new(Default::default())?;
        let charlie = Jid::parse_in("charlie@localhost", &mut arena)?;
        let zoe = Jid::parse_in("zoe@localhost", &mut arena)?;
        let charlie = RosterJid::from(charlie.resolve(&arena)?);
        let zoe = RosterJid::from(zoe.resolve(&arena)?);
        let mut transaction = fixture.storage.begin_write().await?;
        transaction.put_pending_request(
            account,
            PendingSubscription {
                sender: charlie,
                stanza: Box::from(b"<presence xmlns='jabber:client' from='charlie@localhost' to='bob@localhost' type='subscribe' id='second'/>".as_slice()),
            },
            NonZeroUsize::MAX,
        ).await?;
        transaction.commit().await?;

        let metrics = crate::c2s::metrics::C2sMetrics::detached();
        let mut session = pending_replay_session(&fixture, &metrics).await?;
        session.handle_availability(parsed("<presence id='echo'/>").await?, true).await
            .map_err(|error| format!("{error:?}"))?;
        let (entered, writing) = oneshot::channel();
        let (release, paused) = oneshot::channel();
        session.outbox.writer.partial_after = 1;
        session.outbox.writer.partial_entered = Some(entered);
        session.outbox.writer.partial_release = Some(paused);
        let liveness = session.registration.liveness();
        let recreated = PendingSubscription {
            sender: zoe,
            stanza: Box::from(b"<presence xmlns='jabber:client' from='zoe@localhost' to='bob@localhost' type='subscribe' id='recreated'/>".as_slice()),
        };

        let recreate = async {
            writing.await?;
            let mut transaction = fixture.storage.begin_write().await?;
            transaction.clear_roster(account).await?;
            transaction.delete_account(account).await?;
            transaction.commit().await?;
            fixture.router.handle().retire_account(account).await?;
            assert!(!liveness.is_alive());

            let mut transaction = fixture.storage.begin_write().await?;
            transaction.create_account(NewAccount {
                key: account.clone(),
                credentials: credentials(),
            }).await?;
            transaction.put_pending_request(account, recreated.clone(), NonZeroUsize::MAX).await?;
            transaction.commit().await?;
            release.send(()).map_err(|_| "first page write ended before release")?;
            Ok::<_, Box<dyn Error>>(())
        };
        let (replay, recreation) = join(session.outbox.flush(), recreate).await;
        recreation?;
        replay.map_err(|error| format!("{error:?}"))?;
        let written = &session.outbox.writer.written;
        assert_eq!(written.len(), 2);
        assert!(written[0].contains(r#"id="echo""#));
        assert!(written[1].contains(r#"id="pending""#));
        assert_pending_replay_counters(&metrics, first.len(), 0, 1)?;
        assert_eq!(
            fixture.storage.begin_read().await?.pending_requests(account).await?,
            [recreated],
        );

        drop(session);
        fixture.finish().await
    }))?
}
