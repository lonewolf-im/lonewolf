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
                        pending: Vec::new(),
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
        router.handle().route_current_presence(session.registration.account(), &target).await?;
        router.handle().route_unavailable_presence(session.registration.account(), &target).await?;
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
                    pending: Vec::new(),
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
