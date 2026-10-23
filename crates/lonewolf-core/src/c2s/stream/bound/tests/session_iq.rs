// SPDX-License-Identifier: Apache-2.0

use super::*;
use lonewolf_extension::delivery::{SessionTag, TagChange};
use lonewolf_extension::iq::{IqRequestKey, SessionIqHandler, SessionIqReply};
use lonewolf_extension::policy::{PolicyFuture, PolicyHandler, PolicyRequest};
use lonewolf_extension::{Extension, Extensions, RegistrationError, Slots};
use lonewolf_xmpp::stanza::STANZA_ERROR_NAMESPACE;
use std::collections::BTreeMap;

const NAMESPACE: &str = "urn:test:session";

#[derive(Debug)]
struct Observation {
    sender: String,
    target: String,
    lang: Option<String>,
    space: Option<XmlSpace>,
    name: String,
}

#[derive(Default)]
struct Handler {
    calls: PlMutex<Vec<Observation>>,
    change: PlMutex<Option<TagChange>>,
    error: PlMutex<Option<IqError>>,
    payload: bool,
    guard: bool,
    reject: bool,
    policy_calls: AtomicUsize,
}

impl Extension<GlobalChunkAllocator, RedbStorage> for Handler {
    fn name(&self) -> &'static str {
        "session"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.session_iq(NAMESPACE, "control", self.clone())?;
        if self.guard {
            slots.iq_destination(
                IqRequestKey {
                    kind: IqRequestType::Set,
                    namespace: NAMESPACE,
                    name: "control",
                },
                IqDestinationRule::SenderBare,
            )?;
        }
        if self.reject {
            slots.policy(self);
        }
        Ok(())
    }
}

impl SessionIqHandler<GlobalChunkAllocator> for Handler {
    fn set(
        &self,
        request: IqRequest<'_, GlobalChunkAllocator>,
        response: &mut Arena<GlobalChunkAllocator>,
    ) -> Result<SessionIqReply, IqError> {
        assert_eq!(request.requester, None);
        assert!(
            request
                .discovery
                .features(lonewolf_extension::discovery::DiscoScope::Account)
                .is_empty()
        );
        self.calls.lock().push(Observation {
            sender: request.sender.as_str().into(),
            target: request.target.as_str().into(),
            lang: request.lang.map(str::to_owned),
            space: request.space,
            name: request.payload.name().into(),
        });
        if let Some(error) = *self.error.lock() {
            return Err(error);
        }
        let payload = if self.payload {
            Some(
                Element::builder_in("ack", NAMESPACE, response)
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?
                    .build()
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?,
            )
        } else {
            None
        };
        Ok(SessionIqReply {
            payload,
            change: *self.change.lock(),
        })
    }
}

impl PolicyHandler<RedbStorage> for Handler {
    fn check<'a>(&'a self, _: PolicyRequest<'a>, _: &'a RedbRead) -> PolicyFuture<'a> {
        Box::pin(async move {
            self.policy_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Verdict::Reject {
                condition: StanzaErrorCondition::Forbidden,
                application: None,
                text: None,
            })
        })
    }
}

async fn setup<'a>(
    fixture: &'a Fixture,
    handler: &Arc<Handler>,
) -> TestResult<(
    Router<GlobalChunkAllocator>,
    BoundSession<'a, GlobalChunkAllocator, ControlledWriter>,
)> {
    let mut extensions = Extensions::default();
    extensions.register(handler.clone())?;
    let router = Router::new(
        Hosts::new(&Config::default().hosts, None)?,
        LocalRouter::new(GlobalChunkAllocator),
    )
    .with_extensions(BTreeMap::from([(
        "localhost".into(),
        extensions.enable_host("localhost", ["session"])?,
    )]));
    let registration = router
        .handle()
        .register(
            fixture.registration.account(),
            Some("desk"),
            NonZeroUsize::MIN,
        )
        .await?;
    let (_sender, incoming) = async_channel::bounded(1);
    let session = fixture.bound_session(
        GlobalChunkAllocator,
        registration,
        router.handle(),
        incoming,
    )?;
    Ok((router, session))
}

async fn request(
    kind: &str,
    attributes: &str,
    name: &str,
) -> TestResult<Parsed<Stanza, GlobalChunkAllocator>> {
    let xml = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' xml:lang='en'><iq type='{kind}' id='session' xml:space='preserve' {attributes}><{name} xmlns='{NAMESPACE}'><child/></{name}></iq>"
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
        return Err("expected IQ".into());
    };
    Ok(parsed)
}

async fn flush(
    session: &mut BoundSession<'_, GlobalChunkAllocator, ControlledWriter>,
) -> TestResult {
    session
        .outbox
        .flush()
        .await
        .map_err(|error| format!("{error:?}"))?;
    Ok(())
}

fn presence(id: &str, full: bool) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let to = Jid::parse_in(
        if full {
            "bob@localhost/desk"
        } else {
            "bob@localhost"
        },
        &mut arena,
    )?;
    let stanza = Stanza::builder_in(
        StanzaType::Presence(PresenceType::Available),
        StanzaNamespace::Client,
        &mut arena,
    )
    .to(Some(to))?
    .id(Some(id))?
    .build()?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}

#[test]
fn session_iq_sets_never_open_storage() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let handler = Arc::new(Handler {
            payload: true,
            change: PlMutex::new(Some(TagChange::Insert(SessionTag::Carbons))),
            ..Default::default()
        });
        let (router, mut session) = setup(&fixture, &handler).await?;
        let mut deletion = fixture.storage.begin_write().await?;
        deletion
            .delete_account(fixture.registration.account())
            .await?;
        deletion.commit().await?;
        let transaction = fixture.storage.begin_write().await?;
        for attributes in ["", "to='bob@localhost'"] {
            session
                .handle_stanza(request("set", attributes, "control").await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            flush(&mut session).await?;
        }
        assert_eq!(session.outbox.writer.written.len(), 2);
        for reply in &session.outbox.writer.written {
            assert!(reply.contains("type=\"result\""), "{reply}");
            assert!(reply.contains("<ack"), "{reply}");
        }
        {
            let calls = handler.calls.lock();
            assert_eq!(calls.len(), 2);
            for call in calls.iter() {
                assert_eq!(call.sender, "bob@localhost/desk");
                assert_eq!(call.target, "bob@localhost");
                assert_eq!(call.lang.as_deref(), Some("en"));
                assert_eq!(call.space, Some(XmlSpace::Preserve));
                assert_eq!(call.name, "control");
            }
        }
        drop(transaction);
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn session_iq_tag_changes_apply_before_the_reply() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let handler = Arc::new(Handler::default());
        let (router, mut session) = setup(&fixture, &handler).await?;
        for (change, delivered) in [
            (TagChange::Insert(SessionTag::Carbons), true),
            (TagChange::Remove(SessionTag::Carbons), false),
        ] {
            *handler.change.lock() = Some(change);
            session
                .handle_stanza(request("set", "", "control").await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            flush(&mut session).await?;
            assert!(
                session
                    .outbox
                    .writer
                    .written
                    .last()
                    .ok_or("reply")?
                    .contains("type=\"result\"")
            );
            router
                .handle()
                .route_presence_to_tagged(SessionTag::Carbons, presence("tagged", false)?)
                .await?;
            let entries = session.registration.take_queued();
            assert_eq!(entries.len(), usize::from(delivered));
            if let Some(entry) = entries.first() {
                assert_eq!(entry.stanza.resolve()?.id()?, Some("tagged"));
            }
        }
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn deliveries_admitted_before_a_session_iq_precede_its_reply() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let handler = Arc::new(Handler {
            change: PlMutex::new(Some(TagChange::Insert(SessionTag::Carbons))),
            ..Default::default()
        });
        let (router, mut session) = setup(&fixture, &handler).await?;
        for change in [
            TagChange::Insert(SessionTag::Carbons),
            TagChange::Remove(SessionTag::Carbons),
        ] {
            *handler.change.lock() = Some(change);
            router
                .handle()
                .route_full(presence("before", true)?)
                .await?;
            session
                .handle_stanza(request("set", "", "control").await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            router.handle().route_full(presence("after", true)?).await?;
            session.outbox.delivered(session.registration.take_queued());
            flush(&mut session).await?;
            let written = &session.outbox.writer.written;
            assert_eq!(written.len(), 3);
            assert!(written[0].contains("id=\"before\""), "{written:?}");
            assert!(written[1].contains("type=\"result\""), "{written:?}");
            assert!(written[2].contains("id=\"after\""), "{written:?}");
            session.outbox.writer.written.clear();
        }
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn session_iq_errors_use_the_generic_error_reply() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let handler = Arc::new(Handler::default());
        let (router, mut session) = setup(&fixture, &handler).await?;
        for error in [
            IqError::from(StanzaErrorCondition::NotAllowed),
            IqError::without_payload(StanzaErrorCondition::NotAllowed.into()),
        ] {
            *handler.error.lock() = Some(error);
            session
                .handle_stanza(request("set", "to='bob@localhost'", "control").await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            flush(&mut session).await?;
            let actual = session.outbox.writer.written.pop().ok_or("session error")?;
            let (stanza, mut arena) = request("set", "to='bob@localhost'", "control")
                .await?
                .into_parts();
            let sender = Jid::parse_in("bob@localhost/desk", &mut arena)?;
            session
                .queue_iq_error(stanza, sender, arena, error)
                .map_err(|error| format!("{error:?}"))?;
            flush(&mut session).await?;
            let expected = session.outbox.writer.written.pop().ok_or("generic error")?;
            assert_eq!(actual, expected);
            assert!(actual.contains("type=\"cancel\""), "{actual}");
            assert!(actual.contains("not-allowed"), "{actual}");
            assert_eq!(
                actual.contains("<control"),
                error.payload() == IqErrorPayload::Include
            );
        }
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn session_iq_policy_and_destinations_run_first() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        for guard in [false, true] {
            let handler = Arc::new(Handler {
                guard,
                reject: !guard,
                ..Default::default()
            });
            let (router, mut session) = setup(&fixture, &handler).await?;
            for target in ["to='alice@localhost'", "to='alice@localhost/phone'"] {
                session
                    .handle_stanza(request("set", target, "control").await?)
                    .await
                    .map_err(|error| format!("{error:?}"))?;
                flush(&mut session).await?;
                let reply = session.outbox.writer.written.pop().ok_or("rejection")?;
                assert!(reply.contains("forbidden"), "{reply}");
            }
            assert!(handler.calls.lock().is_empty());
            assert_eq!(
                handler.policy_calls.load(Ordering::SeqCst),
                if guard { 0 } else { 4 }
            );
            drop(session);
            router.shutdown().await?;
        }
        fixture.finish().await
    }))?
}

#[test]
fn session_iq_lookup_excludes_gets_server_and_missing_handlers() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let handler = Arc::new(Handler::default());
        let (router, mut session) = setup(&fixture, &handler).await?;
        for (kind, attributes, name) in [
            ("get", "", "control"),
            ("set", "", "missing"),
            ("set", "to='localhost'", "control"),
            ("set", "to='bob@localhost/absent'", "control"),
        ] {
            session
                .handle_stanza(request(kind, attributes, name).await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            flush(&mut session).await?;
            let reply = session.outbox.writer.written.pop().ok_or("unavailable")?;
            assert!(reply.contains("service-unavailable"), "{reply}");
        }
        assert!(handler.calls.lock().is_empty());
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn session_iq_retirement_returns_an_omitted_internal_error_and_stopped_router_closes() -> TestResult
{
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let handler = Arc::new(Handler {
            change: PlMutex::new(Some(TagChange::Insert(SessionTag::Carbons))),
            ..Default::default()
        });
        let (router, mut session) = setup(&fixture, &handler).await?;
        router
            .handle()
            .retire_account(fixture.registration.account())
            .await?;
        session
            .handle_stanza(request("set", "", "control").await?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        let Some(Output::Owned { stanza, arena }) = session.outbox.queue.front() else {
            return Err("retirement reply".into());
        };
        let view = stanza.resolve(arena)?;
        assert_eq!(view.stanza_type(), StanzaType::Iq(IqType::Error));
        let children = view.children()?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name(), "error");
        assert!(
            children[0]
                .child("internal-server-error", STANZA_ERROR_NAMESPACE)?
                .is_some()
        );
        router.shutdown().await?;
        assert_eq!(
            session
                .handle_stanza(request("set", "", "control").await?)
                .await,
            Err(CloseOutcome::InternalError)
        );
        assert_eq!(session.outbox.queue.len(), 1);
        assert_eq!(handler.calls.lock().len(), 2);
        drop(session);
        fixture.finish().await
    }))?
}
