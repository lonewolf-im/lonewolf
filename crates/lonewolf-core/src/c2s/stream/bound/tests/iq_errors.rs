// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::delivery::failure_tests::{Capture, KINDS};
use lonewolf_extension::iq::IqFuture;
use lonewolf_storage::StorageErrorKind;
use lonewolf_xmpp::stanza::{NodeRef, STANZA_ERROR_NAMESPACE};

const PROFILE: &str = "seeded-private-profile";

async fn session<A: ChunkAllocator + Clone>(
    fixture: &Fixture,
    allocator: A,
) -> TestResult<(Router<A>, BoundSession<'_, A, ControlledWriter>)> {
    let config = Config::default();
    let router = Router::new(
        Hosts::new(&config.hosts, None)?,
        LocalRouter::new(allocator.clone()),
    )
    .with_extensions(std::collections::BTreeMap::from([(
        "localhost".into(),
        Default::default(),
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
    let mut outbox = fixture.outbox(allocator.clone(), ControlledWriter::default());
    outbox.liveness = registration.liveness();
    let session = BoundSession {
        outbox,
        registration,
        router: router.handle(),
        storage: fixture.storage.clone(),
        allocator,
        work: fixture.work.handle(),
        service_presence: None,
        service_pending: None,
        recipients: RecipientLimiter::new(
            NonZeroUsize::MIN,
            NonZeroUsize::new(100).ok_or("burst")?,
            Instant::now(),
            crate::c2s::metrics::C2sWorkerMetrics::detached(),
        ),
        available: false,
        priority: None,
        incoming,
    };
    Ok((router, session))
}

async fn parsed_request<A: ChunkAllocator + Clone>(
    allocator: A,
    kind: &str,
    attributes: &str,
    stream_lang: &str,
) -> TestResult<Parsed<Stanza, A>> {
    let error = if kind == "error" {
        "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
    } else {
        ""
    };
    let input = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'{stream_lang}><iq type='{kind}' {attributes}><vCard xmlns='vcard-temp'>{PROFILE}</vCard>{error}</iq>"
    );
    let mut parser = XmppParser::new(
        input.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4096).ok_or("stanza limit")?,
            arena: ArenaConfig::default(),
        },
        allocator,
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

async fn request<A: ChunkAllocator + Clone>(
    allocator: A,
    kind: &str,
    attributes: &str,
    stream_lang: &str,
) -> TestResult<(Stanza, Jid, Arena<A>)> {
    let (request, mut arena) = parsed_request(allocator, kind, attributes, stream_lang)
        .await?
        .into_parts();
    let sender = Jid::parse_in("bob@localhost/desk", &mut arena)?;
    Ok((request, sender, arena))
}

fn assert_omitted_reply<A: ChunkAllocator>(
    outbox: &Outbox<'_, A, ControlledWriter>,
    id: Option<&str>,
    from: Option<&str>,
    lang: Option<&str>,
    condition: StanzaErrorCondition,
) -> TestResult {
    assert_eq!(outbox.queue.len(), 1);
    let Some(Output::Owned { stanza, arena }) = outbox.queue.front() else {
        return Err("expected owned IQ error".into());
    };
    let reply = stanza.resolve(arena)?;
    assert_eq!(reply.stanza_type(), StanzaType::Iq(IqType::Error));
    assert_eq!(reply.namespace(), StanzaNamespace::Client);
    assert_eq!(reply.id()?, id);
    assert_eq!(reply.lang()?, lang);
    assert_eq!(reply.from()?.map(|jid| jid.as_str()), from);
    assert_eq!(
        reply.to()?.map(|jid| jid.as_str()),
        Some("bob@localhost/desk")
    );
    let children = reply.children()?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(children.len(), 1);
    let error = &children[0];
    assert_eq!(error.name(), "error");
    assert_eq!(error.namespace(), CLIENT_NAMESPACE);
    assert_eq!(error.attribute("type", "")?, Some(condition.error_type()));
    assert_eq!(error.attributes()?.count(), 1);
    let conditions = error.children()?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(conditions.len(), 2);
    let NodeRef::Element(condition_element) = &conditions[0] else {
        return Err("expected standard condition element".into());
    };
    assert_eq!(condition_element.name(), condition.as_str());
    assert_eq!(condition_element.namespace(), STANZA_ERROR_NAMESPACE);
    assert_eq!(condition_element.children()?.count(), 0);
    assert_eq!(condition_element.attributes()?.count(), 0);
    let NodeRef::Element(text) = &conditions[1] else {
        return Err("expected explanatory text".into());
    };
    assert_eq!(text.name(), "text");
    assert_eq!(text.namespace(), STANZA_ERROR_NAMESPACE);
    assert_eq!(
        text.attribute("lang", lonewolf_xmpp::stanza::XML_NAMESPACE)?,
        Some("en")
    );
    let lonewolf_xmpp::stanza::StanzaErrorText::Static(expected) = condition.default_text() else {
        return Err("expected static default".into());
    };
    assert_eq!(text.text()?, Some(expected));
    let mut xml = String::new();
    reply.write_xml(&mut xml)?;
    assert!(!xml.contains(PROFILE), "{xml}");
    assert!(!xml.contains("vcard-temp"), "{xml}");
    assert!(!xml.contains("mallory"), "{xml}");
    Ok(())
}

#[test]
fn omitted_iq_error_preserves_parsed_envelope_and_authenticated_recipient() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let (router, mut session) = session(&fixture, GlobalChunkAllocator).await?;
        for kind in ["get", "set"] {
            for target in [None, Some("localhost"), Some("bob@localhost")] {
                for forged in [false, true] {
                    for (encoded_id, parsed_id) in [("", ""), ("a&amp;&lt;&quot;&apos;", "a&<\"'")]
                    {
                        for (stream_lang, iq_lang, effective) in [
                            ("", "", None),
                            (" xml:lang='en'", "", Some("en")),
                            (" xml:lang='es'", "", Some("es")),
                            (" xml:lang='en'", " xml:lang='fr'", Some("fr")),
                            (" xml:lang='en'", " xml:lang=''", Some("")),
                            ("", " xml:lang='x-Unchecked'", Some("x-Unchecked")),
                        ] {
                            let mut attributes = format!("id='{encoded_id}'{iq_lang}");
                            if let Some(target) = target {
                                attributes.push_str(&format!(" to='{target}'"));
                            }
                            if forged {
                                attributes.push_str(" from='mallory@localhost/spy'");
                            }
                            let (request, sender, arena) =
                                request(GlobalChunkAllocator, kind, &attributes, stream_lang)
                                    .await?;
                            session
                                .queue_iq_error(
                                    request,
                                    sender,
                                    arena,
                                    IqError::without_payload(
                                        StanzaErrorCondition::ResourceConstraint.into(),
                                    ),
                                )
                                .map_err(|error| format!("{error:?}"))?;
                            assert_omitted_reply(
                                &session.outbox,
                                Some(parsed_id),
                                target,
                                effective,
                                StanzaErrorCondition::ResourceConstraint,
                            )?;
                            session
                                .outbox
                                .flush()
                                .await
                                .map_err(|error| format!("{error:?}"))?;
                        }
                    }
                }
            }
        }
        assert_eq!(session.outbox.writer.written.len(), 144);
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    })
}

struct Omit {
    path: &'static str,
    kind: StorageErrorKind,
    calls: AtomicUsize,
}

impl Omit {
    fn reject<A: ChunkAllocator>(&self, response: &mut Arena<A>) -> IqError {
        while response.try_alloc_slice_copy(&[0_u8; 1024]).is_ok() {}
        while response.try_alloc(0_u8).is_ok() {}
        self.calls.fetch_add(1, Ordering::SeqCst);
        IqError::without_payload(HandlerError::Internal {
            condition: StanzaErrorCondition::ResourceConstraint,
            failure: Failure {
                kind: FailureKind::Storage(self.kind),
                operation: "iq_omit",
            },
        })
    }
}

impl IqHandler<GlobalChunkAllocator, RedbStorage> for Omit {
    fn get<'a>(
        &'a self,
        _: IqRequest<'a, GlobalChunkAllocator>,
        _: &'a RedbRead,
        response: &'a mut Arena<GlobalChunkAllocator>,
    ) -> IqFuture<'a, GlobalChunkAllocator> {
        Box::pin(async move {
            assert_eq!(self.path, "get");
            Err(self.reject(response))
        })
    }

    fn get_missing_account(
        &self,
        _: IqRequest<'_, GlobalChunkAllocator>,
        response: &mut Arena<GlobalChunkAllocator>,
    ) -> Result<Option<Element>, IqError> {
        assert_eq!(self.path, "missing");
        Err(self.reject(response))
    }

    fn set<'a>(
        &'a self,
        request: IqRequest<'a, GlobalChunkAllocator>,
        transaction: &'a mut RedbWrite,
        _: &'a dyn lonewolf_extension::delivery::HostLookup,
        response: &'a mut Arena<GlobalChunkAllocator>,
    ) -> IqFuture<'a, GlobalChunkAllocator> {
        Box::pin(async move {
            assert_eq!(self.path, "set");
            let account = AccountKey::try_from(request.target)
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            transaction
                .delete_account(&account)
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            Err(self.reject(response))
        })
    }
}

#[test]
fn omitted_get_set_and_missing_account_errors_report_once_and_set_rolls_back() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let (router, mut session) = session(&fixture, GlobalChunkAllocator).await?;
        for path in ["get", "set", "missing"] {
            for kind in KINDS {
                let capture = Capture::default();
                let _subscriber = tracing::subscriber::set_default(capture.clone());
                let handler = Arc::new(Omit {
                    path,
                    kind,
                    calls: AtomicUsize::new(0),
                });
                let target = if path == "missing" {
                    "missing@localhost"
                } else {
                    "bob@localhost"
                };
                let attributes = format!(
                    "id='private-client-stanza-id' to='{target}' from='mallory@localhost/spy'"
                );
                let (request, sender, arena) = request(
                    GlobalChunkAllocator,
                    if path == "set" { "set" } else { "get" },
                    &attributes,
                    "",
                )
                .await?;
                let target =
                    AccountKey::try_from(request.resolve(&arena)?.to()?.ok_or("missing target")?)?;
                let response = Arena::try_new(ArenaConfig {
                    chunk_size: NonZeroUsize::new(4096).ok_or("chunk")?,
                    max_reserved_bytes: NonZeroUsize::new(4096).ok_or("limit")?,
                })?;
                if path == "set" {
                    session
                        .handle_iq_set(
                            request,
                            sender,
                            arena,
                            response,
                            handler.clone(),
                            Some(target),
                        )
                        .await
                        .map_err(|error| format!("{error:?}"))?;
                } else {
                    let work = GetWork {
                        account: fixture.registration.account().clone(),
                        target_account: Some(target),
                        transaction: fixture.storage.begin_read().await?,
                        handler: handler.clone(),
                        discovery: Arc::new(Discovery::default()),
                        arena,
                        request,
                        sender,
                        response,
                        delivery: RouterDelivery::new(
                            &session.router,
                            &GlobalChunkAllocator,
                            Some(&session.registration),
                        ),
                    };
                    let outcome = work
                        .run(Vec::new())
                        .await
                        .map_err(|error| format!("{error:?}"))?;
                    session
                        .queue_iq_reply(
                            request,
                            sender,
                            outcome.arena,
                            outcome.response,
                            outcome.reply,
                            outcome.results,
                        )
                        .map_err(|error| format!("{error:?}"))?;
                }
                assert_omitted_reply(
                    &session.outbox,
                    Some("private-client-stanza-id"),
                    Some(if path == "missing" {
                        "missing@localhost"
                    } else {
                        "bob@localhost"
                    }),
                    None,
                    StanzaErrorCondition::ResourceConstraint,
                )?;
                session
                    .outbox
                    .flush()
                    .await
                    .map_err(|error| format!("{error:?}"))?;
                assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
                capture.assert_one(FailureKind::Storage(kind), "iq_omit");
                assert!(
                    fixture
                        .storage
                        .begin_read()
                        .await?
                        .account(fixture.registration.account())
                        .await?
                        .is_some()
                );
            }
        }
        assert_eq!(session.outbox.writer.written.len(), 15);
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    })
}

fn full_request<A: ChunkAllocator + Clone>(allocator: A) -> TestResult<(Stanza, Jid, Arena<A>)> {
    let mut arena = Arena::try_new_in(
        ArenaConfig {
            chunk_size: NonZeroUsize::new(16384).ok_or("chunk")?,
            max_reserved_bytes: NonZeroUsize::new(16384).ok_or("limit")?,
        },
        allocator,
    )?;
    let sender = Jid::parse_in("bob@localhost/desk", &mut arena)?;
    let profile = PROFILE.repeat(600);
    let payload = Element::builder_in("vCard", "vcard-temp", &mut arena)?
        .text(&profile)?
        .build()?;
    let request = Stanza::builder_in(
        StanzaType::Iq(IqType::Set),
        StanzaNamespace::Client,
        &mut arena,
    )
    .id(Some(""))?
    .child(payload)?
    .build()?;
    while arena.try_alloc(0_u8).is_ok() {}
    assert!(arena.stats().used_bytes > 16000);
    assert!(arena.try_alloc(0_u8).is_err());
    Ok((request, sender, arena))
}

#[test]
fn omitted_iq_error_uses_fresh_arena_when_source_and_handler_arenas_are_full() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let (router, mut session) = session(&fixture, GlobalChunkAllocator).await?;
        let (request, sender, arena) = full_request(GlobalChunkAllocator)?;
        let mut response = Arena::try_new(ArenaConfig {
            chunk_size: NonZeroUsize::new(4096).ok_or("chunk")?,
            max_reserved_bytes: NonZeroUsize::new(4096).ok_or("limit")?,
        })?;
        let handler = Omit {
            path: "set",
            kind: StorageErrorKind::Other,
            calls: AtomicUsize::new(0),
        };
        let error = handler.reject(&mut response);
        assert!(response.try_alloc(0_u8).is_err());
        session
            .queue_iq_reply(request, sender, arena, response, Err(error), Vec::new())
            .map_err(|error| format!("{error:?}"))?;
        assert_omitted_reply(
            &session.outbox,
            Some(""),
            None,
            None,
            StanzaErrorCondition::ResourceConstraint,
        )?;
        session
            .outbox
            .flush()
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(session.outbox.writer.written.len(), 1);
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    })
}

#[derive(Clone)]
struct CountingAllocator {
    fail_at: Arc<AtomicUsize>,
    allocations: Arc<AtomicUsize>,
}

// Successful blocks retain the global allocator's ownership contract.
unsafe impl ChunkAllocator for CountingAllocator {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        let allocation = self.allocations.fetch_add(1, Ordering::SeqCst) + 1;
        if allocation >= self.fail_at.load(Ordering::Acquire) {
            Err(AllocationError::Exhausted)
        } else {
            GlobalChunkAllocator.allocate(layout)
        }
    }

    unsafe fn deallocate(&self, chunk: Chunk) {
        unsafe { GlobalChunkAllocator.deallocate(chunk) };
    }
}

#[test]
fn omitted_iq_error_fresh_arena_failure_closes_without_retry_or_output() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let allocator = CountingAllocator {
            fail_at: Arc::new(AtomicUsize::new(usize::MAX)),
            allocations: Arc::new(AtomicUsize::new(0)),
        };
        let (router, mut session) = session(&fixture, allocator.clone()).await?;
        let (request, sender, arena) = full_request(allocator.clone())?;
        let response = Arena::try_new_in(Default::default(), allocator.clone())?;
        let before = allocator.allocations.load(Ordering::SeqCst);
        allocator.fail_at.store(before + 1, Ordering::Release);
        let outcome = session.queue_iq_reply(
            request,
            sender,
            arena,
            response,
            Err(IqError::without_payload(
                StanzaErrorCondition::ResourceConstraint.into(),
            )),
            Vec::new(),
        );
        assert!(matches!(outcome, Err(CloseOutcome::InternalError)));
        assert_eq!(allocator.allocations.load(Ordering::SeqCst), before + 1);
        assert!(session.outbox.queue.is_empty());
        assert!(session.outbox.writer.written.is_empty());
        assert!(session.outbox.writer.bytes.is_empty());
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    })
}

#[test]
fn omitted_iq_error_rejects_response_misuse_and_dispatcher_sends_no_reply() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let (router, mut session) = session(&fixture, GlobalChunkAllocator).await?;
        for kind in ["result", "error"] {
            let (request, sender, arena) =
                request(GlobalChunkAllocator, kind, "id='response'", "").await?;
            let mut response = Arena::try_new(Default::default())?;
            assert!(
                iq::error_reply_omitting_payload(
                    &request.resolve(&arena)?,
                    sender.resolve(&arena)?,
                    StanzaErrorCondition::BadRequest,
                    StanzaErrorCondition::BadRequest.default_text(),
                    &mut response,
                )
                .is_err()
            );
            assert!(matches!(
                session.queue_iq_error(
                    request,
                    sender,
                    arena,
                    IqError::without_payload(StanzaErrorCondition::BadRequest.into()),
                ),
                Err(CloseOutcome::InternalError)
            ));
            let parsed = parsed_request(GlobalChunkAllocator, kind, "id='response'", "").await?;
            session
                .handle_iq(parsed)
                .await
                .map_err(|error| format!("{error:?}"))?;
            assert!(session.outbox.queue.is_empty());
        }
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    })
}

#[test]
fn included_iq_errors_keep_the_existing_builder_output() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let (router, mut session) = session(&fixture, GlobalChunkAllocator).await?;
        for kind in ["get", "set"] {
            for attributes in [
                "id='' from='mallory@localhost/spy' xml:lang=''",
                "id='a&amp;&lt;&quot;&apos;' to='localhost' xml:lang='fr'",
            ] {
                let (request, sender, mut arena) =
                    request(GlobalChunkAllocator, kind, attributes, " xml:lang='en'").await?;
                let reference = iq::error_reply(
                    &request,
                    &mut arena,
                    StanzaErrorCondition::ServiceUnavailable,
                    Some(sender),
                )
                .map_err(|_| "reference reply")?;
                let mut expected = String::new();
                reference.resolve(&arena)?.write_xml(&mut expected)?;
                let (request, sender, arena) =
                    self::request(GlobalChunkAllocator, kind, attributes, " xml:lang='en'").await?;
                session
                    .queue_iq_reply(
                        request,
                        sender,
                        arena,
                        Arena::try_new(Default::default())?,
                        Err(StanzaErrorCondition::ServiceUnavailable.into()),
                        Vec::new(),
                    )
                    .map_err(|error| format!("{error:?}"))?;
                session
                    .outbox
                    .flush()
                    .await
                    .map_err(|error| format!("{error:?}"))?;
                let actual = session
                    .outbox
                    .writer
                    .written
                    .last()
                    .ok_or("missing error")?;
                assert_eq!(actual, &expected);
                assert!(actual.contains(PROFILE));
            }
        }
        assert_eq!(session.outbox.writer.written.len(), 4);
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    })
}

#[test]
fn omitted_iq_error_envelope_allocation_failure_closes_without_retry_or_output() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let allocator = CountingAllocator {
            fail_at: Arc::new(AtomicUsize::new(usize::MAX)),
            allocations: Arc::new(AtomicUsize::new(0)),
        };
        let (router, mut session) = session(&fixture, allocator.clone()).await?;
        let mut arena = Arena::try_new_in(Default::default(), allocator.clone())?;
        let sender = Jid::parse_in("bob@localhost/desk", &mut arena)?;
        let id = "private-client-stanza-id".repeat(400);
        let payload = Element::builder_in("vCard", "vcard-temp", &mut arena)?
            .text(PROFILE)?
            .build()?;
        let request = Stanza::builder_in(
            StanzaType::Iq(IqType::Get),
            StanzaNamespace::Client,
            &mut arena,
        )
        .id(Some(&id))?
        .child(payload)?
        .build()?;
        let response = Arena::try_new_in(Default::default(), allocator.clone())?;
        let before = allocator.allocations.load(Ordering::SeqCst);
        allocator.fail_at.store(before + 2, Ordering::Release);
        let outcome = session.queue_iq_reply(
            request,
            sender,
            arena,
            response,
            Err(IqError::without_payload(
                StanzaErrorCondition::ResourceConstraint.into(),
            )),
            Vec::new(),
        );
        assert!(matches!(outcome, Err(CloseOutcome::InternalError)));
        assert_eq!(allocator.allocations.load(Ordering::SeqCst), before + 2);
        assert!(session.outbox.queue.is_empty());
        assert!(session.outbox.writer.written.is_empty());
        assert!(session.outbox.writer.bytes.is_empty());
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    })
}
