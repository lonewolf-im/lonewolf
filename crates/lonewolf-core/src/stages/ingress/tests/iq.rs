// SPDX-License-Identifier: Apache-2.0

use std::alloc::Layout;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use compio::runtime::Runtime;
use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::iq::{
    IqError, IqErrorPayload, IqHandler, IqRequest, IqRequestType, IqRoute, IqScope, Requester,
};
use lonewolf_extension::{Extension, Extensions, RegistrationError, Slots};
use lonewolf_storage::{RedbRead, RedbStorage};
use lonewolf_util::arena::{
    AllocationError, Arena, ArenaConfig, Chunk, ChunkAllocator, GlobalChunkAllocator,
};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{
    Element, IqType, RoutedStanza, STANZA_ERROR_NAMESPACE, Stanza, StanzaNamespace, StanzaType,
};
use parking_lot::Mutex as PlMutex;

use super::{Fixture, TestResult, account};
use crate::config::Config;
use crate::delivery::WorkGroup;
use crate::hosts::Hosts;
use crate::router::local::LocalRouter;
use crate::router::{Destination, Router};
use crate::stages::Stage;
use crate::stages::ingress::Origin;
use crate::stages::ingress::iq::{
    AnswerStanzas, IqAnswer, IqDisposition, IqInput, handle_request, render_answer,
};
use crate::stages::iq::{error_reply_omitting_payload, result_reply};

fn request<A: ChunkAllocator + Clone>(
    allocator: A,
    from: &str,
    to: &str,
    text: &str,
) -> TestResult<(Stanza, Arena<A>, Jid)> {
    let mut arena = Arena::try_new_in(Default::default(), allocator)?;
    let sender = Jid::parse_in(from, &mut arena)?;
    let target = Jid::parse_in(to, &mut arena)?;
    let payload = Element::builder_in("query", "urn:test:shared-iq", &mut arena)?
        .text(text)?
        .build()?;
    let stanza = Stanza::builder_in(
        StanzaType::Iq(IqType::Get),
        StanzaNamespace::Client,
        &mut arena,
    )
    .id(Some("request"))?
    .from(Some(sender))?
    .to(Some(target))?
    .child(payload)?
    .build()?;
    Ok((stanza, arena, sender))
}

#[test]
fn misaddressed_results_answer_internal_server_error_for_every_origin() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(false)?;
        let session = fixture
            .handle
            .register(
                &account("alice@localhost")?,
                Some("desk"),
                NonZeroUsize::MIN,
            )
            .await?;
        for origin in [
            Origin::Session(&session),
            Origin::Remote {
                local: "localhost",
                remote: "remote.test",
            },
            Origin::Service {
                domain: "service.test",
            },
        ] {
            let from = match origin {
                Origin::Session(_) => "alice@localhost/desk",
                Origin::Remote { .. } => "alice@remote.test/desk",
                Origin::Service { .. } => "service.test",
            };
            for to in ["bob@localhost", "localhost"] {
                let (request, arena, sender) = request(GlobalChunkAllocator, from, to, "")?;
                let mut response = Arena::try_new(Default::default())?;
                let other = Jid::parse_in("mallory@localhost", &mut response)?;
                let result = Stanza::builder_in(
                    StanzaType::Iq(IqType::Result),
                    StanzaNamespace::Client,
                    &mut response,
                )
                .id(Some("other"))?
                .to(Some(other))?
                .build()?;
                let answer = IqAnswer {
                    request,
                    arena,
                    sender: origin.session().map(|_| sender),
                    response,
                    reply: Ok(None),
                    results: vec![result],
                };
                let AnswerStanzas::One { stanza, arena } =
                    render_answer(&origin, &GlobalChunkAllocator, answer)
                        .map_err(|_| "render failed")?
                else {
                    return Err("misaddressed results escaped".into());
                };
                let view = stanza.resolve(&arena)?;
                assert_eq!(view.stanza_type(), StanzaType::Iq(IqType::Error));
                assert_eq!(view.from()?.ok_or("from")?.as_str(), to);
                assert_eq!(view.to()?.ok_or("to")?.as_str(), from);
                assert_eq!(view.id()?, Some("request"));
                assert!(
                    view.child("error", "jabber:client")?
                        .ok_or("error")?
                        .child("internal-server-error", STANZA_ERROR_NAMESPACE)?
                        .is_some()
                );
            }
        }
        drop(session);
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[derive(Default)]
struct MissingRequester(PlMutex<Vec<Option<Requester>>>);

impl Extension<GlobalChunkAllocator, RedbStorage> for MissingRequester {
    fn name(&self) -> &'static str {
        "missing-requester"
    }
    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq(
            IqRoute {
                scope: IqScope::Account,
                kind: IqRequestType::Get,
                namespace: "urn:test:shared-iq",
                name: "query",
            },
            self,
        )
    }
}

impl IqHandler<GlobalChunkAllocator, RedbStorage> for MissingRequester {
    fn get<'a>(
        &'a self,
        _: IqRequest<'a, GlobalChunkAllocator>,
        _: &'a RedbRead,
        _: &'a mut Arena<GlobalChunkAllocator>,
    ) -> lonewolf_extension::iq::IqFuture<'a, GlobalChunkAllocator> {
        Box::pin(async {
            Err(lonewolf_xmpp::stanza::StanzaErrorCondition::InternalServerError.into())
        })
    }
    fn get_missing_account(
        &self,
        request: IqRequest<'_, GlobalChunkAllocator>,
        response: &mut Arena<GlobalChunkAllocator>,
    ) -> Result<Option<Element>, lonewolf_extension::iq::IqError> {
        self.0.lock().push(request.requester);
        Ok(Some(
            Element::builder_in("missing", "urn:test:shared-iq", response)
                .map_err(|_| {
                    HandlerError::from(
                        lonewolf_xmpp::stanza::StanzaErrorCondition::InternalServerError,
                    )
                })?
                .build()
                .map_err(|_| {
                    HandlerError::from(
                        lonewolf_xmpp::stanza::StanzaErrorCondition::InternalServerError,
                    )
                })?,
        ))
    }
}

#[test]
fn missing_account_requester_is_other_for_remote_senders() -> TestResult {
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let handler = Arc::new(MissingRequester::default());
        let mut extensions = Extensions::default();
        extensions.register(handler.clone())?;
        let router = Router::new(
            Hosts::new(&Config::default().hosts, None)?,
            LocalRouter::new(GlobalChunkAllocator),
        )
        .with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", ["missing-requester"])?,
        )]));
        let handle = router.handle();
        let work = WorkGroup::new().handle();
        let stage = Stage {
            router: &handle,
            storage: &storage,
            allocator: &GlobalChunkAllocator,
            work: &work,
        };
        let origin = Origin::Remote {
            local: "localhost",
            remote: "remote.test",
        };
        let (request, arena, _) = request(
            GlobalChunkAllocator,
            "alice@remote.test/desk",
            "missing@localhost",
            "",
        )?;
        let disposition = handle_request(
            &stage,
            &origin,
            IqInput::Routed(RoutedStanza::from_parts(request, arena)),
            Destination::Account,
            IqRequestType::Get,
            Some(account("missing@localhost")?),
        )
        .await
        .map_err(|_| "prepare failed")?;
        let IqDisposition::Ordered(pending) = disposition else {
            return Err("missing ordered get".into());
        };
        let completed = pending
            .finished()
            .await
            .ok_or("cancelled get")?
            .map_err(|_| "get failed")?;
        assert!(completed.queued.is_empty());
        assert_eq!(*handler.0.lock(), [Some(Requester::Other)]);
        assert!(completed.answer.reply.is_ok());
        assert!(completed.answer.results.is_empty());
        let AnswerStanzas::One { stanza, arena } =
            render_answer(&origin, &GlobalChunkAllocator, completed.answer)
                .map_err(|_| "render failed")?
        else {
            return Err("unexpected results".into());
        };
        let view = stanza.resolve(&arena)?;
        assert_eq!(view.stanza_type(), StanzaType::Iq(IqType::Result));
        assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@remote.test/desk");
        assert!(view.child("missing", "urn:test:shared-iq")?.is_some());
        router.shutdown().await?;
        Ok(())
    })
}

#[derive(Default)]
struct CountingAllocator(AtomicUsize);

// Each block keeps the global allocator's layout and ownership contract.
unsafe impl ChunkAllocator for CountingAllocator {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        GlobalChunkAllocator.allocate(layout)
    }
    unsafe fn deallocate(&self, chunk: Chunk) {
        unsafe { GlobalChunkAllocator.deallocate(chunk) };
    }
}

#[test]
fn routed_conversion_and_rendering_use_only_the_existing_sender_and_request_copy() -> TestResult {
    let allocator = Arc::new(CountingAllocator::default());
    let from = format!("{}@remote.test/desk", "a".repeat(700));
    let text = "x".repeat(2300);
    let (source, arena, _) = request(allocator.clone(), &from, "bob@localhost", &text)?;
    let routed = RoutedStanza::from_parts(source, arena);
    let mut oracle = Arena::try_new_in(ArenaConfig::default(), allocator.clone())?;
    let clone = routed.resolve()?.clone_in(&mut oracle)?;
    let stats = oracle.stats();
    assert_eq!(stats.chunk_count, 1);
    assert!(stats.used_bytes > 3000);
    assert!(stats.reserved_bytes - stats.used_bytes < from.len());
    for error_payload in [
        None,
        Some(IqErrorPayload::Include),
        Some(IqErrorPayload::Omit),
    ] {
        let before = allocator.0.load(Ordering::SeqCst);
        let (request, arena, sender) = IqInput::Routed(routed.clone())
            .into_owned(&allocator)
            .map_err(|_| "conversion failed")?;
        assert_eq!(allocator.0.load(Ordering::SeqCst) - before, 1);
        assert!(sender.is_none());
        assert_eq!(arena.stats(), stats);
        let mut expected = String::new();
        clone.resolve(&oracle)?.write_xml(&mut expected)?;
        let mut actual = String::new();
        request.resolve(&arena)?.write_xml(&mut actual)?;
        assert_eq!(actual, expected);
        let response = Arena::try_new_in(Default::default(), allocator.clone())?;
        let condition = lonewolf_xmpp::stanza::StanzaErrorCondition::Forbidden;
        let reply = match error_payload {
            None => Ok(None),
            Some(IqErrorPayload::Include) => Err(IqError::from(HandlerError::from(condition))),
            Some(IqErrorPayload::Omit) => Err(IqError::without_payload(condition.into())),
        };
        let origin: Origin<'_, Arc<CountingAllocator>> = Origin::Remote {
            local: "localhost",
            remote: "remote.test",
        };
        let answer = IqAnswer {
            request,
            arena,
            sender,
            response,
            reply,
            results: Vec::new(),
        };
        let before = allocator.0.load(Ordering::SeqCst);
        let AnswerStanzas::One { stanza, arena } =
            render_answer(&origin, &allocator, answer).map_err(|_| "render failed")?
        else {
            return Err("unexpected results".into());
        };
        let shared_allocations = allocator.0.load(Ordering::SeqCst) - before;
        if error_payload.is_none() {
            assert_eq!(shared_allocations, 0);
        }
        if error_payload == Some(IqErrorPayload::Omit) {
            assert_eq!(shared_allocations, 1);
        }
        let view = stanza.resolve(&arena)?;
        assert_eq!(view.to()?.ok_or("to")?.as_str(), from);
        assert_eq!(view.from()?.ok_or("from")?.as_str(), "bob@localhost");
        assert_eq!(
            view.stanza_type(),
            StanzaType::Iq(if error_payload.is_none() {
                IqType::Result
            } else {
                IqType::Error
            })
        );
        if error_payload == Some(IqErrorPayload::Include) {
            assert_eq!(
                view.child("query", "urn:test:shared-iq")?
                    .ok_or("included payload")?
                    .text()?,
                Some(text.as_str())
            );
        } else {
            assert!(view.child("query", "urn:test:shared-iq")?.is_none());
        }
        let mut actual = String::new();
        view.write_xml(&mut actual)?;

        let mut response = Arena::try_new_in(Default::default(), allocator.clone())?;
        let before = allocator.0.load(Ordering::SeqCst);
        let mut original = Arena::try_new_in(Default::default(), allocator.clone())?;
        let request = routed.resolve()?.clone_in(&mut original)?;
        let (legacy, legacy_arena) = match error_payload {
            None => {
                let legacy = result_reply(
                    &request.resolve(&original)?,
                    routed.resolve()?.from()?.ok_or("sender")?,
                    None,
                    &mut response,
                )
                .map_err(|_| "baseline result failed")?;
                (legacy, response)
            }
            Some(IqErrorPayload::Include) => (
                request
                    .error_reply_described_in(
                        &mut original,
                        condition,
                        None,
                        condition.default_text(),
                    )?
                    .build()?,
                original,
            ),
            Some(IqErrorPayload::Omit) => {
                let mut envelope = Arena::try_new_in(Default::default(), allocator.clone())?;
                let view = request.resolve(&original)?;
                let legacy = error_reply_omitting_payload(
                    &view,
                    view.from()?.ok_or("sender")?,
                    condition,
                    condition.default_text(),
                    &mut envelope,
                )
                .map_err(|_| "baseline omit failed")?;
                (legacy, envelope)
            }
        };
        let legacy_allocations = allocator.0.load(Ordering::SeqCst) - before;
        assert_eq!(legacy_allocations, shared_allocations + 1);
        let mut expected = String::new();
        legacy.resolve(&legacy_arena)?.write_xml(&mut expected)?;
        assert_eq!(actual, expected);
    }
    Ok(())
}

#[test]
fn owned_conversion_reuses_the_authenticated_sender_for_rendering() -> TestResult {
    Runtime::new()?.block_on(async {
        let allocator = Arc::new(CountingAllocator::default());
        let bare = format!("{}@localhost", "a".repeat(700));
        let authenticated = format!("{bare}/desk");
        let router = Router::new(
            Hosts::new(&Config::default().hosts, None)?,
            LocalRouter::new(allocator.clone()),
        );
        let session = router
            .handle()
            .register(&account(&bare)?, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let (request, mut arena, _) = request(
            allocator.clone(),
            "mallory@localhost/forged",
            "bob@localhost",
            &"x".repeat(2300),
        )?;
        let sender = Jid::parse_in(&authenticated, &mut arena)?;
        let stats = arena.stats();
        assert_eq!(stats.chunk_count, 1);
        assert!(stats.used_bytes > 3000);
        assert!(stats.reserved_bytes - stats.used_bytes < authenticated.len());
        let before = allocator.0.load(Ordering::SeqCst);
        let (request, arena, sender) = IqInput::Owned {
            request,
            arena,
            sender,
        }
        .into_owned(&allocator)
        .map_err(|_| "conversion failed")?;
        assert_eq!(allocator.0.load(Ordering::SeqCst), before);
        assert_eq!(arena.stats(), stats);
        assert!(sender.is_some());
        let response = Arena::try_new_in(Default::default(), allocator.clone())?;
        let origin = Origin::Session(&session);
        let answer = IqAnswer {
            request,
            arena,
            sender,
            response,
            reply: Ok(None),
            results: Vec::new(),
        };
        let before = allocator.0.load(Ordering::SeqCst);
        let AnswerStanzas::One { stanza, arena } =
            render_answer(&origin, &allocator, answer).map_err(|_| "render failed")?
        else {
            return Err("unexpected results".into());
        };
        assert_eq!(allocator.0.load(Ordering::SeqCst), before);
        assert_eq!(
            stanza.resolve(&arena)?.to()?.ok_or("to")?.as_str(),
            authenticated
        );
        assert_eq!(
            stanza.resolve(&arena)?.from()?.ok_or("from")?.as_str(),
            "bob@localhost"
        );
        drop(session);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn only_remote_origin_classifies_invalid_result_handles_as_misaddressed() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(false)?;
        let session = fixture
            .handle
            .register(
                &account("alice@localhost")?,
                Some("desk"),
                NonZeroUsize::MIN,
            )
            .await?;
        for origin in [
            Origin::Session(&session),
            Origin::Remote {
                local: "localhost",
                remote: "remote.test",
            },
            Origin::Service {
                domain: "service.test",
            },
        ] {
            let (request, arena, sender) = request(
                GlobalChunkAllocator,
                "alice@remote.test/desk",
                "localhost",
                "",
            )?;
            let mut foreign = Arena::try_new(Default::default())?;
            let to = Jid::parse_in("alice@remote.test/desk", &mut foreign)?;
            let result = Stanza::builder_in(
                StanzaType::Iq(IqType::Result),
                StanzaNamespace::Client,
                &mut foreign,
            )
            .id(Some("result"))?
            .to(Some(to))?
            .build()?;
            let answer = IqAnswer {
                request,
                arena,
                sender: origin.session().map(|_| sender),
                response: Arena::try_new(Default::default())?,
                reply: Ok(None),
                results: vec![result],
            };
            let rendered = render_answer(&origin, &GlobalChunkAllocator, answer);
            if matches!(origin, Origin::Remote { .. }) {
                assert!(matches!(rendered, Ok(AnswerStanzas::One { .. })));
            } else {
                assert!(rendered.is_err());
            }
        }
        drop(session);
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn missing_remote_handler_keeps_routed_request_without_an_arena_allocation() -> TestResult {
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let allocator = Arc::new(CountingAllocator::default());
        let router = Router::new(
            Hosts::new(&Config::default().hosts, None)?,
            LocalRouter::new(allocator.clone()),
        )
        .with_extensions(BTreeMap::from([("localhost".into(), Default::default())]));
        let handle = router.handle();
        let work = WorkGroup::new().handle();
        let stage = Stage {
            router: &handle,
            storage: &storage,
            allocator: &allocator,
            work: &work,
        };
        let origin = Origin::Remote {
            local: "localhost",
            remote: "remote.test",
        };
        let (request, arena, _) = request(
            allocator.clone(),
            "alice@remote.test/desk",
            "bob@localhost",
            "",
        )?;
        let input = IqInput::Routed(RoutedStanza::from_parts(request, arena));
        let target = account("bob@localhost")?;
        let before = allocator.0.load(Ordering::SeqCst);
        let disposition = handle_request(
            &stage,
            &origin,
            input,
            Destination::Account,
            IqRequestType::Get,
            Some(target),
        )
        .await
        .map_err(|_| "lookup failed")?;
        assert_eq!(allocator.0.load(Ordering::SeqCst), before);
        let IqDisposition::Unavailable {
            input: IqInput::Routed(stanza),
            response,
            condition,
            ..
        } = disposition
        else {
            return Err("unexpected disposition".into());
        };
        assert!(response.is_none());
        assert_eq!(
            condition,
            lonewolf_xmpp::stanza::StanzaErrorCondition::ServiceUnavailable
        );
        assert_eq!(
            stanza.resolve()?.from()?.ok_or("from")?.as_str(),
            "alice@remote.test/desk"
        );
        assert_eq!(
            stanza.resolve()?.to()?.ok_or("to")?.as_str(),
            "bob@localhost"
        );
        router.shutdown().await?;
        Ok(())
    })
}

#[derive(Default)]
struct EarlyErrorAllocator {
    calls: AtomicUsize,
    live: AtomicUsize,
    fail_at: AtomicUsize,
}

// Accepted blocks retain the global allocator's layout and ownership contract.
unsafe impl ChunkAllocator for EarlyErrorAllocator {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_at.load(Ordering::SeqCst) {
            return Err(AllocationError::Exhausted);
        }
        let chunk = GlobalChunkAllocator.allocate(layout)?;
        self.live.fetch_add(1, Ordering::SeqCst);
        Ok(chunk)
    }
    unsafe fn deallocate(&self, chunk: Chunk) {
        unsafe { GlobalChunkAllocator.deallocate(chunk) };
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

#[test]
fn early_routed_rejection_keeps_both_arenas_and_exact_xml() -> TestResult {
    use crate::stages::ingress::iq::{RoutedIqError, render_routed_omitted_error};
    let allocator = Arc::new(EarlyErrorAllocator::default());
    let (request, arena, _) = request(
        allocator.clone(),
        "alice@remote.test/desk",
        "bob@localhost",
        "private-payload",
    )?;
    let source = RoutedStanza::from_parts(request, arena);
    let before = allocator.calls.load(Ordering::SeqCst);
    let RoutedIqError { stanza, retained_source } = render_routed_omitted_error(
        &allocator, &source, lonewolf_xmpp::stanza::StanzaErrorCondition::Forbidden,
        lonewolf_xmpp::stanza::StanzaErrorText::Static("This operation requires an omitted destination or your authenticated bare JID without a resource."),
    ).map_err(|_| "early reply failed")?;
    assert_eq!(allocator.calls.load(Ordering::SeqCst) - before, 2);
    assert_eq!(allocator.live.load(Ordering::SeqCst), 3);
    assert_eq!(retained_source.stats().chunk_count, 1);
    let mut xml = String::new();
    stanza.resolve()?.write_xml(&mut xml)?;
    assert_eq!(
        xml,
        r#"<iq xmlns="jabber:client" from="bob@localhost" to="alice@remote.test/desk" id="request" type="error"><error type="auth"><forbidden xmlns="urn:ietf:params:xml:ns:xmpp-stanzas"/><text xmlns="urn:ietf:params:xml:ns:xmpp-stanzas" xml:lang="en">This operation requires an omitted destination or your authenticated bare JID without a resource.</text></error></iq>"#
    );
    assert_eq!(
        source.resolve()?.to()?.ok_or("source to")?.as_str(),
        "bob@localhost"
    );
    drop(retained_source);
    assert_eq!(allocator.live.load(Ordering::SeqCst), 2);
    drop(stanza);
    assert_eq!(allocator.live.load(Ordering::SeqCst), 1);
    drop(source);
    assert_eq!(allocator.live.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn early_routed_rejection_allocation_failures_release_only_temporary_arenas() -> TestResult {
    use crate::stages::ingress::iq::render_routed_omitted_error;
    for failed_allocation in [1, 2] {
        let allocator = Arc::new(EarlyErrorAllocator::default());
        let (request, arena, _) = request(
            allocator.clone(),
            "alice@remote.test/desk",
            "bob@localhost",
            "private-payload",
        )?;
        let source = RoutedStanza::from_parts(request, arena);
        let before = allocator.calls.load(Ordering::SeqCst);
        allocator
            .fail_at
            .store(before + failed_allocation, Ordering::SeqCst);
        let result = render_routed_omitted_error(
            &allocator,
            &source,
            lonewolf_xmpp::stanza::StanzaErrorCondition::Forbidden,
            lonewolf_xmpp::stanza::StanzaErrorCondition::Forbidden.default_text(),
        );
        assert!(result.is_err());
        assert_eq!(
            allocator.calls.load(Ordering::SeqCst) - before,
            failed_allocation
        );
        assert_eq!(allocator.live.load(Ordering::SeqCst), 1);
        assert_eq!(source.resolve()?.id()?, Some("request"));
        drop(source);
        assert_eq!(allocator.live.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
struct BorrowedPolicyCall {
    account: String,
    address: usize,
    direction: lonewolf_extension::policy::Direction,
    peer: String,
}

struct ForwardingPolicy {
    verdict: lonewolf_extension::policy::Verdict,
    calls: PlMutex<Vec<BorrowedPolicyCall>>,
}

impl<A: ChunkAllocator + Clone + 'static> Extension<A, RedbStorage> for ForwardingPolicy {
    fn name(&self) -> &'static str {
        "forwarding-policy"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, A, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.policy(self.clone());
        slots.presence(
            lonewolf_extension::presence::PresenceRequestType::Available,
            self,
        )
    }
}

impl lonewolf_extension::policy::PolicyHandler<RedbStorage> for ForwardingPolicy {
    fn check<'a>(
        &'a self,
        request: lonewolf_extension::policy::PolicyRequest<'a>,
        _: &'a RedbRead,
    ) -> lonewolf_extension::policy::PolicyFuture<'a> {
        Box::pin(async move {
            self.calls.lock().push(BorrowedPolicyCall {
                account: request.account.as_str().into(),
                address: std::ptr::from_ref(request.account) as usize,
                direction: request.direction,
                peer: request.peer.as_str().into(),
            });
            Ok(
                if request.direction == lonewolf_extension::policy::Direction::Outbound {
                    lonewolf_extension::policy::Verdict::Allow
                } else {
                    self.verdict
                },
            )
        })
    }
}

impl<A: ChunkAllocator> lonewolf_extension::presence::PresenceHandler<A, RedbStorage>
    for ForwardingPolicy
{
    fn visibility<'a>(
        &'a self,
        _: &'a lonewolf_storage::account::AccountKey,
        _: lonewolf_xmpp::jid::JidRef<'a>,
        _: &'a RedbRead,
    ) -> lonewolf_extension::presence::PresenceFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }
}

#[test]
fn remote_origin_forwards_full_jid_iq_without_an_extra_arena() -> TestResult {
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let allocator = Arc::new(CountingAllocator::default());
        let policy = Arc::new(ForwardingPolicy {
            verdict: lonewolf_extension::policy::Verdict::Allow,
            calls: PlMutex::default(),
        });
        let mut extensions = Extensions::default();
        extensions.register(policy.clone())?;
        let router = Router::new(
            Hosts::new(&Config::default().hosts, None)?,
            LocalRouter::new(allocator.clone()),
        )
        .with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", ["forwarding-policy"])?,
        )]));
        let handle = router.handle();
        let phone = handle
            .register(&account("bob@localhost")?, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let work = WorkGroup::new();
        let worker = work.handle();
        let stage = Stage {
            router: &handle,
            storage: &storage,
            allocator: &allocator,
            work: &worker,
        };
        let (stanza, arena, _) = request(
            allocator.clone(),
            "alice@remote.test/desk",
            "bob@localhost/phone",
            "payload",
        )?;
        let routed = RoutedStanza::from_parts(stanza, arena);
        let mut expected = String::new();
        routed.resolve()?.write_xml(&mut expected)?;
        let before = allocator.0.load(Ordering::SeqCst);
        let disposition = super::super::iq::handle(
            &stage,
            &Origin::Remote {
                local: "localhost",
                remote: "remote.test",
            },
            IqInput::Routed(routed),
            Destination::Resource,
            IqType::Get,
        )
        .await
        .map_err(|_| "forward failed")?;
        assert!(matches!(disposition, IqDisposition::Done));
        assert_eq!(allocator.0.load(Ordering::SeqCst), before);
        let delivered = phone.recv().await.ok_or("forwarded request")?;
        let mut actual = String::new();
        delivered.stanza.resolve()?.write_xml(&mut actual)?;
        assert_eq!(actual, expected);
        assert_eq!(policy.calls.lock().len(), 1);
        drop((delivered, phone));
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn owned_policy_rejection_borrows_authenticated_sender_and_preserves_request_arena() -> TestResult {
    Runtime::new()?.block_on(async {
        use lonewolf_extension::policy::{Direction, Verdict};
        use lonewolf_xmpp::stanza::StanzaErrorCondition;
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let allocator = Arc::new(CountingAllocator::default());
        let policy = Arc::new(ForwardingPolicy {
            verdict: Verdict::Reject {
                condition: StanzaErrorCondition::ServiceUnavailable,
                application: None,
                text: None,
            },
            calls: PlMutex::default(),
        });
        let mut extensions = Extensions::default();
        extensions.register(policy.clone())?;
        let router = Router::new(
            Hosts::new(&Config::default().hosts, None)?,
            LocalRouter::new(allocator.clone()),
        )
        .with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", ["forwarding-policy"])?,
        )]));
        let handle = router.handle();
        let session = handle
            .register(
                &account("alice@localhost")?,
                Some("desk"),
                NonZeroUsize::MIN,
            )
            .await?;
        let work = WorkGroup::new();
        let worker = work.handle();
        let stage = Stage {
            router: &handle,
            storage: &storage,
            allocator: &allocator,
            work: &worker,
        };
        for raw_from in [Some("mallory@remote.test/spoof"), None] {
            for (target, destination) in [
                ("bob@localhost", Destination::Account),
                ("bob@localhost/phone", Destination::Resource),
            ] {
                policy.calls.lock().clear();
                let (stanza, mut arena, _) =
                    request(allocator.clone(), "alice@localhost/desk", target, "payload")?;
                let sender = Jid::parse_in("alice@localhost/desk", &mut arena)?;
                let raw = raw_from
                    .map(|from| Jid::parse_in(from, &mut arena))
                    .transpose()?;
                let stanza = stanza.derive_in(&mut arena)?.from(raw)?.build()?;
                let used = arena.stats().used_bytes;
                let before = allocator.0.load(Ordering::SeqCst);
                let disposition = super::super::iq::handle(
                    &stage,
                    &Origin::Session(&session),
                    IqInput::Owned {
                        request: stanza,
                        arena,
                        sender,
                    },
                    destination,
                    IqType::Get,
                )
                .await
                .map_err(|_| "policy failed")?;
                let IqDisposition::PolicyRejected {
                    input: IqInput::Owned { request, arena, .. },
                    ..
                } = disposition
                else {
                    return Err("owned rejection lost".into());
                };
                assert_eq!(allocator.0.load(Ordering::SeqCst), before);
                assert_eq!(arena.stats().used_bytes, used);
                assert_eq!(
                    request.resolve(&arena)?.from()?.map(|from| from.as_str()),
                    raw_from
                );
                let calls = policy.calls.lock();
                assert_eq!(calls.len(), 2);
                assert_eq!(calls[0].account, "alice@localhost");
                assert_eq!(calls[0].direction, Direction::Outbound);
                assert_eq!(calls[0].peer, target);
                assert_eq!(calls[1].account, "bob@localhost");
                assert_eq!(calls[1].direction, Direction::Inbound);
                assert_eq!(calls[1].peer, "alice@localhost/desk");
            }
        }
        policy.calls.lock().clear();
        let (stanza, mut arena, sender) = request(
            allocator.clone(),
            "alice@localhost/desk",
            "alice@localhost",
            "",
        )?;
        let stanza = stanza
            .derive_in(&mut arena)?
            .to(None)?
            .from(None)?
            .build()?;
        let disposition = super::super::iq::handle(
            &stage,
            &Origin::Session(&session),
            IqInput::Owned {
                request: stanza,
                arena,
                sender,
            },
            Destination::Account,
            IqType::Get,
        )
        .await
        .map_err(|_| "own account failed")?;
        assert!(matches!(disposition, IqDisposition::Unavailable { .. }));
        assert!(policy.calls.lock().is_empty());
        drop(session);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn borrowed_policy_checks_reuse_target_key_and_authenticated_inbound_peer() -> TestResult {
    Runtime::new()?.block_on(async {
        use lonewolf_extension::policy::Direction;
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let policy = Arc::new(ForwardingPolicy {
            verdict: lonewolf_extension::policy::Verdict::Allow,
            calls: PlMutex::default(),
        });
        let mut extensions = Extensions::default();
        extensions.register(policy.clone())?;
        let router = Router::new(
            Hosts::new(&Config::default().hosts, None)?,
            LocalRouter::new(GlobalChunkAllocator),
        )
        .with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", ["forwarding-policy"])?,
        )]));
        let handle = router.handle();
        let source = account("alice@localhost")?;
        let target = account("bob@localhost")?;
        let (stanza, mut arena, sender) = request(
            GlobalChunkAllocator,
            "alice@localhost/desk",
            "bob@localhost/phone",
            "",
        )?;
        let spoof = Jid::parse_in("mallory@remote.test/spoof", &mut arena)?;
        let stanza = stanza.derive_in(&mut arena)?.from(Some(spoof))?.build()?;
        let verdict = super::super::checks::check_from(
            &handle,
            &storage,
            Some(&source),
            Some(&target),
            &stanza.resolve(&arena)?,
            Some(sender.resolve(&arena)?),
            super::super::checks::Snapshot::Fresh,
        )
        .await
        .map_err(|_| "check failed")?;
        assert_eq!(verdict, lonewolf_extension::policy::Verdict::Allow);
        {
            let calls = policy.calls.lock();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].direction, Direction::Outbound);
            assert_eq!(calls[1].direction, Direction::Inbound);
            assert_eq!(calls[1].peer, "alice@localhost/desk");
            assert_eq!(calls[0].address, std::ptr::from_ref(&source) as usize);
            assert_eq!(calls[1].address, std::ptr::from_ref(&target) as usize);
        }
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn unsupported_remote_iq_responses_are_silent() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(false)?;
        for destination in [
            Destination::Remote,
            Destination::Service,
            Destination::ServerResource,
        ] {
            for kind in [IqType::Result, IqType::Error] {
                let (stanza, mut arena, sender) = request(
                    GlobalChunkAllocator,
                    "alice@remote.test/desk",
                    "localhost/unsupported",
                    "",
                )?;
                let stanza = if kind == IqType::Error {
                    let target = Jid::parse_in("localhost/unsupported", &mut arena)?;
                    let condition = lonewolf_xmpp::stanza::StanzaErrorCondition::ServiceUnavailable;
                    stanza
                        .error_reply_described_in(
                            &mut arena,
                            condition,
                            None,
                            condition.default_text(),
                        )?
                        .from(Some(sender))?
                        .to(Some(target))?
                        .build()?
                } else {
                    stanza
                        .derive_in(&mut arena)?
                        .stanza_type(StanzaType::Iq(kind))
                        .build()?
                };
                let disposition = super::super::iq::handle(
                    &fixture.stage(),
                    &Origin::Remote {
                        local: "localhost",
                        remote: "remote.test",
                    },
                    IqInput::Routed(RoutedStanza::from_parts(stanza, arena)),
                    destination,
                    kind,
                )
                .await
                .map_err(|_| "response failed")?;
                assert!(matches!(disposition, IqDisposition::Done));
            }
        }
        fixture.router.shutdown().await?;
        Ok(())
    })
}
