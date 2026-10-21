// SPDX-License-Identifier: Apache-2.0

use super::*;
use lonewolf_extension::iq::{IqFuture, IqRequestKey, IqRoute};
use lonewolf_extension::policy::{PolicyFuture, PolicyHandler, PolicyRequest};
use lonewolf_extension::service::{ServiceContext, ServiceHandler};
use lonewolf_extension::{Extension, ExtensionFuture, Extensions, RegistrationError, Slots};
use lonewolf_xmpp::stanza::STANZA_ERROR_NAMESPACE;
use std::collections::BTreeMap;

const KEY: IqRequestKey = IqRequestKey {
    kind: IqRequestType::Set,
    namespace: "urn:test:destination",
    name: "guarded",
};

struct Guard;

impl Extension<GlobalChunkAllocator, RedbStorage> for Guard {
    fn name(&self) -> &'static str {
        "guard"
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq_destination(KEY, IqDestinationRule::SenderBare)
    }
}

#[derive(Default)]
struct Probe {
    iq: AtomicUsize,
    service: AtomicUsize,
    policy: AtomicUsize,
}

impl Extension<GlobalChunkAllocator, RedbStorage> for Probe {
    fn name(&self) -> &'static str {
        "probe"
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        for scope in [IqScope::Server, IqScope::Account] {
            for kind in [IqRequestType::Get, IqRequestType::Set] {
                for (namespace, name) in [
                    (KEY.namespace, KEY.name),
                    (KEY.namespace, "unrelated"),
                    ("urn:test:unrelated", KEY.name),
                ] {
                    slots.iq(
                        IqRoute {
                            scope,
                            kind,
                            namespace,
                            name,
                        },
                        self.clone(),
                    )?;
                }
            }
        }
        slots.policy(self);
        Ok(())
    }
}

impl IqHandler<GlobalChunkAllocator, RedbStorage> for Probe {
    fn get<'a>(
        &'a self,
        _request: IqRequest<'a, GlobalChunkAllocator>,
        _transaction: &'a RedbRead,
        _response: &'a mut Arena<GlobalChunkAllocator>,
    ) -> IqFuture<'a, GlobalChunkAllocator> {
        Box::pin(async move {
            self.iq.fetch_add(1, Ordering::SeqCst);
            Ok(IqReply::new(None, Effects::none()))
        })
    }

    fn set<'a>(
        &'a self,
        _request: IqRequest<'a, GlobalChunkAllocator>,
        _transaction: &'a mut RedbWrite,
        _hosts: &'a dyn lonewolf_extension::delivery::HostLookup,
        _response: &'a mut Arena<GlobalChunkAllocator>,
    ) -> IqFuture<'a, GlobalChunkAllocator> {
        Box::pin(async move {
            self.iq.fetch_add(1, Ordering::SeqCst);
            Ok(IqReply::new(None, Effects::none()))
        })
    }
}

impl ServiceHandler<GlobalChunkAllocator, RedbStorage> for Probe {
    fn route<'a>(
        &'a self,
        _stanza: RoutedStanza<GlobalChunkAllocator>,
        _context: ServiceContext<'a, GlobalChunkAllocator, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            self.service.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

impl PolicyHandler<RedbStorage> for Probe {
    fn check<'a>(
        &'a self,
        _request: PolicyRequest<'a>,
        _transaction: &'a RedbRead,
    ) -> PolicyFuture<'a> {
        Box::pin(async move {
            self.policy.fetch_add(1, Ordering::SeqCst);
            Ok(Verdict::Allow)
        })
    }
}

fn recipients_without_refill(burst: NonZeroUsize) -> RecipientLimiter {
    RecipientLimiter::new(
        NonZeroUsize::MIN,
        burst,
        Instant::now() + Duration::from_secs(3600),
        crate::c2s::metrics::C2sWorkerMetrics::detached(),
    )
}

async fn setup<'a>(
    fixture: &'a Fixture,
    probe: &Arc<Probe>,
    source: bool,
    target: bool,
) -> TestResult<(
    Router<GlobalChunkAllocator>,
    BoundSession<'a, GlobalChunkAllocator, ControlledWriter>,
)> {
    let mut config = Config::default();
    config.hosts.insert(
        "other.localhost".into(),
        crate::config::HostConfig {
            tls: Some(crate::config::HostTlsConfig {
                source: crate::config::HostTlsSource::LetsEncrypt,
                client_auth: None,
            }),
            ..Default::default()
        },
    );
    let mut extensions = Extensions::default();
    extensions.register(Arc::new(Guard))?;
    extensions.register(probe.clone())?;
    let mut registries = BTreeMap::new();
    for (domain, guarded) in [("localhost", source), ("other.localhost", target)] {
        let enabled = if guarded {
            vec!["guard", "probe"]
        } else {
            vec!["probe"]
        };
        registries.insert(domain.into(), extensions.enable_host(domain, enabled)?);
    }
    let router = Router::new(
        Hosts::new(&config.hosts, Some("localhost"))?,
        LocalRouter::new(GlobalChunkAllocator),
    )
    .with_extensions(registries)
    .with_services(BTreeMap::from([(
        "svc.other.localhost".into(),
        ServiceRoute {
            domain: Arc::from("svc.other.localhost"),
            handler: probe.clone(),
        },
    )]));
    let registration = router
        .handle()
        .register(
            fixture.registration.account(),
            Some("desk"),
            NonZeroUsize::new(8).ok_or("resource limit")?,
        )
        .await?;
    let (_sender, incoming) = async_channel::bounded(1);
    let mut outbox = fixture.outbox(GlobalChunkAllocator, ControlledWriter::default());
    outbox.liveness = registration.liveness();
    let session = BoundSession {
        registration,
        router: router.handle(),
        storage: fixture.storage.clone(),
        allocator: GlobalChunkAllocator,
        work: fixture.work.handle(),
        service_presence: None,
        service_pending: None,
        recipients: recipients_without_refill(NonZeroUsize::new(100).ok_or("burst")?),
        available: false,
        priority: None,
        incoming,
        outbox,
    };
    Ok((router, session))
}

async fn request(
    kind: &str,
    target: Option<&str>,
    namespace: &str,
    name: &str,
) -> TestResult<Parsed<Stanza, GlobalChunkAllocator>> {
    let to = target.map(|to| format!(" to='{to}'")).unwrap_or_default();
    let error = if kind == "error" {
        "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
    } else {
        ""
    };
    let xml = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' xml:lang='fr'><iq type='{kind}' id='guard&amp;id' from='mallory@remote/spy'{to}><{name} xmlns='{namespace}'>private-synthetic-content</{name}>{error}</iq>"
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
    let Some(StreamEvent::Stanza(parsed)) = parser.next_event().await? else {
        return Err("missing IQ".into());
    };
    Ok(parsed)
}

fn assert_error(
    session: &BoundSession<'_, GlobalChunkAllocator, ControlledWriter>,
    target: &str,
    condition: StanzaErrorCondition,
) -> TestResult {
    assert_eq!(session.outbox.queue.len(), 1);
    let Some(Output::Owned { stanza, arena }) = session.outbox.queue.front() else {
        return Err("missing error".into());
    };
    let view = stanza.resolve(arena)?;
    assert_eq!(view.stanza_type(), StanzaType::Iq(IqType::Error));
    assert_eq!(view.id()?, Some("guard&id"));
    assert_eq!(
        view.to()?.map(|jid| jid.as_str()),
        Some("bob@localhost/desk")
    );
    assert_eq!(view.from()?.map(|jid| jid.as_str()), Some(target));
    assert_eq!(view.lang()?, Some("fr"));
    let children = view.children()?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        children.len(),
        if condition == StanzaErrorCondition::Forbidden {
            1
        } else {
            2
        }
    );
    let error = children.last().ok_or("missing error element")?;
    assert_eq!(error.name(), "error");
    assert_eq!(error.attribute("type", "")?, Some(condition.error_type()));
    let condition_element = error
        .child(condition.as_str(), STANZA_ERROR_NAMESPACE)?
        .ok_or("missing condition")?;
    assert_eq!(condition_element.children()?.count(), 0);
    let mut xml = String::new();
    view.write_xml(&mut xml)?;
    assert!(!xml.contains("mallory"));
    if condition == StanzaErrorCondition::Forbidden {
        assert!(!xml.contains("private-synthetic-content"));
        assert!(!xml.contains(KEY.namespace));
        assert_eq!(condition.error_type(), "auth");
    }
    Ok(())
}

async fn account(storage: &RedbStorage, address: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(Default::default())?;
    let key = AccountKey::try_from(Jid::parse_in(address, &mut arena)?.resolve(&arena)?)?;
    let mut transaction = storage.begin_write().await?;
    transaction
        .create_account(NewAccount {
            key: key.clone(),
            credentials: credentials(),
        })
        .await?;
    transaction.commit().await?;
    Ok(key)
}

#[test]
fn iq_destination_host_matrix_uses_only_exact_normalized_domains() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        for source in [false, true] {
            for target in [false, true] {
                let probe = Arc::new(Probe::default());
                let (router, mut session) = setup(&fixture, &probe, source, target).await?;
                for (address, target_enabled) in [
                    ("bob@other.localhost", target),
                    ("BOB@OTHER.LOCALHOST", target),
                    ("bob@other.localhost/resource", target),
                    ("other.localhost", target),
                    ("other.localhost/resource", target),
                    ("alice@localhost", source),
                    ("bob@remote.example", false),
                    ("remote.example", false),
                    ("bob@sub.other.localhost", false),
                    ("svc.other.localhost", false),
                    ("room@svc.other.localhost/nick", false),
                ] {
                    let parsed = request("set", Some(address), KEY.namespace, KEY.name).await?;
                    let normalized = parsed
                        .value()
                        .resolve(parsed.arena())?
                        .to()?
                        .ok_or("target")?
                        .as_str()
                        .to_owned();
                    let result = session
                        .admit_iq(parsed)
                        .map_err(|error| format!("{error:?}"))?;
                    if source || target_enabled {
                        assert!(result.is_none(), "{source}/{target}/{address}");
                        assert_error(&session, &normalized, StanzaErrorCondition::Forbidden)?;
                        session.outbox.queue.clear();
                    } else {
                        assert!(result.is_some(), "{source}/{target}/{address}");
                        assert!(session.outbox.queue.is_empty());
                    }
                }
                assert_eq!(probe.iq.load(Ordering::SeqCst), 0);
                assert_eq!(probe.service.load(Ordering::SeqCst), 0);
                assert_eq!(probe.policy.load(Ordering::SeqCst), 0);
                drop(session);
                router.shutdown().await?;
            }
        }
        fixture.finish().await
    })
}

#[test]
fn iq_destination_rejections_precede_target_work_and_never_deliver() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(10), async {
        let fixture = Fixture::new(&[]).await?;
        let alice = account(&fixture.storage, "alice@localhost").await?;
        let unavailable = account(&fixture.storage, "offline@localhost").await?;
        let probe = Arc::new(Probe::default());
        let (router, mut session) = setup(&fixture, &probe, true, true).await?;
        let own = router
            .handle()
            .register(
                fixture.registration.account(),
                Some("phone"),
                NonZeroUsize::new(8).ok_or("resources")?,
            )
            .await?;
        let hidden = router
            .handle()
            .register(
                &alice,
                Some("hidden"),
                NonZeroUsize::new(8).ok_or("resources")?,
            )
            .await?;
        let available = router
            .handle()
            .register(
                &alice,
                Some("available"),
                NonZeroUsize::new(8).ok_or("resources")?,
            )
            .await?;
        available
            .handle()
            .set_presence(
                Some(0),
                routed_presence("alice@localhost/available", None, PresenceType::Available)?,
                None,
            )
            .await?;
        let (_value, mut order) = router
            .handle()
            .order()
            .fix(
                vec![alice.clone(), fixture.registration.account().clone()],
                async { Ok::<_, RouterError>(()) },
            )
            .await?;
        order.turn().await;
        let held = fixture.storage.begin_write().await?;
        for address in [
            "bob@localhost/desk",
            "bob@localhost/phone",
            "bob@localhost/missing",
            "alice@localhost",
            "alice@localhost/hidden",
            "alice@localhost/available",
            "alice@localhost/missing",
            "offline@localhost",
            "offline@localhost/missing",
            "missing@localhost",
            "missing@localhost/missing",
            "localhost",
            "localhost/resource",
            "remote.example",
            "remote.example/resource",
            "bob@remote.example",
            "bob@remote.example/resource",
            "svc.other.localhost",
            "room@svc.other.localhost/nick",
        ] {
            session
                .handle_stanza(request("set", Some(address), KEY.namespace, KEY.name).await?)
                .now_or_never()
                .ok_or("constraint rejection started asynchronous target work")?
                .map_err(|error| format!("{error:?}"))?;
            assert_error(&session, address, StanzaErrorCondition::Forbidden)?;
            assert_eq!(probe.iq.load(Ordering::SeqCst), 0);
            assert_eq!(probe.service.load(Ordering::SeqCst), 0);
            assert_eq!(probe.policy.load(Ordering::SeqCst), 0);
            assert!(own.take_queued().is_empty());
            assert!(hidden.take_queued().is_empty());
            assert!(available.take_queued().is_empty());
            assert!(session.registration.take_queued().is_empty());
            session
                .outbox
                .flush()
                .await
                .map_err(|error| format!("{error:?}"))?;
            assert_eq!(session.outbox.writer.written.len(), 1);
            session.outbox.writer.written.clear();
        }
        drop(held);
        drop(order);
        for key in [&alice, &unavailable, fixture.registration.account()] {
            assert_eq!(
                fixture
                    .storage
                    .begin_read()
                    .await?
                    .offline_count(key)
                    .await?,
                0
            );
        }
        drop((own, hidden, available, session));
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn iq_destination_owner_and_unmatched_requests_keep_existing_dispatch() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        account(&fixture.storage, "alice@localhost").await?;
        let probe = Arc::new(Probe::default());
        let (router, mut session) = setup(&fixture, &probe, true, false).await?;
        for target in [None, Some("bob@localhost"), Some("BOB@LOCALHOST")] {
            let parsed = request("set", target, KEY.namespace, KEY.name).await?;
            session
                .handle_stanza(parsed)
                .await
                .map_err(|error| format!("{error:?}"))?;
            let Some(Output::Owned { stanza, arena }) = session.outbox.queue.front() else {
                return Err("missing result".into());
            };
            assert_eq!(
                stanza.resolve(arena)?.stanza_type(),
                StanzaType::Iq(IqType::Result)
            );
            session.outbox.queue.clear();
        }
        assert_eq!(probe.iq.load(Ordering::SeqCst), 3);
        for (kind, namespace, name) in [
            ("get", KEY.namespace, KEY.name),
            ("set", "urn:test:unrelated", KEY.name),
            ("set", KEY.namespace, "unrelated"),
        ] {
            session
                .handle_stanza(request(kind, Some("alice@localhost"), namespace, name).await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            let Some(Output::Owned { stanza, arena }) = session.outbox.queue.front() else {
                return Err("missing unguarded result".into());
            };
            assert_eq!(
                stanza.resolve(arena)?.stanza_type(),
                StanzaType::Iq(IqType::Result)
            );
            session.outbox.queue.clear();
            session
                .handle_stanza(request(kind, Some("svc.other.localhost"), namespace, name).await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            assert!(session.outbox.queue.is_empty());
        }
        assert_eq!(probe.iq.load(Ordering::SeqCst), 6);
        assert_eq!(probe.service.load(Ordering::SeqCst), 3);
        assert!(probe.policy.load(Ordering::SeqCst) >= 3);
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    })
}

#[test]
fn iq_destination_responses_skip_rules_and_preserve_resource_routing_without_loops() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let probe = Arc::new(Probe::default());
        let (router, mut session) = setup(&fixture, &probe, true, true).await?;
        let other = router
            .handle()
            .register(
                fixture.registration.account(),
                Some("phone"),
                NonZeroUsize::new(8).ok_or("resources")?,
            )
            .await?;
        for kind in ["result", "error"] {
            for address in [
                "bob@localhost/phone",
                "bob@localhost/missing",
                "missing@localhost",
                "remote.example",
                "localhost",
            ] {
                session
                    .handle_stanza(request(kind, Some(address), KEY.namespace, KEY.name).await?)
                    .await
                    .map_err(|error| format!("{error:?}"))?;
                assert!(session.outbox.queue.is_empty());
                assert_eq!(
                    other.take_queued().len(),
                    usize::from(address == "bob@localhost/phone")
                );
            }
            session
                .handle_stanza(
                    request(kind, Some("svc.other.localhost"), KEY.namespace, KEY.name).await?,
                )
                .await
                .map_err(|error| format!("{error:?}"))?;
            assert!(session.outbox.queue.is_empty());
        }
        assert_eq!(probe.service.load(Ordering::SeqCst), 2);
        assert_eq!(probe.iq.load(Ordering::SeqCst), 0);
        drop((other, session));
        router.shutdown().await?;
        fixture.finish().await
    })
}

#[test]
fn iq_destination_recipient_limit_precedes_constraints_and_keeps_exemptions() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let probe = Arc::new(Probe::default());
        let (router, mut session) = setup(&fixture, &probe, true, true).await?;
        session.recipients = recipients_without_refill(NonZeroUsize::MIN);
        for (address, condition) in [
            ("alice@localhost", StanzaErrorCondition::Forbidden),
            ("other@localhost", StanzaErrorCondition::PolicyViolation),
            ("alice@localhost/resource", StanzaErrorCondition::Forbidden),
        ] {
            session
                .handle_stanza(request("set", Some(address), KEY.namespace, KEY.name).await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            assert_error(&session, address, condition)?;
            session.outbox.queue.clear();
        }
        assert_eq!(session.recipients.admission_calls(), 3);
        for target in [
            None,
            Some("BOB@LOCALHOST"),
            Some("bob@localhost/desk"),
            Some("localhost"),
            Some("localhost/resource"),
            Some("svc.other.localhost"),
        ] {
            let parsed = request("set", target, KEY.namespace, KEY.name).await?;
            let accepted = session
                .admit_iq(parsed)
                .map_err(|error| format!("{error:?}"))?;
            assert_eq!(
                accepted.is_some(),
                matches!(target, None | Some("BOB@LOCALHOST"))
            );
            if let Some(address) = target.filter(|_| accepted.is_none()) {
                assert_error(&session, address, StanzaErrorCondition::Forbidden)?;
            }
            session.outbox.queue.clear();
        }
        for kind in ["result", "error"] {
            assert!(
                session
                    .admit_iq(
                        request(
                            kind,
                            Some("new@localhost/resource"),
                            KEY.namespace,
                            KEY.name
                        )
                        .await?
                    )
                    .map_err(|error| format!("{error:?}"))?
                    .is_some()
            );
        }
        assert_eq!(session.recipients.admission_calls(), 3);
        assert!(session.outbox.queue.is_empty());
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    })
}

#[test]
fn iq_destination_accepted_requests_preserve_recipient_allowance() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        account(&fixture.storage, "alice@localhost").await?;
        account(&fixture.storage, "carol@localhost").await?;
        let probe = Arc::new(Probe::default());
        let (router, mut session) = setup(&fixture, &probe, true, true).await?;
        session.recipients = recipients_without_refill(NonZeroUsize::new(2).ok_or("burst")?);
        for address in ["alice@localhost", "carol@localhost"] {
            session
                .handle_stanza(request("get", Some(address), KEY.namespace, KEY.name).await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            let Some(Output::Owned { stanza, arena }) = session.outbox.queue.front() else {
                return Err("missing result".into());
            };
            assert_eq!(
                stanza.resolve(arena)?.stanza_type(),
                StanzaType::Iq(IqType::Result)
            );
            session.outbox.queue.clear();
        }
        assert_eq!(session.recipients.admission_calls(), 2);
        assert_eq!(probe.iq.load(Ordering::SeqCst), 2);
        session
            .handle_stanza(request("get", Some("new@localhost"), KEY.namespace, KEY.name).await?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_error(
            &session,
            "new@localhost",
            StanzaErrorCondition::PolicyViolation,
        )?;
        assert_eq!(probe.iq.load(Ordering::SeqCst), 2);
        assert_eq!(session.recipients.admission_calls(), 3);
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    })
}

#[test]
fn iq_admission_preserves_accepted_parser_trees_without_allocating() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let probe = Arc::new(Probe::default());
        let (router, mut session) = setup(&fixture, &probe, true, true).await?;
        for (kind, target) in [
            ("set", None),
            ("set", Some("BOB@LOCALHOST")),
            ("get", Some("alice@localhost")),
            ("result", Some("alice@localhost/resource")),
            ("error", Some("alice@localhost/resource")),
        ] {
            let parsed = request(kind, target, KEY.namespace, KEY.name).await?;
            let original = parsed.value();
            let stats = parsed.arena().stats();
            let mut before = String::new();
            original.resolve(parsed.arena())?.write_xml(&mut before)?;
            let accepted = session
                .admit_iq(parsed)
                .map_err(|error| format!("{error:?}"))?
                .ok_or("accepted IQ rejected")?;
            assert_eq!(accepted.arena().stats(), stats);
            let mut after = String::new();
            original.resolve(accepted.arena())?.write_xml(&mut after)?;
            assert_eq!(after, before);
            let mut accepted_xml = String::new();
            accepted
                .value()
                .resolve(accepted.arena())?
                .write_xml(&mut accepted_xml)?;
            assert_eq!(accepted_xml, before);
        }
        assert!(session.outbox.queue.is_empty());
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    })
}
