// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use compio::runtime::Runtime;
use lonewolf_extension::ExtensionFuture;
use lonewolf_extension::delivery::{Failure, FailureKind, HandlerError};
use lonewolf_extension::service::ServiceHandler;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};

use super::*;
use crate::component::{credentials, metrics::ComponentMetrics};
use crate::config::{ComponentLimits, ComponentsConfig, Config};
use crate::delivery::WorkGroup;
use crate::hosts::Hosts;
use crate::router::Router;
use crate::router::local::LocalRouter;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn run(test: impl Future<Output = TestResult>) -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), test))?
}

struct RejectingService;

impl ServiceHandler<GlobalChunkAllocator, RedbStorage> for RejectingService {
    fn route<'a>(
        &'a self,
        _stanza: RoutedStanza<GlobalChunkAllocator>,
        _context: ServiceContext<'a, GlobalChunkAllocator, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async {
            Err(HandlerError::described(
                StanzaErrorCondition::BadRequest,
                lonewolf_xmpp::stanza::StanzaErrorText::Static(
                    "The service requires a supported request format.",
                ),
            ))
        })
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    storage: RedbStorage,
    router: Router<GlobalChunkAllocator>,
    handle: RouterHandle<GlobalChunkAllocator>,
    work: WorkHandle,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Self::with_services(BTreeMap::new())
    }

    fn with_services(
        mut services: BTreeMap<String, ServiceRoute<GlobalChunkAllocator>>,
    ) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, None)?;
        let route = ServiceRoute {
            domain: Arc::from("echo.localhost"),
            handler: Arc::new(RejectingService),
        };
        services.insert("echo.localhost".into(), route);
        let router =
            Router::new(hosts, LocalRouter::new(GlobalChunkAllocator)).with_services(services);
        let handle = router.handle();
        Ok(Self {
            _directory: directory,
            storage,
            router,
            handle,
            work: WorkGroup::new().handle(),
        })
    }

    fn stage(&self) -> Stage<'_, GlobalChunkAllocator> {
        Stage {
            router: &self.handle,
            storage: &self.storage,
            allocator: &GlobalChunkAllocator,
            work: &self.work,
        }
    }

    fn outbound(&self) -> Outbound<'_, GlobalChunkAllocator> {
        Outbound {
            router: &self.handle,
            storage: &self.storage,
            allocator: &GlobalChunkAllocator,
            work: &self.work,
            domain: "echo.localhost",
            component_reply: None,
        }
    }
}

async fn parsed(xml: &str) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let input = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>{xml}"
    );
    let mut parser = XmppParser::new(
        input.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4096).ok_or("zero stanza limit")?,
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

struct ComponentFixture {
    service: Fixture,
    registry: ComponentRegistry<GlobalChunkAllocator>,
    metrics: Arc<ComponentMetrics>,
}

struct UnexpectedComponentHandler;

impl ServiceHandler<GlobalChunkAllocator, RedbStorage> for UnexpectedComponentHandler {
    fn route<'a>(
        &'a self,
        _stanza: RoutedStanza<GlobalChunkAllocator>,
        _context: ServiceContext<'a, GlobalChunkAllocator, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        panic!("the reply path dispatched to a component service handler")
    }
}

impl ComponentFixture {
    fn new() -> TestResult<Self> {
        let config: ComponentsConfig = toml::from_str(
            "[domains.'muc.localhost']
secret = 'component-test-secret-0001'
max_connections = 2
[domains.'other.localhost']
secret = 'component-test-secret-0002'",
        )?;
        let limits = ComponentLimits {
            max_queued_stanzas: NonZeroUsize::MIN,
            ..ComponentLimits::default()
        };
        let metrics = ComponentMetrics::new(1, config.domains.len());
        let registry = ComponentRegistry::new(
            &config,
            credentials::load(&config)?,
            &limits,
            metrics.clone(),
        );
        let services = config
            .domains
            .into_keys()
            .map(|domain| {
                let route = ServiceRoute {
                    domain: Arc::from(domain.as_str()),
                    handler: Arc::new(UnexpectedComponentHandler),
                };
                (domain, route)
            })
            .collect();
        Ok(Self {
            service: Fixture::with_services(services)?,
            registry,
            metrics,
        })
    }

    fn target(&self, connection_id: u64) -> Option<ComponentReplyTarget<'_, GlobalChunkAllocator>> {
        Some(ComponentReplyTarget {
            registry: &self.registry,
            domain: "muc.localhost",
            connection_id,
        })
    }
}

struct ReplyingService {
    replies: Vec<(RoutedStanza<GlobalChunkAllocator>, bool)>,
    result: Result<(), HandlerError>,
}

impl ServiceHandler<GlobalChunkAllocator, RedbStorage> for ReplyingService {
    fn route<'a>(
        &'a self,
        _stanza: RoutedStanza<GlobalChunkAllocator>,
        context: ServiceContext<'a, GlobalChunkAllocator, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            for (index, (reply, accepted)) in self.replies.iter().enumerate() {
                assert_eq!(
                    context.outbound.route(reply.clone()).await.is_ok(),
                    *accepted,
                    "outbound response {index}"
                );
            }
            self.result
        })
    }
}

async fn replying_route(
    replies: &[(&str, bool)],
    result: Result<(), HandlerError>,
) -> TestResult<ServiceRoute<GlobalChunkAllocator>> {
    let mut stanzas = Vec::with_capacity(replies.len());
    for (xml, accepted) in replies {
        stanzas.push((parsed(xml).await?, *accepted));
    }
    Ok(ServiceRoute {
        domain: Arc::from("echo.localhost"),
        handler: Arc::new(ReplyingService {
            replies: stanzas,
            result,
        }),
    })
}

const GET: &str = concat!(
    "<iq type='get' id='reply' from='Visitor@MUC.LOCALHOST/nick' to='Room@ECHO.LOCALHOST/handler'>",
    "<query xmlns='urn:test'/></iq>"
);
const RESULT: &str = concat!(
    "<iq type='result' id='reply' from='room@echo.localhost/handler' ",
    "to='visitor@muc.localhost/nick'/>"
);

const HANDLER_FAILURE: HandlerError = HandlerError::Internal {
    condition: StanzaErrorCondition::InternalServerError,
    failure: Failure {
        kind: FailureKind::Delivery,
        operation: "test_service_reply",
    },
};

#[test]
fn component_dispatch_claims_one_correlated_result_or_error_per_request() -> TestResult {
    run(async {
        let fixture = ComponentFixture::new()?;
        let mut link = fixture
            .registry
            .attach("muc.localhost")
            .map_err(|_| "attach origin")?;
        let mut spare = fixture
            .registry
            .attach("muc.localhost")
            .map_err(|_| "attach spare")?;
        let stage = fixture.service.stage();
        let set = concat!(
            "<iq type='set' id='reply' from='visitor@muc.localhost/nick' to='room@echo.localhost/handler'>",
            "<query xmlns='urn:test'/></iq>"
        );
        let error = concat!(
            "<iq type='error' id='reply' from='room@echo.localhost/handler' to='visitor@muc.localhost/nick'>",
            "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
        );
        for (request, response, kind) in
            [(GET, RESULT, IqType::Result), (set, error, IqType::Error)]
        {
            let route =
                replying_route(&[(response, true), (response, false)], Err(HANDLER_FAILURE))
                    .await?;
            let outcome = dispatch_with_component_reply(
                &stage,
                &route,
                parsed(request).await?,
                fixture.target(link.id()),
            )
            .await
            .map_err(|_| "dispatch failed")?;
            assert!(matches!(outcome, ServiceOutcome::Handled));
            let delivered = link.try_next().ok_or("missing affine reply")?;
            let view = delivered.resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Iq(kind));
            assert_eq!(view.id()?, Some("reply"));
            assert_eq!(
                view.from()?.map(|jid| jid.as_str()),
                Some("room@echo.localhost/handler")
            );
            assert_eq!(
                view.to()?.map(|jid| jid.as_str()),
                Some("visitor@muc.localhost/nick")
            );
            assert!(link.try_next().is_none());
            assert!(spare.try_next().is_none());
        }
        fixture.service.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn component_dispatch_rejects_uncorrelated_stanzas_and_requires_origin_context() -> TestResult {
    run(async {
        let fixture = ComponentFixture::new()?;
        let mut link = fixture
            .registry
            .attach("muc.localhost")
            .map_err(|_| "attach origin")?;
        let mut other = fixture
            .registry
            .attach("other.localhost")
            .map_err(|_| "attach other domain")?;
        let stage = fixture.service.stage();
        let route = replying_route(&[
            ("<iq type='result' id='reply' from='outside.localhost' to='visitor@muc.localhost/nick'/>", false),
            ("<iq type='result' id='reply' from='room@echo.localhost/other' to='visitor@muc.localhost/nick'/>", false),
            ("<iq type='result' id='reply' from='room@echo.localhost/handler' to='other@muc.localhost/nick'/>", false),
            ("<iq type='result' id='reply' from='room@echo.localhost/handler' to='visitor@muc.localhost/other'/>", false),
            ("<iq type='result' id='reply' from='room@echo.localhost/handler' to='visitor@other.localhost/nick'/>", false),
            ("<iq type='result' id='different' from='room@echo.localhost/handler' to='visitor@muc.localhost/nick'/>", false),
            ("<iq type='get' id='reply' from='room@echo.localhost/handler' to='visitor@muc.localhost/nick'><query xmlns='urn:test'/></iq>", false),
            ("<message type='chat' id='reply' from='room@echo.localhost/handler' to='visitor@muc.localhost/nick'/>", false),
        ], Err(HANDLER_FAILURE)).await?;
        let outcome = dispatch_with_component_reply(
            &stage,
            &route,
            parsed(GET).await?,
            fixture.target(link.id()),
        )
        .await
        .map_err(|_| "dispatch failed")?;
        assert!(matches!(
            outcome,
            ServiceOutcome::Rejected {
                condition: StanzaErrorCondition::InternalServerError,
                ..
            }
        ));

        let route = replying_route(&[(RESULT, false)], Err(HANDLER_FAILURE)).await?;
        let outcome = dispatch(&stage, &route, parsed(GET).await?)
            .await
            .map_err(|_| "dispatch failed")?;
        assert!(matches!(
            outcome,
            ServiceOutcome::Rejected {
                condition: StanzaErrorCondition::InternalServerError,
                ..
            }
        ));

        let nonrequest = parsed("<iq type='result' id='reply' from='visitor@muc.localhost/nick' to='room@echo.localhost/handler'/>").await?;
        let outcome =
            dispatch_with_component_reply(&stage, &route, nonrequest, fixture.target(link.id()))
                .await
                .map_err(|_| "dispatch failed")?;
        assert!(matches!(outcome, ServiceOutcome::Handled));

        let other_origin = parsed("<iq type='get' id='reply' from='visitor@other.localhost/nick' to='room@echo.localhost/handler'><query xmlns='urn:test'/></iq>").await?;
        let other_reply = "<iq type='result' id='reply' from='room@echo.localhost/handler' to='visitor@other.localhost/nick'/>";
        let route = replying_route(&[(other_reply, false)], Err(HANDLER_FAILURE)).await?;
        let outcome =
            dispatch_with_component_reply(&stage, &route, other_origin, fixture.target(link.id()))
                .await
                .map_err(|_| "dispatch failed")?;
        assert!(matches!(
            outcome,
            ServiceOutcome::Rejected {
                condition: StanzaErrorCondition::InternalServerError,
                ..
            }
        ));

        assert!(link.try_next().is_none());
        assert!(other.try_next().is_none());
        fixture.service.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn component_dispatch_consumes_one_full_queue_attempt_and_falls_back_after_detach() -> TestResult {
    run(async {
        let fixture = ComponentFixture::new()?;
        let mut link = fixture
            .registry
            .attach("muc.localhost")
            .map_err(|_| "attach origin")?;
        let mut spare = fixture
            .registry
            .attach("muc.localhost")
            .map_err(|_| "attach spare")?;
        let origin = link.id();
        let stage = fixture.service.stage();
        let queued = parsed(
            "<message id='occupied' from='echo.localhost' to='visitor@muc.localhost/nick'/>",
        )
        .await?;
        fixture
            .registry
            .reply("muc.localhost", origin, queued)
            .map_err(|_| "fill origin queue")?;

        let route =
            replying_route(&[(RESULT, true), (RESULT, false)], Err(HANDLER_FAILURE)).await?;
        let outcome = dispatch_with_component_reply(
            &stage,
            &route,
            parsed(GET).await?,
            fixture.target(origin),
        )
        .await
        .map_err(|_| "dispatch failed")?;
        assert!(matches!(outcome, ServiceOutcome::Handled));
        assert!(spare.try_next().is_none());
        let occupied = link.try_next().ok_or("missing queued stanza")?;
        assert_eq!(occupied.resolve()?.id()?, Some("occupied"));
        assert!(link.try_next().is_none());

        let detached = link.detach();
        assert!(detached.stranded.is_empty());
        assert_eq!(detached.moved, 0);
        let outcome = dispatch_with_component_reply(
            &stage,
            &route,
            parsed(GET).await?,
            fixture.target(origin),
        )
        .await
        .map_err(|_| "dispatch failed")?;
        assert!(matches!(outcome, ServiceOutcome::Handled));
        let delivered = spare.try_next().ok_or("missing fallback reply")?;
        assert_eq!(
            delivered.resolve()?.stanza_type(),
            StanzaType::Iq(IqType::Result)
        );
        assert_eq!(delivered.resolve()?.id()?, Some("reply"));
        assert!(spare.try_next().is_none());

        let mut metrics = prometheus_client::registry::Registry::default();
        fixture
            .metrics
            .register(metrics.sub_registry_with_prefix("lonewolf"));
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &metrics)?;
        assert!(
            output.lines().any(|line| line
                == "lonewolf_component_admission_rejections_total{reason=\"queue_full\"} 1"),
            "{output}"
        );
        fixture.service.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn dispatch_replies_only_to_iq_requests_and_non_error_messages() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let route = fixture.handle.service("echo.localhost").ok_or("missing service")?;
        for (xml, rejected) in [
            ("<iq type='get' id='get' from='alice@localhost/desk' to='echo.localhost'><query xmlns='urn:test'/></iq>", true),
            ("<iq type='set' id='set' from='alice@localhost/desk' to='echo.localhost'><query xmlns='urn:test'/></iq>", true),
            ("<iq type='result' id='result' from='alice@localhost/desk' to='echo.localhost'/>", false),
            ("<iq type='error' id='error' from='alice@localhost/desk' to='echo.localhost'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>", false),
            ("<message type='chat' from='alice@localhost/desk' to='echo.localhost'/>", true),
            ("<message type='error' from='alice@localhost/desk' to='echo.localhost'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>", false),
            ("<presence type='subscribe' from='alice@localhost/desk' to='echo.localhost'/>", false),
            ("<presence type='unavailable' from='alice@localhost/desk' to='echo.localhost'/>", false),
        ] {
            let outcome = dispatch(&fixture.stage(), route, parsed(xml).await?).await.map_err(|_| "dispatch failed")?;
            match outcome {
                ServiceOutcome::Rejected { condition, text, .. } => {
                    assert!(rejected, "unexpected error reply: {xml}");
                    assert_eq!(condition, StanzaErrorCondition::BadRequest);
                    assert_eq!(text, lonewolf_xmpp::stanza::StanzaErrorText::Static("The service requires a supported request format."));
                }
                ServiceOutcome::Handled => assert!(!rejected, "missing error reply: {xml}"),
            }
        }
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn outbound_requires_the_service_sender_domain_and_a_supported_destination() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let mut arena = Arena::try_new(ArenaConfig::default())?;
        let recipient =
            AccountKey::try_from(Jid::parse_in("alice@localhost", &mut arena)?.resolve(&arena)?)?;
        let registration = fixture
            .handle
            .register(&recipient, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let outbound = fixture.outbound();
        for xml in [
            "<message to='alice@localhost/desk'/>",
            "<message from='alice@localhost/forged' to='alice@localhost/desk'/>",
            "<message from='echo.localhost.evil' to='alice@localhost/desk'/>",
            "<message from='echo.localhost'/>",
            "<message from='echo.localhost' to='localhost'/>",
            "<message from='echo.localhost' to='localhost/resource'/>",
            "<message from='echo.localhost' to='echo.localhost'/>",
            "<message from='echo.localhost' to='alice@example.org'/>",
            "<iq type='result' id='bare' from='echo.localhost' to='alice@localhost'/>",
        ] {
            assert!(
                outbound.route(parsed(xml).await?).await.is_err(),
                "accepted {xml}"
            );
        }
        assert!(registration.take_queued().is_empty());
        for from in ["echo.localhost", "room@echo.localhost/nick"] {
            let stanza = parsed(&format!(
                "<message type='chat' from='{from}' to='alice@localhost/desk'/>"
            ))
            .await?;
            outbound.route(stanza).await?;
            let delivery = registration.recv().await.ok_or("missing service message")?;
            assert_eq!(
                delivery
                    .stanza
                    .resolve()?
                    .from()?
                    .ok_or("missing sender")?
                    .as_str(),
                from
            );
        }
        drop(registration);
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

fn federating_service_hosts(directory: &std::path::Path) -> TestResult<Hosts> {
    use crate::config::{HostConfig, HostTlsConfig, HostTlsSource};
    use base64::Engine as _;
    let parameters = rcgen::CertificateParams::new(vec![
        "example.com".into(),
        "echo.example.com".into(),
        "covered.example.com".into(),
        "optout.test".into(),
    ])?;
    let (certificate, key) = crate::hosts::test_support::material(parameters)?;
    let certificate_chain_path = directory.join("certificate.pem");
    let private_key_path = directory.join("key.pem");
    for (label, bytes, path) in [
        ("CERTIFICATE", certificate.as_ref(), &certificate_chain_path),
        ("PRIVATE KEY", key.secret_der(), &private_key_path),
    ] {
        std::fs::write(
            path,
            format!(
                "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            ),
        )?;
    }
    let host = HostConfig {
        tls: Some(HostTlsConfig {
            source: HostTlsSource::Files {
                certificate_chain_path,
                private_key_path,
            },
            client_auth: None,
        }),
        ..Default::default()
    };
    let mut optout = host.clone();
    optout.federation = false;
    Ok(Hosts::new(
        &BTreeMap::from([("example.com".into(), host), ("optout.test".into(), optout)]),
        Some("example.com"),
    )?)
}

#[test]
fn registered_service_federation_requires_the_global_gate_and_certificate_coverage() -> TestResult {
    use crate::s2s::outbound::test_support::{AdmissionState, Fixture as RemoteFixture};
    let directory = tempfile::tempdir()?;
    let hosts = federating_service_hosts(directory.path())?;
    let remote = RemoteFixture::with_hosts_and_pair(
        AdmissionState::Link,
        NonZeroUsize::MIN,
        hosts.clone(),
        ("echo.example.com".into(), "remote.test".into()),
    )?;
    for enabled in [false, true] {
        let router = Router::new(hosts.clone(), LocalRouter::new(GlobalChunkAllocator))
            .with_services(
                ["echo.example.com", "uncovered.example.com"]
                    .into_iter()
                    .map(|domain| {
                        (
                            domain.into(),
                            ServiceRoute {
                                domain: Arc::from(domain),
                                handler: Arc::new(RejectingService) as _,
                            },
                        )
                    })
                    .collect(),
            );
        let router = if enabled {
            router.with_remote(remote.remote())
        } else {
            router
        };
        let handle = router.handle();
        assert_eq!(handle.federates_domain("example.com"), enabled);
        assert_eq!(handle.federates_domain("echo.example.com"), enabled);
        for domain in [
            "covered.example.com",
            "uncovered.example.com",
            "optout.test",
            "unknown.test",
        ] {
            assert!(!handle.federates_domain(domain), "{domain}");
        }
    }
    Ok(())
}

#[test]
fn service_remote_outbound_uses_real_admission_and_maps_each_failure() -> TestResult {
    use crate::s2s::outbound::{
        RemoteFailure,
        test_support::{AdmissionState, Fixture as RemoteFixture},
    };
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let directory = tempfile::tempdir()?;
        let hosts = federating_service_hosts(directory.path())?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        for initial in [AdmissionState::Link, AdmissionState::Backoff(RemoteFailure::NotFound), AdmissionState::Backoff(RemoteFailure::Timeout)] {
            let link = matches!(initial, AdmissionState::Link);
            let mut remote = RemoteFixture::with_hosts_and_pair(initial, NonZeroUsize::MIN, hosts.clone(), ("echo.example.com".into(), "remote.test".into()))?;
            let router = Router::new(hosts.clone(), LocalRouter::new(GlobalChunkAllocator)).with_remote(remote.remote()).with_services(BTreeMap::from([("echo.example.com".into(), ServiceRoute { domain: Arc::from("echo.example.com"), handler: Arc::new(RejectingService) })]));
            let handle = router.handle();
            let mut work = WorkGroup::new();
            let outbound = Outbound { router: &handle, storage: &storage, allocator: &GlobalChunkAllocator, work: &work.handle(), domain: "echo.example.com", component_reply: None };
            let xml = "<message type='chat' id='service-remote' from='room@echo.example.com/nick' to='alice@remote.test/desk'/>";
            assert_eq!(outbound.route(parsed(xml).await?).await.is_ok(), link);
            if link {
                assert!(outbound.route(parsed(xml).await?).await.is_err());
                let received = remote.receive()?.ok_or("service stanza not admitted")?;
                assert_eq!(received.resolve()?.from()?.ok_or("no sender")?.as_str(), "room@echo.example.com/nick");
                assert_eq!(received.resolve()?.id()?, Some("service-remote"));
            }
            let unsupported = Outbound { domain: "covered.example.com", component_reply: None, ..outbound };
            assert!(unsupported.route(parsed("<message from='covered.example.com' to='alice@remote.test'/>").await?).await.is_err());
            let mut registry = prometheus_client::registry::Registry::default();
            remote.metrics().register(registry.sub_registry_with_prefix("lonewolf"));
            let mut metrics = String::new();
            prometheus_client::encoding::text::encode(&mut metrics, &registry)?;
            assert!(metrics.lines().any(|line| line == "lonewolf_s2s_admission_rejections_total{reason=\"unsupported\"} 1"), "{metrics}");
            remote.remote().stop();
            assert!(outbound.route(parsed(xml).await?).await.is_err());
            work.drain().await;
            remote.finish(std::time::Instant::now() + Duration::from_secs(5)).await?;
            router.shutdown().await?;
        }
        Ok(())
    }))?
}
