// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use compio::runtime::Runtime;
use lonewolf_extension::ExtensionFuture;
use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::service::ServiceHandler;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};

use super::*;
use crate::config::Config;
use crate::delivery::WorkGroup;
use crate::hosts::Hosts;
use crate::router::Router;
use crate::router::local::LocalRouter;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct RejectingService;

impl ServiceHandler<GlobalChunkAllocator, RedbStorage> for RejectingService {
    fn route<'a>(
        &'a self,
        _stanza: RoutedStanza<GlobalChunkAllocator>,
        _context: ServiceContext<'a, GlobalChunkAllocator, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async { Err(StanzaErrorCondition::BadRequest.into()) })
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
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, None)?;
        let route = ServiceRoute {
            domain: Arc::from("echo.localhost"),
            handler: Arc::new(RejectingService),
        };
        let router = Router::new(hosts, LocalRouter::new(GlobalChunkAllocator))
            .with_services(BTreeMap::from([("echo.localhost".into(), route)]));
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
                ServiceOutcome::Rejected { condition, .. } => {
                    assert!(rejected, "unexpected error reply: {xml}");
                    assert_eq!(condition, StanzaErrorCondition::BadRequest);
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
