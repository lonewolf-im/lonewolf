// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lonewolf_extension::ExtensionFuture;
use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::service::{ServiceContext, ServiceHandler};
use lonewolf_storage::RedbStorage;
use lonewolf_xmpp::parser::{ParserConfig, XmppParser};
use parking_lot::Mutex as PlMutex;
use tokio::io::AsyncWriteExt as _;

use super::*;
use crate::component::registry::{ComponentRegistry, EnqueueError};
use crate::router::{Router, ServiceRoute};

mod semantic_xml;

const DOMAIN: &str = "muc.localhost";
const FROM: &str = "sender@pubsub.localhost/source";
const TO: &str = "room@muc.localhost/member";
const ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";
const TEXT: &str = "The service at this domain is not connected. Try again later.";

#[derive(Default)]
struct Capture(PlMutex<Vec<RoutedStanza<GlobalChunkAllocator>>>);
impl ServiceHandler<GlobalChunkAllocator, RedbStorage> for Capture {
    fn route<'a>(
        &'a self,
        stanza: RoutedStanza<GlobalChunkAllocator>,
        _: ServiceContext<'a, GlobalChunkAllocator, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            self.0.lock().push(stanza);
            Ok(())
        })
    }
}

async fn parsed(xml: &str) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let stream = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>{xml}"
    );
    let mut parser = XmppParser::new(
        stream.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(65_536).ok_or("stanza limit")?,
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
fn xml(
    stanza: &RoutedStanza<GlobalChunkAllocator>,
    namespace: StanzaNamespace,
) -> TestResult<String> {
    let mut output = String::new();
    stanza.resolve()?.write_xml_as(namespace, &mut output)?;
    Ok(output)
}
fn input(kind: &str, id: &str) -> String {
    let (name, attributes, payload) = match kind {
        "iq" => (
            "iq",
            "type='get'",
            "<query xmlns='urn:test:loss'><item>keep</item></query>",
        ),
        "presence" => ("presence", "", "<status>directed</status>"),
        "error" => (
            "message",
            "type='error'",
            "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>",
        ),
        _ => ("message", "type='chat'", "<body>keep payload</body>"),
    };
    format!("<{name} {attributes} id='{id}' from='{FROM}' to='{TO}'>{payload}</{name}>")
}
async fn expected_bounce(kind: &str, id: &str) -> TestResult<semantic_xml::Stanza> {
    let (name, payload) = if kind == "iq" {
        (
            "iq",
            "<query xmlns='urn:test:loss'><item>keep</item></query>",
        )
    } else {
        ("message", "<body>keep payload</body>")
    };
    semantic_xml::stanza(&parsed(&format!("<{name} type='error' id='{id}' from='{TO}' to='{FROM}'>{payload}<error type='wait'><remote-server-timeout xmlns='{ERRORS}'/><text xmlns='{ERRORS}' xml:lang='en'>{TEXT}</text></error></{name}>")).await?)
}
async fn fixture(clock: &TestClock) -> TestResult<(Fixture, Arc<Capture>)> {
    let mut fixture = Fixture::new(clock).await?;
    let config: ComponentsConfig = toml::from_str(
        "[domains.'muc.localhost']\nsecret='component-test-secret-0001'\nmax_connections=2",
    )?;
    fixture.settings.limits.max_queued_stanzas = NonZeroUsize::new(4).ok_or("capacity")?;
    fixture.settings.registry = ComponentRegistry::new(
        &config,
        crate::component::credentials::load(&config)?,
        &fixture.settings.limits,
        Arc::clone(&fixture.settings.metrics),
    );
    fixture.authenticated.link = fixture
        .settings
        .registry
        .attach(DOMAIN)
        .map_err(|_| "attachment")?;
    let captured = Arc::new(Capture::default());
    let router = Router::new(
        fixture.settings.hosts.clone(),
        crate::router::local::LocalRouter::new(GlobalChunkAllocator),
    )
    .with_services(BTreeMap::from([(
        "pubsub.localhost".into(),
        ServiceRoute {
            domain: Arc::from("pubsub.localhost"),
            handler: captured.clone(),
        },
    )]));
    fixture.settings.services.router = router.handle();
    Ok((fixture, captured))
}
pub(super) fn metrics(
    metrics: &Arc<ComponentMetrics>,
    moved: u64,
    bounced: u64,
    dropped: u64,
    shutdown: u64,
    queued: u64,
) -> TestResult {
    let mut registry = prometheus_client::registry::Registry::default();
    metrics.register(registry.sub_registry_with_prefix("lonewolf"));
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry)?;
    for (sample, expected) in [
        ("lonewolf_component_moved_stanzas_total", moved),
        ("lonewolf_component_bounces_total", bounced),
        (
            "lonewolf_component_dropped_stanzas_total{reason=\"not_bounceable\"}",
            dropped,
        ),
        (
            "lonewolf_component_dropped_stanzas_total{reason=\"shutdown\"}",
            shutdown,
        ),
        ("lonewolf_component_queued_stanzas", queued),
    ] {
        let actual = text
            .lines()
            .find_map(|line| {
                line.strip_prefix(sample)
                    .and_then(|value| value.strip_prefix(' '))
            })
            .unwrap_or("0")
            .parse::<u64>()?;
        assert_eq!(actual, expected, "{sample}");
    }
    Ok(())
}
async fn admit(
    registry: &ComponentRegistry<GlobalChunkAllocator>,
    id: u64,
    kind: &str,
    stanza_id: &str,
) -> TestResult {
    registry
        .reply(DOMAIN, id, parsed(&input(kind, stanza_id)).await?)
        .map_err(|_| "admission")?;
    Ok(())
}

async fn mixed_loss(reset: bool) -> TestResult {
    let clock = TestClock::new();
    let (mut fixture, capture) = fixture(&clock).await?;
    let id = fixture.authenticated.link.id();
    let first = stanza("started")?;
    let mut expected_output = xml(&first, StanzaNamespace::ComponentAccept)?;
    fixture
        .settings
        .registry
        .reply(DOMAIN, id, first)
        .map_err(|_| "first admission")?;
    let aborted = Cell::new(false);
    let abort = || aborted.set(true);
    let mut serving = Box::pin(serve_with(
        fixture.authenticated,
        &fixture.settings,
        &fixture.settings.services,
        std::future::pending::<Instant>().boxed_local().shared(),
        ingress::dispatch,
        &clock,
        &abort,
    ));
    fixture.output.release(64);
    assert!(poll!(serving.as_mut()).is_pending());
    assert_eq!(fixture.output.bytes.borrow().len(), 64);
    for (kind, tail_id) in [
        ("iq", "iq"),
        ("chat", "chat"),
        ("presence", "presence"),
        ("error", "error"),
    ] {
        admit(&fixture.settings.registry, id, kind, tail_id).await?;
    }
    if !reset {
        fixture.peer.write_all(b"</stream:stream>").await?;
    }
    fixture.peer.shutdown().await?;
    if !reset {
        assert!(poll!(serving.as_mut()).is_pending());
        assert_eq!(fixture.output.bytes.borrow().len(), 64);
        fixture.output.release(usize::MAX);
    }
    let outcome = serving.await;
    assert!(matches!(
        (reset, outcome),
        (true, StreamClose::TransportError) | (false, StreamClose::StreamEnd)
    ));
    if reset {
        assert_eq!(fixture.output.bytes.borrow().len(), 64);
    } else {
        expected_output.push_str("</stream:stream>");
        assert_eq!(&*fixture.output.bytes.borrow(), expected_output.as_bytes());
    }
    let actual = capture
        .0
        .lock()
        .iter()
        .map(semantic_xml::stanza)
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(
        actual,
        vec![
            expected_bounce("iq", "iq").await?,
            expected_bounce("chat", "chat").await?
        ]
    );
    metrics(&fixture.settings.metrics, 0, 2, 2, 0, 0)?;
    assert!(matches!(
        fixture.settings.registry.enqueue(DOMAIN, stanza("new")?),
        Err(EnqueueError::NotConnected)
    ));
    assert!(aborted.get());
    Ok(())
}

#[test]
fn graceful_fixed_tail_bounces_only_iq_and_chat_after_finishing_the_active_stanza() -> TestResult {
    run(mixed_loss(false))
}
#[test]
fn transport_termination_bounces_fixed_tail_without_replaying_partial_output() -> TestResult {
    run(mixed_loss(true))
}

async fn failover(prefill: usize) -> TestResult {
    let clock = TestClock::new();
    let (mut fixture, capture) = fixture(&clock).await?;
    let first_id = fixture.authenticated.link.id();
    let mut survivor = fixture
        .settings
        .registry
        .attach(DOMAIN)
        .map_err(|_| "survivor")?;
    let mut expected_survivor = Vec::new();
    for n in 0..prefill {
        let id = format!("prefill{n}");
        let stanza = parsed(&input("chat", &id)).await?;
        expected_survivor.push(xml(&stanza, StanzaNamespace::Client)?);
        fixture
            .settings
            .registry
            .reply(DOMAIN, survivor.id(), stanza)
            .map_err(|_| "prefill admission")?;
    }
    let first = stanza("started")?;
    let mut expected_output = xml(&first, StanzaNamespace::ComponentAccept)?;
    fixture
        .settings
        .registry
        .reply(DOMAIN, first_id, first)
        .map_err(|_| "first admission")?;
    let abort = || {};
    let mut serving = Box::pin(serve_with(
        fixture.authenticated,
        &fixture.settings,
        &fixture.settings.services,
        std::future::pending::<Instant>().boxed_local().shared(),
        ingress::dispatch,
        &clock,
        &abort,
    ));
    fixture.output.release(64);
    assert!(poll!(serving.as_mut()).is_pending());
    assert_eq!(fixture.output.bytes.borrow().len(), 64);
    let tail = [("chat", "tail0"), ("chat", "tail1"), ("iq", "tail2")];
    for (kind, id) in tail {
        admit(&fixture.settings.registry, first_id, kind, id).await?;
    }
    fixture.peer.write_all(b"</stream:stream>").await?;
    fixture.peer.shutdown().await?;
    assert!(poll!(serving.as_mut()).is_pending());
    assert_eq!(fixture.output.bytes.borrow().len(), 64);
    fixture.output.release(usize::MAX);
    assert!(matches!(serving.await, StreamClose::StreamEnd));
    expected_output.push_str("</stream:stream>");
    assert_eq!(&*fixture.output.bytes.borrow(), expected_output.as_bytes());
    let moved = (4 - prefill).min(tail.len());
    for (kind, id) in &tail[..moved] {
        expected_survivor.push(xml(
            &parsed(&input(kind, id)).await?,
            StanzaNamespace::Client,
        )?);
    }
    if prefill == 0 {
        let new = parsed(&input("chat", "new")).await?;
        expected_survivor.push(xml(&new, StanzaNamespace::Client)?);
        fixture
            .settings
            .registry
            .enqueue(DOMAIN, new)
            .map_err(|_| "new admission")?;
    }
    let mut actual = Vec::new();
    while let Some(stanza) = survivor.try_next() {
        actual.push(xml(&stanza, StanzaNamespace::Client)?);
    }
    assert_eq!(actual, expected_survivor);
    let mut expected_replies = Vec::new();
    for (kind, id) in &tail[moved..] {
        expected_replies.push(expected_bounce(kind, id).await?);
    }
    let actual_replies = capture
        .0
        .lock()
        .iter()
        .map(semantic_xml::stanza)
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(actual_replies, expected_replies);
    metrics(
        &fixture.settings.metrics,
        moved as u64,
        (tail.len() - moved) as u64,
        0,
        0,
        0,
    )?;
    if prefill != 0 {
        fixture
            .settings
            .registry
            .enqueue(DOMAIN, parsed(&input("chat", "new")).await?)
            .map_err(|_| "new admission")?;
        assert_eq!(
            xml(
                &survivor.try_next().ok_or("new stanza missing")?,
                StanzaNamespace::Client
            )?,
            xml(
                &parsed(&input("chat", "new")).await?,
                StanzaNamespace::Client
            )?
        );
    }
    assert!(survivor.try_next().is_none());
    Ok(())
}
#[test]
fn graceful_failover_moves_the_known_tail_once_in_fifo_order() -> TestResult {
    run(failover(0))
}
#[test]
fn full_failover_target_bounces_the_entire_known_tail() -> TestResult {
    run(failover(4))
}
#[test]
fn one_free_target_slot_moves_only_the_first_tail_stanza_and_bounces_the_rest() -> TestResult {
    run(failover(3))
}

#[test]
fn shutdown_discards_the_exact_tail_once_without_moving_or_bouncing() -> TestResult {
    run(async {
        let clock = TestClock::new();
        let (mut fixture, capture) = fixture(&clock).await?;
        let id = fixture.authenticated.link.id();
        let mut survivor = fixture
            .settings
            .registry
            .attach(DOMAIN)
            .map_err(|_| "survivor")?;
        let first = stanza("started")?;
        let mut expected_output = xml(&first, StanzaNamespace::ComponentAccept)?;
        fixture
            .settings
            .registry
            .reply(DOMAIN, id, first)
            .map_err(|_| "first admission")?;
        let (stop, stopped) = futures_channel::oneshot::channel();
        let shutdown = async move { stopped.await.unwrap_or_else(|_| Instant::now()) }
            .boxed_local()
            .shared();
        let abort = || {};
        let mut serving = Box::pin(serve_with(
            fixture.authenticated,
            &fixture.settings,
            &fixture.settings.services,
            shutdown,
            ingress::dispatch,
            &clock,
            &abort,
        ));
        fixture.output.release(64);
        assert!(poll!(serving.as_mut()).is_pending());
        assert_eq!(fixture.output.bytes.borrow().len(), 64);
        for (kind, tail_id) in [
            ("iq", "iq"),
            ("chat", "chat"),
            ("presence", "presence"),
            ("error", "error"),
        ] {
            admit(&fixture.settings.registry, id, kind, tail_id).await?;
        }
        stop.send(clock.now() + Duration::from_secs(20))
            .map_err(|_| "shutdown receiver")?;
        fixture.peer.write_all(b"</stream:stream>").await?;
        fixture.peer.shutdown().await?;
        assert!(poll!(serving.as_mut()).is_pending());
        fixture.output.release(usize::MAX);
        assert!(matches!(serving.await, StreamClose::Shutdown));
        expected_output.push_str(&crate::xml_stream::stream_error_xml(
            StreamErrorCondition::SystemShutdown,
        ));
        assert_eq!(&*fixture.output.bytes.borrow(), expected_output.as_bytes());
        assert!(capture.0.lock().is_empty());
        assert!(survivor.try_next().is_none());
        metrics(&fixture.settings.metrics, 0, 0, 0, 4, 0)?;
        assert_closed(&fixture.settings.metrics, StreamClose::Shutdown)?;
        Ok(())
    })
}
