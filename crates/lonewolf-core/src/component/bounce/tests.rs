// SPDX-License-Identifier: Apache-2.0

use std::alloc::Layout;
use std::cell::{Cell, RefCell};
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

use futures_util::poll;
use lonewolf_util::arena::{AllocationError, ArenaConfig, Chunk, GlobalChunkAllocator};
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{Stanza, StanzaNamespace};

use super::*;
use crate::component::registry::ComponentRegistry;
use crate::config::ComponentsConfig;
use crate::delivery::WorkGroup;
use crate::router::{Router, local::LocalRouter};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const DOMAIN: &str = "muc.localhost";
const ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";

fn run(test: impl Future<Output = TestResult>) -> TestResult {
    compio::runtime::Runtime::new()?
        .block_on(compio::time::timeout(Duration::from_secs(5), test))?
}

struct Fixture<A: ChunkAllocator> {
    context: Context<A>,
    metrics: Arc<ComponentMetrics>,
    _directory: tempfile::TempDir,
}

impl<A: ChunkAllocator + Clone> Fixture<A> {
    fn new(allocator: A) -> TestResult<Self> {
        let config: ComponentsConfig =
            toml::from_str("[domains.'muc.localhost']\nsecret='component-test-secret-0001'")?;
        let metrics = ComponentMetrics::new(1, 1);
        let registry = ComponentRegistry::new(
            &config,
            crate::component::credentials::load(&config)?,
            &Default::default(),
            Arc::clone(&metrics),
        );
        let hosts = crate::hosts::Hosts::new(&crate::Config::default().hosts, None)?;
        let router = Router::new(hosts, LocalRouter::new(allocator.clone()));
        let directory = tempfile::tempdir()?;
        let context = Context {
            router: router.handle(),
            storage: lonewolf_storage::RedbStorage::open(directory.path().join("state.redb"))?,
            allocator,
            work: WorkGroup::new().handle(),
            registry,
            connection_id: 1,
        };
        Ok(Self {
            context,
            metrics,
            _directory: directory,
        })
    }
}

async fn stanza<A: ChunkAllocator + Clone>(
    name: &str,
    kind: &str,
    id: &str,
    allocator: A,
) -> TestResult<RoutedStanza<A>> {
    let payload = match name {
        "message" => "<body>keep payload</body>",
        "iq" => "<query xmlns='urn:test:bounce'><item>keep</item></query>",
        _ => "<status>keep status</status>",
    };
    let error = if kind == "error" {
        "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
    } else {
        ""
    };
    let kind = if kind.is_empty() {
        String::new()
    } else {
        format!(" type='{kind}'")
    };
    let xml = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><{name}{kind} id='{id}' from='alice@localhost/desk' to='room@muc.localhost/member'>{payload}{error}</{name}>"
    );
    let mut parser = XmppParser::new(
        xml.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(65_536).ok_or("stanza limit")?,
            arena: ArenaConfig::default(),
        },
        allocator,
    );
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    match parser.next_event().await? {
        Some(StreamEvent::Stanza(stanza)) => Ok(RoutedStanza::from_parsed(stanza)),
        _ => Err("missing stanza".into()),
    }
}

async fn chat(id: &str) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    stanza("message", "chat", id, GlobalChunkAllocator).await
}

fn metrics(
    metrics: &Arc<ComponentMetrics>,
    bounced: u64,
    dropped: u64,
    shutdown: u64,
) -> TestResult {
    let mut registry = prometheus_client::registry::Registry::default();
    metrics.register(registry.sub_registry_with_prefix("lonewolf"));
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry)?;
    for (sample, expected) in [
        ("lonewolf_component_bounces_total", bounced),
        (
            "lonewolf_component_dropped_stanzas_total{reason=\"not_bounceable\"}",
            dropped,
        ),
        (
            "lonewolf_component_dropped_stanzas_total{reason=\"shutdown\"}",
            shutdown,
        ),
    ] {
        let actual = text
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{sample} ")))
            .unwrap_or("0")
            .parse::<u64>()?;
        assert_eq!(actual, expected, "{sample}");
    }
    if bounced > 0 {
        assert!(text.contains("# HELP lonewolf_component_bounces Error-reply dispatch attempts for component stanzas still queued at disconnect."));
    }
    Ok(())
}

#[test]
fn all_stanza_types_classify_once_and_preserve_bounce_content_in_fifo_order() -> TestResult {
    run(async {
        let fixture = Fixture::new(GlobalChunkAllocator)?;
        let mut inputs = Vec::new();
        for (name, kinds) in [
            (
                "message",
                &["normal", "chat", "groupchat", "headline", "error"][..],
            ),
            ("iq", &["get", "set", "result", "error"][..]),
            (
                "presence",
                &[
                    "available",
                    "unavailable",
                    "probe",
                    "subscribe",
                    "subscribed",
                    "unsubscribe",
                    "unsubscribed",
                    "error",
                ][..],
            ),
        ] {
            for kind in kinds {
                let kind = if *kind == "available" { "" } else { kind };
                let id = format!("{name}:{kind}");
                inputs.push(stanza(name, kind, &id, GlobalChunkAllocator).await?);
            }
        }
        let replies = RefCell::new(Vec::new());
        let result = undelivered_with(
            &fixture.context,
            DOMAIN,
            inputs,
            std::future::pending(),
            async |_, _, reply| {
                replies.borrow_mut().push(reply);
                Ok(())
            },
        )
        .await;
        assert_eq!((result.bounced, result.dropped), (6, 11));
        let replies = replies.into_inner();
        let expected = [
            "message:normal",
            "message:chat",
            "message:groupchat",
            "message:headline",
            "iq:get",
            "iq:set",
        ];
        assert_eq!(replies.len(), expected.len());
        for (reply, id) in replies.iter().zip(expected) {
            let view = reply.resolve()?;
            assert_eq!(view.id()?, Some(id));
            assert_eq!(
                view.from()?.ok_or("from")?.to_string(),
                "room@muc.localhost/member"
            );
            assert_eq!(view.to()?.ok_or("to")?.to_string(), "alice@localhost/desk");
            assert!(matches!(
                view.stanza_type(),
                StanzaType::Message(MessageType::Error) | StanzaType::Iq(IqType::Error)
            ));
            let mut xml = String::new();
            view.write_xml(&mut xml)?;
            assert!(xml.contains("<error type=\"wait\">"), "{xml}");
            assert!(
                xml.contains(&format!("<remote-server-timeout xmlns=\"{ERRORS}\"/>")),
                "{xml}"
            );
            assert!(xml.contains(NOT_CONNECTED_TEXT), "{xml}");
            assert!(
                xml.contains("keep payload") || xml.contains("<item>keep</item>"),
                "{xml}"
            );
        }
        metrics(&fixture.metrics, 6, 11, 0)
    })
}

#[test]
fn shutdown_before_the_walk_or_at_the_dispatch_race_never_enters_dispatch() -> TestResult {
    run(async {
        for ready_on in [1, 2] {
            let fixture = Fixture::new(GlobalChunkAllocator)?;
            let polls = Cell::new(0);
            let shutdown = std::future::poll_fn(|_| {
                polls.set(polls.get() + 1);
                if polls.get() >= ready_on {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            });
            let result = undelivered_with(
                &fixture.context,
                DOMAIN,
                vec![chat("current").await?, chat("tail").await?],
                shutdown,
                async |_, _, _| panic!("dispatch entered after shutdown"),
            )
            .await;
            assert_eq!((result.bounced, result.dropped), (0, 2));
            metrics(&fixture.metrics, 0, 0, 2)?;
        }
        Ok(())
    })
}

#[test]
fn returned_dispatch_failure_counts_one_attempt_and_continues_in_order() -> TestResult {
    run(async {
        let fixture = Fixture::new(GlobalChunkAllocator)?;
        let ids = RefCell::new(Vec::new());
        let result = undelivered_with(
            &fixture.context,
            DOMAIN,
            vec![chat("first").await?, chat("second").await?],
            std::future::pending(),
            async |_, _, stanza| {
                let id = stanza
                    .resolve()
                    .map_err(|_| IngressFailure)?
                    .id()
                    .map_err(|_| IngressFailure)?
                    .ok_or(IngressFailure)?
                    .to_owned();
                let failed = id == "first";
                ids.borrow_mut().push(id);
                if failed { Err(IngressFailure) } else { Ok(()) }
            },
        )
        .await;
        assert_eq!(&*ids.borrow(), &["first", "second"]);
        assert_eq!((result.bounced, result.dropped), (2, 0));
        metrics(&fixture.metrics, 2, 0, 0)
    })
}

struct Cancelled(Rc<Cell<bool>>);
impl Drop for Cancelled {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

#[test]
fn shutdown_cancels_an_entered_attempt_and_counts_only_the_unstarted_tail_as_dropped() -> TestResult
{
    run(async {
        let fixture = Fixture::new(GlobalChunkAllocator)?;
        let (stop, stopped) = futures_channel::oneshot::channel();
        let entered = Cell::new(0);
        let cancelled = Rc::new(Cell::new(false));
        let mut walk = Box::pin(undelivered_with(
            &fixture.context,
            DOMAIN,
            vec![
                chat("current").await?,
                chat("tail1").await?,
                chat("tail2").await?,
            ],
            async {
                let _ = stopped.await;
            },
            async |_, _, _| {
                entered.set(entered.get() + 1);
                let _cancel = Cancelled(Rc::clone(&cancelled));
                std::future::pending().await
            },
        ));
        assert!(poll!(walk.as_mut()).is_pending());
        assert_eq!(entered.get(), 1);
        metrics(&fixture.metrics, 0, 0, 0)?;
        stop.send(()).map_err(|_| "shutdown receiver")?;
        let result = walk.await;
        assert!(cancelled.get());
        assert_eq!(entered.get(), 1);
        assert_eq!((result.bounced, result.dropped), (1, 2));
        metrics(&fixture.metrics, 1, 0, 2)
    })
}

async fn mixed_cancellation(unwind: bool) -> TestResult {
    let fixture = Fixture::new(GlobalChunkAllocator)?;
    let cancelled = Rc::new(Cell::new(false));
    let entries = Cell::new(0);
    let walk = undelivered_with(
        &fixture.context,
        DOMAIN,
        vec![
            chat("first").await?,
            stanza("presence", "unavailable", "drop", GlobalChunkAllocator).await?,
            chat("pending").await?,
            chat("tail1").await?,
            chat("tail2").await?,
        ],
        std::future::pending(),
        async |_, _, stanza| {
            entries.set(entries.get() + 1);
            if stanza
                .resolve()
                .map_err(|_| IngressFailure)?
                .id()
                .map_err(|_| IngressFailure)?
                == Some("pending")
            {
                let _cancel = Cancelled(Rc::clone(&cancelled));
                if unwind {
                    panic!("controlled dispatch unwind");
                }
                std::future::pending::<()>().await;
            }
            Ok(())
        },
    );
    if unwind {
        assert!(
            std::panic::AssertUnwindSafe(walk)
                .catch_unwind()
                .await
                .is_err()
        );
    } else {
        let mut walk = Box::pin(walk);
        assert!(poll!(walk.as_mut()).is_pending());
        assert_eq!(entries.get(), 2);
        metrics(&fixture.metrics, 0, 0, 0)?;
        drop(walk);
    }
    assert!(cancelled.get());
    assert_eq!(entries.get(), 2);
    metrics(&fixture.metrics, 2, 1, 2)
}

#[test]
fn forced_drop_publishes_accumulated_attempts_and_drops_once() -> TestResult {
    run(mixed_cancellation(false))
}

#[test]
#[cfg(panic = "unwind")]
fn unwind_publishes_accumulated_attempts_and_drops_once() -> TestResult {
    run(mixed_cancellation(true))
}

#[derive(Clone, Default)]
struct FailingAllocator(Arc<AtomicBool>);

// Successful allocations and every deallocation use the same global allocator.
unsafe impl ChunkAllocator for FailingAllocator {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        if self.0.swap(false, Ordering::Relaxed) {
            Err(AllocationError::Exhausted)
        } else {
            GlobalChunkAllocator.allocate(layout)
        }
    }

    unsafe fn deallocate(&self, chunk: Chunk) {
        // The caller returns a live chunk allocated by the global allocator.
        unsafe { GlobalChunkAllocator.deallocate(chunk) };
    }
}

#[test]
fn allocation_failure_drops_only_that_item_and_continues_to_the_next_attempt() -> TestResult {
    run(async {
        let allocator = FailingAllocator::default();
        let fixture = Fixture::new(allocator.clone())?;
        let stranded = vec![
            stanza("message", "chat", "failed", allocator.clone()).await?,
            stanza("message", "chat", "valid", allocator.clone()).await?,
        ];
        allocator.0.store(true, Ordering::Relaxed);
        let ids = RefCell::new(Vec::new());
        let result = undelivered_with(
            &fixture.context,
            DOMAIN,
            stranded,
            std::future::pending(),
            async |_, _, stanza| {
                ids.borrow_mut().push(
                    stanza
                        .resolve()
                        .map_err(|_| IngressFailure)?
                        .id()
                        .map_err(|_| IngressFailure)?
                        .ok_or(IngressFailure)?
                        .to_owned(),
                );
                Ok(())
            },
        )
        .await;
        assert_eq!(&*ids.borrow(), &["valid"]);
        assert_eq!((result.bounced, result.dropped), (1, 1));
        metrics(&fixture.metrics, 1, 1, 0)
    })
}

#[test]
fn unresolvable_stanza_is_dropped_without_preventing_later_attempts() -> TestResult {
    run(async {
        let fixture = Fixture::new(GlobalChunkAllocator)?;
        let mut original = Arena::try_new(ArenaConfig::default())?;
        let source = Stanza::builder_in(
            StanzaType::Message(MessageType::Chat),
            StanzaNamespace::Client,
            &mut original,
        )
        .build()?;
        let invalid = RoutedStanza::from_parts(source, Arena::try_new(ArenaConfig::default())?);
        assert!(invalid.resolve().is_err());
        let entries = Cell::new(0);
        let result = undelivered_with(
            &fixture.context,
            DOMAIN,
            vec![invalid, chat("valid").await?],
            std::future::pending(),
            async |_, _, _| {
                entries.set(entries.get() + 1);
                Ok(())
            },
        )
        .await;
        assert_eq!(entries.get(), 1);
        assert_eq!((result.bounced, result.dropped), (1, 1));
        metrics(&fixture.metrics, 1, 1, 0)
    })
}
