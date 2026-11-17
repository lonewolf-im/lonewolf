// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use std::task::{Context as TaskContext, Waker};

use futures_util::io::AsyncWriteExt as _;
use futures_util::poll;
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{Element, MessageType, Stanza, StanzaType};

use super::*;
use crate::component::negotiate::ComponentByteObserver;
use crate::component::stream::WriteProgress;
use crate::config::{ComponentsConfig, limits::ComponentLimits};
use crate::xml_stream::traffic::TrafficObserver;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn run(test: impl Future<Output = TestResult>) -> TestResult {
    compio::runtime::Runtime::new()?
        .block_on(compio::time::timeout(Duration::from_secs(5), test))?
}

#[derive(Clone)]
struct TestClock {
    at: Rc<Cell<Instant>>,
    sleepers: Rc<RefCell<Vec<Waker>>>,
}
impl TestClock {
    fn new() -> Self {
        Self {
            at: Rc::new(Cell::new(Instant::now())),
            sleepers: Rc::default(),
        }
    }
    fn advance(&self, duration: Duration) {
        self.at.set(self.at.get() + duration);
        for waker in self.sleepers.borrow_mut().drain(..) {
            waker.wake();
        }
    }
}
impl Clock for TestClock {
    fn now(&self) -> Instant {
        self.at.get()
    }
    async fn sleep_until(&self, deadline: Instant) {
        poll_fn(|cx| {
            if self.now() >= deadline {
                Poll::Ready(())
            } else {
                let mut sleepers = self.sleepers.borrow_mut();
                if !sleepers.iter().any(|waker| waker.will_wake(cx.waker())) {
                    sleepers.push(cx.waker().clone());
                }
                Poll::Pending
            }
        })
        .await;
    }
}

#[derive(Clone)]
struct Output {
    bytes: Rc<RefCell<Vec<u8>>>,
    allowance: Rc<Cell<usize>>,
    waker: Rc<RefCell<Option<Waker>>>,
}
impl Output {
    fn new() -> Self {
        Self {
            bytes: Rc::default(),
            allowance: Rc::new(Cell::new(0)),
            waker: Rc::default(),
        }
    }
    fn release(&self, bytes: usize) {
        self.allowance.set(bytes);
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }
}
struct Writer {
    output: Output,
    progress: WriteProgress,
    clock: TestClock,
}
impl AsyncWrite for Writer {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = self.output.allowance.get().min(input.len());
        if n == 0 {
            *self.output.waker.borrow_mut() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        self.output
            .bytes
            .borrow_mut()
            .extend_from_slice(&input[..n]);
        self.output.allowance.set(self.output.allowance.get() - n);
        self.progress.record(self.clock.now());
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: std::pin::Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
fn writer(clock: &TestClock) -> (ComponentWriter<Writer>, Output, WriteProgress) {
    let output = Output::new();
    let progress = WriteProgress::new(clock.now());
    (
        ComponentWriter::new(
            Writer {
                output: output.clone(),
                progress: progress.clone(),
                clock: clock.clone(),
            },
            progress.clone(),
        ),
        output,
        progress,
    )
}

#[test]
fn no_progress_watchdog_rearms_without_restarting_the_output_future() -> TestResult {
    run(async {
        let clock = TestClock::new();
        let output = Output::new();
        let progress = WriteProgress::new(clock.now());
        let mut writer = Writer {
            output: output.clone(),
            progress: progress.clone(),
            clock: clock.clone(),
        };
        let aborted = Cell::new(false);
        let abort = || aborted.set(true);
        let mut writing = Box::pin(watch(
            async {
                writer
                    .write_all(b"abcde")
                    .await
                    .map_err(ComponentError::from)
            },
            &progress,
            Duration::from_millis(10),
            &clock,
            &abort,
        ));
        for _ in 0..4 {
            output.release(1);
            assert!(poll!(writing.as_mut()).is_pending());
            clock.advance(Duration::from_millis(9));
        }
        output.release(1);
        assert!(writing.await.is_ok());
        assert_eq!(&*output.bytes.borrow(), b"abcde");
        assert!(!aborted.get());
        Ok(())
    })
}

#[test]
fn incoming_reads_and_zero_byte_writes_do_not_postpone_a_stalled_write() -> TestResult {
    run(async {
        let clock = TestClock::new();
        let progress = WriteProgress::new(clock.now());
        let metrics = ComponentMetrics::new(1, 1);
        let observer = ComponentByteObserver::new(metrics, progress.clone());
        let aborted = Cell::new(false);
        let abort = || aborted.set(true);
        let mut operation = Box::pin(watch(
            std::future::pending::<Result<(), ComponentError>>(),
            &progress,
            Duration::from_secs(1),
            &clock,
            &abort,
        ));
        assert!(poll!(operation.as_mut()).is_pending());
        clock.advance(Duration::from_millis(999));
        let last_write = progress.last();
        observer.received(8192);
        observer.sent(0);
        assert_eq!(progress.last(), last_write);
        assert!(poll!(operation.as_mut()).is_pending());
        clock.advance(Duration::from_millis(1));
        assert!(matches!(operation.await, Err(StreamClose::StalledWrite)));
        assert!(aborted.get());
        Ok(())
    })
}

fn registry(metrics: &std::sync::Arc<ComponentMetrics>) -> TestResult<ComponentLinkFixture> {
    let config: ComponentsConfig = toml::from_str(
        "[domains.'muc.localhost']\nsecret='component-test-secret-0001'\nmax_connections=2",
    )?;
    let registry = super::super::registry::ComponentRegistry::new(
        &config,
        super::super::credentials::load(&config)?,
        &ComponentLimits::default(),
        metrics.clone(),
    );
    let first = registry
        .attach("muc.localhost")
        .map_err(|_| "first attachment")?;
    let second = registry
        .attach("muc.localhost")
        .map_err(|_| "second attachment")?;
    Ok(ComponentLinkFixture {
        registry,
        first,
        second,
    })
}
struct ComponentLinkFixture {
    registry: super::super::registry::ComponentRegistry<GlobalChunkAllocator>,
    first: ComponentLink<GlobalChunkAllocator>,
    second: ComponentLink<GlobalChunkAllocator>,
}
fn stanza(id: &str) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let from = Jid::parse_in("alice@localhost/desk", &mut arena)?;
    let to = Jid::parse_in("room@muc.localhost", &mut arena)?;
    let body = Element::builder_in("body", "jabber:client", &mut arena)?
        .text(&"x".repeat(8192))?
        .build()?;
    let stanza = Stanza::builder_in(
        StanzaType::Message(MessageType::Chat),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(from))?
    .to(Some(to))?
    .id(Some(id))?
    .child(body)?
    .build()?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}

#[test]
fn stop_finishes_the_started_stanza_without_dequeuing_the_next_two() -> TestResult {
    run(async {
        let metrics = ComponentMetrics::new(1, 1);
        let mut fixture = registry(&metrics)?;
        let mut expected = String::new();
        stanza("A")?
            .resolve()?
            .write_xml_as(StanzaNamespace::ComponentAccept, &mut expected)?;
        for id in ["A", "B", "C"] {
            fixture
                .registry
                .reply("muc.localhost", fixture.first.id(), stanza(id)?)
                .map_err(|_| "queue admission")?;
        }
        let clock = TestClock::new();
        let (mut writer, output, _) = writer(&clock);
        let stop = StopRequest::default();
        let aborted = Cell::new(false);
        let abort = || aborted.set(true);
        let mut sending = Box::pin(sending(
            &mut fixture.first,
            &mut writer,
            &stop,
            &metrics,
            Duration::from_secs(60),
            &clock,
            &abort,
        ));
        output.release(64);
        assert!(poll!(sending.as_mut()).is_pending());
        assert_eq!(output.bytes.borrow().len(), 64);
        stop.request();
        output.release(usize::MAX);
        assert!(sending.await.is_ok());
        writer.flush().await.map_err(|e| format!("{e:?}"))?;
        assert_eq!(&*output.bytes.borrow(), expected.as_bytes());
        assert!(!aborted.get());
        let detached = fixture.first.detach();
        assert_eq!(detached.moved, 2);
        assert!(detached.stranded.is_empty());
        for id in ["B", "C"] {
            let stanza = fixture.second.try_next().ok_or("missing moved stanza")?;
            assert_eq!(stanza.resolve()?.id()?, Some(id));
        }
        assert!(fixture.second.try_next().is_none());
        Ok(())
    })
}

struct Fixture {
    settings: Settings<GlobalChunkAllocator>,
    authenticated:
        Authenticated<GlobalChunkAllocator, tokio::io::BufReader<tokio::io::DuplexStream>, Writer>,
    peer: tokio::io::DuplexStream,
    output: Output,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn new(clock: &TestClock) -> TestResult<Self> {
        use tokio::io::AsyncWriteExt as _;
        let config = crate::Config {
            components: toml::from_str(
                "[domains.'muc.localhost']\nsecret='component-test-secret-0001'",
            )?,
            ..crate::Config::default()
        };
        let metrics = ComponentMetrics::new(1, 1);
        let registry = super::super::registry::ComponentRegistry::new(
            &config.components,
            super::super::credentials::load(&config.components)?,
            &config.limits.components,
            metrics.clone(),
        );
        let link = registry.attach("muc.localhost").map_err(|_| "attachment")?;
        let (input, mut peer) = tokio::io::duplex(65_536);
        peer.write_all(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:component:accept'>").await?;
        let mut reader = ComponentReader::new(
            tokio::io::BufReader::new(input),
            &config.limits.components,
            GlobalChunkAllocator,
            metrics.clone(),
        );
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::StreamStart { .. }))
        ));
        let (writer, output, _) = writer(clock);
        let directory = tempfile::tempdir()?;
        let hosts = crate::hosts::Hosts::new(&config.hosts, None)?;
        let router = crate::router::Router::new(
            hosts.clone(),
            crate::router::local::LocalRouter::new(GlobalChunkAllocator),
        );
        let services = ComponentServices {
            router: router.handle(),
            storage: lonewolf_storage::RedbStorage::open(directory.path().join("state.redb"))?,
            allocator: GlobalChunkAllocator,
        };
        let authenticated = Authenticated {
            domain: std::sync::Arc::from("muc.localhost"),
            connection_id: 99,
            reader,
            writer,
            link,
            stream_accounting: super::super::StreamAccounting::new(metrics.clone()),
            stream_gauge: metrics.stream_opened(),
        };
        Ok(Self {
            settings: Settings {
                hosts,
                tls_mode: crate::config::ComponentTlsMode::None,
                limits: config.limits.components,
                timeout: Duration::from_secs(30),
                registry,
                services,
                metrics,
            },
            authenticated,
            peer,
            output,
            _directory: directory,
        })
    }
}
fn assert_closed(metrics: &std::sync::Arc<ComponentMetrics>, expected: StreamClose) -> TestResult {
    let snapshot = metrics.shutdown_state();
    assert_eq!(snapshot.streams, 0);
    assert_eq!(snapshot.streams_closed_total, 1);
    assert_eq!(
        snapshot.streams_closed_shutdown,
        u64::from(matches!(expected, StreamClose::Shutdown))
    );
    let mut root = prometheus_client::registry::Registry::default();
    metrics.register(root.sub_registry_with_prefix("lonewolf"));
    let mut encoded = String::new();
    prometheus_client::encoding::text::encode(&mut encoded, &root)?;
    let expected_sample = format!(
        "lonewolf_component_streams_closed_total{{outcome=\"{}\"}} 1",
        expected.as_str()
    );
    assert!(encoded.lines().any(|line| line == expected_sample));
    Ok(())
}

#[derive(Clone, Copy)]
enum CloseCase {
    Release,
    Expire,
    ExpireReady,
    Shorten,
    Cancel,
}
async fn close_partial_write(case: CloseCase) -> TestResult {
    use tokio::io::AsyncWriteExt as _;
    let clock = TestClock::new();
    let mut fixture = Fixture::new(&clock).await?;
    fixture.settings.limits.stalled_write_timeout_secs =
        std::num::NonZeroU64::new(60).ok_or("timeout")?;
    let mut expected = String::new();
    stanza("A")?
        .resolve()?
        .write_xml_as(StanzaNamespace::ComponentAccept, &mut expected)?;
    fixture
        .settings
        .registry
        .reply(
            "muc.localhost",
            fixture.authenticated.link.id(),
            stanza("A")?,
        )
        .map_err(|_| "admission")?;
    let (stop, stopped) = futures_channel::oneshot::channel();
    let shutdown = async move {
        stopped
            .await
            .unwrap_or_else(|_| Instant::now() + Duration::from_secs(20))
    }
    .boxed_local()
    .shared();
    let aborted = Cell::new(false);
    let abort = || aborted.set(true);
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
    fixture
        .peer
        .write_all(b"<handshake/></stream:stream>")
        .await?;
    assert!(poll!(serving.as_mut()).is_pending());
    assert!(!aborted.get());
    match case {
        CloseCase::Release => fixture.output.release(usize::MAX),
        CloseCase::Expire => clock.advance(Duration::from_secs(6)),
        CloseCase::ExpireReady => {
            clock.advance(Duration::from_secs(6));
            fixture.output.release(usize::MAX);
        }
        CloseCase::Shorten => {
            clock.advance(Duration::from_secs(1));
            stop.send(clock.now() + Duration::from_secs(2))
                .map_err(|_| "shutdown receiver")?;
            assert!(poll!(serving.as_mut()).is_pending());
            assert!(!aborted.get());
            clock.advance(Duration::from_secs(2));
        }
        CloseCase::Cancel => {
            drop(serving);
            assert_eq!(fixture.output.bytes.borrow().len(), 64);
            assert_closed(
                &fixture.settings.metrics,
                StreamClose::UnsupportedStanzaType,
            )?;
            drop(
                fixture
                    .settings
                    .registry
                    .attach("muc.localhost")
                    .map_err(|_| "attachment was not released")?,
            );
            return Ok(());
        }
    }
    let outcome = serving.await;
    assert!(matches!(outcome, StreamClose::UnsupportedStanzaType));
    assert!(aborted.get());
    match case {
        CloseCase::Release => {
            expected.push_str(&crate::xml_stream::stream_error_xml(
                StreamErrorCondition::UnsupportedStanzaType,
            ));
            assert_eq!(&*fixture.output.bytes.borrow(), expected.as_bytes());
        }
        CloseCase::Expire | CloseCase::ExpireReady | CloseCase::Shorten | CloseCase::Cancel => {
            assert_eq!(fixture.output.bytes.borrow().len(), 64)
        }
    }
    assert_closed(
        &fixture.settings.metrics,
        StreamClose::UnsupportedStanzaType,
    )?;
    drop(
        fixture
            .settings
            .registry
            .attach("muc.localhost")
            .map_err(|_| "attachment was not released")?,
    );
    Ok(())
}

#[test]
fn terminal_close_finishes_the_partial_stanza_before_error_and_footer() -> TestResult {
    run(close_partial_write(CloseCase::Release))
}
#[test]
fn absolute_close_budget_aborts_partial_output_without_trailing_xml() -> TestResult {
    run(close_partial_write(CloseCase::Expire))
}
#[test]
fn output_readiness_at_the_close_deadline_does_not_write_more_stanza_bytes() -> TestResult {
    run(close_partial_write(CloseCase::ExpireReady))
}

#[test]
fn later_shutdown_shortens_the_existing_close_deadline_without_restarting_it() -> TestResult {
    run(close_partial_write(CloseCase::Shorten))
}

#[test]
fn cancellation_during_terminal_output_preserves_the_selected_close_outcome_once() -> TestResult {
    run(close_partial_write(CloseCase::Cancel))
}

#[test]
fn dispatch_failure_sends_internal_server_error_and_records_one_close() -> TestResult {
    run(async {
        use tokio::io::AsyncWriteExt as _;
        let clock = TestClock::new();
        let mut fixture = Fixture::new(&clock).await?;
        fixture
            .peer
            .write_all(b"<message from='muc.localhost' to='alice@localhost'/></stream:stream>")
            .await?;
        fixture.peer.shutdown().await?;
        fixture.output.release(usize::MAX);
        let shutdown = std::future::pending::<Instant>().boxed_local().shared();
        let aborted = Cell::new(false);
        let abort = || aborted.set(true);
        let outcome = serve_with(
            fixture.authenticated,
            &fixture.settings,
            &fixture.settings.services,
            shutdown,
            async |_: &Context<GlobalChunkAllocator>,
                   _: &str,
                   _: RoutedStanza<GlobalChunkAllocator>| Err(IngressFailure),
            &clock,
            &abort,
        )
        .await;
        assert!(matches!(outcome, StreamClose::InternalError));
        let expected =
            crate::xml_stream::stream_error_xml(StreamErrorCondition::InternalServerError);
        assert_eq!(&*fixture.output.bytes.borrow(), expected.as_bytes());
        assert!(aborted.get());
        assert_closed(&fixture.settings.metrics, StreamClose::InternalError)?;
        Ok(())
    })
}

#[test]
fn pending_dispatch_prevents_processing_the_next_stanza() -> TestResult {
    run(async {
        use tokio::io::AsyncWriteExt as _;
        let clock = TestClock::new();
        let mut fixture = Fixture::new(&clock).await?;
        fixture.peer.write_all(b"<message id='first' from='muc.localhost' to='alice@localhost'/><message id='second' from='muc.localhost' to='alice@localhost'/></stream:stream>").await?;
        fixture.peer.shutdown().await?;
        fixture.output.release(usize::MAX);
        let (release, released) = futures_channel::oneshot::channel();
        let released = RefCell::new(Some(released));
        let dispatched = RefCell::new(Vec::new());
        let dispatch = async |_: &Context<GlobalChunkAllocator>,
                              _: &str,
                              stanza: RoutedStanza<GlobalChunkAllocator>| {
            let id = stanza
                .resolve()
                .map_err(|_| IngressFailure)?
                .id()
                .map_err(|_| IngressFailure)?
                .ok_or(IngressFailure)?
                .to_owned();
            dispatched.borrow_mut().push(id);
            let wait = released.borrow_mut().take();
            if let Some(wait) = wait {
                wait.await.map_err(|_| IngressFailure)?;
            }
            Ok(())
        };
        let shutdown = std::future::pending::<Instant>().boxed_local().shared();
        let aborted = Cell::new(false);
        let abort = || aborted.set(true);
        let mut serving = Box::pin(serve_with(
            fixture.authenticated,
            &fixture.settings,
            &fixture.settings.services,
            shutdown,
            dispatch,
            &clock,
            &abort,
        ));
        assert!(poll!(serving.as_mut()).is_pending());
        assert_eq!(&*dispatched.borrow(), &["first"]);
        let mut root = prometheus_client::registry::Registry::default();
        fixture
            .settings
            .metrics
            .register(root.sub_registry_with_prefix("lonewolf"));
        let mut encoded = String::new();
        prometheus_client::encoding::text::encode(&mut encoded, &root)?;
        assert!(encoded.lines().any(|line| line == "lonewolf_component_stanzas_received_total{kind=\"message\"} 1"));
        release.send(()).map_err(|_| "dispatch receiver dropped")?;
        assert!(matches!(serving.await, StreamClose::StreamEnd));
        assert_eq!(&*dispatched.borrow(), &["first", "second"]);
        assert_eq!(&*fixture.output.bytes.borrow(), b"</stream:stream>");
        assert!(aborted.get());
        assert_closed(&fixture.settings.metrics, StreamClose::StreamEnd)?;
        Ok(())
    })
}

struct Foreground(Rc<Cell<bool>>);
impl Drop for Foreground {
    fn drop(&mut self) {
        self.0.set(true);
    }
}
async fn abort_with_work(outer_deadline: bool) -> TestResult {
    use tokio::io::AsyncWriteExt as _;
    let clock = TestClock::new();
    let mut fixture = Fixture::new(&clock).await?;
    fixture.settings.limits.stalled_write_timeout_secs =
        std::num::NonZeroU64::new(60).ok_or("timeout")?;
    fixture
        .settings
        .registry
        .reply(
            "muc.localhost",
            fixture.authenticated.link.id(),
            stanza("A")?,
        )
        .map_err(|_| "admission")?;
    fixture
        .peer
        .write_all(b"<message from='muc.localhost' to='alice@localhost'/>")
        .await?;
    let (release, work) = futures_channel::oneshot::channel();
    let work = RefCell::new(Some(work));
    let (completed, completion) = futures_channel::oneshot::channel();
    let completed = RefCell::new(Some(completed));
    let entered = Cell::new(false);
    let cancelled = Rc::new(Cell::new(false));
    let dispatch = async |context: &Context<GlobalChunkAllocator>,
                          _: &str,
                          _: RoutedStanza<GlobalChunkAllocator>| {
        entered.set(true);
        let guard = context.work.start();
        let work = work.borrow_mut().take().ok_or(IngressFailure)?;
        let completed = completed.borrow_mut().take().ok_or(IngressFailure)?;
        compio::runtime::spawn(async move {
            guard
                .run(async {
                    let _ = work.await;
                })
                .await;
            let _ = completed.send(());
        })
        .detach();
        let _foreground = Foreground(cancelled.clone());
        std::future::pending::<Result<(), IngressFailure>>().await
    };
    let (stop, stopped) = futures_channel::oneshot::channel();
    let shutdown = async move {
        stopped
            .await
            .unwrap_or_else(|_| Instant::now() + Duration::from_secs(20))
    }
    .boxed_local()
    .shared();
    let aborted = Cell::new(false);
    let abort = || {
        assert!(cancelled.get());
        aborted.set(true);
    };
    let global = crate::admission::global_limit::GlobalLimit::new(1);
    let permit = global.reserve(Instant::now()).map_err(|_| "permit")?;
    let mut serving = Box::pin(async {
        let _permit = permit;
        serve_with(
            fixture.authenticated,
            &fixture.settings,
            &fixture.settings.services,
            shutdown,
            dispatch,
            &clock,
            &abort,
        )
        .await
    });
    fixture.output.release(64);
    assert!(poll!(serving.as_mut()).is_pending());
    assert!(entered.get());
    assert_eq!(fixture.output.bytes.borrow().len(), 64);
    stop.send(clock.now() + Duration::from_secs(20))
        .map_err(|_| "shutdown receiver")?;
    assert!(poll!(serving.as_mut()).is_pending());
    assert!(cancelled.get());
    clock.advance(Duration::from_secs(6));
    assert!(poll!(serving.as_mut()).is_pending());
    assert!(aborted.get());
    assert_eq!(fixture.output.bytes.borrow().len(), 64);
    assert_eq!(global.active(), 1);
    assert_eq!(fixture.settings.metrics.shutdown_state().streams, 1);
    assert_eq!(
        fixture
            .settings
            .metrics
            .shutdown_state()
            .streams_closed_total,
        0
    );
    assert!(matches!(
        fixture.settings.registry.attach("muc.localhost"),
        Err(super::super::registry::AttachError::Conflict)
    ));
    if outer_deadline {
        let active = futures_util::stream::FuturesUnordered::new();
        active.push(crate::connection::socket::ConnectionTask {
            _socket: (),
            future: Box::pin(async {
                let _ = serving.await;
            }),
        });
        let error = crate::connection::drain_connections(
            active,
            Instant::now(),
            crate::connection::ListenerKind::Component,
            |_| panic!("work completed before the deadline"),
        )
        .await
        .err()
        .ok_or("missing drain failure")?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            error.to_string(),
            "component connections exceeded shutdown deadline"
        );
    } else {
        release.send(()).map_err(|_| "background work receiver")?;
        assert!(matches!(serving.await, StreamClose::Shutdown));
        completion.await?;
        assert_eq!(global.active(), 0);
        assert_closed(&fixture.settings.metrics, StreamClose::Shutdown)?;
        drop(
            fixture
                .settings
                .registry
                .attach("muc.localhost")
                .map_err(|_| "attachment was not released")?,
        );
        return Ok(());
    }
    assert_eq!(global.active(), 0);
    assert_closed(&fixture.settings.metrics, StreamClose::Shutdown)?;
    drop(
        fixture
            .settings
            .registry
            .attach("muc.localhost")
            .map_err(|_| "attachment was not released")?,
    );
    release.send(()).map_err(|_| "background work receiver")?;
    completion.await?;
    Ok(())
}
#[test]
fn transport_abort_precedes_work_drain_while_permit_attachment_and_gauges_stay_owned() -> TestResult
{
    run(abort_with_work(false))
}
#[test]
fn outer_listener_deadline_preserves_drain_failure_and_one_close_sample() -> TestResult {
    run(abort_with_work(true))
}

#[test]
fn write_readiness_after_the_progress_deadline_does_not_revive_the_operation() -> TestResult {
    run(async {
        let clock = TestClock::new();
        let output = Output::new();
        let progress = WriteProgress::new(clock.now());
        let mut writer = Writer {
            output: output.clone(),
            progress: progress.clone(),
            clock: clock.clone(),
        };
        let aborted = Cell::new(false);
        let abort = || aborted.set(true);
        let mut operation = Box::pin(watch(
            async { writer.write_all(b"ab").await.map_err(ComponentError::from) },
            &progress,
            Duration::from_secs(1),
            &clock,
            &abort,
        ));
        output.release(1);
        assert!(poll!(operation.as_mut()).is_pending());
        clock.advance(Duration::from_secs(1));
        output.release(1);
        assert!(matches!(operation.await, Err(StreamClose::StalledWrite)));
        assert_eq!(&*output.bytes.borrow(), b"a");
        assert!(aborted.get());
        Ok(())
    })
}

#[test]
fn invalid_rescope_drops_only_that_stanza_before_output_and_continues_sending() -> TestResult {
    run(async {
        let metrics = ComponentMetrics::new(1, 1);
        let mut fixture = registry(&metrics)?;
        let mut arena = Arena::try_new(ArenaConfig::default())?;
        let to = Jid::parse_in("room@muc.localhost", &mut arena)?;
        let invalid = Stanza::builder_in(
            StanzaType::Message(MessageType::Chat),
            StanzaNamespace::Client,
            &mut arena,
        )
        .to(Some(to))?
        .id(Some("invalid"))?
        .build()?;
        let invalid = RoutedStanza::from_parts(invalid, arena);
        assert!(
            invalid
                .resolve()?
                .validate_rescope(StanzaNamespace::ComponentAccept)
                .is_err()
        );
        fixture
            .registry
            .reply("muc.localhost", fixture.first.id(), invalid)
            .map_err(|_| "invalid stanza admission")?;
        let mut expected = String::new();
        stanza("valid")?
            .resolve()?
            .write_xml_as(StanzaNamespace::ComponentAccept, &mut expected)?;
        fixture
            .registry
            .reply("muc.localhost", fixture.first.id(), stanza("valid")?)
            .map_err(|_| "valid stanza admission")?;
        let clock = TestClock::new();
        let (mut writer, output, _) = writer(&clock);
        output.release(usize::MAX);
        let stop = StopRequest::default();
        let aborted = Cell::new(false);
        let abort = || aborted.set(true);
        let mut sender = Box::pin(sending(
            &mut fixture.first,
            &mut writer,
            &stop,
            &metrics,
            Duration::from_secs(1),
            &clock,
            &abort,
        ));
        poll_fn(|cx| {
            assert!(sender.as_mut().poll(cx).is_pending());
            if output.bytes.borrow().len() == expected.len() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        stop.request();
        assert!(sender.await.is_ok());
        assert_eq!(&*output.bytes.borrow(), expected.as_bytes());
        assert!(!aborted.get());
        let mut root = prometheus_client::registry::Registry::default();
        metrics.register(root.sub_registry_with_prefix("lonewolf"));
        let mut encoded = String::new();
        prometheus_client::encoding::text::encode(&mut encoded, &root)?;
        assert!(
            encoded.lines().any(
                |line| line == "lonewolf_component_dropped_stanzas_total{reason=\"invalid\"} 1"
            )
        );
        assert!(
            encoded
                .lines()
                .any(|line| line == "lonewolf_component_stanzas_sent_total{kind=\"message\"} 1")
        );
        Ok(())
    })
}
