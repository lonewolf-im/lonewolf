// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::error::Error;
use std::io;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

use compio::runtime::Runtime;
use futures_channel::oneshot;
use futures_util::io::AsyncWrite;
use futures_util::{FutureExt, poll};
use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::GlobalChunkAllocator;
use prometheus_client::registry::Registry;

use super::*;
use crate::config::Config;
use crate::hosts::{Hosts, peer_identity::PeerTrust};
use crate::router::{Router, local::LocalRouter};
use crate::s2s::ingress::IngressServices;
use crate::s2s::stream::S2sReaderLimits;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const HEADER: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0'>";

struct Fixture {
    settings: Settings<GlobalChunkAllocator>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, None)?;
        let router = Router::new(hosts.clone(), LocalRouter::new(GlobalChunkAllocator));
        let directory = tempfile::tempdir()?;
        Ok(Self {
            settings: Settings {
                trust: PeerTrust::load(&config.s2s.tls, hosts.crypto_provider())?,
                hosts,
                timeout: Duration::from_secs(5),
                reader_limits: S2sReaderLimits {
                    max_stanza_bytes: config.limits.s2s.max_stanza_bytes,
                    stanzas: config.limits.s2s.incoming_stanzas_per_connection,
                    xml: config.limits.s2s.incoming_xml_per_connection,
                },
                services: IngressServices {
                    router: router.handle(),
                    storage: RedbStorage::open(directory.path().join("state.redb"))?,
                    allocator: GlobalChunkAllocator,
                },
                streams: Arc::new(super::super::streams::InboundStreams::default()),
                max_streams: 1,
                idle_timeout: Duration::from_secs(30),
                metrics: S2sMetrics::new(0),
            },
            _directory: directory,
        })
    }

    async fn reader(
        &self,
        xml: &str,
    ) -> TestResult<S2sReader<GlobalChunkAllocator, std::io::Cursor<Vec<u8>>>> {
        let mut reader = S2sReader::new(
            std::io::Cursor::new(format!("{HEADER}{xml}").into_bytes()),
            &self.settings.reader_limits,
            GlobalChunkAllocator,
            None,
        );
        assert!(matches!(
            reader
                .next_event()
                .await
                .map_err(|error| format!("{error:?}"))?,
            Some(StreamEvent::StreamStart { .. })
        ));
        Ok(reader)
    }

    fn parameters<'a>(
        &'a self,
        peer: &'a InboundPeer,
        shutdown: ShutdownSignal,
        valid_until: SystemTime,
    ) -> Parameters<'a, GlobalChunkAllocator> {
        Parameters {
            peer,
            valid_until,
            settings: &self.settings,
            shutdown,
        }
    }
}

#[derive(Clone, Default)]
struct Output(Rc<RefCell<Vec<u8>>>);
impl AsyncWrite for Output {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn peer() -> InboundPeer {
    InboundPeer {
        local: "local.test".into(),
        remote: "peer.test".into(),
        connection_id: 1,
    }
}
fn signal() -> (oneshot::Sender<Instant>, ShutdownSignal) {
    let (send, recv) = oneshot::channel();
    (
        send,
        async { recv.await.unwrap_or_else(|_| Instant::now()) }
            .boxed_local()
            .shared(),
    )
}
fn render(metrics: &Arc<S2sMetrics>) -> TestResult<String> {
    let mut registry = Registry::default();
    metrics.register(&mut registry);
    let mut output = String::new();
    prometheus_client::encoding::text::encode(&mut output, &registry)?;
    Ok(output)
}
fn sample(metrics: &Arc<S2sMetrics>, key: &str, value: usize) -> TestResult {
    assert!(
        render(metrics)?
            .lines()
            .any(|line| line == format!("{key} {value}")),
        "{}",
        render(metrics)?
    );
    Ok(())
}

#[test]
fn dispatch_is_sequential_and_rescoped_before_the_second_stanza_is_read() -> TestResult {
    let runtime = Runtime::new()?;
    runtime.block_on(async {
        assert!(runtime.current_timeout().is_none());
        let fixture = Fixture::new()?;
        let peer = peer();
        let (_stop, shutdown) = signal();
        let mut reader = fixture.reader("<message from='a@peer.test' to='b@local.test' id='one'/><message from='a@peer.test' to='b@local.test' id='two'/></stream:stream>").await?;
        let output = Output::default();
        let mut writer = S2sWriter::new(output);
        let (release, held) = std::sync::mpsc::sync_channel(0);
        let (started, entered) = std::sync::mpsc::sync_channel(0);
        let mut held = Some((started, held));
        let executor = lonewolf_util::blocking::BlockingExecutor::new(
            std::num::NonZeroUsize::new(1).ok_or("zero capacity")?,
        );
        let timeout = fixture.settings.timeout;
        let ids = Rc::new(RefCell::new(Vec::new()));
        let recorded = Rc::clone(&ids);
        let completed = Rc::new(std::cell::Cell::new(0));
        let dispatch_completed = Rc::clone(&completed);
        let dispatch = async move |_: &IngressContext<GlobalChunkAllocator>, _: &InboundPeer, stanza: RoutedStanza<GlobalChunkAllocator>| {
            let view = stanza.resolve().map_err(|_| IngressFailure)?;
            assert_eq!(view.namespace(), StanzaNamespace::Client);
            recorded.borrow_mut().push(view.id().map_err(|_| IngressFailure)?.unwrap_or_default().to_owned());
            if let Some((started, held)) = held.take() {
                let (receipt, released) = executor.run(move || {
                    (started.send(()), held.recv_timeout(timeout))
                }).await;
                assert!(receipt.is_ok());
                assert!(released.is_ok());
            }
            dispatch_completed.set(dispatch_completed.get() + 1);
            Ok(())
        };
        let expiry = rcgen::CertificateParams::default().not_after;
        let valid_until = SystemTime::UNIX_EPOCH + Duration::from_secs(expiry.unix_timestamp().try_into()?);
        let future = run(&mut reader, &mut writer, fixture.parameters(&peer, shutdown, valid_until), || {}, dispatch);
        let mut future = Box::pin(future);
        assert!(poll!(future.as_mut()).is_pending());
        entered.recv_timeout(timeout)?;
        assert_eq!(*ids.borrow(), ["one"]);
        assert_eq!(completed.get(), 0);
        let driver_timeout = runtime.current_timeout().ok_or("missing expiry timer")?;
        assert!(driver_timeout <= Duration::from_secs(i32::MAX as u64));
        assert!(driver_timeout > fixture.settings.idle_timeout);
        release.send(()).map_err(|_| "dispatch dropped")?;
        assert!(matches!(future.await, StreamClose::StreamEnd));
        assert_eq!(*ids.borrow(), ["one", "two"]);
        assert_eq!(completed.get(), 2);
        assert!(runtime.current_timeout().is_none());
        Ok(())
    })
}

#[test]
fn shutdown_closes_wire_then_drains_admitted_children_with_permit_and_gauges_held() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new()?;
        let peer = peer();
        let (stop, shutdown) = signal();
        let mut reader = fixture
            .reader("<message from='a@peer.test' to='b@local.test'/></stream:stream>")
            .await?;
        let output = Output::default();
        let mut writer = S2sWriter::new(output.clone());
        let (release, completion) = oneshot::channel::<()>();
        let mut completion = Some(completion);
        let (done, finished) = oneshot::channel();
        let mut done = Some(done);
        let aborted = Rc::new(std::cell::Cell::new(false));
        let abort = Rc::clone(&aborted);
        let future = run(
            &mut reader,
            &mut writer,
            fixture.parameters(&peer, shutdown, SystemTime::now() + Duration::from_secs(60)),
            move || abort.set(true),
            async move |context: &IngressContext<GlobalChunkAllocator>,
                        _: &InboundPeer,
                        _: RoutedStanza<GlobalChunkAllocator>| {
                let guard = context.work.start();
                let completion = completion.take().ok_or(IngressFailure)?;
                let done = done.take().ok_or(IngressFailure)?;
                compio::runtime::spawn(guard.run(async move {
                    let _ = completion.await;
                    let _ = done.send(());
                }))
                .detach();
                std::future::pending::<Result<(), IngressFailure>>().await
            },
        );
        let mut future = Box::pin(future);
        assert!(poll!(future.as_mut()).is_pending());
        stop.send(Instant::now() + Duration::from_secs(1))
            .map_err(|_| "stop dropped")?;
        assert!(poll!(future.as_mut()).is_pending());
        assert!(aborted.get());
        assert!(String::from_utf8(output.0.borrow().clone())?.contains("system-shutdown"));
        assert!(
            fixture
                .settings
                .streams
                .acquire("local.test", "peer.test", 1)
                .is_none()
        );
        sample(
            &fixture.settings.metrics,
            "s2s_streams{direction=\"inbound\"}",
            1,
        )?;
        release.send(()).map_err(|_| "child dropped")?;
        assert!(matches!(future.await, StreamClose::Shutdown));
        finished.await?;
        assert!(
            fixture
                .settings
                .streams
                .acquire("local.test", "peer.test", 1)
                .is_some()
        );
        sample(
            &fixture.settings.metrics,
            "s2s_streams{direction=\"inbound\"}",
            0,
        )?;
        sample(
            &fixture.settings.metrics,
            "s2s_streams_closed_total{direction=\"inbound\",outcome=\"shutdown\"}",
            1,
        )?;
        Ok(())
    })
}

#[test]
fn expiry_interrupts_dispatch_and_idle_waits_for_its_completion() -> TestResult {
    Runtime::new()?.block_on(async {
        for expiry in [true, false] {
            let mut fixture = Fixture::new()?;
            fixture.settings.idle_timeout = Duration::from_millis(10);
            let peer = peer();
            let (_stop, shutdown) = signal();
            let mut reader = fixture
                .reader("<message from='a@peer.test' to='b@local.test'/></stream:stream>")
                .await?;
            let output = Output::default();
            let mut writer = S2sWriter::new(output.clone());
            let (release, held) = oneshot::channel::<()>();
            let mut held = Some(held);
            let validity = SystemTime::now()
                + if expiry {
                    fixture.settings.idle_timeout
                } else {
                    Duration::from_secs(60)
                };
            let future = run(
                &mut reader,
                &mut writer,
                fixture.parameters(&peer, shutdown, validity),
                || {},
                async move |_: &IngressContext<GlobalChunkAllocator>,
                            _: &InboundPeer,
                            _: RoutedStanza<GlobalChunkAllocator>| {
                    if let Some(held) = held.take() {
                        let _ = held.await;
                    }
                    Ok(())
                },
            );
            let mut future = Box::pin(future);
            assert!(poll!(future.as_mut()).is_pending());
            if !expiry {
                compio::time::sleep_until(Instant::now() + fixture.settings.idle_timeout).await;
                assert!(poll!(future.as_mut()).is_pending());
                release.send(()).map_err(|_| "idle canceled dispatch")?;
            }
            let outcome = future.await;
            if expiry {
                assert!(matches!(outcome, StreamClose::CertificateExpired));
                assert!(String::from_utf8(output.0.borrow().clone())?.contains("reset"));
            } else {
                assert!(matches!(outcome, StreamClose::Idle));
            }
        }
        Ok(())
    })
}

#[test]
fn hard_listener_deadline_aborts_socket_before_adapters_and_keeps_child_guard_alive() -> TestResult
{
    struct Socket(Rc<std::cell::Cell<bool>>);
    impl Drop for Socket {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    struct Adapter {
        socket: Rc<std::cell::Cell<bool>>,
        dropped: Rc<std::cell::Cell<bool>>,
    }
    impl Drop for Adapter {
        fn drop(&mut self) {
            assert!(self.socket.get());
            self.dropped.set(true);
        }
    }
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new()?;
        let peer = peer();
        let (stop, shutdown) = signal();
        let mut reader = fixture
            .reader("<message from='a@peer.test' to='b@local.test'/></stream:stream>")
            .await?;
        let output = Output::default();
        let mut writer = S2sWriter::new(output);
        let (release, completion) = oneshot::channel::<()>();
        let mut completion = Some(completion);
        let (done, mut finished) = oneshot::channel::<()>();
        let mut done = Some(done);
        let socket = Rc::new(std::cell::Cell::new(false));
        let adapters = Rc::new(std::cell::Cell::new(false));
        let adapter = Adapter {
            socket: Rc::clone(&socket),
            dropped: Rc::clone(&adapters),
        };
        let future = run(
            &mut reader,
            &mut writer,
            fixture.parameters(&peer, shutdown, SystemTime::now() + Duration::from_secs(60)),
            || {},
            async move |context: &IngressContext<GlobalChunkAllocator>,
                        _: &InboundPeer,
                        _: RoutedStanza<GlobalChunkAllocator>| {
                let guard = context.work.start();
                let completion = completion.take().ok_or(IngressFailure)?;
                let done = done.take().ok_or(IngressFailure)?;
                compio::runtime::spawn(guard.run(async move {
                    let _ = completion.await;
                    let _ = done.send(());
                }))
                .detach();
                std::future::pending::<Result<(), IngressFailure>>().await
            },
        );
        let task = super::super::ConnectionTask {
            _socket: Socket(Rc::clone(&socket)),
            future: Box::pin(async move {
                let _adapter = adapter;
                future.await;
            }),
        };
        let active = futures_util::stream::FuturesUnordered::new();
        active.push(task);
        let deadline = Instant::now() + Duration::from_millis(10);
        let mut draining = Box::pin(super::super::drain_connections(active, deadline));
        assert!(poll!(draining.as_mut()).is_pending());
        stop.send(deadline).map_err(|_| "stop dropped")?;
        assert!(poll!(draining.as_mut()).is_pending());
        sample(
            &fixture.settings.metrics,
            "s2s_streams{direction=\"inbound\"}",
            1,
        )?;
        assert!(matches!(draining.await, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        assert!(socket.get() && adapters.get());
        sample(
            &fixture.settings.metrics,
            "s2s_streams{direction=\"inbound\"}",
            0,
        )?;
        sample(
            &fixture.settings.metrics,
            "s2s_streams_closed_total{direction=\"inbound\",outcome=\"shutdown\"}",
            1,
        )?;
        assert!(
            fixture
                .settings
                .streams
                .acquire("local.test", "peer.test", 1)
                .is_some()
        );
        assert!(poll!(&mut finished).is_pending());
        release
            .send(())
            .map_err(|_| "admitted child destroyed with parent")?;
        finished.await?;
        Ok(())
    })
}

#[test]
fn ingress_failure_closes_with_one_internal_error_outcome() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new()?;
        let peer = peer();
        let (_stop, shutdown) = signal();
        let mut reader = fixture
            .reader("<message from='a@peer.test' to='b@local.test'/></stream:stream>")
            .await?;
        let output = Output::default();
        let mut writer = S2sWriter::new(output.clone());
        let outcome = run(
            &mut reader,
            &mut writer,
            fixture.parameters(&peer, shutdown, SystemTime::now() + Duration::from_secs(60)),
            || {},
            async |_: &IngressContext<GlobalChunkAllocator>,
                   _: &InboundPeer,
                   _: RoutedStanza<GlobalChunkAllocator>| Err(IngressFailure),
        )
        .await;
        assert!(matches!(outcome, StreamClose::InternalError));
        let xml = String::from_utf8(output.0.borrow().clone())?;
        assert!(xml.contains("internal-server-error"));
        assert_eq!(xml.matches("</stream:stream>").count(), 1);
        sample(
            &fixture.settings.metrics,
            "s2s_streams_closed_total{direction=\"inbound\",outcome=\"internal_error\"}",
            1,
        )?;
        Ok(())
    })
}

#[test]
fn shutdown_shortens_pending_close_without_restarting_output_or_releasing_buffered_bytes()
-> TestResult {
    struct PendingFlush {
        output: Output,
        closes: Rc<std::cell::Cell<usize>>,
    }
    impl AsyncWrite for PendingFlush {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            std::pin::Pin::new(&mut self.output).poll_write(context, bytes)
        }
        fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_close(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.closes.set(self.closes.get() + 1);
            Poll::Ready(Ok(()))
        }
    }
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new()?;
        let peer = peer();
        let (stop, shutdown) = signal();
        let mut reader = fixture.reader("</stream:stream>").await?;
        let output = Output::default();
        let closes = Rc::new(std::cell::Cell::new(0));
        let mut writer = S2sWriter::new(PendingFlush {
            output: output.clone(),
            closes: Rc::clone(&closes),
        });
        let aborted = Rc::new(std::cell::Cell::new(false));
        let abort = Rc::clone(&aborted);
        let mut serving = Box::pin(run(
            &mut reader,
            &mut writer,
            fixture.parameters(&peer, shutdown, SystemTime::now() + Duration::from_secs(60)),
            move || abort.set(true),
            ingress::dispatch,
        ));
        assert!(poll!(serving.as_mut()).is_pending());
        assert_eq!(output.0.borrow().as_slice(), b"</stream:stream>");
        stop.send(Instant::now())
            .map_err(|_| "close stopped observing shutdown")?;
        assert!(matches!(serving.await, StreamClose::StreamEnd));
        assert!(aborted.get());
        assert_eq!(closes.get(), 0);
        assert_eq!(output.0.borrow().as_slice(), b"</stream:stream>");
        sample(
            &fixture.settings.metrics,
            "s2s_streams_closed_total{direction=\"inbound\",outcome=\"stream_end\"}",
            1,
        )?;
        Ok(())
    })
}

#[test]
fn reader_failures_preserve_each_wire_condition_and_use_bounded_metrics() {
    for (condition, outcome) in [
        (StreamErrorCondition::PolicyViolation, "protocol_error"),
        (StreamErrorCondition::NotWellFormed, "protocol_error"),
        (StreamErrorCondition::RestrictedXml, "protocol_error"),
        (StreamErrorCondition::UnsupportedEncoding, "protocol_error"),
        (StreamErrorCondition::BadNamespacePrefix, "protocol_error"),
        (StreamErrorCondition::InvalidXml, "protocol_error"),
        (StreamErrorCondition::BadFormat, "protocol_error"),
        (StreamErrorCondition::InvalidNamespace, "invalid_namespace"),
        (
            StreamErrorCondition::UnsupportedStanzaType,
            "unsupported_stanza_type",
        ),
    ] {
        let closed = Closed::reader_error(S2sError::Stream(condition));
        assert_eq!(closed.outcome.as_str(), outcome);
        assert!(matches!(closed.wire, WireClose::Error(actual) if actual == condition));
    }
    let internal = Closed::reader_error(S2sError::Internal);
    assert!(matches!(internal.outcome, StreamClose::InternalError));
    assert!(matches!(
        internal.wire,
        WireClose::Error(StreamErrorCondition::InternalServerError)
    ));
    for (error, outcome) in [
        (S2sError::Eof, "transport_error"),
        (S2sError::Io, "transport_error"),
        (S2sError::Timeout, "transport_error"),
        (
            S2sError::PeerError(StreamErrorCondition::PolicyViolation),
            "peer_error",
        ),
    ] {
        let closed = Closed::reader_error(error);
        assert_eq!(closed.outcome.as_str(), outcome);
        assert!(matches!(closed.wire, WireClose::Abort));
    }
    assert!(matches!(
        Closed::footer(StreamClose::StreamEnd, true).wire,
        WireClose::Footer { peer_closed: true }
    ));
    assert!(matches!(
        Closed::footer(StreamClose::Idle, false).wire,
        WireClose::Footer { peer_closed: false }
    ));
}
