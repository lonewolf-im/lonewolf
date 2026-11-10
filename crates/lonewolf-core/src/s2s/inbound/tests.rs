// SPDX-License-Identifier: Apache-2.0

use std::cell::{Cell, RefCell};
use std::error::Error;
use std::io;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::SystemTime;

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
use crate::s2s::revocation::PeerRevocation;
use crate::s2s::stream::S2sReaderLimits;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const HEADER: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0'>";

struct Fixture {
    settings: Settings<GlobalChunkAllocator>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Self::with_bidi(false)
    }

    fn with_bidi(bidi: bool) -> TestResult<Self> {
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, None)?;
        Self::with_hosts(hosts, bidi)
    }

    fn with_hosts(hosts: Hosts, bidi: bool) -> TestResult<Self> {
        use crate::s2s::outbound::{BidiIngress, RemoteRouter};
        use crate::s2s::revocation::PeerVerification;
        let config = Config::default();
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("state.redb"))?;
        let metrics = S2sMetrics::new(0);
        let mut router = Router::new(hosts.clone(), LocalRouter::new(GlobalChunkAllocator));
        if bidi {
            router = router.with_remote(RemoteRouter::new(
                hosts.clone(),
                PeerVerification {
                    trust: PeerTrust::load(&config.s2s.tls, hosts.crypto_provider())?,
                    revocation: PeerRevocation::disabled(),
                },
                Arc::new(crate::s2s::dns::Resolver::new(&config.s2s)?),
                &config.limits.s2s,
                GlobalChunkAllocator,
                Arc::clone(&metrics),
                Some(BidiIngress {
                    storage: storage.clone(),
                }),
            ));
        }
        Ok(Self {
            settings: Settings {
                tls_mode: crate::config::TlsMode::StartTls,
                trust: PeerTrust::load(&config.s2s.tls, hosts.crypto_provider())?,
                revocation: PeerRevocation::disabled(),
                hosts,
                timeout: Duration::from_secs(5),
                reader_limits: S2sReaderLimits {
                    max_stanza_bytes: config.limits.s2s.max_stanza_bytes,
                    stanzas: config.limits.s2s.incoming_stanzas_per_connection,
                    xml: config.limits.s2s.incoming_xml_per_connection,
                },
                services: IngressServices {
                    router: router.handle(),
                    storage,
                    allocator: GlobalChunkAllocator,
                },
                streams: Arc::new(super::super::streams::InboundStreams::default()),
                max_streams: 1,
                idle_timeout: Duration::from_secs(30),
                metrics,
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
        validity: &'a LinkValidity,
    ) -> Parameters<'a, GlobalChunkAllocator> {
        Parameters {
            peer,
            validity,
            settings: &self.settings,
            shutdown,
            bidi: false,
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
        let validity = LinkValidity::fixed(SystemTime::UNIX_EPOCH + Duration::from_secs(expiry.unix_timestamp().try_into()?));
        let future = run(&mut reader, &mut writer, fixture.parameters(&peer, shutdown, &validity), || {}, dispatch);
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
        drop(validity);
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
        let validity = LinkValidity::fixed(SystemTime::now() + Duration::from_secs(60));
        let future = run(
            &mut reader,
            &mut writer,
            fixture.parameters(&peer, shutdown, &validity),
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
            let validity = LinkValidity::fixed(
                SystemTime::now() + Duration::from_secs(if expiry { 1 } else { 60 }),
            );
            let future = run(
                &mut reader,
                &mut writer,
                fixture.parameters(&peer, shutdown, &validity),
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
        let validity = LinkValidity::fixed(SystemTime::now() + Duration::from_secs(60));
        let future = run(
            &mut reader,
            &mut writer,
            fixture.parameters(&peer, shutdown, &validity),
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
        let task = crate::connection::socket::ConnectionTask {
            _socket: Socket(Rc::clone(&socket)),
            future: Box::pin(async move {
                let _adapter = adapter;
                future.await;
            }),
        };
        let active = futures_util::stream::FuturesUnordered::new();
        active.push(task);
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut draining = Box::pin(crate::connection::drain_connections(
            active,
            deadline,
            crate::connection::ListenerKind::S2s,
            |_| {},
        ));
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
        let validity = LinkValidity::fixed(SystemTime::now() + Duration::from_secs(60));
        let outcome = run(
            &mut reader,
            &mut writer,
            fixture.parameters(&peer, shutdown, &validity),
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
        pending: bool,
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
            if self.pending {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
        fn poll_close(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.closes.set(self.closes.get() + 1);
            Poll::Ready(Ok(()))
        }
    }
    struct PendingInput {
        bytes: io::Cursor<Vec<u8>>,
        polls: Rc<std::cell::Cell<usize>>,
        dropped: Rc<std::cell::Cell<bool>>,
    }
    impl tokio::io::AsyncRead for PendingInput {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let position = self.bytes.position() as usize;
            if position < self.bytes.get_ref().len() {
                let count = output
                    .remaining()
                    .min(self.bytes.get_ref().len() - position);
                output.put_slice(&self.bytes.get_ref()[position..position + count]);
                self.bytes.set_position((position + count) as u64);
                Poll::Ready(Ok(()))
            } else {
                self.polls.set(self.polls.get() + 1);
                Poll::Pending
            }
        }
    }
    impl Drop for PendingInput {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    Runtime::new()?.block_on(async {
        for (pending_flush, expiry) in [(true, false), (false, false), (false, true)] {
            let fixture = Fixture::new()?;
            let peer = peer();
            let (stop, shutdown) = signal();
            let polls = Rc::new(std::cell::Cell::new(0));
            let dropped = Rc::new(std::cell::Cell::new(false));
            let mut reader = S2sReader::new(
                tokio::io::BufReader::new(PendingInput {
                    bytes: io::Cursor::new(format!("{HEADER}</stream:stream>").into_bytes()),
                    polls: Rc::clone(&polls),
                    dropped: Rc::clone(&dropped),
                }),
                &fixture.settings.reader_limits,
                GlobalChunkAllocator,
                None,
            );
            assert!(matches!(
                reader.next_event().await,
                Ok(Some(StreamEvent::StreamStart { .. }))
            ));
            let output = Output::default();
            let closes = Rc::new(std::cell::Cell::new(0));
            let mut writer = S2sWriter::new(PendingFlush {
                output: output.clone(),
                pending: pending_flush,
                closes: Rc::clone(&closes),
            });
            let aborted = Rc::new(std::cell::Cell::new(false));
            let abort = Rc::clone(&aborted);
            let validity = LinkValidity::fixed(
                SystemTime::now() + Duration::from_secs(if expiry { 1 } else { 60 }),
            );
            let mut serving = Box::pin(run(
                &mut reader,
                &mut writer,
                fixture.parameters(&peer, shutdown, &validity),
                move || abort.set(true),
                ingress::dispatch,
            ));
            assert!(poll!(serving.as_mut()).is_pending());
            assert_eq!(output.0.borrow().as_slice(), b"</stream:stream>");
            assert_eq!(closes.get(), usize::from(!pending_flush));
            assert_eq!(polls.get(), usize::from(!pending_flush));
            assert!(!dropped.get());
            assert!(!aborted.get());
            sample(
                &fixture.settings.metrics,
                "s2s_streams{direction=\"inbound\"}",
                1,
            )?;
            if !expiry {
                stop.send(Instant::now())
                    .map_err(|_| "close stopped observing shutdown")?;
            }
            assert!(matches!(serving.await, StreamClose::StreamEnd));
            assert!(aborted.get());
            assert_eq!(closes.get(), usize::from(!pending_flush));
            assert_eq!(dropped.get(), !pending_flush);
            assert_eq!(output.0.borrow().as_slice(), b"</stream:stream>");
            sample(
                &fixture.settings.metrics,
                "s2s_streams_closed_total{direction=\"inbound\",outcome=\"stream_end\"}",
                1,
            )?;
        }
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

#[test]
fn monitored_revocation_resets_the_stream_and_records_the_close() -> TestResult {
    use crate::s2s::revocation::{RevocationSource, RevocationStatus, RevocationVerdict};
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new()?;
        let peer = peer();
        let (_stop, shutdown) = signal();
        let mut reader = fixture
            .reader("<message from='a@peer.test' to='b@local.test'/></stream:stream>")
            .await?;
        let output = Output::default();
        let mut writer = S2sWriter::new(output.clone());
        let initial = RevocationVerdict {
            source: RevocationSource::Fetched,
            status: RevocationStatus::Good,
            next_update: None,
            refresh_at: None,
            pending: vec![async {}.boxed().shared()],
            leases: Vec::new(),
            recheckable: true,
        };
        let revalidate = Box::new(move || {
            async {
                Some(RevocationVerdict {
                    source: RevocationSource::Fetched,
                    status: RevocationStatus::Revoked,
                    next_update: None,
                    refresh_at: None,
                    pending: Vec::new(),
                    leases: Vec::new(),
                    recheckable: true,
                })
            }
            .boxed_local()
        });
        let (validity, monitor) = LinkValidity::monitored(
            SystemTime::now() + Duration::from_secs(60),
            initial,
            Duration::from_secs(60),
            revalidate,
        );
        let outcome = supervise(
            Some(monitor),
            MonitorLog {
                direction: Direction::Inbound,
                connection_id: peer.connection_id,
                local: &peer.local,
                remote: &peer.remote,
            },
            fixture.settings.timeout,
            run(
                &mut reader,
                &mut writer,
                fixture.parameters(&peer, shutdown, &validity),
                || {},
                async |_: &IngressContext<GlobalChunkAllocator>,
                       _: &InboundPeer,
                       _: RoutedStanza<GlobalChunkAllocator>| {
                    std::future::pending::<Result<(), IngressFailure>>().await
                },
            ),
        )
        .await;
        assert!(matches!(outcome, StreamClose::CertificateRevoked));
        let xml = String::from_utf8(output.0.borrow().clone())?;
        assert!(xml.contains("reset"));
        assert_eq!(xml.matches("</stream:stream>").count(), 1);
        let mut registry = Registry::default();
        fixture.settings.metrics.register(registry.sub_registry_with_prefix("lonewolf"));
        let mut metrics = String::new();
        prometheus_client::encoding::text::encode(&mut metrics, &registry)?;
        assert!(metrics.lines().any(|line| line == "lonewolf_s2s_streams_closed_total{direction=\"inbound\",outcome=\"certificate_revoked\"} 1"));
        Ok(())
    })
}

#[test]
fn monitored_file_deadline_resets_the_stream_and_records_staleness() -> TestResult {
    use crate::s2s::revocation::{RevocationSource, RevocationStatus, RevocationVerdict};
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new()?;
        let peer = peer();
        let (_stop, shutdown) = signal();
        let mut reader = fixture
            .reader("<message from='a@peer.test' to='b@local.test'/></stream:stream>")
            .await?;
        let output = Output::default();
        let mut writer = S2sWriter::new(output.clone());
        let now = SystemTime::now();
        let verdict = RevocationVerdict {
            source: RevocationSource::File,
            status: RevocationStatus::Good,
            next_update: Some(now + Duration::from_millis(100)),
            refresh_at: None,
            pending: Vec::new(),
            leases: Vec::new(),
            recheckable: true,
        };
        let (validity, monitor) = LinkValidity::monitored(
            now + Duration::from_secs(60),
            verdict,
            Duration::from_secs(60),
            Box::new(|| async { panic!("file deadline precedes rechecks") }.boxed_local()),
        );
        let outcome = supervise(
            Some(monitor),
            MonitorLog {
                direction: Direction::Inbound,
                connection_id: peer.connection_id,
                local: &peer.local,
                remote: &peer.remote,
            },
            fixture.settings.timeout,
            run(
                &mut reader,
                &mut writer,
                fixture.parameters(&peer, shutdown, &validity),
                || {},
                async |_: &IngressContext<GlobalChunkAllocator>,
                       _: &InboundPeer,
                       _: RoutedStanza<GlobalChunkAllocator>| {
                    std::future::pending::<Result<(), IngressFailure>>().await
                },
            ),
        )
        .await;
        assert!(matches!(outcome, StreamClose::RevocationStale));
        assert!(String::from_utf8(output.0.borrow().clone())?.contains("reset"));
        sample(
            &fixture.settings.metrics,
            "s2s_streams_closed_total{direction=\"inbound\",outcome=\"revocation_stale\"}",
            1,
        )?;
        Ok(())
    })
}

#[derive(Default)]
struct CloseInput {
    bytes: std::collections::VecDeque<u8>,
    eof: bool,
    waker: Option<Waker>,
}

#[derive(Clone, Default)]
struct CloseReader(Rc<RefCell<CloseInput>>);

impl CloseReader {
    fn supply(&self, bytes: &[u8], eof: bool) {
        let mut state = self.0.borrow_mut();
        state.bytes.extend(bytes);
        state.eof = eof;
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}

impl tokio::io::AsyncRead for CloseReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.0.borrow_mut();
        if state.bytes.is_empty() && !state.eof {
            state.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        while output.remaining() > 0 {
            let Some(byte) = state.bytes.pop_front() else {
                break;
            };
            output.put_slice(&[byte]);
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct CloseOutput {
    bytes: Vec<u8>,
    paused: bool,
    failed: bool,
    blocked: bool,
    flushed: bool,
    polls: usize,
    aborted: bool,
    waker: Option<Waker>,
}

#[derive(Clone, Default)]
struct CloseWriter(Rc<RefCell<CloseOutput>>);

impl CloseWriter {
    fn resume(&self) {
        let mut state = self.0.borrow_mut();
        state.paused = false;
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}

impl AsyncWrite for CloseWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.borrow_mut();
        assert!(!state.aborted);
        state.polls += 1;
        if state.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if state.paused {
            state.blocked = true;
            state.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        state.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.borrow_mut();
        assert!(!state.aborted);
        state.polls += 1;
        state.flushed = true;
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.borrow_mut();
        assert!(!state.aborted);
        state.polls += 1;
        Poll::Ready(Ok(()))
    }
}

async fn close_reader(
    fixture: &Fixture,
) -> TestResult<(
    CloseReader,
    S2sReader<GlobalChunkAllocator, tokio::io::BufReader<CloseReader>>,
)> {
    let input = CloseReader::default();
    input.supply(HEADER.as_bytes(), false);
    let mut reader = S2sReader::new(
        tokio::io::BufReader::new(input.clone()),
        &fixture.settings.reader_limits,
        GlobalChunkAllocator,
        None,
    );
    assert!(matches!(
        reader.next_event().await.map_err(|e| format!("{e:?}"))?,
        Some(StreamEvent::StreamStart { .. })
    ));
    Ok((input, reader))
}

fn close_validity() -> (LinkValidity, crate::s2s::validity::ValidityMonitor) {
    use crate::s2s::revocation::{RevocationSource, RevocationStatus, RevocationVerdict};
    LinkValidity::monitored(
        SystemTime::now() + Duration::from_secs(3600),
        RevocationVerdict {
            source: RevocationSource::Fetched,
            status: RevocationStatus::Good,
            next_update: None,
            refresh_at: None,
            pending: Vec::new(),
            leases: Vec::new(),
            recheckable: false,
        },
        Duration::from_secs(60),
        Box::new(|| async { None }.boxed_local()),
    )
}

#[test]
fn buffered_stanza_and_close_flush_before_queue_handoff_and_peer_footer() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::with_bidi(true)?;
        let router = &fixture.settings.services.router;
        let remote = router.remote_router().ok_or("missing remote")?;
        let older = remote.register_bidi(router, "localhost", "remote.test").ok_or("missing older")?;
        let registration = remote.register_bidi(router, "localhost", "remote.test").ok_or("missing registration")?;
        let mut source = fixture.reader("<message from='a@localhost' to='b@remote.test'><body>first</body></message><message from='a@localhost' to='b@remote.test'><body>second</body></message>").await?;
        for _ in 0..2 {
            let Some(StreamEvent::Stanza(stanza)) = source.next_event().await.map_err(|e| format!("{e:?}"))? else { return Err("missing stanza".into()); };
            remote.route(router, "localhost", "remote.test", RoutedStanza::from_parsed(stanza)).map_err(|e| format!("{e:?}"))?;
        }
        let mut queue = Some(registration.assigned().await.ok_or("missing assignment")?);
        let (input, mut reader) = close_reader(&fixture).await?;
        let output = CloseWriter::default();
        let mut writer = S2sWriter::new(output.clone());
        let validity = LinkValidity::fixed(SystemTime::now() + Duration::from_secs(3600));
        let mut group = WorkGroup::new();
        let context = IngressContext { router: router.clone(), storage: fixture.settings.services.storage.clone(), allocator: GlobalChunkAllocator, work: group.handle() };
        let peer = InboundPeer { local: "localhost".into(), remote: "remote.test".into(), connection_id: 1 };
        let (stop, shutdown) = oneshot::channel::<()>();
        let mut dispatch = async |_: &IngressContext<GlobalChunkAllocator>, _: &InboundPeer, _: RoutedStanza<GlobalChunkAllocator>| Ok(());
        let end = {
            let mut driver = std::pin::pin!(duplex::run_inbound(&registration, &mut queue, &mut reader, &mut writer, DuplexParameters { peer: &peer, context: &context, validity: &validity, idle_timeout: Duration::from_secs(30) }, async { let _ = shutdown.await; }, &mut dispatch));
            assert!(poll!(driver.as_mut()).is_pending());
            sample(&fixture.settings.metrics, "s2s_bidi_stanzas_sent_total{kind=\"message\"}", 1)?;
            assert!(output.0.borrow().bytes.is_empty());
            stop.send(()).map_err(|_| "driver stopped")?;
            driver.await
        };
        assert!(matches!(end.reason, StreamClose::Shutdown));
        assert!(queue.is_some());
        sample(&fixture.settings.metrics, "s2s_outbound_queued_stanzas", 1)?;
        output.0.borrow_mut().paused = true;
        let mut registration = Some(registration);
        let released = Cell::new(0);
        let mut release = || {
            if let Some(registration) = registration.take() {
                assert!(output.0.borrow().flushed);
                let state = output.0.borrow();
                assert!(state.bytes.windows(b"<body>first</body></message>".len()).any(|bytes| bytes == b"<body>first</body></message>"));
                assert!(state.bytes.ends_with(b"</stream:stream>"));
                assert!(!state.bytes.windows(6).any(|bytes| bytes == b"second"));
                released.set(released.get() + 1);
                registration.release(queue.take());
            }
        };
        let (_stop, shutdown) = signal();
        let mut closing = Box::pin(finish(&mut reader, &mut writer, Closed::footer(StreamClose::StreamEnd, false), &validity, shutdown, || { output.0.borrow_mut().aborted = true; }, &mut release));
        let mut assigned = Box::pin(older.assigned());
        assert!(poll!(closing.as_mut()).is_pending());
        assert!(output.0.borrow().blocked);
        assert_eq!(released.get(), 0);
        assert!(poll!(assigned.as_mut()).is_pending());
        output.resume();
        assert!(poll!(closing.as_mut()).is_pending());
        assert_eq!(released.get(), 1);
        assert!(!output.0.borrow().aborted);
        let tail = assigned.await.ok_or("missing tail handoff")?;
        sample(&fixture.settings.metrics, "s2s_outbound_queued_stanzas", 1)?;
        input.supply(b"</stream:stream>", true);
        closing.await;
        assert!(output.0.borrow().aborted);
        assert_eq!(released.get(), 1);
        remote.stop();
        older.release(Some(tail));
        remote.join(Instant::now() + Duration::from_secs(1)).await?;
        drop(context);
        group.drain().await;
        sample(&fixture.settings.metrics, "s2s_outbound_queued_stanzas", 0)?;
        Ok(())
    }))?
}

#[test]
fn failed_cancelled_and_aborted_close_abort_before_releasing_once() -> TestResult {
    Runtime::new()?.block_on(async {
        for case in 0..4 {
            let fixture = Fixture::new()?;
            let (_input, mut reader) = close_reader(&fixture).await?;
            let output = CloseWriter::default();
            output.0.borrow_mut().paused = case == 1 || case == 2;
            output.0.borrow_mut().failed = case == 0;
            let mut writer = S2sWriter::new(output.clone());
            let (validity, monitor) = close_validity();
            let (stop, shutdown) = signal();
            let events = RefCell::new(Vec::new());
            let released = Cell::new(false);
            let mut release = || {
                if !released.replace(true) {
                    assert!(output.0.borrow().aborted);
                    events.borrow_mut().push("release");
                }
            };
            let closed = if case == 3 {
                Closed {
                    outcome: StreamClose::TransportError,
                    wire: WireClose::Abort,
                }
            } else {
                Closed::footer(StreamClose::StreamEnd, false)
            };
            let mut closing = Box::pin(finish(
                &mut reader,
                &mut writer,
                closed,
                &validity,
                shutdown,
                || {
                    output.0.borrow_mut().aborted = true;
                    events.borrow_mut().push("abort");
                },
                &mut release,
            ));
            if case == 1 || case == 2 {
                assert!(poll!(closing.as_mut()).is_pending());
                assert!(output.0.borrow().blocked);
                assert!(!released.get());
                assert!(!output.0.borrow().aborted);
                if case == 1 {
                    validity.record_invalidation(StreamClose::CertificateRevoked);
                    drop(monitor);
                } else {
                    stop.send(Instant::now() - Duration::from_secs(1))
                        .map_err(|_| "shutdown dropped")?;
                }
            }
            closing.await;
            assert_eq!(*events.borrow(), ["abort", "release"]);
            if case == 3 {
                assert_eq!(output.0.borrow().polls, 0);
            }
            let polls = output.0.borrow().polls;
            output.resume();
            assert_eq!(output.0.borrow().polls, polls);
        }
        Ok(())
    })
}

#[test]
fn selected_reset_flushes_before_release_despite_existing_invalidation() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new()?;
        let (input, mut reader) = close_reader(&fixture).await?;
        let output = CloseWriter::default();
        output.0.borrow_mut().paused = true;
        let mut writer = S2sWriter::new(output.clone());
        let (validity, monitor) = close_validity();
        validity.record_invalidation(StreamClose::CertificateRevoked);
        drop(monitor);
        let (_stop, shutdown) = signal();
        let events = RefCell::new(Vec::new());
        let released = Cell::new(false);
        let mut release = || {
            if !released.replace(true) {
                let state = output.0.borrow();
                assert!(state.flushed);
                assert!(!state.aborted);
                events.borrow_mut().push("release");
            }
        };
        let mut closing = Box::pin(finish(
            &mut reader,
            &mut writer,
            Closed {
                outcome: StreamClose::CertificateRevoked,
                wire: WireClose::Error(StreamErrorCondition::Reset),
            },
            &validity,
            shutdown,
            || {
                output.0.borrow_mut().aborted = true;
                events.borrow_mut().push("abort");
            },
            &mut release,
        ));
        assert!(poll!(closing.as_mut()).is_pending());
        assert!(output.0.borrow().blocked);
        assert!(!released.get());
        assert!(poll!(closing.as_mut()).is_pending());
        input.supply(b"</stream:stream>", true);
        output.resume();
        closing.await;
        assert_eq!(*events.borrow(), ["release", "abort"]);
        assert!(
            output
                .0
                .borrow()
                .bytes
                .windows(5)
                .any(|bytes| bytes == b"reset")
        );
        Ok(())
    })
}

#[test]
fn physical_whitespace_and_partial_xml_extend_inbound_idle_until_silence() -> TestResult {
    use crate::s2s::stream::traffic::{
        S2sTrafficObserver,
        test_support::{Clock, Fragments},
    };
    use crate::xml_stream::traffic::CountingIo;
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    Runtime::new()?.block_on(async {
        let mut fixture = Fixture::new()?;
        fixture.settings.idle_timeout = Duration::from_millis(200);
        let clock = Clock::new();
        let input = Fragments::default();
        input.push(HEADER.as_bytes());
        let counted = CountingIo::new(
            input.clone(),
            S2sTrafficObserver::new(Arc::clone(&fixture.settings.metrics), Direction::Inbound),
        );
        let activity = counted.observer().activity();
        let mut reader = S2sReader::new(
            tokio::io::BufReader::new(counted.compat()),
            &fixture.settings.reader_limits,
            GlobalChunkAllocator,
            None,
        )
        .with_activity(activity.clone());
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::StreamStart { .. }))
        ));
        activity.record(clock.now());
        let peer = peer();
        let validity = LinkValidity::fixed(SystemTime::now() + Duration::from_secs(60));
        let (_stop, shutdown) = signal();
        let group = WorkGroup::new();
        let context = IngressContext {
            router: fixture.settings.services.router.clone(),
            storage: fixture.settings.services.storage.clone(),
            allocator: GlobalChunkAllocator,
            work: group.handle(),
        };
        let received = Cell::new(0);
        let mut dispatch =
            async |_: &IngressContext<GlobalChunkAllocator>,
                   _: &InboundPeer,
                   _: RoutedStanza<GlobalChunkAllocator>| {
                received.set(received.get() + 1);
                Ok(())
            };
        let mut running = std::pin::pin!(receive_with_clock(
            &mut reader,
            Receiving {
                peer: &peer,
                validity: &validity,
                settings: &fixture.settings,
                shutdown,
                context: &context
            },
            &mut dispatch,
            &clock
        ));
        assert!(poll!(running.as_mut()).is_pending());
        assert!(poll!(running.as_mut()).is_pending());
        for fragment in [b" \n".as_slice(), b"<message", b" from='"] {
            clock.advance(Duration::from_millis(100));
            let before = input.polls();
            input.push(fragment);
            assert!(poll!(running.as_mut()).is_pending());
            assert!(input.polls() > before);
            activity.record(clock.now());
        }
        assert_eq!(received.get(), 0);
        clock.advance(Duration::from_millis(199));
        assert!(poll!(running.as_mut()).is_pending());
        clock.advance(Duration::from_millis(1));
        assert!(matches!(running.await.outcome, StreamClose::Idle));
        Ok(())
    })
}

#[test]
fn direct_sni_normalizes_idna_and_checks_registration_coverage_and_federation()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::config::{Config, HostConfig, HostTlsConfig, HostTlsSource};
    use crate::hosts::Hosts;
    use crate::router::{Router, ServiceRoute, local::LocalRouter};
    use lonewolf_extension::{
        ExtensionFuture,
        delivery::HandlerError,
        service::{ServiceContext, ServiceHandler},
    };
    use lonewolf_storage::RedbStorage;
    use lonewolf_util::arena::GlobalChunkAllocator;
    use std::collections::BTreeMap;
    struct UncalledService;
    impl ServiceHandler<GlobalChunkAllocator, RedbStorage> for UncalledService {
        fn route<'a>(
            &'a self,
            _stanza: lonewolf_xmpp::stanza::RoutedStanza<GlobalChunkAllocator>,
            _context: ServiceContext<'a, GlobalChunkAllocator, RedbStorage>,
        ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
            Box::pin(async { panic!("selection must not route a stanza") })
        }
    }
    compio::runtime::Runtime::new()?.block_on(async {
        use base64::Engine as _;
        let directory = tempfile::tempdir()?;
        let mut config = Config::default();
        for (domain, names) in [
            (
                "example.com",
                vec!["example.com".into(), "*.example.com".into()],
            ),
            ("bücher.example", vec!["xn--bcher-kva.example".into()]),
            ("disabled.example.com", vec!["disabled.example.com".into()]),
        ] {
            let (certificate, key) =
                crate::hosts::test_support::material(rcgen::CertificateParams::new(names)?)?;
            let certificate_chain_path = directory.path().join(format!("{domain}.pem"));
            let private_key_path = directory.path().join(format!("{domain}.key"));
            let pem = |label, bytes: &[u8]| {
                format!(
                    "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                )
            };
            std::fs::write(
                &certificate_chain_path,
                pem("CERTIFICATE", certificate.as_ref()),
            )?;
            std::fs::write(&private_key_path, pem("PRIVATE KEY", key.secret_der()))?;
            config.hosts.insert(
                domain.into(),
                HostConfig {
                    federation: domain != "disabled.example.com",
                    tls: Some(HostTlsConfig {
                        source: HostTlsSource::Files {
                            certificate_chain_path,
                            private_key_path,
                        },
                        client_auth: None,
                    }),
                    ..HostConfig::default()
                },
            );
        }
        let hosts = Hosts::new(&config.hosts, Some("localhost"))?;
        let mut fixture = Fixture::with_hosts(hosts.clone(), true)?;
        let services = || {
            BTreeMap::from_iter(["echo.example.com", "echo.other.test"].map(|domain| {
                (
                    domain.into(),
                    ServiceRoute {
                        domain: Arc::from(domain),
                        handler: Arc::new(UncalledService)
                            as Arc<dyn ServiceHandler<GlobalChunkAllocator, RedbStorage>>,
                    },
                )
            }))
        };
        let remote = fixture
            .settings
            .services
            .router
            .remote_router()
            .ok_or("missing remote router")?
            .clone();
        let router = Router::new(hosts.clone(), LocalRouter::new(GlobalChunkAllocator))
            .with_remote(remote)
            .with_services(services());
        fixture.settings.services.router = router.handle();
        for (name, expected) in [
            ("EXAMPLE.COM", "example.com"),
            ("XN--BCHER-KVA.EXAMPLE", "bücher.example"),
            ("ECHO.EXAMPLE.COM", "echo.example.com"),
        ] {
            assert_eq!(
                super::super::negotiate::select_sni(Some(name), &fixture.settings).as_deref(),
                Some(expected)
            );
            let direct = hosts
                .s2s_direct_server_config(expected, &fixture.settings.trust)
                .ok_or("missing direct config")?;
            assert_eq!(direct.alpn_protocols, [b"xmpp-server".to_vec()]);
            assert!(
                hosts
                    .s2s_server_config(expected, &fixture.settings.trust)
                    .ok_or("missing STARTTLS config")?
                    .alpn_protocols
                    .is_empty()
            );
        }
        assert!(
            hosts
                .s2s_direct_server_config("unregistered.example.com", &fixture.settings.trust)
                .is_some()
        );
        assert!(
            hosts
                .s2s_direct_server_config("echo.other.test", &fixture.settings.trust)
                .is_none()
        );
        for name in [
            None,
            Some("unknown.test"),
            Some("unregistered.example.com"),
            Some("echo.other.test"),
            Some("disabled.example.com"),
            Some("localhost"),
        ] {
            assert!(
                super::super::negotiate::select_sni(name, &fixture.settings).is_none(),
                "{name:?}"
            );
        }
        let disabled =
            Router::new(hosts, LocalRouter::new(GlobalChunkAllocator)).with_services(services());
        fixture.settings.services.router = disabled.handle();
        assert!(
            super::super::negotiate::select_sni(Some("example.com"), &fixture.settings).is_none()
        );
        assert!(
            super::super::negotiate::select_sni(Some("echo.example.com"), &fixture.settings)
                .is_none()
        );
        Ok(())
    })
}

#[test]
fn admitted_unpolled_connection_counts_cancelled_once_and_releases_mode_gauges_and_permits()
-> TestResult {
    use super::super::{AdmissionLimits, GlobalLimit, S2sAcceptor};
    use crate::config::TlsMode;
    use crate::connection::{
        AcceptHandler, ListenerSlot,
        socket::{ConnectionSocket, ConnectionTask},
    };
    use parking_lot::Mutex as PlMutex;
    use std::io::Read as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    Runtime::new()?.block_on(async {
        for mode in TlsMode::ALL {
            let mut fixture = Fixture::new()?;
            fixture.settings.metrics = S2sMetrics::new(1);
            fixture.settings.tls_mode = mode;
            let limits = Config::default().limits.s2s;
            let admission = Arc::new(AdmissionLimits {
                attempts: crate::admission::attempt_limit::AttemptLimiter::new(&limits.connection_attempts_per_ip),
                connections: crate::admission::connection_limit::ConnectionLimiter::new(limits.max_connections_per_ip.get()),
                global: Arc::new(GlobalLimit { active: AtomicUsize::new(0), max: limits.max_inbound_connections.get(), report: PlMutex::new(crate::admission::rejection_report::RejectionReport::default()) }),
            });
            let handler = S2sAcceptor { admission: Arc::clone(&admission), settings: fixture.settings.clone() };
            let listener = crate::connection::bind(([127, 0, 0, 1], 0).into()).await?;
            let mut peer = std::net::TcpStream::connect(listener.local_addr()?)?;
            peer.set_read_timeout(Some(Duration::from_secs(5)))?;
            let (socket, peer_address) = listener.accept().await?;
            let permit = handler.admit(peer_address.ip()).await.map_err(|_| "admission rejected")?;
            let task = ConnectionTask { _socket: ConnectionSocket(socket.clone()), future: Box::pin(handler.serve(ListenerSlot { listener_id: 0, worker_id: 0 }, socket, permit, std::future::pending().boxed_local().shared())) };
            assert_eq!(admission.global.active.load(Ordering::Acquire), 1);
            let output = render(&fixture.settings.metrics)?;
            assert!(!output.contains("s2s_transport_attempts_total"));
            assert!(output.contains("s2s_connections{direction=\"inbound\"} 1"));
            drop(task);
            assert_eq!(peer.read(&mut [0; 1])?, 0);
            assert_eq!(admission.global.active.load(Ordering::Acquire), 0);
            let output = render(&fixture.settings.metrics)?;
            assert_eq!(output.lines().filter(|line| line.starts_with("s2s_transport_attempts_total{")).count(), 1);
            assert!(output.contains(&format!("s2s_transport_attempts_total{{direction=\"inbound\",tls_mode=\"{}\",outcome=\"cancelled\"}} 1", mode.as_str())));
            assert!(!output.contains("s2s_authentications_total"));
            assert!(output.contains("s2s_connections{direction=\"inbound\"} 0"));
            for tls_mode in TlsMode::ALL { assert!(output.contains(&format!("s2s_transport_connections{{direction=\"inbound\",tls_mode=\"{}\"}} 0", tls_mode.as_str()))); }
            listener.close().await?;
        }
        Ok(())
    })
}
