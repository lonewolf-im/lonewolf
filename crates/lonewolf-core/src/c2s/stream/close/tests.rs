// SPDX-License-Identifier: Apache-2.0

use std::cell::{Cell, RefCell};
use std::error::Error;
use std::io::Cursor;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use compio::runtime::Runtime;
use futures_util::io::AsyncWrite;
use futures_util::poll;
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::parser::{ParserConfig, XmppParser};

use super::*;
use crate::c2s::stream::header::ClientHeader;
use crate::c2s::stream::stanza_rate::StanzaLimiter;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type TestReader = Reader<GlobalChunkAllocator, std::io::Cursor<Vec<u8>>>;
const HEADER: &str =
    "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>";

fn reader(xml: String) -> TestResult<TestReader> {
    Ok(Reader::new(
        XmppParser::new(
            Cursor::new(xml.into_bytes()),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(16384).ok_or("invalid size")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        ),
        StanzaLimiter::new(NonZeroUsize::MIN, NonZeroUsize::MIN),
    ))
}

fn header() -> ClientHeader {
    ClientHeader {
        host: "localhost".into(),
        response_to: None,
        client_content_namespace: true,
    }
}

#[test]
fn local_close_discards_complete_stanzas_without_spending_stanza_tokens() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut reader = reader(format!(
            "{HEADER}<message/><message/><message/></stream:stream>"
        ))?;
        reader
            .next_event()
            .await
            .map_err(|outcome| format!("{outcome:?}"))?;
        let mut writer = Writer::new(
            Vec::new(),
            "localhost".into(),
            crate::c2s::metrics::C2sWorkerMetrics::detached(),
        );
        writer
            .send_header(&header())
            .await
            .map_err(|outcome| format!("{outcome:?}"))?;
        compio::time::timeout(
            Duration::from_millis(100),
            xml(
                &mut reader,
                &mut writer,
                CloseReason::Local(CloseOutcome::InternalError),
            ),
        )
        .await?
        .map_err(|outcome| format!("{outcome:?}"))?;
        let output = String::from_utf8(
            writer
                .take_output()
                .map_err(|outcome| format!("{outcome:?}"))?,
        )?;
        assert_eq!(output.matches("</stream:stream>").count(), 1);
        assert_eq!(output.matches("<stream:error>").count(), 1);
        assert!(!output.contains("<message"));
        Ok(())
    })
}

struct PartialWriter {
    bytes: Rc<RefCell<Vec<u8>>>,
    allowance: Rc<Cell<usize>>,
}

impl AsyncWrite for PartialWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let count = bytes.len().min(self.allowance.get());
        if count == 0 {
            return Poll::Pending;
        }
        self.bytes.borrow_mut().extend_from_slice(&bytes[..count]);
        self.allowance.set(self.allowance.get() - count);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("XML close must not finalize the transport")
    }
}

#[test]
fn interrupted_stanza_serialization_never_appends_or_flushes_a_footer() -> TestResult {
    Runtime::new()?.block_on(async {
        let bytes = Rc::new(RefCell::new(Vec::new()));
        let allowance = Rc::new(Cell::new(usize::MAX));
        let mut writer = Writer::new(
            PartialWriter {
                bytes: Rc::clone(&bytes),
                allowance: Rc::clone(&allowance),
            },
            "localhost".into(),
            crate::c2s::metrics::C2sWorkerMetrics::detached(),
        );
        writer
            .send_header(&header())
            .await
            .map_err(|outcome| format!("{outcome:?}"))?;
        let mut source = XmppParser::new(
            Cursor::new(
                format!(
                    "{HEADER}<message><body>{}</body></message>",
                    "x".repeat(8192)
                )
                .into_bytes(),
            ),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(16384).ok_or("invalid size")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        );
        source.next_event().await?;
        let Some(StreamEvent::Stanza(stanza)) = source.next_event().await? else {
            return Err("missing stanza".into());
        };
        let view = stanza.value().resolve(stanza.arena())?;
        allowance.set(64);
        let mut write = Box::pin(writer.write_stanza(&view));
        assert!(poll!(write.as_mut()).is_pending());
        drop(write);
        assert!(!writer.is_intact());
        let accepted = bytes.borrow().len();
        allowance.set(usize::MAX);
        let (mut input, _, _) = probe_reader(HEADER.as_bytes().to_vec(), Tail::Panic);
        assert!(
            xml(
                &mut input,
                &mut writer,
                CloseReason::Local(CloseOutcome::SystemShutdown)
            )
            .await
            .map_err(|outcome| format!("{outcome:?}"))?
        );
        drop(
            writer
                .take_output()
                .map_err(|outcome| format!("{outcome:?}"))?,
        );
        assert_eq!(bytes.borrow().len(), accepted);
        assert!(!String::from_utf8_lossy(&bytes.borrow()).contains("</stream:stream>"));
        Ok(())
    })
}

#[test]
fn blocked_phase_writes_cancel_before_timeout_close_discards_application_buffering() -> TestResult {
    use futures_util::FutureExt as _;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdTcpStream};
    Runtime::new()?.block_on(async {
        let stanza = format!("<message><body>{}</body></message>", "x".repeat(8192));
        for outcome in [
            CloseOutcome::EstablishmentTimeout,
            CloseOutcome::AuthenticationTimeout,
            CloseOutcome::BindingTimeout,
        ] {
            let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            let _peer = StdTcpStream::connect(listener.local_addr()?)?;
            let (socket, _) = listener.accept().await?;
            let bytes = Rc::new(RefCell::new(Vec::new()));
            let allowance = Rc::new(Cell::new(usize::MAX));
            let mut writer = Writer::new(
                PartialWriter {
                    bytes: Rc::clone(&bytes),
                    allowance: Rc::clone(&allowance),
                },
                "localhost".into(),
                crate::c2s::metrics::C2sWorkerMetrics::detached(),
            );
            writer
                .send_header(&header())
                .await
                .map_err(|error| format!("{error:?}"))?;
            allowance.set(64);
            let deadline = Instant::now() + Duration::from_millis(20);
            assert_eq!(
                crate::c2s::stream::run_phase(Some(deadline), outcome, writer.send(&stanza)).await,
                Err(outcome)
            );
            assert!(!writer.is_intact());
            let accepted = bytes.borrow().len();
            allowance.set(usize::MAX);
            let context = CloseContext {
                socket,
                shutdown: std::future::pending::<Instant>().boxed_local().shared(),
                phase_deadline: Some(deadline),
            };
            let (mut input, _, _) = probe_reader(HEADER.as_bytes().to_vec(), Tail::Panic);
            assert_eq!(
                finish_plain(&mut input, &mut writer, outcome.into(), &context).await,
                outcome
            );
            assert_eq!(bytes.borrow().len(), accepted);
            assert!(!String::from_utf8_lossy(&bytes.borrow()).contains("</stream:stream>"));
            assert!(!String::from_utf8_lossy(&bytes.borrow()).contains("policy-violation"));
            listener.close().await?;
        }
        Ok(())
    })
}

#[test]
fn timeout_during_starttls_proceed_flush_never_appends_plaintext_after_proceed() -> TestResult {
    use futures_util::FutureExt as _;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdTcpStream};
    Runtime::new()?.block_on(async {
        let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let _peer = StdTcpStream::connect(listener.local_addr()?)?;
        let (socket, _) = listener.accept().await?;
        let bytes = Rc::new(RefCell::new(Vec::new()));
        let allowance = Rc::new(Cell::new(usize::MAX));
        let mut writer = Writer::new(
            PartialWriter {
                bytes: Rc::clone(&bytes),
                allowance: Rc::clone(&allowance),
            },
            "localhost".into(),
            crate::c2s::metrics::C2sWorkerMetrics::detached(),
        );
        writer
            .send_header(&header())
            .await
            .map_err(|error| format!("{error:?}"))?;
        let header_bytes = bytes.borrow().len();
        allowance.set(1);
        let deadline = Instant::now() + Duration::from_millis(20);
        assert_eq!(
            crate::c2s::stream::run_phase(
                Some(deadline),
                CloseOutcome::EstablishmentTimeout,
                writer.send(crate::c2s::stream::establish::STARTTLS_PROCEED)
            )
            .await,
            Err(CloseOutcome::EstablishmentTimeout)
        );
        assert_eq!(bytes.borrow().len(), header_bytes + 1);
        let accepted = bytes.borrow().len();
        allowance.set(usize::MAX);
        let context = CloseContext {
            socket,
            shutdown: std::future::pending::<Instant>().boxed_local().shared(),
            phase_deadline: Some(deadline),
        };
        let (mut input, _, _) = probe_reader(
            format!("{HEADER}</stream:stream>").into_bytes(),
            Tail::Panic,
        );
        assert_eq!(
            finish_plain(
                &mut input,
                &mut writer,
                CloseOutcome::EstablishmentTimeout.into(),
                &context
            )
            .await,
            CloseOutcome::EstablishmentTimeout
        );
        drop(writer);
        {
            let output = bytes.borrow();
            assert_eq!(output.len(), accepted);
            assert!(!String::from_utf8_lossy(&output).contains("policy-violation"));
            assert!(!String::from_utf8_lossy(&output).contains("</stream:stream>"));
        }
        listener.close().await?;
        Ok(())
    })
}

#[test]
fn phase_timeouts_survive_every_secondary_close_failure() {
    for outcome in [
        CloseOutcome::EstablishmentTimeout,
        CloseOutcome::AuthenticationTimeout,
        CloseOutcome::BindingTimeout,
    ] {
        for failure in [
            CloseOutcome::TransportError,
            CloseOutcome::InternalError,
            CloseOutcome::SystemShutdown,
        ] {
            assert_eq!(completed(Ok(Err(failure)), outcome, "test"), outcome);
        }
        assert_eq!(completed(Err(()), outcome, "test"), outcome);
    }
    assert_eq!(
        completed(
            Ok(Err(CloseOutcome::TransportError)),
            CloseOutcome::InvalidXml,
            "test"
        ),
        CloseOutcome::TransportError
    );
}

#[test]
fn timeout_grace_is_anchored_to_the_original_phase_deadline() -> TestResult {
    use futures_util::FutureExt as _;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdTcpStream};
    Runtime::new()?.block_on(async {
        let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let _peer = StdTcpStream::connect(listener.local_addr()?)?;
        let (socket, _) = listener.accept().await?;
        let expired = Instant::now() - Duration::from_secs(1);
        let mut context = CloseContext {
            socket,
            shutdown: std::future::pending::<Instant>().boxed_local().shared(),
            phase_deadline: Some(expired),
        };
        for outcome in [
            CloseOutcome::EstablishmentTimeout,
            CloseOutcome::AuthenticationTimeout,
            CloseOutcome::BindingTimeout,
        ] {
            assert_eq!(context.deadline_for(outcome), expired + CLOSE_TIMEOUT);
        }
        assert_eq!(context.deadline_for(CloseOutcome::InternalError), expired);
        context.phase_deadline = None;
        let started = Instant::now();
        let fallback = context.deadline_for(CloseOutcome::BindingTimeout);
        assert!(fallback >= started + CLOSE_TIMEOUT);
        assert!(fallback <= Instant::now() + CLOSE_TIMEOUT);
        context.abort();
        listener.close().await?;
        Ok(())
    })
}

#[test]
fn shutdown_shortens_a_close_already_waiting_on_its_original_deadline() -> TestResult {
    use futures_util::FutureExt as _;
    use std::io::Read as _;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdTcpStream};

    Runtime::new()?.block_on(async {
        let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let mut peer = StdTcpStream::connect(listener.local_addr()?)?;
        peer.set_read_timeout(Some(Duration::from_secs(1)))?;
        let (socket, _) = listener.accept().await?;
        let (stop, stopped) = futures_channel::oneshot::channel();
        let context = CloseContext {
            socket,
            shutdown: async move { stopped.await.unwrap_or_else(|_| Instant::now()) }
                .boxed_local()
                .shared(),
            phase_deadline: None,
        };
        let mut close = Box::pin(context.until(context.deadline(), std::future::pending::<()>()));
        for _ in 0..100 {
            assert!(poll!(close.as_mut()).is_pending());
        }
        let deadline = Instant::now() + Duration::from_millis(100);
        stop.send(deadline).map_err(|_| "close stopped listening")?;
        assert!(
            compio::time::timeout(Duration::from_secs(1), close)
                .await?
                .is_err()
        );
        assert!(Instant::now() >= deadline);
        assert_eq!(peer.read(&mut [0; 1])?, 0);
        listener.close().await?;
        Ok(())
    })
}

#[test]
fn elapsed_close_budgets_preserve_the_phase_timeout_without_polling_network_work() -> TestResult {
    use futures_util::FutureExt as _;
    use std::io::Read as _;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdTcpStream};

    Runtime::new()?.block_on(async {
        for shutdown_case in 0..3 {
            let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            let mut peer = StdTcpStream::connect(listener.local_addr()?)?;
            peer.set_read_timeout(Some(Duration::from_secs(1)))?;
            let (socket, _) = listener.accept().await?;
            let expired = Instant::now();
            let shutdown = match shutdown_case {
                0 => std::future::pending::<Instant>().boxed_local().shared(),
                1 => std::future::ready(expired).boxed_local().shared(),
                _ => std::future::ready(expired + Duration::from_secs(1))
                    .boxed_local()
                    .shared(),
            };
            let context = CloseContext {
                socket,
                shutdown,
                phase_deadline: Some(expired - CLOSE_TIMEOUT),
            };
            let deadline = if shutdown_case == 1 {
                expired + Duration::from_secs(1)
            } else {
                context.deadline_for(CloseOutcome::AuthenticationTimeout)
            };
            let polled = Cell::new(false);
            let result = context
                .until(deadline, async {
                    polled.set(true);
                    Err(CloseOutcome::TransportError)
                })
                .await;
            assert_eq!(
                completed(result, CloseOutcome::AuthenticationTimeout, "test"),
                CloseOutcome::AuthenticationTimeout
            );
            assert!(!polled.get());
            assert_eq!(peer.read(&mut [0; 1])?, 0);
            listener.close().await?;
        }
        Ok(())
    })
}

#[test]
fn network_work_that_becomes_ready_after_expiry_is_not_polled_again() -> TestResult {
    use futures_util::FutureExt as _;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdTcpStream};

    Runtime::new()?.block_on(async {
        let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let _peer = StdTcpStream::connect(listener.local_addr()?)?;
        let (socket, _) = listener.accept().await?;
        let context = CloseContext {
            socket,
            shutdown: std::future::pending::<Instant>().boxed_local().shared(),
            phase_deadline: None,
        };
        let deadline = Instant::now() + Duration::from_millis(20);
        let ready = Cell::new(false);
        let polls = Cell::new(0);
        let mut close = Box::pin(context.until(
            deadline,
            poll_fn(|_| {
                polls.set(polls.get() + 1);
                if ready.get() {
                    Poll::Ready(Err(CloseOutcome::TransportError))
                } else {
                    Poll::Pending
                }
            }),
        ));
        assert!(poll!(close.as_mut()).is_pending());
        assert_eq!(polls.get(), 1);
        compio::time::sleep(Duration::from_millis(30)).await;
        ready.set(true);
        assert_eq!(
            completed(close.await, CloseOutcome::AuthenticationTimeout, "test"),
            CloseOutcome::AuthenticationTimeout
        );
        assert_eq!(polls.get(), 1);
        listener.close().await?;
        Ok(())
    })
}

#[derive(Clone, Copy)]
enum Tail {
    Eof,
    Error,
    Ready,
    Panic,
}

struct ProbeInput {
    bytes: Cursor<Vec<u8>>,
    reads: Rc<Cell<usize>>,
    parser_polls: Rc<Cell<usize>>,
    tail: Tail,
}

impl tokio::io::AsyncRead for ProbeInput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads.set(self.reads.get() + 1);
        if self.bytes.position() < self.bytes.get_ref().len() as u64 {
            return Pin::new(&mut self.bytes).poll_read(cx, buffer);
        }
        match self.tail {
            Tail::Eof => Poll::Ready(Ok(())),
            Tail::Error => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            Tail::Ready => {
                buffer.put_slice(&[b'x'; 4096]);
                Poll::Ready(Ok(()))
            }
            Tail::Panic => panic!("ineligible close polled its input"),
        }
    }
}

impl AsyncBufRead for ProbeInput {
    fn poll_fill_buf(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        this.parser_polls.set(this.parser_polls.get() + 1);
        if matches!(this.tail, Tail::Panic) {
            panic!("ineligible close polled its parser");
        }
        let position = this.bytes.position() as usize;
        Poll::Ready(Ok(&this.bytes.get_ref()[position..]))
    }

    fn consume(mut self: Pin<&mut Self>, count: usize) {
        let position = self.bytes.position();
        self.bytes.set_position(position + count as u64);
    }
}

type ProbeReader = Reader<GlobalChunkAllocator, ProbeInput>;

fn probe_reader(bytes: Vec<u8>, tail: Tail) -> (ProbeReader, Rc<Cell<usize>>, Rc<Cell<usize>>) {
    let reads = Rc::new(Cell::new(0));
    let parser_polls = Rc::new(Cell::new(0));
    let reader = Reader::new(
        XmppParser::new(
            ProbeInput {
                bytes: Cursor::new(bytes),
                reads: Rc::clone(&reads),
                parser_polls: Rc::clone(&parser_polls),
                tail,
            },
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::MAX,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        ),
        StanzaLimiter::new(NonZeroUsize::MIN, NonZeroUsize::MIN),
    );
    (reader, reads, parser_polls)
}

async fn test_context(
    phase_deadline: Option<Instant>,
    shutdown: ShutdownSignal,
) -> TestResult<(CloseContext, compio::net::TcpListener, std::net::TcpStream)> {
    let listener = crate::c2s::bind(std::net::SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        0,
    )))
    .await?;
    let peer = std::net::TcpStream::connect(listener.local_addr()?)?;
    let (socket, _) = listener.accept().await?;
    Ok((
        CloseContext {
            socket,
            shutdown,
            phase_deadline,
        },
        listener,
        peer,
    ))
}

#[test]
fn plaintext_drain_yields_after_each_positive_read_and_maps_eof_and_errors() -> TestResult {
    Runtime::new()?.block_on(async {
        for tail in [Tail::Eof, Tail::Error] {
            let mut input = ProbeInput {
                bytes: Cursor::new(vec![b'x'; 8192]),
                reads: Rc::new(Cell::new(0)),
                parser_polls: Rc::new(Cell::new(0)),
                tail,
            };
            let reads = Rc::clone(&input.reads);
            let mut drain = Box::pin(drain_plain(&mut input));
            assert!(poll!(drain.as_mut()).is_pending());
            assert_eq!(reads.get(), 1);
            assert!(poll!(drain.as_mut()).is_pending());
            assert_eq!(reads.get(), 2);
            let expected = match tail {
                Tail::Eof => Ok(()),
                _ => Err(CloseOutcome::TransportError),
            };
            assert_eq!(drain.await, expected);
            assert_eq!(reads.get(), 3);
        }
        Ok(())
    })
}

#[test]
fn plaintext_drain_deadline_bounds_always_ready_input_and_stops_polls_after_expiry() -> TestResult {
    use futures_util::FutureExt as _;
    Runtime::new()?.block_on(async {
        for expired in [false, true] {
            let (context, listener, _peer) = test_context(
                None,
                std::future::pending::<Instant>().boxed_local().shared(),
            )
            .await?;
            let mut input = ProbeInput {
                bytes: Cursor::new(Vec::new()),
                reads: Rc::new(Cell::new(0)),
                parser_polls: Rc::new(Cell::new(0)),
                tail: Tail::Ready,
            };
            let reads = Rc::clone(&input.reads);
            let deadline = Instant::now()
                + if expired {
                    Duration::ZERO
                } else {
                    Duration::from_millis(20)
                };
            let started = Instant::now();
            assert_eq!(
                context.until(deadline, drain_plain(&mut input)).await,
                Err(())
            );
            assert!(started.elapsed() < Duration::from_secs(1));
            assert_eq!(reads.get() == 0, expired);
            let polls = reads.get();
            assert_eq!(
                context.until(deadline, drain_plain(&mut input)).await,
                Err(())
            );
            assert_eq!(reads.get(), polls);
            listener.close().await?;
        }
        Ok(())
    })
}

#[test]
fn shutdown_expiry_prevents_another_plaintext_drain_read() -> TestResult {
    use futures_util::FutureExt as _;
    Runtime::new()?.block_on(async {
        let (stop, stopped) = futures_channel::oneshot::channel();
        let (context, listener, _peer) = test_context(
            None,
            async move { stopped.await.unwrap_or_else(|_| Instant::now()) }
                .boxed_local()
                .shared(),
        )
        .await?;
        let mut input = ProbeInput {
            bytes: Cursor::new(Vec::new()),
            reads: Rc::new(Cell::new(0)),
            parser_polls: Rc::new(Cell::new(0)),
            tail: Tail::Ready,
        };
        let reads = Rc::clone(&input.reads);
        let mut drain = Box::pin(context.until(context.deadline(), drain_plain(&mut input)));
        assert!(poll!(drain.as_mut()).is_pending());
        assert_eq!(reads.get(), 1);
        stop.send(Instant::now())
            .map_err(|_| "close stopped listening")?;
        assert_eq!(drain.await, Err(()));
        assert_eq!(reads.get(), 1);
        listener.close().await?;
        Ok(())
    })
}

#[test]
fn failed_plaintext_parser_drains_raw_input_with_original_deadline_and_outcome() -> TestResult {
    use futures_util::FutureExt as _;
    Runtime::new()?.block_on(async {
        for (outcome, tail) in [
            (CloseOutcome::NotWellFormed, Tail::Eof),
            (CloseOutcome::NotWellFormed, Tail::Error),
            (CloseOutcome::NotWellFormed, Tail::Ready),
            (CloseOutcome::AuthenticationTimeout, Tail::Ready),
            (CloseOutcome::AuthenticationTimeout, Tail::Error),
            (CloseOutcome::AuthenticationTimeout, Tail::Eof),
        ] {
            let (mut context, listener, _peer) = test_context(
                None,
                std::future::pending::<Instant>().boxed_local().shared(),
            )
            .await?;
            let (mut input, reads, parser_polls) = probe_reader(
                format!("{HEADER}<message><body></message>trailing bytes").into_bytes(),
                tail,
            );
            input
                .next_event()
                .await
                .map_err(|error| format!("{error:?}"))?;
            assert_eq!(
                input.next_event().await.err(),
                Some(CloseOutcome::NotWellFormed)
            );
            assert!(input.is_failed());
            let polls = parser_polls.get();
            let mut writer = Writer::new(
                Vec::new(),
                "localhost".into(),
                crate::c2s::metrics::C2sWorkerMetrics::detached(),
            );
            writer
                .send_header(&header())
                .await
                .map_err(|error| format!("{error:?}"))?;
            let deadline = Instant::now() + Duration::from_millis(30);
            context.phase_deadline = Some(if outcome.is_phase_timeout() {
                deadline - CLOSE_TIMEOUT
            } else {
                deadline
            });
            assert_eq!(context.deadline_for(outcome), deadline);
            let result = finish_plain(&mut input, &mut writer, outcome.into(), &context).await;
            let expected = match tail {
                Tail::Error if !outcome.is_phase_timeout() => CloseOutcome::TransportError,
                _ => outcome,
            };
            assert_eq!(result, expected);
            assert_eq!(parser_polls.get(), polls);
            assert!(reads.get() > 0);
            if matches!(tail, Tail::Ready) {
                assert!(Instant::now() >= deadline);
                assert!(Instant::now() < deadline + Duration::from_secs(1));
            }
            listener.close().await?;
        }
        Ok(())
    })
}

#[test]
fn peer_footer_plaintext_drain_preserves_outcome_and_deadline() -> TestResult {
    use futures_util::FutureExt as _;
    Runtime::new()?.block_on(async {
        for tail in [Tail::Eof, Tail::Error, Tail::Ready] {
            let (mut input, reads, parser_polls) =
                probe_reader(format!("{HEADER}</stream:stream>").into_bytes(), tail);
            assert!(matches!(
                input
                    .next_event()
                    .await
                    .map_err(|error| format!("{error:?}"))?,
                Some(StreamEvent::StreamStart { .. })
            ));
            assert!(matches!(
                input
                    .next_event()
                    .await
                    .map_err(|error| format!("{error:?}"))?,
                Some(StreamEvent::StreamEnd)
            ));
            assert!(!input.is_failed());
            let polls = parser_polls.get();
            let mut writer = Writer::new(
                Vec::new(),
                "localhost".into(),
                crate::c2s::metrics::C2sWorkerMetrics::detached(),
            );
            writer
                .send_header(&header())
                .await
                .map_err(|error| format!("{error:?}"))?;
            let (mut context, listener, _peer) = test_context(
                None,
                std::future::pending::<Instant>().boxed_local().shared(),
            )
            .await?;
            let deadline = Instant::now() + Duration::from_millis(30);
            context.phase_deadline = Some(deadline);
            assert_eq!(context.deadline_for(CloseOutcome::StreamEnd), deadline);
            let result = finish_plain(
                &mut input,
                &mut writer,
                CloseOutcome::StreamEnd.into(),
                &context,
            )
            .await;
            let expected = match tail {
                Tail::Eof => CloseOutcome::StreamEnd,
                Tail::Error => CloseOutcome::TransportError,
                Tail::Ready => CloseOutcome::ClosingTimeout,
                Tail::Panic => return Err("unexpected probe tail".into()),
            };
            assert_eq!(result, expected);
            assert_eq!(parser_polls.get(), polls);
            assert!(reads.get() > 0);
            let output =
                String::from_utf8(writer.take_output().map_err(|error| format!("{error:?}"))?)?;
            assert_eq!(output.matches("</stream:stream>").count(), 1);
            assert!(!output.contains("<stream:error"));
            if matches!(tail, Tail::Ready) {
                assert!(Instant::now() >= deadline);
                assert!(Instant::now() < deadline + Duration::from_secs(1));
            }
            listener.close().await?;
        }
        Ok(())
    })
}

#[test]
fn unopened_and_disconnected_plaintext_closes_never_poll_input() -> TestResult {
    use futures_util::FutureExt as _;
    Runtime::new()?.block_on(async {
        for outcome in [
            CloseOutcome::AuthenticationTimeout,
            CloseOutcome::Eof,
            CloseOutcome::TransportError,
            CloseOutcome::TlsFailure,
        ] {
            let (context, listener, _peer) = test_context(
                None,
                std::future::pending::<Instant>().boxed_local().shared(),
            )
            .await?;
            let (mut input, _, _) = probe_reader(Vec::new(), Tail::Panic);
            let mut writer = Writer::new(
                Vec::new(),
                "localhost".into(),
                crate::c2s::metrics::C2sWorkerMetrics::detached(),
            );
            if outcome != CloseOutcome::AuthenticationTimeout {
                writer
                    .send_header(&header())
                    .await
                    .map_err(|error| format!("{error:?}"))?;
            }
            assert_eq!(
                finish_plain(&mut input, &mut writer, outcome.into(), &context).await,
                outcome
            );
            listener.close().await?;
        }
        Ok(())
    })
}

#[test]
fn plaintext_drain_ready_after_expiry_is_not_polled_again() -> TestResult {
    use futures_util::FutureExt as _;
    Runtime::new()?.block_on(async {
        let (context, listener, _peer) = test_context(
            None,
            std::future::pending::<Instant>().boxed_local().shared(),
        )
        .await?;
        let mut input = ProbeInput {
            bytes: Cursor::new(Vec::new()),
            reads: Rc::new(Cell::new(0)),
            parser_polls: Rc::new(Cell::new(0)),
            tail: Tail::Ready,
        };
        let reads = Rc::clone(&input.reads);
        let deadline = Instant::now() + Duration::from_millis(20);
        let mut drain = Box::pin(context.until(deadline, drain_plain(&mut input)));
        assert!(poll!(drain.as_mut()).is_pending());
        assert_eq!(reads.get(), 1);
        compio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(drain.await, Err(()));
        assert_eq!(reads.get(), 1);
        listener.close().await?;
        Ok(())
    })
}

struct FlushFailure(Rc<Cell<bool>>);

impl AsyncWrite for FlushFailure {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.0.get() {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("XML close must not finalize the transport")
    }
}

#[test]
fn failed_plaintext_footer_flush_never_polls_input() -> TestResult {
    use futures_util::FutureExt as _;
    Runtime::new()?.block_on(async {
        let (context, listener, _peer) = test_context(
            None,
            std::future::pending::<Instant>().boxed_local().shared(),
        )
        .await?;
        let failure = Rc::new(Cell::new(false));
        let mut writer = Writer::new(
            FlushFailure(Rc::clone(&failure)),
            "localhost".into(),
            crate::c2s::metrics::C2sWorkerMetrics::detached(),
        );
        writer
            .send_header(&header())
            .await
            .map_err(|error| format!("{error:?}"))?;
        failure.set(true);
        let (mut input, reads, parser_polls) = probe_reader(Vec::new(), Tail::Panic);
        assert_eq!(
            finish_plain(&mut input, &mut writer, CloseReason::PeerFooter, &context).await,
            CloseOutcome::TransportError
        );
        assert_eq!(reads.get(), 0);
        assert_eq!(parser_polls.get(), 0);
        listener.close().await?;
        Ok(())
    })
}

#[test]
fn shutdown_interrupts_after_repeated_pending_polls() -> TestResult {
    use futures_util::FutureExt as _;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdTcpStream};

    Runtime::new()?.block_on(async {
        let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let _peer = StdTcpStream::connect(listener.local_addr()?)?;
        let (socket, _) = listener.accept().await?;
        let (stop, stopped) = futures_channel::oneshot::channel();
        let context = CloseContext {
            socket,
            shutdown: async move { stopped.await.unwrap_or_else(|_| Instant::now()) }
                .boxed_local()
                .shared(),
            phase_deadline: None,
        };
        let mut interrupt =
            Box::pin(context.interrupt(std::future::pending::<Result<(), CloseOutcome>>()));
        for _ in 0..100 {
            assert!(poll!(interrupt.as_mut()).is_pending());
        }
        stop.send(Instant::now())
            .map_err(|_| "interrupt stopped listening")?;
        assert_eq!(interrupt.await, Err(CloseOutcome::SystemShutdown));
        context.abort();
        listener.close().await?;
        Ok(())
    })
}
