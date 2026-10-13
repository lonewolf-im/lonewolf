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
        let mut writer = Writer::new(Vec::new(), "localhost".into());
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
        let mut input = reader(HEADER.into())?;
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
            let mut input = reader(HEADER.into())?;
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
        let mut input = reader(format!("{HEADER}</stream:stream>"))?;
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
        assert!(poll!(close.as_mut()).is_pending());
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
        for expired_shutdown in [false, true] {
            let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            let mut peer = StdTcpStream::connect(listener.local_addr()?)?;
            peer.set_read_timeout(Some(Duration::from_secs(1)))?;
            let (socket, _) = listener.accept().await?;
            let expired = Instant::now();
            let shutdown = if expired_shutdown {
                std::future::ready(expired).boxed_local().shared()
            } else {
                std::future::pending::<Instant>().boxed_local().shared()
            };
            let context = CloseContext {
                socket,
                shutdown,
                phase_deadline: Some(expired - CLOSE_TIMEOUT),
            };
            let deadline = if expired_shutdown {
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
