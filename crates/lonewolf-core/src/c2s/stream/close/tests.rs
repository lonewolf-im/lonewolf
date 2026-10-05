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
