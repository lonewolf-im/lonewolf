// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::error::Error;
use std::future::{Future, poll_fn};
use std::io::{self, Cursor};
use std::num::NonZeroUsize;
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::task::{Context, Poll};

use compio::runtime::Runtime;
use futures_util::io::AsyncWrite;
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::StanzaNamespace;
use lonewolf_xmpp::stream::StreamErrorCondition;

use super::StreamWriter;
use crate::xml_stream::{STREAM_FOOTER, stream_error_xml};

type TestResult = Result<(), Box<dyn Error>>;

const HEADER: &str =
    "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server'>";

#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    blocked: bool,
    failing: bool,
}

#[derive(Clone, Default)]
struct Output(Rc<RefCell<State>>);

impl Output {
    fn block(&self) {
        self.0.borrow_mut().blocked = true;
    }

    fn unblock(&self) {
        self.0.borrow_mut().blocked = false;
    }

    fn fail(&self) {
        self.0.borrow_mut().failing = true;
    }

    fn text(&self) -> Result<String, Box<dyn Error>> {
        Ok(String::from_utf8(self.0.borrow().bytes.clone())?)
    }

    fn ready(&self) -> Poll<io::Result<()>> {
        let state = self.0.borrow();
        if state.failing {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else if state.blocked {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for Output {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        std::task::ready!(self.ready())?;
        self.0.borrow_mut().bytes.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ready()
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ready()
    }
}

async fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
    let mut future = pin!(future);
    poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}

#[test]
fn unopened_stream_gets_no_error_or_footer() -> TestResult {
    Runtime::new()?.block_on(async {
        let output = Output::default();
        let mut writer = StreamWriter::new(output.clone(), 64);
        assert!(writer.needs_header());
        assert!(!writer.close(Some(StreamErrorCondition::Conflict)).await?);
        assert!(writer.needs_header());
        assert_eq!(output.text()?, "");
        Ok(())
    })
}

#[test]
fn close_writes_one_error_or_footer() -> TestResult {
    Runtime::new()?.block_on(async {
        for condition in [None, Some(StreamErrorCondition::HostUnknown)] {
            let output = Output::default();
            let mut writer = StreamWriter::new(output.clone(), 4_096);
            writer.send_header(HEADER).await?;
            assert!(writer.close(condition).await?);
            assert!(!writer.close(Some(StreamErrorCondition::Conflict)).await?);
            assert!(!writer.close(None).await?);
            assert!(!writer.needs_header());
            assert!(!writer.is_open());
            let ending = condition.map_or_else(|| STREAM_FOOTER.to_owned(), stream_error_xml);
            assert_eq!(output.text()?, format!("{HEADER}{ending}"));
        }
        Ok(())
    })
}

#[test]
fn cancelled_header_flush_still_opens_the_stream() -> TestResult {
    Runtime::new()?.block_on(async {
        let output = Output::default();
        let mut writer = StreamWriter::new(output.clone(), 4_096);
        output.block();
        assert!(poll_once(writer.send_header(HEADER)).await.is_pending());
        assert!(writer.is_open());
        assert!(writer.is_intact());
        assert!(!writer.needs_header());
        output.unblock();
        assert!(
            writer
                .close(Some(StreamErrorCondition::SystemShutdown))
                .await?
        );
        assert_eq!(
            output.text()?,
            format!(
                "{HEADER}{}",
                stream_error_xml(StreamErrorCondition::SystemShutdown)
            )
        );
        Ok(())
    })
}

#[test]
fn cancelled_element_flush_still_allows_a_stream_error() -> TestResult {
    Runtime::new()?.block_on(async {
        let output = Output::default();
        let mut writer = StreamWriter::new(output.clone(), 4_096);
        writer.send_header(HEADER).await?;
        output.block();
        assert!(
            poll_once(writer.send("<stream:features/>"))
                .await
                .is_pending()
        );
        assert!(writer.is_intact());
        output.unblock();
        assert!(writer.close(None).await?);
        assert_eq!(
            output.text()?,
            format!("{HEADER}<stream:features/>{STREAM_FOOTER}")
        );
        Ok(())
    })
}

#[test]
fn torn_element_suppresses_close_xml() -> TestResult {
    Runtime::new()?.block_on(async {
        let output = Output::default();
        let mut writer = StreamWriter::new(output.clone(), 4);
        writer.send_header(HEADER).await?;
        output.block();
        assert!(
            poll_once(writer.send("<stream:features><bind/></stream:features>"))
                .await
                .is_pending()
        );
        assert!(!writer.is_intact());
        output.unblock();
        assert!(!writer.close(Some(StreamErrorCondition::Conflict)).await?);
        assert_eq!(output.text()?, HEADER);
        Ok(())
    })
}

#[test]
fn torn_stanza_suppresses_close_xml() -> TestResult {
    Runtime::new()?.block_on(async {
        let input = format!(
            "{HEADER}<message from='a@peer.test' to='b@local.test'><body>{}</body></message>",
            "x".repeat(64)
        );
        let mut parser = XmppParser::new(
            Cursor::new(input.into_bytes()),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(10_000).ok_or("stanza size")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        );
        assert!(matches!(
            parser.next_event().await?,
            Some(StreamEvent::StreamStart { .. })
        ));
        let Some(StreamEvent::Stanza(parsed)) = parser.next_event().await? else {
            return Err("stanza".into());
        };
        let stanza = parsed.value().resolve(parsed.arena())?;
        let output = Output::default();
        let mut writer = StreamWriter::new(output.clone(), 16);
        writer.send_header(HEADER).await?;
        output.block();
        assert!(
            poll_once(writer.write_stanza(&stanza, StanzaNamespace::Server))
                .await
                .is_pending()
        );
        assert!(!writer.is_intact());
        output.unblock();
        assert!(!writer.close(None).await?);
        assert_eq!(output.text()?, HEADER);
        Ok(())
    })
}

#[test]
fn cancelled_protocol_switch_suppresses_close_xml() -> TestResult {
    Runtime::new()?.block_on(async {
        let output = Output::default();
        let mut writer = StreamWriter::new(output.clone(), 4_096);
        writer.send_header(HEADER).await?;
        output.block();
        assert!(
            poll_once(writer.send_protocol_switch("<proceed/>"))
                .await
                .is_pending()
        );
        assert!(!writer.is_intact());
        output.unblock();
        assert!(!writer.close(Some(StreamErrorCondition::Conflict)).await?);
        assert_eq!(output.text()?, HEADER);
        Ok(())
    })
}

#[test]
fn failed_flush_suppresses_close_xml() -> TestResult {
    Runtime::new()?.block_on(async {
        let output = Output::default();
        let mut writer = StreamWriter::new(output.clone(), 4_096);
        writer.send_header(HEADER).await?;
        output.fail();
        assert!(writer.send("<stream:features/>").await.is_err());
        assert!(!writer.is_intact());
        assert!(!writer.close(None).await?);
        Ok(())
    })
}

#[test]
fn restart_requires_a_new_header() -> TestResult {
    Runtime::new()?.block_on(async {
        let output = Output::default();
        let mut writer = StreamWriter::new(output.clone(), 4_096);
        writer.send_header(HEADER).await?;
        writer.send_protocol_switch("<success/>").await?;
        writer.restart();
        assert!(writer.needs_header());
        assert!(!writer.close(None).await?);
        writer.send_header(HEADER).await?;
        assert!(writer.close(None).await?);
        assert_eq!(
            output.text()?,
            format!("{HEADER}<success/>{HEADER}{STREAM_FOOTER}")
        );
        Ok(())
    })
}

#[test]
fn restart_after_close_keeps_the_stream_ended() -> TestResult {
    Runtime::new()?.block_on(async {
        let output = Output::default();
        let mut writer = StreamWriter::new(output.clone(), 4_096);
        writer.send_header(HEADER).await?;
        assert!(writer.close(None).await?);
        writer.restart();
        assert!(!writer.needs_header());
        assert!(!writer.close(None).await?);
        Ok(())
    })
}
