// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::error::Error;
use std::future::Future;
use std::io::Cursor;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use lonewolf_util::arena::ArenaConfig;
use lonewolf_util::pool::{PoolConfig, PooledChunkAllocator};
use lonewolf_xmpp::parser::{ParseError, ParserConfig, StreamEvent, XmppParser};

use crate::test_allocator::allocations_during;
use crate::xml_stream::limiter::StanzaLimiter;
use crate::xml_stream::reader::{ReadMode, ReadObserver, XmlReader};

struct Observer;
impl ReadObserver for Observer {}

type TestResult = Result<(), Box<dyn Error>>;
const HEADER: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>";

#[test]
fn warmed_reader_does_not_allocate_per_event() -> TestResult {
    let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
        total_bytes: NonZeroUsize::new(8 * 1024 * 1024).ok_or("invalid pool size")?,
        shards_per_bucket: NonZeroUsize::MIN,
    })?);
    let input = format!("{HEADER}{}</stream:stream>", "<message/>".repeat(40));
    let mut reader = XmlReader::new(
        XmppParser::new(
            Cursor::new(input.into_bytes()),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(10_000).ok_or("invalid stanza size")?,
                arena: ArenaConfig::default(),
            },
            pool,
        ),
        StanzaLimiter::new(
            NonZeroUsize::MIN,
            NonZeroUsize::new(1000).ok_or("invalid burst")?,
        ),
        Rc::new(Cell::new(ReadMode::Open)),
        Observer,
    );
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        pin!(reader.read_event()).poll(&mut cx),
        Poll::Ready(Ok(Some(StreamEvent::StreamStart { .. })))
    ));
    for _ in 0..8 {
        assert!(matches!(
            pin!(reader.read_event()).poll(&mut cx),
            Poll::Ready(Ok(Some(StreamEvent::Stanza(_))))
        ));
    }
    let allocations = allocations_during(|| {
        for _ in 0..32 {
            assert!(matches!(
                pin!(reader.read_event()).poll(&mut cx),
                Poll::Ready(Ok(Some(StreamEvent::Stanza(_))))
            ));
        }
    });
    assert_eq!(allocations, 0);
    Ok(())
}

struct GatedInput {
    input: Cursor<Vec<u8>>,
    open: Rc<Cell<bool>>,
    reads: Rc<Cell<usize>>,
}

impl tokio::io::AsyncRead for GatedInput {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.open.get() {
            return Poll::Pending;
        }
        std::pin::Pin::new(&mut self.input).poll_read(cx, output)
    }
}

impl tokio::io::AsyncBufRead for GatedInput {
    fn poll_fill_buf(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        self.reads.set(self.reads.get() + 1);
        if !self.open.get() {
            return Poll::Pending;
        }
        std::pin::Pin::new(&mut self.get_mut().input).poll_fill_buf(cx)
    }

    fn consume(mut self: std::pin::Pin<&mut Self>, amount: usize) {
        std::pin::Pin::new(&mut self.input).consume(amount);
    }
}

type TestReader = XmlReader<lonewolf_util::arena::GlobalChunkAllocator, GatedInput, Observer>;

fn gated_reader(input: &str, open: Rc<Cell<bool>>, reads: Rc<Cell<usize>>) -> TestReader {
    XmlReader::new(
        XmppParser::new(
            GatedInput {
                input: Cursor::new(input.as_bytes().to_vec()),
                open,
                reads,
            },
            ParserConfig {
                max_stanza_bytes: const { NonZeroUsize::new(10_000).unwrap() },
                arena: ArenaConfig::default(),
            },
            lonewolf_util::arena::GlobalChunkAllocator,
        ),
        StanzaLimiter::new(NonZeroUsize::MIN, NonZeroUsize::MIN),
        Rc::new(Cell::new(ReadMode::Open)),
        Observer,
    )
}

#[test]
fn unpolled_read_and_idle_failed_restart_extraction_do_not_advance_input() -> TestResult {
    let reads = Rc::new(Cell::new(0));
    let mut reader = gated_reader(HEADER, Rc::new(Cell::new(true)), Rc::clone(&reads));
    drop(reader.read_event());
    assert!(reader.has_input());
    assert!(reader.has_ready_state());
    let allocations = allocations_during(|| {
        assert!(matches!(reader.restart(), Err(ParseError::UnexpectedEvent)));
    });
    assert_eq!(allocations, 0);
    assert!(reader.is_failed());
    assert!(reader.has_ready_state());
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok((parser, limiter, _))) = pin!(reader.take_parts()).poll(&mut cx) else {
        return Err("idle extraction did not complete".into());
    };
    assert_eq!(reads.get(), 0);
    assert_eq!(parser.into_inner().input.position(), 0);
    assert_eq!(limiter.available(), 1);
    assert!(!reader.has_input());
    assert!(!reader.has_ready_state());
    assert!(matches!(reader.restart(), Err(ParseError::ParserFailed)));
    assert!(matches!(
        pin!(reader.read_event()).poll(&mut cx),
        Poll::Ready(Err(ParseError::ParserFailed))
    ));
    Ok(())
}

#[test]
fn pending_restart_preserves_failed_flag_and_resumes_the_same_read() -> TestResult {
    let open = Rc::new(Cell::new(false));
    let mut reader = gated_reader(
        &format!("{HEADER}<message/>"),
        Rc::clone(&open),
        Rc::new(Cell::new(0)),
    );
    let mut cx = Context::from_waker(Waker::noop());
    assert!(pin!(reader.read_event()).poll(&mut cx).is_pending());
    assert!(reader.has_input());
    assert!(!reader.has_ready_state());
    assert!(!reader.is_failed());
    assert!(matches!(reader.restart(), Err(ParseError::ParserFailed)));
    assert!(!reader.is_failed());
    assert!(!reader.has_ready_state());
    open.set(true);
    assert!(matches!(
        pin!(reader.read_event()).poll(&mut cx),
        Poll::Ready(Ok(Some(StreamEvent::StreamStart { .. })))
    ));
    assert!(reader.has_ready_state());
    assert!(!reader.is_failed());
    assert!(matches!(
        pin!(reader.read_event()).poll(&mut cx),
        Poll::Ready(Ok(Some(StreamEvent::Stanza(_))))
    ));
    Ok(())
}

#[test]
fn reads_continue_after_a_rejected_idle_restart() {
    let mut reader = gated_reader(
        &format!("{HEADER}<message/>"),
        Rc::new(Cell::new(true)),
        Rc::new(Cell::new(0)),
    );
    assert!(matches!(reader.restart(), Err(ParseError::UnexpectedEvent)));
    assert!(reader.is_failed());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        pin!(reader.read_event()).poll(&mut cx),
        Poll::Ready(Ok(Some(StreamEvent::StreamStart { .. })))
    ));
    assert!(!reader.is_failed());
    assert!(matches!(
        pin!(reader.read_event()).poll(&mut cx),
        Poll::Ready(Ok(Some(StreamEvent::Stanza(_))))
    ));
}

#[test]
fn terminal_reads_retain_input_without_replacement_allocations() -> TestResult {
    for malformed in [false, true] {
        let ending = if malformed {
            "<message></presence>"
        } else {
            "</stream:stream>"
        };
        let mut reader = gated_reader(
            &format!("{HEADER}{ending}"),
            Rc::new(Cell::new(true)),
            Rc::new(Cell::new(0)),
        );
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            pin!(reader.read_event()).poll(&mut cx),
            Poll::Ready(Ok(Some(StreamEvent::StreamStart { .. })))
        ));
        if malformed {
            assert!(matches!(
                pin!(reader.read_event()).poll(&mut cx),
                Poll::Ready(Err(_))
            ));
        } else {
            assert!(matches!(
                pin!(reader.read_event()).poll(&mut cx),
                Poll::Ready(Ok(Some(StreamEvent::StreamEnd)))
            ));
            assert!(matches!(
                pin!(reader.read_event()).poll(&mut cx),
                Poll::Ready(Ok(None))
            ));
        }
        assert!(reader.has_input());
        assert!(reader.has_ready_state());
        let allocations = allocations_during(|| {
            for _ in 0..32 {
                let result = pin!(reader.read_event()).poll(&mut cx);
                if malformed {
                    assert!(matches!(result, Poll::Ready(Err(ParseError::ParserFailed))));
                } else {
                    assert!(matches!(result, Poll::Ready(Ok(None))));
                }
            }
        });
        assert_eq!(allocations, 0);
        assert!(matches!(
            pin!(reader.take_parts()).poll(&mut cx),
            Poll::Ready(Ok(_))
        ));
        assert!(!reader.has_input());
    }
    Ok(())
}
