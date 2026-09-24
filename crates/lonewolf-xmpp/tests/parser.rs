// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io::{self, Cursor};
use std::num::NonZeroUsize;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use compio_io::compat::AsyncReadStream;
use futures_executor::block_on;
use lonewolf_util::arena::{
    ArenaConfig, ArenaError, ChunkAllocator, ChunkAllocatorHandle, GlobalChunkAllocator,
};
use lonewolf_util::pool::{MIN_POOL_SIZE, PoolConfig, PooledChunkAllocator};
use lonewolf_xmpp::parser::{
    MAX_ATTRIBUTES_PER_ELEMENT, MAX_STREAM_HEADER_BYTES, ParseError, Parsed, ParserConfig,
    StreamEvent, XmppParser, compio_reader,
};
use lonewolf_xmpp::stanza::{
    BuildError, CLIENT_NAMESPACE, MAX_ELEMENT_DEPTH, MAX_ELEMENT_NODES, MessageType, NodeRef,
    Stanza, StanzaNamespace, StanzaType,
};
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const OPEN: &str =
    "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>";
const CLOSE: &str = "</stream:stream>";

fn config(limit: usize) -> TestResult<ParserConfig> {
    Ok(ParserConfig {
        max_stanza_bytes: NonZeroUsize::new(limit).ok_or("zero limit")?,
        arena: ArenaConfig::default(),
    })
}

async fn open<R: AsyncBufRead + Unpin, A: ChunkAllocator + Clone>(
    parser: &mut XmppParser<R, A>,
) -> TestResult {
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    Ok(())
}

#[test]
fn opening_stream_exposes_content_namespace() -> TestResult {
    block_on(async {
        for (declaration, expected) in [
            ("xmlns='jabber:client'", "jabber:client"),
            ("xmlns='jabber:server'", "jabber:server"),
            (
                "xmlns='http://etherx.jabber.org/streams'",
                "http://etherx.jabber.org/streams",
            ),
            ("", ""),
        ] {
            let input = format!(
                "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' {declaration}>"
            );
            let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
            let Some(StreamEvent::StreamStart {
                content_namespace, ..
            }) = parser.next_event().await?
            else {
                return Err("expected stream start".into());
            };
            assert_eq!(content_namespace, expected);
        }
        Ok(())
    })
}

async fn stanza<R: AsyncBufRead + Unpin, A: ChunkAllocator + Clone>(
    parser: &mut XmppParser<R, A>,
) -> TestResult<Parsed<Stanza, A>> {
    match parser.next_event().await? {
        Some(StreamEvent::Stanza(stanza)) => Ok(stanza),
        _ => Err("expected stanza".into()),
    }
}

struct Fragmented<'a> {
    bytes: &'a [u8],
    position: usize,
    chunk: usize,
    split: usize,
    pending: bool,
    stall_at_end: bool,
    consumed: Arc<AtomicUsize>,
}

impl<'a> Fragmented<'a> {
    fn new(bytes: &'a [u8], chunk: usize) -> Self {
        Self {
            bytes,
            position: 0,
            chunk,
            split: bytes.len(),
            pending: false,
            stall_at_end: false,
            consumed: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl AsyncBufRead for Fragmented<'_> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.pending {
            this.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if this.stall_at_end && this.position == this.bytes.len() {
            return Poll::Pending;
        }
        let end = if this.position < this.split {
            this.split
        } else {
            this.bytes.len()
        };
        Poll::Ready(Ok(
            &this.bytes[this.position..end.min(this.position.saturating_add(this.chunk))]
        ))
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        this.position += amount;
        this.consumed.store(this.position, Ordering::Relaxed);
        this.pending = true;
    }
}

impl AsyncRead for Fragmented<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let bytes = std::task::ready!(self.as_mut().poll_fill_buf(cx))?;
        let count = bytes.len().min(buf.remaining());
        buf.put_slice(&bytes[..count]);
        self.consume(count);
        Poll::Ready(Ok(()))
    }
}

#[test]
fn parses_every_transport_split_with_namespaces_entities_and_utf8() -> TestResult {
    let input = format!(
        "{OPEN}<message type='chat' from='Alice@EXAMPLE.COM/Desk' id='a&amp;b'><body>hé&amp;<![CDATA[<llo>]]>&#x1F43A;</body><x xmlns='urn:example' flag='a&#x9;b\r\nc'/></message>{CLOSE}"
    );
    for split in 1..input.len() {
        block_on(async {
            let mut source = Fragmented::new(input.as_bytes(), usize::MAX);
            source.split = split;
            let mut parser = XmppParser::new(source, config(4096)?, GlobalChunkAllocator);
            open(&mut parser).await?;
            let parsed = stanza(&mut parser).await?;
            let view = parsed.value().resolve(parsed.arena())?;
            assert_eq!(view.stanza_type(), StanzaType::Message(MessageType::Chat));
            assert_eq!(
                view.from()?.ok_or("from")?.as_str(),
                "alice@example.com/Desk"
            );
            assert_eq!(view.id()?, Some("a&b"));
            assert_eq!(
                view.child("body", CLIENT_NAMESPACE)?
                    .ok_or("body")?
                    .text()?,
                Some("hé&<llo>🐺")
            );
            assert_eq!(
                view.child("x", "urn:example")?
                    .ok_or("x")?
                    .attribute("flag", "")?,
                Some("a\tb c")
            );
            assert!(matches!(
                parser.next_event().await?,
                Some(StreamEvent::StreamEnd)
            ));
            assert!(parser.next_event().await?.is_none());
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn compio_adapter_parses_large_stanzas_without_a_tokio_runtime() -> TestResult {
    for capacity in [1, 16 * 1024] {
        block_on(async {
            let body = "x".repeat(80 * 1024);
            let wire_stanza = format!("<message><body>{body}</body></message>");
            let input = format!("{OPEN}{wire_stanza}<presence/>{CLOSE}");
            let mut source = pin!(AsyncReadStream::with_capacity(
                capacity,
                Cursor::new(input.into_bytes())
            ));
            let mut parser = XmppParser::new(
                compio_reader(source.as_mut()),
                config(wire_stanza.len())?,
                GlobalChunkAllocator,
            );
            open(&mut parser).await?;
            let first = stanza(&mut parser).await?;
            stanza(&mut parser).await?;
            let (value, arena) = first.into_parts();
            let arena = arena.freeze();
            assert_eq!(
                value
                    .resolve(&arena)?
                    .child("body", CLIENT_NAMESPACE)?
                    .ok_or("body")?
                    .text()?,
                Some(body.as_str())
            );
            assert!(matches!(
                parser.next_event().await?,
                Some(StreamEvent::StreamEnd)
            ));
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn size_limit_counts_wire_bytes_per_stanza_and_excludes_stream_whitespace() -> TestResult {
    block_on(async {
        let first = "<message><body>&amp;&#x1F43A;</body></message>";
        let input = format!("{OPEN}{}{first} \r\n{first}{CLOSE}", " ".repeat(100_000));
        let mut parser =
            XmppParser::new(input.as_bytes(), config(first.len())?, GlobalChunkAllocator);
        open(&mut parser).await?;
        stanza(&mut parser).await?;
        stanza(&mut parser).await?;
        assert!(matches!(
            parser.next_event().await?,
            Some(StreamEvent::StreamEnd)
        ));

        let mut parser = XmppParser::new(
            input.as_bytes(),
            config(first.len() - 1)?,
            GlobalChunkAllocator,
        );
        open(&mut parser).await?;
        assert!(
            matches!(parser.next_event().await, Err(ParseError::SizeLimitExceeded { limit }) if limit == first.len() - 1)
        );
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::ParserFailed)
        ));
        Ok(())
    })
}

#[test]
fn rejects_unterminated_tokens_at_the_limit_without_waiting_for_more_input() -> TestResult {
    for prefix in [
        "<message attr='",
        "<message><body>",
        "<message><![CDATA[",
        "<message>&",
        "<message><!--",
    ] {
        block_on(async {
            let input = format!("{OPEN}{prefix}{}", "x".repeat(4096));
            let mut source = Fragmented::new(input.as_bytes(), 17);
            source.stall_at_end = true;
            let consumed = source.consumed.clone();
            let mut parser = XmppParser::new(source, config(4096)?, GlobalChunkAllocator);
            open(&mut parser).await?;
            assert!(matches!(
                parser.next_event().await,
                Err(ParseError::SizeLimitExceeded { limit: 4096 })
            ));
            assert_eq!(consumed.load(Ordering::Relaxed), OPEN.len() + 4096);
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn namespace_scopes_normalize_values_and_preserve_mixed_content() -> TestResult {
    block_on(async {
        let input = "<s:stream xmlns:s='http://etherx.jabber.org/streams' xmlns='jabber:cl&#105;ent' xmlns:p='urn:a&amp;b' xml:lang='en'><message p:id='ext'><body>a<p:x xmlns:p='urn:inner' p:flag='1'/>b<p:y/></body><empty xmlns=''/></message><message xml:lang=''/></s:stream>";
        let mut parser = XmppParser::new(
            Fragmented::new(input.as_bytes(), 1),
            config(4096)?,
            GlobalChunkAllocator,
        );
        open(&mut parser).await?;
        let parsed = stanza(&mut parser).await?;
        let view = parsed.value().resolve(parsed.arena())?;
        assert_eq!(view.lang()?, Some("en"));
        assert_eq!(view.attribute("id", "urn:a&b")?, Some("ext"));
        assert!(view.child("empty", "")?.is_some());
        let body = view.child("body", CLIENT_NAMESPACE)?.ok_or("body")?;
        let nodes = body.children()?.collect::<Result<Vec<_>, _>>()?;
        assert!(matches!(nodes[0], NodeRef::Text("a")));
        let NodeRef::Element(x) = &nodes[1] else {
            return Err("x".into());
        };
        assert_eq!(x.namespace(), "urn:inner");
        assert_eq!(x.attribute("flag", "urn:inner")?, Some("1"));
        assert!(matches!(nodes[2], NodeRef::Text("b")));
        let NodeRef::Element(y) = &nodes[3] else {
            return Err("y".into());
        };
        assert_eq!(y.namespace(), "urn:a&b");
        let parsed = stanza(&mut parser).await?;
        assert_eq!(parsed.value().resolve(parsed.arena())?.lang()?, Some(""));
        Ok(())
    })
}

#[test]
fn restart_preserves_buffered_bytes_and_resets_stream_context() -> TestResult {
    block_on(async {
        let input = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' xmlns:x='urn:old' xml:lang='en'><success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server'><message from='a.example' to='b.example'/><message from='a.example' to='b.example'><x:test/></message>";
        let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        let Some(StreamEvent::Element(success)) = parser.next_event().await? else {
            return Err("success".into());
        };
        assert_eq!(
            success.value().resolve(success.arena())?.namespace(),
            "urn:ietf:params:xml:ns:xmpp-sasl"
        );
        let mut parser = parser.restart()?;
        open(&mut parser).await?;
        let parsed = stanza(&mut parser).await?;
        let view = parsed.value().resolve(parsed.arena())?;
        assert_eq!(view.namespace(), StanzaNamespace::Server);
        assert_eq!(view.lang()?, None);
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::InvalidNamespace)
        ));
        Ok(())
    })
}

#[test]
fn preserves_unread_bytes_for_transport_upgrade() -> TestResult {
    block_on(async {
        let input = format!("{OPEN}<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>TLS-BYTES");
        let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        assert!(matches!(
            parser.next_event().await?,
            Some(StreamEvent::Element(_))
        ));
        assert_eq!(parser.into_inner(), b"TLS-BYTES");
        Ok(())
    })
}

#[test]
fn rejects_malformed_restricted_and_invalid_stanza_input() -> TestResult {
    let cases = [
        "<message><body></message>",
        "<message id='a' id='b'/>",
        "<message xmlns:a='urn:x' xmlns:b='urn:x' a:x='1' b:x='2'/>",
        "<message xmlns:a=''/>",
        "<message xmlns='http://www.w3.org/XML/1998/namespace'/>",
        "<message xmlns:a='http://www.w3.org/XML/1998/namesp&#97;ce'/>",
        "<message xmlns:xml='urn:bad'/>",
        "<message xmlns:xmlns='urn:bad'/>",
        "<message a:flag='1'/>",
        "<message><1bad/></message>",
        "<message><a:b:c/></message>",
        "<message id='<'/>",
        "<message><body>]]></body></message>",
        "<message><body>\0</body></message>",
        "<message><body>&#0;</body></message>",
        "<message><body>&unknown;</body></message>",
        "<message><!--comment--></message>",
        "<message><?pi value?></message>",
        "<!DOCTYPE message><message/>",
        "<?xml version='1.0'?><message/>",
        "<message>invalid top-level text</message>",
        "<message type='invalid'/>",
        "<iq type='get' id='1'/>",
        "<iq type='result'/>",
        "<stream:stream>",
    ];
    for invalid in cases {
        block_on(async {
            let input = format!("{OPEN}{invalid}{CLOSE}");
            let mut parser = XmppParser::new(
                Fragmented::new(input.as_bytes(), 1),
                config(4096)?,
                GlobalChunkAllocator,
            );
            open(&mut parser).await?;
            assert!(parser.next_event().await.is_err(), "accepted {invalid:?}");
            assert!(matches!(
                parser.next_event().await,
                Err(ParseError::ParserFailed)
            ));
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn declaration_bom_encoding_and_unclosed_stream_are_checked() -> TestResult {
    block_on(async {
        let input = format!(
            "\u{feff}<?xml version='1.0' encoding='utf-8' standalone='yes'?>{OPEN}<presence/>{CLOSE}"
        );
        let mut parser = XmppParser::new(
            Fragmented::new(input.as_bytes(), 1),
            config(32)?,
            GlobalChunkAllocator,
        );
        open(&mut parser).await?;
        stanza(&mut parser).await?;
        for declaration in [
            "<?xml version='1.1'?>",
            "<?xml version='1.0' encoding='ISO-8859-1'?>",
            "<?xml encoding='UTF-8' version='1.0'?>",
            "<?xml version='1.0' extra='1'?>",
        ] {
            let input = format!("{declaration}{OPEN}");
            let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
            assert!(parser.next_event().await.is_err());
        }
        let mut parser = XmppParser::new(OPEN.as_bytes(), config(32)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::UnexpectedEof)
        ));
        Ok(())
    })
}

#[test]
fn header_attributes_depth_and_arena_capacity_have_independent_limits() -> TestResult {
    block_on(async {
        let header = format!("<stream:stream id='{}", "a".repeat(MAX_STREAM_HEADER_BYTES));
        let mut parser =
            XmppParser::new(header.as_bytes(), config(usize::MAX)?, GlobalChunkAllocator);
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::SizeLimitExceeded {
                limit: MAX_STREAM_HEADER_BYTES
            })
        ));

        let attributes = (0..=MAX_ATTRIBUTES_PER_ELEMENT)
            .map(|i| format!(" a{i}='v'"))
            .collect::<String>();
        let input = format!("{OPEN}<message{attributes}/>");
        let mut parser = XmppParser::new(input.as_bytes(), config(16384)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::TooManyAttributes)
        ));

        let input = format!(
            "{OPEN}<message>{}{}",
            "<x>".repeat(MAX_ELEMENT_DEPTH),
            "</x>".repeat(MAX_ELEMENT_DEPTH)
        );
        let mut parser = XmppParser::new(input.as_bytes(), config(16384)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::Build(BuildError::TreeLimitExceeded))
        ));

        let input = format!("{OPEN}<message><body>{}</body></message>", "a".repeat(8192));
        let mut limits = config(16384)?;
        limits.arena.max_reserved_bytes = NonZeroUsize::new(4096).ok_or("arena limit")?;
        let mut parser = XmppParser::new(input.as_bytes(), limits, GlobalChunkAllocator);
        open(&mut parser).await?;
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::Build(BuildError::Allocation(
                ArenaError::ArenaLimitExceeded
            )))
        ));
        Ok(())
    })
}

#[test]
fn pooled_arenas_outlive_parser_and_release_partial_allocations_on_error() -> TestResult {
    block_on(async {
        let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
            total_bytes: NonZeroUsize::new(MIN_POOL_SIZE).ok_or("pool size")?,
            ..PoolConfig::default()
        })?);
        let before = pool.stats();
        let input =
            format!("{OPEN}<message><body>retained</body></message><message><body>unfinished");
        let allocator = ChunkAllocatorHandle::new(pool.clone());
        let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, allocator);
        open(&mut parser).await?;
        let parsed = stanza(&mut parser).await?;
        let retained = pool.stats();
        assert!(parser.next_event().await.is_err());
        assert_eq!(
            pool.stats().buckets.map(|b| b.available_chunks),
            retained.buckets.map(|b| b.available_chunks)
        );
        drop(parser);
        let (value, arena) = parsed.into_parts();
        let arena = arena.freeze();
        let shared = arena.clone();
        drop(arena);
        assert_eq!(
            value
                .resolve(&shared)?
                .child("body", CLIENT_NAMESPACE)?
                .ok_or("body")?
                .text()?,
            Some("retained")
        );
        drop(shared);
        let after = pool.stats();
        assert_eq!(
            after.buckets.map(|b| b.available_chunks),
            before.buckets.map(|b| b.available_chunks)
        );
        assert_eq!(after.heap_allocation_count, before.heap_allocation_count);
        Ok(())
    })
}

#[test]
fn cancelling_mid_token_releases_the_arena_and_prevents_reentry() -> TestResult {
    block_on(async {
        let input = format!("{OPEN}<message><body>partial");
        let mut source = Fragmented::new(input.as_bytes(), usize::MAX);
        source.stall_at_end = true;
        let consumed = source.consumed.clone();
        let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
            total_bytes: NonZeroUsize::new(MIN_POOL_SIZE).ok_or("pool size")?,
            ..PoolConfig::default()
        })?);
        let mut parser = XmppParser::new(
            source,
            config(4096)?,
            ChunkAllocatorHandle::new(pool.clone()),
        );
        open(&mut parser).await?;
        let before = pool.stats().buckets.map(|b| b.available_chunks);
        {
            let mut future = pin!(parser.next_event());
            let mut context = Context::from_waker(Waker::noop());
            for _ in 0..20 {
                assert!(future.as_mut().poll(&mut context).is_pending());
            }
            assert_eq!(consumed.load(Ordering::Relaxed), input.len());
            assert_ne!(pool.stats().buckets.map(|b| b.available_chunks), before);
        }
        assert_eq!(pool.stats().buckets.map(|b| b.available_chunks), before);
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::ParserFailed)
        ));
        Ok(())
    })
}

#[test]
fn stream_footer_does_not_consume_the_stanza_budget() -> TestResult {
    for chunk in [1, usize::MAX] {
        block_on(async {
            let input = format!("{OPEN}<presence/>{CLOSE}");
            let mut parser = XmppParser::new(
                Fragmented::new(input.as_bytes(), chunk),
                config("<presence/>".len())?,
                GlobalChunkAllocator,
            );
            open(&mut parser).await?;
            stanza(&mut parser).await?;
            assert!(matches!(
                parser.next_event().await?,
                Some(StreamEvent::StreamEnd)
            ));
            let input = format!("{OPEN}{CLOSE}");
            let mut parser = XmppParser::new(
                Fragmented::new(input.as_bytes(), chunk),
                config(1)?,
                GlobalChunkAllocator,
            );
            open(&mut parser).await?;
            assert!(matches!(
                parser.next_event().await?,
                Some(StreamEvent::StreamEnd)
            ));
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn declaration_position_and_bom_are_independent_of_fragmentation() -> TestResult {
    for chunk in [1, usize::MAX] {
        block_on(async {
            for prefix in [
                "\u{feff}\u{feff}",
                "\u{feff} \u{feff}",
                " \u{feff}",
                " <?xml version='1.0'?>",
                "\u{feff} <?xml version='1.0'?>",
            ] {
                let input = format!("{prefix}{OPEN}");
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                assert!(parser.next_event().await.is_err(), "accepted {prefix:?}");
            }
            for prefix in ["\u{feff} \r\n", " \r\n"] {
                let input = format!("{prefix}{OPEN}");
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                open(&mut parser).await?;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn node_limit_is_enforced_before_the_tree_is_complete() -> TestResult {
    block_on(async {
        for children in [MAX_ELEMENT_NODES - 1, MAX_ELEMENT_NODES] {
            let input = format!("{OPEN}<message>{}</message>", "<x/>".repeat(children));
            let mut limits = config(input.len())?;
            limits.arena.max_reserved_bytes =
                NonZeroUsize::new(32 * 1024 * 1024).ok_or("arena limit")?;
            let mut parser = XmppParser::new(input.as_bytes(), limits, GlobalChunkAllocator);
            open(&mut parser).await?;
            if children < MAX_ELEMENT_NODES {
                stanza(&mut parser).await?;
            } else {
                assert!(matches!(
                    parser.next_event().await,
                    Err(ParseError::Build(BuildError::TreeLimitExceeded))
                ));
            }
        }
        Ok(())
    })
}
