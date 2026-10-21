// SPDX-License-Identifier: Apache-2.0

use std::alloc::Layout;
use std::future::Future;
use std::io::{self, Cursor};
use std::num::NonZeroUsize;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use crate::parser::{
    MAX_ATTRIBUTES_PER_ELEMENT, MAX_STREAM_HEADER_BYTES, ParseError, Parsed, ParserConfig,
    StreamEvent, XmppParser, compio_reader, parse_element,
};
use crate::stanza::{
    BuildError, CLIENT_NAMESPACE, Element, ElementRef, MAX_ELEMENT_DEPTH, MAX_ELEMENT_NODES,
    MessageType, NodeRef, Stanza, StanzaErrorCondition, StanzaNamespace, StanzaRejection,
    StanzaType, XML_NAMESPACE,
};
use compio_io::compat::AsyncReadStream;
use futures_executor::block_on;
use lonewolf_util::arena::{
    AllocationError, Arena, ArenaConfig, ArenaError, ArenaRead, Chunk, ChunkAllocator,
    ChunkAllocatorHandle, GlobalChunkAllocator, HandleError,
};
use lonewolf_util::pool::{MIN_POOL_SIZE, PoolConfig, PooledChunkAllocator};
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

#[derive(Debug, PartialEq)]
enum ElementSnapshot {
    Element {
        name: String,
        namespace: String,
        attributes: Vec<(String, String, String)>,
        children: Vec<ElementSnapshot>,
    },
    Text(String),
}

fn element_snapshot(element: &ElementRef<'_, impl ArenaRead>) -> TestResult<ElementSnapshot> {
    let attributes = element
        .attributes()?
        .map(|attribute| {
            let attribute = attribute?;
            Ok((
                attribute.name.to_owned(),
                attribute.namespace.to_owned(),
                attribute.value.to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, HandleError>>()?;
    let children = element
        .children()?
        .map(|node| match node? {
            NodeRef::Element(child) => element_snapshot(&child),
            NodeRef::Text(text) => Ok(ElementSnapshot::Text(text.to_owned())),
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok(ElementSnapshot::Element {
        name: element.name().to_owned(),
        namespace: element.namespace().to_owned(),
        attributes,
        children,
    })
}

async fn standalone_round_trip(
    xml: &[u8],
) -> TestResult<(Parsed<Element, GlobalChunkAllocator>, String)> {
    let parsed = parse_element(xml, config(16384)?, GlobalChunkAllocator).await?;
    let original = parsed.value().resolve(parsed.arena())?;
    let expected = element_snapshot(&original)?;
    let mut serialized = String::new();
    original.write_xml(&mut serialized)?;
    let replay = parse_element(serialized.as_bytes(), config(16384)?, GlobalChunkAllocator).await?;
    let replay = replay.value().resolve(replay.arena())?;
    assert_eq!(element_snapshot(&replay)?, expected);
    let mut second = String::new();
    replay.write_xml(&mut second)?;
    let second = parse_element(second.as_bytes(), config(16384)?, GlobalChunkAllocator).await?;
    assert_eq!(
        element_snapshot(&second.value().resolve(second.arena())?)?,
        expected
    );
    let mut asynchronous = futures_util::io::Cursor::new(Vec::new());
    original.write_xml_async(&mut asynchronous).await?;
    assert_eq!(asynchronous.into_inner(), serialized.as_bytes());
    let mut copied_arena = Arena::try_new(ArenaConfig::default())?;
    let copied = original.clone_in(&mut copied_arena)?;
    assert_eq!(element_snapshot(&copied.resolve(&copied_arena)?)?, expected);
    Ok((parsed, serialized))
}

#[test]
fn standalone_elements_preserve_expanded_names_and_mixed_child_order() -> TestResult {
    block_on(async {
        for input in [
            "<x/>",
            " \t\r\n<vCard xmlns='vcard-temp'><FN>Zoë &amp; 李</FN><N><GIVEN>Zoë</GIVEN></N></vCard>\r\n\t ",
            "<x attr='&quot;&amp;&lt;&gt;'>a&amp;&lt;&gt;<![CDATA[b<c>]]><y/>tail</x>",
            "<x xmlns='urn:root' xmlns:p='urn:outer' p:attr='value'><y xmlns=''/><p:z xmlns:p='urn:inner' p:attr='inner'/><p:z/></x>",
        ] {
            standalone_round_trip(input.as_bytes()).await?;
        }
        let (parsed, _) = standalone_round_trip(b"<x>first<y/>second<z/>third</x>").await?;
        let root = parsed.value().resolve(parsed.arena())?;
        assert_eq!(root.name(), "x");
        assert_eq!(root.namespace(), "");
        let nodes = root.children()?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(nodes.len(), 5);
        assert!(matches!(nodes[0], NodeRef::Text("first")));
        assert!(matches!(&nodes[1], NodeRef::Element(child) if child.name() == "y"));
        assert!(matches!(nodes[2], NodeRef::Text("second")));
        assert!(matches!(&nodes[3], NodeRef::Element(child) if child.name() == "z"));
        assert!(matches!(nodes[4], NodeRef::Text("third")));

        let (text, _) = standalone_round_trip(b"<x>a&lt;b&gt;c</x>").await?;
        let (cdata, _) = standalone_round_trip(b"<x><![CDATA[a<b>c]]></x>").await?;
        assert_eq!(
            element_snapshot(&text.value().resolve(text.arena())?)?,
            element_snapshot(&cdata.value().resolve(cdata.arena())?)?
        );
        Ok(())
    })
}

#[test]
fn standalone_namespaces_preserve_qname_values_and_scoped_bindings() -> TestResult {
    block_on(async {
        let input = b"<vCard xmlns='vcard-temp' xmlns:p='urn:types' xmlns:a='urn:attributes' a:type='p:Root'>p:Text<reset xmlns=''/><p:child xmlns:p='urn:inner' a:type='p:Inner'/><p:child/></vCard>";
        let (parsed, serialized) = standalone_round_trip(input).await?;
        assert_root_namespace_binding(&serialized, "p", Some("urn:types"))?;
        assert_root_namespace_binding(&serialized, "a", Some("urn:attributes"))?;
        assert_root_namespace_binding(&serialized, "stream", None)?;
        let root = parsed.value().resolve(parsed.arena())?;
        assert_eq!(root.attribute("type", "urn:attributes")?, Some("p:Root"));
        assert_eq!(root.child("reset", "")?.ok_or("reset")?.namespace(), "");
        assert_eq!(
            root.child("child", "urn:inner")?
                .ok_or("rebound child")?
                .attribute("type", "urn:attributes")?,
            Some("p:Inner")
        );
        assert!(root.child("child", "urn:types")?.is_some());
        Ok(())
    })
}

#[test]
fn standalone_normalization_survives_serialization_without_value_changes() -> TestResult {
    block_on(async {
        let input = "<vCard xmlns='vcard-temp' xmlns:f='urn:foreign' literal='a\tb\nc\rd\r\ne' references='a&#9;b&#10;c&#13;d' xml:lang='' xml:space='preserve'>a\rb\r\nc&#13;d<f:MiXeD f:CaSe='e\u{301}'>e\u{301}<nested xml:lang='es' xml:space='default'><reset xml:lang='' xml:space='preserve'/></nested></f:MiXeD></vCard>";
        let (parsed, serialized) = standalone_round_trip(input.as_bytes()).await?;
        let root = parsed.value().resolve(parsed.arena())?;
        assert_eq!(root.attribute("literal", "")?, Some("a b c d e"));
        assert_eq!(root.attribute("references", "")?, Some("a\tb\nc\rd"));
        assert_eq!(root.attribute("lang", XML_NAMESPACE)?, Some(""));
        assert_eq!(root.attribute("space", XML_NAMESPACE)?, Some("preserve"));
        let first = root.children()?.next().ok_or("text")??;
        assert!(matches!(first, NodeRef::Text("a\nb\nc\rd")));
        let foreign = root.child("MiXeD", "urn:foreign")?.ok_or("foreign")?;
        assert_eq!(foreign.attribute("CaSe", "urn:foreign")?, Some("e\u{301}"));
        assert!(foreign.attribute("case", "urn:foreign")?.is_none());
        let nested = foreign.child("nested", "vcard-temp")?.ok_or("nested")?;
        assert_eq!(nested.attribute("lang", XML_NAMESPACE)?, Some("es"));
        assert_eq!(nested.attribute("space", XML_NAMESPACE)?, Some("default"));
        let reset = nested.child("reset", "vcard-temp")?.ok_or("reset")?;
        assert_eq!(reset.attribute("lang", XML_NAMESPACE)?, Some(""));
        assert_eq!(reset.attribute("space", XML_NAMESPACE)?, Some("preserve"));
        assert!(serialized.contains("&#x9;"));
        assert!(serialized.contains("&#xA;"));
        assert!(serialized.contains("&#xD;"));
        let absent = parse_element(b"<x><y/></x>", config(4096)?, GlobalChunkAllocator).await?;
        let absent = absent.value().resolve(absent.arena())?;
        assert_eq!(absent.attribute("lang", XML_NAMESPACE)?, None);
        assert_eq!(absent.attribute("space", XML_NAMESPACE)?, None);
        for value in ["", "invalid", "default", "preserve", "Preserve"] {
            let input = format!("<x xml:space='{value}'><y/></x>");
            let (parsed, _) = standalone_round_trip(input.as_bytes()).await?;
            let root = parsed.value().resolve(parsed.arena())?;
            assert_eq!(root.attribute("space", XML_NAMESPACE)?, Some(value));
            assert_eq!(root.attribute("lang", XML_NAMESPACE)?, None);
            let child = root.child("y", "")?.ok_or("child")?;
            assert_eq!(child.attribute("lang", XML_NAMESPACE)?, None);
            assert_eq!(child.attribute("space", XML_NAMESPACE)?, None);
        }
        Ok(())
    })
}

#[test]
fn standalone_rejects_empty_documents_and_non_whitespace_remainders() -> TestResult {
    block_on(async {
        for input in [b"".as_slice(), b" \t\r\n"] {
            assert!(matches!(
                parse_element(input, config(4096)?, GlobalChunkAllocator).await,
                Err(ParseError::UnexpectedEof)
            ));
        }
        for suffix in [
            "<y/>",
            "text",
            "</stream:stream>",
            "</stream:stream>junk",
            "<?xml version='1.0'?>",
            "<!--comment-->",
            "<?pi value?>",
            "<!DOCTYPE x>",
            "&#32;",
            "\u{a0}",
        ] {
            let input = format!("<x/> \t\r\n{suffix}");
            assert!(
                matches!(
                    parse_element(input.as_bytes(), config(4096)?, GlobalChunkAllocator).await,
                    Err(ParseError::UnexpectedEvent)
                ),
                "suffix={suffix:?}"
            );
        }
        Ok(())
    })
}

#[test]
fn standalone_enforces_restricted_xml_namespaces_and_root_kind() -> TestResult {
    block_on(async {
        for input in [
            "<?xml version='1.0'?><x/>",
            "<?xml version='1.1'?><x/>",
            "<!--comment--><x/>",
            "<?pi value?><x/>",
            "<!DOCTYPE x><x/>",
            "<!DOCTYPE x [<!ENTITY e 'expanded'>]><x>&e;</x>",
            "<x>&unknown;</x>",
            "<x><!--comment--></x>",
            "<x><?pi value?></x>",
            "<p:x/>",
            "<stream:x/>",
            "<x stream:attr='value'/>",
            "<x xmlns:a='urn:a' xmlns:b='urn:a' a:id='1' b:id='2'/>",
            "<x></y>",
            "<x>",
            "text<x/>",
            "<message xmlns='jabber:client'/>",
            "<presence xmlns='jabber:client'/>",
            "<iq xmlns='jabber:client' type='get' id='1'><query/></iq>",
            "<iq xmlns='jabber:client'/>",
            "<message xmlns='jabber:server'/>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams'>",
            "<stream xmlns='http://etherx.jabber.org/streams'/>",
            "</stream:stream>",
        ] {
            assert!(
                parse_element(input.as_bytes(), config(4096)?, GlobalChunkAllocator)
                    .await
                    .is_err(),
                "input={input:?}"
            );
        }
        for input in [b"<x>\xff</x>".as_slice(), b"<x attr='\xff'/>", b"<\xff/>"] {
            assert!(matches!(
                parse_element(input, config(4096)?, GlobalChunkAllocator).await,
                Err(ParseError::UnsupportedEncoding)
            ));
        }
        assert!(matches!(
            parse_element(b"<stream:x/>", config(4096)?, GlobalChunkAllocator).await,
            Err(ParseError::UnboundNamespacePrefix)
        ));
        Ok(())
    })
}

#[derive(Clone)]
struct ExhaustedElementAllocator(Arc<AtomicUsize>);

// This allocator never returns storage, so no memory can outlive an allocation.
unsafe impl ChunkAllocator for ExhaustedElementAllocator {
    fn allocate(&self, _: Layout) -> Result<Chunk, AllocationError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(AllocationError::Exhausted)
    }

    unsafe fn deallocate(&self, _: Chunk) {
        panic!("exhausted allocator cannot own chunks");
    }
}

#[test]
fn standalone_byte_limit_precedes_allocator_use_and_includes_surrounding_whitespace() -> TestResult
{
    block_on(async {
        let input = b" \t<x/>\r\n ";
        parse_element(input, config(input.len())?, GlobalChunkAllocator).await?;
        let calls = Arc::new(AtomicUsize::new(0));
        let allocator = ExhaustedElementAllocator(calls.clone());
        assert!(matches!(
            parse_element(input, config(input.len() - 1)?, allocator.clone()).await,
            Err(ParseError::SizeLimitExceeded { limit }) if limit == input.len() - 1
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(matches!(
            parse_element(b"<x/>", config(4)?, allocator).await,
            Err(ParseError::Build(BuildError::Allocation(
                ArenaError::Allocation(AllocationError::Exhausted)
            )))
        ));
        assert!(calls.load(Ordering::Relaxed) > 0);
        Ok(())
    })
}

#[test]
fn standalone_tree_attribute_and_arena_limits_are_enforced() -> TestResult {
    block_on(async {
        for depth in [MAX_ELEMENT_DEPTH, MAX_ELEMENT_DEPTH + 1] {
            let input = format!("{}{}", "<x>".repeat(depth), "</x>".repeat(depth));
            let result =
                parse_element(input.as_bytes(), config(input.len())?, GlobalChunkAllocator).await;
            if depth == MAX_ELEMENT_DEPTH {
                result?;
            } else {
                assert!(matches!(
                    result,
                    Err(ParseError::Build(BuildError::TreeLimitExceeded))
                ));
            }
        }
        for count in [MAX_ATTRIBUTES_PER_ELEMENT, MAX_ATTRIBUTES_PER_ELEMENT + 1] {
            let attributes = (0..count)
                .map(|index| format!(" a{index}='v'"))
                .collect::<String>();
            let input = format!("<x{attributes}/>");
            let result =
                parse_element(input.as_bytes(), config(input.len())?, GlobalChunkAllocator).await;
            if count == MAX_ATTRIBUTES_PER_ELEMENT {
                result?;
            } else {
                assert!(matches!(result, Err(ParseError::TooManyAttributes)));
            }
        }
        for children in [MAX_ELEMENT_NODES - 1, MAX_ELEMENT_NODES] {
            let input = format!("<x>{}</x>", "<y/>".repeat(children));
            let mut limits = config(input.len())?;
            limits.arena.max_reserved_bytes =
                NonZeroUsize::new(32 * 1024 * 1024).ok_or("arena limit")?;
            let result = parse_element(input.as_bytes(), limits, GlobalChunkAllocator).await;
            if children == MAX_ELEMENT_NODES - 1 {
                result?;
            } else {
                assert!(matches!(
                    result,
                    Err(ParseError::Build(BuildError::TreeLimitExceeded))
                ));
            }
        }
        let input = format!("<x>{}</x>", "a".repeat(8192));
        let mut limits = config(input.len())?;
        limits.arena.max_reserved_bytes = NonZeroUsize::new(4096).ok_or("arena limit")?;
        assert!(matches!(
            parse_element(input.as_bytes(), limits, GlobalChunkAllocator).await,
            Err(ParseError::Build(BuildError::Allocation(
                ArenaError::ArenaLimitExceeded
            )))
        ));
        Ok(())
    })
}

#[test]
fn standalone_element_owns_values_after_source_buffer_is_dropped() -> TestResult {
    block_on(async {
        let parsed = {
            let source = String::from("<vCard xmlns='vcard-temp'><FN>retained</FN></vCard>");
            parse_element(source.as_bytes(), config(4096)?, GlobalChunkAllocator).await?
        };
        let root = parsed.value().resolve(parsed.arena())?;
        assert_eq!(root.namespace(), "vcard-temp");
        assert_eq!(
            root.child("FN", "vcard-temp")?.ok_or("FN")?.text()?,
            Some("retained")
        );
        Ok(())
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

#[test]
fn stream_start_flags_extra_normalized_header_namespaces() -> TestResult {
    block_on(async {
        for chunk in [1, usize::MAX] {
            for (root, declarations, expected) in [
                (
                    "stream:stream",
                    "xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'",
                    false,
                ),
                (
                    "s:stream",
                    "xmlns:s='http://etherx.jabber.org/streams'",
                    false,
                ),
                (
                    "s:stream",
                    "xmlns:s='http://etherx.jabber.org/streams' xmlns=''",
                    false,
                ),
                (
                    "s:stream",
                    "xmlns:s='http://etherx.jabber.org/streams' xmlns='http://etherx.jabber.org/streams'",
                    false,
                ),
                ("stream", "xmlns='http://etherx.jabber.org/streams'", false),
                (
                    "stream",
                    "xmlns='http://etherx.jabber.org/streams' xmlns:s='http://etherx.jabber.org/streams'",
                    false,
                ),
                (
                    "s:stream",
                    "xmlns:s='http://etherx.jabber.org/strea&#109;s' xmlns:xml='http://www.w3.org/XML/1998/na&#109;espace'",
                    false,
                ),
                (
                    "stream:stream",
                    "xmlns:stream='http://etherx.jabber.org/streams' xmlns:w='urn:x'",
                    true,
                ),
                (
                    "stream:stream",
                    "xmlns:stream='http://etherx.jabber.org/streams' xmlns:c='jabber:cl&#105;ent'",
                    true,
                ),
                (
                    "stream:stream",
                    "xmlns:stream='http://etherx.jabber.org/streams' xmlns:s='http://etherx.jabber.org/strea&#109;s'",
                    true,
                ),
                (
                    "stream",
                    "xmlns='http://etherx.jabber.org/streams' xmlns:s='http://etherx.jabber.org/streams' xmlns:w='http://etherx.jabber.org/streams'",
                    true,
                ),
            ] {
                let input = format!("<{root} {declarations}>");
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                let Some(StreamEvent::StreamStart {
                    extra_header_namespaces,
                    ..
                }) = parser.next_event().await?
                else {
                    return Err("expected stream start".into());
                };
                assert_eq!(
                    extra_header_namespaces, expected,
                    "input={input:?}, chunk={chunk}"
                );
            }
        }
        Ok(())
    })
}

#[test]
fn stanza_writers_preserve_header_aliases_and_stanza_namespace_bindings() -> TestResult {
    block_on(async {
        for chunk in [1, usize::MAX] {
            for (opening, prefix) in [
                (OPEN, "stream"),
                (
                    "<s:stream xmlns:s='http://etherx.jabber.org/strea&#109;s' xmlns='jabber:client' xmlns:xml='http://www.w3.org/XML/1998/namespace'>",
                    "s",
                ),
            ] {
                let input = format!(
                    "{opening}<message xmlns:w='urn:types'><payload xmlns='urn:x' type='w:Example'/></message>"
                );
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                open(&mut parser).await?;
                let parsed = stanza(&mut parser).await?;
                let view = parsed.value().resolve(parsed.arena())?;
                let mut output = String::new();
                view.write_xml(&mut output)?;
                assert!(
                    output.contains(&format!(
                        "xmlns:{prefix}=\"http://etherx.jabber.org/streams\""
                    )),
                    "{output}"
                );
                assert!(!output.contains("xmlns:xml="), "{output}");
                assert!(output.contains("xmlns:w=\"urn:types\""), "{output}");
                assert!(output.contains("xmlns=\"jabber:client\""), "{output}");
                let mut asynchronous = futures_util::io::Cursor::new(Vec::new());
                view.write_xml_async(&mut asynchronous).await?;
                assert_eq!(asynchronous.into_inner(), output.as_bytes());

                let stored = format!("{OPEN}{output}{CLOSE}");
                let mut replay = XmppParser::new(
                    Fragmented::new(stored.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                open(&mut replay).await?;
                let parsed = stanza(&mut replay).await?;
                let mut replayed = String::new();
                parsed
                    .value()
                    .resolve(parsed.arena())?
                    .write_xml(&mut replayed)?;
                assert!(!replayed.contains("xmlns:xml="), "{replayed}");
                assert_root_namespace_binding(&replayed, "w", Some("urn:types"))?;
                assert_root_namespace_binding(
                    &replayed,
                    prefix,
                    Some(crate::stanza::STREAM_NAMESPACE),
                )?;
            }
        }
        Ok(())
    })
}

#[test]
fn explicit_attributes_exclude_inherited_stream_language_and_space() -> TestResult {
    block_on(async {
        let input = format!(
            "{}<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls' xml:space='default'/>",
            OPEN.replace('>', " xml:lang='es' xml:space='preserve'>")
        );
        let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        let Some(StreamEvent::Element(first)) = parser.next_event().await? else {
            return Err("expected first element".into());
        };
        assert!(!first.has_explicit_attributes());
        assert_eq!(
            first
                .value()
                .resolve(first.arena())?
                .attribute("space", XML_NAMESPACE)?,
            Some("preserve")
        );
        assert_eq!(
            first
                .value()
                .resolve(first.arena())?
                .attribute("lang", "http://www.w3.org/XML/1998/namespace")?,
            Some("es")
        );
        let Some(StreamEvent::Element(second)) = parser.next_event().await? else {
            return Err("expected second element".into());
        };
        assert!(second.has_explicit_attributes());
        assert_eq!(
            second
                .value()
                .resolve(second.arena())?
                .attribute("space", XML_NAMESPACE)?,
            Some("default")
        );
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
    error_at_end: bool,
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
            error_at_end: false,
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
        if this.error_at_end && this.position == this.bytes.len() {
            return Poll::Ready(Err(io::Error::other("transport failure")));
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
fn adjacent_attributes_fail_terminally_at_every_transport_split() -> TestResult {
    block_on(async {
        for (opening, content) in [
            (
                OPEN,
                "<message to='bob@localhost/phone'id='missing-space'><body>probe</body></message>",
            ),
            (OPEN, "<message id='a'type='chat'/>"),
            (OPEN, "<message xmlns:x='urn:x'xmlns:y='urn:y'/>"),
            (OPEN, "<message><x xmlns='urn:x' a='1'b='2'/></message>"),
            (OPEN, "<iq type='bogus'id='invalid'/>"),
            (
                "",
                "<stream:stream xmlns:stream='http://etherx.jabber.org/streams'xmlns='jabber:client'>",
            ),
            ("", "<?xml version='1.0'encoding='UTF-8'?>"),
            ("", "<?xml version='1.0'encoding='ISO-8859-1'?>"),
            ("", "<?xml version='1.0' encoding='UTF-8'standalone='yes'?>"),
            (OPEN, "<message id='a'\u{a0}type='chat'/>"),
            (OPEN, "<message id='a'\u{b}type='chat'/>"),
        ] {
            let input = format!("{opening}{content}<message id='trailing'/>{CLOSE}");
            for (chunk, split) in [(1, input.len()), (usize::MAX, input.len())]
                .into_iter()
                .chain((1..input.len()).map(|split| (usize::MAX, split)))
            {
                let mut source = Fragmented::new(input.as_bytes(), chunk);
                source.split = split;
                let mut parser = XmppParser::new(source, config(4096)?, GlobalChunkAllocator);
                if !opening.is_empty() {
                    open(&mut parser).await?;
                }
                assert!(
                    matches!(parser.next_event().await, Err(ParseError::NotWellFormed)),
                    "{content}, chunk={chunk}, split={split}"
                );
                assert!(matches!(
                    parser.next_event().await,
                    Err(ParseError::ParserFailed)
                ));
            }
        }
        Ok(())
    })
}

#[test]
fn attribute_spacing_rejects_incomplete_raw_suffixes() {
    for suffix in [
        "a='1'",
        " =''",
        " name",
        " name ",
        " name=",
        " name= ",
        " name=value",
        " name='value",
        " name=\"value",
        " name='value'other='value'",
        " name='value'\u{a0}other='value'",
        " name='value'\u{c}other='value'",
    ] {
        let content = format!("x{suffix}");
        let start = quick_xml::events::BytesStart::from_content(&content, 1);
        assert!(
            matches!(
                super::names::validate_attribute_spacing(&start),
                Err(ParseError::NotWellFormed)
            ),
            "{suffix:?}"
        );
    }
}

#[test]
fn valid_attribute_spacing_and_quoted_values_survive_every_transport_split() -> TestResult {
    block_on(async {
        for content in [
            "<message/>",
            "<message > <body/></message>",
            "<message id = '' type=\"chat\"/>",
            "<message\tid\t=\t'a'\r type\r=\r'chat'\n xml:lang\n=\n'en' \t\r\n/>",
            "<message a=\"' b='x' &quot; &apos;\" b='\" c=\"x\" &apos; &quot;'><x xmlns='urn:x' flag=''/></message>",
        ] {
            let input = format!(
                "<?xml\tversion \r=\n'1.0'\r encoding=\"UTF-8\"\n standalone = 'yes' \t?>{OPEN}{content}{CLOSE}"
            );
            for (chunk, split) in [(1, input.len()), (usize::MAX, input.len())]
                .into_iter()
                .chain((1..input.len()).map(|split| (usize::MAX, split)))
            {
                let mut source = Fragmented::new(input.as_bytes(), chunk);
                source.split = split;
                let mut parser = XmppParser::new(source, config(4096)?, GlobalChunkAllocator);
                open(&mut parser).await?;
                let parsed = stanza(&mut parser).await?;
                let view = parsed.value().resolve(parsed.arena())?;
                if content.contains(" a=") {
                    assert_eq!(view.attribute("a", "")?, Some("' b='x' \" '"));
                    assert_eq!(view.attribute("b", "")?, Some("\" c=\"x\" ' \""));
                }
                assert!(matches!(
                    parser.next_event().await?,
                    Some(StreamEvent::StreamEnd)
                ));
                assert!(parser.next_event().await?.is_none());
            }
        }
        Ok(())
    })
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
        let input = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' xmlns:x='urn:old' xml:lang='en' xml:space='preserve'><success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server'><message from='a.example' to='b.example'/><message from='a.example' to='b.example'><x:test/></message>";
        let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        let Some(StreamEvent::Element(success)) = parser.next_event().await? else {
            return Err("success".into());
        };
        assert_eq!(
            success.value().resolve(success.arena())?.namespace(),
            "urn:ietf:params:xml:ns:xmpp-sasl"
        );
        assert_eq!(
            success
                .value()
                .resolve(success.arena())?
                .attribute("space", XML_NAMESPACE)?,
            Some("preserve")
        );
        let mut parser = parser.restart()?;
        open(&mut parser).await?;
        let parsed = stanza(&mut parser).await?;
        let view = parsed.value().resolve(parsed.arena())?;
        assert_eq!(view.attribute("space", XML_NAMESPACE)?, None);
        assert_eq!(view.namespace(), StanzaNamespace::Server);
        assert_eq!(view.lang()?, None);
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::UnboundNamespacePrefix)
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
fn rejects_malformed_and_restricted_xml() -> TestResult {
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
fn invalid_namespace_declarations_are_not_well_formed_errors() -> TestResult {
    const INVALID_DECLARATIONS: [&str; 6] = [
        "xmlns:p=''",
        "xmlns:p='http://www.w3.org/2000/xmlns/'",
        "xmlns:p='http://www.w3.org/XML/1998/namespace'",
        "xmlns='http://www.w3.org/XML/1998/namespace'",
        "xmlns:xml='urn:bad'",
        "xmlns:xmlns='urn:bad'",
    ];

    block_on(async {
        for declaration in INVALID_DECLARATIONS {
            let input = format!("{OPEN}<message {declaration}/>{CLOSE}");
            let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
            open(&mut parser).await?;
            assert!(
                matches!(parser.next_event().await, Err(ParseError::NotWellFormed)),
                "accepted or misclassified {declaration:?}"
            );

            let stream = format!(
                "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' {declaration}>"
            );
            let mut parser =
                XmppParser::new(stream.as_bytes(), config(4096)?, GlobalChunkAllocator);
            assert!(
                matches!(parser.next_event().await, Err(ParseError::NotWellFormed)),
                "accepted or misclassified stream declaration {declaration:?}"
            );
        }

        let input = format!(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' xmlns:xml='http://www.w3.org/XML/1998/namespace'><message xmlns:xml='http://www.w3.org/XML/1998/namespace'/>{CLOSE}"
        );
        let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        assert!(matches!(
            parser.next_event().await?,
            Some(StreamEvent::Stanza(_))
        ));
        Ok(())
    })
}

#[test]
fn quick_xml_namespace_errors_preserve_well_formedness_classification() {
    use quick_xml::name::NamespaceError;

    for error in [
        NamespaceError::UnknownPrefix("p".to_owned()),
        NamespaceError::InvalidXmlPrefixBind("urn:bad".to_owned()),
        NamespaceError::InvalidXmlnsPrefixBind("urn:bad".to_owned()),
        NamespaceError::InvalidPrefixForXml("p".to_owned()),
        NamespaceError::InvalidPrefixForXmlns("p".to_owned()),
    ] {
        assert!(matches!(
            ParseError::from(quick_xml::Error::Namespace(error)),
            ParseError::NotWellFormed
        ));
    }

    for error in [
        NamespaceError::TooManyBindings(1),
        NamespaceError::TooDeeplyNested(1),
    ] {
        assert!(matches!(
            ParseError::from(quick_xml::Error::Namespace(error)),
            ParseError::Xml(quick_xml::Error::Namespace(_))
        ));
    }
}

#[test]
fn malformed_entity_names_return_not_well_formed_in_every_context() -> TestResult {
    block_on(async {
        for reference in ["&;", "&123;", "&foo bar;", "&foo:bar;", "&\u{301}foo;"] {
            for chunk in [1, usize::MAX] {
                for (input, in_header) in entity_reference_inputs(reference) {
                    let mut parser = XmppParser::new(
                        Fragmented::new(input.as_bytes(), chunk),
                        config(4096)?,
                        GlobalChunkAllocator,
                    );
                    if !in_header {
                        open(&mut parser).await?;
                    }
                    assert!(
                        matches!(parser.next_event().await, Err(ParseError::NotWellFormed)),
                        "reference={reference:?}, input={input:?}, chunk={chunk}"
                    );
                }
            }
        }
        Ok(())
    })
}

fn entity_reference_inputs(reference: &str) -> [(String, bool); 4] {
    [
        (OPEN.replace('>', &format!(" flag='{reference}'>")), true),
        (format!("{OPEN}<message id='{reference}'/>{CLOSE}"), false),
        (format!("{OPEN}{reference}{CLOSE}"), false),
        (
            format!("{OPEN}<message><body>{reference}</body></message>{CLOSE}"),
            false,
        ),
    ]
}

#[test]
fn undeclared_entities_return_restricted_xml_in_every_context() -> TestResult {
    block_on(async {
        for name in ["foo", "é", "_name-1", "xmlns"] {
            let reference = format!("&{name};");
            for chunk in [1, usize::MAX] {
                for (input, in_header) in entity_reference_inputs(&reference) {
                    let mut parser = XmppParser::new(
                        Fragmented::new(input.as_bytes(), chunk),
                        config(4096)?,
                        GlobalChunkAllocator,
                    );
                    if !in_header {
                        open(&mut parser).await?;
                    }
                    assert!(
                        matches!(parser.next_event().await, Err(ParseError::RestrictedXml)),
                        "reference={reference:?}, input={input:?}, chunk={chunk}"
                    );
                }
            }
        }
        Ok(())
    })
}

#[test]
fn invalid_character_references_return_not_well_formed_in_every_context() -> TestResult {
    block_on(async {
        for reference in [
            "&#x0;",
            "&#0;",
            "&#xD800;",
            "&#x110000;",
            "&#xG;",
            "&#;",
            "&#x;",
            "&#12",
        ] {
            for chunk in [1, usize::MAX] {
                for (input, in_header) in entity_reference_inputs(reference) {
                    let mut parser = XmppParser::new(
                        Fragmented::new(input.as_bytes(), chunk),
                        config(4096)?,
                        GlobalChunkAllocator,
                    );
                    if !in_header {
                        open(&mut parser).await?;
                    }
                    assert!(
                        matches!(parser.next_event().await, Err(ParseError::NotWellFormed)),
                        "reference={reference:?}, input={input:?}, chunk={chunk}"
                    );
                }
            }
        }
        Ok(())
    })
}

#[test]
fn predefined_entities_and_character_references_preserve_values_and_depth_one_errors() -> TestResult
{
    block_on(async {
        for (reference, expected) in [
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&amp;", "&"),
            ("&apos;", "'"),
            ("&quot;", "\""),
            ("&#65;", "A"),
            ("&#xE9;", "é"),
            ("&#x9;", "\t"),
            ("&#10;", "\n"),
            ("&#xD;", "\r"),
            ("&#32;", " "),
        ] {
            for chunk in [1, usize::MAX] {
                let input = format!(
                    "{}<message id='{reference}'><body>{reference}</body></message>{CLOSE}",
                    OPEN.replace('>', &format!(" flag='{reference}'>"))
                );
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                let Some(StreamEvent::StreamStart { header, .. }) = parser.next_event().await?
                else {
                    return Err("expected stream start".into());
                };
                assert_eq!(
                    header
                        .value()
                        .resolve(header.arena())?
                        .attribute("flag", "")?,
                    Some(expected)
                );
                let parsed = stanza(&mut parser).await?;
                let view = parsed.value().resolve(parsed.arena())?;
                assert_eq!(view.id()?, Some(expected));
                assert_eq!(
                    view.child("body", CLIENT_NAMESPACE)?
                        .ok_or("body")?
                        .text()?,
                    Some(expected)
                );
                assert!(matches!(
                    parser.next_event().await?,
                    Some(StreamEvent::StreamEnd)
                ));

                let input = format!("{OPEN}{reference}{CLOSE}");
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                open(&mut parser).await?;
                assert!(
                    matches!(parser.next_event().await, Err(ParseError::UnexpectedEvent)),
                    "reference={reference:?}, chunk={chunk}"
                );
            }
        }
        Ok(())
    })
}

#[test]
fn unbound_prefix_remains_fatal() -> TestResult {
    block_on(async {
        let input = format!("{OPEN}<x:message/>");
        let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::UnboundNamespacePrefix)
        ));
        Ok(())
    })
}

#[test]
fn distinguishes_transport_errors_from_invalid_xml() {
    let transport = ParseError::from(quick_xml::Error::Io(Arc::new(io::Error::other(
        "read failed",
    ))));
    assert!(transport.is_transport_error());
    assert!(!ParseError::InvalidXml.is_transport_error());
}

#[test]
fn failed_restart_returns_the_unchanged_parser_and_unread_transport() -> TestResult {
    block_on(async {
        let input = format!("{OPEN}<presence/>{CLOSE}");
        let parser = XmppParser::new(
            Fragmented::new(input.as_bytes(), 1),
            config(4096)?,
            GlobalChunkAllocator,
        );
        let mut parser = match parser.try_restart() {
            Err((parser, ParseError::UnexpectedEvent)) => parser,
            _ => return Err("expected initial restart rejection".into()),
        };
        open(&mut parser).await?;
        stanza(&mut parser).await?;
        assert!(matches!(
            parser.next_event().await?,
            Some(StreamEvent::StreamEnd)
        ));
        let mut parser = match parser.try_restart() {
            Err((parser, ParseError::UnexpectedEvent)) => parser,
            _ => return Err("expected closed restart rejection".into()),
        };
        assert!(parser.next_event().await?.is_none());
        Ok(())
    })
}

#[test]
fn xml_one_x_declarations_keep_xml_one_zero_character_rules_and_events() -> TestResult {
    block_on(async {
        for chunk in [1, usize::MAX] {
            let mut expected = String::new();
            for version in [
                "1.0",
                "1.1",
                "1.000",
                "1.999999999999999999999999999999999999999",
            ] {
                let input = format!(
                    "<?xml version='{version}'?>{OPEN}<message><body>\u{85}\u{2028}&amp;&#65;</body></message>{CLOSE}"
                );
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                open(&mut parser).await?;
                let parsed = stanza(&mut parser).await?;
                let view = parsed.value().resolve(parsed.arena())?;
                assert_eq!(
                    view.child("body", CLIENT_NAMESPACE)?
                        .ok_or("body")?
                        .text()?,
                    Some("\u{85}\u{2028}&A")
                );
                let mut output = String::new();
                view.write_xml(&mut output)?;
                if expected.is_empty() {
                    expected = output;
                } else {
                    assert_eq!(output, expected);
                }
                assert!(matches!(
                    parser.next_event().await?,
                    Some(StreamEvent::StreamEnd)
                ));

                for element in [
                    "<message id='&#x1;'/>",
                    "<message><body>&#x1;</body></message>",
                ] {
                    let input = format!("<?xml version='{version}'?>{OPEN}{element}{CLOSE}");
                    let mut parser = XmppParser::new(
                        Fragmented::new(input.as_bytes(), chunk),
                        config(4096)?,
                        GlobalChunkAllocator,
                    );
                    open(&mut parser).await?;
                    assert!(matches!(
                        parser.next_event().await,
                        Err(ParseError::NotWellFormed)
                    ));
                }
            }
        }
        Ok(())
    })
}

#[test]
fn declaration_encoding_and_unclosed_stream_are_checked() -> TestResult {
    block_on(async {
        let input = format!(
            "<?xml version='1.0' encoding='utf-8' standalone='yes'?>{OPEN}<presence/>{CLOSE}"
        );
        let mut parser = XmppParser::new(
            Fragmented::new(input.as_bytes(), 1),
            config(32)?,
            GlobalChunkAllocator,
        );
        open(&mut parser).await?;
        stanza(&mut parser).await?;
        for declaration in [
            "<?xml version='2.0'?>",
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
fn invalid_utf8_is_rejected_as_unsupported_encoding() -> TestResult {
    block_on(async {
        for invalid in [
            b"<message>\xff</message>".as_slice(),
            b"<mess\xffage/>",
            b"<message id='\xff'/>",
        ] {
            let mut input = OPEN.as_bytes().to_vec();
            input.extend_from_slice(invalid);
            let mut parser = XmppParser::new(input.as_slice(), config(4096)?, GlobalChunkAllocator);
            open(&mut parser).await?;
            assert!(matches!(
                parser.next_event().await,
                Err(ParseError::UnsupportedEncoding)
            ));
        }
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
fn declaration_position_is_independent_of_fragmentation() -> TestResult {
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
                assert!(
                    matches!(parser.next_event().await, Err(ParseError::NotWellFormed)),
                    "accepted {prefix:?}"
                );
            }
            for prefix in [" \r\n", "\t"] {
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
fn stream_start_preserves_character_semantics_across_splits_and_restarts() -> TestResult {
    block_on(async {
        for prefix in [
            "\u{feff}",
            "\u{feff}<?xml version='1.0' encoding='UTF-8'?>",
            "\u{feff}\u{feff}",
            "\u{feff} \t\r\n",
            " \t\r\n\u{feff}",
            "\u{feff} \u{feff}",
            "\u{fffd}",
            "\u{f000}",
            "é",
            "🐺",
            "!",
        ] {
            for suffix in ["", OPEN] {
                for restart in [false, true] {
                    let initial = if restart { OPEN } else { "" };
                    let input = format!("{initial}{prefix}{suffix}");
                    for chunk in [1, usize::MAX] {
                        for split in [1, 2, input.len() - initial.len()] {
                            let mut reader = Fragmented::new(input.as_bytes(), chunk);
                            reader.split = initial.len() + split.min(input.len() - initial.len());
                            let mut parser =
                                XmppParser::new(reader, config(4096)?, GlobalChunkAllocator);
                            if restart {
                                open(&mut parser).await?;
                                parser = parser.restart()?;
                            }
                            let error = parser
                                .next_event()
                                .await
                                .err()
                                .ok_or("accepted stream text")?;
                            assert!(
                                matches!(error, ParseError::NotWellFormed),
                                "{prefix:?}, restart={restart}, chunk={chunk}, split={split}: {error:?}"
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    })
}

#[test]
fn stream_start_distinguishes_malformed_utf8_from_clean_eof() -> TestResult {
    block_on(async {
        for invalid in [
            b"\xef".as_slice(),
            b"\xef\xbb",
            b"\xef<",
            b"\xef\xbb<",
            b"\xef\xff\xbf",
            b"\x80",
            b"\xc0\x80",
            b"\xed\xa0\x80",
            b"\xf4\x90\x80\x80",
            b"\xf0\x9f\x90",
            b"\xff",
        ] {
            for restart in [false, true] {
                let mut input = Vec::new();
                if restart {
                    input.extend_from_slice(OPEN.as_bytes());
                }
                input.extend_from_slice(invalid);
                for chunk in [1, usize::MAX] {
                    let mut parser = XmppParser::new(
                        Fragmented::new(&input, chunk),
                        config(4096)?,
                        GlobalChunkAllocator,
                    );
                    if restart {
                        open(&mut parser).await?;
                        parser = parser.restart()?;
                    }
                    let error = parser
                        .next_event()
                        .await
                        .err()
                        .ok_or("accepted invalid UTF-8")?;
                    assert!(
                        matches!(error, ParseError::UnsupportedEncoding),
                        "{invalid:?}, restart={restart}: {error:?}"
                    );
                }
            }
        }
        for input in ["", " \t\r\n"] {
            let mut parser = XmppParser::new(
                Fragmented::new(input.as_bytes(), 1),
                config(4096)?,
                GlobalChunkAllocator,
            );
            assert!(matches!(
                parser.next_event().await,
                Err(ParseError::UnexpectedEof)
            ));
        }
        Ok(())
    })
}

#[test]
fn stream_start_retains_transport_errors_during_scalar_reads() -> TestResult {
    block_on(async {
        for bytes in [b"".as_slice(), b"\xef", b"\xef\xbb", b"\xf0\x9f\x90"] {
            for restart in [false, true] {
                let mut input = Vec::new();
                if restart {
                    input.extend_from_slice(OPEN.as_bytes());
                }
                input.extend_from_slice(bytes);
                let mut reader = Fragmented::new(&input, 1);
                reader.error_at_end = true;
                let mut parser = XmppParser::new(reader, config(4096)?, GlobalChunkAllocator);
                if restart {
                    open(&mut parser).await?;
                    parser = parser.restart()?;
                }
                let error = parser
                    .next_event()
                    .await
                    .err()
                    .ok_or("expected transport error")?;
                assert!(error.is_transport_error(), "{bytes:?}: {error:?}");
                assert!(matches!(
                    parser.next_event().await,
                    Err(ParseError::ParserFailed)
                ));
            }
        }
        Ok(())
    })
}

#[test]
fn payload_preserves_feff_and_replacement_characters_with_wire_byte_limits() -> TestResult {
    block_on(async {
        let message = "<message><body>\u{feff}a\u{feff}\u{fffd}</body></message>";
        let input = format!("{OPEN}{message}{CLOSE}");
        for chunk in [1, usize::MAX] {
            let mut parser = XmppParser::new(
                Fragmented::new(input.as_bytes(), chunk),
                config(message.len())?,
                GlobalChunkAllocator,
            );
            open(&mut parser).await?;
            let parsed = stanza(&mut parser).await?;
            let body = parsed
                .value()
                .resolve(parsed.arena())?
                .child("body", CLIENT_NAMESPACE)?
                .ok_or("body")?;
            assert_eq!(body.text()?, Some("\u{feff}a\u{feff}\u{fffd}"));
            assert!(matches!(
                parser.next_event().await?,
                Some(StreamEvent::StreamEnd)
            ));
            let mut parser = XmppParser::new(
                Fragmented::new(input.as_bytes(), chunk),
                config(message.len() - 1)?,
                GlobalChunkAllocator,
            );
            open(&mut parser).await?;
            assert!(
                matches!(parser.next_event().await, Err(ParseError::SizeLimitExceeded { limit }) if limit == message.len() - 1)
            );
        }
        Ok(())
    })
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

#[test]
fn complete_stanza_rejections_preserve_ids_and_allow_the_next_stanza() -> TestResult {
    block_on(async {
        for (input, reason, id, can_reply) in [
            ("<iq><q/></iq>", StanzaRejection::BadRequest, Some(""), true),
            (
                "<iq type='get'><q/></iq>",
                StanzaRejection::BadRequest,
                Some(""),
                true,
            ),
            (
                "<iq type='future' id=''><q/></iq>",
                StanzaRejection::BadRequest,
                Some(""),
                true,
            ),
            (
                "<iq type='future' id='a&amp;b'><q/></iq>",
                StanzaRejection::BadRequest,
                Some("a&b"),
                true,
            ),
            (
                "<iq type='get' id='zero'/>",
                StanzaRejection::BadRequest,
                Some("zero"),
                true,
            ),
            (
                "<iq type='set' id='two'><q/><q/></iq>",
                StanzaRejection::BadRequest,
                Some("two"),
                true,
            ),
            (
                "<presence type='future' id='presence'/>",
                StanzaRejection::BadRequest,
                Some("presence"),
                true,
            ),
            (
                "<message id='text'>text<child/></message>",
                StanzaRejection::BadRequest,
                Some("text"),
                true,
            ),
            (
                "<message id='error-child'><error/></message>",
                StanzaRejection::BadRequest,
                Some("error-child"),
                true,
            ),
            (
                "<message to='bad@' id='to'/>",
                StanzaRejection::JidMalformed,
                Some("to"),
                true,
            ),
            (
                "<presence from='@bad' id='from'/>",
                StanzaRejection::JidMalformed,
                Some("from"),
                true,
            ),
            (
                "<iq type='get' id='to' to='bad@'><q/></iq>",
                StanzaRejection::JidMalformed,
                Some("to"),
                true,
            ),
            (
                "<iq type='future' id='precedence' to='bad@'><q/></iq>",
                StanzaRejection::BadRequest,
                Some("precedence"),
                true,
            ),
            (
                "<iq type='result'/>",
                StanzaRejection::BadRequest,
                None,
                false,
            ),
            (
                "<iq type='result' id='result'><q/><q/></iq>",
                StanzaRejection::BadRequest,
                None,
                false,
            ),
            (
                "<iq type='result' id='result' to='bad@'/>",
                StanzaRejection::JidMalformed,
                None,
                false,
            ),
            (
                "<iq type='error' id='error'/>",
                StanzaRejection::BadRequest,
                None,
                false,
            ),
            (
                "<message type='error' to='bad@'/>",
                StanzaRejection::BadRequest,
                None,
                false,
            ),
            (
                "<presence type='error' from='bad@'><error/></presence>",
                StanzaRejection::JidMalformed,
                None,
                false,
            ),
        ] {
            let input = format!(
                "{}{input}<presence id='sentinel'/>{CLOSE}",
                OPEN.replace('>', " xml:lang='es'>")
            );
            let mut parser = XmppParser::new(
                Fragmented::new(input.as_bytes(), 1),
                config(4096)?,
                GlobalChunkAllocator,
            );
            open(&mut parser).await?;
            let Some(StreamEvent::RejectedStanza(parsed)) = parser.next_event().await? else {
                return Err(format!("expected rejection: {input}").into());
            };
            let (rejected, mut arena) = parsed.into_parts();
            assert_eq!(rejected.reason(), reason, "{input}");
            assert_eq!(rejected.can_reply(), can_reply, "{input}");
            let authenticated = crate::jid::Jid::parse_in("alice@example.org/desk", &mut arena)?;
            let server = crate::jid::Jid::parse_in("example.org", &mut arena)?;
            if can_reply {
                let reply = rejected.error_in(authenticated, server, &mut arena)?;
                let reply = reply.resolve(&arena)?;
                assert_eq!(reply.kind(), rejected.kind());
                assert!(reply.stanza_type().is_error());
                assert_eq!(reply.id()?, id);
                assert_eq!(reply.lang()?, Some("es"));
                assert_eq!(
                    reply.to()?.ok_or("reply recipient")?.as_str(),
                    "alice@example.org/desk"
                );
                assert_eq!(
                    reply.from()?.map(|jid| jid.as_str()),
                    rejected.invalid_to().then_some("example.org")
                );
                let error = reply
                    .child("error", CLIENT_NAMESPACE)?
                    .ok_or("error child")?;
                assert_eq!(error.attribute("type", "")?, Some("modify"));
                let condition = match reason {
                    StanzaRejection::BadRequest => "bad-request",
                    StanzaRejection::JidMalformed => "jid-malformed",
                };
                assert!(
                    error
                        .child(condition, crate::stanza::STANZA_ERROR_NAMESPACE)?
                        .is_some()
                );
            } else {
                assert!(matches!(
                    rejected.error_in(authenticated, server, &mut arena),
                    Err(BuildError::InvalidErrorSource)
                ));
            }
            let sentinel = stanza(&mut parser).await?;
            assert_eq!(
                sentinel.value().resolve(sentinel.arena())?.id()?,
                Some("sentinel")
            );
            assert!(matches!(
                parser.next_event().await?,
                Some(StreamEvent::StreamEnd)
            ));
        }
        Ok(())
    })
}

#[test]
fn rejected_iq_envelopes_preserve_address_validity_and_borrowed_metadata() -> TestResult {
    block_on(async {
        for (attributes, from, to, invalid_from, invalid_to) in [
            ("", None, None, false, false),
            (
                "from='Alice@Example.org' to='Example.org'",
                Some("alice@example.org"),
                Some("example.org"),
                false,
                false,
            ),
            ("from='bad@'", None, None, true, false),
            ("to='@bad'", None, None, false, true),
            ("from='' to=''", None, None, true, true),
        ] {
            let input = format!("{OPEN}<iq type='bogus' id='a&amp;b' {attributes}/>{CLOSE}");
            let mut parser = XmppParser::new(
                Fragmented::new(input.as_bytes(), 1),
                config(4096)?,
                GlobalChunkAllocator,
            );
            open(&mut parser).await?;
            let Some(StreamEvent::RejectedStanza(parsed)) = parser.next_event().await? else {
                return Err("expected rejection".into());
            };
            let rejected = parsed.value();
            assert_eq!(rejected.reason(), StanzaRejection::BadRequest);
            assert_eq!(rejected.invalid_from(), invalid_from);
            assert_eq!(rejected.invalid_to(), invalid_to);
            assert_eq!(rejected.from(parsed.arena())?.map(|jid| jid.as_str()), from);
            assert_eq!(rejected.to(parsed.arena())?.map(|jid| jid.as_str()), to);
            assert_eq!(rejected.id(parsed.arena())?, Some("a&b"));

            let foreign = Arena::try_new(ArenaConfig::default())?;
            assert!(matches!(
                rejected.from(&foreign),
                Err(HandleError::WrongArena)
            ));
            assert!(matches!(
                rejected.to(&foreign),
                Err(HandleError::WrongArena)
            ));
            assert_eq!(rejected.id(&foreign), Err(HandleError::WrongArena));
        }
        Ok(())
    })
}

#[test]
fn rejected_stanza_error_checks_all_arena_owners_without_optional_metadata() -> TestResult {
    block_on(async {
        let input = format!("{OPEN}<iq/>");
        let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        let Some(StreamEvent::RejectedStanza(parsed)) = parser.next_event().await? else {
            return Err("expected rejection".into());
        };
        let (rejected, mut source) = parsed.into_parts();
        let mut other = Arena::try_new(ArenaConfig::default())?;
        let foreign = crate::jid::Jid::parse_in("alice@example.org/desk", &mut other)?;
        let foreign_server = crate::jid::Jid::parse_in("example.org", &mut other)?;
        let authenticated = crate::jid::Jid::parse_in("alice@example.org/desk", &mut source)?;
        let server = crate::jid::Jid::parse_in("example.org", &mut source)?;
        assert!(matches!(
            rejected.error_in(foreign, foreign_server, &mut other),
            Err(BuildError::Access(HandleError::WrongArena))
        ));
        assert!(matches!(
            rejected.error_in(foreign, server, &mut source),
            Err(BuildError::Access(HandleError::WrongArena))
        ));
        assert!(matches!(
            rejected.error_in(authenticated, foreign_server, &mut source),
            Err(BuildError::Access(HandleError::WrongArena))
        ));
        Ok(())
    })
}

#[test]
fn explicit_empty_ids_are_valid_for_every_stanza_kind() -> TestResult {
    block_on(async {
        for input in [
            "<message id=''/>",
            "<presence id=''/>",
            "<iq type='get' id=''><q/></iq>",
            "<iq type='result' id=''/>",
        ] {
            let input = format!("{OPEN}{input}");
            let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
            open(&mut parser).await?;
            let parsed = stanza(&mut parser).await?;
            let (stanza, mut arena) = parsed.into_parts();
            assert_eq!(stanza.resolve(&arena)?.id()?, Some(""));
            if !matches!(
                stanza.resolve(&arena)?.stanza_type(),
                StanzaType::Iq(crate::stanza::IqType::Result)
            ) {
                let reply = stanza
                    .error_reply_in(&mut arena, StanzaErrorCondition::BadRequest)?
                    .build()?;
                assert_eq!(reply.resolve(&arena)?.id()?, Some(""));
            }
        }
        Ok(())
    })
}

#[test]
fn original_message_type_survives_copying_and_is_cleared_for_new_types() -> TestResult {
    block_on(async {
        for raw_type in [None, Some("normal"), Some("future-type"), Some("")] {
            let attribute = raw_type.map_or_else(String::new, |value| format!(" type='{value}'"));
            let input = format!(
                "{}<message{attribute} id='' xmlns:x='urn:attr' x:flag='yes'><body>hello</body><extra xmlns='urn:payload'/></message>",
                OPEN.replace('>', " xml:lang='es'>")
            );
            let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
            open(&mut parser).await?;
            let (original, mut arena) = stanza(&mut parser).await?.into_parts();
            let view = original.resolve(&arena)?;
            assert_eq!(view.stanza_type(), StanzaType::Message(MessageType::Normal));
            let mut expected = String::new();
            view.write_xml(&mut expected)?;
            match raw_type {
                Some(value) => assert!(expected.contains(&format!(" type=\"{value}\""))),
                None => assert!(!expected.contains(" type=")),
            }
            assert_eq!(view.lang()?, Some("es"));
            assert_eq!(view.attribute("flag", "urn:attr")?, Some("yes"));
            assert_eq!(
                view.child("body", CLIENT_NAMESPACE)?
                    .ok_or("body")?
                    .text()?,
                Some("hello")
            );
            let mut copied_arena = Arena::try_new(ArenaConfig::default())?;
            let copied = view.clone_in(&mut copied_arena)?;
            let mut actual = String::new();
            copied.resolve(&copied_arena)?.write_xml(&mut actual)?;
            assert_eq!(actual, expected);
            let derived = original.derive_in(&mut arena)?.build()?;
            actual.clear();
            derived.resolve(&arena)?.write_xml(&mut actual)?;
            assert_eq!(actual, expected);
            let mut asynchronous = futures_util::io::Cursor::new(Vec::new());
            derived
                .resolve(&arena)?
                .write_xml_async(&mut asynchronous)
                .await?;
            assert_eq!(asynchronous.into_inner(), expected.as_bytes());
            let changed = original
                .derive_in(&mut arena)?
                .stanza_type(StanzaType::Message(MessageType::Chat))
                .build()?;
            actual.clear();
            changed.resolve(&arena)?.write_xml(&mut actual)?;
            assert!(actual.contains(" type=\"chat\""));
            let error = original
                .error_reply_in(&mut arena, StanzaErrorCondition::ServiceUnavailable)?
                .build()?;
            actual.clear();
            error.resolve(&arena)?.write_xml(&mut actual)?;
            assert!(actual.contains(" type=\"error\""));
            assert!(!actual.contains("future-type"));
        }
        Ok(())
    })
}

#[test]
fn fatal_errors_override_recoverable_envelopes_and_release_the_pool() -> TestResult {
    block_on(async {
        let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
            total_bytes: NonZeroUsize::new(MIN_POOL_SIZE).ok_or("pool size")?,
            ..PoolConfig::default()
        })?);
        for (input, expected, limit, arena_limit) in [
            (
                "<iq type='unknown'><q></iq>".to_owned(),
                "xml",
                4096,
                1024 * 1024,
            ),
            (
                "<iq type='unknown'><!--forbidden--></iq>".to_owned(),
                "restricted",
                4096,
                1024 * 1024,
            ),
            (
                "<iq type='unknown' to='bad@'><q>\0</q></iq>".to_owned(),
                "text",
                4096,
                1024 * 1024,
            ),
            (
                "<iq type='unknown'><q xmlns:p=''/></iq>".to_owned(),
                "namespace",
                4096,
                1024 * 1024,
            ),
            (
                format!(
                    "<iq type='unknown'>{}{}</iq>",
                    "<x>".repeat(MAX_ELEMENT_DEPTH),
                    "</x>".repeat(MAX_ELEMENT_DEPTH)
                ),
                "tree",
                4096,
                1024 * 1024,
            ),
            (
                format!("<iq type='unknown'><q>{}</q></iq>", "x".repeat(4096)),
                "size",
                4096,
                1024 * 1024,
            ),
            (
                format!("<iq type='unknown'><q>{}</q></iq>", "x".repeat(8192)),
                "allocation",
                16384,
                4096,
            ),
        ] {
            let before = pool.stats().buckets.map(|bucket| bucket.available_chunks);
            let input = format!("{OPEN}{input}");
            let mut limits = config(limit)?;
            limits.arena.max_reserved_bytes =
                NonZeroUsize::new(arena_limit).ok_or("arena limit")?;
            let mut parser = XmppParser::new(input.as_bytes(), limits, pool.clone());
            open(&mut parser).await?;
            let error = parser
                .next_event()
                .await
                .err()
                .ok_or("expected fatal error")?;
            assert!(
                matches!(
                    (&error, expected),
                    (ParseError::NotWellFormed, "xml")
                        | (ParseError::RestrictedXml, "restricted")
                        | (ParseError::NotWellFormed, "namespace")
                        | (ParseError::NotWellFormed, "text")
                        | (ParseError::Build(BuildError::TreeLimitExceeded), "tree")
                        | (ParseError::SizeLimitExceeded { .. }, "size")
                        | (ParseError::Build(BuildError::Allocation(_)), "allocation")
                ),
                "{error:?}: {expected}"
            );
            assert_eq!(
                pool.stats().buckets.map(|bucket| bucket.available_chunks),
                before
            );
            assert!(matches!(
                parser.next_event().await,
                Err(ParseError::ParserFailed)
            ));
        }
        Ok(())
    })
}

#[test]
fn buffer_retention_reuses_small_events_and_releases_large_events() -> TestResult {
    let mut retained_capacities = Vec::new();
    for chunk in [4096, usize::MAX] {
        for (name, sizes) in [
            ("small_repeat", vec![1024; 32]),
            ("large_then_small", vec![256 * 1024, 1024, 1024]),
            ("consecutive_large", vec![256 * 1024; 4]),
        ] {
            block_on(async {
                let mut input = String::from(OPEN);
                for size in &sizes {
                    input.push_str("<message><body>");
                    input.extend(std::iter::repeat_n('x', *size));
                    input.push_str("</body></message>");
                }
                input.push_str(CLOSE);
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(512 * 1024)?,
                    GlobalChunkAllocator,
                );
                assert_eq!(parser.scratch.capacity(), 0);
                assert_eq!(parser.text.capacity(), 0);
                open(&mut parser).await?;
                let mut first = None;
                let mut capacities = Vec::new();
                for (index, size) in sizes.iter().enumerate() {
                    let before = (
                        parser.scratch.as_ptr(),
                        parser.scratch.capacity(),
                        parser.text.as_ptr(),
                        parser.text.capacity(),
                    );
                    let parsed = stanza(&mut parser).await?;
                    let view = parsed.value().resolve(parsed.arena())?;
                    let text = view
                        .child("body", CLIENT_NAMESPACE)?
                        .ok_or("body")?
                        .text()?
                        .ok_or("text")?;
                    assert_eq!(text.len(), *size);
                    assert!(text.bytes().all(|byte| byte == b'x'));
                    if index > 0 && *size == 1024 {
                        assert_eq!(parser.scratch.as_ptr(), before.0);
                        assert_eq!(parser.scratch.capacity(), before.1);
                        assert_eq!(parser.text.as_ptr(), before.2);
                        assert_eq!(parser.text.capacity(), before.3);
                    }
                    if *size > super::MAX_RETAINED_BUFFER_BYTES {
                        assert!(
                            (super::RETAINED_BUFFER_RESERVE_BYTES
                                ..=super::MAX_RETAINED_BUFFER_BYTES)
                                .contains(&parser.scratch.capacity())
                        );
                        assert!(
                            (super::RETAINED_BUFFER_RESERVE_BYTES
                                ..=super::MAX_RETAINED_BUFFER_BYTES)
                                .contains(&parser.text.capacity())
                        );
                    }
                    capacities.push((parser.scratch.capacity(), parser.text.capacity()));
                    if first.is_none() {
                        first = Some(parsed);
                    }
                }
                let first = first.ok_or("first stanza")?;
                let view = first.value().resolve(first.arena())?;
                assert_eq!(
                    view.child("body", CLIENT_NAMESPACE)?
                        .ok_or("body")?
                        .text()?
                        .ok_or("text")?
                        .len(),
                    sizes[0]
                );
                assert!(matches!(
                    parser.next_event().await?,
                    Some(StreamEvent::StreamEnd)
                ));
                eprintln!(
                    "parser retention case={name} chunk={chunk} payload_bytes={sizes:?} scratch_text_capacities={capacities:?}"
                );
                retained_capacities.extend(capacities);
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
    }
    assert!(retained_capacities.iter().all(|(scratch, text)| {
        *scratch <= super::MAX_RETAINED_BUFFER_BYTES && *text <= super::MAX_RETAINED_BUFFER_BYTES
    }));
    Ok(())
}

#[test]
fn complete_events_trim_each_buffer_independently_above_the_capacity_boundary() -> TestResult {
    let threshold = super::MAX_RETAINED_BUFFER_BYTES;
    for (scratch_capacity, text_capacity) in [
        (threshold, threshold),
        (threshold + 1, threshold),
        (threshold, threshold + 1),
        (threshold + 1, threshold + 1),
    ] {
        block_on(async {
            let input =
                format!("{OPEN}<presence/><x xmlns='urn:test'/><iq type='unknown'/>{CLOSE}");
            let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
            for event in 0..5 {
                parser.scratch = Vec::with_capacity(scratch_capacity);
                parser.text = String::with_capacity(text_capacity);
                let scratch_pointer = parser.scratch.as_ptr();
                let text_pointer = parser.text.as_ptr();
                assert_eq!(parser.scratch.capacity(), scratch_capacity);
                assert_eq!(parser.text.capacity(), text_capacity);
                let parsed = parser.next_event().await?;
                assert!(matches!(
                    (event, parsed),
                    (0, Some(StreamEvent::StreamStart { .. }))
                        | (1, Some(StreamEvent::Stanza(_)))
                        | (2, Some(StreamEvent::Element(_)))
                        | (3, Some(StreamEvent::RejectedStanza(_)))
                        | (4, Some(StreamEvent::StreamEnd))
                ));
                assert!(parser.scratch.is_empty());
                assert!(parser.text.is_empty());
                if scratch_capacity <= threshold {
                    assert_eq!(parser.scratch.capacity(), scratch_capacity);
                    assert_eq!(parser.scratch.as_ptr(), scratch_pointer);
                } else {
                    assert!(
                        (super::RETAINED_BUFFER_RESERVE_BYTES..=super::MAX_RETAINED_BUFFER_BYTES)
                            .contains(&parser.scratch.capacity())
                    );
                }
                if text_capacity <= threshold {
                    assert_eq!(parser.text.capacity(), text_capacity);
                    assert_eq!(parser.text.as_ptr(), text_pointer);
                } else {
                    assert!(
                        (super::RETAINED_BUFFER_RESERVE_BYTES..=super::MAX_RETAINED_BUFFER_BYTES)
                            .contains(&parser.text.capacity())
                    );
                }
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn failed_events_keep_the_existing_buffer_cleanup_and_parser_poisoning() -> TestResult {
    block_on(async {
        let input = format!("{OPEN}<message><body>x</body><!-- restricted -->");
        let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        let capacity = super::MAX_RETAINED_BUFFER_BYTES + 1;
        parser.scratch = Vec::with_capacity(capacity);
        parser.text = String::with_capacity(capacity);
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::RestrictedXml)
        ));
        assert_eq!(parser.scratch.capacity(), capacity);
        assert_eq!(parser.text.capacity(), capacity);
        assert!(parser.scratch.is_empty());
        assert!(parser.text.is_empty());
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::ParserFailed)
        ));
        assert!(matches!(parser.restart(), Err(ParseError::ParserFailed)));
        Ok(())
    })
}

#[test]
fn cancelling_an_incomplete_large_event_does_not_trim_accumulated_text() -> TestResult {
    block_on(async {
        let body = "x".repeat(256 * 1024);
        let input = format!("{OPEN}<message><body>{body}</bo");
        let mut source = Fragmented::new(input.as_bytes(), 4096);
        source.stall_at_end = true;
        let consumed = source.consumed.clone();
        let mut parser = XmppParser::new(source, config(512 * 1024)?, GlobalChunkAllocator);
        open(&mut parser).await?;
        {
            let mut future = pin!(parser.next_event());
            let mut context = Context::from_waker(Waker::noop());
            for _ in 0..input.len() / 4096 + 20 {
                assert!(future.as_mut().poll(&mut context).is_pending());
            }
            assert_eq!(consumed.load(Ordering::Relaxed), input.len());
        }
        assert_eq!(parser.text, body);
        assert!(parser.text.capacity() > super::MAX_RETAINED_BUFFER_BYTES);
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::ParserFailed)
        ));
        assert!(matches!(parser.restart(), Err(ParseError::ParserFailed)));
        Ok(())
    })
}

fn assert_opaque_qname_context(output: &str) -> TestResult {
    use quick_xml::events::Event;
    use quick_xml::name::{QName, ResolveResult};
    let mut reader = quick_xml::NsReader::from_str(output);
    let mut observed = 0;
    loop {
        match reader.read_event()? {
            Event::Start(start) | Event::Empty(start) => {
                let (element_namespace, local) = reader.resolver().resolve_element(start.name());
                let expected = match local.as_ref() {
                    "payload" => "urn:types",
                    "inherited" => "urn:ancestor",
                    "root-inherited" => "urn:root-types",
                    "nested" => "urn:nested",
                    "collision" => "urn:reserved",
                    "prefixed" => "urn:default",
                    "reset" => "",
                    _ => continue,
                };
                let expected_element_namespace = match local.as_ref() {
                    "prefixed" => "urn:element",
                    "reset" => "",
                    _ => "urn:payload",
                };
                match element_namespace {
                    ResolveResult::Bound(namespace) => {
                        assert_eq!(namespace.as_ref(), expected_element_namespace)
                    }
                    ResolveResult::Unbound => assert_eq!(expected_element_namespace, ""),
                    ResolveResult::Unknown(_) => return Err("unbound element namespace".into()),
                }
                let attribute = start
                    .attributes()
                    .find_map(|attribute| match attribute {
                        Ok(attribute)
                            if attribute.key.as_namespace_binding().is_none()
                                && attribute.key.local_name().as_ref() == "type" =>
                        {
                            Some(Ok(attribute))
                        }
                        Err(error) => Some(Err(error)),
                        _ => None,
                    })
                    .ok_or("missing QName attribute")??;
                let (attribute_namespace, _) = reader.resolver().resolve_attribute(attribute.key);
                if matches!(local.as_ref(), "payload" | "collision") {
                    assert!(
                        matches!(attribute_namespace, ResolveResult::Bound(namespace) if namespace.as_ref() == "http://www.w3.org/2001/XMLSchema-instance")
                    );
                } else {
                    assert!(matches!(attribute_namespace, ResolveResult::Unbound));
                }
                let value = attribute.normalized_value(quick_xml::XmlVersion::Explicit1_0)?;
                let name = QName(value.as_ref());
                let prefix = name.prefix();
                let local = name.local_name();
                assert_eq!(local.as_ref(), "Example");
                let resolved = reader.resolver().resolve_prefix(prefix, true);
                let namespace = match resolved {
                    ResolveResult::Bound(namespace) => namespace.into_inner(),
                    ResolveResult::Unbound => "",
                    ResolveResult::Unknown(_) => {
                        return Err(format!("unbound QName in {output}").into());
                    }
                };
                assert_eq!(namespace, expected, "{output}");
                observed += 1;
            }
            Event::Text(text) if text.as_ref() == "t:Example" => {
                assert!(
                    matches!(reader.resolver().resolve_prefix(QName("t:Example").prefix(), true), ResolveResult::Bound(namespace) if namespace.as_ref() == "urn:types")
                );
                observed += 1;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    assert_eq!(observed, 8, "{output}");
    Ok(())
}

fn assert_root_namespace_binding(output: &str, prefix: &str, expected: Option<&str>) -> TestResult {
    use quick_xml::events::Event;
    use quick_xml::name::{PrefixDeclaration, QName, ResolveResult};
    let mut reader = quick_xml::NsReader::from_str(output);
    let (Event::Start(start) | Event::Empty(start)) = reader.read_event()? else {
        return Err("expected root element".into());
    };
    let name = format!("{prefix}:value");
    let resolved = reader
        .resolver()
        .resolve_prefix(QName(&name).prefix(), true);
    match expected {
        Some(expected) => assert!(
            matches!(resolved, ResolveResult::Bound(namespace) if namespace.as_ref() == expected),
            "{output}"
        ),
        None => assert!(matches!(resolved, ResolveResult::Unknown(_)), "{output}"),
    }
    let mut declarations = 0;
    for attribute in start.attributes() {
        if attribute?.key.as_namespace_binding() == Some(PrefixDeclaration::Named(prefix)) {
            declarations += 1;
        }
    }
    assert_eq!(declarations, usize::from(expected.is_some()), "{output}");
    Ok(())
}

fn assert_stream_qname_context(output: &str, prefix: &str, inherited: &str) -> TestResult {
    use quick_xml::events::Event;
    use quick_xml::name::{QName, ResolveResult};
    let value = format!("{prefix}:stream");
    let mut reader = quick_xml::NsReader::from_str(output);
    let mut observed = 0;
    loop {
        let expected = match reader.read_event()? {
            Event::Start(start) | Event::Empty(start) => {
                let local = start.name().local_name();
                let expected = match local.as_ref() {
                    "stream-inherited" | "stream-following" | "stream-reset" => inherited,
                    "stream-nested" => "urn:nested-stream",
                    _ => continue,
                };
                let kind = start.try_get_attribute("kind")?.ok_or("kind")?;
                assert_eq!(kind.value.as_ref(), value, "{output}");
                let (namespace, _) = reader.resolver().resolve_element(start.name());
                if local.as_ref() == "stream-reset" {
                    assert!(matches!(namespace, ResolveResult::Unbound), "{output}");
                } else {
                    assert!(
                        matches!(namespace, ResolveResult::Bound(namespace) if namespace.as_ref() == "urn:payload"),
                        "{output}"
                    );
                }
                expected
            }
            Event::Text(text) if text.as_ref() == value => inherited,
            Event::Eof => break,
            _ => continue,
        };
        assert!(
            matches!(reader.resolver().resolve_prefix(QName(&value).prefix(), true), ResolveResult::Bound(namespace) if namespace.as_ref() == expected),
            "{output}"
        );
        observed += 1;
    }
    assert_eq!(observed, 5, "{output}");
    Ok(())
}

#[test]
fn element_root_preserves_stream_alias_with_an_empty_default_namespace() -> TestResult {
    block_on(async {
        for chunk in [1, usize::MAX] {
            let input = "<s:stream xmlns:s='http://etherx.jabber.org/streams' xmlns='jabber:client'><x xmlns='' kind='s:stream'>s:stream</x>";
            let mut parser = XmppParser::new(
                Fragmented::new(input.as_bytes(), chunk),
                config(4096)?,
                GlobalChunkAllocator,
            );
            open(&mut parser).await?;
            let Some(StreamEvent::Element(parsed)) = parser.next_event().await? else {
                return Err("expected element".into());
            };
            drop(parser);
            let view = parsed.value().resolve(parsed.arena())?;
            assert_eq!(view.namespace(), "");
            assert_eq!(view.attribute("kind", "")?, Some("s:stream"));
            assert_eq!(view.text()?, Some("s:stream"));
            let mut synchronous = String::new();
            view.write_xml(&mut synchronous)?;
            let mut asynchronous = futures_util::io::Cursor::new(Vec::new());
            view.write_xml_async(&mut asynchronous).await?;
            for output in [
                synchronous.as_str(),
                std::str::from_utf8(asynchronous.get_ref())?,
            ] {
                assert_root_namespace_binding(output, "s", Some(crate::stanza::STREAM_NAMESPACE))?;
                let mut reader = quick_xml::NsReader::from_str(output);
                let quick_xml::events::Event::Start(start) = reader.read_event()? else {
                    return Err("expected nonempty element".into());
                };
                assert!(matches!(
                    reader.resolver().resolve_element(start.name()),
                    (quick_xml::name::ResolveResult::Unbound, local) if local.as_ref() == "x"
                ));
            }
        }
        Ok(())
    })
}

#[test]
fn stream_alias_context_survives_restart_and_parser_destruction() -> TestResult {
    block_on(async {
        for chunk in [1, usize::MAX] {
            let input = "<s:stream xmlns:s='http://etherx.jabber.org/streams' xmlns='jabber:client'><message/><success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/><next:stream xmlns:next='http://etherx.jabber.org/streams' xmlns='jabber:client'><message/>";
            let mut parser = XmppParser::new(
                Fragmented::new(input.as_bytes(), chunk),
                config(4096)?,
                GlobalChunkAllocator,
            );
            open(&mut parser).await?;
            let old = stanza(&mut parser).await?;
            let Some(StreamEvent::Element(success)) = parser.next_event().await? else {
                return Err("expected success element".into());
            };
            let mut parser = parser.restart()?;
            open(&mut parser).await?;
            let new = stanza(&mut parser).await?;
            drop(parser);
            for (parsed, prefix, absent) in [(&old, "s", "next"), (&new, "next", "s")] {
                let mut output = String::new();
                parsed
                    .value()
                    .resolve(parsed.arena())?
                    .write_xml(&mut output)?;
                assert_root_namespace_binding(
                    &output,
                    prefix,
                    Some(crate::stanza::STREAM_NAMESPACE),
                )?;
                assert_root_namespace_binding(&output, absent, None)?;
            }
            let mut output = String::new();
            success
                .value()
                .resolve(success.arena())?
                .write_xml(&mut output)?;
            assert_root_namespace_binding(&output, "s", Some(crate::stanza::STREAM_NAMESPACE))?;
            assert_root_namespace_binding(&output, "next", None)?;
        }
        Ok(())
    })
}

#[test]
fn opaque_qnames_keep_namespace_context_through_writers_and_copies() -> TestResult {
    block_on(async {
        for chunk in [1, usize::MAX] {
            for prefix in ["s", "stream", "ns0"] {
                for root_shadow in [false, true] {
                    let expected = if root_shadow {
                        "urn:root-shadow"
                    } else {
                        crate::stanza::STREAM_NAMESPACE
                    };
                    let root_binding = if root_shadow {
                        format!("xmlns:{prefix}='urn:root-shadow'")
                    } else {
                        String::new()
                    };
                    let input = format!(
                        "<{prefix}:stream xmlns:{prefix}='http://etherx.jabber.org/streams' xmlns='jabber:client'><message {root_binding} xmlns:a='urn:ancestor' xmlns:w='urn:root-types'><payload xmlns='urn:payload' xmlns:t='urn:ty&#112;es' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:type='t:Example'><inherited type='a:Example'/><root-inherited type='w:Example'/><nested xmlns:a='urn:nested' type='a:Example'/><collision xmlns:ns0='urn:reserved' xsi:type='ns0:Example'/><textual>t:Example</textual><p:prefixed xmlns:p='urn:element' xmlns='urn:default' type='Example'/><reset xmlns='' type='Example'/><stream-inherited kind='{prefix}:stream'>{prefix}:stream</stream-inherited><stream-nested xmlns:{prefix}='urn:nested-stream' kind='{prefix}:stream'/><stream-following kind='{prefix}:stream'/><stream-reset xmlns='' kind='{prefix}:stream'/></payload><discard xmlns='urn:discard'/></message><message/>"
                    );
                    let mut parser = XmppParser::new(
                        Fragmented::new(input.as_bytes(), chunk),
                        config(4096)?,
                        GlobalChunkAllocator,
                    );
                    open(&mut parser).await?;
                    let (original, mut arena) = stanza(&mut parser).await?.into_parts();
                    let mut output = String::new();
                    original.resolve(&arena)?.write_xml(&mut output)?;
                    assert_opaque_qname_context(&output)?;
                    assert_stream_qname_context(&output, prefix, expected)?;
                    let mut asynchronous = futures_util::io::Cursor::new(Vec::new());
                    original
                        .resolve(&arena)?
                        .write_xml_async(&mut asynchronous)
                        .await?;
                    assert_opaque_qname_context(std::str::from_utf8(asynchronous.get_ref())?)?;
                    assert_stream_qname_context(
                        std::str::from_utf8(asynchronous.get_ref())?,
                        prefix,
                        expected,
                    )?;
                    let mut copied_arena = Arena::try_new(ArenaConfig::default())?;
                    let copied = original.resolve(&arena)?.clone_in(&mut copied_arena)?;
                    let filtered = original
                        .resolve(&arena)?
                        .to_builder_in_filtered(&mut copied_arena, |child| {
                            Ok(child.namespace() != "urn:discard")
                        })?
                        .build()?;
                    let derived = original.derive_in(&mut arena)?.build()?;
                    let error = original
                        .error_reply_in(&mut arena, StanzaErrorCondition::ServiceUnavailable)?
                        .build()?;
                    for stanza in [derived, error] {
                        output.clear();
                        stanza.resolve(&arena)?.write_xml(&mut output)?;
                        assert_opaque_qname_context(&output)?;
                        assert_stream_qname_context(&output, prefix, expected)?;
                    }
                    output.clear();
                    copied.resolve(&copied_arena)?.write_xml(&mut output)?;
                    assert_opaque_qname_context(&output)?;
                    assert_stream_qname_context(&output, prefix, expected)?;
                    output.clear();
                    filtered.resolve(&copied_arena)?.write_xml(&mut output)?;
                    assert_opaque_qname_context(&output)?;
                    assert_stream_qname_context(&output, prefix, expected)?;
                    assert!(
                        filtered
                            .resolve(&copied_arena)?
                            .child("discard", "urn:discard")?
                            .is_none()
                    );
                    let payload = original
                        .resolve(&arena)?
                        .child("payload", "urn:payload")?
                        .ok_or("payload")?
                        .handle();
                    let detached = payload.resolve(&arena)?.clone_in(&mut copied_arena)?;
                    let detached_derived = payload.derive_in(&mut arena)?.build()?;
                    output.clear();
                    detached_derived.resolve(&arena)?.write_xml(&mut output)?;
                    assert_opaque_qname_context(&output)?;
                    assert_stream_qname_context(&output, prefix, expected)?;
                    let next = stanza(&mut parser).await?;
                    let mut next_output = String::new();
                    next.value()
                        .resolve(next.arena())?
                        .write_xml(&mut next_output)?;
                    assert_root_namespace_binding(
                        &next_output,
                        prefix,
                        Some(crate::stanza::STREAM_NAMESPACE),
                    )?;
                    drop(parser);
                    drop(arena);
                    output.clear();
                    detached.resolve(&copied_arena)?.write_xml(&mut output)?;
                    assert_opaque_qname_context(&output)?;
                    assert_stream_qname_context(&output, prefix, expected)?;
                    asynchronous.get_mut().clear();
                    detached
                        .resolve(&copied_arena)?
                        .write_xml_async(&mut asynchronous)
                        .await?;
                    assert_opaque_qname_context(std::str::from_utf8(asynchronous.get_ref())?)?;
                    assert_stream_qname_context(
                        std::str::from_utf8(asynchronous.get_ref())?,
                        prefix,
                        expected,
                    )?;
                }
            }
        }
        Ok(())
    })
}

#[test]
fn derived_attributes_generate_prefixes_without_changing_opaque_values() -> TestResult {
    block_on(async {
        for (opening, declaration, expected) in [
            (OPEN, "xmlns:ns0='urn:types'", "urn:types"),
            (
                "<ns0:stream xmlns:ns0='http://etherx.jabber.org/streams' xmlns='jabber:client'>",
                "",
                crate::stanza::STREAM_NAMESPACE,
            ),
        ] {
            let input = format!(
                "{opening}<message><p:payload xmlns:p='urn:element' xmlns='urn:default' {declaration} type='ns0:Example'/></message>"
            );
            let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
            open(&mut parser).await?;
            let (original, mut arena) = stanza(&mut parser).await?.into_parts();
            let payload = original
                .resolve(&arena)?
                .child("payload", "urn:element")?
                .ok_or("payload")?
                .handle();
            let derived = payload
                .derive_in(&mut arena)?
                .attribute("flag", "urn:new", "<&\"\t")?
                .attribute("other", "urn:other", "kept")?
                .build()?;
            let mut synchronous = String::new();
            derived.resolve(&arena)?.write_xml(&mut synchronous)?;
            let mut asynchronous = futures_util::io::Cursor::new(Vec::new());
            derived
                .resolve(&arena)?
                .write_xml_async(&mut asynchronous)
                .await?;
            for output in [
                synchronous.as_str(),
                std::str::from_utf8(asynchronous.get_ref())?,
            ] {
                let mut reader = quick_xml::NsReader::from_str(output);
                let quick_xml::events::Event::Empty(start) = reader.read_event()? else {
                    return Err("expected payload".into());
                };
                assert!(
                    matches!(reader.resolver().resolve_prefix(quick_xml::name::QName("ns0:Example").prefix(), true), quick_xml::name::ResolveResult::Bound(namespace) if namespace.as_ref() == expected)
                );
                assert!(
                    matches!(reader.resolver().resolve_element(start.name()), (quick_xml::name::ResolveResult::Bound(namespace), local) if namespace.as_ref() == "urn:element" && local.as_ref() == "payload")
                );
                assert_eq!(
                    start
                        .try_get_attribute("type")?
                        .ok_or("type")?
                        .value
                        .as_ref(),
                    "ns0:Example"
                );
                assert!(
                    matches!(reader.resolver().resolve_prefix(None, true), quick_xml::name::ResolveResult::Bound(namespace) if namespace.as_ref() == "urn:default")
                );
                let mut checked = 0;
                for attribute in start.attributes() {
                    let attribute = attribute?;
                    let (namespace, local) = reader.resolver().resolve_attribute(attribute.key);
                    let expected = match local.as_ref() {
                        "flag" => Some(("urn:new", "<&\"\t")),
                        "other" => Some(("urn:other", "kept")),
                        _ => None,
                    };
                    if let Some((expected_namespace, expected_value)) = expected {
                        assert!(
                            matches!(namespace, quick_xml::name::ResolveResult::Bound(namespace) if namespace.as_ref() == expected_namespace)
                        );
                        assert_eq!(
                            attribute.normalized_value(quick_xml::XmlVersion::Explicit1_0)?,
                            expected_value
                        );
                        checked += 1;
                    }
                }
                assert_eq!(checked, 2);
            }
        }
        Ok(())
    })
}

#[test]
fn prefixed_stanza_roots_and_direct_content_children_are_rejected() -> TestResult {
    block_on(async {
        for chunk in [1, usize::MAX] {
            for namespace in ["jabber:client", "jabber:server"] {
                for name in ["message", "presence", "iq"] {
                    for default in ["jabber:client", "urn:types"] {
                        for empty in [true, false] {
                            let suffix = if empty {
                                "/>".to_owned()
                            } else {
                                format!("></c:{name}>")
                            };
                            let input = format!(
                                "{OPEN}<c:{name} xmlns:c='{namespace}' xmlns='{default}'{suffix}{CLOSE}"
                            );
                            let mut parser = XmppParser::new(
                                Fragmented::new(input.as_bytes(), chunk),
                                config(4096)?,
                                GlobalChunkAllocator,
                            );
                            open(&mut parser).await?;
                            assert!(
                                matches!(
                                    parser.next_event().await,
                                    Err(ParseError::BadNamespacePrefix)
                                ),
                                "input={input:?}, chunk={chunk}"
                            );
                        }
                    }
                }
            }
            for (root, attributes) in [
                ("message", ""),
                ("presence", ""),
                ("iq", "type='get'"),
                ("iq", "type='bogus'"),
            ] {
                for child in [
                    "body", "subject", "thread", "status", "show", "priority", "error", "x",
                ] {
                    for suffix in ["/>".to_owned(), format!(">x</c:{child}>")] {
                        let input = format!(
                            "{OPEN}<{root} {attributes}><c:{child} xmlns:c='jabber:client'{suffix}</{root}>{CLOSE}"
                        );
                        let mut parser = XmppParser::new(
                            Fragmented::new(input.as_bytes(), chunk),
                            config(4096)?,
                            GlobalChunkAllocator,
                        );
                        open(&mut parser).await?;
                        assert!(
                            matches!(
                                parser.next_event().await,
                                Err(ParseError::BadNamespacePrefix)
                            ),
                            "input={input:?}, chunk={chunk}"
                        );
                    }
                }
            }
        }
        Ok(())
    })
}

#[test]
fn extension_payload_prefixes_and_unprefixed_stanzas_keep_their_namespace_context() -> TestResult {
    block_on(async {
        for chunk in [1, usize::MAX] {
            let input = format!(
                "{OPEN}<message xmlns='jabber:client'><forwarded xmlns='urn:xmpp:forward:0'><c:message xmlns:c='jabber:client'><c:body>kept</c:body></c:message></forwarded><p:x xmlns:p='urn:x'/><body xmlns:c='jabber:client' c:flag='kept'>normal</body></message>{CLOSE}"
            );
            let mut parser = XmppParser::new(
                Fragmented::new(input.as_bytes(), chunk),
                config(4096)?,
                GlobalChunkAllocator,
            );
            open(&mut parser).await?;
            let parsed = stanza(&mut parser).await?;
            let view = parsed.value().resolve(parsed.arena())?;
            let mut output = String::new();
            view.write_xml(&mut output)?;
            assert!(output.contains("<c:message"), "{output}");
            assert!(output.contains("<c:body"), "{output}");
            assert!(output.contains("<p:x"), "{output}");
            assert!(output.contains("c:flag=\"kept\""), "{output}");
            let mut asynchronous = futures_util::io::Cursor::new(Vec::new());
            view.write_xml_async(&mut asynchronous).await?;
            assert_eq!(asynchronous.into_inner(), output.as_bytes());
            assert!(matches!(
                parser.next_event().await?,
                Some(StreamEvent::StreamEnd)
            ));
        }
        Ok(())
    })
}

#[test]
fn xml_grammar_errors_are_not_well_formed_and_poison_the_parser() -> TestResult {
    for chunk in [1, usize::MAX] {
        block_on(async {
            for malformed in [
                "<message><body></message>",
                "<message id='a' id='b'/>",
                "<message id='a<b'/>",
                "<message><body>]]></body></message>",
                "<message xmlns:a='urn:x' xmlns:b='urn:x' a:x='1' b:x='2'/>",
                "<message><1bad/></message>",
                "<message><a:b:c/></message>",
                "<message 1bad='x'/>",
                "<message id=unquoted/>",
                "<message",
                "<message id='unterminated",
                "<message id='&#invalid;'/>",
                "<message id='\0'/>",
                "<message xmlns:x='urn:\0'/>",
                "<message><body>\0</body></message>",
                "<message><body><![CDATA[\0]]></body></message>",
                "<message><body>&#0;</body></message>",
                "<message><body>&#x110000;</body></message>",
                "<message><body>&#invalid;</body></message>",
                "<?xml version='1.0'?><message/>",
                "<message><?xml version='1.0'?></message>",
            ] {
                let input = format!("{OPEN}{malformed}<presence/>{CLOSE}");
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                open(&mut parser).await?;
                let error = parser
                    .next_event()
                    .await
                    .err()
                    .ok_or("expected grammar error")?;
                assert!(
                    matches!(error, ParseError::NotWellFormed),
                    "{malformed:?}: {error:?}"
                );
                assert!(matches!(
                    parser.next_event().await,
                    Err(ParseError::ParserFailed)
                ));
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn xml_declaration_grammar_and_position_errors_are_not_well_formed() -> TestResult {
    for chunk in [1, usize::MAX] {
        block_on(async {
            for declaration in [
                "<?xml?>",
                "<?xml encoding='UTF-8'?>",
                "<?xml encoding='ISO-8859-1'?>",
                "<?xml version='1.1' unexpected='yes'?>",
                "<?xml version='1.0' unexpected='yes'?>",
                "<?xml version='1.0' standalone='invalid'?>",
                "<?xml version='1.0' standalone='yes' encoding='UTF-8'?>",
                "<?xml version='1.0' version='1.0'?>",
                "<?xml version='invalid'?>",
                "<?xml version='2.0'?>",
                "<?xml version='1.'?>",
                "<?xml version='1.0' encoding='9invalid'?>",
                " <?xml version='1.0'?>",
                "<?xml version='1.0'?><?xml version='1.0'?>",
            ] {
                let input = format!("{declaration}{OPEN}");
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                let error = parser
                    .next_event()
                    .await
                    .err()
                    .ok_or("expected declaration error")?;
                assert!(
                    matches!(error, ParseError::NotWellFormed),
                    "{declaration:?}: {error:?}"
                );
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn stream_character_data_checks_grammar_before_xmpp_structure() -> TestResult {
    for chunk in [1, usize::MAX] {
        block_on(async {
            for (text, expected) in [
                ("]]>", "not-well-formed"),
                ("\0", "not-well-formed"),
                ("\u{1}", "not-well-formed"),
                ("<![CDATA[\u{1}]]>", "not-well-formed"),
                ("<![CDATA[\u{fffe}]]>", "not-well-formed"),
                ("&#0;", "not-well-formed"),
                ("&#1;", "not-well-formed"),
                ("&#xFFFE;", "not-well-formed"),
                ("&#x110000;", "not-well-formed"),
                ("&#invalid;", "not-well-formed"),
                ("ordinary text", "unexpected-event"),
                ("<![CDATA[ordinary text]]>", "unexpected-event"),
                ("&#65;", "unexpected-event"),
                ("&unknown;", "restricted-xml"),
            ] {
                let input = format!("{OPEN}{text}{CLOSE}");
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                open(&mut parser).await?;
                let error = parser
                    .next_event()
                    .await
                    .err()
                    .ok_or("expected stream text error")?;
                assert!(
                    matches!(
                        (&error, expected),
                        (ParseError::NotWellFormed, "not-well-formed")
                            | (ParseError::UnexpectedEvent, "unexpected-event")
                            | (ParseError::RestrictedXml, "restricted-xml")
                    ),
                    "{text:?}: {error:?}"
                );
            }
            for text in [
                "ordinary text",
                "<![CDATA[ordinary text]]>",
                "&#65;",
                "]]&gt;",
            ] {
                let input = format!("{OPEN}<message><body>{text}</body></message>{CLOSE}");
                let mut parser = XmppParser::new(
                    Fragmented::new(input.as_bytes(), chunk),
                    config(4096)?,
                    GlobalChunkAllocator,
                );
                open(&mut parser).await?;
                stanza(&mut parser).await?;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

fn xml_context_attributes(lang: Option<&str>, space: Option<&str>) -> String {
    let mut attributes = String::new();
    if let Some(lang) = lang {
        attributes.push_str(&format!(" xml:lang='{lang}'"));
    }
    if let Some(space) = space {
        attributes.push_str(&format!(" xml:space='{space}'"));
    }
    attributes
}

#[test]
fn stream_language_and_iq_language_keep_payload_overrides_separate() -> TestResult {
    block_on(async {
        for (stream, iq, payload, expected) in [
            (None, None, None, None),
            (Some("es"), None, None, Some("es")),
            (Some("es"), Some("fr"), Some("de"), Some("fr")),
            (Some("es"), Some(""), Some("de"), Some("")),
            (None, Some(""), None, Some("")),
            (Some(""), None, Some("de"), None),
            (Some("x-Unchecked"), None, Some(""), Some("x-Unchecked")),
        ] {
            let input = format!(
                "{}<iq type='get' id='context'{}><query xmlns='urn:test'{}><child/></query></iq>",
                OPEN.replace('>', &format!("{}>", xml_context_attributes(stream, None))),
                xml_context_attributes(iq, None),
                xml_context_attributes(payload, None),
            );
            let mut parser = XmppParser::new(input.as_bytes(), config(4096)?, GlobalChunkAllocator);
            open(&mut parser).await?;
            let parsed = stanza(&mut parser).await?;
            let view = parsed.value().resolve(parsed.arena())?;
            assert_eq!(view.lang()?, expected);
            let query = view.child("query", "urn:test")?.ok_or("query")?;
            assert_eq!(query.attribute("lang", XML_NAMESPACE)?, payload);
            assert_eq!(
                query
                    .child("child", "urn:test")?
                    .ok_or("child")?
                    .attribute("lang", XML_NAMESPACE)?,
                None
            );
        }
        Ok(())
    })
}

#[test]
fn stream_space_is_raw_root_context_and_survives_forwarding() -> TestResult {
    block_on(async {
        let values = [
            None,
            Some("preserve"),
            Some("default"),
            Some(""),
            Some("unknown"),
            Some("Preserve"),
            Some(" preserve "),
        ];
        for stream in values {
            for iq in values {
                for payload in [None, Some("default"), Some("preserve")] {
                    let input = format!(
                        "{}<iq type='set' id='context'{}><query xmlns='urn:test'{}><child/></query></iq><message/>",
                        OPEN.replace('>', &format!("{}>", xml_context_attributes(None, stream))),
                        xml_context_attributes(None, iq),
                        xml_context_attributes(None, payload),
                    );
                    let mut parser = XmppParser::new(
                        Fragmented::new(input.as_bytes(), 1),
                        config(4096)?,
                        GlobalChunkAllocator,
                    );
                    open(&mut parser).await?;
                    let parsed = stanza(&mut parser).await?;
                    let view = parsed.value().resolve(parsed.arena())?;
                    let expected = iq.or(stream);
                    assert_eq!(view.attribute("space", XML_NAMESPACE)?, expected);
                    let query = view.child("query", "urn:test")?.ok_or("query")?;
                    assert_eq!(query.attribute("space", XML_NAMESPACE)?, payload);
                    assert_eq!(
                        query
                            .child("child", "urn:test")?
                            .ok_or("child")?
                            .attribute("space", XML_NAMESPACE)?,
                        None
                    );
                    let mut forwarded = String::new();
                    view.write_xml(&mut forwarded)?;
                    let replay = format!("{OPEN}{forwarded}");
                    let mut replay =
                        XmppParser::new(replay.as_bytes(), config(4096)?, GlobalChunkAllocator);
                    open(&mut replay).await?;
                    let replayed = stanza(&mut replay).await?;
                    assert_eq!(
                        replayed
                            .value()
                            .resolve(replayed.arena())?
                            .attribute("space", XML_NAMESPACE)?,
                        expected
                    );
                    let next = stanza(&mut parser).await?;
                    assert!(!next.has_explicit_attributes());
                    assert_eq!(
                        next.value()
                            .resolve(next.arena())?
                            .attribute("space", XML_NAMESPACE)?,
                        stream
                    );
                }
            }
        }
        Ok(())
    })
}

#[test]
fn inherited_space_obeys_wire_attribute_and_arena_limits() -> TestResult {
    block_on(async {
        for count in [MAX_ATTRIBUTES_PER_ELEMENT, MAX_ATTRIBUTES_PER_ELEMENT + 1] {
            let attributes = (0..count).map(|i| format!(" a{i}='v'")).collect::<String>();
            let input = format!(
                "{}<message{attributes}/>",
                OPEN.replace('>', " xml:space='preserve'>")
            );
            let mut parser =
                XmppParser::new(input.as_bytes(), config(16384)?, GlobalChunkAllocator);
            open(&mut parser).await?;
            if count == MAX_ATTRIBUTES_PER_ELEMENT {
                let parsed = stanza(&mut parser).await?;
                assert!(parsed.has_explicit_attributes());
                assert_eq!(
                    parsed
                        .value()
                        .resolve(parsed.arena())?
                        .attribute("space", XML_NAMESPACE)?,
                    Some("preserve")
                );
            } else {
                assert!(matches!(
                    parser.next_event().await,
                    Err(ParseError::TooManyAttributes)
                ));
            }
        }
        let large = "a".repeat(2048);
        for (stream, explicit, succeeds) in [
            (None, "", true),
            (Some(large.as_str()), "", false),
            (Some(large.as_str()), " xml:space='default'", true),
        ] {
            let input = format!(
                "{}<message extra='{large}'{explicit}/>",
                OPEN.replace('>', &format!("{}>", xml_context_attributes(None, stream)))
            );
            let mut limits = config(16384)?;
            limits.arena.max_reserved_bytes = NonZeroUsize::new(4096).ok_or("arena limit")?;
            let mut parser = XmppParser::new(input.as_bytes(), limits, GlobalChunkAllocator);
            open(&mut parser).await?;
            if succeeds {
                stanza(&mut parser).await?;
            } else {
                assert!(matches!(
                    parser.next_event().await,
                    Err(ParseError::Build(BuildError::Allocation(
                        ArenaError::ArenaLimitExceeded
                    )))
                ));
            }
        }
        let input = format!(
            "{}<message/>",
            OPEN.replace(
                '>',
                &format!(
                    " xml:space='{large}{}'>",
                    "a".repeat(MAX_STREAM_HEADER_BYTES)
                )
            )
        );
        let mut parser =
            XmppParser::new(input.as_bytes(), config(usize::MAX)?, GlobalChunkAllocator);
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::SizeLimitExceeded {
                limit: MAX_STREAM_HEADER_BYTES
            })
        ));
        Ok(())
    })
}
