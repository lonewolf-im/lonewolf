// SPDX-License-Identifier: Apache-2.0

//! Parses UTF-8 XML 1.0 streams with XMPP restrictions and bounded event sizes.
//!
//! Each parsed value owns a separate arena and can outlive the parser.

use std::fmt;
use std::num::NonZeroUsize;
use std::pin::Pin;

use compio_io::compat::AsyncReadStream;
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use quick_xml::events::{BytesDecl, BytesStart, Event};
use quick_xml::name::NamespaceResolver;
use quick_xml::reader::Reader;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

use crate::stanza::incoming::{Completed, Frame};
use crate::stanza::{
    BuildError, Element, MAX_ELEMENT_DEPTH, MAX_ELEMENT_NODES, STREAM_NAMESPACE, Stanza,
    XML_NAMESPACE,
};

mod input;
mod names;

use input::{InputLimit, LimitedReader};

/// Applies separately to the XML declaration, stream header, and stream footer.
pub const MAX_STREAM_HEADER_BYTES: usize = 16 * 1024;
/// Includes namespace declarations in the per-element count.
pub const MAX_ATTRIBUTES_PER_ELEMENT: usize = 256;

#[derive(Clone, Copy, Debug)]
pub struct ParserConfig {
    /// Counts wire bytes per top-level element, including markup.
    /// Excludes stream whitespace.
    pub max_stanza_bytes: NonZeroUsize,
    /// Applies per parsed value, excluding parser scratch buffers.
    pub arena: ArenaConfig,
}

pub struct Parsed<T, A: ChunkAllocator> {
    value: T,
    arena: Arena<A>,
}

impl<T: Copy, A: ChunkAllocator> Parsed<T, A> {
    pub fn value(&self) -> T {
        self.value
    }

    pub fn arena(&self) -> &Arena<A> {
        &self.arena
    }

    pub fn into_parts(self) -> (T, Arena<A>) {
        (self.value, self.arena)
    }
}

pub enum StreamEvent<A: ChunkAllocator> {
    StreamStart {
        header: Parsed<Element, A>,
        content_namespace: String,
    },
    Stanza(Parsed<Stanza, A>),
    Element(Parsed<Element, A>),
    StreamEnd,
}

#[derive(Debug)]
pub enum ParseError {
    Xml(quick_xml::Error),
    Build(BuildError),
    SizeLimitExceeded { limit: usize },
    TooManyAttributes,
    InvalidXml,
    InvalidNamespace,
    UnsupportedEncoding,
    UnsupportedVersion,
    RestrictedXml,
    UnexpectedEvent,
    UnexpectedEof,
    InvalidStanzaType,
    ParserFailed,
}

pub struct XmppParser<R, A: ChunkAllocator> {
    reader: Reader<LimitedReader<R>>,
    namespaces: NamespaceResolver,
    config: ParserConfig,
    allocator: A,
    scratch: Vec<u8>,
    text: String,
    frames: Vec<Frame>,
    stream_lang: String,
    phase: Phase,
    failed: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Initial,
    Open,
    Closed,
}

/// Retains receive buffers and runs on the caller's executor.
pub fn compio_reader<R: compio_io::AsyncRead + Unpin + 'static>(
    reader: Pin<&mut AsyncReadStream<R>>,
) -> Compat<Pin<&mut AsyncReadStream<R>>> {
    reader.compat()
}

impl<R, A: ChunkAllocator> XmppParser<R, A> {
    pub fn new(reader: R, config: ParserConfig, allocator: A) -> Self {
        Self {
            reader: Reader::from_reader(LimitedReader::new(reader, MAX_STREAM_HEADER_BYTES)),
            namespaces: NamespaceResolver::default(),
            config,
            allocator,
            scratch: Vec::new(),
            text: String::new(),
            frames: Vec::new(),
            stream_lang: String::new(),
            phase: Phase::Initial,
            failed: false,
        }
    }

    /// Resets stream context while preserving unread transport bytes.
    ///
    /// Requires an open stream between completed events.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::ParserFailed`] after a failed or cancelled read.
    /// Returns [`ParseError::UnexpectedEvent`] if the stream is not open.
    pub fn restart(mut self) -> Result<Self, ParseError> {
        if self.failed {
            return Err(ParseError::ParserFailed);
        }
        if self.phase != Phase::Open {
            return Err(ParseError::UnexpectedEvent);
        }
        let mut input = self.reader.into_inner();
        input.reset(MAX_STREAM_HEADER_BYTES);
        self.reader = Reader::from_reader(input);
        self.namespaces = NamespaceResolver::default();
        self.stream_lang.clear();
        self.phase = Phase::Initial;
        Ok(self)
    }

    /// Preserves buffered transport bytes beyond the last completed event.
    pub fn into_inner(self) -> R {
        self.reader.into_inner().inner
    }
}

impl<R: AsyncBufRead + Unpin, A: ChunkAllocator + Clone> XmppParser<R, A> {
    /// Returns `None` only after [`StreamEvent::StreamEnd`].
    ///
    /// An error or cancellation after the first poll makes the parser unusable.
    /// The incomplete event's arena is dropped in either case.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::ParserFailed`] after a failed or cancelled read.
    /// Input violations return the matching [`ParseError`] variant;
    /// transport errors use [`ParseError::Xml`], and arena or stanza validation
    /// failures use [`ParseError::Build`]. EOF before the stream footer returns
    /// [`ParseError::UnexpectedEof`].
    pub async fn next_event(&mut self) -> Result<Option<StreamEvent<A>>, ParseError> {
        if self.failed {
            return Err(ParseError::ParserFailed);
        }
        if self.phase == Phase::Closed {
            return Ok(None);
        }
        // Cancellation skips cleanup below, so failure must be recorded before awaiting.
        self.failed = true;
        let mut scratch = std::mem::take(&mut self.scratch);
        let result = self.read_next(&mut scratch).await;
        scratch.clear();
        self.scratch = scratch;
        self.text.clear();
        self.frames.clear();
        if result.is_ok() {
            self.failed = false;
        }
        result.map(Some)
    }

    async fn read_next(&mut self, scratch: &mut Vec<u8>) -> Result<StreamEvent<A>, ParseError> {
        let mut arena = None;
        let mut nodes = 0;
        let mut declaration_seen = false;
        let mut declaration_allowed = false;
        if self.phase == Phase::Initial {
            let input = self.reader.get_mut();
            if input
                .fill_buf()
                .await
                .map_err(quick_xml::Error::from)?
                .first()
                == Some(&0xef)
            {
                if input.whitespace_skipped {
                    return Err(ParseError::UnexpectedEvent);
                }
                let mut bom = [0; 3];
                input
                    .read_exact(&mut bom)
                    .await
                    .map_err(quick_xml::Error::from)?;
                if bom != [0xef, 0xbb, 0xbf] {
                    return Err(ParseError::UnsupportedEncoding);
                }
                input.skip_whitespace();
            }
            match input
                .fill_buf()
                .await
                .map_err(quick_xml::Error::from)?
                .first()
            {
                Some(b'<') => {}
                None => return Err(ParseError::UnexpectedEof),
                _ => return Err(ParseError::UnexpectedEvent),
            }
            declaration_allowed = !input.whitespace_skipped;
        }
        loop {
            scratch.clear();
            let event = self.reader.read_event_into_async(scratch).await?;
            match event {
                Event::Decl(declaration) => {
                    if self.phase != Phase::Initial || declaration_seen || !declaration_allowed {
                        return Err(ParseError::UnexpectedEvent);
                    }
                    validate_declaration(&declaration)?;
                    declaration_seen = true;
                    self.reader.get_mut().reset(MAX_STREAM_HEADER_BYTES);
                }
                Event::Start(ref start) | Event::Empty(ref start) => {
                    let empty = matches!(event, Event::Empty(_));
                    self.flush_text(arena.as_mut(), &mut nodes)?;
                    if self.frames.len() == MAX_ELEMENT_DEPTH {
                        return Err(BuildError::TreeLimitExceeded.into());
                    }
                    count_node(&mut nodes)?;
                    names::push(&mut self.namespaces, start)?;
                    if self.phase == Phase::Initial {
                        let (name, namespace) = names::element(&self.namespaces, start)?;
                        if empty || name != "stream" || namespace != STREAM_NAMESPACE {
                            return Err(ParseError::UnexpectedEvent);
                        }
                        let mut header_arena =
                            Arena::try_new_in(self.config.arena, self.allocator.clone())
                                .map_err(BuildError::from)?;
                        let header =
                            names::frame(&self.namespaces, start, &mut header_arena, false, "")?
                                .finish(&mut header_arena)?;
                        let Completed::Element(value) = header else {
                            return Err(ParseError::UnexpectedEvent);
                        };
                        let content_namespace = names::content_namespace(&self.namespaces)?.into();
                        if let Some(lang) = value
                            .resolve(&header_arena)
                            .map_err(BuildError::from)?
                            .attribute("lang", XML_NAMESPACE)
                            .map_err(BuildError::from)?
                        {
                            self.stream_lang.push_str(lang);
                        }
                        self.phase = Phase::Open;
                        self.reader
                            .get_mut()
                            .reset(self.config.max_stanza_bytes.get());
                        return Ok(StreamEvent::StreamStart {
                            header: Parsed {
                                value,
                                arena: header_arena,
                            },
                            content_namespace,
                        });
                    }
                    if self.frames.is_empty() {
                        let (name, namespace) = names::element(&self.namespaces, start)?;
                        if name == "stream" && namespace == STREAM_NAMESPACE {
                            return Err(ParseError::UnexpectedEvent);
                        }
                    }
                    if arena.is_none() {
                        arena = Some(
                            Arena::try_new_in(self.config.arena, self.allocator.clone())
                                .map_err(BuildError::from)?,
                        );
                    }
                    let current = arena.as_mut().ok_or(ParseError::UnexpectedEvent)?;
                    let frame = names::frame(
                        &self.namespaces,
                        start,
                        current,
                        self.frames.is_empty(),
                        &self.stream_lang,
                    )?;
                    if empty {
                        self.namespaces.pop();
                        if let Some(event) = self.finish_frame(frame, &mut arena)? {
                            return Ok(event);
                        }
                    } else {
                        self.frames.push(frame);
                    }
                }
                Event::End(_) => {
                    self.flush_text(arena.as_mut(), &mut nodes)?;
                    self.namespaces.pop();
                    if let Some(frame) = self.frames.pop() {
                        if let Some(event) = self.finish_frame(frame, &mut arena)? {
                            return Ok(event);
                        }
                    } else if self.phase == Phase::Open {
                        self.phase = Phase::Closed;
                        return Ok(StreamEvent::StreamEnd);
                    } else {
                        return Err(ParseError::UnexpectedEvent);
                    }
                }
                Event::Text(text) => {
                    if self.frames.is_empty() {
                        return Err(ParseError::UnexpectedEvent);
                    }
                    if text.as_ref().windows(3).any(|bytes| bytes == b"]]>") {
                        return Err(ParseError::InvalidXml);
                    }
                    self.text
                        .push_str(&text.xml10_content().map_err(quick_xml::Error::from)?);
                }
                Event::CData(text) => {
                    if self.frames.is_empty() {
                        return Err(ParseError::UnexpectedEvent);
                    }
                    self.text
                        .push_str(&text.xml10_content().map_err(quick_xml::Error::from)?);
                }
                Event::GeneralRef(reference) => {
                    if self.frames.is_empty() {
                        return Err(ParseError::UnexpectedEvent);
                    }
                    if let Some(ch) = reference.resolve_char_ref()? {
                        self.text.push(ch);
                    } else {
                        let name = reference.decode().map_err(quick_xml::Error::from)?;
                        let replacement = quick_xml::escape::resolve_predefined_entity(&name)
                            .ok_or(ParseError::RestrictedXml)?;
                        self.text.push_str(replacement);
                    }
                }
                Event::Comment(_) | Event::PI(_) | Event::DocType(_) => {
                    return Err(ParseError::RestrictedXml);
                }
                Event::Eof => return Err(ParseError::UnexpectedEof),
            }
        }
    }

    fn flush_text(
        &mut self,
        arena: Option<&mut Arena<A>>,
        nodes: &mut usize,
    ) -> Result<(), ParseError> {
        if self.text.is_empty() {
            return Ok(());
        }
        count_node(nodes)?;
        let frame = self.frames.last_mut().ok_or(ParseError::UnexpectedEvent)?;
        frame.text(&self.text, arena.ok_or(ParseError::UnexpectedEvent)?)?;
        self.text.clear();
        Ok(())
    }

    fn finish_frame(
        &mut self,
        frame: Frame,
        arena: &mut Option<Arena<A>>,
    ) -> Result<Option<StreamEvent<A>>, ParseError> {
        let current = arena.as_mut().ok_or(ParseError::UnexpectedEvent)?;
        let completed = frame.finish(current)?;
        if let Some(parent) = self.frames.last_mut() {
            let Completed::Element(element) = completed else {
                return Err(ParseError::UnexpectedEvent);
            };
            parent.child(element, current)?;
            Ok(None)
        } else {
            let arena = arena.take().ok_or(ParseError::UnexpectedEvent)?;
            self.reader
                .get_mut()
                .reset(self.config.max_stanza_bytes.get());
            Ok(Some(completed_event(completed, arena)))
        }
    }
}

fn count_node(nodes: &mut usize) -> Result<(), ParseError> {
    if *nodes == MAX_ELEMENT_NODES {
        return Err(BuildError::TreeLimitExceeded.into());
    }
    *nodes += 1;
    Ok(())
}

fn completed_event<A: ChunkAllocator>(completed: Completed, arena: Arena<A>) -> StreamEvent<A> {
    match completed {
        Completed::Element(value) => StreamEvent::Element(Parsed { value, arena }),
        Completed::Stanza(value) => StreamEvent::Stanza(Parsed { value, arena }),
    }
}

fn validate_declaration(declaration: &BytesDecl<'_>) -> Result<(), ParseError> {
    let declaration =
        std::str::from_utf8(declaration.as_ref()).map_err(|_| ParseError::InvalidXml)?;
    let start = BytesStart::from_content(declaration, 3);
    let mut previous = 0;
    for attribute in start.attributes() {
        let attribute = attribute.map_err(quick_xml::Error::from)?;
        let order = match attribute.key.as_ref() {
            b"version" if attribute.value.as_ref() == b"1.0" => 1,
            b"version" => return Err(ParseError::UnsupportedVersion),
            b"encoding" if attribute.value.eq_ignore_ascii_case(b"UTF-8") => 2,
            b"encoding" => return Err(ParseError::UnsupportedEncoding),
            b"standalone" if matches!(attribute.value.as_ref(), b"yes" | b"no") => 3,
            _ => return Err(ParseError::InvalidXml),
        };
        if order <= previous || (previous == 0 && order != 1) {
            return Err(ParseError::InvalidXml);
        }
        previous = order;
    }
    if previous == 0 {
        return Err(ParseError::InvalidXml);
    }
    Ok(())
}

impl From<quick_xml::Error> for ParseError {
    fn from(error: quick_xml::Error) -> Self {
        if let quick_xml::Error::Io(error) = &error
            && let Some(limit) = error
                .get_ref()
                .and_then(|error| error.downcast_ref::<InputLimit>())
        {
            return Self::SizeLimitExceeded { limit: limit.0 };
        }
        Self::Xml(error)
    }
}

impl From<BuildError> for ParseError {
    fn from(error: BuildError) -> Self {
        Self::Build(error)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Xml(_) | Self::InvalidXml => "invalid XML input",
            Self::Build(_) => "cannot build incoming XML element",
            Self::SizeLimitExceeded { .. } => "XML input exceeds the byte limit",
            Self::TooManyAttributes => "too many XML attributes",
            Self::InvalidNamespace => "invalid XML namespace",
            Self::UnsupportedEncoding => "XMPP requires UTF-8 input",
            Self::UnsupportedVersion => "XMPP requires XML 1.0",
            Self::RestrictedXml => "restricted XML construct",
            Self::UnexpectedEvent => "unexpected XML stream event",
            Self::UnexpectedEof => "XML stream ended without a closing tag",
            Self::InvalidStanzaType => "invalid stanza type",
            Self::ParserFailed => "parser failed or its read was cancelled",
        })
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Xml(error) => Some(error),
            Self::Build(error) => Some(error),
            _ => None,
        }
    }
}
