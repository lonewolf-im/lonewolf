// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use compio::io::compat::AsyncStream;
use compio::net::TcpStream;
use futures_util::io::{AsyncWrite, AsyncWriteExt as _, BufWriter, ReadHalf, WriteHalf};
use lonewolf_util::arena::{ArenaRead, ChunkAllocator};
use lonewolf_util::rate_limited_reader::RateLimitedReader;
use lonewolf_xmpp::parser::{ParseError, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{
    AsyncWriteError, CLIENT_NAMESPACE, NodeRef, SERVER_NAMESPACE, StanzaNamespace, StanzaRef,
};
use lonewolf_xmpp::stream::{STREAM_ERROR_NAMESPACE, StreamErrorCondition};
use tokio::io::{AsyncBufRead, AsyncRead, BufReader, ReadBuf};

use super::close::CloseContext;
use super::header::{ClientHeader, response_header_xml, response_to_from_header, validate_header};
use super::outcome::CloseOutcome;
use super::stanza_rate::StanzaLimiter;
use crate::hosts::Hosts;
use crate::router::RoutedStanza;

pub(super) const IO_BUFFER_BYTES: usize = 4_096;

pub(super) type TlsTransport = futures_rustls::server::TlsStream<Pin<Box<AsyncStream<TcpStream>>>>;
pub(super) type TlsReader = ReadHalf<TlsTransport>;
pub(super) type TlsWriter = WriteHalf<TlsTransport>;
pub(super) type XmlInput = ClosingInput<BufReader<tokio_util::compat::Compat<TlsReader>>>;

/// Separate halves keep a read pinned while the stream writes stanzas.
pub(super) struct Session<A: ChunkAllocator> {
    pub(super) reader: Reader<A>,
    pub(super) writer: Writer,
    pub(super) close: CloseContext,
}

pub(super) struct Reader<A: ChunkAllocator, R = XmlInput> {
    ready: Option<ReadState<A, R>>,
    pending: Option<PendingRead<A, R>>,
    closing: Rc<Cell<ReadMode>>,
    failed: bool,
}

struct ReadState<A: ChunkAllocator, R> {
    parser: XmppParser<R, A>,
    stanzas: StanzaLimiter,
}

type ReadResult<A, R> = (ReadState<A, R>, Result<Option<StreamEvent<A>>, ParseError>);
type PendingRead<A, R> = Pin<Box<dyn Future<Output = ReadResult<A, R>>>>;

pub(super) struct Writer<W = TlsWriter> {
    output: Option<BufWriter<W>>,
    host: String,
    intact: bool,
    open: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ReadMode {
    Open,
    Closing,
    AbandonParser,
}

pub(super) struct ClosingInput<R> {
    input: RateLimitedReader<R>,
    closing: Rc<Cell<ReadMode>>,
}

impl<R> ClosingInput<R> {
    pub(super) fn new(input: RateLimitedReader<R>, closing: Rc<Cell<ReadMode>>) -> Self {
        Self { input, closing }
    }

    pub(super) fn into_rate_limited(self) -> RateLimitedReader<R> {
        self.input
    }

    pub(super) fn into_inner(self) -> R {
        self.input.into_inner()
    }
}

impl<R: AsyncBufRead + Unpin> AsyncBufRead for ClosingInput<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.closing.get() == ReadMode::Open {
            Pin::new(&mut this.input).poll_fill_buf(cx)
        } else {
            Pin::new(this.input.get_mut()).poll_fill_buf(cx)
        }
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        if this.closing.get() == ReadMode::Open {
            Pin::new(&mut this.input).consume(amount);
        } else {
            Pin::new(this.input.get_mut()).consume(amount);
        }
    }
}

impl<R: AsyncBufRead + Unpin> AsyncRead for ClosingInput<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let available = std::task::ready!(self.as_mut().poll_fill_buf(cx))?;
        let amount = available.len().min(output.remaining());
        output.put_slice(&available[..amount]);
        self.consume(amount);
        Poll::Ready(Ok(()))
    }
}

impl<A: ChunkAllocator + Clone> Session<A> {
    pub(super) fn new(
        parser: XmppParser<XmlInput, A>,
        writer: TlsWriter,
        host: String,
        stanzas: StanzaLimiter,
        closing: Rc<Cell<ReadMode>>,
        close: CloseContext,
    ) -> Self {
        Self {
            reader: Reader::with_mode(parser, stanzas, closing),
            writer: Writer::new(writer, host),
            close,
        }
    }

    pub(super) async fn finish(&mut self, outcome: CloseOutcome) -> CloseOutcome {
        super::close::finish(
            &mut self.reader,
            &mut self.writer,
            outcome.into(),
            &self.close,
            self.close.deadline(),
        )
        .await
    }

    pub(super) fn host(&self) -> &str {
        &self.writer.host
    }

    pub(super) async fn restart(self) -> Result<Self, CloseOutcome> {
        let Self {
            reader,
            mut writer,
            close,
        } = self;
        writer.open = false;
        match reader.restart() {
            Ok(reader) => Ok(Self {
                reader,
                writer,
                close,
            }),
            Err(_) => Err(writer
                .reject_header(None, false, CloseOutcome::ParserError)
                .await),
        }
    }

    pub(super) async fn next_event(&mut self) -> Result<Option<StreamEvent<A>>, CloseOutcome> {
        let event = self.reader.next_event().await?;
        if let Some(event) = event.as_ref()
            && let Some(condition) = peer_stream_error(event)?
        {
            return Err(CloseOutcome::PeerError(condition));
        }
        Ok(event)
    }

    pub(super) async fn read_header(
        &mut self,
        hosts: &Hosts,
    ) -> Result<ClientHeader, CloseOutcome> {
        match self.reader.read_event().await {
            Ok(Some(StreamEvent::StreamStart {
                header,
                content_namespace,
            })) => match validate_header(&header, &content_namespace, hosts) {
                Ok(header) => Ok(header),
                Err(outcome) => Err(self
                    .writer
                    .reject_header(
                        response_to_from_header(&header).as_deref(),
                        content_namespace == CLIENT_NAMESPACE,
                        outcome,
                    )
                    .await),
            },
            Err(ParseError::UnexpectedEof) => Err(CloseOutcome::Eof),
            Err(error) => Err(self
                .writer
                .reject_header(None, false, CloseOutcome::from_parse_error(&error))
                .await),
            Ok(_) => Err(self
                .writer
                .reject_header(None, false, CloseOutcome::ParserError)
                .await),
        }
    }
}

impl<A: ChunkAllocator + Clone, R: AsyncBufRead + Unpin + 'static> Reader<A, R> {
    #[cfg(test)]
    pub(super) fn new(parser: XmppParser<R, A>, stanzas: StanzaLimiter) -> Self {
        Self::with_mode(parser, stanzas, Rc::new(Cell::new(ReadMode::Open)))
    }

    pub(super) fn with_mode(
        parser: XmppParser<R, A>,
        stanzas: StanzaLimiter,
        closing: Rc<Cell<ReadMode>>,
    ) -> Self {
        Self {
            ready: Some(ReadState { parser, stanzas }),
            pending: None,
            closing,
            failed: false,
        }
    }

    fn restart(mut self) -> Result<Self, ParseError> {
        let Some(state) = self.ready.take() else {
            return Err(ParseError::ParserFailed);
        };
        self.ready = Some(ReadState {
            parser: state.parser.restart()?,
            stanzas: state.stanzas,
        });
        Ok(self)
    }

    async fn read_event(&mut self) -> Result<Option<StreamEvent<A>>, ParseError> {
        if self.pending.is_none() {
            let Some(mut state) = self.ready.take() else {
                return Err(ParseError::ParserFailed);
            };
            let closing = Rc::clone(&self.closing);
            self.pending = Some(Box::pin(async move {
                let event = {
                    let mut next = std::pin::pin!(state.parser.next_event());
                    poll_fn(|cx| {
                        if closing.get() == ReadMode::AbandonParser {
                            Poll::Ready(Err(ParseError::ParserFailed))
                        } else {
                            next.as_mut().poll(cx)
                        }
                    })
                    .await
                };
                if matches!(
                    event,
                    Ok(Some(
                        StreamEvent::Stanza(_) | StreamEvent::RejectedStanza(_)
                    ))
                ) {
                    let mut acquire = std::pin::pin!(state.stanzas.acquire());
                    poll_fn(|cx| {
                        if closing.get() != ReadMode::Open {
                            std::task::Poll::Ready(())
                        } else {
                            acquire.as_mut().poll(cx)
                        }
                    })
                    .await;
                }
                (state, event)
            }));
        }
        let Some(pending) = &mut self.pending else {
            return Err(ParseError::ParserFailed);
        };
        let (state, result) = pending.await;
        self.pending = None;
        self.ready = Some(state);
        self.failed = result.is_err();
        result
    }

    pub(super) fn is_failed(&self) -> bool {
        self.failed
    }

    pub(super) fn closing(&mut self) {
        self.closing.set(ReadMode::Closing);
    }

    pub(super) async fn take_input(&mut self) -> Result<R, CloseOutcome> {
        if self.pending.is_some() {
            self.closing.set(ReadMode::AbandonParser);
            let _ = self.read_event().await;
        }
        self.ready
            .take()
            .map(|state| state.parser.into_inner())
            .ok_or(CloseOutcome::InternalError)
    }

    /// Each complete stanza consumes one token before its caller can process it.
    pub(super) async fn next_event(&mut self) -> Result<Option<StreamEvent<A>>, CloseOutcome> {
        match self.read_event().await {
            Ok(event) => Ok(event),
            Err(ParseError::UnexpectedEof) => Err(CloseOutcome::Eof),
            Err(error) => Err(CloseOutcome::from_parse_error(&error)),
        }
    }
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub(super) fn new(output: W, host: String) -> Self {
        Self {
            output: Some(BufWriter::with_capacity(IO_BUFFER_BYTES, output)),
            host,
            intact: true,
            open: false,
        }
    }

    pub(super) fn is_open(&self) -> bool {
        self.open
    }

    pub(super) fn set_host(&mut self, host: String) {
        self.host = host;
    }

    pub(super) fn is_intact(&self) -> bool {
        self.intact
    }

    pub(super) fn take_output(&mut self) -> Result<W, CloseOutcome> {
        self.output
            .take()
            .map(BufWriter::into_inner)
            .ok_or(CloseOutcome::InternalError)
    }

    pub(super) async fn send(&mut self, xml: &str) -> Result<(), CloseOutcome> {
        self.intact = false;
        self.output
            .as_mut()
            .ok_or(CloseOutcome::TransportError)?
            .write_all(xml.as_bytes())
            .await
            .map_err(|_| CloseOutcome::TransportError)?;
        self.intact = true;
        self.flush().await
    }

    /// The caller must flush buffered output.
    pub(super) async fn write_stanza<R: ArenaRead>(
        &mut self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<(), CloseOutcome> {
        self.intact = false;
        stanza
            .write_xml_async(self.output.as_mut().ok_or(CloseOutcome::TransportError)?)
            .await
            .map_err(|error| match error {
                AsyncWriteError::Access(_) => CloseOutcome::InternalError,
                AsyncWriteError::Output(_) => CloseOutcome::TransportError,
            })?;
        self.intact = true;
        Ok(())
    }

    pub(super) async fn write_routed<A: ChunkAllocator>(
        &mut self,
        stanza: &RoutedStanza<A>,
    ) -> Result<(), CloseOutcome> {
        let view = stanza.resolve()?;
        self.write_stanza(&view).await
    }

    pub(super) async fn send_header(&mut self, header: &ClientHeader) -> Result<(), CloseOutcome> {
        let xml = response_header_xml(
            &self.host,
            header.response_to.as_deref(),
            header.client_content_namespace,
            true,
        )?;
        self.send(&xml).await?;
        self.open = true;
        Ok(())
    }

    pub(super) async fn reject_header(
        &mut self,
        to: Option<&str>,
        client_content_namespace: bool,
        outcome: CloseOutcome,
    ) -> CloseOutcome {
        let header = match response_header_xml(
            &self.host,
            to,
            client_content_namespace,
            outcome != CloseOutcome::UnsupportedVersion,
        ) {
            Ok(header) => header,
            Err(outcome) => return outcome,
        };
        if self.send(&header).await.is_err() {
            return CloseOutcome::TransportError;
        }
        self.open = true;
        outcome
    }

    pub(super) async fn flush(&mut self) -> Result<(), CloseOutcome> {
        if self
            .output
            .as_mut()
            .ok_or(CloseOutcome::TransportError)?
            .flush()
            .await
            .is_err()
        {
            self.intact = false;
            return Err(CloseOutcome::TransportError);
        }
        Ok(())
    }
}

pub(super) fn namespace_error<A: ChunkAllocator>(event: &StreamEvent<A>) -> Option<CloseOutcome> {
    match event {
        StreamEvent::Stanza(parsed) => match parsed.value().resolve(parsed.arena()) {
            Ok(stanza) if stanza.namespace() != StanzaNamespace::Client => {
                Some(CloseOutcome::InvalidNamespace)
            }
            Ok(_) => None,
            Err(_) => Some(CloseOutcome::InternalError),
        },
        StreamEvent::RejectedStanza(parsed) => (parsed.value().namespace()
            != StanzaNamespace::Client)
            .then_some(CloseOutcome::InvalidNamespace),
        StreamEvent::Element(parsed) => match parsed.value().resolve(parsed.arena()) {
            Ok(element) if element.namespace() == SERVER_NAMESPACE => {
                Some(CloseOutcome::InvalidNamespace)
            }
            Ok(_) => None,
            Err(_) => Some(CloseOutcome::InternalError),
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests;

pub(super) fn peer_stream_error<A: ChunkAllocator>(
    event: &StreamEvent<A>,
) -> Result<Option<StreamErrorCondition>, CloseOutcome> {
    let StreamEvent::Element(parsed) = event else {
        return Ok(None);
    };
    let element = parsed.value().resolve(parsed.arena())?;
    if element.namespace() != "http://etherx.jabber.org/streams" || element.name() != "error" {
        return Ok(None);
    }
    let mut condition = None;
    for child in element.children()? {
        if let NodeRef::Element(child) = child?
            && child.namespace() == STREAM_ERROR_NAMESPACE
            && child.name() != "text"
        {
            if condition.is_some() {
                return Ok(Some(StreamErrorCondition::UndefinedCondition));
            }
            condition = Some(
                StreamErrorCondition::from_name(child.name())
                    .unwrap_or(StreamErrorCondition::UndefinedCondition),
            );
        }
    }
    Ok(Some(
        condition.unwrap_or(StreamErrorCondition::UndefinedCondition),
    ))
}
