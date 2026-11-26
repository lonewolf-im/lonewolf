// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use compio::io::compat::AsyncStream;
use compio::net::TcpStream;
use futures_util::io::{AsyncWrite, ReadHalf, WriteHalf};
use lonewolf_util::arena::{ArenaRead, ChunkAllocator};
use lonewolf_util::rate_limited_reader::RateLimitedReader;
use lonewolf_xmpp::parser::{ParseError, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{
    AsyncWriteError, CLIENT_NAMESPACE, SERVER_NAMESPACE, StanzaKind, StanzaNamespace, StanzaRef,
};
use lonewolf_xmpp::stream::StreamErrorCondition;
use tokio::io::{AsyncBufRead, AsyncRead, BufReader, ReadBuf};

use super::close::CloseContext;
use super::header::{
    ClientHeader, ResponseVersion, response_header_xml, response_to_from_header,
    response_version_from_header, validate_header_with_default,
};
use super::outcome::CloseOutcome;
use super::renegotiation::RecordGuard;
use super::traffic::C2sTraffic;
use crate::c2s::metrics::{C2sWorkerMetrics, RateLimit};
use crate::hosts::Hosts;
use crate::router::RoutedStanza;
use crate::xml_stream::limiter::StanzaLimiter;
use crate::xml_stream::peer_stream_error;
pub(super) use crate::xml_stream::reader::ReadMode;
use crate::xml_stream::reader::{ReadObserver, XmlReader};
use crate::xml_stream::traffic::{ObservedIo, WriteProgress};
use crate::xml_stream::writer::StreamWriter;

pub(super) const IO_BUFFER_BYTES: usize = 4_096;

pub(super) type TlsTransport = futures_rustls::server::TlsStream<
    RecordGuard<Pin<Box<AsyncStream<ObservedIo<TcpStream, C2sTraffic>>>>>,
>;
pub(super) type TlsReader = ReadHalf<TlsTransport>;
pub(super) type TlsWriter = WriteHalf<TlsTransport>;
pub(super) type XmlInput = ClosingInput<BufReader<tokio_util::compat::Compat<TlsReader>>>;

/// Separate halves keep a read pinned while the stream writes stanzas.
pub(super) struct Session<A: ChunkAllocator> {
    pub(super) reader: Reader<A>,
    pub(super) writer: Writer,
    pub(super) close: CloseContext,
    pub(super) write_progress: WriteProgress,
    selected_host_default: bool,
}

pub(super) struct Reader<A: ChunkAllocator, R = XmlInput> {
    inner: XmlReader<A, R, C2sWorkerMetrics>,
    closing: Rc<Cell<ReadMode>>,
}

impl ReadObserver for C2sWorkerMetrics {
    fn stanza_parsed(&self, kind: StanzaKind) {
        self.stanza_received(kind);
    }
    fn rate_limited(&self) {
        self.rate_limited(RateLimit::IncomingStanzasPerConnection);
    }
}

pub(super) struct Writer<W = TlsWriter> {
    stream: StreamWriter<W>,
    host: String,
    metrics: C2sWorkerMetrics,
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
        traffic: C2sTraffic,
    ) -> Self {
        let (metrics, write_progress) = traffic.into_parts();
        Self {
            reader: Reader::with_mode(parser, stanzas, closing, metrics.clone()),
            writer: Writer::new(writer, host, metrics),
            close,
            write_progress,
            selected_host_default: false,
        }
    }

    pub(super) fn use_selected_host_as_default(&mut self) {
        self.selected_host_default = true;
    }

    pub(super) async fn finish(&mut self, outcome: CloseOutcome) -> CloseOutcome {
        super::close::finish(
            &mut self.reader,
            &mut self.writer,
            outcome.into(),
            &self.close,
            self.close.deadline_for(outcome),
        )
        .await
    }

    pub(super) fn host(&self) -> &str {
        &self.writer.host
    }

    pub(super) fn restart(&mut self) -> Result<(), ParseError> {
        self.writer.restart();
        self.reader.restart()
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
                extra_header_namespaces,
            })) => {
                match validate_header_with_default(
                    &header,
                    &content_namespace,
                    extra_header_namespaces,
                    hosts,
                    if self.selected_host_default {
                        self.host()
                    } else {
                        hosts.default_host_name()
                    },
                ) {
                    Ok(header) => Ok(header),
                    Err(outcome) => {
                        let (version, outcome) = match response_version_from_header(&header) {
                            Ok(version) => (version, outcome),
                            Err(outcome) => (ResponseVersion::Current, outcome),
                        };
                        Err(self
                            .writer
                            .reject_header(
                                response_to_from_header(&header).as_deref(),
                                content_namespace == CLIENT_NAMESPACE,
                                version,
                                outcome,
                            )
                            .await)
                    }
                }
            }
            Err(ParseError::UnexpectedEof) => Err(CloseOutcome::Eof),
            Err(error) => {
                let outcome = CloseOutcome::from_parse_error(&error);
                if outcome == CloseOutcome::TlsFailure {
                    Err(outcome)
                } else {
                    Err(self
                        .writer
                        .reject_header(None, false, ResponseVersion::Current, outcome)
                        .await)
                }
            }
            Ok(_) => Err(self
                .writer
                .reject_header(
                    None,
                    false,
                    ResponseVersion::Current,
                    CloseOutcome::ParserError,
                )
                .await),
        }
    }
}

impl<A: ChunkAllocator + Clone, R: AsyncBufRead + Unpin + 'static> Reader<A, R> {
    #[cfg(test)]
    pub(super) fn new(parser: XmppParser<R, A>, stanzas: StanzaLimiter) -> Self {
        Self::with_mode(
            parser,
            stanzas,
            Rc::new(Cell::new(ReadMode::Open)),
            C2sWorkerMetrics::detached(),
        )
    }

    pub(super) fn with_mode(
        parser: XmppParser<R, A>,
        stanzas: StanzaLimiter,
        closing: Rc<Cell<ReadMode>>,
        metrics: C2sWorkerMetrics,
    ) -> Self {
        Self {
            inner: XmlReader::new(parser, stanzas, Rc::clone(&closing), metrics),
            closing,
        }
    }

    fn restart(&mut self) -> Result<(), ParseError> {
        self.inner.restart()
    }
    async fn read_event(&mut self) -> Result<Option<StreamEvent<A>>, ParseError> {
        self.inner.read_event().await
    }
    pub(super) fn is_failed(&self) -> bool {
        self.inner.is_failed()
    }

    #[cfg(test)]
    pub(super) async fn take_remaining_stanza_tokens(&mut self) -> Result<usize, ParseError> {
        self.inner
            .take_parts()
            .await
            .map(|(_, limiter, _)| limiter.available())
    }

    pub(super) fn closing(&mut self) {
        self.closing.set(ReadMode::Closing);
    }

    pub(super) async fn take_input(&mut self) -> Result<R, CloseOutcome> {
        self.inner
            .take_parts()
            .await
            .map(|(parser, _, _)| parser.into_inner())
            .map_err(|_| CloseOutcome::InternalError)
    }

    /// Open streams consume one token per complete stanza.
    pub(super) async fn next_event(&mut self) -> Result<Option<StreamEvent<A>>, CloseOutcome> {
        match self.read_event().await {
            Ok(event) => Ok(event),
            Err(ParseError::UnexpectedEof) => Err(CloseOutcome::Eof),
            Err(error) => Err(CloseOutcome::from_parse_error(&error)),
        }
    }
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub(super) fn new(output: W, host: String, metrics: C2sWorkerMetrics) -> Self {
        Self {
            stream: StreamWriter::new(output, IO_BUFFER_BYTES),
            host,
            metrics,
        }
    }

    pub(super) fn is_open(&self) -> bool {
        self.stream.is_open()
    }

    pub(super) fn set_host(&mut self, host: String) {
        self.host = host;
    }

    #[cfg(test)]
    pub(super) fn is_intact(&self) -> bool {
        self.stream.is_intact()
    }

    pub(super) fn restart(&mut self) {
        self.stream.restart();
    }

    pub(super) fn take_output(&mut self) -> Result<W, CloseOutcome> {
        self.stream.take_output().ok_or(CloseOutcome::InternalError)
    }

    /// `xml` must not switch protocols, so a stream error may follow it after a cancelled flush.
    pub(super) async fn send(&mut self, xml: &str) -> Result<(), CloseOutcome> {
        self.stream.send(xml).await.map_err(io_outcome)
    }

    /// Use for elements after which the peer leaves the current XML stream.
    pub(super) async fn send_protocol_switch(&mut self, xml: &str) -> Result<(), CloseOutcome> {
        self.stream
            .send_protocol_switch(xml)
            .await
            .map_err(io_outcome)
    }

    /// `xml` must contain one complete stanza of `kind`.
    pub(super) async fn send_stanza_xml(
        &mut self,
        xml: &str,
        kind: StanzaKind,
    ) -> Result<(), CloseOutcome> {
        self.send(xml).await?;
        self.metrics.stanza_sent(kind);
        Ok(())
    }

    /// The caller must flush buffered output.
    pub(super) async fn write_stanza<R: ArenaRead>(
        &mut self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<(), CloseOutcome> {
        self.stream
            .write_stanza(stanza, stanza.namespace())
            .await
            .map_err(|error| match error {
                AsyncWriteError::Access(_) => CloseOutcome::InternalError,
                AsyncWriteError::Output(error) => CloseOutcome::from_io_error(&error),
            })?;
        self.metrics.stanza_sent(stanza.kind());
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
            ResponseVersion::Current,
        )?;
        self.stream.send_header(&xml).await.map_err(io_outcome)
    }

    pub(super) async fn reject_header(
        &mut self,
        to: Option<&str>,
        client_content_namespace: bool,
        version: ResponseVersion<'_>,
        outcome: CloseOutcome,
    ) -> CloseOutcome {
        let header = match response_header_xml(&self.host, to, client_content_namespace, version) {
            Ok(header) => header,
            Err(outcome) => return outcome,
        };
        self.stream
            .send_header(&header)
            .await
            .map_err(io_outcome)
            .err()
            .unwrap_or(outcome)
    }

    pub(super) async fn close(
        &mut self,
        condition: Option<StreamErrorCondition>,
    ) -> Result<bool, CloseOutcome> {
        self.stream.close(condition).await.map_err(io_outcome)
    }

    pub(super) async fn flush(&mut self) -> Result<(), CloseOutcome> {
        self.stream.flush().await.map_err(io_outcome)
    }
}

fn io_outcome(error: io::Error) -> CloseOutcome {
    CloseOutcome::from_io_error(&error)
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
