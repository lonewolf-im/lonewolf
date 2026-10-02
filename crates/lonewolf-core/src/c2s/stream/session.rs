// SPDX-License-Identifier: Apache-2.0

use std::pin::Pin;

use compio::io::compat::AsyncStream;
use compio::net::TcpStream;
use futures_util::io::{AsyncWrite, AsyncWriteExt as _, BufWriter, ReadHalf, WriteHalf};
use lonewolf_util::arena::{ArenaRead, ChunkAllocator};
use lonewolf_util::rate_limited_reader::RateLimitedReader;
use lonewolf_xmpp::parser::{ParseError, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{
    AsyncWriteError, CLIENT_NAMESPACE, SERVER_NAMESPACE, StanzaNamespace, StanzaRef,
};
use tokio::io::{AsyncBufRead, BufReader};

use super::header::{
    ClientHeader, STREAM_FOOTER, response_header_xml, response_to_from_header, stream_error_xml,
    validate_header,
};
use super::outcome::CloseOutcome;
use super::stanza_rate::StanzaLimiter;
use crate::hosts::Hosts;
use crate::router::RoutedStanza;

pub(super) const IO_BUFFER_BYTES: usize = 4_096;

pub(super) type TlsTransport = futures_rustls::server::TlsStream<Pin<Box<AsyncStream<TcpStream>>>>;
pub(super) type TlsReader = ReadHalf<TlsTransport>;
pub(super) type TlsWriter = WriteHalf<TlsTransport>;
pub(super) type XmlInput = RateLimitedReader<BufReader<tokio_util::compat::Compat<TlsReader>>>;

/// Separate halves keep a read pinned while the stream writes stanzas.
pub(super) struct Session<A: ChunkAllocator> {
    pub(super) reader: Reader<A>,
    pub(super) writer: Writer,
}

pub(super) struct Reader<A: ChunkAllocator, R = XmlInput> {
    parser: XmppParser<R, A>,
    stanzas: StanzaLimiter,
}

pub(super) struct Writer {
    output: BufWriter<TlsWriter>,
    host: String,
}

impl<A: ChunkAllocator + Clone> Session<A> {
    pub(super) fn new(
        parser: XmppParser<XmlInput, A>,
        writer: TlsWriter,
        host: String,
        stanzas: StanzaLimiter,
    ) -> Self {
        Self {
            reader: Reader { parser, stanzas },
            writer: Writer {
                output: BufWriter::with_capacity(IO_BUFFER_BYTES, writer),
                host,
            },
        }
    }

    pub(super) fn host(&self) -> &str {
        &self.writer.host
    }

    pub(super) async fn restart(self) -> Result<Self, CloseOutcome> {
        let Self { reader, mut writer } = self;
        match reader.restart() {
            Ok(reader) => Ok(Self { reader, writer }),
            Err(_) => Err(writer
                .reject_header(None, false, CloseOutcome::ParserError)
                .await),
        }
    }

    pub(super) async fn next_event(&mut self) -> Result<Option<StreamEvent<A>>, CloseOutcome> {
        match self.reader.next_event().await {
            Ok(event) => Ok(event),
            Err(outcome) => Err(self.writer.fail(outcome).await),
        }
    }

    /// Rejects invalid client headers on the same stream.
    pub(super) async fn read_header(
        &mut self,
        hosts: &Hosts,
    ) -> Result<ClientHeader, CloseOutcome> {
        match self.reader.parser.next_event().await {
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

impl<A: ChunkAllocator + Clone, R: AsyncBufRead + Unpin> Reader<A, R> {
    fn restart(self) -> Result<Self, ParseError> {
        Ok(Self {
            parser: self.parser.restart()?,
            stanzas: self.stanzas,
        })
    }

    /// Each complete stanza consumes one token before its caller can process it.
    pub(super) async fn next_event(&mut self) -> Result<Option<StreamEvent<A>>, CloseOutcome> {
        match self.parser.next_event().await {
            Ok(event) => {
                if matches!(event, Some(StreamEvent::Stanza(_))) {
                    self.stanzas.acquire().await;
                }
                Ok(event)
            }
            Err(ParseError::UnexpectedEof) => Err(CloseOutcome::Eof),
            Err(error) => Err(CloseOutcome::from_parse_error(&error)),
        }
    }
}

impl Writer {
    pub(super) async fn send(&mut self, xml: &str) -> Result<(), CloseOutcome> {
        self.output
            .write_all(xml.as_bytes())
            .await
            .map_err(|_| CloseOutcome::TransportError)?;
        self.flush().await
    }

    /// The caller must flush buffered output.
    pub(super) async fn write_stanza<R: ArenaRead>(
        &mut self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<(), CloseOutcome> {
        stanza
            .write_xml_async(&mut self.output)
            .await
            .map_err(|error| match error {
                AsyncWriteError::Access(_) => CloseOutcome::InternalError,
                AsyncWriteError::Output(_) => CloseOutcome::TransportError,
            })
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
        self.send(&xml).await
    }

    pub(super) async fn fail(&mut self, outcome: CloseOutcome) -> CloseOutcome {
        send_stream_error(&mut self.output, outcome).await
    }

    /// Answers a rejected stream header with a response header followed by the stream error.
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
        self.fail(outcome).await
    }

    pub(super) async fn close(&mut self) -> CloseOutcome {
        if self.send(STREAM_FOOTER).await.is_err() || self.output.close().await.is_err() {
            CloseOutcome::TransportError
        } else {
            CloseOutcome::StreamEnd
        }
    }

    pub(super) async fn flush(&mut self) -> Result<(), CloseOutcome> {
        self.output
            .flush()
            .await
            .map_err(|_| CloseOutcome::TransportError)
    }
}

/// Closes the output when the outcome has a stream error.
pub(super) async fn send_stream_error<W: AsyncWrite + Unpin>(
    output: &mut W,
    outcome: CloseOutcome,
) -> CloseOutcome {
    let Some(xml) = stream_error_xml(outcome) else {
        return outcome;
    };
    let sent = async {
        output.write_all(xml.as_bytes()).await?;
        output.flush().await?;
        output.close().await
    };
    if sent.await.is_err() {
        CloseOutcome::TransportError
    } else {
        outcome
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
