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
use tokio::io::BufReader;

use super::header::{
    ClientHeader, STREAM_FOOTER, response_header_xml, response_to_from_header, stream_error_xml,
    validate_header,
};
use super::outcome::CloseOutcome;
use crate::hosts::Hosts;
use crate::router::RoutedStanza;

pub(super) const IO_BUFFER_BYTES: usize = 4_096;

pub(super) type TlsTransport = futures_rustls::server::TlsStream<Pin<Box<AsyncStream<TcpStream>>>>;
pub(super) type TlsReader = ReadHalf<TlsTransport>;
pub(super) type TlsWriter = WriteHalf<TlsTransport>;
pub(super) type XmlInput = RateLimitedReader<BufReader<tokio_util::compat::Compat<TlsReader>>>;

/// The TLS-protected XML stream of one client connection.
///
/// The halves are separate fields so a pending read can stay pinned while
/// stanzas are written.
pub(super) struct Session<A: ChunkAllocator> {
    pub(super) reader: Reader<A>,
    pub(super) writer: Writer,
}

pub(super) struct Reader<A: ChunkAllocator> {
    parser: XmppParser<XmlInput, A>,
}

pub(super) struct Writer {
    output: BufWriter<TlsWriter>,
    host: String,
}

impl<A: ChunkAllocator + Clone> Session<A> {
    pub(super) fn new(parser: XmppParser<XmlInput, A>, writer: TlsWriter, host: String) -> Self {
        Self {
            reader: Reader { parser },
            writer: Writer {
                output: BufWriter::with_capacity(IO_BUFFER_BYTES, writer),
                host,
            },
        }
    }

    pub(super) fn host(&self) -> &str {
        &self.writer.host
    }

    /// Prepares the parser for the stream header the client sends after authentication.
    pub(super) async fn restart(self) -> Result<Self, CloseOutcome> {
        let Self { reader, mut writer } = self;
        match reader.parser.restart() {
            Ok(parser) => Ok(Self {
                reader: Reader { parser },
                writer,
            }),
            Err(_) => Err(writer
                .reject_header(None, false, CloseOutcome::ParserError)
                .await),
        }
    }

    /// Reads the next event and answers a parse failure with its stream error.
    pub(super) async fn next_event(&mut self) -> Result<Option<StreamEvent<A>>, CloseOutcome> {
        match self.reader.next_event().await {
            Ok(event) => Ok(event),
            Err(outcome) => Err(self.writer.fail(outcome).await),
        }
    }

    /// Reads and validates the client's stream header, answering a rejection in place.
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

impl<A: ChunkAllocator + Clone> Reader<A> {
    /// Maps the transport end to `Eof` and a parse failure to its outcome without replying.
    pub(super) async fn next_event(&mut self) -> Result<Option<StreamEvent<A>>, CloseOutcome> {
        match self.parser.next_event().await {
            Ok(event) => Ok(event),
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

    pub(super) async fn send_stanza<R: ArenaRead>(
        &mut self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<(), CloseOutcome> {
        stanza
            .write_xml_async(&mut self.output)
            .await
            .map_err(|error| match error {
                AsyncWriteError::Access(_) => CloseOutcome::InternalError,
                AsyncWriteError::Output(_) => CloseOutcome::TransportError,
            })?;
        self.flush().await
    }

    pub(super) async fn send_routed<A: ChunkAllocator>(
        &mut self,
        stanza: &RoutedStanza<A>,
    ) -> Result<(), CloseOutcome> {
        let view = stanza.resolve()?;
        self.send_stanza(&view).await
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

    /// Ends the stream after the client closed its side.
    pub(super) async fn close(&mut self) -> CloseOutcome {
        if self.send(STREAM_FOOTER).await.is_err() || self.output.close().await.is_err() {
            CloseOutcome::TransportError
        } else {
            CloseOutcome::StreamEnd
        }
    }

    async fn flush(&mut self) -> Result<(), CloseOutcome> {
        self.output
            .flush()
            .await
            .map_err(|_| CloseOutcome::TransportError)
    }
}

/// Sends the stream error for `outcome`, when it has one, and closes the output.
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

/// Reports an event that belongs to the server-to-server namespace on a client stream.
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
