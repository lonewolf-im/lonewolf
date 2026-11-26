// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::fmt::Write as _;
use std::io;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::io::AsyncWrite;
use lonewolf_util::arena::{ArenaConfig, ArenaRead, ChunkAllocator, HandleError};
use lonewolf_util::rate_limited_reader::RateLimitedReader;
use lonewolf_xmpp::parser::{ParseError, ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{AsyncWriteError, StanzaNamespace, StanzaRef};
use lonewolf_xmpp::stream::StreamErrorCondition;
use tokio::io::{AsyncBufRead, AsyncReadExt as _};

use super::metrics::{ComponentMetrics, InboundLimit};
use crate::config::limits::ComponentLimits;
use crate::xml_stream::limiter::StanzaLimiter;
use crate::xml_stream::parse::{ParseFailure, classify_parse_error};
use crate::xml_stream::reader::{ReadMode, ReadObserver, XmlReader};
pub(crate) use crate::xml_stream::traffic::WriteProgress;
use crate::xml_stream::writer::StreamWriter;
use crate::xml_stream::{escape_attribute, peer_stream_error};

const IO_BUFFER_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ComponentError {
    Eof,
    Io,
    Timeout,
    PeerError(StreamErrorCondition),
    Stream(StreamErrorCondition),
    Internal,
}

pub(crate) fn response_header_xml(
    domain: Option<&str>,
) -> Result<(String, Box<str>), ComponentError> {
    let mut random = [0_u8; 16];
    aws_lc_rs::rand::fill(&mut random).map_err(|_| ComponentError::Internal)?;
    let id = format!("{:032x}", u128::from_be_bytes(random)).into_boxed_str();
    let mut xml = String::with_capacity(192 + domain.map_or(0, str::len));
    xml.push_str("<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:component:accept' id='");
    write!(xml, "{id}'").map_err(|_| ComponentError::Internal)?;
    if let Some(domain) = domain {
        xml.push_str(" from='");
        escape_attribute(&mut xml, domain);
        xml.push('\'');
    }
    xml.push('>');
    Ok((xml, id))
}

pub(crate) struct ComponentReader<A: ChunkAllocator, R> {
    inner: XmlReader<A, RateLimitedReader<R>, ComponentReadObserver>,
}

struct ComponentReadObserver(Arc<ComponentMetrics>);
impl ReadObserver for ComponentReadObserver {
    fn rate_limited(&self) {
        self.0
            .rate_limited(InboundLimit::IncomingStanzasPerConnection);
    }
}

impl<A: ChunkAllocator + Clone, R: AsyncBufRead + Unpin + 'static> ComponentReader<A, R> {
    pub(crate) fn new(
        input: R,
        limits: &ComponentLimits,
        allocator: A,
        metrics: Arc<ComponentMetrics>,
    ) -> Self {
        let xml = &limits.incoming_xml_per_connection;
        let input = RateLimitedReader::new(input, xml.bytes_per_second, xml.burst_bytes)
            .with_observer(Arc::clone(&metrics)
                as Arc<dyn lonewolf_util::rate_limited_reader::RateLimitObserver>);
        let parser = XmppParser::new(
            input,
            ParserConfig {
                max_stanza_bytes: limits.max_stanza_bytes,
                arena: ArenaConfig::default(),
            },
            allocator,
        );
        let stanzas = &limits.incoming_stanzas_per_connection;
        Self {
            inner: XmlReader::new(
                parser,
                StanzaLimiter::new(stanzas.per_second, stanzas.burst),
                Rc::new(Cell::new(ReadMode::Open)),
                ComponentReadObserver(metrics),
            ),
        }
    }

    /// Consume the reader only after a peer footer.
    pub(crate) async fn transport_end(&mut self) -> Result<(), ComponentError> {
        let (parser, _, _) = self.inner.take_parts().await?;
        let (mut input, _) = parser.into_inner().into_parts();
        let mut byte = [0];
        match input.read(&mut byte).await? {
            0 => Ok(()),
            _ => Err(ComponentError::Io),
        }
    }

    pub(crate) async fn next_event(&mut self) -> Result<Option<StreamEvent<A>>, ComponentError> {
        let event = match self.inner.read_event().await {
            Err(ParseError::UnexpectedEof) => return Err(ComponentError::Eof),
            result => result?,
        };
        if let Some(event) = &event
            && let Some(condition) = peer_stream_error(event)?
        {
            return Err(ComponentError::PeerError(condition));
        }
        Ok(event)
    }
}

#[cfg(not(feature = "test-support"))]
type Output<W> = W;
#[cfg(feature = "test-support")]
type Output<W> = crate::test_support::component_write::ComponentOutput<W>;

pub(crate) struct ComponentWriter<W> {
    stream: StreamWriter<Output<W>>,
    progress: WriteProgress,
}
impl<W: AsyncWrite + Unpin> ComponentWriter<W> {
    pub(crate) fn new(output: W, progress: WriteProgress) -> Self {
        Self {
            stream: StreamWriter::new(Self::output(output), IO_BUFFER_BYTES),
            progress,
        }
    }
    #[cfg(test)]
    pub(crate) fn opened(output: W, progress: WriteProgress) -> Self {
        Self {
            stream: StreamWriter::opened(Self::output(output), IO_BUFFER_BYTES),
            progress,
        }
    }
    #[cfg(not(feature = "test-support"))]
    fn output(output: W) -> Output<W> {
        output
    }
    #[cfg(feature = "test-support")]
    fn output(output: W) -> Output<W> {
        crate::test_support::component_write::ComponentOutput::new(output)
    }
    #[cfg(feature = "test-support")]
    pub(crate) fn bind_write_probe(&mut self, peer: std::net::SocketAddr) {
        if let Some(output) = self.stream.get_mut() {
            output.bind(peer);
        }
    }
    pub(crate) fn progress(&self) -> WriteProgress {
        self.progress.clone()
    }
    pub(crate) fn needs_header(&self) -> bool {
        self.stream.needs_header()
    }
    pub(crate) async fn write_stanza<R: ArenaRead>(
        &mut self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<(), ComponentError> {
        self.stream
            .write_stanza(stanza, StanzaNamespace::ComponentAccept)
            .await
            .map_err(|error| match error {
                AsyncWriteError::Access(_) => ComponentError::Internal,
                AsyncWriteError::Output(error) => error.into(),
            })
    }
    pub(crate) async fn send_header(&mut self, xml: &str) -> Result<(), ComponentError> {
        Ok(self.stream.send_header(xml).await?)
    }
    pub(crate) async fn send(&mut self, xml: &str) -> Result<(), ComponentError> {
        Ok(self.stream.send(xml).await?)
    }
    pub(crate) async fn flush(&mut self) -> Result<(), ComponentError> {
        Ok(self.stream.flush().await?)
    }
    pub(crate) async fn close(
        &mut self,
        condition: Option<StreamErrorCondition>,
    ) -> Result<(), ComponentError> {
        self.stream.close(condition).await?;
        Ok(())
    }
    pub(crate) async fn shutdown(&mut self) -> Result<(), ComponentError> {
        Ok(self.stream.shutdown().await?)
    }
}

pub(super) async fn close<
    A: ChunkAllocator + Clone,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
>(
    reader: &mut ComponentReader<A, R>,
    writer: &mut ComponentWriter<W>,
    condition: Option<StreamErrorCondition>,
    peer_footer: bool,
    shutdown_deadline: Option<Instant>,
) {
    let deadline = Instant::now() + Duration::from_secs(6);
    let deadline = shutdown_deadline.map_or(deadline, |shutdown| deadline.min(shutdown));
    let _ = compio::time::timeout_at(
        deadline,
        pin!(async {
            writer.close(condition).await?;
            if !peer_footer {
                let _ = compio::time::timeout_at(
                    deadline.min(Instant::now() + Duration::from_secs(5)),
                    pin!(async {
                        while let Ok(Some(event)) = reader.next_event().await {
                            if matches!(event, StreamEvent::StreamEnd) {
                                break;
                            }
                        }
                    }),
                )
                .await;
            }
            writer.shutdown().await
        }),
    )
    .await;
}

impl From<io::Error> for ComponentError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::TimedOut {
            Self::Timeout
        } else {
            Self::Io
        }
    }
}
impl From<HandleError> for ComponentError {
    fn from(_: HandleError) -> Self {
        Self::Internal
    }
}
impl From<ParseError> for ComponentError {
    fn from(error: ParseError) -> Self {
        let condition = match classify_parse_error(&error) {
            ParseFailure::Transport(error) => {
                return if error.is_some_and(|error| error.kind() == io::ErrorKind::TimedOut) {
                    Self::Timeout
                } else {
                    Self::Io
                };
            }
            ParseFailure::SizeLimit | ParseFailure::ParserLimit => {
                StreamErrorCondition::PolicyViolation
            }
            ParseFailure::Allocation => return Self::Internal,
            ParseFailure::InvalidNamespace => StreamErrorCondition::InvalidNamespace,
            ParseFailure::BadNamespacePrefix => StreamErrorCondition::BadNamespacePrefix,
            ParseFailure::InvalidXml => StreamErrorCondition::InvalidXml,
            ParseFailure::NotWellFormed => StreamErrorCondition::NotWellFormed,
            ParseFailure::RestrictedXml => StreamErrorCondition::RestrictedXml,
            ParseFailure::UnsupportedEncoding => StreamErrorCondition::UnsupportedEncoding,
            ParseFailure::Other => StreamErrorCondition::BadFormat,
        };
        Self::Stream(condition)
    }
}

#[cfg(test)]
mod tests;
