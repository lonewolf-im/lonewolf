// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::error::Error as _;
use std::fmt::Write as _;
use std::future::{Future, poll_fn};
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use compio::io::compat::AsyncReadStream;
use compio::net::TcpStream;
use futures_util::io::{AsyncWrite, AsyncWriteExt as _, BufWriter};
use lonewolf_util::arena::{
    Arena, ArenaConfig, ArenaError, ArenaRead, ChunkAllocator, HandleError,
};
use lonewolf_util::rate_limited_reader::{RateLimitState, RateLimitedReader};
use lonewolf_util::token_bucket::TokenBucket;
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParseError, Parsed, ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{
    AsyncWriteError, BuildError, Element, NodeRef, SERVER_NAMESPACE, StanzaRef, XML_NAMESPACE,
};
use lonewolf_xmpp::stream::{STREAM_ERROR_NAMESPACE, StreamError, StreamErrorCondition};
use oxilangtag::LanguageTag;
use tokio::io::{AsyncBufRead, AsyncReadExt as _};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _};

use super::metrics::{InboundLimit, S2sMetrics};
use crate::config::limits::{ByteRate, EventRate};

pub(crate) mod traffic;

const TLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const STREAM_FOOTER: &str = "</stream:stream>";
const HEADER_PREFIX: &str = "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='";

pub(crate) const STARTTLS_REQUIRED_FEATURES: &str = "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>";
pub(crate) const EXTERNAL_FEATURES: &str = "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>";
pub(crate) const EMPTY_FEATURES: &str = "<stream:features/>";
pub(crate) const STARTTLS: &str = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
pub(crate) const PROCEED: &str = "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
pub(crate) const TLS_FAILURE: &str = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
pub(crate) const SASL_SUCCESS: &str = "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";
pub(crate) const EMPTY_CHALLENGE: &str = "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InitialHeader {
    pub(crate) to: Box<str>,
    pub(crate) from: Option<Box<str>>,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct Features {
    pub(crate) starttls: bool,
    pub(crate) external: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Auth {
    NoInitialResponse,
    Response(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SaslFailure {
    Aborted,
    InvalidAuthzid,
    InvalidMechanism,
    MalformedRequest,
    NotAuthorized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum S2sError {
    Eof,
    Io,
    Timeout,
    PeerError(StreamErrorCondition),
    Stream(StreamErrorCondition),
    Internal,
}

pub(crate) fn initial_header_xml(from: &str, to: &str) -> String {
    let mut xml = String::with_capacity(192 + from.len() + to.len());
    xml.push_str(HEADER_PREFIX);
    escape_attribute(&mut xml, from);
    xml.push_str("' to='");
    escape_attribute(&mut xml, to);
    xml.push_str("' version='1.0' xml:lang='en'>");
    xml
}

pub(crate) fn response_header_xml(from: &str, to: Option<&str>) -> Result<String, S2sError> {
    let mut id = [0_u8; 16];
    graviola::random::fill(&mut id).map_err(|_| S2sError::Internal)?;
    let mut xml = String::with_capacity(224 + from.len() + to.map_or(0, str::len));
    xml.push_str(HEADER_PREFIX);
    escape_attribute(&mut xml, from);
    xml.push_str("' id='");
    write!(xml, "{:032x}", u128::from_be_bytes(id)).map_err(|_| S2sError::Internal)?;
    xml.push('\'');
    if let Some(to) = to {
        xml.push_str(" to='");
        escape_attribute(&mut xml, to);
        xml.push('\'');
    }
    xml.push_str(" version='1.0' xml:lang='en'>");
    Ok(xml)
}

fn escape_attribute(output: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            '\n' => output.push_str("&#xA;"),
            '\r' => output.push_str("&#xD;"),
            '\t' => output.push_str("&#x9;"),
            _ => output.push(ch),
        }
    }
}

fn validate_header<A: ChunkAllocator>(
    header: &Parsed<Element, A>,
    content_namespace: &str,
) -> Result<(), StreamErrorCondition> {
    if !matches!(content_namespace, "" | SERVER_NAMESPACE) {
        return Err(StreamErrorCondition::InvalidNamespace);
    }
    let header = header
        .value()
        .resolve(header.arena())
        .map_err(internal_condition)?;
    let version = header
        .attribute("version", "")
        .map_err(internal_condition)?
        .ok_or(StreamErrorCondition::UnsupportedVersion)?;
    let Some((major, minor)) = version.split_once('.') else {
        return Err(StreamErrorCondition::UnsupportedVersion);
    };
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|digit| digit.is_ascii_digit())
        || !minor.bytes().all(|digit| digit.is_ascii_digit())
        || major.trim_start_matches('0') != "1"
    {
        return Err(StreamErrorCondition::UnsupportedVersion);
    }
    if header
        .attribute("lang", XML_NAMESPACE)
        .map_err(internal_condition)?
        .is_some_and(|lang| LanguageTag::parse(lang).is_err())
    {
        return Err(StreamErrorCondition::InvalidXml);
    }
    Ok(())
}

fn internal_condition(_: HandleError) -> StreamErrorCondition {
    StreamErrorCondition::InternalServerError
}

fn domain(value: &str, invalid: StreamErrorCondition) -> Result<Box<str>, StreamErrorCondition> {
    let mut arena = Arena::try_new(ArenaConfig::default())
        .map_err(|_| StreamErrorCondition::InternalServerError)?;
    let jid = Jid::parse_in(value, &mut arena).map_err(|_| invalid)?;
    let jid = jid.resolve(&arena).map_err(internal_condition)?;
    if jid.localpart().is_some() || jid.resourcepart().is_some() {
        return Err(invalid);
    }
    Ok(jid.domainpart().into())
}

pub(crate) fn validate_initial_header<A: ChunkAllocator>(
    header: &Parsed<Element, A>,
    content_namespace: &str,
) -> Result<InitialHeader, StreamErrorCondition> {
    validate_header(header, content_namespace)?;
    let header = header
        .value()
        .resolve(header.arena())
        .map_err(internal_condition)?;
    let to = header
        .attribute("to", "")
        .map_err(internal_condition)?
        .ok_or(StreamErrorCondition::HostUnknown)?;
    let to = domain(to, StreamErrorCondition::HostUnknown)?;
    let from = header
        .attribute("from", "")
        .map_err(internal_condition)?
        .map(|value| domain(value, StreamErrorCondition::InvalidFrom))
        .transpose()?;
    Ok(InitialHeader { to, from })
}

pub(crate) fn validate_response_header<A: ChunkAllocator>(
    header: &Parsed<Element, A>,
    content_namespace: &str,
    expected_from: &str,
) -> Result<(), StreamErrorCondition> {
    validate_header(header, content_namespace)?;
    let header = header
        .value()
        .resolve(header.arena())
        .map_err(internal_condition)?;
    if let Some(from) = header.attribute("from", "").map_err(internal_condition)? {
        let from = domain(from, StreamErrorCondition::HostUnknown)?;
        let expected = domain(expected_from, StreamErrorCondition::HostUnknown)?;
        if from != expected {
            return Err(StreamErrorCondition::HostUnknown);
        }
    }
    Ok(())
}

pub(crate) fn parse_features<A: ChunkAllocator>(element: &Parsed<Element, A>) -> Features {
    let mut features = Features::default();
    if let Ok(element) = element.value().resolve(element.arena())
        && let Ok(children) = element.children()
    {
        for child in children {
            let Ok(NodeRef::Element(child)) = child else {
                continue;
            };
            if child.name() == "starttls" && child.namespace() == TLS_NAMESPACE {
                features.starttls = true;
            } else if child.name() == "mechanisms"
                && child.namespace() == SASL_NAMESPACE
                && let Ok(mechanisms) = child.children()
            {
                for mechanism in mechanisms {
                    if let Ok(NodeRef::Element(mechanism)) = mechanism
                        && mechanism.name() == "mechanism"
                        && mechanism.namespace() == SASL_NAMESPACE
                        && mechanism.text().is_ok_and(|text| text == Some("EXTERNAL"))
                    {
                        features.external = true;
                    }
                }
            }
        }
    }
    features
}

pub(crate) fn auth_external_xml(authzid: &str) -> String {
    let mut xml = String::with_capacity(96 + authzid.len().div_ceil(3) * 4);
    xml.push_str("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>");
    if authzid.is_empty() {
        xml.push('=');
    } else {
        STANDARD.encode_string(authzid, &mut xml);
    }
    xml.push_str("</auth>");
    xml
}

pub(crate) fn parse_auth<A: ChunkAllocator>(
    element: &Parsed<Element, A>,
) -> Result<Auth, SaslFailure> {
    let element = element
        .value()
        .resolve(element.arena())
        .map_err(|_| SaslFailure::MalformedRequest)?;
    if element
        .attribute("mechanism", "")
        .map_err(|_| SaslFailure::MalformedRequest)?
        != Some("EXTERNAL")
    {
        return Err(SaslFailure::InvalidMechanism);
    }
    match element.text().map_err(|_| SaslFailure::MalformedRequest)? {
        None | Some("") => Ok(Auth::NoInitialResponse),
        Some("=") => Ok(Auth::Response(Vec::new())),
        Some(text) => {
            let decoded = STANDARD
                .decode(text)
                .map_err(|_| SaslFailure::MalformedRequest)?;
            std::str::from_utf8(&decoded).map_err(|_| SaslFailure::MalformedRequest)?;
            Ok(Auth::Response(decoded))
        }
    }
}

pub(crate) fn sasl_failure_xml(failure: SaslFailure) -> String {
    let name = match failure {
        SaslFailure::Aborted => "aborted",
        SaslFailure::InvalidAuthzid => "invalid-authzid",
        SaslFailure::InvalidMechanism => "invalid-mechanism",
        SaslFailure::MalformedRequest => "malformed-request",
        SaslFailure::NotAuthorized => "not-authorized",
    };
    format!("<failure xmlns='{SASL_NAMESPACE}'><{name}/></failure>")
}

pub(crate) fn stream_error_xml(condition: StreamErrorCondition) -> String {
    let mut xml = String::with_capacity(128);
    let _ = StreamError::new(condition).write_xml(&mut xml);
    xml.push_str(STREAM_FOOTER);
    xml
}

#[derive(Clone)]
pub(crate) struct S2sReaderLimits {
    pub(crate) max_stanza_bytes: NonZeroUsize,
    pub(crate) stanzas: EventRate,
    pub(crate) xml: ByteRate,
}

pub(crate) struct S2sReader<A: ChunkAllocator, R> {
    ready: Option<ReadState<A, R>>,
    pending: Option<PendingRead<A, R>>,
    abandon: Rc<Cell<bool>>,
}

struct ReadState<A: ChunkAllocator, R> {
    parser: XmppParser<RateLimitedReader<R>, A>,
    max_stanza_bytes: NonZeroUsize,
    stanzas: EventRate,
    bucket: TokenBucket,
    metrics: Option<Arc<S2sMetrics>>,
}

pub(crate) struct S2sReaderState {
    max_stanza_bytes: NonZeroUsize,
    xml: RateLimitState,
    stanzas: EventRate,
    bucket: TokenBucket,
    metrics: Option<Arc<S2sMetrics>>,
}

type PendingRead<A, R> =
    Pin<Box<dyn Future<Output = (ReadState<A, R>, Result<Option<StreamEvent<A>>, ParseError>)>>>;
type PlainInput = Compat<Pin<Box<AsyncReadStream<TcpStream>>>>;

impl<A: ChunkAllocator + Clone> S2sReader<A, PlainInput> {
    pub(crate) fn plain(
        tcp: TcpStream,
        limits: &S2sReaderLimits,
        allocator: A,
        metrics: Option<Arc<S2sMetrics>>,
    ) -> Self {
        // One-byte reads cannot consume TLS records before the STARTTLS boundary.
        Self::new(
            Box::pin(AsyncReadStream::with_capacity(1, tcp)).compat(),
            limits,
            allocator,
            metrics,
        )
    }
}

impl<A: ChunkAllocator + Clone, R: AsyncBufRead + Unpin + 'static> S2sReader<A, R> {
    pub(crate) fn new(
        input: R,
        limits: &S2sReaderLimits,
        allocator: A,
        metrics: Option<Arc<S2sMetrics>>,
    ) -> Self {
        let mut xml =
            RateLimitedReader::new(input, limits.xml.bytes_per_second, limits.xml.burst_bytes);
        if let Some(metrics) = &metrics {
            xml = xml.with_observer(Arc::clone(metrics)
                as Arc<dyn lonewolf_util::rate_limited_reader::RateLimitObserver>);
        }
        let (input, xml) = xml.into_parts();
        Self::from_state(
            input,
            S2sReaderState {
                max_stanza_bytes: limits.max_stanza_bytes,
                xml,
                stanzas: limits.stanzas.clone(),
                bucket: TokenBucket::new(limits.stanzas.burst, Instant::now()),
                metrics,
            },
            allocator,
        )
    }

    pub(crate) fn from_state(input: R, state: S2sReaderState, allocator: A) -> Self {
        Self {
            ready: Some(ReadState {
                parser: XmppParser::new(
                    RateLimitedReader::from_state(input, state.xml),
                    ParserConfig {
                        max_stanza_bytes: state.max_stanza_bytes,
                        arena: ArenaConfig::default(),
                    },
                    allocator,
                ),
                max_stanza_bytes: state.max_stanza_bytes,
                stanzas: state.stanzas,
                bucket: state.bucket,
                metrics: state.metrics,
            }),
            pending: None,
            abandon: Rc::new(Cell::new(false)),
        }
    }

    pub(crate) async fn next_event(&mut self) -> Result<Option<StreamEvent<A>>, S2sError> {
        if self.pending.is_none() {
            let mut state = self.ready.take().ok_or(S2sError::Internal)?;
            let abandon = Rc::clone(&self.abandon);
            self.pending = Some(Box::pin(async move {
                let event = {
                    let mut next = std::pin::pin!(state.parser.next_event());
                    poll_fn(|cx| {
                        if abandon.get() {
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
                    let mut reported = false;
                    loop {
                        if abandon.get() {
                            break;
                        }
                        state.bucket.replenish(
                            state.stanzas.per_second,
                            state.stanzas.burst,
                            Instant::now(),
                        );
                        if state.bucket.available() != 0 {
                            state.bucket.consume(1);
                            break;
                        }
                        let mut wait = std::pin::pin!(compio::time::sleep(
                            state.bucket.refill_delay(state.stanzas.per_second)
                        ));
                        poll_fn(|cx| {
                            if abandon.get() {
                                Poll::Ready(())
                            } else {
                                let result = wait.as_mut().poll(cx);
                                if result.is_pending() && !reported {
                                    if let Some(metrics) = &state.metrics {
                                        metrics.rate_limited(
                                            InboundLimit::IncomingStanzasPerConnection,
                                        );
                                    }
                                    reported = true;
                                }
                                result
                            }
                        })
                        .await;
                    }
                }
                (state, event)
            }));
        }
        let (state, result) = self.pending.as_mut().ok_or(S2sError::Internal)?.await;
        self.pending = None;
        self.ready = Some(state);
        let event = result.map_err(S2sError::from)?;
        if let Some(event) = &event
            && let Some(condition) = peer_stream_error(event)?
        {
            return Err(S2sError::PeerError(condition));
        }
        Ok(event)
    }

    pub(crate) fn restart(&mut self) -> Result<(), S2sError> {
        let mut state = self.ready.take().ok_or(S2sError::Internal)?;
        let (parser, result) = match state.parser.try_restart() {
            Ok(parser) => (parser, Ok(())),
            Err((parser, error)) => (parser, Err(error.into())),
        };
        state.parser = parser;
        self.ready = Some(state);
        result
    }

    /// Call once after a TLS reader returns `StreamEvent::StreamEnd`.
    /// Consumes input even if the read fails or is canceled.
    pub(crate) async fn read_transport_end(&mut self) -> Result<(), S2sError> {
        let (mut input, _) = self.take_input().await?;
        let mut byte = [0];
        match input.read(&mut byte).await? {
            0 => Ok(()),
            _ => Err(io::Error::from(io::ErrorKind::InvalidData).into()),
        }
    }

    pub(crate) async fn take_input(&mut self) -> Result<(R, S2sReaderState), S2sError> {
        if self.pending.is_some() {
            self.abandon.set(true);
            let _ = self.next_event().await;
        }
        self.ready
            .take()
            .map(|state| {
                let (input, xml) = state.parser.into_inner().into_parts();
                (
                    input,
                    S2sReaderState {
                        max_stanza_bytes: state.max_stanza_bytes,
                        xml,
                        stanzas: state.stanzas,
                        bucket: state.bucket,
                        metrics: state.metrics,
                    },
                )
            })
            .ok_or(S2sError::Internal)
    }
}

fn peer_stream_error<A: ChunkAllocator>(
    event: &StreamEvent<A>,
) -> Result<Option<StreamErrorCondition>, S2sError> {
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

pub(crate) struct S2sWriter<W> {
    output: BufWriter<W>,
}

impl<W: AsyncWrite + Unpin> S2sWriter<W> {
    pub(crate) fn new(output: W) -> Self {
        Self {
            output: BufWriter::with_capacity(4_096, output),
        }
    }

    pub(crate) async fn send(&mut self, xml: &str) -> Result<(), S2sError> {
        self.output.write_all(xml.as_bytes()).await?;
        self.flush().await
    }

    pub(crate) async fn write_stanza<R: ArenaRead>(
        &mut self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<(), S2sError> {
        stanza
            .write_xml_async(&mut self.output)
            .await
            .map_err(|error| match error {
                AsyncWriteError::Access(_) => S2sError::Internal,
                AsyncWriteError::Output(error) => error.into(),
            })
    }

    pub(crate) async fn flush(&mut self) -> Result<(), S2sError> {
        self.output.flush().await.map_err(Into::into)
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), S2sError> {
        self.output.close().await.map_err(Into::into)
    }

    pub(crate) async fn close(
        &mut self,
        condition: Option<StreamErrorCondition>,
    ) -> Result<(), S2sError> {
        match condition {
            Some(condition) => self.send(&stream_error_xml(condition)).await,
            None => self.send(STREAM_FOOTER).await,
        }
    }
}

impl From<io::Error> for S2sError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::TimedOut {
            Self::Timeout
        } else {
            Self::Io
        }
    }
}

impl From<HandleError> for S2sError {
    fn from(_: HandleError) -> Self {
        Self::Internal
    }
}

impl From<ParseError> for S2sError {
    fn from(error: ParseError) -> Self {
        if error.is_transport_error() {
            if let ParseError::Xml(xml) = &error
                && let Some(error) = xml
                    .source()
                    .and_then(|source| source.downcast_ref::<Arc<io::Error>>())
                && error.kind() == io::ErrorKind::TimedOut
            {
                return Self::Timeout;
            }
            return Self::Io;
        }
        let condition = match error {
            ParseError::SizeLimitExceeded { .. }
            | ParseError::TooManyAttributes
            | ParseError::Build(BuildError::TreeLimitExceeded)
            | ParseError::Build(BuildError::Allocation(ArenaError::ArenaLimitExceeded)) => {
                StreamErrorCondition::PolicyViolation
            }
            ParseError::Build(BuildError::Allocation(_)) => return Self::Internal,
            ParseError::InvalidNamespace => StreamErrorCondition::InvalidNamespace,
            ParseError::BadNamespacePrefix => StreamErrorCondition::BadNamespacePrefix,
            ParseError::InvalidXml => StreamErrorCondition::InvalidXml,
            ParseError::NotWellFormed | ParseError::UnboundNamespacePrefix => {
                StreamErrorCondition::NotWellFormed
            }
            ParseError::RestrictedXml => StreamErrorCondition::RestrictedXml,
            ParseError::UnsupportedEncoding => StreamErrorCondition::UnsupportedEncoding,
            _ => StreamErrorCondition::BadFormat,
        };
        Self::Stream(condition)
    }
}

#[cfg(test)]
mod tests;
