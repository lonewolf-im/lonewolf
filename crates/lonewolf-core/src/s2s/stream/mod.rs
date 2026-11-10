// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::fmt::Write as _;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use compio::io::compat::AsyncReadStream;
use compio::net::TcpStream;
use futures_util::io::{AsyncWrite, AsyncWriteExt as _, BufWriter};
use lonewolf_util::arena::{Arena, ArenaConfig, ArenaRead, ChunkAllocator, HandleError};
use lonewolf_util::rate_limited_reader::{RateLimitState, RateLimitedReader};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParseError, Parsed, ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{
    AsyncWriteError, Element, NodeRef, SERVER_NAMESPACE, StanzaRef, XML_NAMESPACE,
};
use lonewolf_xmpp::stream::StreamErrorCondition;
use oxilangtag::LanguageTag;
use tokio::io::{AsyncBufRead, AsyncReadExt as _};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _};

use super::metrics::{InboundLimit, S2sMetrics};
use crate::config::limits::{ByteRate, EventRate};
use crate::xml_stream::limiter::StanzaLimiter;
use crate::xml_stream::parse::{ParseFailure, classify_parse_error};
use crate::xml_stream::reader::{ReadMode, ReadObserver, XmlReader};
use crate::xml_stream::{
    STREAM_FOOTER, escape_attribute, peer_stream_error, stream_error_xml, version_components,
};

pub(crate) mod limits;
pub(crate) mod traffic;

const TLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const HEADER_PREFIX: &str = "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='";

#[cfg(test)]
pub(crate) const STARTTLS_REQUIRED_FEATURES: &str = "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>";
#[cfg(test)]
pub(crate) const EXTERNAL_FEATURES: &str = "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>";
pub(crate) const BIDI_NAMESPACE: &str = "urn:xmpp:bidi";
pub(crate) const BIDI_FEATURE_NAMESPACE: &str = "urn:xmpp:features:bidi";

#[cfg(test)]
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
    pub(crate) limits: Option<limits::StreamLimits>,
    pub(crate) bidi: bool,
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum HeaderKind {
    Initial,
    Response,
}

fn validate_header<A: ChunkAllocator>(
    header: &Parsed<Element, A>,
    content_namespace: &str,
    kind: HeaderKind,
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
    let Some((major, _)) = version_components(version) else {
        return Err(StreamErrorCondition::UnsupportedVersion);
    };
    if major == "0" || (kind == HeaderKind::Response && major != "1") {
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

pub(super) fn domain(
    value: &str,
    invalid: StreamErrorCondition,
) -> Result<Box<str>, StreamErrorCondition> {
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
    validate_header(header, content_namespace, HeaderKind::Initial)?;
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
    validate_header(header, content_namespace, HeaderKind::Response)?;
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

pub(crate) fn parse_features<A: ChunkAllocator>(
    element: &Parsed<Element, A>,
) -> Result<Features, HandleError> {
    let parent = element.value().resolve(element.arena())?;
    let mut features = Features {
        limits: limits::parse_limits(&parent)?,
        ..Features::default()
    };
    if let Ok(element) = element.value().resolve(element.arena())
        && let Ok(children) = element.children()
    {
        for child in children {
            let Ok(NodeRef::Element(child)) = child else {
                continue;
            };
            if child.name() == "starttls" && child.namespace() == TLS_NAMESPACE {
                features.starttls = true;
            } else if child.name() == "bidi" && child.namespace() == BIDI_FEATURE_NAMESPACE {
                features.bidi = true;
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
    Ok(features)
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

#[derive(Clone)]
pub(crate) struct S2sReaderLimits {
    pub(crate) max_stanza_bytes: NonZeroUsize,
    pub(crate) stanzas: EventRate,
    pub(crate) xml: ByteRate,
}

pub(crate) struct S2sReader<A: ChunkAllocator, R> {
    inner: XmlReader<A, RateLimitedReader<R>, S2sReadObserver>,
    max_stanza_bytes: NonZeroUsize,
    activity: Option<traffic::ConnectionActivity>,
    #[cfg(feature = "test-support")]
    transport_direction: Option<crate::s2s::metrics::Direction>,
}

struct S2sReadObserver(Option<Arc<S2sMetrics>>);

impl ReadObserver for S2sReadObserver {
    fn rate_limited(&self) {
        if let Some(metrics) = &self.0 {
            metrics.rate_limited(InboundLimit::IncomingStanzasPerConnection);
        }
    }
}

pub(crate) struct S2sReaderState {
    max_stanza_bytes: NonZeroUsize,
    xml: RateLimitState,
    limiter: StanzaLimiter,
    metrics: Option<Arc<S2sMetrics>>,
}

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
                limiter: StanzaLimiter::new(limits.stanzas.per_second, limits.stanzas.burst),
                metrics,
            },
            allocator,
        )
    }

    pub(crate) fn from_state(input: R, state: S2sReaderState, allocator: A) -> Self {
        let parser = XmppParser::new(
            RateLimitedReader::from_state(input, state.xml),
            ParserConfig {
                max_stanza_bytes: state.max_stanza_bytes,
                arena: ArenaConfig::default(),
            },
            allocator,
        );
        Self {
            inner: XmlReader::new(
                parser,
                state.limiter,
                Rc::new(Cell::new(ReadMode::Open)),
                S2sReadObserver(state.metrics),
            ),
            max_stanza_bytes: state.max_stanza_bytes,
            activity: None,
            #[cfg(feature = "test-support")]
            transport_direction: None,
        }
    }

    pub(crate) fn with_activity(mut self, activity: traffic::ConnectionActivity) -> Self {
        self.activity = Some(activity);
        self
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn with_transport_direction(
        mut self,
        direction: crate::s2s::metrics::Direction,
    ) -> Self {
        self.transport_direction = Some(direction);
        self
    }

    pub(crate) fn activity(&self) -> Option<traffic::ConnectionActivity> {
        self.activity.clone()
    }

    pub(crate) async fn next_event(&mut self) -> Result<Option<StreamEvent<A>>, S2sError> {
        if !self.inner.has_input() {
            return Err(S2sError::Internal);
        }
        let event = self.inner.read_event().await.map_err(S2sError::from)?;
        if let Some(event) = &event
            && let Some(condition) = peer_stream_error(event)?
        {
            return Err(S2sError::PeerError(condition));
        }
        Ok(event)
    }

    pub(crate) fn restart(&mut self) -> Result<(), S2sError> {
        if !self.inner.has_ready_state() {
            return Err(S2sError::Internal);
        }
        self.inner.restart().map_err(S2sError::from)
    }

    /// Call once after a TLS reader returns `StreamEvent::StreamEnd`.
    /// Consumes input even if the read fails or is canceled.
    pub(crate) async fn read_transport_end(&mut self) -> Result<(), S2sError> {
        let (mut input, state) = self.take_input().await?;
        #[cfg(feature = "test-support")]
        let metrics = state.metrics.as_ref().map(Arc::clone);
        drop(state);
        let mut byte = [0];
        match input.read(&mut byte).await? {
            0 => {
                #[cfg(feature = "test-support")]
                if let (Some(metrics), Some(direction)) = (metrics, self.transport_direction) {
                    metrics.transport_end(direction);
                }
                Ok(())
            }
            _ => Err(io::Error::from(io::ErrorKind::InvalidData).into()),
        }
    }

    pub(crate) async fn take_input(&mut self) -> Result<(R, S2sReaderState), S2sError> {
        let (parser, limiter, observer) = self
            .inner
            .take_parts()
            .await
            .map_err(|_| S2sError::Internal)?;
        let (input, xml) = parser.into_inner().into_parts();
        Ok((
            input,
            S2sReaderState {
                max_stanza_bytes: self.max_stanza_bytes,
                xml,
                limiter,
                metrics: observer.0,
            },
        ))
    }
}

pub(crate) struct S2sWriter<W> {
    output: BufWriter<W>,
    peer_limits: limits::StreamLimits,
}

impl<W: AsyncWrite + Unpin> S2sWriter<W> {
    pub(crate) fn new(output: W) -> Self {
        Self {
            output: BufWriter::with_capacity(4_096, output),
            peer_limits: limits::StreamLimits::default(),
        }
    }

    pub(crate) fn peer_limits(&self) -> limits::StreamLimits {
        self.peer_limits
    }

    pub(crate) fn update_peer_limits(&mut self, update: Option<limits::StreamLimits>) {
        if let Some(limits) = update {
            self.peer_limits = limits;
        }
    }

    pub(crate) async fn send(&mut self, xml: &str) -> Result<(), S2sError> {
        if self
            .peer_limits
            .max_bytes
            .is_some_and(|max| xml.len() as u64 > u64::from(max))
        {
            return Err(S2sError::Stream(StreamErrorCondition::PolicyViolation));
        }
        self.send_header(xml).await
    }

    pub(crate) async fn send_header(&mut self, xml: &str) -> Result<(), S2sError> {
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
            Some(condition) => self.send_header(&stream_error_xml(condition)).await,
            None => self.send_header(STREAM_FOOTER).await,
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
