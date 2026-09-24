// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;
use std::num::NonZeroUsize;
use std::pin::{Pin, pin};
use std::sync::Arc;

use compio::io::compat::AsyncReadStream;
use compio::io::{AsyncWrite, AsyncWriteExt};
use compio::net::TcpStream;
use compio::tls::TlsAcceptor;
use langtag::LangTag;
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_util::rate_limited_reader::{RateLimitState, RateLimitedReader};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParseError, ParserConfig, StreamEvent, XmppParser, compio_reader};
use lonewolf_xmpp::stanza::{CLIENT_NAMESPACE, Element, STREAM_NAMESPACE};
use tokio::io::BufReader;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use super::connection_limit::ConnectionPermit;
use super::unauthenticated_limit::UnauthenticatedPermit;
use crate::config::limits::ByteRate;
use crate::hosts::Hosts;

const READ_BUFFER_BYTES: usize = 1_024;
const STARTTLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const STREAM_ERROR_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-streams";
const STARTTLS_FEATURES: &str = "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>";
const STARTTLS_PROCEED: &str = "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
const STARTTLS_FAILURE: &str = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>";
const STREAM_FOOTER: &str = "</stream:stream>";

pub(super) struct XmppStream<A: ChunkAllocator> {
    transport: TcpStream,
    ip_permit: ConnectionPermit,
    unauthenticated_permit: UnauthenticatedPermit,
    hosts: Hosts,
    settings: StreamSettings<A>,
}

#[derive(Clone)]
pub(super) struct StreamSettings<A: ChunkAllocator> {
    max_stanza_bytes: NonZeroUsize,
    xml_bytes_per_second: NonZeroUsize,
    xml_burst_bytes: NonZeroUsize,
    allocator: A,
}

impl<A: ChunkAllocator> StreamSettings<A> {
    pub(super) fn new(max_stanza_bytes: NonZeroUsize, xml_rate: &ByteRate, allocator: A) -> Self {
        Self {
            max_stanza_bytes,
            xml_bytes_per_second: xml_rate.bytes_per_second,
            xml_burst_bytes: xml_rate.burst_bytes,
            allocator,
        }
    }
}

impl<A: ChunkAllocator + Clone> XmppStream<A> {
    pub(super) fn new(
        transport: TcpStream,
        ip_permit: ConnectionPermit,
        unauthenticated_permit: UnauthenticatedPermit,
        hosts: Hosts,
        settings: StreamSettings<A>,
    ) -> Self {
        Self {
            transport,
            ip_permit,
            unauthenticated_permit,
            hosts,
            settings,
        }
    }

    pub(super) async fn run(self) -> CloseOutcome {
        let Self {
            transport,
            ip_permit,
            unauthenticated_permit,
            hosts,
            settings,
        } = self;
        let outcome = establish(transport, &hosts, settings).await;
        drop(unauthenticated_permit);
        drop(ip_permit);
        outcome
    }
}

async fn establish<A: ChunkAllocator + Clone>(
    mut transport: TcpStream,
    hosts: &Hosts,
    settings: StreamSettings<A>,
) -> CloseOutcome {
    let (selected_host, rate_state) = {
        // One-byte reads cannot consume TLS records before the STARTTLS boundary.
        let mut input = pin!(AsyncReadStream::with_capacity(1, transport.clone()));
        let mut parser = XmppParser::new(
            RateLimitedReader::new(
                compio_reader(input.as_mut()),
                settings.xml_bytes_per_second,
                settings.xml_burst_bytes,
            ),
            ParserConfig {
                max_stanza_bytes: settings.max_stanza_bytes,
                arena: ArenaConfig::default(),
            },
            settings.allocator.clone(),
        );
        let header = match parser.next_event().await {
            Ok(Some(StreamEvent::StreamStart {
                header,
                content_namespace,
            })) => match validate_header(&header, &content_namespace, hosts) {
                Ok(header) => header,
                Err(outcome) => {
                    let response_to = response_to_from_header(&header);
                    return send_setup_error(
                        &mut transport,
                        hosts.default_host_name(),
                        response_to.as_deref(),
                        content_namespace == CLIENT_NAMESPACE,
                        outcome,
                    )
                    .await;
                }
            },
            Err(ParseError::UnexpectedEof) => return CloseOutcome::Eof,
            Err(error) => {
                let outcome = CloseOutcome::from_parse_error(&error);
                return send_setup_error(
                    &mut transport,
                    hosts.default_host_name(),
                    None,
                    false,
                    outcome,
                )
                .await;
            }
            _ => return CloseOutcome::ParserError,
        };
        if send_response_header(
            &mut transport,
            &header.host,
            header.response_to.as_deref(),
            header.client_content_namespace,
            true,
        )
        .await
        .is_err()
            || send(&mut transport, STARTTLS_FEATURES).await.is_err()
        {
            return CloseOutcome::TransportError;
        }
        let rate_state = match parser.next_event().await {
            Ok(Some(StreamEvent::Element(element))) if is_starttls(&element) => {
                if send(&mut transport, STARTTLS_PROCEED).await.is_err() {
                    return CloseOutcome::TransportError;
                }
                parser.into_inner().into_state()
            }
            Ok(Some(StreamEvent::Element(element))) if is_starttls_element(&element) => {
                if send(&mut transport, STARTTLS_FAILURE).await.is_err() {
                    return CloseOutcome::TransportError;
                }
                return CloseOutcome::StartTlsRejected;
            }
            Ok(Some(StreamEvent::StreamEnd) | None) => {
                if send(&mut transport, STREAM_FOOTER).await.is_err() {
                    return CloseOutcome::TransportError;
                }
                return CloseOutcome::StreamEnd;
            }
            Err(ParseError::UnexpectedEof) => return CloseOutcome::Eof,
            Err(error) => {
                let outcome = CloseOutcome::from_parse_error(&error);
                return send_stream_error(&mut transport, outcome).await;
            }
            _ => {
                return send_stream_error(&mut transport, CloseOutcome::UnsupportedInput).await;
            }
        };
        (header.host, rate_state)
    };

    let Some(tls_config) = hosts.tls_server_config(&selected_host) else {
        return CloseOutcome::InternalError;
    };
    let acceptor = TlsAcceptor::from(Arc::clone(tls_config));
    let mut transport = match acceptor.accept(transport).await {
        Ok(transport) => transport,
        Err(_) => return CloseOutcome::TlsFailure,
    };
    let restarted = read_restarted_header(&mut transport, hosts, &settings, rate_state).await;
    let outcome = match restarted {
        Ok(header) if header.host == selected_host => {
            if send_response_header(
                &mut transport,
                &header.host,
                header.response_to.as_deref(),
                header.client_content_namespace,
                true,
            )
            .await
            .is_err()
            {
                return CloseOutcome::TransportError;
            }
            send_stream_error(&mut transport, CloseOutcome::AuthenticationUnavailable).await
        }
        Ok(header) => {
            send_setup_error(
                &mut transport,
                &selected_host,
                header.response_to.as_deref(),
                header.client_content_namespace,
                CloseOutcome::HostUnknown,
            )
            .await
        }
        Err((CloseOutcome::Eof, _, _)) => CloseOutcome::Eof,
        Err((outcome, client_content_namespace, response_to)) => {
            send_setup_error(
                &mut transport,
                &selected_host,
                response_to.as_deref(),
                client_content_namespace,
                outcome,
            )
            .await
        }
    };
    let _ = transport.shutdown().await;
    outcome
}

async fn read_restarted_header<A: ChunkAllocator + Clone>(
    transport: &mut compio::tls::TlsStream<TcpStream>,
    hosts: &Hosts,
    settings: &StreamSettings<A>,
    rate_state: RateLimitState,
) -> Result<ClientHeader, (CloseOutcome, bool, Option<String>)> {
    let mut parser = XmppParser::new(
        RateLimitedReader::from_state(
            BufReader::with_capacity(READ_BUFFER_BYTES, Pin::new(transport).compat()),
            rate_state,
        ),
        ParserConfig {
            max_stanza_bytes: settings.max_stanza_bytes,
            arena: ArenaConfig::default(),
        },
        settings.allocator.clone(),
    );
    match parser.next_event().await {
        Ok(Some(StreamEvent::StreamStart {
            header,
            content_namespace,
        })) => validate_header(&header, &content_namespace, hosts).map_err(|outcome| {
            (
                outcome,
                content_namespace == CLIENT_NAMESPACE,
                response_to_from_header(&header),
            )
        }),
        Err(ParseError::UnexpectedEof) => Err((CloseOutcome::Eof, false, None)),
        Err(error) => Err((CloseOutcome::from_parse_error(&error), false, None)),
        _ => Err((CloseOutcome::ParserError, false, None)),
    }
}

struct ClientHeader {
    host: String,
    response_to: Option<String>,
    client_content_namespace: bool,
}

fn validate_header<A: ChunkAllocator>(
    header: &lonewolf_xmpp::parser::Parsed<Element, A>,
    content_namespace: &str,
    hosts: &Hosts,
) -> Result<ClientHeader, CloseOutcome> {
    if !matches!(content_namespace, "" | CLIENT_NAMESPACE | STREAM_NAMESPACE) {
        return Err(CloseOutcome::InvalidNamespace);
    }
    let header = header
        .value()
        .resolve(header.arena())
        .map_err(|_| CloseOutcome::InternalError)?;
    let version = header
        .attribute("version", "")
        .map_err(|_| CloseOutcome::InternalError)?
        .ok_or(CloseOutcome::UnsupportedVersion)?;
    let (major, minor) = version
        .split_once('.')
        .ok_or(CloseOutcome::UnsupportedVersion)?;
    if major.is_empty()
        || minor.is_empty()
        || major.bytes().all(|digit| digit == b'0')
        || !major.bytes().all(|digit| digit.is_ascii_digit())
        || !minor.bytes().all(|digit| digit.is_ascii_digit())
    {
        return Err(CloseOutcome::UnsupportedVersion);
    }
    let to = header
        .attribute("to", "")
        .map_err(|_| CloseOutcome::InternalError)?;
    let from = header
        .attribute("from", "")
        .map_err(|_| CloseOutcome::InternalError)?;
    if header
        .attribute("lang", lonewolf_xmpp::stanza::XML_NAMESPACE)
        .map_err(|_| CloseOutcome::InternalError)?
        .is_some_and(|lang| LangTag::new(lang).is_err())
    {
        return Err(CloseOutcome::InvalidLanguage);
    }
    let mut arena =
        Arena::try_new(ArenaConfig::default()).map_err(|_| CloseOutcome::InternalError)?;
    let host = match to {
        Some(to) => {
            let jid = Jid::parse_in(to, &mut arena).map_err(|_| CloseOutcome::HostUnknown)?;
            let jid = jid
                .resolve(&arena)
                .map_err(|_| CloseOutcome::InternalError)?;
            if jid.localpart().is_some() || jid.resourcepart().is_some() {
                return Err(CloseOutcome::HostUnknown);
            }
            if !hosts.is_local_host(jid.domainpart()) {
                return Err(CloseOutcome::HostUnknown);
            }
            jid.domainpart().to_owned()
        }
        None => hosts.default_host_name().to_owned(),
    };
    let response_to = from
        .map(|from| {
            let jid = Jid::parse_in(from, &mut arena).map_err(|_| CloseOutcome::InvalidFrom)?;
            Ok(jid
                .bare()
                .resolve(&arena)
                .map_err(|_| CloseOutcome::InternalError)?
                .as_str()
                .to_owned())
        })
        .transpose()?;
    Ok(ClientHeader {
        host,
        response_to,
        client_content_namespace: content_namespace == CLIENT_NAMESPACE,
    })
}

fn is_starttls<A: ChunkAllocator>(element: &lonewolf_xmpp::parser::Parsed<Element, A>) -> bool {
    let Ok(view) = element.value().resolve(element.arena()) else {
        return false;
    };
    view.name() == "starttls"
        && view.namespace() == STARTTLS_NAMESPACE
        && !element.has_explicit_attributes()
        && view
            .children()
            .is_ok_and(|mut children| children.next().is_none())
        && view.text().is_ok_and(|text| text.is_none())
}

fn response_to_from_header<A: ChunkAllocator>(
    header: &lonewolf_xmpp::parser::Parsed<Element, A>,
) -> Option<String> {
    let header = header.value().resolve(header.arena()).ok()?;
    let from = header.attribute("from", "").ok()??;
    let mut arena = Arena::try_new(ArenaConfig::default()).ok()?;
    let jid = Jid::parse_in(from, &mut arena).ok()?;
    Some(jid.bare().resolve(&arena).ok()?.as_str().to_owned())
}

fn is_starttls_element<A: ChunkAllocator>(
    element: &lonewolf_xmpp::parser::Parsed<Element, A>,
) -> bool {
    element
        .value()
        .resolve(element.arena())
        .is_ok_and(|element| {
            element.name() == "starttls" && element.namespace() == STARTTLS_NAMESPACE
        })
}

async fn send_setup_error<W: AsyncWrite>(
    transport: &mut W,
    host: &str,
    to: Option<&str>,
    client_content_namespace: bool,
    outcome: CloseOutcome,
) -> CloseOutcome {
    if send_response_header(
        transport,
        host,
        to,
        client_content_namespace,
        outcome != CloseOutcome::UnsupportedVersion,
    )
    .await
    .is_err()
    {
        return CloseOutcome::TransportError;
    }
    send_stream_error(transport, outcome).await
}

async fn send_stream_error<W: AsyncWrite>(
    transport: &mut W,
    outcome: CloseOutcome,
) -> CloseOutcome {
    let Some(condition) = outcome.stream_condition() else {
        return outcome;
    };
    let xml = format!(
        "<stream:error><{condition} xmlns='{STREAM_ERROR_NAMESPACE}'/></stream:error>{STREAM_FOOTER}"
    );
    if send_owned(transport, xml).await.is_err() {
        return CloseOutcome::TransportError;
    }
    outcome
}

async fn send_response_header<W: AsyncWrite>(
    transport: &mut W,
    host: &str,
    to: Option<&str>,
    client_content_namespace: bool,
    include_version: bool,
) -> Result<(), CloseOutcome> {
    let mut id = [0_u8; 16];
    graviola::random::fill(&mut id).map_err(|_| CloseOutcome::InternalError)?;
    let mut xml = String::with_capacity(192 + host.len() + to.map_or(0, str::len));
    xml.push_str(
        "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams'",
    );
    if client_content_namespace {
        xml.push_str(" xmlns='jabber:client'");
    }
    xml.push_str(" from='");
    escape_attribute(&mut xml, host);
    xml.push_str("' id='");
    write!(xml, "{:032x}", u128::from_be_bytes(id)).map_err(|_| CloseOutcome::InternalError)?;
    xml.push('\'');
    if include_version {
        xml.push_str(" version='1.0'");
    }
    xml.push_str(" xml:lang='en'");
    if let Some(to) = to {
        xml.push_str(" to='");
        escape_attribute(&mut xml, to);
        xml.push('\'');
    }
    xml.push('>');
    send_owned(transport, xml)
        .await
        .map_err(|_| CloseOutcome::TransportError)
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

async fn send<W: AsyncWrite>(transport: &mut W, xml: &'static str) -> std::io::Result<()> {
    transport.write_all(xml.as_bytes()).await.0
}

async fn send_owned<W: AsyncWrite>(transport: &mut W, xml: String) -> std::io::Result<()> {
    transport.write_all(xml.into_bytes()).await.0
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum CloseOutcome {
    StreamEnd,
    Eof,
    UnsupportedInput,
    SizeLimitExceeded,
    ParserError,
    HostUnknown,
    UnsupportedVersion,
    InvalidNamespace,
    InvalidFrom,
    InvalidLanguage,
    InvalidXml,
    RestrictedXml,
    UnsupportedEncoding,
    StartTlsRejected,
    TlsFailure,
    AuthenticationUnavailable,
    InternalError,
    TransportError,
}

impl CloseOutcome {
    fn from_parse_error(error: &ParseError) -> Self {
        match error {
            ParseError::SizeLimitExceeded { .. } => Self::SizeLimitExceeded,
            ParseError::InvalidNamespace => Self::InvalidNamespace,
            ParseError::InvalidXml => Self::InvalidXml,
            ParseError::RestrictedXml => Self::RestrictedXml,
            ParseError::UnsupportedEncoding => Self::UnsupportedEncoding,
            ParseError::UnsupportedVersion => Self::UnsupportedVersion,
            _ => Self::ParserError,
        }
    }

    fn stream_condition(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedInput => Some("not-authorized"),
            Self::SizeLimitExceeded => Some("policy-violation"),
            Self::ParserError => Some("bad-format"),
            Self::HostUnknown => Some("host-unknown"),
            Self::UnsupportedVersion => Some("unsupported-version"),
            Self::InvalidNamespace => Some("invalid-namespace"),
            Self::InvalidFrom => Some("invalid-from"),
            Self::InvalidLanguage => Some("bad-format"),
            Self::InvalidXml => Some("invalid-xml"),
            Self::RestrictedXml => Some("restricted-xml"),
            Self::UnsupportedEncoding => Some("unsupported-encoding"),
            Self::AuthenticationUnavailable | Self::InternalError => Some("internal-server-error"),
            _ => None,
        }
    }

    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::StreamEnd => "stream_end",
            Self::Eof => "eof",
            Self::UnsupportedInput => "unsupported_input",
            Self::SizeLimitExceeded => "size_limit_exceeded",
            Self::ParserError => "parser_error",
            Self::HostUnknown => "host_unknown",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidNamespace => "invalid_namespace",
            Self::InvalidFrom => "invalid_from",
            Self::InvalidLanguage => "invalid_language",
            Self::InvalidXml => "invalid_xml",
            Self::RestrictedXml => "restricted_xml",
            Self::UnsupportedEncoding => "unsupported_encoding",
            Self::StartTlsRejected => "starttls_rejected",
            Self::TlsFailure => "tls_failure",
            Self::AuthenticationUnavailable => "authentication_unavailable",
            Self::InternalError => "internal_error",
            Self::TransportError => "transport_error",
        }
    }
}

#[cfg(test)]
#[path = "../../tests/c2s/stream.rs"]
mod tests;
