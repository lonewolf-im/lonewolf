// SPDX-License-Identifier: Apache-2.0

use std::pin::pin;
use std::sync::Arc;
use std::time::Instant;

use compio::io::compat::{AsyncReadStream, AsyncStream};
use compio::io::{AsyncWrite, AsyncWriteExt};
use compio::net::TcpStream;
use futures_rustls::TlsAcceptor;
use futures_util::io::AsyncReadExt as _;
use lonewolf_util::arena::{ArenaConfig, ChunkAllocator};
use lonewolf_util::rate_limited_reader::RateLimitedReader;
use lonewolf_xmpp::parser::{
    ParseError, Parsed, ParserConfig, StreamEvent, XmppParser, compio_reader,
};
use lonewolf_xmpp::stanza::{CLIENT_NAMESPACE, Element};
use tokio::io::BufReader;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use super::StreamSettings;
use super::header::{
    STREAM_FOOTER, response_header_xml, response_to_from_header, stream_error_xml, validate_header,
};
use super::outcome::CloseOutcome;
use super::session::{IO_BUFFER_BYTES, Session, namespace_error};
use super::stanza_rate::StanzaLimiter;
use crate::hosts::Hosts;

pub(super) const STARTTLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
pub(super) const STARTTLS_FEATURES: &str = "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>";
pub(super) const STARTTLS_PROCEED: &str = "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
const STARTTLS_FAILURE: &str = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>";

/// A secured stream whose client has been offered the SASL mechanisms.
pub(super) struct Established<A: ChunkAllocator> {
    pub(super) session: Session<A>,
    pub(super) client_from: Option<String>,
    pub(super) binding: TlsBinding,
    pub(super) auth_started_at: Instant,
}

pub(super) struct TlsBinding {
    pub(super) exporter: [u8; 32],
}

pub(super) async fn establish<A: ChunkAllocator + Clone>(
    mut transport: TcpStream,
    hosts: &Hosts,
    settings: &StreamSettings<A>,
) -> Result<Established<A>, CloseOutcome> {
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
                    return Err(send_setup_error(
                        &mut transport,
                        hosts.default_host_name(),
                        response_to.as_deref(),
                        content_namespace == CLIENT_NAMESPACE,
                        outcome,
                    )
                    .await);
                }
            },
            Err(ParseError::UnexpectedEof) => return Err(CloseOutcome::Eof),
            Err(error) => {
                let outcome = CloseOutcome::from_parse_error(&error);
                return Err(send_setup_error(
                    &mut transport,
                    hosts.default_host_name(),
                    None,
                    false,
                    outcome,
                )
                .await);
            }
            _ => return Err(CloseOutcome::ParserError),
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
            return Err(CloseOutcome::TransportError);
        }
        let rate_state = match parser.next_event().await {
            Ok(Some(StreamEvent::Element(element))) if is_starttls(&element) => {
                if send(&mut transport, STARTTLS_PROCEED).await.is_err() {
                    return Err(CloseOutcome::TransportError);
                }
                parser.into_inner().into_state()
            }
            Ok(Some(StreamEvent::Element(element))) if is_starttls_element(&element) => {
                if send(&mut transport, STARTTLS_FAILURE).await.is_err() {
                    return Err(CloseOutcome::TransportError);
                }
                return Err(CloseOutcome::StartTlsRejected);
            }
            Ok(Some(StreamEvent::StreamEnd) | None) => {
                if send(&mut transport, STREAM_FOOTER).await.is_err() {
                    return Err(CloseOutcome::TransportError);
                }
                return Err(CloseOutcome::StreamEnd);
            }
            Err(ParseError::UnexpectedEof) => return Err(CloseOutcome::Eof),
            Err(error) => {
                let outcome = CloseOutcome::from_parse_error(&error);
                return Err(send_stream_error(&mut transport, outcome).await);
            }
            Ok(Some(event)) => {
                let outcome = namespace_error(&event).unwrap_or(CloseOutcome::UnsupportedInput);
                return Err(send_stream_error(&mut transport, outcome).await);
            }
        };
        (header.host, rate_state)
    };

    let Some(tls_config) = hosts.tls_server_config(&selected_host) else {
        return Err(CloseOutcome::InternalError);
    };
    let acceptor = TlsAcceptor::from(Arc::clone(tls_config));
    let transport = match acceptor.accept(Box::pin(AsyncStream::new(transport))).await {
        Ok(transport) => transport,
        Err(_) => return Err(CloseOutcome::TlsFailure),
    };
    let mut exporter = [0_u8; 32];
    transport
        .get_ref()
        .1
        .export_keying_material(&mut exporter, b"EXPORTER-Channel-Binding", None)
        .map_err(|_| CloseOutcome::TlsFailure)?;
    let (reader, writer) = transport.split();
    let parser = XmppParser::new(
        RateLimitedReader::from_state(
            BufReader::with_capacity(IO_BUFFER_BYTES, reader.compat()),
            rate_state,
        ),
        ParserConfig {
            max_stanza_bytes: settings.max_stanza_bytes,
            arena: ArenaConfig::default(),
        },
        settings.allocator.clone(),
    );
    let mut session = Session::new(
        parser,
        writer,
        selected_host,
        StanzaLimiter::new(settings.stanzas_per_second, settings.stanza_burst),
    );
    let header = session.read_header(hosts).await?;
    if header.host != session.host() {
        return Err(session
            .writer
            .reject_header(
                header.response_to.as_deref(),
                header.client_content_namespace,
                CloseOutcome::HostUnknown,
            )
            .await);
    }
    session.writer.send_header(&header).await?;
    session.writer.send(&settings.sasl_features).await?;
    Ok(Established {
        session,
        client_from: header.response_to,
        binding: TlsBinding { exporter },
        auth_started_at: Instant::now(),
    })
}

fn is_starttls<A: ChunkAllocator>(element: &Parsed<Element, A>) -> bool {
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

fn is_starttls_element<A: ChunkAllocator>(element: &Parsed<Element, A>) -> bool {
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
    let Some(xml) = stream_error_xml(outcome) else {
        return outcome;
    };
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
    let xml = response_header_xml(host, to, client_content_namespace, include_version)?;
    send_owned(transport, xml)
        .await
        .map_err(|_| CloseOutcome::TransportError)
}

async fn send<W: AsyncWrite>(transport: &mut W, xml: &'static str) -> std::io::Result<()> {
    transport.write_all(xml.as_bytes()).await.0
}

async fn send_owned<W: AsyncWrite>(transport: &mut W, xml: String) -> std::io::Result<()> {
    transport.write_all(xml.into_bytes()).await.0
}
