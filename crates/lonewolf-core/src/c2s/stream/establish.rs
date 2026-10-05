// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use compio::io::compat::{AsyncReadStream, AsyncStream};
use compio::net::TcpStream;
use futures_rustls::TlsAcceptor;
use futures_util::io::AsyncReadExt as _;
use lonewolf_util::arena::{ArenaConfig, ChunkAllocator};
use lonewolf_util::rate_limited_reader::RateLimitedReader;
use lonewolf_xmpp::parser::{Parsed, ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{CLIENT_NAMESPACE, Element};
use tokio::io::BufReader;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use super::StreamSettings;
use super::close::{self, CloseContext};
use super::header::{response_to_from_header, validate_header};
use super::outcome::CloseOutcome;
use super::session::{
    ClosingInput, IO_BUFFER_BYTES, ReadMode, Reader, Session, Writer, namespace_error,
    peer_stream_error,
};
use super::stanza_rate::StanzaLimiter;
use crate::hosts::Hosts;

pub(super) const STARTTLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
pub(super) const STARTTLS_FEATURES: &str = "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>";
pub(super) const STARTTLS_PROCEED: &str = "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
const STARTTLS_FAILURE: &str = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";

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
    transport: TcpStream,
    hosts: &Hosts,
    settings: &StreamSettings<A>,
    context: CloseContext,
) -> Result<Established<A>, CloseOutcome> {
    let closing = Rc::new(Cell::new(ReadMode::Open));
    // One-byte reads cannot consume TLS records before the STARTTLS boundary.
    let input = Box::pin(AsyncReadStream::with_capacity(1, transport.clone())).compat();
    let parser = XmppParser::new(
        ClosingInput::new(
            RateLimitedReader::new(
                input,
                settings.xml_bytes_per_second,
                settings.xml_burst_bytes,
            ),
            Rc::clone(&closing),
        ),
        ParserConfig {
            max_stanza_bytes: settings.max_stanza_bytes,
            arena: ArenaConfig::default(),
        },
        settings.allocator.clone(),
    );
    let mut reader = Reader::with_mode(
        parser,
        StanzaLimiter::new(settings.stanzas_per_second, settings.stanza_burst),
        closing,
    );
    let mut writer = Writer::new(
        Box::pin(AsyncStream::new(transport.clone())),
        hosts.default_host_name().to_owned(),
    );
    let plain = context
        .interrupt(async {
            let header = match reader.next_event().await {
                Ok(Some(StreamEvent::StreamStart {
                    header,
                    content_namespace,
                })) => match validate_header(&header, &content_namespace, hosts) {
                    Ok(header) => header,
                    Err(outcome) => {
                        return Err(writer
                            .reject_header(
                                response_to_from_header(&header).as_deref(),
                                content_namespace == CLIENT_NAMESPACE,
                                outcome,
                            )
                            .await);
                    }
                },
                Err(CloseOutcome::Eof) => return Err(CloseOutcome::Eof),
                Err(outcome) => return Err(writer.reject_header(None, false, outcome).await),
                _ => return Err(CloseOutcome::ParserError),
            };
            writer.set_host(header.host.clone());
            writer.send_header(&header).await?;
            writer.send(STARTTLS_FEATURES).await?;
            match reader.next_event().await? {
                Some(StreamEvent::Element(element)) if is_starttls(&element) => {
                    writer.send(STARTTLS_PROCEED).await?;
                    Ok(header.host)
                }
                Some(StreamEvent::Element(element)) if is_starttls_element(&element) => {
                    writer.send(STARTTLS_FAILURE).await?;
                    Err(CloseOutcome::StartTlsRejected)
                }
                Some(StreamEvent::StreamEnd) | None => Err(CloseOutcome::StreamEnd),
                Some(event) => {
                    if let Some(condition) = peer_stream_error(&event)? {
                        return Err(CloseOutcome::PeerError(condition));
                    }
                    Err(namespace_error(&event).unwrap_or(CloseOutcome::UnsupportedInput))
                }
            }
        })
        .await;
    let selected_host = match plain {
        Ok(host) => host,
        Err(outcome) => {
            return Err(
                close::finish_plain(&mut reader, &mut writer, outcome.into(), &context).await,
            );
        }
    };
    let rate_state = reader.take_input().await?.into_rate_limited().into_state();
    drop(writer);
    let Some(tls_config) = hosts.tls_server_config(&selected_host) else {
        return Err(CloseOutcome::InternalError);
    };
    let acceptor = TlsAcceptor::from(Arc::clone(tls_config));
    let transport = context
        .interrupt(async {
            acceptor
                .accept(Box::pin(AsyncStream::new(transport)))
                .await
                .map_err(|_| CloseOutcome::TlsFailure)
        })
        .await?;
    let mut exporter = [0_u8; 32];
    transport
        .get_ref()
        .1
        .export_keying_material(&mut exporter, b"EXPORTER-Channel-Binding", Some(&[]))
        .map_err(|_| CloseOutcome::TlsFailure)?;
    let (read, write) = transport.split();
    let closing = Rc::new(Cell::new(ReadMode::Open));
    let parser = XmppParser::new(
        ClosingInput::new(
            RateLimitedReader::from_state(
                BufReader::with_capacity(IO_BUFFER_BYTES, read.compat()),
                rate_state,
            ),
            Rc::clone(&closing),
        ),
        ParserConfig {
            max_stanza_bytes: settings.max_stanza_bytes,
            arena: ArenaConfig::default(),
        },
        settings.allocator.clone(),
    );
    let mut session = Session::new(
        parser,
        write,
        selected_host,
        StanzaLimiter::new(settings.stanzas_per_second, settings.stanza_burst),
        closing,
        context.clone(),
    );
    let opened = context
        .interrupt(async {
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
            Ok(header)
        })
        .await;
    let header = match opened {
        Ok(header) => header,
        Err(outcome) => return Err(session.finish(outcome).await),
    };
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
