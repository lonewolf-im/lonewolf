// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Write as _;
use std::net::Shutdown;
use std::num::NonZeroUsize;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use compio::io::compat::{AsyncReadStream, AsyncStream};
use compio::io::{AsyncWrite, AsyncWriteExt};
use compio::net::TcpStream;
use compio::time::timeout;
use futures_rustls::TlsAcceptor;
use futures_util::io::{
    AsyncReadExt as _, AsyncWrite as FuturesAsyncWrite, AsyncWriteExt as _, ReadHalf, WriteHalf,
};
use lonewolf_auth::scram::SCRAM_POLICY_ITERATIONS;
use lonewolf_auth::server::{BindingType, ClientFirst, Mechanism, ServerError};
use lonewolf_storage::account::{AccountKey, AccountRepository};
use lonewolf_util::arena::{Arena, ArenaConfig, ArenaRead, ChunkAllocator};
use lonewolf_util::rate_limited_reader::RateLimitedReader;
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{
    ParseError, Parsed, ParserConfig, StreamEvent, XmppParser, compio_reader,
};
use lonewolf_xmpp::stanza::{
    CLIENT_NAMESPACE, Element, IqType, NodeRef, STANZA_ERROR_NAMESPACE, STREAM_NAMESPACE, Stanza,
    StanzaErrorCondition, StanzaNamespace, StanzaRef, StanzaType, XML_NAMESPACE,
};
use lonewolf_xmpp::stream::{StreamError, StreamErrorCondition};
use oxilangtag::LanguageTag;
use socket2::SockRef;
use tokio::io::BufReader;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use super::AuthService;
use super::connection_limit::ConnectionPermit;
use super::unauthenticated_limit::UnauthenticatedPermit;
use crate::config::AuthMechanisms;
use crate::config::limits::ByteRate;
use crate::hosts::Hosts;
use crate::router::Registration;
use crate::router::{RouterError, RouterHandle};

const READ_BUFFER_BYTES: usize = 1_024;
const STARTTLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const STARTTLS_FEATURES: &str = "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>";
const STARTTLS_PROCEED: &str = "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
const STARTTLS_FAILURE: &str = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>";
const STREAM_FOOTER: &str = "</stream:stream>";
const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const BIND_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-bind";
const BIND_FEATURES: &str =
    "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>";
const MAX_AUTH_ATTEMPTS: usize = 3;
const MAX_BIND_FAILURES: usize = 6;

fn sasl_features(mechanisms: AuthMechanisms) -> String {
    let mut features = String::with_capacity(440);
    features.push_str("<stream:features>");
    if mechanisms.has_plus() {
        features.push_str("<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/><channel-binding type='tls-exporter'/></sasl-channel-binding>");
    }
    features.push_str("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>");
    for mechanism in [
        Mechanism::Sha256Plus,
        Mechanism::Sha256,
        Mechanism::Sha1Plus,
        Mechanism::Sha1,
    ] {
        if mechanisms.allows(mechanism) {
            features.push_str("<mechanism>");
            features.push_str(mechanism.name());
            features.push_str("</mechanism>");
        }
    }
    features.push_str("</mechanisms></stream:features>");
    features
}

type TlsTransport = futures_rustls::server::TlsStream<Pin<Box<AsyncStream<TcpStream>>>>;
type TlsReader = ReadHalf<TlsTransport>;
type TlsWriter = WriteHalf<TlsTransport>;
type XmlInput = RateLimitedReader<BufReader<tokio_util::compat::Compat<TlsReader>>>;

struct Established<A: ChunkAllocator> {
    parser: XmppParser<XmlInput, A>,
    writer: TlsWriter,
    host: String,
    client_from: Option<String>,
    binding: TlsBinding,
    auth_started_at: Instant,
}

struct Bound<A: ChunkAllocator> {
    parser: XmppParser<XmlInput, A>,
    writer: TlsWriter,
    registration: Registration<A>,
}

enum BindRequestError {
    Malformed,
    Internal,
}

struct TlsBinding {
    exporter: [u8; 32],
}

pub(super) struct XmppStream<A: ChunkAllocator> {
    transport: TcpStream,
    ip_permit: ConnectionPermit,
    unauthenticated_permit: UnauthenticatedPermit,
    hosts: Hosts,
    auth: Arc<AuthService>,
    router: RouterHandle<A>,
    settings: StreamSettings<A>,
    accepted_at: Instant,
}

#[derive(Clone)]
pub(super) struct StreamSettings<A: ChunkAllocator> {
    auth_mechanisms: AuthMechanisms,
    sasl_features: Arc<str>,
    max_stanza_bytes: NonZeroUsize,
    xml_bytes_per_second: NonZeroUsize,
    xml_burst_bytes: NonZeroUsize,
    establishment_timeout: Duration,
    authentication_timeout: Duration,
    binding_timeout: Duration,
    max_resources_per_account: NonZeroUsize,
    allocator: A,
}

#[derive(Clone, Copy)]
pub(super) struct StreamTimeouts {
    pub(super) establishment: Duration,
    pub(super) authentication: Duration,
    pub(super) binding: Duration,
}

impl<A: ChunkAllocator> StreamSettings<A> {
    pub(super) fn new(
        auth_mechanisms: AuthMechanisms,
        max_stanza_bytes: NonZeroUsize,
        xml_rate: &ByteRate,
        timeouts: StreamTimeouts,
        max_resources_per_account: NonZeroUsize,
        allocator: A,
    ) -> Self {
        Self {
            auth_mechanisms,
            sasl_features: sasl_features(auth_mechanisms).into(),
            max_stanza_bytes,
            xml_bytes_per_second: xml_rate.bytes_per_second,
            xml_burst_bytes: xml_rate.burst_bytes,
            establishment_timeout: timeouts.establishment,
            authentication_timeout: timeouts.authentication,
            binding_timeout: timeouts.binding,
            max_resources_per_account,
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
        auth: Arc<AuthService>,
        router: RouterHandle<A>,
        settings: StreamSettings<A>,
    ) -> Self {
        Self {
            transport,
            ip_permit,
            unauthenticated_permit,
            hosts,
            auth,
            router,
            settings,
            accepted_at: Instant::now(),
        }
    }

    pub(super) async fn run(self) -> CloseOutcome {
        let Self {
            transport,
            ip_permit,
            unauthenticated_permit,
            hosts,
            auth,
            router,
            settings,
            accepted_at,
        } = self;
        let close_control = transport.clone();
        let established = timeout(
            accepted_at
                .checked_add(settings.establishment_timeout)
                .map_or(Duration::ZERO, |deadline| {
                    deadline.saturating_duration_since(Instant::now())
                }),
            establish(transport, &hosts, &settings),
        )
        .await;
        let mut unauthenticated_permit = Some(unauthenticated_permit);
        let outcome = match established {
            Ok(Ok(mut established)) => {
                let authentication_remaining = established
                    .auth_started_at
                    .checked_add(settings.authentication_timeout)
                    .map_or(Duration::ZERO, |deadline| {
                        deadline.saturating_duration_since(Instant::now())
                    });
                match timeout(
                    authentication_remaining,
                    authenticate(&mut established, &hosts, &auth, settings.auth_mechanisms),
                )
                .await
                {
                    Ok(Ok(account)) => {
                        unauthenticated_permit.take();
                        let binding_started_at = Instant::now();
                        let binding_remaining = binding_started_at
                            .checked_add(settings.binding_timeout)
                            .map_or(Duration::ZERO, |deadline| {
                                deadline.saturating_duration_since(Instant::now())
                            });
                        match timeout(
                            binding_remaining,
                            bind_resource(
                                established,
                                &hosts,
                                &account,
                                &router,
                                settings.max_resources_per_account,
                            ),
                        )
                        .await
                        {
                            Ok(Ok(bound)) => bound_stream(bound).await,
                            Ok(Err(outcome)) => outcome,
                            Err(_) => {
                                let _ = SockRef::from(&close_control).shutdown(Shutdown::Both);
                                CloseOutcome::BindingTimeout
                            }
                        }
                    }
                    Ok(Err(outcome)) => outcome,
                    Err(_) => {
                        let _ = SockRef::from(&close_control).shutdown(Shutdown::Both);
                        CloseOutcome::AuthenticationTimeout
                    }
                }
            }
            Ok(Err(outcome)) => outcome,
            Err(_) => {
                let _ = SockRef::from(&close_control).shutdown(Shutdown::Both);
                CloseOutcome::EstablishmentTimeout
            }
        };
        drop(unauthenticated_permit);
        drop(ip_permit);
        outcome
    }
}

async fn establish<A: ChunkAllocator + Clone>(
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
            _ => {
                return Err(
                    send_stream_error(&mut transport, CloseOutcome::UnsupportedInput).await,
                );
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
    let (reader, mut writer) = transport.split();
    let mut parser = XmppParser::new(
        RateLimitedReader::from_state(
            BufReader::with_capacity(READ_BUFFER_BYTES, reader.compat()),
            rate_state,
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
                return Err(send_setup_error_tls(
                    &mut writer,
                    &selected_host,
                    response_to_from_header(&header).as_deref(),
                    content_namespace == CLIENT_NAMESPACE,
                    outcome,
                )
                .await);
            }
        },
        Err(ParseError::UnexpectedEof) => return Err(CloseOutcome::Eof),
        Err(error) => {
            let outcome = CloseOutcome::from_parse_error(&error);
            return Err(
                send_setup_error_tls(&mut writer, &selected_host, None, false, outcome).await,
            );
        }
        _ => return Err(CloseOutcome::ParserError),
    };
    if header.host != selected_host {
        return Err(send_setup_error_tls(
            &mut writer,
            &selected_host,
            header.response_to.as_deref(),
            header.client_content_namespace,
            CloseOutcome::HostUnknown,
        )
        .await);
    }
    send_response_header_tls(
        &mut writer,
        &selected_host,
        header.response_to.as_deref(),
        header.client_content_namespace,
        true,
    )
    .await?;
    send_tls(&mut writer, &settings.sasl_features).await?;
    Ok(Established {
        parser,
        writer,
        host: selected_host,
        client_from: header.response_to,
        binding: TlsBinding { exporter },
        auth_started_at: Instant::now(),
    })
}

async fn authenticate<A: ChunkAllocator + Clone>(
    established: &mut Established<A>,
    hosts: &Hosts,
    auth: &AuthService,
    mechanisms: AuthMechanisms,
) -> Result<AccountKey, CloseOutcome> {
    let Some(endpoint) = hosts.tls_server_end_point(&established.host) else {
        return Err(CloseOutcome::InternalError);
    };
    let mut replacement_auth = None;
    for attempt in 0..MAX_AUTH_ATTEMPTS {
        let (mechanism, initial) = if let Some(auth) = replacement_auth.take() {
            auth
        } else {
            let event = match established.parser.next_event().await {
                Ok(Some(event)) => event,
                Ok(None) | Err(ParseError::UnexpectedEof) => return Err(CloseOutcome::Eof),
                Err(error) => {
                    return Err(send_stream_error_tls(
                        &mut established.writer,
                        CloseOutcome::from_parse_error(&error),
                    )
                    .await);
                }
            };
            match event {
                StreamEvent::Element(element) => match parse_sasl_message(&element) {
                    Ok(SaslMessage::Auth { mechanism, payload }) => (mechanism, payload),
                    Ok(SaslMessage::Abort) => {
                        if send_sasl_failure(&mut established.writer, "aborted")
                            .await
                            .is_err()
                        {
                            return Err(CloseOutcome::TransportError);
                        }
                        if attempt + 1 == MAX_AUTH_ATTEMPTS {
                            break;
                        }
                        continue;
                    }
                    Err(condition) => {
                        if send_sasl_failure(&mut established.writer, condition)
                            .await
                            .is_err()
                        {
                            return Err(CloseOutcome::TransportError);
                        }
                        if attempt + 1 == MAX_AUTH_ATTEMPTS {
                            break;
                        }
                        continue;
                    }
                    _ => {
                        return Err(send_stream_error_tls(
                            &mut established.writer,
                            CloseOutcome::UnsupportedInput,
                        )
                        .await);
                    }
                },
                StreamEvent::StreamEnd => {
                    return Err(send_footer_tls(&mut established.writer).await);
                }
                _ => {
                    return Err(send_stream_error_tls(
                        &mut established.writer,
                        CloseOutcome::UnsupportedInput,
                    )
                    .await);
                }
            }
        };
        let Some(mechanism) = mechanism.filter(|mechanism| mechanisms.allows(*mechanism)) else {
            if send_sasl_failure(&mut established.writer, "invalid-mechanism")
                .await
                .is_err()
            {
                return Err(CloseOutcome::TransportError);
            }
            if attempt + 1 == MAX_AUTH_ATTEMPTS {
                break;
            }
            continue;
        };
        let initial = if initial.is_empty() {
            if send_tls(
                &mut established.writer,
                "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>",
            )
            .await
            .is_err()
            {
                return Err(CloseOutcome::TransportError);
            }
            match next_sasl_response(established).await {
                SaslResponse::Data(response) => response,
                SaslResponse::Auth { mechanism, payload } => {
                    replacement_auth = Some((mechanism, payload));
                    continue;
                }
                SaslResponse::Eof => return Err(CloseOutcome::Eof),
                SaslResponse::StreamEnd => {
                    return Err(send_footer_tls(&mut established.writer).await);
                }
                SaslResponse::ParseError(outcome) => {
                    return Err(send_stream_error_tls(&mut established.writer, outcome).await);
                }
                SaslResponse::Failure(condition) => {
                    if send_sasl_failure(&mut established.writer, condition)
                        .await
                        .is_err()
                    {
                        return Err(CloseOutcome::TransportError);
                    }
                    if attempt + 1 == MAX_AUTH_ATTEMPTS {
                        break;
                    }
                    continue;
                }
            }
        } else {
            initial
        };
        let first = match ClientFirst::parse(mechanism, &initial, mechanisms.has_plus()) {
            Ok(first) => first,
            Err(error) => {
                if send_sasl_failure(&mut established.writer, scram_failure(error))
                    .await
                    .is_err()
                {
                    return Err(CloseOutcome::TransportError);
                }
                if attempt + 1 == MAX_AUTH_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let binding_kind = first.binding();
        let account = account_key(first.username(), &established.host);
        let authzid_matches = first
            .authzid()
            .is_none_or(|authzid| account_key_from_jid(authzid).as_ref() == account.as_ref());
        let verifier = match account.as_ref() {
            Some(key) => match auth.accounts.get_scram(key, mechanism.hash()).await {
                Ok(verifier) => verifier,
                Err(_) => {
                    if send_sasl_failure(&mut established.writer, "temporary-auth-failure")
                        .await
                        .is_err()
                    {
                        return Err(CloseOutcome::TransportError);
                    }
                    if attempt + 1 == MAX_AUTH_ATTEMPTS {
                        break;
                    }
                    continue;
                }
            },
            None => None,
        };
        let verifier = verifier.filter(|verifier| verifier.iterations() == SCRAM_POLICY_ITERATIONS);
        let known = verifier.is_some() && authzid_matches;
        let verifier = match verifier {
            Some(verifier) => verifier,
            None => match auth.decoy.verifier(
                mechanism.hash(),
                &decoy_identity(account.as_ref(), first.username(), &established.host),
            ) {
                Ok(verifier) => verifier,
                Err(_) => {
                    return Err(send_stream_error_tls(
                        &mut established.writer,
                        CloseOutcome::InternalError,
                    )
                    .await);
                }
            },
        };
        let mut server_nonce = [0_u8; 24];
        if graviola::random::fill(&mut server_nonce).is_err() {
            return Err(send_stream_error_tls(
                &mut established.writer,
                CloseOutcome::InternalError,
            )
            .await);
        }
        let nonce = STANDARD.encode(server_nonce);
        let (server, challenge) = match first.start(verifier, &nonce) {
            Ok(value) => value,
            Err(_) => {
                return Err(send_stream_error_tls(
                    &mut established.writer,
                    CloseOutcome::InternalError,
                )
                .await);
            }
        };
        if send_sasl_data(&mut established.writer, "challenge", &challenge)
            .await
            .is_err()
        {
            return Err(CloseOutcome::TransportError);
        }
        let response = match next_sasl_response(established).await {
            SaslResponse::Data(response) => response,
            SaslResponse::Auth { mechanism, payload } => {
                replacement_auth = Some((mechanism, payload));
                continue;
            }
            SaslResponse::Eof => return Err(CloseOutcome::Eof),
            SaslResponse::StreamEnd => return Err(send_footer_tls(&mut established.writer).await),
            SaslResponse::ParseError(outcome) => {
                return Err(send_stream_error_tls(&mut established.writer, outcome).await);
            }
            SaslResponse::Failure(condition) => {
                if send_sasl_failure(&mut established.writer, condition)
                    .await
                    .is_err()
                {
                    return Err(CloseOutcome::TransportError);
                }
                if attempt + 1 == MAX_AUTH_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let binding_data: &[u8] = match binding_kind {
            Some(BindingType::TlsExporter) => &established.binding.exporter,
            Some(BindingType::TlsServerEndPoint) => endpoint,
            None => &[],
        };
        let final_message = server.finish(&response, binding_data);
        let authenticated = match final_message {
            Ok(message) if known => Some(message),
            Ok(_) | Err(ServerError::InvalidProof | ServerError::ChannelBindingMismatch) => None,
            Err(error) => {
                if send_sasl_failure(&mut established.writer, scram_failure(error))
                    .await
                    .is_err()
                {
                    return Err(CloseOutcome::TransportError);
                }
                if attempt + 1 == MAX_AUTH_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        if let Some(final_message) = authenticated {
            let Some(account_key) = account.as_ref() else {
                return Err(CloseOutcome::InternalError);
            };
            let current = match auth.accounts.get_scram(account_key, mechanism.hash()).await {
                Ok(current) => current,
                Err(_) => {
                    if send_sasl_failure(&mut established.writer, "temporary-auth-failure")
                        .await
                        .is_err()
                    {
                        return Err(CloseOutcome::TransportError);
                    }
                    if attempt + 1 == MAX_AUTH_ATTEMPTS {
                        break;
                    }
                    continue;
                }
            };
            if current
                .as_ref()
                .is_some_and(|current| server.credential_is_current(current))
            {
                if established
                    .client_from
                    .as_deref()
                    .is_some_and(|from| from != account_key.as_str())
                {
                    return Err(send_stream_error_tls(
                        &mut established.writer,
                        CloseOutcome::InvalidFrom,
                    )
                    .await);
                }
                if send_sasl_data(&mut established.writer, "success", &final_message)
                    .await
                    .is_err()
                {
                    return Err(CloseOutcome::TransportError);
                }
                return account.ok_or(CloseOutcome::InternalError);
            }
        }
        if send_sasl_failure(&mut established.writer, "not-authorized")
            .await
            .is_err()
        {
            return Err(CloseOutcome::TransportError);
        }
        if attempt + 1 == MAX_AUTH_ATTEMPTS {
            break;
        }
    }
    Err(send_stream_error_tls(
        &mut established.writer,
        CloseOutcome::AuthenticationAttemptsExceeded,
    )
    .await)
}

async fn bind_resource<A: ChunkAllocator + Clone>(
    established: Established<A>,
    hosts: &Hosts,
    account: &AccountKey,
    router: &RouterHandle<A>,
    max_resources_per_account: NonZeroUsize,
) -> Result<Bound<A>, CloseOutcome> {
    let Established {
        parser,
        mut writer,
        host,
        ..
    } = established;
    let mut parser = match parser.restart() {
        Ok(parser) => parser,
        Err(_) => {
            return Err(send_setup_error_tls(
                &mut writer,
                &host,
                None,
                false,
                CloseOutcome::ParserError,
            )
            .await);
        }
    };
    let header = match parser.next_event().await {
        Ok(Some(StreamEvent::StreamStart {
            header,
            content_namespace,
        })) => match validate_header(&header, &content_namespace, hosts) {
            Ok(header) => header,
            Err(outcome) => {
                return Err(send_setup_error_tls(
                    &mut writer,
                    &host,
                    response_to_from_header(&header).as_deref(),
                    content_namespace == CLIENT_NAMESPACE,
                    outcome,
                )
                .await);
            }
        },
        Err(ParseError::UnexpectedEof) => return Err(CloseOutcome::Eof),
        Err(error) => {
            return Err(send_setup_error_tls(
                &mut writer,
                &host,
                None,
                false,
                CloseOutcome::from_parse_error(&error),
            )
            .await);
        }
        _ => {
            return Err(send_setup_error_tls(
                &mut writer,
                &host,
                None,
                false,
                CloseOutcome::ParserError,
            )
            .await);
        }
    };
    if header.host != host
        || header
            .response_to
            .as_deref()
            .is_some_and(|from| from != account.as_str())
    {
        return Err(send_setup_error_tls(
            &mut writer,
            &host,
            header.response_to.as_deref(),
            header.client_content_namespace,
            CloseOutcome::InvalidFrom,
        )
        .await);
    }
    if send_response_header_tls(
        &mut writer,
        &host,
        header.response_to.as_deref(),
        header.client_content_namespace,
        true,
    )
    .await
    .is_err()
        || send_tls(&mut writer, BIND_FEATURES).await.is_err()
    {
        return Err(CloseOutcome::TransportError);
    }
    let mut invalid_attempts = 0;
    loop {
        let parsed = match parser.next_event().await {
            Ok(Some(StreamEvent::Stanza(parsed))) => parsed,
            Ok(Some(StreamEvent::StreamEnd) | None) => {
                return Err(send_footer_tls(&mut writer).await);
            }
            Err(ParseError::UnexpectedEof) => return Err(CloseOutcome::Eof),
            Err(error) => {
                return Err(send_stream_error_tls(
                    &mut writer,
                    CloseOutcome::from_parse_error(&error),
                )
                .await);
            }
            _ => {
                return Err(
                    send_stream_error_tls(&mut writer, CloseOutcome::UnsupportedInput).await,
                );
            }
        };
        let stanza = match parsed.value().resolve(parsed.arena()) {
            Ok(stanza) => stanza,
            Err(_) => {
                return Err(send_stream_error_tls(&mut writer, CloseOutcome::InternalError).await);
            }
        };
        if stanza.namespace() != StanzaNamespace::Client {
            return Err(send_stream_error_tls(&mut writer, CloseOutcome::InvalidNamespace).await);
        }
        if stanza.stanza_type() != StanzaType::Iq(IqType::Set) {
            return Err(send_stream_error_tls(&mut writer, CloseOutcome::UnsupportedInput).await);
        }
        let id = match stanza.id() {
            Ok(Some(id)) => id,
            Ok(None) => {
                return Err(send_stream_error_tls(&mut writer, CloseOutcome::ParserError).await);
            }
            Err(_) => {
                return Err(send_stream_error_tls(&mut writer, CloseOutcome::InternalError).await);
            }
        };
        let from = match stanza.from() {
            Ok(from) => from,
            Err(_) => {
                return Err(send_stream_error_tls(&mut writer, CloseOutcome::InternalError).await);
            }
        };
        if from.is_some_and(|from| from.as_str() != account.as_str()) {
            return Err(send_stream_error_tls(&mut writer, CloseOutcome::InvalidFrom).await);
        }
        let to = match stanza.to() {
            Ok(to) => to,
            Err(_) => {
                return Err(send_stream_error_tls(&mut writer, CloseOutcome::InternalError).await);
            }
        };
        if to.is_some_and(|to| to.as_str() != host) {
            return Err(send_stream_error_tls(&mut writer, CloseOutcome::UnsupportedInput).await);
        }
        let requested = match requested_resource(&stanza) {
            Ok(requested) => requested,
            Err(BindRequestError::Malformed) => {
                send_bind_error(&mut writer, id, "modify", "bad-request").await?;
                invalid_attempts += 1;
                if invalid_attempts == MAX_BIND_FAILURES {
                    return Err(send_stream_error_tls(
                        &mut writer,
                        CloseOutcome::BindingAttemptsExceeded,
                    )
                    .await);
                }
                continue;
            }
            Err(BindRequestError::Internal) => {
                return Err(send_stream_error_tls(&mut writer, CloseOutcome::InternalError).await);
            }
        };
        let registration = match router
            .register(account, requested, max_resources_per_account)
            .await
        {
            Ok(registration) => registration,
            Err(RouterError::InvalidResource) => {
                send_bind_error(&mut writer, id, "modify", "bad-request").await?;
                invalid_attempts += 1;
                if invalid_attempts == MAX_BIND_FAILURES {
                    return Err(send_stream_error_tls(
                        &mut writer,
                        CloseOutcome::BindingAttemptsExceeded,
                    )
                    .await);
                }
                continue;
            }
            Err(RouterError::ResourceLimit) => {
                send_bind_error(&mut writer, id, "wait", "resource-constraint").await?;
                continue;
            }
            Err(_) => {
                return Err(send_stream_error_tls(&mut writer, CloseOutcome::InternalError).await);
            }
        };
        send_bind_result(&mut writer, id, &registration).await?;
        return Ok(Bound {
            parser,
            writer,
            registration,
        });
    }
}

fn requested_resource<'a, R: ArenaRead>(
    stanza: &StanzaRef<'a, R>,
) -> Result<Option<&'a str>, BindRequestError> {
    let mut children = stanza.children().map_err(|_| BindRequestError::Internal)?;
    let bind = children
        .next()
        .ok_or(BindRequestError::Malformed)?
        .map_err(|_| BindRequestError::Internal)?;
    if children
        .next()
        .transpose()
        .map_err(|_| BindRequestError::Internal)?
        .is_some()
        || bind.name() != "bind"
        || bind.namespace() != BIND_NAMESPACE
    {
        return Err(BindRequestError::Malformed);
    }
    if bind
        .attributes()
        .map_err(|_| BindRequestError::Internal)?
        .next()
        .transpose()
        .map_err(|_| BindRequestError::Internal)?
        .is_some()
    {
        return Err(BindRequestError::Malformed);
    }
    let mut resource = None;
    for child in bind.children().map_err(|_| BindRequestError::Internal)? {
        match child.map_err(|_| BindRequestError::Internal)? {
            NodeRef::Text(text) if text.trim().is_empty() => {}
            NodeRef::Element(element)
                if element.name() == "resource"
                    && element.namespace() == BIND_NAMESPACE
                    && resource.is_none() =>
            {
                if element
                    .attributes()
                    .map_err(|_| BindRequestError::Internal)?
                    .next()
                    .transpose()
                    .map_err(|_| BindRequestError::Internal)?
                    .is_some()
                {
                    return Err(BindRequestError::Malformed);
                }
                let text = element
                    .text()
                    .map_err(|_| BindRequestError::Internal)?
                    .filter(|text| !text.is_empty())
                    .ok_or(BindRequestError::Malformed)?;
                resource = Some(text);
            }
            _ => return Err(BindRequestError::Malformed),
        }
    }
    Ok(resource)
}

async fn send_bind_result<A: ChunkAllocator>(
    writer: &mut TlsWriter,
    id: &str,
    registration: &Registration<A>,
) -> Result<(), CloseOutcome> {
    let jid = registration.full_jid();
    let mut xml = String::with_capacity(119 + CLIENT_NAMESPACE.len() + id.len() + jid.len());
    xml.push_str("<iq xmlns='");
    xml.push_str(CLIENT_NAMESPACE);
    xml.push_str("' type='result' id='");
    escape_attribute(&mut xml, id);
    xml.push_str("'><bind xmlns='");
    xml.push_str(BIND_NAMESPACE);
    xml.push_str("'><jid>");
    escape_text(&mut xml, &jid);
    xml.push_str("</jid></bind></iq>");
    send_tls(writer, &xml).await
}

async fn send_bind_error(
    writer: &mut TlsWriter,
    id: &str,
    error_type: &str,
    condition: &str,
) -> Result<(), CloseOutcome> {
    let mut xml = String::with_capacity(129 + CLIENT_NAMESPACE.len() + id.len());
    xml.push_str("<iq xmlns='");
    xml.push_str(CLIENT_NAMESPACE);
    xml.push_str("' type='error' id='");
    escape_attribute(&mut xml, id);
    xml.push_str("'><error type='");
    xml.push_str(error_type);
    xml.push_str("'><");
    xml.push_str(condition);
    xml.push_str(" xmlns='");
    xml.push_str(STANZA_ERROR_NAMESPACE);
    xml.push_str("'/></error></iq>");
    send_tls(writer, &xml).await
}

fn escape_text(output: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            _ => output.push(ch),
        }
    }
}

async fn bound_stream<A: ChunkAllocator + Clone>(bound: Bound<A>) -> CloseOutcome {
    let Bound {
        mut parser,
        mut writer,
        registration,
    } = bound;
    let mut response = String::new();
    let outcome = loop {
        match parser.next_event().await {
            Ok(Some(StreamEvent::StreamEnd) | None) => break send_footer_tls(&mut writer).await,
            Ok(Some(StreamEvent::Stanza(parsed))) => {
                let (stanza_type, namespace) = match parsed.value().resolve(parsed.arena()) {
                    Ok(stanza) => (stanza.stanza_type(), stanza.namespace()),
                    Err(_) => {
                        break send_stream_error_tls(&mut writer, CloseOutcome::InternalError)
                            .await;
                    }
                };
                if namespace != StanzaNamespace::Client {
                    break send_stream_error_tls(&mut writer, CloseOutcome::UnsupportedBoundInput)
                        .await;
                }
                match stanza_type {
                    StanzaType::Iq(IqType::Get | IqType::Set) => {
                        if let Err(outcome) =
                            unsupported_iq_xml(parsed, &registration, &mut response)
                        {
                            break send_stream_error_tls(&mut writer, outcome).await;
                        }
                        if let Err(outcome) = send_tls(&mut writer, &response).await {
                            break outcome;
                        }
                    }
                    StanzaType::Iq(IqType::Result | IqType::Error) => {}
                    _ => {
                        break send_stream_error_tls(
                            &mut writer,
                            CloseOutcome::UnsupportedBoundInput,
                        )
                        .await;
                    }
                }
            }
            Err(ParseError::UnexpectedEof) => break CloseOutcome::Eof,
            Err(error) => {
                break send_stream_error_tls(&mut writer, CloseOutcome::from_parse_error(&error))
                    .await;
            }
            _ => {
                break send_stream_error_tls(&mut writer, CloseOutcome::UnsupportedBoundInput)
                    .await;
            }
        }
    };
    drop(registration);
    outcome
}

fn unsupported_iq_xml<A: ChunkAllocator>(
    parsed: Parsed<Stanza, A>,
    registration: &Registration<A>,
    xml: &mut String,
) -> Result<(), CloseOutcome> {
    let (request, mut arena) = parsed.into_parts();
    let addressed = request
        .resolve(&arena)
        .map_err(|_| CloseOutcome::InternalError)?
        .to()
        .map_err(|_| CloseOutcome::InternalError)?
        .is_some();
    let from = if addressed {
        let (_, domain) = registration
            .account()
            .as_str()
            .split_once('@')
            .ok_or(CloseOutcome::InternalError)?;
        Some(Jid::parse_in(domain, &mut arena).map_err(|_| CloseOutcome::InternalError)?)
    } else {
        None
    };
    let reply = request
        .error_reply_in(&mut arena, StanzaErrorCondition::ServiceUnavailable)
        .map_err(|_| CloseOutcome::InternalError)?
        .from(from)
        .map_err(|_| CloseOutcome::InternalError)?
        .to(None)
        .map_err(|_| CloseOutcome::InternalError)?
        .build()
        .map_err(|_| CloseOutcome::InternalError)?;
    xml.clear();
    reply
        .resolve(&arena)
        .map_err(|_| CloseOutcome::InternalError)?
        .write_xml(xml)
        .map_err(|_| CloseOutcome::InternalError)?;
    Ok(())
}

fn account_key(username: &str, host: &str) -> Option<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default()).ok()?;
    let jid = Jid::from_parts_in(Some(username), host, None, &mut arena).ok()?;
    AccountKey::try_from(jid.resolve(&arena).ok()?).ok()
}

fn decoy_identity<'a>(account: Option<&'a AccountKey>, username: &str, host: &str) -> Cow<'a, str> {
    match account {
        Some(account) => Cow::Borrowed(account.as_str()),
        None => Cow::Owned(format!("\0{host}\0{username}")),
    }
}

fn account_key_from_jid(jid: &str) -> Option<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default()).ok()?;
    let jid = Jid::parse_in(jid, &mut arena).ok()?;
    AccountKey::try_from(jid.resolve(&arena).ok()?).ok()
}

fn scram_failure(error: ServerError) -> &'static str {
    match error {
        ServerError::Malformed => "malformed-request",
        ServerError::UnsupportedBinding => "malformed-request",
        ServerError::ChannelBindingMismatch | ServerError::InvalidProof => "not-authorized",
        ServerError::HashMismatch | ServerError::RandomUnavailable => "temporary-auth-failure",
    }
}

enum SaslMessage {
    Auth {
        mechanism: Option<Mechanism>,
        payload: Vec<u8>,
    },
    Response(Vec<u8>),
    Abort,
}

fn parse_sasl_message<A: ChunkAllocator>(
    element: &lonewolf_xmpp::parser::Parsed<Element, A>,
) -> Result<SaslMessage, &'static str> {
    let view = element
        .value()
        .resolve(element.arena())
        .map_err(|_| "malformed-request")?;
    if view.namespace() != SASL_NAMESPACE {
        return Err("malformed-request");
    }
    let mut mechanism = None;
    let mut attribute_count = 0;
    for attribute in view.attributes().map_err(|_| "malformed-request")? {
        let attribute = attribute.map_err(|_| "malformed-request")?;
        if attribute.name == "lang" && attribute.namespace == XML_NAMESPACE {
            continue;
        }
        attribute_count += 1;
        if attribute.name == "mechanism" && attribute.namespace.is_empty() {
            mechanism = Some(attribute.value);
        }
    }
    let mut content = None;
    for child in view.children().map_err(|_| "malformed-request")? {
        let child = child.map_err(|_| "malformed-request")?;
        match child {
            NodeRef::Text(text) if content.is_none() => content = Some(text),
            _ => return Err("malformed-request"),
        }
    }
    match view.name() {
        "auth" if attribute_count == 1 => {
            let mechanism = mechanism.ok_or("malformed-request")?;
            Ok(SaslMessage::Auth {
                mechanism: Mechanism::from_name(mechanism),
                payload: decode_sasl_text(content)?,
            })
        }
        "response" if attribute_count == 0 => Ok(SaslMessage::Response(decode_sasl_text(content)?)),
        "abort" if attribute_count == 0 && content.is_none() => Ok(SaslMessage::Abort),
        _ => Err("malformed-request"),
    }
}

fn decode_sasl_text(text: Option<&str>) -> Result<Vec<u8>, &'static str> {
    let text = text.unwrap_or_default();
    if text == "=" || text.is_empty() {
        return Ok(Vec::new());
    }
    if text.len() > 8_192 {
        return Err("malformed-request");
    }
    STANDARD.decode(text).map_err(|_| "incorrect-encoding")
}

enum SaslResponse {
    Data(Vec<u8>),
    Auth {
        mechanism: Option<Mechanism>,
        payload: Vec<u8>,
    },
    Failure(&'static str),
    StreamEnd,
    Eof,
    ParseError(CloseOutcome),
}

async fn next_sasl_response<A: ChunkAllocator + Clone>(
    established: &mut Established<A>,
) -> SaslResponse {
    match established.parser.next_event().await {
        Ok(Some(StreamEvent::Element(element))) => match parse_sasl_message(&element) {
            Ok(SaslMessage::Response(response)) => SaslResponse::Data(response),
            Ok(SaslMessage::Auth { mechanism, payload }) => {
                SaslResponse::Auth { mechanism, payload }
            }
            Ok(SaslMessage::Abort) => SaslResponse::Failure("aborted"),
            Err(condition) => SaslResponse::Failure(condition),
        },
        Ok(Some(StreamEvent::StreamEnd)) => SaslResponse::StreamEnd,
        Ok(None) | Err(ParseError::UnexpectedEof) => SaslResponse::Eof,
        Err(error) => SaslResponse::ParseError(CloseOutcome::from_parse_error(&error)),
        _ => SaslResponse::Failure("malformed-request"),
    }
}

async fn send_sasl_failure(
    writer: &mut TlsWriter,
    condition: &'static str,
) -> Result<(), CloseOutcome> {
    let mut xml = String::with_capacity(SASL_NAMESPACE.len() + condition.len() + 48);
    write!(
        xml,
        "<failure xmlns='{SASL_NAMESPACE}'><{condition}/></failure>"
    )
    .map_err(|_| CloseOutcome::InternalError)?;
    send_tls(writer, &xml).await
}

async fn send_sasl_data(
    writer: &mut TlsWriter,
    kind: &'static str,
    message: &str,
) -> Result<(), CloseOutcome> {
    let mut xml = String::with_capacity(message.len() * 4 / 3 + 96);
    write!(xml, "<{kind} xmlns='{SASL_NAMESPACE}'>").map_err(|_| CloseOutcome::InternalError)?;
    STANDARD.encode_string(message, &mut xml);
    write!(xml, "</{kind}>").map_err(|_| CloseOutcome::InternalError)?;
    send_tls(writer, &xml).await
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
        .is_some_and(|lang| LanguageTag::parse(lang).is_err())
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

fn response_header_xml(
    host: &str,
    to: Option<&str>,
    client_content_namespace: bool,
    include_version: bool,
) -> Result<String, CloseOutcome> {
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
    Ok(xml)
}

fn stream_error_xml(outcome: CloseOutcome) -> Option<String> {
    let condition = outcome.stream_condition()?;
    let mut xml = String::with_capacity(128);
    StreamError::new(condition).write_xml(&mut xml).ok()?;
    xml.push_str(STREAM_FOOTER);
    Some(xml)
}

async fn send_tls<W: FuturesAsyncWrite + Unpin>(
    writer: &mut W,
    xml: &str,
) -> Result<(), CloseOutcome> {
    writer
        .write_all(xml.as_bytes())
        .await
        .map_err(|_| CloseOutcome::TransportError)?;
    writer
        .flush()
        .await
        .map_err(|_| CloseOutcome::TransportError)
}

async fn send_footer_tls<W: FuturesAsyncWrite + Unpin>(writer: &mut W) -> CloseOutcome {
    if send_tls(writer, STREAM_FOOTER).await.is_err() || writer.close().await.is_err() {
        CloseOutcome::TransportError
    } else {
        CloseOutcome::StreamEnd
    }
}

async fn send_response_header_tls<W: FuturesAsyncWrite + Unpin>(
    writer: &mut W,
    host: &str,
    to: Option<&str>,
    client_content_namespace: bool,
    include_version: bool,
) -> Result<(), CloseOutcome> {
    let xml = response_header_xml(host, to, client_content_namespace, include_version)?;
    send_tls(writer, &xml).await
}

async fn send_stream_error_tls<W: FuturesAsyncWrite + Unpin>(
    writer: &mut W,
    outcome: CloseOutcome,
) -> CloseOutcome {
    let Some(xml) = stream_error_xml(outcome) else {
        return outcome;
    };
    if send_tls(writer, &xml).await.is_err() || writer.close().await.is_err() {
        CloseOutcome::TransportError
    } else {
        outcome
    }
}

async fn send_setup_error_tls<W: FuturesAsyncWrite + Unpin>(
    writer: &mut W,
    host: &str,
    to: Option<&str>,
    client_content_namespace: bool,
    outcome: CloseOutcome,
) -> CloseOutcome {
    if let Err(outcome) = send_response_header_tls(
        writer,
        host,
        to,
        client_content_namespace,
        outcome != CloseOutcome::UnsupportedVersion,
    )
    .await
    {
        return outcome;
    }
    send_stream_error_tls(writer, outcome).await
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CloseOutcome {
    StreamEnd,
    Eof,
    UnsupportedInput,
    UnsupportedBoundInput,
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
    AuthenticationTimeout,
    BindingTimeout,
    BindingAttemptsExceeded,
    EstablishmentTimeout,
    AuthenticationAttemptsExceeded,
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

    fn stream_condition(&self) -> Option<StreamErrorCondition> {
        match self {
            Self::UnsupportedInput => Some(StreamErrorCondition::NotAuthorized),
            Self::SizeLimitExceeded => Some(StreamErrorCondition::PolicyViolation),
            Self::ParserError | Self::InvalidLanguage => Some(StreamErrorCondition::BadFormat),
            Self::HostUnknown => Some(StreamErrorCondition::HostUnknown),
            Self::UnsupportedVersion => Some(StreamErrorCondition::UnsupportedVersion),
            Self::InvalidNamespace => Some(StreamErrorCondition::InvalidNamespace),
            Self::InvalidFrom => Some(StreamErrorCondition::InvalidFrom),
            Self::InvalidXml => Some(StreamErrorCondition::InvalidXml),
            Self::RestrictedXml => Some(StreamErrorCondition::RestrictedXml),
            Self::UnsupportedEncoding => Some(StreamErrorCondition::UnsupportedEncoding),
            Self::AuthenticationAttemptsExceeded => Some(StreamErrorCondition::PolicyViolation),
            Self::BindingAttemptsExceeded | Self::UnsupportedBoundInput => {
                Some(StreamErrorCondition::PolicyViolation)
            }
            Self::InternalError => Some(StreamErrorCondition::InternalServerError),
            _ => None,
        }
    }

    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::StreamEnd => "stream_end",
            Self::Eof => "eof",
            Self::UnsupportedInput => "unsupported_input",
            Self::UnsupportedBoundInput => "unsupported_bound_input",
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
            Self::AuthenticationTimeout => "authentication_timeout",
            Self::BindingTimeout => "binding_timeout",
            Self::BindingAttemptsExceeded => "binding_attempts_exceeded",
            Self::EstablishmentTimeout => "establishment_timeout",
            Self::AuthenticationAttemptsExceeded => "authentication_attempts_exceeded",
            Self::InternalError => "internal_error",
            Self::TransportError => "transport_error",
        }
    }
}

#[cfg(test)]
#[path = "../../tests/c2s/stream.rs"]
mod tests;
