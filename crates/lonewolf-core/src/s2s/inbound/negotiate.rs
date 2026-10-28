// SPDX-License-Identifier: Apache-2.0

use std::pin::{Pin, pin};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use compio::io::compat::{AsyncReadStream, AsyncStream};
use compio::net::TcpStream;
use futures_rustls::TlsAcceptor;
use futures_util::future::{Either, select};
use futures_util::io::{AsyncReadExt as _, ReadHalf, WriteHalf};
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{Parsed, StreamEvent};
use lonewolf_xmpp::stanza::Element;
use lonewolf_xmpp::stream::StreamErrorCondition;
use rustls::pki_types::{CertificateDer, UnixTime};
use tokio::io::BufReader;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _};

use super::{Settings, ShutdownSignal};
use crate::s2s::metrics::{AuthOutcome, Direction, S2sMetrics};
use crate::s2s::stream::traffic::CountingIo;
use crate::s2s::stream::{self, Auth, S2sError, S2sReader, S2sWriter, SaslFailure};

const TLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const CLOSE_GRACE: Duration = Duration::from_secs(5);

type PlainInput = Compat<Pin<Box<AsyncReadStream<TcpStream>>>>;
type PlainOutput = Pin<Box<AsyncStream<TcpStream>>>;
type TlsTransport = CountingIo<futures_rustls::server::TlsStream<PlainOutput>>;
type TlsInput = BufReader<Compat<ReadHalf<TlsTransport>>>;
type TlsOutput = WriteHalf<TlsTransport>;

pub(crate) struct Authenticated<A: ChunkAllocator> {
    pub(crate) local: Box<str>,
    pub(crate) remote: Box<str>,
    #[allow(dead_code)]
    pub(crate) valid_until: SystemTime,
    pub(crate) reader: S2sReader<A, TlsInput>,
    pub(crate) writer: S2sWriter<TlsOutput>,
    pub(crate) connection_id: u64,
}

enum Connection<A: ChunkAllocator> {
    Plain(S2sReader<A, PlainInput>, S2sWriter<PlainOutput>),
    Tls(S2sReader<A, TlsInput>, S2sWriter<TlsOutput>),
}

impl<A: ChunkAllocator + Clone> Connection<A> {
    async fn next(&mut self) -> Result<Option<StreamEvent<A>>, S2sError> {
        match self {
            Self::Plain(reader, _) => reader.next_event().await,
            Self::Tls(reader, _) => reader.next_event().await,
        }
    }

    async fn send(&mut self, xml: &str) -> Result<(), S2sError> {
        match self {
            Self::Plain(_, writer) => writer.send(xml).await,
            Self::Tls(_, writer) => writer.send(xml).await,
        }
    }

    async fn close(&mut self, condition: Option<StreamErrorCondition>) -> Result<(), S2sError> {
        match self {
            Self::Plain(_, writer) => writer.close(condition).await,
            Self::Tls(_, writer) => writer.close(condition).await,
        }
    }

    async fn shutdown(&mut self) -> Result<(), S2sError> {
        match self {
            Self::Plain(_, writer) => writer.shutdown().await,
            Self::Tls(_, writer) => writer.shutdown().await,
        }
    }
}

struct Accounting {
    metrics: Arc<S2sMetrics>,
    started: Instant,
    outcome: AuthOutcome,
    elapsed: Option<Duration>,
}

impl Drop for Accounting {
    fn drop(&mut self) {
        self.metrics.authentication(
            Direction::Inbound,
            self.outcome,
            self.elapsed.unwrap_or_else(|| self.started.elapsed()),
        );
    }
}

struct Failure {
    error: S2sError,
    outcome: AuthOutcome,
}

impl From<S2sError> for Failure {
    fn from(error: S2sError) -> Self {
        Self {
            error,
            outcome: AuthOutcome::Protocol,
        }
    }
}

fn reject(condition: StreamErrorCondition, outcome: AuthOutcome) -> Failure {
    Failure {
        error: S2sError::Stream(condition),
        outcome,
    }
}

pub(super) async fn negotiate<A: ChunkAllocator + Clone>(
    tcp: &TcpStream,
    settings: &Settings<A>,
    shutdown: ShutdownSignal,
    connection_id: u64,
) -> Result<Authenticated<A>, S2sError> {
    let mut accounting = Accounting {
        metrics: Arc::clone(&settings.metrics),
        started: Instant::now(),
        outcome: AuthOutcome::Protocol,
        elapsed: None,
    };
    let mut connection = Some(Connection::Plain(
        S2sReader::plain(
            tcp.clone(),
            &settings.reader_limits,
            settings.allocator.clone(),
            Some(Arc::clone(&settings.metrics)),
        ),
        S2sWriter::new(Box::pin(AsyncStream::new(tcp.clone()))),
    ));
    let mut response_from: Box<str> = settings.hosts.default_host_name().into();
    let mut header_sent = false;
    let mut peer_footer = false;
    let mut footer_sent = false;
    let deadline = accounting.started + settings.timeout;
    let mut close_deadline = None;
    let result = {
        let flow = run(
            tcp,
            settings,
            &mut connection,
            &mut header_sent,
            &mut peer_footer,
            &mut footer_sent,
            &mut response_from,
        );
        match select(
            pin!(shutdown),
            pin!(compio::time::timeout_at(deadline, flow)),
        )
        .await
        {
            Either::Left((deadline, _)) => {
                close_deadline = Some(deadline);
                Err(reject(
                    StreamErrorCondition::SystemShutdown,
                    AuthOutcome::Protocol,
                ))
            }
            Either::Right((Ok(result), _)) => result,
            Either::Right((Err(_), _)) => Err(reject(
                StreamErrorCondition::ConnectionTimeout,
                AuthOutcome::Timeout,
            )),
        }
    };
    accounting.elapsed = Some(accounting.started.elapsed());
    match result {
        Ok((local, remote, valid_until)) => {
            accounting.outcome = AuthOutcome::Success;
            let Some(Connection::Tls(reader, writer)) = connection.take() else {
                return Err(S2sError::Internal);
            };
            Ok(Authenticated {
                local,
                remote,
                valid_until,
                reader,
                writer,
                connection_id,
            })
        }
        Err(failure) => {
            accounting.outcome = failure.outcome;
            if let Some(connection) = &mut connection {
                let deadline = close_deadline
                    .unwrap_or_else(|| Instant::now() + CLOSE_GRACE + Duration::from_secs(1));
                let _ = compio::time::timeout_at(deadline, async {
                    if !header_sent {
                        connection
                            .send(&stream::response_header_xml(&response_from, None)?)
                            .await?;
                    }
                    if !footer_sent {
                        let condition = match failure.error {
                            S2sError::Stream(condition) => Some(condition),
                            _ => None,
                        };
                        connection.close(condition).await?;
                    }
                    if !peer_footer {
                        let _ = compio::time::timeout_at(
                            deadline.min(Instant::now() + CLOSE_GRACE),
                            async {
                                while let Ok(Some(event)) = connection.next().await {
                                    if matches!(event, StreamEvent::StreamEnd) {
                                        break;
                                    }
                                }
                            },
                        )
                        .await;
                    }
                    connection.shutdown().await
                })
                .await;
            }
            let _ = socket2::SockRef::from(tcp).shutdown(std::net::Shutdown::Both);
            Err(failure.error)
        }
    }
}

async fn expected<A: ChunkAllocator + Clone>(
    connection: &mut Connection<A>,
    peer_footer: &mut bool,
) -> Result<StreamEvent<A>, S2sError> {
    match connection.next().await? {
        Some(StreamEvent::StreamEnd) => {
            *peer_footer = true;
            Err(S2sError::Eof)
        }
        Some(event) => Ok(event),
        None => Err(S2sError::Eof),
    }
}

fn header<A: ChunkAllocator>(event: StreamEvent<A>) -> Result<stream::InitialHeader, Failure> {
    let StreamEvent::StreamStart {
        header,
        content_namespace,
        ..
    } = event
    else {
        return Err(reject(
            StreamErrorCondition::NotAuthorized,
            AuthOutcome::Protocol,
        ));
    };
    stream::validate_initial_header(&header, &content_namespace).map_err(|condition| {
        reject(
            condition,
            match condition {
                StreamErrorCondition::HostUnknown => AuthOutcome::HostUnknown,
                StreamErrorCondition::InvalidFrom => AuthOutcome::InvalidFrom,
                _ => AuthOutcome::Protocol,
            },
        )
    })
}

async fn run<A: ChunkAllocator + Clone>(
    tcp: &TcpStream,
    settings: &Settings<A>,
    connection: &mut Option<Connection<A>>,
    header_sent: &mut bool,
    peer_footer: &mut bool,
    footer_sent: &mut bool,
    response_from: &mut Box<str>,
) -> Result<(Box<str>, Box<str>, SystemTime), Failure> {
    let plain = connection.as_mut().ok_or(S2sError::Internal)?;
    let initial = header(expected(plain, peer_footer).await?)?;
    if !settings.hosts.federates(&initial.to) {
        plain
            .send(&stream::response_header_xml(
                settings.hosts.default_host_name(),
                initial.from.as_deref(),
            )?)
            .await?;
        *header_sent = true;
        return Err(reject(
            StreamErrorCondition::HostUnknown,
            AuthOutcome::HostUnknown,
        ));
    }
    *response_from = initial.to.clone();
    plain
        .send(&stream::response_header_xml(
            &initial.to,
            initial.from.as_deref(),
        )?)
        .await?;
    *header_sent = true;
    plain.send(stream::STARTTLS_REQUIRED_FEATURES).await?;
    match expected(plain, peer_footer).await? {
        StreamEvent::Element(element) if is_empty_element(&element, "starttls", TLS_NAMESPACE)? => {
        }
        StreamEvent::Element(element)
            if element
                .value()
                .resolve(element.arena())
                .map_err(S2sError::from)?
                .namespace()
                == TLS_NAMESPACE =>
        {
            plain.send(stream::TLS_FAILURE).await?;
            return Err(S2sError::Eof.into());
        }
        _ => {
            return Err(reject(
                StreamErrorCondition::NotAuthorized,
                AuthOutcome::Protocol,
            ));
        }
    }
    let Some(config) = settings
        .hosts
        .s2s_server_config(&initial.to, &settings.trust)
    else {
        plain.send(stream::TLS_FAILURE).await?;
        return Err(S2sError::Eof.into());
    };
    plain.send(stream::PROCEED).await?;
    let Some(Connection::Plain(mut reader, writer)) = connection.take() else {
        return Err(S2sError::Internal.into());
    };
    let (input, state) = reader.take_input().await?;
    drop(input);
    drop(reader);
    drop(writer);
    let tls = TlsAcceptor::from(config)
        .accept(Box::pin(AsyncStream::new(tcp.clone())))
        .await
        .map_err(|_| Failure {
            error: S2sError::Io,
            outcome: AuthOutcome::TlsFailure,
        })?;
    let certificate = tls.get_ref().1.peer_certificates().and_then(|chain| {
        chain.first().map(|leaf| {
            (
                leaf.clone().into_owned(),
                settings
                    .trust
                    .verify_chain(chain, UnixTime::now())
                    .map(|validity| validity.valid_until),
            )
        })
    });
    let (input, output) =
        CountingIo::new(tls, Arc::clone(&settings.metrics), Direction::Inbound).split();
    *connection = Some(Connection::Tls(
        S2sReader::from_state(
            BufReader::new(input.compat()),
            state,
            settings.allocator.clone(),
        ),
        S2sWriter::new(output),
    ));
    *header_sent = false;
    let tls = connection.as_mut().ok_or(S2sError::Internal)?;
    let restarted = header(expected(tls, peer_footer).await?)?;
    if restarted.to != initial.to {
        return Err(reject(
            StreamErrorCondition::HostUnknown,
            AuthOutcome::HostUnknown,
        ));
    }
    let remote = restarted.from.ok_or_else(|| {
        reject(
            StreamErrorCondition::NotAuthorized,
            AuthOutcome::MissingFrom,
        )
    })?;
    if settings.hosts.is_local_host(&remote) {
        return Err(reject(
            StreamErrorCondition::InvalidFrom,
            AuthOutcome::InvalidFrom,
        ));
    }
    let (leaf, validity) = certificate.ok_or_else(|| {
        reject(
            StreamErrorCondition::NotAuthorized,
            AuthOutcome::NoCertificate,
        )
    })?;
    let valid_until = verify_peer(settings, &leaf, validity, &remote)?;
    tls.send(&stream::response_header_xml(&initial.to, Some(&remote))?)
        .await?;
    *header_sent = true;
    tls.send(stream::EXTERNAL_FEATURES).await?;
    for attempt in 0..2 {
        let auth = expected(tls, peer_footer).await?;
        let StreamEvent::Element(element) = auth else {
            return Err(reject(
                StreamErrorCondition::NotAuthorized,
                AuthOutcome::Protocol,
            ));
        };
        let resolved = element
            .value()
            .resolve(element.arena())
            .map_err(S2sError::from)?;
        if resolved.name() != "auth" || resolved.namespace() != SASL_NAMESPACE {
            return Err(reject(
                StreamErrorCondition::NotAuthorized,
                AuthOutcome::Protocol,
            ));
        }
        let mut response = stream::parse_auth(&element);
        if matches!(response, Ok(Auth::NoInitialResponse)) {
            tls.send(stream::EMPTY_CHALLENGE).await?;
            response = match expected(tls, peer_footer).await? {
                StreamEvent::Element(element) => challenge_response(&element)?,
                _ => {
                    return Err(reject(
                        StreamErrorCondition::NotAuthorized,
                        AuthOutcome::Protocol,
                    ));
                }
            };
        }
        let authorized = match response {
            Ok(Auth::Response(bytes)) => authorize(&bytes, &remote),
            Ok(Auth::NoInitialResponse) => Err(SaslFailure::MalformedRequest),
            Err(failure) => Err(failure),
        };
        match authorized {
            Ok(()) => break,
            Err(failure) => {
                tls.send(&stream::sasl_failure_xml(failure)).await?;
                if attempt == 1 {
                    tls.close(None).await?;
                    *footer_sent = true;
                    return Err(Failure {
                        error: S2sError::Eof,
                        outcome: match failure {
                            SaslFailure::InvalidAuthzid => AuthOutcome::InvalidAuthzid,
                            SaslFailure::InvalidMechanism => AuthOutcome::InvalidMechanism,
                            _ => AuthOutcome::Protocol,
                        },
                    });
                }
            }
        }
    }
    tls.send(stream::SASL_SUCCESS).await?;
    if let Connection::Tls(reader, _) = tls {
        reader.restart()?;
    }
    *header_sent = false;
    let final_header = header(expected(tls, peer_footer).await?)?;
    if final_header.from.as_deref() != Some(&remote) {
        return Err(reject(
            StreamErrorCondition::InvalidFrom,
            AuthOutcome::InvalidFrom,
        ));
    }
    if final_header.to != initial.to {
        return Err(reject(
            StreamErrorCondition::HostUnknown,
            AuthOutcome::InvalidFrom,
        ));
    }
    tls.send(&stream::response_header_xml(&initial.to, Some(&remote))?)
        .await?;
    *header_sent = true;
    tls.send(stream::EMPTY_FEATURES).await?;
    Ok((initial.to, remote, valid_until))
}

fn verify_peer<A: ChunkAllocator>(
    settings: &Settings<A>,
    leaf: &CertificateDer<'_>,
    validity: Result<SystemTime, rustls::Error>,
    remote: &str,
) -> Result<SystemTime, Failure> {
    let valid_until =
        validity.map_err(|_| reject(StreamErrorCondition::NotAuthorized, AuthOutcome::Protocol))?;
    if settings.trust.verify_identity(leaf, remote).is_err() {
        tracing::warn!(outcome = "certificate_rejected", remote_domain = %safe_domain(remote), "s2s certificate rejected");
        return Err(reject(
            StreamErrorCondition::NotAuthorized,
            AuthOutcome::CertificateName,
        ));
    }
    Ok(valid_until)
}

fn is_empty_element<A: ChunkAllocator>(
    parsed: &Parsed<Element, A>,
    name: &str,
    namespace: &str,
) -> Result<bool, S2sError> {
    let element = parsed.value().resolve(parsed.arena())?;
    Ok(element.name() == name
        && element.namespace() == namespace
        && !parsed.has_explicit_attributes()
        && element.children()?.next().is_none()
        && element.text()?.is_none())
}

fn challenge_response<A: ChunkAllocator>(
    parsed: &Parsed<Element, A>,
) -> Result<Result<Auth, SaslFailure>, Failure> {
    if is_empty_element(parsed, "abort", SASL_NAMESPACE)? {
        return Ok(Err(SaslFailure::Aborted));
    }
    let element = parsed
        .value()
        .resolve(parsed.arena())
        .map_err(S2sError::from)?;
    if element.name() != "response" || element.namespace() != SASL_NAMESPACE {
        return Err(reject(
            StreamErrorCondition::NotAuthorized,
            AuthOutcome::Protocol,
        ));
    }
    let text = element.text().map_err(S2sError::from)?.unwrap_or("");
    Ok(if text == "=" || text.is_empty() {
        Ok(Auth::Response(Vec::new()))
    } else {
        STANDARD
            .decode(text)
            .map(Auth::Response)
            .map_err(|_| SaslFailure::MalformedRequest)
    })
}

fn authorize(bytes: &[u8], remote: &str) -> Result<(), SaslFailure> {
    if bytes.is_empty() {
        return Ok(());
    }
    let value = std::str::from_utf8(bytes).map_err(|_| SaslFailure::MalformedRequest)?;
    let mut arena =
        Arena::try_new(ArenaConfig::default()).map_err(|_| SaslFailure::NotAuthorized)?;
    let jid = Jid::parse_in(value, &mut arena).map_err(|_| SaslFailure::InvalidAuthzid)?;
    let jid = jid
        .resolve(&arena)
        .map_err(|_| SaslFailure::NotAuthorized)?;
    if jid.localpart().is_none() && jid.resourcepart().is_none() && jid.domainpart() == remote {
        Ok(())
    } else {
        Err(SaslFailure::InvalidAuthzid)
    }
}

pub(super) fn safe_domain(domain: &str) -> String {
    domain
        .chars()
        .take(253)
        .map(|ch| if ch.is_control() { '\u{fffd}' } else { ch })
        .collect()
}

pub(super) async fn serve<A: ChunkAllocator + Clone>(
    mut authenticated: Authenticated<A>,
    tcp: &TcpStream,
    shutdown: ShutdownSignal,
) -> &'static str {
    tracing::info!(connection_id = authenticated.connection_id, local_domain = %safe_domain(&authenticated.local), remote_domain = %safe_domain(&authenticated.remote), direction = "inbound", "s2s connection authenticated");
    let (condition, peer_closed, deadline, outcome) = loop {
        match select(
            pin!(shutdown.clone()),
            pin!(authenticated.reader.next_event()),
        )
        .await
        {
            Either::Left((deadline, _)) => {
                break (
                    Some(StreamErrorCondition::SystemShutdown),
                    false,
                    deadline,
                    "shutdown",
                );
            }
            Either::Right((Ok(Some(StreamEvent::StreamEnd)), _)) => {
                break (None, true, Instant::now() + CLOSE_GRACE, "stream_end");
            }
            Either::Right((Ok(None), _)) => {
                break (None, true, Instant::now() + CLOSE_GRACE, "eof");
            }
            Either::Right((Err(error), _)) => {
                break (
                    match error {
                        S2sError::Stream(condition) => Some(condition),
                        _ => None,
                    },
                    false,
                    Instant::now() + CLOSE_GRACE + Duration::from_secs(1),
                    "protocol",
                );
            }
            Either::Right((
                Ok(Some(StreamEvent::Stanza(_) | StreamEvent::RejectedStanza(_))),
                _,
            )) => {
                tracing::debug!(
                    connection_id = authenticated.connection_id,
                    "s2s stanza discarded"
                );
            }
            Either::Right((Ok(Some(_)), _)) => {
                break (
                    Some(StreamErrorCondition::NotAuthorized),
                    false,
                    Instant::now() + CLOSE_GRACE + Duration::from_secs(1),
                    "protocol",
                );
            }
        }
    };
    let _ = compio::time::timeout_at(deadline, async {
        authenticated.writer.close(condition).await?;
        if !peer_closed {
            let _ = compio::time::timeout_at(deadline.min(Instant::now() + CLOSE_GRACE), async {
                while let Ok(Some(event)) = authenticated.reader.next_event().await {
                    if matches!(event, StreamEvent::StreamEnd) {
                        break;
                    }
                }
            })
            .await;
        }
        authenticated.writer.shutdown().await
    })
    .await;
    let _ = socket2::SockRef::from(tcp).shutdown(std::net::Shutdown::Both);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_normalizes_domain_only_identities() {
        assert_eq!(authorize(b"PEER.TEST", "peer.test"), Ok(()));
        assert_eq!(authorize(b"", "peer.test"), Ok(()));
        for value in [
            b"other.test".as_slice(),
            b"user@peer.test",
            b"peer.test/resource",
        ] {
            assert_eq!(
                authorize(value, "peer.test"),
                Err(SaslFailure::InvalidAuthzid)
            );
        }
    }
    #[test]
    fn log_domains_are_bounded_and_control_free() {
        let domain = format!("{}\n", "a".repeat(300));
        assert_eq!(safe_domain(&domain).len(), 253);
        assert_eq!(safe_domain("bad\nname"), "bad\u{fffd}name");
    }
}
