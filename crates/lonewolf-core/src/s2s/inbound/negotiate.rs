// SPDX-License-Identifier: Apache-2.0

use std::pin::{Pin, pin};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use compio::io::compat::{AsyncReadStream, AsyncStream};
use compio::net::TcpStream;
use futures_rustls::{LazyConfigAcceptor, TlsAcceptor};
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
use crate::s2s::log_domain;
use crate::s2s::metrics::{AuthOutcome, BidiOutcome, Direction, S2sMetrics, TransportAttempt};
use crate::s2s::outbound::RemoteRouter;
use crate::s2s::revocation::{CheckPhase, RevocationStatus, RevocationVerdict};
use crate::s2s::stream::traffic::S2sTrafficObserver;
use crate::s2s::stream::{self, Auth, S2sError, S2sReader, S2sWriter, SaslFailure};
use crate::xml_stream::traffic::CountingIo;

const TLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const CLOSE_GRACE: Duration = Duration::from_secs(5);

type PlainInput = Compat<Pin<Box<AsyncReadStream<TcpStream>>>>;
type PlainOutput = Pin<Box<AsyncStream<TcpStream>>>;
type TlsTransport = CountingIo<futures_rustls::server::TlsStream<PlainOutput>, S2sTrafficObserver>;
type TlsInput = BufReader<Compat<ReadHalf<TlsTransport>>>;
type TlsOutput = WriteHalf<TlsTransport>;

pub(crate) struct Authenticated<A: ChunkAllocator> {
    pub(crate) local: Box<str>,
    pub(crate) remote: Box<str>,
    pub(crate) valid_until: SystemTime,
    pub(crate) chain: Arc<[CertificateDer<'static>]>,
    pub(crate) revocation: Option<RevocationVerdict>,
    pub(crate) reader: S2sReader<A, TlsInput>,
    pub(crate) writer: S2sWriter<TlsOutput>,
    pub(crate) connection_id: u64,
    pub(crate) bidi: bool,
}

struct VerifiedPeer {
    bidi_offered: bool,
    bidi: bool,
    local: Box<str>,
    remote: Box<str>,
    valid_until: SystemTime,
    chain: Arc<[CertificateDer<'static>]>,
    revocation: Option<RevocationVerdict>,
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

    async fn send_header(&mut self, xml: &str) -> Result<(), S2sError> {
        match self {
            Self::Plain(_, writer) => writer.send_header(xml).await,
            Self::Tls(_, writer) => writer.send_header(xml).await,
        }
    }

    fn update_peer_limits(&mut self, update: Option<stream::limits::StreamLimits>) {
        match self {
            Self::Plain(_, writer) => writer.update_peer_limits(update),
            Self::Tls(_, writer) => writer.update_peer_limits(update),
        }
    }

    async fn close(&mut self, condition: Option<StreamErrorCondition>) -> Result<(), S2sError> {
        match self {
            Self::Plain(_, writer) => writer.close(condition).await,
            Self::Tls(_, writer) => writer.close(condition).await,
        }
    }

    async fn shutdown(&mut self, peer_footer: bool) -> Result<(), S2sError> {
        match self {
            Self::Plain(_, writer) => writer.shutdown().await,
            Self::Tls(reader, writer) => {
                writer.shutdown().await?;
                if peer_footer {
                    reader.read_transport_end().await
                } else {
                    Ok(())
                }
            }
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
    mut attempt: TransportAttempt,
) -> Result<Authenticated<A>, S2sError> {
    let mut accounting = Accounting {
        metrics: Arc::clone(&settings.metrics),
        started: Instant::now(),
        outcome: AuthOutcome::Protocol,
        elapsed: None,
    };
    let mut connection = match settings.tls_mode {
        crate::config::TlsMode::Direct => None,
        crate::config::TlsMode::StartTls => Some(Connection::Plain(
            S2sReader::plain(
                tcp.clone(),
                &settings.reader_limits,
                settings.services.allocator.clone(),
                Some(Arc::clone(&settings.metrics)),
            ),
            S2sWriter::new(Box::pin(AsyncStream::new(tcp.clone()))),
        )),
    };
    let mut response_from: Box<str> = match settings.tls_mode {
        crate::config::TlsMode::Direct => Box::default(),
        crate::config::TlsMode::StartTls => settings.hosts.default_host_name().into(),
    };
    let mut header_sent = false;
    let mut peer_footer = false;
    let mut footer_sent = false;
    let deadline = accounting.started + settings.timeout;
    let mut close_deadline = None;
    let mut cancelled = false;
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
                cancelled = true;
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
    match &result {
        Ok(_) => attempt.complete(AuthOutcome::Success),
        Err(_) if cancelled => attempt.cancel(),
        Err(failure) => attempt.complete(failure.outcome),
    }
    match result {
        Ok(VerifiedPeer {
            bidi_offered,
            bidi,
            local,
            remote,
            valid_until,
            chain,
            revocation,
        }) => {
            accounting.outcome = AuthOutcome::Success;
            if bidi_offered {
                settings.metrics.bidi_negotiated(
                    Direction::Inbound,
                    if bidi {
                        BidiOutcome::Enabled
                    } else {
                        BidiOutcome::NotRequested
                    },
                );
            }
            let Some(Connection::Tls(reader, writer)) = connection.take() else {
                return Err(S2sError::Internal);
            };
            Ok(Authenticated {
                bidi,
                local,
                remote,
                valid_until,
                chain,
                revocation,
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
                            .send_header(&stream::response_header_xml(&response_from, None)?)
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
                                        peer_footer = true;
                                        break;
                                    }
                                }
                            },
                        )
                        .await;
                    }
                    connection.shutdown(peer_footer).await
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
) -> Result<VerifiedPeer, Failure> {
    let local_limits = stream::limits::local_limits(
        settings.reader_limits.max_stanza_bytes.get(),
        settings.idle_timeout.as_secs(),
    )?;
    let mut features_xml = String::new();
    let offer_bidi = settings
        .services
        .router
        .remote_router()
        .is_some_and(RemoteRouter::bidirectional);
    let (local, tls, state) = if settings.tls_mode == crate::config::TlsMode::Direct {
        let accepted = LazyConfigAcceptor::new(
            rustls::server::Acceptor::default(),
            Box::pin(AsyncStream::new(tcp.clone())),
        )
        .await
        .map_err(|_| Failure {
            error: S2sError::Io,
            outcome: AuthOutcome::TlsFailure,
        })?;
        let local = select_sni(accepted.client_hello().server_name(), settings)
            .ok_or_else(|| reject(StreamErrorCondition::HostUnknown, AuthOutcome::HostUnknown))?;
        let config = settings
            .hosts
            .s2s_direct_server_config(&local, &settings.trust)
            .ok_or_else(|| reject(StreamErrorCondition::HostUnknown, AuthOutcome::HostUnknown))?;
        let tls = accepted.into_stream(config).await.map_err(|_| Failure {
            error: S2sError::Io,
            outcome: AuthOutcome::TlsFailure,
        })?;
        *response_from = local.clone();
        (local, tls, None)
    } else {
        let plain = connection.as_mut().ok_or(S2sError::Internal)?;
        let initial = header(expected(plain, peer_footer).await?)?;
        if !settings.services.router.federates_domain(&initial.to) {
            plain
                .send_header(&stream::response_header_xml(
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
            .send_header(&stream::response_header_xml(
                &initial.to,
                initial.from.as_deref(),
            )?)
            .await?;
        *header_sent = true;
        stream::limits::write_features_xml(
            &mut features_xml,
            stream::limits::FeaturePhase::StartTls,
            local_limits,
        )?;
        plain.send(&features_xml).await?;
        match expected(plain, peer_footer).await? {
            StreamEvent::Element(element)
                if is_empty_element(&element, "starttls", TLS_NAMESPACE)? => {}
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
        let Some(Connection::Plain(mut reader, mut writer)) = connection.take() else {
            return Err(S2sError::Internal.into());
        };
        writer.send(stream::PROCEED).await?;
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
        (initial.to, tls, Some(state))
    };
    let certificate = tls.get_ref().1.peer_certificates().and_then(|chain| {
        chain.first().map(|_| {
            (
                chain
                    .iter()
                    .map(|certificate| certificate.clone().into_owned())
                    .collect::<Arc<[_]>>(),
                settings
                    .trust
                    .verify_chain(chain, UnixTime::now())
                    .map(|validity| validity.valid_until),
            )
        })
    });
    let counted = CountingIo::new(
        tls,
        S2sTrafficObserver::new(Arc::clone(&settings.metrics), Direction::Inbound),
    );
    let activity = counted.observer().activity();
    let (input, output) = counted.split();
    *connection = Some(Connection::Tls(
        match state {
            Some(state) => S2sReader::from_state(
                BufReader::new(input.compat()),
                state,
                settings.services.allocator.clone(),
            ),
            None => S2sReader::new(
                BufReader::new(input.compat()),
                &settings.reader_limits,
                settings.services.allocator.clone(),
                Some(Arc::clone(&settings.metrics)),
            ),
        }
        .with_activity(activity),
        S2sWriter::new(output),
    ));
    *header_sent = false;
    let tls = connection.as_mut().ok_or(S2sError::Internal)?;
    let restarted = header(expected(tls, peer_footer).await?)?;
    if restarted.to != local {
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
    let (chain, validity) = certificate.ok_or_else(|| {
        reject(
            StreamErrorCondition::NotAuthorized,
            AuthOutcome::NoCertificate,
        )
    })?;
    let valid_until = verify_peer(settings, &chain[0], validity, &remote)?;
    let revocation = settings
        .revocation
        .check(
            Arc::clone(&chain),
            Direction::Inbound,
            CheckPhase::Handshake,
        )
        .await;
    if let Some(verdict) = &revocation {
        if let Some(outcome) = verdict.auth_outcome() {
            tracing::warn!(outcome = outcome.as_str(), direction = "inbound", tls_mode = settings.tls_mode.as_str(), local_domain = %log_domain(&local), remote_domain = %log_domain(&remote), "s2s certificate rejected");
            return Err(reject(StreamErrorCondition::NotAuthorized, outcome));
        }
        if let RevocationStatus::Unknown(reason) = verdict.status {
            tracing::debug!(reason = reason.as_str(), direction = "inbound", tls_mode = settings.tls_mode.as_str(), local_domain = %log_domain(&local), remote_domain = %log_domain(&remote), "s2s revocation status unknown");
        }
    }
    tls.send_header(&stream::response_header_xml(&local, Some(&remote))?)
        .await?;
    *header_sent = true;
    stream::limits::write_features_xml(
        &mut features_xml,
        stream::limits::FeaturePhase::Sasl { bidi: offer_bidi },
        local_limits,
    )?;
    tls.send(&features_xml).await?;
    let mut requested = false;
    for attempt in 0..2 {
        let mut auth = expected(tls, peer_footer).await?;
        if let StreamEvent::Element(element) = &auth
            && {
                let view = element
                    .value()
                    .resolve(element.arena())
                    .map_err(S2sError::from)?;
                view.name() == "bidi" && view.namespace() == stream::BIDI_NAMESPACE
            }
        {
            if !offer_bidi || requested {
                return Err(reject(
                    StreamErrorCondition::NotAuthorized,
                    AuthOutcome::Protocol,
                ));
            }
            tls.update_peer_limits(stream::limits::parse_bidi(element)?);
            requested = true;
            auth = expected(tls, peer_footer).await?;
        }
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
    if final_header.to != local {
        return Err(reject(
            StreamErrorCondition::HostUnknown,
            AuthOutcome::InvalidFrom,
        ));
    }
    tls.send_header(&stream::response_header_xml(&local, Some(&remote))?)
        .await?;
    *header_sent = true;
    stream::limits::write_features_xml(
        &mut features_xml,
        stream::limits::FeaturePhase::Authenticated,
        local_limits,
    )?;
    tls.send(&features_xml).await?;
    Ok(VerifiedPeer {
        bidi_offered: offer_bidi,
        bidi: requested,
        local,
        remote,
        valid_until,
        chain,
        revocation,
    })
}

pub(super) fn select_sni<A: ChunkAllocator + Clone>(
    sni: Option<&str>,
    settings: &Settings<A>,
) -> Option<Box<str>> {
    let sni = sni?;
    let domain = stream::domain(sni, StreamErrorCondition::HostUnknown).ok()?;
    (crate::hosts::sni_matches_domain(sni, &domain)
        && settings.services.router.federates_domain(&domain))
    .then_some(domain)
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
        tracing::warn!(outcome = "certificate_rejected", remote_domain = %log_domain(remote), "s2s certificate rejected");
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
        assert_eq!(log_domain(&domain).len(), 253);
        assert_eq!(log_domain("bad\nname"), "bad?name");
    }
}
