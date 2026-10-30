// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime};

use compio::io::compat::{AsyncReadStream, AsyncStream};
use compio::net::TcpStream;
use futures_rustls::TlsConnector;
use futures_util::io::AsyncReadExt as _;
use lonewolf_util::arena::{ChunkAllocator, HandleError};
use lonewolf_xmpp::parser::{Parsed, StreamEvent};
use lonewolf_xmpp::stanza::{Element, NodeRef, StanzaErrorCondition};
use lonewolf_xmpp::stream::StreamErrorCondition;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig};
use tokio::io::BufReader;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _};

use super::{ClientTlsInput, ClientTlsOutput, OutboundStream};
use crate::config::limits::S2sLimits;
use crate::hosts::{Hosts, peer_identity::PeerTrust, tls_identity};
use crate::s2s::dns::{ResolveError, Resolved, ResolvedVia, Resolver};
use crate::s2s::metrics::{AuthOutcome, Direction, DnsOutcome, S2sMetrics};
use crate::s2s::stream::traffic::CountingIo;
use crate::s2s::stream::{self, Features, S2sError, S2sReader, S2sReaderLimits, S2sWriter};
use crate::s2s::{ConnectionSocket, NEXT_S2S_CONNECTION_ID};

const TLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const STREAM_NAMESPACE: &str = "http://etherx.jabber.org/streams";
const EMPTY_RESPONSE: &str = "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>=</response>";
const CLOSE_BUDGET: Duration = Duration::from_secs(6);
const FOOTER_GRACE: Duration = Duration::from_secs(5);

type PlainInput = Compat<Pin<Box<AsyncReadStream<TcpStream>>>>;
type PlainOutput = Pin<Box<AsyncStream<TcpStream>>>;

pub(crate) struct ConnectContext<'a> {
    pub(crate) hosts: &'a Hosts,
    pub(crate) trust: &'a Arc<PeerTrust>,
    pub(crate) resolver: &'a Resolver,
    pub(crate) limits: &'a S2sLimits,
    pub(crate) metrics: Arc<S2sMetrics>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NegotiationFailure {
    NoTls,
    TlsRefused,
    ExternalNotOffered,
    SaslFailure(&'static str),
    Protocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EstablishError {
    NoService,
    NotFound,
    DnsUnavailable,
    Unreachable,
    Tls(&'static str),
    Negotiation(NegotiationFailure),
    Timeout,
}

impl EstablishError {
    pub(crate) fn condition(self) -> StanzaErrorCondition {
        match self {
            Self::NoService | Self::NotFound | Self::DnsUnavailable => {
                StanzaErrorCondition::RemoteServerNotFound
            }
            _ => StanzaErrorCondition::RemoteServerTimeout,
        }
    }

    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::NoService => "no_service",
            Self::NotFound => "not_found",
            Self::DnsUnavailable => "dns_unavailable",
            Self::Unreachable => "unreachable",
            Self::Tls(reason) => reason,
            Self::Negotiation(NegotiationFailure::NoTls) => "no_tls",
            Self::Negotiation(NegotiationFailure::TlsRefused) => "tls_refused",
            Self::Negotiation(NegotiationFailure::ExternalNotOffered) => "external_not_offered",
            Self::Negotiation(NegotiationFailure::SaslFailure(_)) => "sasl_failure",
            Self::Negotiation(NegotiationFailure::Protocol) => "protocol",
            Self::Timeout => "timeout",
        }
    }

    fn authentication(self) -> Option<AuthOutcome> {
        Some(match self {
            Self::NoService | Self::NotFound | Self::DnsUnavailable => return None,
            Self::Unreachable => AuthOutcome::Unreachable,
            Self::Tls("certificate_untrusted") => AuthOutcome::CertificateUntrusted,
            Self::Tls("certificate_name") => AuthOutcome::CertificateName,
            Self::Tls("certificate_purpose") => AuthOutcome::CertificatePurpose,
            Self::Tls("certificate_expired") => AuthOutcome::CertificateExpired,
            Self::Tls(_) => AuthOutcome::TlsFailure,
            Self::Negotiation(NegotiationFailure::NoTls) => AuthOutcome::NoTls,
            Self::Negotiation(NegotiationFailure::TlsRefused) => AuthOutcome::TlsRefused,
            Self::Negotiation(NegotiationFailure::ExternalNotOffered) => {
                AuthOutcome::ExternalNotOffered
            }
            Self::Negotiation(NegotiationFailure::SaslFailure(_)) => AuthOutcome::SaslFailure,
            Self::Negotiation(NegotiationFailure::Protocol) => AuthOutcome::Protocol,
            Self::Timeout => AuthOutcome::Timeout,
        })
    }

    fn stage(self) -> &'static str {
        match self {
            Self::NoService | Self::NotFound | Self::DnsUnavailable => "dns",
            Self::Unreachable => "connect",
            Self::Tls(_) => "tls",
            _ => "negotiation",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Failure {
    error: EstablishError,
    condition: Option<StreamErrorCondition>,
}

impl From<EstablishError> for Failure {
    fn from(error: EstablishError) -> Self {
        Self {
            error,
            condition: None,
        }
    }
}

impl From<S2sError> for Failure {
    fn from(error: S2sError) -> Self {
        match error {
            S2sError::Timeout => Self {
                error: EstablishError::Timeout,
                condition: Some(StreamErrorCondition::ConnectionTimeout),
            },
            S2sError::Stream(condition) => Self {
                condition: Some(condition),
                ..protocol()
            },
            _ => protocol(),
        }
    }
}

impl From<HandleError> for Failure {
    fn from(_: HandleError) -> Self {
        protocol()
    }
}

fn protocol() -> Failure {
    EstablishError::Negotiation(NegotiationFailure::Protocol).into()
}

fn dns_result(
    result: Result<Resolved, ResolveError>,
) -> (DnsOutcome, Result<Resolved, EstablishError>) {
    match result {
        Ok(resolved) => {
            let outcome = match resolved.via {
                ResolvedVia::Srv => DnsOutcome::Srv,
                ResolvedVia::Fallback => DnsOutcome::Fallback,
                ResolvedVia::Static => DnsOutcome::Static,
                ResolvedVia::Literal => DnsOutcome::Literal,
            };
            (outcome, Ok(resolved))
        }
        Err(error) => {
            let (outcome, error) = match error {
                ResolveError::NoService => (DnsOutcome::NoService, EstablishError::NoService),
                ResolveError::NotFound => (DnsOutcome::NotFound, EstablishError::NotFound),
                ResolveError::Unavailable => {
                    (DnsOutcome::Unavailable, EstablishError::DnsUnavailable)
                }
                ResolveError::InvalidDomain => {
                    (DnsOutcome::InvalidDomain, EstablishError::NotFound)
                }
            };
            (outcome, Err(error))
        }
    }
}

fn tls_reason(error: &rustls::Error) -> &'static str {
    match error {
        rustls::Error::InvalidCertificate(error) => {
            match error {
                CertificateError::UnknownIssuer | CertificateError::BadSignature => {
                    "certificate_untrusted"
                }
                CertificateError::NotValidForName
                | CertificateError::NotValidForNameContext { .. } => "certificate_name",
                CertificateError::InvalidPurpose
                | CertificateError::InvalidPurposeContext { .. } => "certificate_purpose",
                CertificateError::Expired
                | CertificateError::ExpiredContext { .. }
                | CertificateError::NotValidYet
                | CertificateError::NotValidYetContext { .. } => "certificate_expired",
                _ => "certificate_untrusted",
            }
        }
        _ => "handshake",
    }
}

fn tls_failure(error: io::Error) -> Failure {
    let reason = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<rustls::Error>())
        .map_or("handshake", tls_reason);
    EstablishError::Tls(reason).into()
}

fn unexpired_validity(
    valid_until: SystemTime,
    completed_at: SystemTime,
) -> Result<SystemTime, Failure> {
    if valid_until <= completed_at {
        Err(EstablishError::Tls("certificate_expired").into())
    } else {
        Ok(valid_until)
    }
}

fn sasl_condition(name: &str) -> &'static str {
    if name.len() > 32 || !name.is_ascii() {
        return "other";
    }
    match name {
        "aborted" => "aborted",
        "account-disabled" => "account-disabled",
        "credentials-expired" => "credentials-expired",
        "encryption-required" => "encryption-required",
        "incorrect-encoding" => "incorrect-encoding",
        "invalid-authzid" => "invalid-authzid",
        "invalid-mechanism" => "invalid-mechanism",
        "malformed-request" => "malformed-request",
        "mechanism-too-weak" => "mechanism-too-weak",
        "not-authorized" => "not-authorized",
        "temporary-auth-failure" => "temporary-auth-failure",
        _ => "other",
    }
}

fn empty<A: ChunkAllocator>(parsed: &Parsed<Element, A>) -> Result<bool, Failure> {
    let element = parsed.value().resolve(parsed.arena())?;
    Ok(!parsed.has_explicit_attributes()
        && element.children()?.next().is_none()
        && element.text()?.is_none())
}

fn features<A: ChunkAllocator>(event: StreamEvent<A>) -> Result<Features, Failure> {
    let StreamEvent::Element(parsed) = event else {
        return Err(protocol());
    };
    let element = parsed.value().resolve(parsed.arena())?;
    if element.name() != "features" || element.namespace() != STREAM_NAMESPACE {
        return Err(protocol());
    }
    Ok(stream::parse_features(&parsed))
}

fn require_starttls(features: &Features) -> Result<(), Failure> {
    if features.starttls {
        Ok(())
    } else {
        Err(Failure {
            error: EstablishError::Negotiation(NegotiationFailure::NoTls),
            condition: Some(StreamErrorCondition::PolicyViolation),
        })
    }
}

fn require_external(features: &Features) -> Result<(), Failure> {
    if features.external {
        Ok(())
    } else {
        Err(EstablishError::Negotiation(NegotiationFailure::ExternalNotOffered).into())
    }
}

fn proceed<A: ChunkAllocator>(event: StreamEvent<A>) -> Result<(), Failure> {
    let StreamEvent::Element(parsed) = event else {
        return Err(protocol());
    };
    let element = parsed.value().resolve(parsed.arena())?;
    if element.namespace() != TLS_NAMESPACE || !empty(&parsed)? {
        return Err(protocol());
    }
    match element.name() {
        "proceed" => Ok(()),
        "failure" => Err(EstablishError::Negotiation(NegotiationFailure::TlsRefused).into()),
        _ => Err(protocol()),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum SaslReply {
    Success,
    Challenge,
}

fn sasl_reply<A: ChunkAllocator>(
    event: StreamEvent<A>,
    challenged: bool,
) -> Result<SaslReply, Failure> {
    let StreamEvent::Element(parsed) = event else {
        return Err(protocol());
    };
    let element = parsed.value().resolve(parsed.arena())?;
    if element.namespace() != SASL_NAMESPACE {
        return Err(protocol());
    }
    match element.name() {
        "success" if empty(&parsed)? => Ok(SaslReply::Success),
        "challenge" if !challenged && empty(&parsed)? => Ok(SaslReply::Challenge),
        "failure" if !parsed.has_explicit_attributes() => {
            let name = match element.children()?.next() {
                Some(Ok(NodeRef::Element(child))) if child.namespace() == SASL_NAMESPACE => {
                    sasl_condition(child.name())
                }
                _ => "other",
            };
            Err(EstablishError::Negotiation(NegotiationFailure::SaslFailure(name)).into())
        }
        _ => Err(protocol()),
    }
}

#[derive(Default)]
struct Attempts {
    last_connected: Option<Failure>,
}

impl Attempts {
    fn failed(&mut self, connected: Option<Failure>) {
        if connected.is_some() {
            self.last_connected = connected;
        }
    }
    fn failure(&self) -> Failure {
        self.last_connected
            .unwrap_or_else(|| EstablishError::Unreachable.into())
    }
}

struct Accounting {
    metrics: Arc<S2sMetrics>,
    active_since: Option<Instant>,
    elapsed: Duration,
    outcome: Option<AuthOutcome>,
    recorded: bool,
}

impl Accounting {
    fn new(metrics: Arc<S2sMetrics>, now: Instant) -> Self {
        Self {
            metrics,
            active_since: Some(now),
            elapsed: Duration::ZERO,
            outcome: None,
            recorded: false,
        }
    }
    fn pause(&mut self, now: Instant) {
        if let Some(started) = self.active_since.take() {
            self.elapsed += now.saturating_duration_since(started);
        }
    }
    fn resume(&mut self, now: Instant) {
        self.active_since = Some(now);
    }
    fn select(&mut self, outcome: AuthOutcome, now: Instant) {
        if self.outcome.is_none() {
            self.pause(now);
            self.outcome = Some(outcome);
        }
    }
    fn sample(&self, now: Instant) -> (AuthOutcome, Duration) {
        (
            self.outcome.unwrap_or(AuthOutcome::Protocol),
            self.elapsed
                + self.active_since.map_or(Duration::ZERO, |started| {
                    now.saturating_duration_since(started)
                }),
        )
    }
    fn record(&mut self, now: Instant) {
        if !self.recorded {
            let (outcome, elapsed) = self.sample(now);
            self.metrics
                .authentication(Direction::Outbound, outcome, elapsed);
            self.recorded = true;
        }
    }
}

impl Drop for Accounting {
    fn drop(&mut self) {
        self.record(Instant::now());
    }
}

fn require_setup<T>(value: Option<T>) -> Result<T, EstablishError> {
    value.ok_or(EstablishError::Negotiation(NegotiationFailure::Protocol))
}

fn deadline(now: Instant, seconds: NonZeroU64) -> Instant {
    now + Duration::from_secs(seconds.get())
}

fn footer_deadline(cleanup_deadline: Instant, now: Instant) -> Instant {
    cleanup_deadline.min(now + FOOTER_GRACE)
}

enum Connection<A: ChunkAllocator> {
    Plain(S2sReader<A, PlainInput>, S2sWriter<PlainOutput>),
    Tls(S2sReader<A, ClientTlsInput>, S2sWriter<ClientTlsOutput>),
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

struct Negotiation<A: ChunkAllocator> {
    connection: Option<Connection<A>>,
    peer_footer: bool,
}

struct TlsSetup {
    config: Arc<ClientConfig>,
    identity: ServerName<'static>,
}

impl<A: ChunkAllocator + Clone> Negotiation<A> {
    async fn expected(&mut self) -> Result<StreamEvent<A>, Failure> {
        match self
            .connection
            .as_mut()
            .ok_or_else(protocol)?
            .next()
            .await?
        {
            Some(StreamEvent::StreamEnd) => {
                self.peer_footer = true;
                Err(protocol())
            }
            Some(event) => Ok(event),
            None => Err(protocol()),
        }
    }
    async fn send(&mut self, xml: &str) -> Result<(), Failure> {
        self.connection
            .as_mut()
            .ok_or_else(protocol)?
            .send(xml)
            .await
            .map_err(Into::into)
    }
    async fn header(&mut self, remote: &str) -> Result<(), Failure> {
        let StreamEvent::StreamStart {
            header,
            content_namespace,
            ..
        } = self.expected().await?
        else {
            return Err(protocol());
        };
        stream::validate_response_header(&header, &content_namespace, remote).map_err(|condition| {
            Failure {
                condition: Some(condition),
                ..protocol()
            }
        })
    }
    async fn cleanup(&mut self, failure: Failure, selected_at: Instant) {
        let Some(connection) = &mut self.connection else {
            return;
        };
        let deadline = selected_at + CLOSE_BUDGET;
        let _ = compio::time::timeout_at(deadline, async {
            connection.close(failure.condition).await?;
            if !self.peer_footer {
                let _ =
                    compio::time::timeout_at(footer_deadline(deadline, Instant::now()), async {
                        while let Ok(Some(event)) = connection.next().await {
                            if matches!(event, StreamEvent::StreamEnd) {
                                self.peer_footer = true;
                                break;
                            }
                        }
                    })
                    .await;
            }
            connection.shutdown(self.peer_footer).await
        })
        .await;
    }
}

async fn negotiate<A: ChunkAllocator + Clone>(
    flow: &mut Negotiation<A>,
    socket: &ConnectionSocket,
    local: &str,
    remote: &str,
    context: &ConnectContext<'_>,
    setup: &TlsSetup,
    allocator: A,
) -> Result<SystemTime, Failure> {
    let header = stream::initial_header_xml(local, remote);
    flow.send(&header).await?;
    flow.header(remote).await?;
    require_starttls(&features(flow.expected().await?)?)?;
    flow.send(stream::STARTTLS).await?;
    proceed(flow.expected().await?)?;
    let Some(Connection::Plain(mut reader, writer)) = flow.connection.take() else {
        return Err(protocol());
    };
    let (input, state) = reader.take_input().await?;
    drop(input);
    drop(reader);
    drop(writer);
    let tls = TlsConnector::from(Arc::clone(&setup.config))
        .connect(
            setup.identity.clone(),
            Box::pin(AsyncStream::new(socket.0.clone())),
        )
        .await
        .map_err(tls_failure)?;
    let certificates = tls.get_ref().1.peer_certificates().map(<[_]>::to_vec);
    let (input, output) =
        CountingIo::new(tls, Arc::clone(&context.metrics), Direction::Outbound).split();
    flow.connection = Some(Connection::Tls(
        S2sReader::from_state(BufReader::new(input.compat()), state, allocator),
        S2sWriter::new(output),
    ));
    flow.send(&header).await?;
    flow.header(remote).await?;
    require_external(&features(flow.expected().await?)?)?;
    flow.send(&stream::auth_external_xml(local)).await?;
    if sasl_reply(flow.expected().await?, false)? == SaslReply::Challenge {
        flow.send(EMPTY_RESPONSE).await?;
        sasl_reply(flow.expected().await?, true)?;
    }
    let Some(Connection::Tls(reader, _)) = &mut flow.connection else {
        return Err(protocol());
    };
    reader.restart()?;
    flow.send(&header).await?;
    flow.header(remote).await?;
    features(flow.expected().await?)?;
    let validity = context
        .trust
        .verify_chain(certificates.as_deref().unwrap_or(&[]), UnixTime::now())
        .map_err(|error| Failure::from(EstablishError::Tls(tls_reason(&error))))?;
    unexpired_validity(validity.valid_until, SystemTime::now())
}

pub(crate) async fn establish<A: ChunkAllocator + Clone>(
    local: &str,
    remote: &str,
    context: &ConnectContext<'_>,
    allocator: A,
) -> Result<OutboundStream<A>, EstablishError> {
    let result = establish_inner(local, remote, context, allocator, |endpoint| {
        TcpStream::connect(endpoint)
    })
    .await;
    match &result {
        Ok(stream) => {
            tracing::info!(connection_id = stream.connection_id, local_domain = %safe_domain(local), remote_domain = %safe_domain(remote), direction = "outbound", "s2s connection authenticated")
        }
        Err(error) => {
            tracing::warn!(local_domain = %safe_domain(local), remote_domain = %safe_domain(remote), stage = error.stage(), reason = error.reason(), "s2s connection failed")
        }
    }
    result
}

async fn establish_inner<A, C, F>(
    local: &str,
    remote: &str,
    context: &ConnectContext<'_>,
    allocator: A,
    mut connect: C,
) -> Result<OutboundStream<A>, EstablishError>
where
    A: ChunkAllocator + Clone,
    C: FnMut(std::net::SocketAddr) -> F,
    F: std::future::Future<Output = io::Result<TcpStream>>,
{
    let (outcome, resolved) = dns_result(context.resolver.resolve(remote).await);
    context.metrics.dns(outcome);
    let resolved = resolved?;
    let mut accounting = Accounting::new(Arc::clone(&context.metrics), Instant::now());
    let setup = TlsSetup {
        config: require_setup(context.hosts.s2s_client_config(local, context.trust))?,
        identity: require_setup(tls_identity(remote).ok())?,
    };
    let limits = S2sReaderLimits {
        max_stanza_bytes: context.limits.max_stanza_bytes,
        stanzas: context.limits.incoming_stanzas_per_connection.clone(),
        xml: context.limits.incoming_xml_per_connection.clone(),
    };
    let mut attempts = Attempts::default();
    for (index, endpoint) in resolved.endpoints.iter().enumerate() {
        let Ok(Ok(tcp)) = compio::time::timeout_at(
            deadline(Instant::now(), context.limits.connect_timeout_secs),
            connect(*endpoint),
        )
        .await
        else {
            attempts.failed(None);
            continue;
        };
        let socket = ConnectionSocket(tcp);
        let gauge = context.metrics.connection_opened(Direction::Outbound);
        let connection_id = NEXT_S2S_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let mut flow = Negotiation {
            connection: None,
            peer_footer: false,
        };
        let negotiated = if socket.0.set_nodelay(true).is_err() {
            (Err(protocol()), Instant::now())
        } else {
            flow.connection = Some(Connection::Plain(
                S2sReader::plain(
                    socket.0.clone(),
                    &limits,
                    allocator.clone(),
                    Some(Arc::clone(&context.metrics)),
                ),
                S2sWriter::new(Box::pin(AsyncStream::new(socket.0.clone()))),
            ));
            let deadline = deadline(Instant::now(), context.limits.negotiation_timeout_secs);
            match compio::time::timeout_at(
                deadline,
                negotiate(
                    &mut flow,
                    &socket,
                    local,
                    remote,
                    context,
                    &setup,
                    allocator.clone(),
                ),
            )
            .await
            {
                Ok(result) => (result, Instant::now()),
                Err(_) => (
                    Err(Failure {
                        error: EstablishError::Timeout,
                        condition: Some(StreamErrorCondition::ConnectionTimeout),
                    }),
                    deadline,
                ),
            }
        };
        let (result, selected_at) = negotiated;
        match result {
            Ok(valid_until) => {
                let Some(Connection::Tls(reader, writer)) = flow.connection.take() else {
                    return Err(protocol().error);
                };
                accounting.select(AuthOutcome::Success, selected_at);
                accounting.record(selected_at);
                return Ok(OutboundStream {
                    _socket: socket,
                    reader,
                    writer,
                    valid_until,
                    connection_id,
                    _connection_gauge: gauge,
                });
            }
            Err(failure) => {
                attempts.failed(Some(failure));
                if index + 1 == resolved.endpoints.len() {
                    accounting.select(
                        failure
                            .error
                            .authentication()
                            .unwrap_or(AuthOutcome::Protocol),
                        selected_at,
                    );
                } else {
                    accounting.pause(selected_at);
                }
                flow.cleanup(failure, selected_at).await;
                drop(socket);
                drop(flow);
                drop(gauge);
                if index + 1 < resolved.endpoints.len() {
                    accounting.resume(Instant::now());
                }
            }
        }
    }
    let failure = attempts.failure();
    accounting.select(
        failure
            .error
            .authentication()
            .unwrap_or(AuthOutcome::Protocol),
        Instant::now(),
    );
    Err(failure.error)
}

fn safe_domain(domain: &str) -> String {
    if domain
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok()
    {
        return "<literal>".into();
    }
    domain
        .chars()
        .take(253)
        .map(|ch| if ch.is_control() { '\u{fffd}' } else { ch })
        .collect()
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
