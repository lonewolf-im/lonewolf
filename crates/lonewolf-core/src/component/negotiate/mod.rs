// SPDX-License-Identifier: Apache-2.0

use std::pin::{Pin, pin};
use std::sync::Arc;
use std::time::{Duration, Instant};

use compio::io::compat::{AsyncReadStream, AsyncStream};
use compio::net::TcpStream;
use futures_rustls::LazyConfigAcceptor;
use futures_util::FutureExt as _;
use futures_util::future::{Either, select};
use futures_util::io::{AsyncReadExt as _, ReadHalf, WriteHalf};
use lonewolf_auth::component::handshake_matches;
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stanza::NodeRef;
use lonewolf_xmpp::stream::StreamErrorCondition;
use tokio::io::BufReader;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _};

use super::metrics::{AuthOutcome, ComponentMetrics, GaugeGuard};
use super::registry::{AttachError, ComponentLink};
use super::stream::{self, ComponentError, ComponentReader, ComponentWriter, WriteProgress};
use super::{Settings, StreamAccounting};
use crate::config::ComponentTlsMode;
use crate::connection::ShutdownSignal;
use crate::xml_stream::traffic::{ObservedIo, TrafficObserver};

const NAMESPACE: &str = "jabber:component:accept";
type PlainInput = Pin<Box<AsyncReadStream<ObservedIo<TcpStream, ComponentByteObserver>>>>;
type PlainOutput = Pin<Box<AsyncStream<ObservedIo<TcpStream, ComponentByteObserver>>>>;
type TlsTransport = futures_rustls::server::TlsStream<PlainOutput>;
type Input = BufReader<Compat<Either<PlainInput, ReadHalf<TlsTransport>>>>;
type Output = Either<PlainOutput, WriteHalf<TlsTransport>>;
type Connection<A> = (ComponentReader<A, Input>, ComponentWriter<Output>);

pub(crate) struct Authenticated<A: ChunkAllocator, R, W> {
    pub(crate) domain: Arc<str>,
    pub(crate) connection_id: u64,
    pub(crate) reader: ComponentReader<A, R>,
    pub(crate) writer: ComponentWriter<W>,
    pub(crate) link: ComponentLink<A>,
    pub(crate) stream_accounting: StreamAccounting,
    pub(crate) stream_gauge: GaugeGuard,
}

#[derive(Clone)]
pub(super) struct ComponentByteObserver(Arc<ComponentMetrics>, WriteProgress);
impl ComponentByteObserver {
    pub(super) fn new(metrics: Arc<ComponentMetrics>, progress: WriteProgress) -> Self {
        Self(metrics, progress)
    }
}
impl TrafficObserver for ComponentByteObserver {
    fn received(&self, bytes: usize) {
        self.0.bytes(bytes as u64, 0);
    }
    fn sent(&self, bytes: usize) {
        self.0.bytes(0, bytes as u64);
        if bytes > 0 {
            self.1.record(Instant::now());
        }
    }
}

pub(super) struct Accounting {
    metrics: Arc<ComponentMetrics>,
    started: Instant,
    outcome: AuthOutcome,
    elapsed: Option<Duration>,
}
impl Accounting {
    pub(super) fn new(metrics: Arc<ComponentMetrics>) -> Self {
        Self {
            metrics,
            started: Instant::now(),
            outcome: AuthOutcome::Shutdown,
            elapsed: None,
        }
    }
}

impl Drop for Accounting {
    fn drop(&mut self) {
        self.metrics.authentication(
            self.outcome,
            self.elapsed.unwrap_or_else(|| self.started.elapsed()),
        );
    }
}

struct Progress {
    domain: Option<Arc<str>>,
    header_sent: bool,
    peer_footer: bool,
}

struct Negotiation<A: ChunkAllocator> {
    connection: Option<Connection<A>>,
    progress: Progress,
    shutdown_deadline: Option<Instant>,
}

struct Failure {
    error: ComponentError,
    outcome: AuthOutcome,
}
impl From<ComponentError> for Failure {
    fn from(error: ComponentError) -> Self {
        Self {
            error,
            outcome: match error {
                ComponentError::Eof
                | ComponentError::Io
                | ComponentError::Timeout
                | ComponentError::PeerError(_) => AuthOutcome::TransportError,
                ComponentError::Stream(_) | ComponentError::Internal => AuthOutcome::ProtocolError,
            },
        }
    }
}
fn reject(condition: StreamErrorCondition, outcome: AuthOutcome) -> Failure {
    Failure {
        error: ComponentError::Stream(condition),
        outcome,
    }
}

pub(super) async fn negotiate<A: ChunkAllocator + Clone>(
    tcp: &TcpStream,
    settings: &Settings<A>,
    shutdown: ShutdownSignal,
    connection_id: u64,
    accounting: Accounting,
) -> Result<Authenticated<A, Input, Output>, ComponentError> {
    let mut state = Negotiation {
        connection: match settings.tls_mode {
            ComponentTlsMode::None => Some(
                transport(tcp, settings)
                    .await
                    .map_err(|failure| failure.error)?,
            ),
            ComponentTlsMode::Direct => None,
        },
        progress: Progress {
            domain: None,
            header_sent: false,
            peer_footer: false,
        },
        shutdown_deadline: None,
    };
    let result = {
        let flow = pin!(async {
            if state.connection.is_none() {
                state.connection = Some(transport(tcp, settings).await?);
            }
            let (reader, writer) = state.connection.as_mut().ok_or(ComponentError::Internal)?;
            run(reader, writer, settings, &mut state.progress).await
        });
        let (result, deadline) = select_terminal(
            flow,
            shutdown.clone(),
            accounting.started + settings.timeout,
        )
        .await;
        state.shutdown_deadline = deadline;
        result
    };
    finish(
        tcp,
        settings,
        shutdown,
        connection_id,
        accounting,
        state,
        result,
    )
    .await
}

async fn select_terminal<A: ChunkAllocator>(
    flow: impl std::future::Future<Output = Result<ComponentLink<A>, Failure>>,
    shutdown: ShutdownSignal,
    deadline: Instant,
) -> (Result<ComponentLink<A>, Failure>, Option<Instant>) {
    match select(
        pin!(shutdown),
        pin!(compio::time::timeout_at(deadline, flow)),
    )
    .await
    {
        Either::Left((deadline, _)) => (
            Err(reject(
                StreamErrorCondition::SystemShutdown,
                AuthOutcome::Shutdown,
            )),
            Some(deadline),
        ),
        Either::Right((Err(_), _)) => (
            Err(reject(
                StreamErrorCondition::ConnectionTimeout,
                AuthOutcome::Timeout,
            )),
            None,
        ),
        Either::Right((Ok(result), _)) => (result, None),
    }
}

async fn transport<A: ChunkAllocator + Clone>(
    tcp: &TcpStream,
    settings: &Settings<A>,
) -> Result<Connection<A>, Failure> {
    let progress = WriteProgress::new(Instant::now());
    let observer = ComponentByteObserver::new(Arc::clone(&settings.metrics), progress.clone());
    let (input, output) = match settings.tls_mode {
        ComponentTlsMode::None => (
            Either::Left(Box::pin(AsyncReadStream::new(ObservedIo::new(
                tcp.clone(),
                observer.clone(),
            )))),
            Either::Left(Box::pin(AsyncStream::new(ObservedIo::new(
                tcp.clone(),
                observer,
            )))),
        ),
        ComponentTlsMode::Direct => {
            let tls = accept_direct(tcp, settings, observer).await?;
            let (input, output) = tls.split();
            (Either::Right(input), Either::Right(output))
        }
    };
    Ok((
        ComponentReader::new(
            BufReader::new(input.compat()),
            &settings.limits,
            settings.services.allocator.clone(),
            Arc::clone(&settings.metrics),
        ),
        ComponentWriter::new(output, progress),
    ))
}

async fn accept_direct<A: ChunkAllocator>(
    tcp: &TcpStream,
    settings: &Settings<A>,
    observer: ComponentByteObserver,
) -> Result<TlsTransport, Failure> {
    let failure = || Failure {
        error: ComponentError::Io,
        outcome: AuthOutcome::TlsFailure,
    };
    let accepted = LazyConfigAcceptor::new(
        rustls::server::Acceptor::default(),
        Box::pin(AsyncStream::new(ObservedIo::new(tcp.clone(), observer))),
    )
    .await
    .map_err(|_| failure())?;
    let domain = match accepted.client_hello().server_name() {
        Some(sni) => settings.hosts.host_for_sni(Some(sni)).ok_or_else(failure)?,
        None => settings.hosts.default_host_name(),
    };
    let config = settings
        .hosts
        .component_tls_config(domain)
        .ok_or_else(failure)?;
    accepted.into_stream(config).await.map_err(|_| failure())
}

async fn finish<A: ChunkAllocator + Clone>(
    tcp: &TcpStream,
    settings: &Settings<A>,
    shutdown: ShutdownSignal,
    connection_id: u64,
    mut accounting: Accounting,
    state: Negotiation<A>,
    result: Result<ComponentLink<A>, Failure>,
) -> Result<Authenticated<A, Input, Output>, ComponentError> {
    let Negotiation {
        mut connection,
        mut progress,
        shutdown_deadline,
    } = state;
    accounting.elapsed = Some(accounting.started.elapsed());
    match result {
        Ok(link) => {
            accounting.outcome = AuthOutcome::Success;
            let domain = progress.domain.take().ok_or(ComponentError::Internal)?;
            let (reader, writer) = connection.take().ok_or(ComponentError::Internal)?;
            Ok(Authenticated {
                domain,
                connection_id,
                reader,
                writer,
                link,
                stream_accounting: StreamAccounting::new(Arc::clone(&settings.metrics)),
                stream_gauge: settings.metrics.stream_opened(),
            })
        }
        Err(failure) => {
            accounting.outcome = failure.outcome;
            if let Some(domain) = &progress.domain {
                tracing::warn!(connection_id, component_domain = %domain, outcome = failure.outcome.as_str(), "component authentication failed");
            } else {
                tracing::warn!(
                    connection_id,
                    outcome = failure.outcome.as_str(),
                    "component authentication failed"
                );
            }
            if let Some((reader, writer)) = connection.as_mut()
                && !matches!(
                    failure.error,
                    ComponentError::Io | ComponentError::Timeout | ComponentError::PeerError(_)
                )
                && (!matches!(failure.error, ComponentError::Eof) || progress.peer_footer)
            {
                let started_closing = Instant::now();
                let deadline = shutdown_deadline
                    .or_else(|| shutdown.now_or_never())
                    .map_or(started_closing + Duration::from_secs(6), |d| {
                        d.min(started_closing + Duration::from_secs(6))
                    });
                let _ = compio::time::timeout_at(deadline, async {
                    if !progress.header_sent {
                        let (header, _) = stream::response_header_xml(progress.domain.as_deref())?;
                        writer.send(&header).await?;
                    }
                    let condition = match failure.error {
                        ComponentError::Stream(c) => Some(c),
                        ComponentError::Internal => Some(StreamErrorCondition::InternalServerError),
                        _ => None,
                    };
                    stream::close(
                        reader,
                        writer,
                        condition,
                        progress.peer_footer,
                        Some(deadline),
                    )
                    .await;
                    Ok::<(), ComponentError>(())
                })
                .await;
            }
            let _ = socket2::SockRef::from(tcp).shutdown(std::net::Shutdown::Both);
            let duration_ms = accounting.started.elapsed().as_millis() as u64;
            if let Some(domain) = &progress.domain {
                tracing::info!(component_domain = %domain, connection_id, outcome = failure.outcome.as_str(), duration_ms, "component disconnected");
            } else {
                tracing::info!(
                    connection_id,
                    outcome = failure.outcome.as_str(),
                    duration_ms,
                    "component disconnected"
                );
            }
            Err(failure.error)
        }
    }
}

async fn next<A: ChunkAllocator + Clone>(
    reader: &mut ComponentReader<A, Input>,
    progress: &mut Progress,
) -> Result<StreamEvent<A>, Failure> {
    match reader.next_event().await? {
        Some(StreamEvent::StreamEnd) => {
            progress.peer_footer = true;
            Err(Failure {
                error: ComponentError::Eof,
                outcome: AuthOutcome::PeerClosed,
            })
        }
        Some(event) => Ok(event),
        None => Err(ComponentError::Eof.into()),
    }
}

async fn run<A: ChunkAllocator + Clone>(
    reader: &mut ComponentReader<A, Input>,
    writer: &mut ComponentWriter<Output>,
    settings: &Settings<A>,
    progress: &mut Progress,
) -> Result<ComponentLink<A>, Failure> {
    let StreamEvent::StreamStart {
        header,
        content_namespace,
        ..
    } = next(reader, progress).await?
    else {
        return Err(reject(
            StreamErrorCondition::NotAuthorized,
            AuthOutcome::NotAuthorized,
        ));
    };
    let header = header
        .value()
        .resolve(header.arena())
        .map_err(ComponentError::from)?;
    if let Some(to) = header.attribute("to", "").map_err(ComponentError::from)? {
        let mut arena =
            Arena::try_new(ArenaConfig::default()).map_err(|_| ComponentError::Internal)?;
        if let Ok(jid) = Jid::parse_in(to, &mut arena) {
            let jid = jid.resolve(&arena).map_err(ComponentError::from)?;
            if jid.localpart().is_none()
                && jid.resourcepart().is_none()
                && settings.registry.secret(jid.domainpart()).is_some()
            {
                progress.domain = Some(Arc::from(jid.domainpart()));
            }
        }
    }
    let (response, id) = stream::response_header_xml(progress.domain.as_deref())?;
    // A buffered header still reaches the peer after a cancelled send, so never write a second one.
    progress.header_sent = true;
    writer.send(&response).await?;
    if content_namespace != NAMESPACE {
        return Err(reject(
            StreamErrorCondition::InvalidNamespace,
            AuthOutcome::InvalidNamespace,
        ));
    }
    if progress.domain.is_none() {
        return Err(reject(
            StreamErrorCondition::HostUnknown,
            AuthOutcome::HostUnknown,
        ));
    }
    let StreamEvent::Element(handshake) = next(reader, progress).await? else {
        return Err(reject(
            StreamErrorCondition::NotAuthorized,
            AuthOutcome::NotAuthorized,
        ));
    };
    let handshake = handshake
        .value()
        .resolve(handshake.arena())
        .map_err(ComponentError::from)?;
    let domain = progress.domain.as_deref().ok_or(ComponentError::Internal)?;
    let valid = handshake.name() == "handshake"
        && handshake.namespace() == NAMESPACE
        && !handshake
            .children()
            .map_err(ComponentError::from)?
            .any(|child| matches!(child, Ok(NodeRef::Element(_))))
        && settings.registry.secret(domain).is_some_and(|secret| {
            handshake
                .text()
                .is_ok_and(|text| handshake_matches(secret, &id, text.unwrap_or("")))
        });
    if !valid {
        return Err(reject(
            StreamErrorCondition::NotAuthorized,
            AuthOutcome::NotAuthorized,
        ));
    }
    let link = settings
        .registry
        .attach(domain)
        .map_err(|error| match error {
            AttachError::Conflict => reject(StreamErrorCondition::Conflict, AuthOutcome::Conflict),
            AttachError::Stopped => {
                reject(StreamErrorCondition::SystemShutdown, AuthOutcome::Shutdown)
            }
            AttachError::Unknown => Failure::from(ComponentError::Internal),
        })?;
    writer.send("<handshake/>").await?;
    Ok(link)
}

#[cfg(test)]
mod tests;
