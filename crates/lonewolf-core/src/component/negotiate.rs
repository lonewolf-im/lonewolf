// SPDX-License-Identifier: Apache-2.0

use std::pin::{Pin, pin};
use std::sync::Arc;
use std::time::{Duration, Instant};

use compio::io::compat::{AsyncReadStream, AsyncStream};
use compio::net::TcpStream;
use futures_util::FutureExt as _;
use futures_util::future::{Either, select};
use lonewolf_auth::component::handshake_matches;
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stanza::NodeRef;
use lonewolf_xmpp::stream::StreamErrorCondition;
use tokio::io::BufReader;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _};

use super::Settings;
use super::metrics::{AuthOutcome, ComponentMetrics, GaugeGuard};
use super::registry::{AttachError, ComponentLink};
use super::stream::{self, ComponentError, ComponentReader, ComponentWriter};
use crate::connection::ShutdownSignal;
use crate::xml_stream::traffic::{ObservedIo, TrafficObserver};

const NAMESPACE: &str = "jabber:component:accept";
type Input =
    BufReader<Compat<Pin<Box<AsyncReadStream<ObservedIo<TcpStream, ComponentByteObserver>>>>>>;
type Output = Pin<Box<AsyncStream<ObservedIo<TcpStream, ComponentByteObserver>>>>;

pub(crate) struct Authenticated<A: ChunkAllocator, R, W> {
    pub(crate) domain: Arc<str>,
    pub(crate) connection_id: u64,
    pub(crate) reader: ComponentReader<A, R>,
    pub(crate) writer: ComponentWriter<W>,
    pub(crate) link: ComponentLink<A>,
    pub(crate) stream_gauge: GaugeGuard,
}

#[derive(Clone)]
pub(super) struct ComponentByteObserver(Arc<ComponentMetrics>);
impl TrafficObserver for ComponentByteObserver {
    fn received(&self, bytes: usize) {
        self.0.bytes(bytes as u64, 0);
    }
    fn sent(&self, bytes: usize) {
        self.0.bytes(0, bytes as u64);
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
    mut accounting: Accounting,
) -> Result<Authenticated<A, Input, Output>, ComponentError> {
    let input = Box::pin(AsyncReadStream::new(ObservedIo::new(
        tcp.clone(),
        ComponentByteObserver(Arc::clone(&settings.metrics)),
    )))
    .compat();
    let mut reader = ComponentReader::new(
        BufReader::new(input),
        &settings.limits,
        settings.services.allocator.clone(),
        Arc::clone(&settings.metrics),
    );
    let mut writer = ComponentWriter::new(Box::pin(AsyncStream::new(ObservedIo::new(
        tcp.clone(),
        ComponentByteObserver(Arc::clone(&settings.metrics)),
    ))));
    let mut progress = Progress {
        domain: None,
        header_sent: false,
        peer_footer: false,
    };
    let mut shutdown_deadline = None;
    let result = {
        let flow = pin!(run(&mut reader, &mut writer, settings, &mut progress));
        match select(
            pin!(shutdown.clone()),
            pin!(compio::time::timeout_at(
                accounting.started + settings.timeout,
                flow
            )),
        )
        .await
        {
            Either::Left((deadline, _)) => {
                shutdown_deadline = Some(deadline);
                Err(reject(
                    StreamErrorCondition::SystemShutdown,
                    AuthOutcome::Shutdown,
                ))
            }
            Either::Right((Err(_), _)) => Err(reject(
                StreamErrorCondition::ConnectionTimeout,
                AuthOutcome::Timeout,
            )),
            Either::Right((Ok(result), _)) => result,
        }
    };
    accounting.elapsed = Some(accounting.started.elapsed());
    match result {
        Ok(link) => {
            accounting.outcome = AuthOutcome::Success;
            let domain = progress.domain.take().ok_or(ComponentError::Internal)?;
            Ok(Authenticated {
                domain,
                connection_id,
                reader,
                writer,
                link,
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
            if !matches!(
                failure.error,
                ComponentError::Io | ComponentError::Timeout | ComponentError::PeerError(_)
            ) && (!matches!(failure.error, ComponentError::Eof) || progress.peer_footer)
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
                        &mut reader,
                        &mut writer,
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
    writer.send(&response).await?;
    progress.header_sent = true;
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
