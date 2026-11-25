// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use compio::net::TcpStream;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_util::core_dispatcher::DispatchHandle;

use super::NEXT_S2S_CONNECTION_ID;
use super::connections::{ConnectionRegistry, ConnectionTraffic};
use super::ingress::IngressServices;
use super::metrics::{ConnectionRejection, Direction, S2sMetrics};
use super::revocation::{PeerRevocation, PeerVerification};
use super::stream::S2sReaderLimits;
use crate::admission::attempt_limit::{Admission, AttemptLimiter};
use crate::admission::connection_limit::{
    ConnectionAdmission, ConnectionLimiter, ConnectionPermit,
};
use crate::admission::global_limit::{GlobalLimit, GlobalPermit};
use crate::config::S2sConfig;
use crate::config::limits::S2sLimits;
use crate::connection::{
    AcceptHandler, ListenerKind, ListenerSet, ListenerSlot, ListenerSpec, ShutdownSignal,
    StartError,
};
use crate::hosts::{Hosts, peer_identity::PeerTrust};

mod negotiate;
mod stream;
mod streams;

#[derive(Clone)]
struct Settings<A: ChunkAllocator> {
    tls_mode: crate::config::TlsMode,
    hosts: Hosts,
    trust: Arc<PeerTrust>,
    revocation: Arc<PeerRevocation>,
    reader_limits: S2sReaderLimits,
    timeout: Duration,
    services: IngressServices<A>,
    streams: Arc<streams::InboundStreams>,
    max_streams: usize,
    idle_timeout: Duration,
    metrics: Arc<S2sMetrics>,
    connections: Arc<ConnectionRegistry>,
}

struct AdmissionLimits {
    attempts: AttemptLimiter,
    connections: ConnectionLimiter,
    global: Arc<GlobalLimit>,
}

struct Rejection {
    reason: ConnectionRejection,
    report_count: Option<u64>,
}

impl AdmissionLimits {
    async fn reserve(&self, ip: IpAddr) -> Result<(GlobalPermit, ConnectionPermit), Rejection> {
        let now = Instant::now();
        if let Admission::Denied {
            outcome,
            report_count,
        } = self.attempts.admit(ip, now).await
        {
            return Err(Rejection {
                reason: if outcome == "source_tracking_full" {
                    ConnectionRejection::AttemptTrackingFull
                } else {
                    ConnectionRejection::ConnectionAttemptsPerIp
                },
                report_count,
            });
        }
        let global = self.global.reserve(now).map_err(|report_count| Rejection {
            reason: ConnectionRejection::MaxInboundConnections,
            report_count,
        })?;
        match self.connections.reserve(ip, now).await {
            ConnectionAdmission::Allowed(permit) => Ok((global, permit)),
            ConnectionAdmission::Denied {
                outcome,
                report_count,
            } => Err(Rejection {
                reason: if outcome == "source_tracking_full" {
                    ConnectionRejection::ConnectionTrackingFull
                } else {
                    ConnectionRejection::MaxConnectionsPerIp
                },
                report_count,
            }),
        }
    }
}

pub(crate) struct S2sListeners(ListenerSet);
impl S2sListeners {
    #[expect(clippy::too_many_arguments)]
    pub(crate) async fn start<A: ChunkAllocator + Clone>(
        config: &S2sConfig,
        limits: &S2sLimits,
        hosts: Hosts,
        peers: PeerVerification,
        dispatcher: &DispatchHandle,
        services: IngressServices<A>,
        metrics: Arc<S2sMetrics>,
        connections: Arc<ConnectionRegistry>,
    ) -> Result<Self, StartError> {
        let admission = Arc::new(AdmissionLimits {
            attempts: AttemptLimiter::new(&limits.connection_attempts_per_ip),
            connections: ConnectionLimiter::new(limits.max_connections_per_ip.get()),
            global: GlobalLimit::new(limits.max_inbound_connections.get()),
        });
        let settings = Settings {
            tls_mode: crate::config::TlsMode::StartTls,
            hosts,
            trust: peers.trust,
            revocation: peers.revocation,
            reader_limits: S2sReaderLimits {
                max_stanza_bytes: limits.max_stanza_bytes,
                stanzas: limits.incoming_stanzas_per_connection.clone(),
                xml: limits.incoming_xml_per_connection.clone(),
            },
            timeout: Duration::from_secs(limits.negotiation_timeout_secs.get()),
            services,
            streams: Arc::new(streams::InboundStreams::default()),
            max_streams: limits.max_inbound_streams_per_domain.get(),
            idle_timeout: Duration::from_secs(limits.idle_timeout_secs.get()),
            metrics,
            connections,
        };
        let specs = config
            .listeners
            .iter()
            .map(|config| ListenerSpec {
                address: config.address,
                handler: {
                    let admission = &admission;
                    let settings = &settings;
                    let tls_mode = config.tls_mode;
                    move |_slot| S2sAcceptor {
                        admission: Arc::clone(admission),
                        settings: Settings {
                            tls_mode,
                            ..settings.clone()
                        },
                    }
                },
            })
            .collect();
        ListenerSet::start(ListenerKind::S2s, dispatcher, specs)
            .await
            .map(Self)
    }
    pub(crate) fn into_inner(self) -> ListenerSet {
        self.0
    }
}

struct S2sAcceptor<A: ChunkAllocator> {
    admission: Arc<AdmissionLimits>,
    settings: Settings<A>,
}
impl<A: ChunkAllocator + Clone> AcceptHandler for S2sAcceptor<A> {
    type Permit = (GlobalPermit, ConnectionPermit);
    type Rejection = Rejection;
    fn listener_bound(&self, slot: ListenerSlot) -> impl Sized + 'static {
        self.settings
            .metrics
            .listener_bound(slot.listener_id, self.settings.tls_mode)
    }
    async fn admit(&self, peer: IpAddr) -> Result<Self::Permit, Self::Rejection> {
        self.admission.reserve(peer).await
    }
    fn rejected(&self, slot: ListenerSlot, rejection: Rejection) {
        let ListenerSlot {
            listener_id,
            worker_id,
        } = slot;
        self.settings
            .metrics
            .connection_rejected(listener_id, rejection.reason);
        if let Some(rejected_connections) = rejection.report_count {
            tracing::warn!(
                connection_type = "s2s",
                listener_id,
                worker_id,
                outcome = rejection.reason.as_str(),
                rejected_connections,
                "s2s connection rejected"
            );
        }
    }
    fn serve(
        &self,
        slot: ListenerSlot,
        tcp: TcpStream,
        permits: Self::Permit,
        shutdown: ShutdownSignal,
    ) -> impl Future<Output = ()> + 'static {
        self.settings.metrics.connection_accepted(slot.listener_id);
        let gauge = self
            .settings
            .metrics
            .connection_opened(Direction::Inbound, self.settings.tls_mode);
        let attempt = self
            .settings
            .metrics
            .transport_attempt(Direction::Inbound, self.settings.tls_mode);
        let settings = self.settings.clone();
        async move {
            let _permits = permits;
            let _gauge = gauge;
            let connection_id = NEXT_S2S_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
            let traffic = Arc::new(ConnectionTraffic::default());
            let started = Instant::now();
            let outcome = match negotiate::negotiate(
                &tcp,
                &settings,
                shutdown.clone(),
                connection_id,
                &traffic,
                attempt,
            )
            .await
            {
                Ok(authenticated) => stream::serve(authenticated, &tcp, &settings, shutdown)
                    .await
                    .as_str(),
                Err(super::stream::S2sError::PeerError(condition)) => {
                    tracing::debug!(connection_id, condition = ?condition, "s2s peer stream error");
                    "peer_error"
                }
                Err(_) => "negotiation_failed",
            };
            tracing::info!(
                connection_id,
                outcome,
                tls_mode = settings.tls_mode.as_str(),
                duration_ms = started.elapsed().as_millis() as u64,
                "s2s stream disconnected"
            );
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::connection::socket::ConnectionSocket;
    use compio::net::{TcpListener, TcpStream};

    use super::*;
    #[test]
    fn connection_owner_shutdown_closes_retained_transport_clones()
    -> Result<(), Box<dyn std::error::Error>> {
        compio::runtime::Runtime::new()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let client = TcpStream::connect(listener.local_addr()?).await?;
            let (socket, _) = listener.accept().await?;
            let retained = socket.clone();
            drop(ConnectionSocket(socket));
            let compio::buf::BufResult(result, _) = compio::time::timeout(
                Duration::from_secs(5),
                compio::io::AsyncRead::read(&mut &client, vec![0; 1]),
            )
            .await?;
            assert_eq!(result?, 0);
            drop(retained);
            Ok(())
        })
    }
}
