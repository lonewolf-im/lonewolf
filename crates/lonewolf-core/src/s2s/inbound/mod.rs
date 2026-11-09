// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use compio::net::TcpStream;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_util::core_dispatcher::DispatchHandle;
use parking_lot::Mutex as PlMutex;

use super::NEXT_S2S_CONNECTION_ID;
use super::ingress::IngressServices;
use super::metrics::{ConnectionRejection, Direction, S2sMetrics};
use super::revocation::{PeerRevocation, PeerVerification};
use super::stream::S2sReaderLimits;
use crate::admission::attempt_limit::{Admission, AttemptLimiter};
use crate::admission::connection_limit::{
    ConnectionAdmission, ConnectionLimiter, ConnectionPermit,
};
use crate::admission::rejection_report::RejectionReport;
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
}

struct GlobalLimit {
    active: AtomicUsize,
    max: usize,
    report: PlMutex<RejectionReport>,
}

struct GlobalPermit(Arc<GlobalLimit>);

impl Drop for GlobalPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
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
        let mut active = self.global.active.load(Ordering::Acquire);
        loop {
            if active >= self.global.max {
                return Err(Rejection {
                    reason: ConnectionRejection::MaxInboundConnections,
                    report_count: self.global.report.lock().record(now),
                });
            }
            match self.global.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => active = current,
            }
        }
        let global = GlobalPermit(Arc::clone(&self.global));
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
    pub(crate) async fn start<A: ChunkAllocator + Clone>(
        config: &S2sConfig,
        limits: &S2sLimits,
        hosts: Hosts,
        peers: PeerVerification,
        dispatcher: &DispatchHandle,
        services: IngressServices<A>,
        metrics: Arc<S2sMetrics>,
    ) -> Result<Self, StartError> {
        let admission = Arc::new(AdmissionLimits {
            attempts: AttemptLimiter::new(&limits.connection_attempts_per_ip),
            connections: ConnectionLimiter::new(limits.max_connections_per_ip.get()),
            global: Arc::new(GlobalLimit {
                active: AtomicUsize::new(0),
                max: limits.max_inbound_connections.get(),
                report: PlMutex::new(RejectionReport::default()),
            }),
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
    pub(crate) fn addresses(&self) -> &[SocketAddr] {
        self.0.addresses()
    }
    pub(crate) fn stop(&mut self, deadline: Instant) {
        self.0.stop(deadline);
    }
    pub(crate) async fn failure(&mut self) -> io::Error {
        self.0.failure().await
    }
    pub(crate) async fn join(&mut self) -> io::Result<()> {
        self.0.join().await
    }
}

struct S2sAcceptor<A: ChunkAllocator> {
    admission: Arc<AdmissionLimits>,
    settings: Settings<A>,
}
impl<A: ChunkAllocator + Clone> AcceptHandler for S2sAcceptor<A> {
    type Permit = (GlobalPermit, ConnectionPermit);
    type Rejection = Rejection;
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
        let gauge = self.settings.metrics.connection_opened(Direction::Inbound);
        let settings = self.settings.clone();
        async move {
            let _permits = permits;
            let _gauge = gauge;
            let connection_id = NEXT_S2S_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
            let started = Instant::now();
            let outcome = match negotiate::negotiate(
                &tcp,
                &settings,
                shutdown.clone(),
                connection_id,
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
