// SPDX-License-Identifier: Apache-2.0

pub(crate) mod credentials;
pub(crate) mod metrics;
pub(crate) mod registry;
pub(crate) mod service;

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use compio::net::TcpStream;
use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_util::core_dispatcher::DispatchHandle;

use self::metrics::{ComponentMetrics, ConnectionRejection, StreamClose, Transport};
use self::registry::ComponentRegistry;
use crate::admission::attempt_limit::{Admission, AttemptLimiter};
use crate::admission::global_limit::{GlobalLimit, GlobalPermit};
use crate::config::limits::ComponentLimits;
use crate::config::{ComponentTlsMode, ComponentsConfig};
use crate::connection::{
    AcceptHandler, ListenerKind, ListenerSet, ListenerSlot, ListenerSpec, ShutdownSignal,
    StartError,
};
use crate::hosts::Hosts;
use crate::router::RouterHandle;

mod bounce;
mod ingress;
mod negotiate;
mod receive;
mod session;
pub(crate) mod stream;

static NEXT_COMPONENT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) struct StreamAccounting {
    metrics: Arc<ComponentMetrics>,
    outcome: StreamClose,
}

impl StreamAccounting {
    fn new(metrics: Arc<ComponentMetrics>) -> Self {
        Self {
            metrics,
            outcome: StreamClose::Shutdown,
        }
    }

    /// Set the terminal outcome before awaiting stream closure.
    fn set_outcome(&mut self, outcome: StreamClose) {
        self.outcome = outcome;
    }
}

impl Drop for StreamAccounting {
    fn drop(&mut self) {
        self.metrics.stream_closed(self.outcome);
    }
}

#[derive(Clone)]
pub(crate) struct ComponentServices<A: ChunkAllocator> {
    pub(crate) router: RouterHandle<A>,
    pub(crate) storage: RedbStorage,
    pub(crate) allocator: A,
}

#[derive(Clone)]
struct Settings<A: ChunkAllocator> {
    limits: ComponentLimits,
    hosts: Hosts,
    tls_mode: ComponentTlsMode,
    timeout: Duration,
    registry: ComponentRegistry<A>,
    services: ComponentServices<A>,
    metrics: Arc<ComponentMetrics>,
}
struct AdmissionLimits {
    attempts: AttemptLimiter,
    global: Arc<GlobalLimit>,
}
struct Rejection {
    reason: ConnectionRejection,
    report_count: Option<u64>,
}

pub(crate) struct ComponentListeners;
impl ComponentListeners {
    pub(crate) async fn start<A: ChunkAllocator + Clone>(
        config: &ComponentsConfig,
        limits: &ComponentLimits,
        hosts: Hosts,
        registry: ComponentRegistry<A>,
        dispatcher: &DispatchHandle,
        services: ComponentServices<A>,
        metrics: Arc<ComponentMetrics>,
    ) -> Result<ListenerSet, StartError> {
        let admission = Arc::new(AdmissionLimits {
            attempts: AttemptLimiter::new(&limits.connection_attempts_per_ip),
            global: GlobalLimit::new(limits.max_inbound_connections.get()),
        });
        let settings = Settings {
            limits: limits.clone(),
            hosts,
            tls_mode: ComponentTlsMode::None,
            timeout: Duration::from_secs(limits.negotiation_timeout_secs.get()),
            registry,
            services,
            metrics,
        };
        let specs = config.listeners.iter().enumerate().map(|(listener_id, config)| {
            if config.tls_mode == ComponentTlsMode::None && !config.address.ip().is_loopback() {
                tracing::warn!(listener_id, port = config.address.port(), "component listener accepts unencrypted connections on a non-loopback address");
            }
            let admission = &admission;
            let mut settings = settings.clone();
            settings.tls_mode = config.tls_mode;
            ListenerSpec { address: config.address, handler: move |_| ComponentAcceptor { admission: Arc::clone(admission), settings: settings.clone() } }
        }).collect();
        ListenerSet::start(ListenerKind::Component, dispatcher, specs).await
    }
}

struct ComponentAcceptor<A: ChunkAllocator> {
    admission: Arc<AdmissionLimits>,
    settings: Settings<A>,
}
impl<A: ChunkAllocator + Clone> AcceptHandler for ComponentAcceptor<A> {
    type Permit = GlobalPermit;
    type Rejection = Rejection;
    fn listener_bound(&self, slot: ListenerSlot) -> impl Sized + 'static {
        self.settings.metrics.listener_bound(
            slot.listener_id,
            match self.settings.tls_mode {
                ComponentTlsMode::None => Transport::Plain,
                ComponentTlsMode::Direct => Transport::DirectTls,
            },
        )
    }
    async fn admit(&self, peer: IpAddr) -> Result<GlobalPermit, Rejection> {
        let now = Instant::now();
        if let Admission::Denied {
            outcome,
            report_count,
        } = self.admission.attempts.admit(peer, now).await
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
        self.admission
            .global
            .reserve(now)
            .map_err(|report_count| Rejection {
                reason: ConnectionRejection::MaxInboundConnections,
                report_count,
            })
    }
    fn rejected(&self, slot: ListenerSlot, rejection: Rejection) {
        self.settings
            .metrics
            .connection_rejected(slot.listener_id, rejection.reason);
        if let Some(rejected_connections) = rejection.report_count {
            tracing::warn!(
                connection_type = "component",
                listener_id = slot.listener_id,
                worker_id = slot.worker_id,
                outcome = rejection.reason.as_str(),
                rejected_connections,
                "component connection rejected"
            );
        }
    }
    fn serve(
        &self,
        slot: ListenerSlot,
        tcp: TcpStream,
        permit: GlobalPermit,
        shutdown: ShutdownSignal,
    ) -> impl Future<Output = ()> + 'static {
        self.settings.metrics.connection_accepted(slot.listener_id);
        let gauge = self.settings.metrics.connection_opened();
        let accounting = negotiate::Accounting::new(Arc::clone(&self.settings.metrics));
        let settings = self.settings.clone();
        async move {
            let _permit = permit;
            let _gauge = gauge;
            let connection_id = NEXT_COMPONENT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
            set_keepalive(&tcp, connection_id);
            let started = Instant::now();
            if let Ok(authenticated) =
                negotiate::negotiate(&tcp, &settings, shutdown.clone(), connection_id, accounting)
                    .await
            {
                let domain = Arc::clone(&authenticated.domain);
                tracing::info!(component_domain = %domain, connection_id, "component connected");
                let outcome =
                    session::serve(authenticated, &tcp, &settings, &settings.services, shutdown)
                        .await;
                tracing::info!(component_domain = %domain, connection_id, outcome = outcome.as_str(), duration_ms = started.elapsed().as_millis() as u64, "component disconnected");
            }
        }
    }
}

fn set_keepalive(tcp: &TcpStream, connection_id: u64) {
    if let Err(error) = socket2::SockRef::from(tcp).set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(10)),
    ) {
        tracing::debug!(connection_id, error_kind = ?error.kind(), "component keepalive unavailable");
    }
}

#[cfg(test)]
mod tests;
