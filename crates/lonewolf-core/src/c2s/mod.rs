// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use compio::net::TcpStream;
use lonewolf_auth::scram::{ScramHash, ScramVerifier};
use lonewolf_auth::server::ScramDecoy;
use lonewolf_storage::account::{AccountError, AccountKey, AccountReads};
use lonewolf_storage::{RedbStorage, Storage};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_util::core_dispatcher::DispatchHandle;
use prometheus_client::registry::Registry;

use crate::admission::attempt_limit::{Admission, AttemptLimiter};
use crate::admission::connection_limit::{
    ConnectionAdmission, ConnectionLimiter, ConnectionPermit,
};
use crate::config::C2sConfig;
use crate::config::limits::C2sLimits;
use crate::connection::{
    AcceptHandler, ListenerKind, ListenerSet, ListenerSlot, ListenerSpec, ShutdownSignal,
    StartError,
};
use crate::hosts::Hosts;
use crate::router::RouterHandle;

mod iq;
mod metrics;
mod stream;
mod unauthenticated_limit;

pub(crate) use metrics::PHASE_BUCKETS;
use metrics::{C2sMetrics, C2sWorkerMetrics, RejectReason};
use stream::{StreamAdmission, StreamSettings, StreamTimeouts, XmppStream};
use unauthenticated_limit::{
    Admission as UnauthenticatedAdmission, UnauthenticatedLimiter, UnauthenticatedPermit,
};

#[derive(Clone)]
struct AdmissionLimits {
    attempts: Arc<AttemptLimiter>,
    connections: Arc<ConnectionLimiter>,
    unauthenticated: Arc<UnauthenticatedLimiter>,
}

enum AdmissionRejection {
    Attempt {
        outcome: &'static str,
        report_count: Option<u64>,
    },
    Unauthenticated {
        report_count: Option<u64>,
    },
    PerIp {
        outcome: &'static str,
        report_count: Option<u64>,
        unauthenticated_permit: UnauthenticatedPermit,
    },
}

impl AdmissionLimits {
    async fn reserve(
        &self,
        source: IpAddr,
    ) -> Result<(ConnectionPermit, UnauthenticatedPermit), AdmissionRejection> {
        if let Admission::Denied {
            outcome,
            report_count,
        } = self.attempts.admit(source, Instant::now()).await
        {
            return Err(AdmissionRejection::Attempt {
                outcome,
                report_count,
            });
        }
        let unauthenticated_permit = match self.unauthenticated.reserve(Instant::now()).await {
            UnauthenticatedAdmission::Allowed(permit) => permit,
            UnauthenticatedAdmission::Denied { report_count } => {
                return Err(AdmissionRejection::Unauthenticated { report_count });
            }
        };
        match self.connections.reserve(source, Instant::now()).await {
            ConnectionAdmission::Allowed(permit) => Ok((permit, unauthenticated_permit)),
            ConnectionAdmission::Denied {
                outcome,
                report_count,
            } => Err(AdmissionRejection::PerIp {
                outcome,
                report_count,
                unauthenticated_permit,
            }),
        }
    }
}

struct AuthService {
    storage: RedbStorage,
}

impl AuthService {
    async fn scram(
        &self,
        key: &AccountKey,
        hash: ScramHash,
    ) -> Result<Option<ScramVerifier>, AccountError> {
        self.storage.begin_read().await?.scram(key, hash).await
    }

    async fn account_exists(&self, key: &AccountKey) -> Result<bool, AccountError> {
        Ok(self
            .storage
            .begin_read()
            .await?
            .account(key)
            .await?
            .is_some())
    }

    fn decoy(&self) -> &ScramDecoy {
        self.storage.scram_decoy()
    }
}

struct StreamServices<A: ChunkAllocator> {
    hosts: Hosts,
    auth: Arc<AuthService>,
    router: RouterHandle<A>,
}

pub(crate) struct Listeners(ListenerSet);
impl Listeners {
    #[expect(clippy::too_many_arguments)]
    pub(crate) async fn start<A: ChunkAllocator + Clone>(
        config: &C2sConfig,
        limits: &C2sLimits,
        hosts: Hosts,
        storage: RedbStorage,
        router: RouterHandle<A>,
        dispatcher: &DispatchHandle,
        allocator: A,
        registry: &mut Registry,
    ) -> Result<Self, StartError> {
        let unauthenticated = Arc::new(UnauthenticatedLimiter::new(
            limits.max_unauthenticated_connections,
        ));
        let metrics = C2sMetrics::new(
            config.listeners.len(),
            NonZeroUsize::new(dispatcher.worker_count()).unwrap_or(NonZeroUsize::MIN),
            Arc::clone(&unauthenticated),
        );
        metrics.register(registry);
        let auth = Arc::new(AuthService { storage });
        let mut specs = Vec::with_capacity(config.listeners.len());
        for (listener_id, config) in config.listeners.iter().enumerate() {
            let profile_name = config.limits.as_deref().unwrap_or(&limits.default);
            let profile = limits.profiles.get(profile_name).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("c2s listener {listener_id} references unknown limit profile {profile_name:?}"),
                )
            }).map_err(|error| StartError { error, deadline: Instant::now() + crate::WORKER_SHUTDOWN_GRACE })?;
            let admission = AdmissionLimits {
                attempts: Arc::new(AttemptLimiter::new(&profile.connection_attempts_per_ip)),
                connections: Arc::new(ConnectionLimiter::new(profile.max_connections_per_ip.get())),
                unauthenticated: Arc::clone(&unauthenticated),
            };
            let establishment_timeout =
                Duration::from_secs(profile.connection_establishment_timeout_secs.get());
            let authentication_timeout =
                Duration::from_secs(profile.authentication_timeout_secs.get());
            let binding_timeout = Duration::from_secs(profile.resource_binding_timeout_secs.get());
            specs.push(ListenerSpec {
                address: config.address,
                handler: {
                    let hosts = &hosts;
                    let auth = &auth;
                    let router = &router;
                    let allocator = &allocator;
                    let metrics = &metrics;
                    move |slot: ListenerSlot| {
                        let worker_metrics = metrics.worker(slot.listener_id, slot.worker_id);
                        C2sAcceptor {
                            admission: admission.clone(),
                            services: StreamServices {
                                hosts: hosts.clone(),
                                auth: Arc::clone(auth),
                                router: router.clone(),
                            },
                            settings: {
                                let mut settings = StreamSettings::new(
                                    config.auth_mechanisms,
                                    profile,
                                    StreamTimeouts {
                                        establishment: establishment_timeout,
                                        authentication: authentication_timeout,
                                        binding: binding_timeout,
                                    },
                                    limits.max_resources_per_account,
                                    allocator.clone(),
                                    worker_metrics.clone(),
                                );
                                settings.tls_mode = config.tls_mode;
                                settings
                            },
                            metrics: worker_metrics,
                        }
                    }
                },
            });
        }
        ListenerSet::start(ListenerKind::C2s, dispatcher, specs)
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

struct C2sAcceptor<A: ChunkAllocator> {
    admission: AdmissionLimits,
    services: StreamServices<A>,
    settings: StreamSettings<A>,
    metrics: C2sWorkerMetrics,
}
impl<A: ChunkAllocator + Clone> AcceptHandler for C2sAcceptor<A> {
    type Permit = (ConnectionPermit, UnauthenticatedPermit);
    type Rejection = AdmissionRejection;
    fn listener_bound(&self, _: ListenerSlot) -> impl Sized + 'static {
        self.metrics.listener_bound(self.settings.tls_mode)
    }
    async fn admit(&self, peer: IpAddr) -> Result<Self::Permit, Self::Rejection> {
        self.admission.reserve(peer).await
    }
    fn rejected(&self, slot: ListenerSlot, rejection: Self::Rejection) {
        let ListenerSlot {
            listener_id,
            worker_id,
        } = slot;
        self.metrics
            .connection_rejected(rejection_reason(&rejection));
        match rejection {
            AdmissionRejection::PerIp {
                outcome,
                report_count,
                unauthenticated_permit,
            } => {
                if let Some(rejected_connections) = report_count {
                    tracing::warn!(
                        connection_type = "c2s",
                        listener_id,
                        worker_id,
                        outcome,
                        rejected_connections,
                        "c2s connection rejected"
                    );
                }
                drop(unauthenticated_permit);
            }
            AdmissionRejection::Unauthenticated { report_count } => {
                if let Some(rejected_connections) = report_count {
                    tracing::warn!(
                        connection_type = "c2s",
                        listener_id,
                        worker_id,
                        outcome = "unauthenticated_connection_limit",
                        rejected_connections,
                        "c2s connection rejected"
                    );
                }
            }
            AdmissionRejection::Attempt {
                outcome,
                report_count,
            } => {
                if let Some(rejected_attempts) = report_count {
                    tracing::warn!(
                        connection_type = "c2s",
                        listener_id,
                        worker_id,
                        outcome,
                        rejected_attempts,
                        "c2s connection attempt rejected"
                    );
                }
            }
        }
    }
    fn serve(
        &self,
        slot: ListenerSlot,
        socket: TcpStream,
        (ip_permit, unauthenticated_permit): Self::Permit,
        shutdown: ShutdownSignal,
    ) -> impl std::future::Future<Output = ()> + 'static {
        self.metrics.connection_accepted();
        let admission = StreamAdmission::new(
            ip_permit,
            unauthenticated_permit,
            slot.listener_id,
            slot.worker_id,
            self.metrics.clone(),
        )
        .with_tls_mode(self.settings.tls_mode);
        let hosts = self.services.hosts.clone();
        let auth = Arc::clone(&self.services.auth);
        let router = self.services.router.clone();
        let settings = self.settings.clone();
        async move {
            let _ = XmppStream::new(socket, admission, hosts, auth, router, settings)
                .run_until(shutdown)
                .await;
        }
    }
    fn active_connections(&self, count: usize) {
        self.metrics.set_connections(count);
    }
}

fn rejection_reason(rejection: &AdmissionRejection) -> RejectReason {
    match rejection {
        AdmissionRejection::Attempt {
            outcome: "rate_limited",
            ..
        } => RejectReason::ConnectionAttemptsPerIp,
        AdmissionRejection::Attempt { .. } => RejectReason::AttemptTrackingFull,
        AdmissionRejection::Unauthenticated { .. } => RejectReason::MaxUnauthenticatedConnections,
        AdmissionRejection::PerIp {
            outcome: "connection_limit",
            ..
        } => RejectReason::MaxConnectionsPerIp,
        AdmissionRejection::PerIp { .. } => RejectReason::ConnectionTrackingFull,
    }
}

#[cfg(test)]
#[path = "tests/listeners.rs"]
mod tests;
