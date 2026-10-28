// SPDX-License-Identifier: Apache-2.0

mod authenticate;
mod bind;
mod bound;
mod certificate;
mod close;
mod establish;
mod header;
mod outcome;
mod recipient_rate;
mod renegotiation;
mod session;
mod stanza_rate;
mod traffic;

use std::future::Future;
use std::net::Shutdown;
use std::num::NonZeroUsize;
use std::panic::AssertUnwindSafe;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use compio::net::TcpStream;
use futures_util::FutureExt;
use lonewolf_util::arena::ChunkAllocator;
use socket2::SockRef;

pub(super) use authenticate::{SaslFailure, SaslMechanism};
use authenticate::{authenticate, sasl_features};
pub(super) use bind::BindRejection;
use bind::bind_resource;
use bound::bound_stream;
use establish::establish;
pub(super) use outcome::CloseOutcome;

use super::AuthService;
use super::metrics::C2sWorkerMetrics;
use super::unauthenticated_limit::UnauthenticatedPermit;
use crate::admission::connection_limit::ConnectionPermit;
use crate::config::AuthMechanisms;
use crate::config::limits::C2sLimitProfile;
use crate::hosts::Hosts;
use crate::router::{RouterHandle, release_deferred};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StreamPhase {
    Establishing,
    Authenticating,
    Binding,
    Bound,
}

impl StreamPhase {
    pub(super) const ALL: [Self; 4] = [
        Self::Establishing,
        Self::Authenticating,
        Self::Binding,
        Self::Bound,
    ];

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Establishing => "establishing",
            Self::Authenticating => "authenticating",
            Self::Binding => "binding",
            Self::Bound => "bound",
        }
    }
}

struct ConnectionLifecycle {
    connection_id: u64,
    listener_id: usize,
    worker_id: usize,
    accepted_at: Instant,
    phase: StreamPhase,
    bound_at: Option<Instant>,
    metrics: C2sWorkerMetrics,
    outcome: Option<CloseOutcome>,
}

pub(super) struct StreamAdmission {
    ip_permit: ConnectionPermit,
    unauthenticated_permit: UnauthenticatedPermit,
    lifecycle: ConnectionLifecycle,
}

pub(super) struct XmppStream<A: ChunkAllocator> {
    transport: TcpStream,
    admission: StreamAdmission,
    hosts: Hosts,
    auth: Arc<AuthService>,
    router: RouterHandle<A>,
    settings: StreamSettings<A>,
}

#[derive(Clone)]
pub(super) struct StreamSettings<A: ChunkAllocator> {
    auth_mechanisms: AuthMechanisms,
    sasl_features: Option<Arc<str>>,
    external_sasl_features: Option<Arc<str>>,
    max_stanza_bytes: NonZeroUsize,
    stanzas_per_second: NonZeroUsize,
    stanza_burst: NonZeroUsize,
    recipients_per_second: NonZeroUsize,
    recipient_burst: NonZeroUsize,
    xml_bytes_per_second: NonZeroUsize,
    xml_burst_bytes: NonZeroUsize,
    establishment_timeout: Duration,
    authentication_timeout: Duration,
    binding_timeout: Duration,
    authentication_retries: NonZeroUsize,
    resource_binding_retries: NonZeroUsize,
    max_resources_per_account: NonZeroUsize,
    allocator: A,
    metrics: C2sWorkerMetrics,
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
        profile: &C2sLimitProfile,
        timeouts: StreamTimeouts,
        max_resources_per_account: NonZeroUsize,
        allocator: A,
        metrics: C2sWorkerMetrics,
    ) -> Self {
        Self {
            auth_mechanisms,
            sasl_features: sasl_features(auth_mechanisms, false).map(Arc::from),
            external_sasl_features: sasl_features(auth_mechanisms, true).map(Arc::from),
            max_stanza_bytes: profile.max_stanza_bytes,
            stanzas_per_second: profile.incoming_stanzas_per_connection.per_second,
            stanza_burst: profile.incoming_stanzas_per_connection.burst,
            recipients_per_second: profile.new_recipients_per_connection.per_second,
            recipient_burst: profile.new_recipients_per_connection.burst,
            xml_bytes_per_second: profile.incoming_xml_per_connection.bytes_per_second,
            xml_burst_bytes: profile.incoming_xml_per_connection.burst_bytes,
            establishment_timeout: timeouts.establishment,
            authentication_timeout: timeouts.authentication,
            binding_timeout: timeouts.binding,
            authentication_retries: profile.authentication_retries,
            resource_binding_retries: profile.resource_binding_retries,
            max_resources_per_account,
            allocator,
            metrics,
        }
    }
}

impl ConnectionLifecycle {
    fn established(&mut self, host: &str) {
        let elapsed = self.accepted_at.elapsed();
        self.metrics
            .phase_completed(StreamPhase::Establishing, elapsed);
        tracing::info!(
            connection_type = "c2s",
            connection_id = self.connection_id,
            listener_id = self.listener_id,
            worker_id = self.worker_id,
            host,
            establishment_ms = elapsed.as_millis(),
            "connection established"
        );
    }

    fn authenticated(&mut self, host: &str, mechanism: SaslMechanism, started_at: Instant) {
        let elapsed = started_at.elapsed();
        self.metrics
            .phase_completed(StreamPhase::Authenticating, elapsed);
        tracing::info!(
            connection_type = "c2s",
            connection_id = self.connection_id,
            listener_id = self.listener_id,
            worker_id = self.worker_id,
            host,
            auth_mechanism = mechanism.name(),
            authentication_ms = elapsed.as_millis(),
            "connection authenticated"
        );
    }

    fn bound(&mut self, resource_requested: bool, started_at: Instant) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(started_at);
        self.metrics.phase_completed(StreamPhase::Binding, elapsed);
        self.phase = StreamPhase::Bound;
        self.bound_at = Some(now);
        tracing::info!(
            connection_type = "c2s",
            connection_id = self.connection_id,
            listener_id = self.listener_id,
            worker_id = self.worker_id,
            resource_requested,
            binding_ms = elapsed.as_millis(),
            "resource bound"
        );
    }
}

impl StreamAdmission {
    pub(super) fn new(
        ip_permit: ConnectionPermit,
        unauthenticated_permit: UnauthenticatedPermit,
        listener_id: usize,
        worker_id: usize,
        metrics: C2sWorkerMetrics,
    ) -> Self {
        Self {
            ip_permit,
            unauthenticated_permit,
            lifecycle: ConnectionLifecycle {
                connection_id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
                listener_id,
                worker_id,
                accepted_at: Instant::now(),
                phase: StreamPhase::Establishing,
                bound_at: None,
                metrics,
                outcome: None,
            },
        }
    }
}

impl Drop for ConnectionLifecycle {
    fn drop(&mut self) {
        tracing::info!(
            connection_type = "c2s",
            connection_id = self.connection_id,
            listener_id = self.listener_id,
            worker_id = self.worker_id,
            stream_phase = self.phase.as_str(),
            outcome = self.outcome.map_or("cancelled", |outcome| outcome.as_str()),
            duration_ms = self.accepted_at.elapsed().as_millis(),
            "stream disconnected"
        );
        self.metrics.connection_closed(self.phase, self.outcome);
        if let Some(bound_at) = self.bound_at {
            self.metrics.session_ended(bound_at.elapsed());
        }
    }
}

impl<A: ChunkAllocator + Clone> XmppStream<A> {
    pub(super) fn new(
        transport: TcpStream,
        admission: StreamAdmission,
        hosts: Hosts,
        auth: Arc<AuthService>,
        router: RouterHandle<A>,
        settings: StreamSettings<A>,
    ) -> Self {
        Self {
            transport,
            admission,
            hosts,
            auth,
            router,
            settings,
        }
    }

    #[cfg(test)]
    pub(super) async fn run(self) -> CloseOutcome {
        self.run_until(std::future::pending::<Instant>().boxed_local().shared())
            .await
    }

    pub(super) async fn run_until(self, shutdown: close::ShutdownSignal) -> CloseOutcome {
        let Self {
            transport,
            admission,
            hosts,
            auth,
            router,
            settings,
        } = self;
        let StreamAdmission {
            ip_permit,
            unauthenticated_permit,
            mut lifecycle,
        } = admission;
        let accepted_at = lifecycle.accepted_at;
        let close_control = transport.clone();
        let mut unauthenticated_permit = Some(unauthenticated_permit);
        let mut context = close::CloseContext {
            socket: close_control.clone(),
            shutdown,
            phase_deadline: accepted_at.checked_add(settings.establishment_timeout),
        };
        let mut work = crate::delivery::WorkGroup::new();
        let phases = async {
            let mut established = establish(transport, &hosts, &settings, context.clone()).await?;
            lifecycle.established(established.session.host());
            lifecycle.phase = StreamPhase::Authenticating;
            context.phase_deadline = established
                .auth_started_at
                .checked_add(settings.authentication_timeout);
            established.session.close = context.clone();
            let authenticated = run_phase(
                context.phase_deadline,
                CloseOutcome::AuthenticationTimeout,
                context.interrupt(authenticate(
                    &mut established,
                    &auth,
                    settings.auth_mechanisms,
                    settings.authentication_retries.get(),
                    &settings.metrics,
                )),
            )
            .await;
            let (account, mechanism) = match authenticated {
                Ok(authenticated) => authenticated,
                Err(outcome) => return Err(established.session.finish(outcome).await),
            };
            lifecycle.authenticated(
                established.session.host(),
                mechanism,
                established.auth_started_at,
            );
            lifecycle.phase = StreamPhase::Binding;
            unauthenticated_permit.take();
            let binding_started_at = Instant::now();
            context.phase_deadline = binding_started_at.checked_add(settings.binding_timeout);
            established.session.close = context.clone();
            let mut bound = bind_resource(
                established,
                &hosts,
                &account,
                &router,
                auth.storage.clone(),
                &settings,
                settings.allocator.clone(),
            )
            .await?;
            lifecycle.bound(bound.resource_requested, binding_started_at);
            bound.session.close.phase_deadline = None;
            let recipients = recipient_rate::RecipientLimiter::new(
                settings.recipients_per_second,
                settings.recipient_burst,
                Instant::now(),
                settings.metrics.clone(),
            );
            Ok(bound_stream(bound, &mut work, recipients).await)
        };
        let outcome = finish_phases(phases, &close_control, &settings.metrics).await;
        work.drain().await;
        drop(unauthenticated_permit);
        drop(ip_permit);
        lifecycle.outcome = Some(outcome);
        outcome
    }
}

async fn finish_phases(
    phases: impl Future<Output = Result<CloseOutcome, CloseOutcome>>,
    close_control: &TcpStream,
    metrics: &C2sWorkerMetrics,
) -> CloseOutcome {
    match AssertUnwindSafe(phases).catch_unwind().await {
        Ok(Ok(outcome) | Err(outcome)) => outcome,
        Err(_) => {
            metrics.connection_panicked();
            let _ = SockRef::from(close_control).shutdown(Shutdown::Both);
            release_deferred();
            tracing::error!("connection task panicked");
            CloseOutcome::InternalError
        }
    }
}

async fn run_phase<T>(
    deadline: Option<Instant>,
    timeout_outcome: CloseOutcome,
    phase: impl Future<Output = Result<T, CloseOutcome>>,
) -> Result<T, CloseOutcome> {
    let mut phase = pin!(phase);
    match close::before_deadline(deadline.unwrap_or_else(Instant::now), phase.as_mut()).await {
        Ok(result) => result,
        Err(_) => Err(timeout_outcome),
    }
}

#[cfg(test)]
#[path = "../tests/stream.rs"]
mod tests;
