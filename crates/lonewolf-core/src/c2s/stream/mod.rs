// SPDX-License-Identifier: Apache-2.0

mod authenticate;
mod bind;
mod bound;
mod certificate;
mod close;
mod establish;
mod header;
mod outcome;
mod session;
mod stanza_rate;

use std::future::Future;
use std::net::Shutdown;
use std::num::NonZeroUsize;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use compio::net::TcpStream;
use compio::time::timeout;
use futures_util::FutureExt;
use lonewolf_util::arena::ChunkAllocator;
use socket2::SockRef;

use authenticate::{SaslMechanism, authenticate, sasl_features};
use bind::bind_resource;
use bound::bound_stream;
use establish::establish;
pub(super) use outcome::CloseOutcome;

use super::AuthService;
use super::connection_limit::ConnectionPermit;
use super::unauthenticated_limit::UnauthenticatedPermit;
use crate::config::AuthMechanisms;
use crate::config::limits::{ByteRate, EventRate};
use crate::hosts::Hosts;
use crate::router::{RouterHandle, release_deferred};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

struct ConnectionLifecycle {
    connection_id: u64,
    listener_id: usize,
    worker_id: usize,
    accepted_at: Instant,
    stream_phase: &'static str,
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
    sasl_features: Arc<str>,
    external_sasl_features: Arc<str>,
    max_stanza_bytes: NonZeroUsize,
    stanzas_per_second: NonZeroUsize,
    stanza_burst: NonZeroUsize,
    xml_bytes_per_second: NonZeroUsize,
    xml_burst_bytes: NonZeroUsize,
    establishment_timeout: Duration,
    authentication_timeout: Duration,
    binding_timeout: Duration,
    max_resources_per_account: NonZeroUsize,
    allocator: A,
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
        max_stanza_bytes: NonZeroUsize,
        stanza_rate: &EventRate,
        xml_rate: &ByteRate,
        timeouts: StreamTimeouts,
        max_resources_per_account: NonZeroUsize,
        allocator: A,
    ) -> Self {
        Self {
            auth_mechanisms,
            sasl_features: sasl_features(auth_mechanisms, false).into(),
            external_sasl_features: sasl_features(auth_mechanisms, true).into(),
            max_stanza_bytes,
            stanzas_per_second: stanza_rate.per_second,
            stanza_burst: stanza_rate.burst,
            xml_bytes_per_second: xml_rate.bytes_per_second,
            xml_burst_bytes: xml_rate.burst_bytes,
            establishment_timeout: timeouts.establishment,
            authentication_timeout: timeouts.authentication,
            binding_timeout: timeouts.binding,
            max_resources_per_account,
            allocator,
        }
    }
}

impl ConnectionLifecycle {
    fn established(&mut self, host: &str) {
        self.stream_phase = "established";
        tracing::info!(
            connection_type = "c2s",
            connection_id = self.connection_id,
            listener_id = self.listener_id,
            worker_id = self.worker_id,
            host,
            establishment_ms = self.accepted_at.elapsed().as_millis(),
            "connection established"
        );
    }

    fn authenticated(&mut self, host: &str, mechanism: SaslMechanism, started_at: Instant) {
        self.stream_phase = "authenticated";
        tracing::info!(
            connection_type = "c2s",
            connection_id = self.connection_id,
            listener_id = self.listener_id,
            worker_id = self.worker_id,
            host,
            auth_mechanism = mechanism.name(),
            authentication_ms = started_at.elapsed().as_millis(),
            "connection authenticated"
        );
    }

    fn bound(&mut self, resource_requested: bool, started_at: Instant) {
        self.stream_phase = "bound";
        tracing::info!(
            connection_type = "c2s",
            connection_id = self.connection_id,
            listener_id = self.listener_id,
            worker_id = self.worker_id,
            resource_requested,
            binding_ms = started_at.elapsed().as_millis(),
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
    ) -> Self {
        Self {
            ip_permit,
            unauthenticated_permit,
            lifecycle: ConnectionLifecycle {
                connection_id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
                listener_id,
                worker_id,
                accepted_at: Instant::now(),
                stream_phase: "establishing",
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
            stream_phase = self.stream_phase,
            outcome = self.outcome.map_or("cancelled", |outcome| outcome.as_str()),
            duration_ms = self.accepted_at.elapsed().as_millis(),
            "stream disconnected"
        );
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
            let mut established = run_phase(
                &close_control,
                phase_remaining(accepted_at, settings.establishment_timeout),
                CloseOutcome::EstablishmentTimeout,
                establish(transport, &hosts, &settings, context.clone()),
            )
            .await?;
            lifecycle.established(established.session.host());
            lifecycle.stream_phase = "authenticating";
            context.phase_deadline = established
                .auth_started_at
                .checked_add(settings.authentication_timeout);
            established.session.close = context.clone();
            let authenticated = run_phase(
                &close_control,
                phase_remaining(established.auth_started_at, settings.authentication_timeout),
                CloseOutcome::AuthenticationTimeout,
                context.interrupt(authenticate(
                    &mut established,
                    &hosts,
                    &auth,
                    settings.auth_mechanisms,
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
            lifecycle.stream_phase = "binding";
            unauthenticated_permit.take();
            let binding_started_at = Instant::now();
            context.phase_deadline = binding_started_at.checked_add(settings.binding_timeout);
            established.session.close = context.clone();
            let mut bound = run_phase(
                &close_control,
                phase_remaining(binding_started_at, settings.binding_timeout),
                CloseOutcome::BindingTimeout,
                bind_resource(
                    established,
                    &hosts,
                    &account,
                    &router,
                    auth.storage.clone(),
                    settings.max_resources_per_account,
                    settings.allocator.clone(),
                ),
            )
            .await?;
            lifecycle.bound(bound.resource_requested, binding_started_at);
            bound.session.close.phase_deadline = None;
            Ok(bound_stream(bound, &mut work).await)
        };
        let outcome = finish_phases(phases, &close_control).await;
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
) -> CloseOutcome {
    match AssertUnwindSafe(phases).catch_unwind().await {
        Ok(Ok(outcome) | Err(outcome)) => outcome,
        Err(_) => {
            let _ = SockRef::from(close_control).shutdown(Shutdown::Both);
            release_deferred();
            tracing::error!("connection task panicked");
            CloseOutcome::InternalError
        }
    }
}

fn phase_remaining(started_at: Instant, duration: Duration) -> Duration {
    started_at
        .checked_add(duration)
        .map_or(Duration::ZERO, |deadline| {
            deadline.saturating_duration_since(Instant::now())
        })
}

/// Shuts the socket down on timeout so a phase blocked on I/O observes the end.
async fn run_phase<T>(
    close_control: &TcpStream,
    remaining: Duration,
    timeout_outcome: CloseOutcome,
    phase: impl Future<Output = Result<T, CloseOutcome>>,
) -> Result<T, CloseOutcome> {
    match timeout(remaining, phase).await {
        Ok(result) => result,
        Err(_) => {
            let _ = SockRef::from(close_control).shutdown(Shutdown::Both);
            Err(timeout_outcome)
        }
    }
}

#[cfg(test)]
#[path = "../tests/stream.rs"]
mod tests;
