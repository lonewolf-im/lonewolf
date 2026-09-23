// SPDX-License-Identifier: Apache-2.0

use std::future::pending;
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use compio::net::{TcpListener, TcpSocket, TcpStream};
use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Either, Shared, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_util::core_dispatcher::{DispatchHandle, Task, WorkerContext};
use nix::errno::Errno;
use socket2::SockRef;

use crate::config::C2sConfig;
use crate::config::limits::C2sLimits;
use crate::hosts::Hosts;

mod attempt_limit;
mod connection_limit;
mod stream;
mod unauthenticated_limit;

use attempt_limit::{Admission, AttemptLimiter};
use connection_limit::{ConnectionAdmission, ConnectionLimiter};
use stream::{StreamSettings, XmppStream};
use unauthenticated_limit::{Admission as UnauthenticatedAdmission, UnauthenticatedLimiter};

const BACKLOG: i32 = 128;
const ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);

type Stop = Shared<BoxFuture<'static, ()>>;

#[derive(Clone)]
struct AdmissionLimits {
    attempts: Arc<AttemptLimiter>,
    connections: Arc<ConnectionLimiter>,
    unauthenticated: Arc<UnauthenticatedLimiter>,
}

pub(crate) struct Listeners {
    stop: Option<oneshot::Sender<()>>,
    tasks: FuturesUnordered<Task<io::Result<()>>>,
    listener_count: usize,
    worker_count: usize,
}

impl Listeners {
    pub(crate) async fn start<A: ChunkAllocator + Clone>(
        config: &C2sConfig,
        limits: &C2sLimits,
        hosts: Arc<Hosts>,
        dispatcher: &DispatchHandle,
        allocator: A,
    ) -> io::Result<Self> {
        let (stop, stopped) = oneshot::channel();
        let stopped = async move {
            let _ = stopped.await;
        }
        .boxed()
        .shared();
        let unauthenticated = Arc::new(UnauthenticatedLimiter::new(
            limits.max_unauthenticated_connections,
        ));
        let listeners = Self {
            stop: Some(stop),
            tasks: FuturesUnordered::new(),
            listener_count: config.listeners.len(),
            worker_count: dispatcher.worker_count(),
        };
        for (listener_id, config) in config.listeners.iter().enumerate() {
            let profile_name = config.limits.as_deref().unwrap_or(&limits.default);
            let profile = limits.profiles.get(profile_name).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("c2s listener {listener_id} references unknown limit profile {profile_name:?}"),
                )
            })?;
            let admission = AdmissionLimits {
                attempts: Arc::new(AttemptLimiter::new(&profile.connection_attempts_per_ip)),
                connections: Arc::new(ConnectionLimiter::new(profile.max_connections_per_ip.get())),
                unauthenticated: Arc::clone(&unauthenticated),
            };
            let max_stanza_bytes = profile.max_stanza_bytes;
            let xml_rate = &profile.incoming_xml_per_connection;
            let mut address = config.address;
            for worker_id in 0..dispatcher.worker_count() {
                let (ready, readiness) = oneshot::channel();
                let stop = stopped.clone();
                let admission = admission.clone();
                let hosts = Arc::clone(&hosts);
                let settings = StreamSettings::new(max_stanza_bytes, xml_rate, allocator.clone());
                let task = dispatcher
                    .dispatch_at(worker_id, move |context| async move {
                        let result = async {
                            let listener = bind(address).await?;
                            let bound = listener.local_addr()?;
                            if ready.send(bound).is_err() {
                                return Ok(());
                            }
                            run_listener(
                                listener,
                                context,
                                stop,
                                listener_id,
                                admission,
                                hosts,
                                settings,
                            )
                            .await
                        }
                        .await;
                        result.map_err(|error| listener_error(listener_id, worker_id, error))
                    })
                    .await
                    .map_err(|error| listener_error(listener_id, worker_id, error))?;
                match readiness.await {
                    Ok(bound) => address = bound,
                    Err(_) => {
                        task.await.map_err(io::Error::other)??;
                        return Err(io::Error::other(
                            "c2s listener stopped before reporting readiness",
                        ));
                    }
                }
                listeners.tasks.push(task);
            }
            tracing::info!(
                listener_id,
                worker_count = dispatcher.worker_count(),
                port = address.port(),
                "c2s TCP listener started"
            );
        }
        Ok(listeners)
    }

    pub(crate) fn stop(&mut self) {
        self.stop.take();
    }

    pub(crate) async fn failure(&mut self) -> io::Error {
        match self.tasks.next().await {
            Some(Ok(Err(error))) => error,
            Some(Err(error)) => io::Error::other(error),
            Some(Ok(Ok(()))) => io::Error::other("c2s listener stopped unexpectedly"),
            None => pending().await,
        }
    }

    pub(crate) async fn join(&mut self) -> io::Result<()> {
        let mut result = Ok(());
        while let Some(task) = self.tasks.next().await {
            result = result.and(task.map_err(io::Error::other).and_then(|result| result));
        }
        for listener_id in 0..std::mem::take(&mut self.listener_count) {
            tracing::info!(
                listener_id,
                worker_count = self.worker_count,
                "c2s TCP listener stopped"
            );
        }
        result
    }
}

async fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4().await?
    } else {
        let socket = TcpSocket::new_v6().await?;
        SockRef::from(&socket).set_only_v6(true)?;
        socket
    };
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.bind(address).await?;
    socket.listen(BACKLOG).await
}

async fn run_listener<A: ChunkAllocator + Clone>(
    listener: TcpListener,
    context: WorkerContext,
    stop: Stop,
    listener_id: usize,
    admission: AdmissionLimits,
    hosts: Arc<Hosts>,
    settings: StreamSettings<A>,
) -> io::Result<()> {
    let worker_id = context.worker.index;
    tracing::debug!(
        listener_id,
        worker_id,
        port = listener.local_addr()?.port(),
        "c2s TCP worker listener started"
    );
    let shutdown = async {
        select(pin!(context.shutdown_requested()), pin!(stop)).await;
    };
    let mut shutdown = pin!(shutdown);
    let mut active = FuturesUnordered::new();
    let mut accept = Box::pin(listener.accept());
    let result = loop {
        let next = async {
            if active.is_empty() {
                ListenerEvent::Accepted(accept.as_mut().await)
            } else {
                match select(pin!(active.next()), accept.as_mut()).await {
                    Either::Left((result, _)) => ListenerEvent::Closed(result),
                    Either::Right((result, _)) => ListenerEvent::Accepted(result),
                }
            }
        };
        let event = match select(shutdown.as_mut(), pin!(next)).await {
            Either::Left(_) => break Ok(()),
            Either::Right((event, _)) => event,
        };
        match event {
            ListenerEvent::Accepted(Ok((stream, peer))) => {
                accept.as_mut().set(listener.accept());
                match admission.attempts.admit(peer.ip(), Instant::now()).await {
                    Admission::Allowed => {
                        match admission.unauthenticated.reserve(Instant::now()).await {
                            UnauthenticatedAdmission::Allowed(unauthenticated_permit) => {
                                match admission
                                    .connections
                                    .reserve(peer.ip(), Instant::now())
                                    .await
                                {
                                    ConnectionAdmission::Allowed(ip_permit) => {
                                        active.push(
                                            XmppStream::new(
                                                stream,
                                                ip_permit,
                                                unauthenticated_permit,
                                                Arc::clone(&hosts),
                                                settings.clone(),
                                            )
                                            .run(),
                                        );
                                    }
                                    ConnectionAdmission::Denied {
                                        outcome,
                                        report_count,
                                    } => {
                                        close_unhandled_connection(stream);
                                        if let Some(rejected_connections) = report_count {
                                            tracing::warn!(
                                                listener_id,
                                                worker_id,
                                                outcome,
                                                rejected_connections,
                                                "c2s connection rejected"
                                            );
                                        }
                                    }
                                }
                            }
                            UnauthenticatedAdmission::Denied { report_count } => {
                                close_unhandled_connection(stream);
                                if let Some(rejected_connections) = report_count {
                                    tracing::warn!(
                                        outcome = "unauthenticated_connection_limit",
                                        rejected_connections,
                                        "c2s connection rejected"
                                    );
                                }
                            }
                        }
                    }
                    Admission::Denied {
                        outcome,
                        report_count,
                    } => {
                        close_unhandled_connection(stream);
                        if let Some(rejected_attempts) = report_count {
                            tracing::warn!(
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
            ListenerEvent::Closed(Some(outcome)) => {
                tracing::trace!(
                    listener_id,
                    worker_id,
                    outcome = outcome.as_str(),
                    "c2s connection closed"
                );
            }
            ListenerEvent::Closed(None) => {}
            ListenerEvent::Accepted(Err(error)) => {
                accept.as_mut().set(listener.accept());
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                ) {
                    continue;
                }
                if resource_exhausted(&error) {
                    tracing::warn!(
                        listener_id,
                        worker_id,
                        error_kind = ?error.kind(),
                        "c2s accept delayed by resource exhaustion"
                    );
                    if let Either::Left(_) = select(
                        shutdown.as_mut(),
                        pin!(compio::time::sleep(ACCEPT_RETRY_DELAY)),
                    )
                    .await
                    {
                        break Ok(());
                    }
                } else {
                    break Err(error);
                }
            }
        }
    };
    drop(accept);
    drop(active);
    let closed = listener.close().await;
    tracing::debug!(listener_id, worker_id, "c2s TCP worker listener stopped");
    result.and(closed)
}

enum ListenerEvent {
    Accepted(io::Result<(TcpStream, SocketAddr)>),
    Closed(Option<stream::CloseOutcome>),
}

fn close_unhandled_connection(stream: TcpStream) {
    drop(stream);
}

fn resource_exhausted(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::OutOfMemory
        || matches!(
            error.raw_os_error().map(Errno::from_raw),
            Some(Errno::EMFILE | Errno::ENFILE | Errno::ENOBUFS | Errno::ENOMEM)
        )
}

fn listener_error(listener_id: usize, worker_id: usize, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("listener {listener_id} on worker {worker_id}: {error}"),
    )
}

#[cfg(test)]
#[path = "../../tests/c2s/listeners.rs"]
mod tests;
