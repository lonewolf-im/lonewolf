// SPDX-License-Identifier: Apache-2.0

use std::future::pending;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use compio::net::{TcpListener, TcpSocket, TcpStream};
use futures_channel::oneshot;
use futures_util::FutureExt as _;
use futures_util::future::{BoxFuture, Either, LocalBoxFuture, Shared, select};
use futures_util::stream::{FuturesUnordered, StreamExt as _};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_util::core_dispatcher::{DispatchHandle, Task, WorkerContext};
use nix::errno::Errno;
use parking_lot::Mutex as PlMutex;
use socket2::SockRef;

use super::metrics::{ConnectionRejection, Direction, S2sMetrics};
use super::stream::S2sReaderLimits;
use crate::admission::attempt_limit::{Admission, AttemptLimiter};
use crate::admission::connection_limit::{
    ConnectionAdmission, ConnectionLimiter, ConnectionPermit,
};
use crate::admission::rejection_report::RejectionReport;
use crate::c2s::StartError;
use crate::config::S2sConfig;
use crate::config::limits::S2sLimits;
use crate::hosts::{Hosts, peer_identity::PeerTrust};

mod negotiate;

static NEXT_S2S_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
type Stop = Shared<BoxFuture<'static, Instant>>;
type ShutdownSignal = Shared<LocalBoxFuture<'static, Instant>>;

#[derive(Clone)]
struct Settings<A: ChunkAllocator> {
    hosts: Hosts,
    trust: Arc<PeerTrust>,
    reader_limits: S2sReaderLimits,
    timeout: Duration,
    allocator: A,
    metrics: Arc<S2sMetrics>,
}

struct GlobalLimit {
    active: AtomicUsize,
    max: usize,
    report: PlMutex<RejectionReport>,
}

struct GlobalPermit(Arc<GlobalLimit>);

struct ConnectionSocket(TcpStream);

impl Drop for ConnectionSocket {
    fn drop(&mut self) {
        let _ = SockRef::from(&self.0).shutdown(std::net::Shutdown::Both);
    }
}

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

pub(crate) struct S2sListeners {
    stop: Option<oneshot::Sender<Instant>>,
    tasks: FuturesUnordered<Task<io::Result<()>>>,
    failures: async_channel::Receiver<io::Error>,
    addresses: Vec<SocketAddr>,
}

impl S2sListeners {
    pub(crate) async fn start<A: ChunkAllocator + Clone>(
        config: &S2sConfig,
        limits: &S2sLimits,
        hosts: Hosts,
        trust: Arc<PeerTrust>,
        dispatcher: &DispatchHandle,
        allocator: A,
        metrics: Arc<S2sMetrics>,
    ) -> Result<Self, StartError> {
        let (stop, stopped) = oneshot::channel();
        let stopped = async move {
            stopped
                .await
                .unwrap_or_else(|_| Instant::now() + crate::WORKER_SHUTDOWN_GRACE)
        }
        .boxed()
        .shared();
        let (report_failure, failures) = async_channel::bounded(1);
        let mut listeners = Self {
            stop: Some(stop),
            tasks: FuturesUnordered::new(),
            failures,
            addresses: Vec::with_capacity(config.listeners.len()),
        };
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
            hosts,
            trust,
            reader_limits: S2sReaderLimits {
                max_stanza_bytes: limits.max_stanza_bytes,
                stanzas: limits.incoming_stanzas_per_connection.clone(),
                xml: limits.incoming_xml_per_connection.clone(),
            },
            timeout: Duration::from_secs(limits.negotiation_timeout_secs.get()),
            allocator,
            metrics,
        };
        let started: io::Result<()> = async {
            for (listener_id, config) in config.listeners.iter().enumerate() {
                let mut address = config.address;
                for worker_id in 0..dispatcher.worker_count() {
                    let (ready, readiness) = oneshot::channel();
                    let stop = stopped.clone();
                    let report_failure = report_failure.clone();
                    let admission = Arc::clone(&admission);
                    let settings = settings.clone();
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
                                    report_failure,
                                    listener_id,
                                    admission,
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
                                "s2s listener stopped before reporting readiness",
                            ));
                        }
                    }
                    listeners.tasks.push(task);
                }
                listeners.addresses.push(address);
                tracing::info!(
                    listener_id,
                    worker_count = dispatcher.worker_count(),
                    port = address.port(),
                    "s2s TCP listener started"
                );
            }
            Ok(())
        }
        .await;
        if let Err(error) = started {
            let deadline = Instant::now() + crate::WORKER_SHUTDOWN_GRACE;
            listeners.stop(deadline);
            let _ = compio::time::timeout_at(deadline, listeners.join()).await;
            return Err(StartError { error, deadline });
        }
        Ok(listeners)
    }

    pub(crate) fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    pub(crate) fn stop(&mut self, deadline: Instant) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(deadline);
        }
    }

    pub(crate) async fn failure(&mut self) -> io::Error {
        let task = match select(pin!(self.failures.recv()), pin!(self.tasks.next())).await {
            Either::Left((Ok(error), _)) => return error,
            Either::Left((Err(_), _)) => self.tasks.next().await,
            Either::Right((task, _)) => task,
        };
        match task {
            Some(Ok(Err(error))) => error,
            Some(Err(error)) => io::Error::other(error),
            Some(Ok(Ok(()))) => io::Error::other("s2s listener stopped unexpectedly"),
            None => pending().await,
        }
    }

    pub(crate) async fn join(&mut self) -> io::Result<()> {
        let mut result = Ok(());
        while let Some(task) = self.tasks.next().await {
            result = result.and(task.map_err(io::Error::other).and_then(|result| result));
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
    socket.listen(128).await
}

async fn run_listener<A: ChunkAllocator + Clone>(
    listener: TcpListener,
    context: WorkerContext,
    stop: Stop,
    report_failure: async_channel::Sender<io::Error>,
    listener_id: usize,
    admission: Arc<AdmissionLimits>,
    settings: Settings<A>,
) -> io::Result<()> {
    let worker_id = context.worker.index;
    let shutdown = async move {
        match select(pin!(context.shutdown_requested()), pin!(stop)).await {
            Either::Left((deadline, _)) | Either::Right((deadline, _)) => deadline,
        }
    }
    .boxed_local()
    .shared();
    let mut active = FuturesUnordered::new();
    let mut accept = Box::pin(listener.accept());
    let result = loop {
        let next = async {
            if active.is_empty() {
                Some(accept.as_mut().await)
            } else {
                match select(pin!(active.next()), accept.as_mut()).await {
                    Either::Left(_) => None,
                    Either::Right((accepted, _)) => Some(accepted),
                }
            }
        };
        let accepted = match select(pin!(shutdown.clone()), pin!(next)).await {
            Either::Left(_) => break Ok(()),
            Either::Right((None, _)) => continue,
            Either::Right((Some(accepted), _)) => accepted,
        };
        accept.as_mut().set(listener.accept());
        match accepted {
            Ok((tcp, peer)) => {
                let permits = match admission.reserve(peer.ip()).await {
                    Ok(permits) => permits,
                    Err(rejection) => {
                        settings
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
                        drop(tcp);
                        continue;
                    }
                };
                if let Err(error) = tcp.set_nodelay(true) {
                    break Err(error);
                }
                settings.metrics.connection_accepted(listener_id);
                let gauge = settings.metrics.connection_opened(Direction::Inbound);
                let settings = settings.clone();
                let shutdown = shutdown.clone();
                let tcp = ConnectionSocket(tcp);
                active.push(async move {
                    let _permits = permits;
                    let _gauge = gauge;
                    let connection_id = NEXT_S2S_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
                    let started = Instant::now();
                    let outcome = match negotiate::negotiate(&tcp.0, &settings, shutdown.clone(), connection_id).await {
                        Ok(authenticated) => negotiate::serve(authenticated, &tcp.0, shutdown).await,
                        Err(super::stream::S2sError::PeerError(condition)) => {
                            tracing::debug!(connection_id, condition = ?condition, "s2s peer stream error");
                            "peer_error"
                        }
                        Err(_) => "negotiation_failed",
                    };
                    tracing::info!(connection_id, outcome, duration_ms = started.elapsed().as_millis() as u64, "s2s stream disconnected");
                });
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                ) => {}
            Err(error) if resource_exhausted(&error) => {
                tracing::warn!(listener_id, worker_id, error_kind = ?error.kind(), "s2s accept delayed by resource exhaustion");
                if matches!(
                    select(
                        pin!(shutdown.clone()),
                        pin!(compio::time::sleep(Duration::from_secs(1)))
                    )
                    .await,
                    Either::Left(_)
                ) {
                    break Ok(());
                }
            }
            Err(error) => break Err(error),
        }
    };
    drop(accept);
    if let Err(error) = &result {
        let _ = report_failure.try_send(io::Error::new(error.kind(), error.to_string()));
    }
    let deadline = shutdown.await;
    let drained =
        compio::time::timeout_at(deadline, async { while active.next().await.is_some() {} }).await;
    result.and(
        drained.map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "s2s listener shutdown timed out")
        }),
    )
}

fn listener_error(listener_id: usize, worker_id: usize, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("listener {listener_id} on worker {worker_id}: {error}"),
    )
}

fn resource_exhausted(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::OutOfMemory
        || matches!(
            error.raw_os_error().map(Errno::from_raw),
            Some(Errno::EMFILE | Errno::ENFILE | Errno::ENOBUFS | Errno::ENOMEM)
        )
}

#[cfg(test)]
mod tests {
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
