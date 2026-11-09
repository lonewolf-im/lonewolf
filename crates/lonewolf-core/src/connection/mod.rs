// SPDX-License-Identifier: Apache-2.0

use std::future::{Future, pending};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::pin;
use std::time::{Duration, Instant};

use compio::net::{TcpListener, TcpSocket, TcpStream};
use futures_channel::oneshot;
use futures_util::FutureExt as _;
use futures_util::future::{BoxFuture, Either, LocalBoxFuture, Shared, select};
use futures_util::stream::{FuturesUnordered, StreamExt as _};
use lonewolf_util::core_dispatcher::{DispatchHandle, Task, WorkerContext};
use nix::errno::Errno;
use socket2::SockRef;

pub(crate) mod socket;
use socket::{ConnectionSocket, ConnectionTask};

const BACKLOG: i32 = 128;
const ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);
type Stop = Shared<BoxFuture<'static, Instant>>;
pub(crate) type ShutdownSignal = Shared<LocalBoxFuture<'static, Instant>>;

pub(crate) struct ListenerControl {
    pub(crate) stop: Stop,
    pub(crate) report_failure: async_channel::Sender<io::Error>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ListenerKind {
    C2s,
    S2s,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ListenerSlot {
    pub(crate) listener_id: usize,
    pub(crate) worker_id: usize,
}

pub(crate) trait AcceptHandler: 'static {
    type Permit: 'static;
    type Rejection;
    async fn admit(&self, peer: IpAddr) -> Result<Self::Permit, Self::Rejection>;
    fn rejected(&self, slot: ListenerSlot, rejection: Self::Rejection);
    fn serve(
        &self,
        slot: ListenerSlot,
        socket: TcpStream,
        permit: Self::Permit,
        shutdown: ShutdownSignal,
    ) -> impl Future<Output = ()> + 'static;
    fn active_connections(&self, _count: usize) {}
}

pub(crate) struct ListenerSpec<F> {
    pub(crate) address: SocketAddr,
    pub(crate) handler: F,
}

#[derive(Debug)]
pub(crate) struct StartError {
    pub(crate) error: io::Error,
    pub(crate) deadline: Instant,
}

impl std::fmt::Display for StartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

pub(crate) struct ListenerSet {
    kind: ListenerKind,
    stop: Option<oneshot::Sender<Instant>>,
    tasks: FuturesUnordered<Task<io::Result<()>>>,
    failures: async_channel::Receiver<io::Error>,
    addresses: Vec<SocketAddr>,
    listener_count: usize,
    worker_count: usize,
}

impl ListenerSet {
    pub(crate) async fn start<F, H>(
        kind: ListenerKind,
        dispatcher: &DispatchHandle,
        specs: Vec<ListenerSpec<F>>,
    ) -> Result<Self, StartError>
    where
        F: FnMut(ListenerSlot) -> H,
        H: AcceptHandler + Send,
    {
        let (stop, stopped) = oneshot::channel();
        let (report_failure, failures) = async_channel::bounded(1);
        let stopped = async move {
            stopped
                .await
                .unwrap_or_else(|_| Instant::now() + crate::WORKER_SHUTDOWN_GRACE)
        }
        .boxed()
        .shared();
        let mut listeners = Self {
            kind,
            stop: Some(stop),
            tasks: FuturesUnordered::new(),
            failures,
            addresses: Vec::with_capacity(specs.len()),
            listener_count: specs.len(),
            worker_count: dispatcher.worker_count(),
        };
        let started: io::Result<()> = async {
            for (listener_id, mut spec) in specs.into_iter().enumerate() {
                let mut address = spec.address;
                for worker_id in 0..dispatcher.worker_count() {
                    let (ready, readiness) = oneshot::channel();
                    let control = ListenerControl {
                        stop: stopped.clone(),
                        report_failure: report_failure.clone(),
                    };
                    let handler = (spec.handler)(ListenerSlot {
                        listener_id,
                        worker_id,
                    });
                    let task = dispatcher
                        .dispatch_at(worker_id, move |context| async move {
                            let result = async {
                                let listener = bind(address).await?;
                                let bound = listener.local_addr()?;
                                if ready.send(bound).is_err() {
                                    return Ok(());
                                }
                                run_listener(listener, context, control, kind, listener_id, handler)
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
                            return Err(io::Error::other(match kind {
                                ListenerKind::C2s => {
                                    "c2s listener stopped before reporting readiness"
                                }
                                ListenerKind::S2s => {
                                    "s2s listener stopped before reporting readiness"
                                }
                            }));
                        }
                    }
                    listeners.tasks.push(task);
                }
                match kind {
                    ListenerKind::C2s => tracing::info!(
                        listener_id,
                        worker_count = dispatcher.worker_count(),
                        port = address.port(),
                        "c2s TCP listener started"
                    ),
                    ListenerKind::S2s => tracing::info!(
                        listener_id,
                        worker_count = dispatcher.worker_count(),
                        port = address.port(),
                        "s2s TCP listener started"
                    ),
                }
                listeners.addresses.push(address);
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
    /// Bound addresses in configuration order.
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
            Some(Ok(Ok(()))) => io::Error::other(match self.kind {
                ListenerKind::C2s => "c2s listener stopped unexpectedly",
                ListenerKind::S2s => "s2s listener stopped unexpectedly",
            }),
            None => pending().await,
        }
    }

    pub(crate) async fn join(&mut self) -> io::Result<()> {
        let mut result = Ok(());
        while let Some(task) = self.tasks.next().await {
            result = result.and(task.map_err(io::Error::other).and_then(|result| result));
        }
        for listener_id in 0..std::mem::take(&mut self.listener_count) {
            match self.kind {
                ListenerKind::C2s => tracing::info!(
                    listener_id,
                    worker_count = self.worker_count,
                    "c2s TCP listener stopped"
                ),
                ListenerKind::S2s => tracing::info!(
                    listener_id,
                    worker_count = self.worker_count,
                    "s2s TCP listener stopped"
                ),
            }
        }
        result
    }
    #[cfg(test)]
    pub(crate) fn with_test_channels(
        kind: ListenerKind,
        stop: oneshot::Sender<Instant>,
        failures: async_channel::Receiver<io::Error>,
        worker_count: usize,
    ) -> Self {
        Self {
            kind,
            stop: Some(stop),
            tasks: FuturesUnordered::new(),
            failures,
            addresses: Vec::new(),
            listener_count: 0,
            worker_count,
        }
    }
    #[cfg(test)]
    pub(crate) fn test_tasks(&mut self) -> &mut FuturesUnordered<Task<io::Result<()>>> {
        &mut self.tasks
    }
}
pub(crate) async fn bind(address: SocketAddr) -> io::Result<TcpListener> {
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

pub(crate) async fn run_listener<H: AcceptHandler>(
    listener: TcpListener,
    context: WorkerContext,
    control: ListenerControl,
    kind: ListenerKind,
    listener_id: usize,
    handler: H,
) -> io::Result<()> {
    let worker_id = context.worker.index;
    let result = run_listener_with_accept(
        &listener,
        context,
        control,
        kind,
        listener_id,
        handler,
        || listener.accept(),
    )
    .await;
    let closed = listener.close().await;
    match kind {
        ListenerKind::C2s => {
            tracing::debug!(listener_id, worker_id, "c2s TCP worker listener stopped")
        }
        ListenerKind::S2s => {
            tracing::debug!(listener_id, worker_id, "s2s TCP worker listener stopped")
        }
    }
    result.and(closed)
}

async fn run_listener_with_accept<H, F>(
    listener: &TcpListener,
    context: WorkerContext,
    control: ListenerControl,
    kind: ListenerKind,
    listener_id: usize,
    handler: H,
    mut accept_next: impl FnMut() -> F,
) -> io::Result<()>
where
    H: AcceptHandler,
    F: Future<Output = io::Result<(TcpStream, SocketAddr)>>,
{
    let ListenerControl {
        stop,
        report_failure,
    } = control;
    let worker_id = context.worker.index;
    let slot = ListenerSlot {
        listener_id,
        worker_id,
    };
    match kind {
        ListenerKind::C2s => tracing::debug!(
            listener_id,
            worker_id,
            port = listener.local_addr()?.port(),
            "c2s TCP worker listener started"
        ),
        ListenerKind::S2s => tracing::debug!(
            listener_id,
            worker_id,
            port = listener.local_addr()?.port(),
            "s2s TCP worker listener started"
        ),
    }
    let shutdown = async move {
        match select(pin!(context.shutdown_requested()), pin!(stop)).await {
            Either::Left((deadline, _)) | Either::Right((deadline, _)) => deadline,
        }
    }
    .boxed_local()
    .shared();
    let mut shutdown_wait = Box::pin(shutdown.clone());
    let mut active = FuturesUnordered::new();
    let mut accept = Box::pin(accept_next());
    let result = loop {
        let next = async {
            if active.is_empty() {
                ListenerEvent::Accepted(accept.as_mut().await)
            } else {
                match select(pin!(active.next()), accept.as_mut()).await {
                    Either::Left((_, _)) => ListenerEvent::Closed,
                    Either::Right((result, _)) => ListenerEvent::Accepted(result),
                }
            }
        };
        let event = match select(shutdown_wait.as_mut(), pin!(next)).await {
            Either::Left(_) => break Ok(()),
            Either::Right((event, _)) => event,
        };
        match event {
            ListenerEvent::Accepted(Ok((stream, peer))) => {
                accept.as_mut().set(accept_next());
                if let Err(error) = stream.set_nodelay(true) {
                    drop(stream);
                    break Err(error);
                }
                match handler.admit(peer.ip()).await {
                    Ok(permit) => {
                        let owner = ConnectionSocket(stream.clone());
                        active.push(ConnectionTask {
                            _socket: owner,
                            future: Box::pin(handler.serve(slot, stream, permit, shutdown.clone())),
                        });
                        handler.active_connections(active.len());
                    }
                    Err(rejection) => {
                        drop(stream);
                        handler.rejected(slot, rejection);
                    }
                }
            }
            ListenerEvent::Closed => handler.active_connections(active.len()),
            ListenerEvent::Accepted(Err(error)) => {
                accept.as_mut().set(accept_next());
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                ) {
                    continue;
                }
                if resource_exhausted(&error) {
                    match kind {
                        ListenerKind::C2s => {
                            tracing::warn!(listener_id, worker_id, error_kind = ?error.kind(), "c2s accept delayed by resource exhaustion")
                        }
                        ListenerKind::S2s => {
                            tracing::warn!(listener_id, worker_id, error_kind = ?error.kind(), "s2s accept delayed by resource exhaustion")
                        }
                    }
                    if let Either::Left(_) = select(
                        shutdown_wait.as_mut(),
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
    if let Err(error) = &result {
        let _ = report_failure.try_send(io::Error::new(error.kind(), error.to_string()));
    }
    let deadline = shutdown.await;
    let drained = drain_connections(active, deadline, kind, |count| {
        handler.active_connections(count)
    })
    .await;
    handler.active_connections(0);
    result.and(drained)
}

pub(crate) async fn drain_connections<F: Future<Output = ()>, S: Unpin>(
    mut active: FuturesUnordered<ConnectionTask<F, S>>,
    deadline: Instant,
    kind: ListenerKind,
    mut closed: impl FnMut(usize),
) -> io::Result<()> {
    compio::time::timeout_at(deadline, async {
        while active.next().await.is_some() {
            closed(active.len());
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            match kind {
                ListenerKind::C2s => "c2s connections exceeded shutdown deadline",
                ListenerKind::S2s => "s2s listener shutdown timed out",
            },
        )
    })
}

enum ListenerEvent {
    Accepted(io::Result<(TcpStream, SocketAddr)>),
    Closed,
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
mod tests;
