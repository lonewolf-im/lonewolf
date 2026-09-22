// SPDX-License-Identifier: Apache-2.0

use std::future::pending;
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::time::Duration;

use compio::net::{TcpListener, TcpSocket, TcpStream};
use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Either, Shared, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
use lonewolf_util::core_dispatcher::{DispatchHandle, Task, WorkerContext};
use nix::errno::Errno;
use socket2::SockRef;

use crate::config::C2sConfig;

const BACKLOG: i32 = 128;
const ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);

type Stop = Shared<BoxFuture<'static, ()>>;

pub(crate) struct Listeners {
    stop: Option<oneshot::Sender<()>>,
    tasks: FuturesUnordered<Task<io::Result<()>>>,
}

impl Listeners {
    pub(crate) async fn start(config: &C2sConfig, dispatcher: &DispatchHandle) -> io::Result<Self> {
        let (stop, stopped) = oneshot::channel();
        let stopped = async move {
            let _ = stopped.await;
        }
        .boxed()
        .shared();
        let listeners = Self {
            stop: Some(stop),
            tasks: FuturesUnordered::new(),
        };
        for (listener_id, config) in config.listeners.iter().enumerate() {
            let mut address = config.address;
            for worker_id in 0..dispatcher.worker_count() {
                let (ready, readiness) = oneshot::channel();
                let stop = stopped.clone();
                let task = dispatcher
                    .dispatch_at(worker_id, move |context| async move {
                        let result = async {
                            let listener = bind(address).await?;
                            let bound = listener.local_addr()?;
                            if ready.send(bound).is_err() {
                                return Ok(());
                            }
                            run_listener(listener, context, stop, listener_id).await
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

async fn run_listener(
    listener: TcpListener,
    context: WorkerContext,
    stop: Stop,
    listener_id: usize,
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
    let result = loop {
        match select(shutdown.as_mut(), pin!(listener.accept())).await {
            Either::Left(_) => break Ok(()),
            Either::Right((Ok((stream, _)), _)) => {
                close_unhandled_connection(stream);
                tracing::trace!(
                    listener_id,
                    worker_id,
                    outcome = "no_session_handler",
                    "c2s connection closed"
                );
            }
            Either::Right((Err(error), _)) => {
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
    let closed = listener.close().await;
    tracing::debug!(listener_id, worker_id, "c2s TCP worker listener stopped");
    result.and(closed)
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
#[path = "../tests/c2s/listeners.rs"]
mod tests;
