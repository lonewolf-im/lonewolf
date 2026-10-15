// SPDX-License-Identifier: Apache-2.0

use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use compio::net::{TcpListener, TcpSocket, TcpStream};
use compio::time::sleep_until;
use compio_io::compat::AsyncStream;
use futures_util::stream::{FuturesUnordered, Stream, StreamExt};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use prometheus_client::registry::Registry;
use socket2::SockRef;
use tokio_util::compat::FuturesAsyncReadCompatExt;

const BACKLOG: i32 = 128;
const MAX_CONNECTIONS: usize = 16;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);
const OPENMETRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

pub struct MetricsServer {
    listener: TcpListener,
    port: u16,
}

impl MetricsServer {
    /// IPv6 addresses accept IPv6 only. Fails if another socket listens on the address.
    pub async fn bind(address: SocketAddr) -> io::Result<Self> {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4().await?
        } else {
            let socket = TcpSocket::new_v6().await?;
            SockRef::from(&socket).set_only_v6(true)?;
            socket
        };
        socket.set_reuseaddr(true)?;
        socket.bind(address).await?;
        let listener = socket.listen(BACKLOG).await?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serves `/metrics` until `shutdown` completes, then drains accepted connections.
    ///
    /// Accept failures are logged and retried; they do not end the service.
    pub async fn run(self, registry: Arc<Registry>, shutdown: impl Future<Output = ()>) {
        tracing::info!(port = self.port, "metrics service started");
        let router = router(registry);
        let mut connections = accept_connections(
            || self.listener.accept(),
            |(stream, _), deadline| serve_connection(stream, router.clone(), deadline),
            shutdown,
            CONNECTION_TIMEOUT,
            ACCEPT_RETRY_DELAY,
        )
        .await;
        drop(self.listener);
        while connections.next().await.is_some() {}
        tracing::info!("metrics service stopped");
    }
}

async fn accept_connections<T, A, AF, S, C>(
    mut next_accept: A,
    mut serve: S,
    shutdown: impl Future<Output = ()>,
    connection_timeout: Duration,
    retry_delay: Duration,
) -> FuturesUnordered<C>
where
    A: FnMut() -> AF,
    AF: Future<Output = io::Result<T>>,
    S: FnMut(T, Instant) -> C,
    C: Future<Output = ()>,
{
    let mut shutdown = pin!(shutdown);
    let mut connections = FuturesUnordered::new();
    // Cancelling a pending accept can discard a new connection.
    let mut accept = pin!(next_accept());
    let mut retry = pin!(sleep_until(Instant::now()));
    let mut retrying = false;
    poll_fn(|context| {
        if shutdown.as_mut().poll(context).is_ready() {
            return Poll::Ready(());
        }
        while let Poll::Ready(Some(())) = Pin::new(&mut connections).poll_next(context) {}
        if shutdown.as_mut().poll(context).is_ready() {
            return Poll::Ready(());
        }
        if retrying {
            if retry.as_mut().poll(context).is_pending() {
                return Poll::Pending;
            }
            retrying = false;
        }
        if connections.len() < MAX_CONNECTIONS
            && let Poll::Ready(result) = accept.as_mut().poll(context)
        {
            let deadline = Instant::now() + connection_timeout;
            accept.set(next_accept());
            match result {
                Ok(accepted) => connections.push(serve(accepted, deadline)),
                Err(error) => match error.kind() {
                    io::ErrorKind::Interrupted
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset => {}
                    _ => {
                        tracing::warn!(error_kind = ?error.kind(), "metrics accept failed");
                        retry.set(sleep_until(Instant::now() + retry_delay));
                        retrying = true;
                    }
                },
            }
            context.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await;
    connections
}

struct Scrape {
    registry: Arc<Registry>,
    buffer: async_lock::Mutex<String>,
}

fn router(registry: Arc<Registry>) -> Router {
    Router::new()
        .route("/metrics", get(scrape))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .method_not_allowed_fallback(|| async { StatusCode::METHOD_NOT_ALLOWED })
        .with_state(Arc::new(Scrape {
            registry,
            buffer: async_lock::Mutex::new(String::new()),
        }))
}

async fn scrape(State(scrape): State<Arc<Scrape>>) -> Response {
    let mut buffer = scrape.buffer.lock().await;
    buffer.clear();
    if prometheus_client::encoding::text::encode(&mut *buffer, &scrape.registry).is_err() {
        tracing::error!(outcome = "encode_failed", "metrics scrape failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    tracing::debug!(bytes = buffer.len(), "metrics scrape served");
    (
        [
            (CONTENT_TYPE, OPENMETRICS_CONTENT_TYPE),
            (CACHE_CONTROL, "no-store"),
        ],
        Bytes::copy_from_slice(buffer.as_bytes()),
    )
        .into_response()
}

async fn serve_connection(stream: TcpStream, router: Router, deadline: Instant) {
    let io = TokioIo::new(Box::pin(AsyncStream::with_limits(4096, 16384, stream)).compat());
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(false)
        .max_buf_size(16384)
        .max_headers(32);
    let connection = builder.serve_connection(io, TowerToHyperService::new(router));
    match until_deadline(deadline, connection).await {
        Some(Ok(())) => {}
        Some(Err(_)) => tracing::debug!(outcome = "connection_failed", "metrics connection closed"),
        None => tracing::debug!(outcome = "timeout", "metrics connection deadline exceeded"),
    }
}

async fn until_deadline<F: Future>(deadline: Instant, future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    let mut timer = pin!(sleep_until(deadline));
    poll_fn(|context| {
        if Instant::now() >= deadline || timer.as_mut().poll(context).is_ready() {
            Poll::Ready(None)
        } else {
            future.as_mut().poll(context).map(Some)
        }
    })
    .await
}

#[cfg(test)]
mod tests;
