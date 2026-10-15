// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use compio::net::{TcpListener, TcpSocket, TcpStream};
use compio::time::{sleep, timeout};
use compio_io::compat::AsyncStream;
use futures_util::future::{Either, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
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
        let mut shutdown = pin!(shutdown);
        let mut connections = FuturesUnordered::new();
        {
            // Cancelling a pending accept can discard a new connection.
            let mut accept = pin!(self.listener.accept());
            loop {
                let event = {
                    let progress = async {
                        if connections.len() >= MAX_CONNECTIONS {
                            connections.next().await;
                            return Ok(None);
                        }
                        if connections.is_empty() {
                            return accept.as_mut().await.map(Some);
                        }
                        match select(accept.as_mut(), pin!(connections.next())).await {
                            Either::Left((accepted, _)) => accepted.map(Some),
                            Either::Right(_) => Ok(None),
                        }
                    };
                    match select(shutdown.as_mut(), pin!(progress)).await {
                        Either::Left(_) => Either::Left(()),
                        Either::Right((result, _)) => Either::Right(result),
                    }
                };
                match event {
                    Either::Left(()) => break,
                    Either::Right(Ok(Some((stream, _)))) => {
                        accept.set(self.listener.accept());
                        connections.push(serve_connection(stream, router.clone()));
                    }
                    Either::Right(Ok(None)) => {}
                    Either::Right(Err(error)) => {
                        accept.set(self.listener.accept());
                        match error.kind() {
                            io::ErrorKind::Interrupted
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset => continue,
                            _ => {
                                tracing::warn!(
                                    error_kind = ?error.kind(),
                                    "metrics accept failed"
                                );
                                if matches!(
                                    select(shutdown.as_mut(), pin!(sleep(ACCEPT_RETRY_DELAY)))
                                        .await,
                                    Either::Left(_)
                                ) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        drop(self.listener);
        while connections.next().await.is_some() {}
        tracing::info!("metrics service stopped");
    }
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

async fn serve_connection(stream: TcpStream, router: Router) {
    let io = TokioIo::new(Box::pin(AsyncStream::with_limits(4096, 16384, stream)).compat());
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(false)
        .max_buf_size(16384)
        .max_headers(32);
    let connection = builder.serve_connection(io, TowerToHyperService::new(router));
    match timeout(CONNECTION_TIMEOUT, connection).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => tracing::debug!(outcome = "connection_failed", "metrics connection closed"),
        Err(_) => tracing::debug!(outcome = "timeout", "metrics connection deadline exceeded"),
    }
}

#[cfg(test)]
mod tests;
