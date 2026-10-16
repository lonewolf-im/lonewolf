// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::convert::Infallible;
use std::future::{Future, poll_fn, ready};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ::http::header::{
    ALLOW, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, TRANSFER_ENCODING,
};
use ::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use compio::net::{TcpListener, TcpSocket, TcpStream};
use compio::time::sleep_until;
use compio_io::compat::AsyncStream;
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::stream::{FuturesUnordered, Stream, StreamExt};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use socket2::SockRef;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use crate::Challenges;
use crate::challenge::valid_token;

const MAX_CONNECTIONS: usize = 32;
const MAX_BUFFER: usize = 16 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);
const PATH_PREFIX: &str = "/.well-known/acme-challenge/";

pub struct Http01Server {
    listeners: Option<Vec<TcpListener>>,
    challenges: Challenges,
}

impl Http01Server {
    /// Binds all addresses atomically; IPv6 listeners accept IPv6 only.
    pub async fn bind(addresses: &[SocketAddr], challenges: Challenges) -> io::Result<Self> {
        let mut server = Self {
            listeners: Some(Vec::with_capacity(addresses.len())),
            challenges,
        };
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no HTTP-01 addresses",
            ));
        }
        for &address in addresses {
            let socket = if address.is_ipv4() {
                TcpSocket::new_v4().await?
            } else {
                let socket = TcpSocket::new_v6().await?;
                SockRef::from(&socket).set_only_v6(true)?;
                socket
            };
            socket.set_reuseaddr(true)?;
            socket.bind(address).await?;
            let listener = socket.listen(128).await?;
            if let Some(listeners) = server.listeners.as_mut() {
                listeners.push(listener);
            }
        }
        Ok(server)
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.listeners
            .iter()
            .flatten()
            .map(TcpListener::local_addr)
            .collect()
    }

    /// Shutdown clears challenges and bounds connection drain by the supplied absolute deadline.
    /// Dropping the server or this future also clears challenges.
    pub async fn run(mut self, shutdown: impl Future<Output = Instant>) -> io::Result<()> {
        let (mut connections, deadline) = {
            let listeners = self.listeners.as_deref().unwrap_or_default();
            let next_accept = |index| accept_endpoint(index, &listeners[index]);
            accept_connections(
                (0..listeners.len()).map(next_accept).collect(),
                next_accept,
                |stream, deadline| serve_connection(stream, self.challenges.clone(), deadline),
                shutdown,
                CONNECTION_TIMEOUT,
            )
            .await
        };
        self.challenges.clear();
        self.listeners.take();
        until_deadline(deadline, async {
            while connections.next().await.is_some() {}
        })
        .await;
        Ok(())
    }
}

impl Drop for Http01Server {
    fn drop(&mut self) {
        self.challenges.clear();
    }
}

async fn accept_endpoint(index: usize, listener: &TcpListener) -> (usize, io::Result<TcpStream>) {
    let accepted = retry_accept(
        || async { listener.accept().await.map(|(stream, _)| stream) },
        index,
    )
    .await;
    (index, accepted)
}

async fn retry_accept<T, A, F>(mut accept: A, endpoint: usize) -> io::Result<T>
where
    A: FnMut() -> F,
    F: Future<Output = io::Result<T>>,
{
    loop {
        match accept().await {
            Ok(stream) => return Ok(stream),
            Err(error) => match error.kind() {
                io::ErrorKind::Interrupted
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset => {
                    let mut yielded = false;
                    poll_fn(|context| {
                        if yielded {
                            Poll::Ready(())
                        } else {
                            yielded = true;
                            context.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                }
                _ => {
                    tracing::warn!(endpoint, error_kind = ?error.kind(), "HTTP-01 accept failed");
                    sleep_until(Instant::now() + ACCEPT_RETRY_DELAY).await;
                }
            },
        }
    }
}

async fn accept_connections<T, A, AF, S, C>(
    mut accepts: FuturesUnordered<AF>,
    mut next_accept: A,
    mut serve: S,
    shutdown: impl Future<Output = Instant>,
    connection_timeout: Duration,
) -> (FuturesUnordered<C>, Instant)
where
    A: FnMut(usize) -> AF,
    AF: Future<Output = (usize, io::Result<T>)>,
    S: FnMut(T, Instant) -> C,
    C: Future<Output = ()>,
{
    let mut shutdown = pin!(shutdown);
    let mut connections = FuturesUnordered::new();
    let deadline = poll_fn(|context| {
        if let Poll::Ready(deadline) = shutdown.as_mut().poll(context) {
            return Poll::Ready(deadline);
        }
        while let Poll::Ready(Some(())) = Pin::new(&mut connections).poll_next(context) {}
        if let Poll::Ready(deadline) = shutdown.as_mut().poll(context) {
            return Poll::Ready(deadline);
        }
        // Cancelling a pending accept can discard a new connection.
        if connections.len() < MAX_CONNECTIONS
            && let Poll::Ready(Some((index, result))) = Pin::new(&mut accepts).poll_next(context)
        {
            accepts.push(next_accept(index));
            if let Ok(stream) = result {
                connections.push(serve(stream, Instant::now() + connection_timeout));
            }
            context.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await;
    (connections, deadline)
}

fn response<B>(
    request: &Request<B>,
    fragment: bool,
    challenges: &Challenges,
) -> Response<Full<Bytes>> {
    let host = host(request.headers());
    let (status, body) = if host.is_none() || forbidden_body(request.headers()) {
        (StatusCode::BAD_REQUEST, Bytes::new())
    } else if request.method() != Method::GET {
        (StatusCode::METHOD_NOT_ALLOWED, Bytes::new())
    } else {
        let uri = request.uri();
        let authorization = (!fragment
            && uri.scheme().is_none()
            && uri.authority().is_none()
            && uri.query().is_none())
        .then(|| uri.path().strip_prefix(PATH_PREFIX))
        .flatten()
        .filter(|token| valid_token(token))
        .and_then(|token| host.and_then(|host| challenges.lookup(host, token)));
        match authorization {
            Some(body) => (StatusCode::OK, body),
            None => (StatusCode::NOT_FOUND, Bytes::new()),
        }
    };
    let length = body.len();
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_LENGTH, HeaderValue::from(length));
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if status == StatusCode::OK {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    } else if status == StatusCode::METHOD_NOT_ALLOWED {
        headers.insert(ALLOW, HeaderValue::from_static("GET"));
    }
    response
}

fn forbidden_body(headers: &HeaderMap) -> bool {
    headers.contains_key(TRANSFER_ENCODING)
        || headers.get_all(CONTENT_LENGTH).iter().any(|value| {
            value.as_bytes().is_empty() || value.as_bytes().iter().any(|&byte| byte != b'0')
        })
}

fn host(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(HOST).iter();
    let authority = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let name = match authority.split_once(':') {
        Some((name, port))
            if !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok() =>
        {
            name
        }
        Some(_) => return None,
        None => authority,
    };
    if name.is_empty()
        || name.len() > 253
        || name.parse::<IpAddr>().is_ok()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(name)
}

async fn serve_connection(stream: TcpStream, challenges: Challenges, deadline: Instant) {
    serve_http(
        Box::pin(AsyncStream::with_limits(4096, MAX_BUFFER, stream)),
        challenges,
        deadline,
    )
    .await;
}

async fn serve_http<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    challenges: Challenges,
    deadline: Instant,
) {
    let fragment = Rc::new(Cell::new(false));
    let observer = RequestLineObserver {
        inner: stream,
        fragment: fragment.clone(),
        nonempty: false,
        done: false,
    };
    let io = TokioIo::new(observer.compat());
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(false)
        .max_buf_size(MAX_BUFFER)
        .max_headers(32)
        .auto_date_header(false);
    let service = service_fn(move |request| {
        ready(Ok::<_, Infallible>(response(
            &request,
            fragment.get(),
            &challenges,
        )))
    });
    match until_deadline(deadline, builder.serve_connection(io, service)).await {
        Some(Ok(())) => {}
        Some(Err(_)) => tracing::debug!(outcome = "connection_failed", "HTTP-01 connection closed"),
        None => tracing::debug!(outcome = "timeout", "HTTP-01 connection closed"),
    }
}

// http::Uri removes fragments before the service can reject them.
struct RequestLineObserver<T> {
    inner: T,
    fragment: Rc<Cell<bool>>,
    nonempty: bool,
    done: bool,
}

impl<T: AsyncRead + Unpin> AsyncRead for RequestLineObserver<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let Poll::Ready(Ok(length)) = result {
            for &byte in &buffer[..length] {
                if self.done {
                    break;
                }
                match byte {
                    b'\n' if self.nonempty => self.done = true,
                    b'\r' | b'\n' => {}
                    b'#' => {
                        self.fragment.set(true);
                        self.nonempty = true;
                    }
                    _ => self.nonempty = true,
                }
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for RequestLineObserver<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }
    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(context)
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
