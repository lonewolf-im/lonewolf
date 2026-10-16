// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::collections::VecDeque;
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
use compio::runtime::fd::PollFd;
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
    listeners: Option<Vec<PollFd<TcpListener>>>,
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
            SockRef::from(&listener).set_nonblocking(true)?;
            if let Some(listeners) = server.listeners.as_mut() {
                listeners.push(PollFd::new(listener)?);
            }
        }
        Ok(server)
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.listeners
            .iter()
            .flatten()
            .map(|listener| listener.local_addr())
            .collect()
    }

    /// Shutdown clears challenges and bounds connection drain by the supplied absolute deadline.
    /// Dropping the server or this future also clears challenges.
    pub async fn run(mut self, shutdown: impl Future<Output = Instant>) -> io::Result<()> {
        let (mut connections, deadline) = {
            let listeners = self.listeners.as_deref().unwrap_or_default();
            accept_connections(
                listeners.len(),
                |index, retry| wait_endpoint(index, &listeners[index], retry),
                |index| accept_nonblocking(&listeners[index]),
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

async fn wait_endpoint(
    index: usize,
    listener: &PollFd<TcpListener>,
    retry: Option<Instant>,
) -> (usize, io::Result<()>) {
    if let Some(deadline) = retry {
        sleep_until(deadline).await;
    }
    (index, listener.accept_ready().await)
}

struct Accepted<T> {
    stream: T,
    accepted_at: Instant,
}

fn accept_nonblocking(listener: &TcpListener) -> io::Result<Accepted<TcpStream>> {
    accept_with(listener, TcpStream::from_std)
}

fn accept_with<T>(
    listener: &TcpListener,
    convert: impl FnOnce(std::net::TcpStream) -> io::Result<T>,
) -> io::Result<Accepted<T>> {
    let (socket, _) = SockRef::from(listener).accept()?;
    let accepted_at = Instant::now();
    // Compio sets the mode for its backend when it attaches the stream.
    socket.set_nonblocking(false)?;
    let stream: std::net::TcpStream = socket.into();
    Ok(Accepted {
        stream: convert(stream)?,
        accepted_at,
    })
}

#[derive(Default)]
struct Admission(Rc<Cell<usize>>);

impl Admission {
    fn acquire(&self) -> Option<Permit> {
        let active = self.0.get();
        if active == MAX_CONNECTIONS {
            return None;
        }
        self.0.set(active + 1);
        Some(Permit(self.0.clone()))
    }
}

struct Permit(Rc<Cell<usize>>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

struct Admitted<C> {
    // The transport must drop before its capacity permit.
    connection: Pin<Box<C>>,
    _permit: Permit,
}

impl<C: Future<Output = ()>> Future for Admitted<C> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        self.connection.as_mut().poll(context)
    }
}

fn retry_after(error: &io::Error, endpoint: usize) -> Option<Instant> {
    match error.kind() {
        io::ErrorKind::WouldBlock
        | io::ErrorKind::Interrupted
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset => None,
        _ => {
            tracing::warn!(endpoint, error_kind = ?error.kind(), "HTTP-01 accept failed");
            Some(Instant::now() + ACCEPT_RETRY_DELAY)
        }
    }
}

async fn accept_connections<T, W, WF, A, S, C>(
    endpoints: usize,
    mut wait: W,
    mut accept: A,
    mut serve: S,
    shutdown: impl Future<Output = Instant>,
    connection_timeout: Duration,
) -> (FuturesUnordered<Admitted<C>>, Instant)
where
    W: FnMut(usize, Option<Instant>) -> WF,
    WF: Future<Output = (usize, io::Result<()>)>,
    A: FnMut(usize) -> io::Result<Accepted<T>>,
    S: FnMut(T, Instant) -> C,
    C: Future<Output = ()>,
{
    const WORK_PER_POLL: usize = 64;
    let mut shutdown = pin!(shutdown);
    let mut connections = FuturesUnordered::new();
    let mut waiting = FuturesUnordered::new();
    let mut ready: VecDeque<_> = (0..endpoints).collect();
    let admission = Admission::default();
    let deadline = poll_fn(|context| {
        if let Poll::Ready(deadline) = shutdown.as_mut().poll(context) {
            return Poll::Ready(deadline);
        }
        while let Poll::Ready(Some(())) = Pin::new(&mut connections).poll_next(context) {}
        if let Poll::Ready(deadline) = shutdown.as_mut().poll(context) {
            return Poll::Ready(deadline);
        }
        let mut work = 0;
        // Readiness operations cannot accept sockets, so they remain safe at capacity.
        while work < WORK_PER_POLL / 2 {
            match Pin::new(&mut waiting).poll_next(context) {
                Poll::Ready(Some((index, Ok(())))) => ready.push_back(index),
                Poll::Ready(Some((index, Err(error)))) => {
                    let retry = retry_after(&error, index);
                    waiting.push(wait(index, retry));
                }
                Poll::Ready(None) | Poll::Pending => break,
            }
            work += 1;
        }
        while work < WORK_PER_POLL && !ready.is_empty() {
            if let Poll::Ready(deadline) = shutdown.as_mut().poll(context) {
                return Poll::Ready(deadline);
            }
            let Some(permit) = admission.acquire() else {
                break;
            };
            let Some(index) = ready.pop_front() else {
                break;
            };
            match accept(index) {
                Ok(Accepted {
                    stream,
                    accepted_at,
                }) => {
                    connections.push(Admitted {
                        connection: Box::pin(serve(stream, accepted_at + connection_timeout)),
                        _permit: permit,
                    });
                    ready.push_back(index);
                }
                Err(error) => {
                    drop(permit);
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                    ) {
                        ready.push_back(index);
                    } else {
                        let retry = retry_after(&error, index);
                        waiting.push(wait(index, retry));
                    }
                }
            }
            work += 1;
        }
        if work > 0 {
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
