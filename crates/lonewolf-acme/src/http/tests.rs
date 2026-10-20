// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::error::Error;
use std::future::{Future, pending, ready};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener as StdListener, TcpStream as StdStream};

use compio::runtime::Runtime;
use compio::time::timeout;
use futures_channel::oneshot;
use futures_util::future::{Either, select};
use socket2::{Domain, Protocol, Socket, Type};

use super::*;
use crate::{ChallengeLease, ManagedHost};

type TestResult = Result<(), Box<dyn Error>>;
const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz_012345";
const AUTHORIZATION: &str =
    "abcdefghijklmnopqrstuvwxyz_012345.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

fn bind_reusable_socket(address: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    Ok(socket)
}

fn reserve_listener_address() -> io::Result<(Socket, SocketAddr)> {
    // A wildcard reservation excludes automatic port allocation without taking the exact endpoint.
    let reservation = bind_reusable_socket((Ipv4Addr::UNSPECIFIED, 0).into())?;
    let address = reservation
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("missing reservation address"))?;
    Ok((reservation, (Ipv4Addr::LOCALHOST, address.port()).into()))
}

fn bind_reusable_listener(address: SocketAddr) -> io::Result<Socket> {
    let socket = bind_reusable_socket(address)?;
    socket.listen(128)?;
    Ok(socket)
}

async fn bind_after_release<T, F, B>(
    addresses: &[SocketAddr],
    deadline: Instant,
    mut bind: F,
) -> io::Result<T>
where
    F: FnMut() -> B,
    B: Future<Output = io::Result<T>>,
{
    loop {
        match bind().await {
            Ok(socket) => return Ok(socket),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("listeners {addresses:?} remain in use after the cleanup deadline"),
                    ));
                }
                compio::time::sleep_until((now + Duration::from_millis(5)).min(deadline)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn bind_released_listener(address: SocketAddr, deadline: Instant) -> io::Result<Socket> {
    bind_after_release(std::slice::from_ref(&address), deadline, || {
        ready(bind_reusable_listener(address))
    })
    .await
}

#[test]
fn release_probe_rejects_a_live_listener_and_waits_for_delayed_release() -> TestResult {
    Runtime::new()?.block_on(async {
        let (_reservation, address) = reserve_listener_address()?;
        let listener = bind_reusable_listener(address)?;
        let deadline = Instant::now() + Duration::from_millis(20);
        assert_eq!(
            bind_released_listener(address, deadline)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrInUse
        );
        assert!(Instant::now() >= deadline);
        let (replacement, ()) = futures_util::future::join(
            bind_released_listener(address, Instant::now() + Duration::from_secs(2)),
            async {
                compio::time::sleep(Duration::from_millis(5)).await;
                drop(listener);
            },
        )
        .await;
        let _replacement = replacement?;
        Ok(())
    })
}

fn challenges() -> (Challenges, ChallengeLease, ChallengeLease) {
    let challenges = Challenges::new(&["one.example", "two.example"].map(|name| ManagedHost {
        xmpp_domain: name.into(),
        dns_name: name.into(),
    }))
    .unwrap();
    let one = challenges
        .publish("one.example", TOKEN, AUTHORIZATION)
        .unwrap();
    let two = challenges
        .publish("two.example", TOKEN, AUTHORIZATION)
        .unwrap();
    (challenges, one, two)
}

struct MemoryIo {
    input: Vec<u8>,
    offset: usize,
    chunk: usize,
    output: Rc<RefCell<Vec<u8>>>,
    block_writes: bool,
    dropped: Rc<Cell<bool>>,
}

impl AsyncRead for MemoryIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.offset == self.input.len() {
            return Poll::Pending;
        }
        let length = self
            .chunk
            .min(buffer.len())
            .min(self.input.len() - self.offset);
        buffer[..length].copy_from_slice(&self.input[self.offset..self.offset + length]);
        self.offset += length;
        Poll::Ready(Ok(length))
    }
}

impl AsyncWrite for MemoryIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.block_writes {
            return Poll::Pending;
        }
        self.output.borrow_mut().extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for MemoryIo {
    fn drop(&mut self) {
        self.dropped.set(true);
    }
}

async fn memory_request(challenges: Challenges, request: String, chunk: usize) -> String {
    let output = Rc::new(RefCell::new(Vec::new()));
    let stream = MemoryIo {
        input: request.into_bytes(),
        offset: 0,
        chunk,
        output: output.clone(),
        block_writes: false,
        dropped: Rc::new(Cell::new(false)),
    };
    timeout(
        Duration::from_secs(2),
        serve_http(stream, challenges, Instant::now() + CONNECTION_TIMEOUT),
    )
    .await
    .unwrap();
    String::from_utf8(output.take()).unwrap()
}

fn get(target: &str, headers: &str) -> String {
    format!("GET {target} HTTP/1.1\r\n{headers}\r\n")
}

#[test]
fn raw_requests_enforce_target_and_status_precedence() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let path = format!("{PATH_PREFIX}{TOKEN}");
        let cases = [
            (get(&path, "Host: ONE.EXAMPLE:8080\r\n"), 200),
            (get(&path, "Host: two.example:80\r\n"), 200),
            (get(&path, "Host: other.example\r\n"), 404),
            (get(&format!("{PATH_PREFIX}{}", "x".repeat(22)), "Host: one.example\r\n"), 404),
            (get("/other", "Host: one.example\r\n"), 404),
            (get(&format!("{path}?"), "Host: one.example\r\n"), 404),
            (get(&format!("{path}?a=b"), "Host: one.example\r\n"), 404),
            (get(&format!("{path}#suffix"), "Host: one.example\r\n"), 404),
            (get(&format!("{path}#"), "Host: one.example\r\n"), 404),
            (get(&format!("http://one.example{path}"), "Host: one.example\r\n"), 404),
            (get(&format!("{PATH_PREFIX}%61{}", &TOKEN[1..]), "Host: one.example\r\n"), 404),
            (get(&format!("{path}/"), "Host: one.example\r\n"), 404),
            (get(&format!("/{path}"), "Host: one.example\r\n"), 404),
            (get("*", "Host: one.example\r\n"), 404),
            (get(&format!("{path}#x"), ""), 400),
            (get(&format!("{path}#x"), "Host: one.example\r\nHost: two.example\r\n"), 400),
            (get(&format!("{path}#x"), "Host: one.example\r\nContent-Length: 1\r\n"), 400),
            (format!("POST {path}#x HTTP/1.1\r\nHost: one.example\r\n\r\n"), 405),
            (format!("HEAD {path} HTTP/1.1\r\nHost: one.example\r\n\r\n"), 405),
            (get(&path, "Host: one.example\r\nX-Unrelated: #fragment\r\n"), 200),
            (get(&path, "Host: other.example\r\nX-Forwarded-Host: one.example\r\nForwarded: host=one.example\r\n"), 404),
            (get(&path, "Host: one.example\r\nContent-Length: 0\r\n"), 200),
            (format!("GET {path} HTTP/1.0\r\nHost: one.example\r\n\r\n"), 200),
            (format!("GET {path} HTTP/1.0\r\n\r\n"), 400),
        ];
        for (request, status) in cases {
            for chunk in [1, usize::MAX] {
                let response = memory_request(challenges.clone(), request.clone(), chunk).await;
                assert!(response.lines().next().unwrap().contains(&format!(" {status} ")), "request={request:?} response={response:?} chunk={chunk}");
                let (headers, body) = response.split_once("\r\n\r\n").unwrap();
                if status == 200 {
                    assert_eq!(body.as_bytes(), AUTHORIZATION.as_bytes());
                    assert!(headers.contains("content-type: text/plain"));
                    assert!(headers.contains(&format!("content-length: {}", AUTHORIZATION.len())));
                    assert!(headers.contains("cache-control: no-store"));
                } else {
                    assert!(body.is_empty());
                }
                if status == 405 { assert!(headers.contains("allow: GET")); }
            }
        }
        for prefix in ["\r\n", "\n", "\r\n\r\n"] {
            let response = memory_request(challenges.clone(), format!("{prefix}{}", get(&format!("{path}#suffix"), "Host: one.example\r\n")), 1).await;
            assert!(response.starts_with("HTTP/1.1 404"), "{response:?}");
        }
    });
    Ok(())
}

#[test]
fn raw_host_and_body_framing_errors_return_400() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let path = format!("{PATH_PREFIX}{TOKEN}");
        for host in [
            "",
            "user@one.example",
            "127.0.0.1",
            "[::1]",
            ":80",
            "one.example:",
            "one.example:abc",
            "one.example:65536",
            "one.example:-1",
            "one.example:80:90",
            "one.example/path",
            "one example",
            "one_.example",
            "-one.example",
            "one..example",
        ] {
            let response = memory_request(
                challenges.clone(),
                get(&path, &format!("Host: {host}\r\n")),
                1,
            )
            .await;
            assert!(
                response.starts_with("HTTP/1.1 400"),
                "host={host:?} response={response:?}"
            );
        }
        for header in [
            "Content-Length: 1\r\n",
            "Content-Length: invalid\r\n",
            "Content-Length: -1\r\n",
            "Content-Length: 0\r\nContent-Length: 1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Transfer-Encoding: gzip\r\n",
            "Transfer-Encoding: \r\n",
            "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n",
        ] {
            let response = memory_request(
                challenges.clone(),
                get(&path, &format!("Host: one.example\r\n{header}")),
                1,
            )
            .await;
            assert!(
                response.starts_with("HTTP/1.1 400"),
                "header={header:?} response={response:?}"
            );
        }
    });
    Ok(())
}

#[test]
fn raw_request_limits_and_pipelining_are_bounded() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let valid = get(&format!("{PATH_PREFIX}{TOKEN}"), "Host: one.example\r\n");
        let response =
            memory_request(challenges.clone(), format!("{valid}{valid}"), usize::MAX).await;
        assert_eq!(response.matches("HTTP/1.1").count(), 1);
        assert!(response.ends_with(AUTHORIZATION));
        for request in [
            get(
                "/",
                &format!("Host: one.example\r\n{}", "X-A: b\r\n".repeat(32)),
            ),
            get(
                "/",
                &format!("Host: one.example\r\nX-A: {}\r\n", "x".repeat(MAX_BUFFER)),
            ),
            format!("GET /{}", "x".repeat(MAX_BUFFER)),
        ] {
            let response = memory_request(challenges.clone(), request, 1).await;
            assert!(
                response.starts_with("HTTP/1.1 431") || response.starts_with("HTTP/1.1 414"),
                "{response:?}"
            );
        }
    });
    Ok(())
}

#[test]
fn slow_readers_and_incomplete_request_lines_obey_absolute_deadline() -> TestResult {
    Runtime::new()?.block_on(async {
        assert_eq!(CONNECTION_TIMEOUT, Duration::from_secs(5));
        for block_writes in [true, false] {
            let (challenges, _one, _two) = challenges();
            let dropped = Rc::new(Cell::new(false));
            let stream = MemoryIo {
                input: if block_writes {
                    get(&format!("{PATH_PREFIX}{TOKEN}"), "Host: one.example\r\n").into_bytes()
                } else {
                    b"GET /incomplete".to_vec()
                },
                offset: 0,
                chunk: 1,
                output: Rc::new(RefCell::new(Vec::new())),
                block_writes,
                dropped: dropped.clone(),
            };
            let started = Instant::now();
            timeout(
                Duration::from_secs(1),
                serve_http(stream, challenges, started + Duration::from_millis(30)),
            )
            .await
            .unwrap();
            assert!(started.elapsed() >= Duration::from_millis(30));
            assert!(dropped.get());
        }
    });
    Ok(())
}

async fn request(address: SocketAddr, request: String) -> io::Result<String> {
    blocking::unblock(move || {
        let mut stream = StdStream::connect_timeout(&address, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(7)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    })
    .await
}

#[test]
fn bound_endpoints_share_challenges_and_release_sockets_on_shutdown() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let (_first_reservation, first) = reserve_listener_address()?;
        let (_second_reservation, second) = reserve_listener_address()?;
        let addresses = [first, second];
        let server = Http01Server::bind(&addresses, challenges.clone()).await?;
        assert_eq!(server.local_addrs()?, addresses);
        for address in addresses {
            assert_eq!(
                bind_reusable_listener(address).unwrap_err().kind(),
                io::ErrorKind::AddrInUse
            );
        }
        let (stop, stopped) = oneshot::channel();
        let task = compio::runtime::spawn(server.run(async { stopped.await.unwrap() }));
        for address in &addresses {
            for host in ["ONE.EXAMPLE", "one.example:80", "two.example:8080"] {
                let response = request(
                    *address,
                    get(
                        &format!("{PATH_PREFIX}{TOKEN}"),
                        &format!("Host: {host}\r\n"),
                    ),
                )
                .await?;
                assert!(response.starts_with("HTTP/1.1 200"));
                assert!(response.ends_with(AUTHORIZATION));
            }
        }
        stop.send(Instant::now()).unwrap();
        timeout(Duration::from_secs(2), task).await???;
        assert!(challenges.lookup("one.example", TOKEN).is_none());
        let restarted =
            bind_after_release(&addresses, Instant::now() + Duration::from_secs(2), || {
                Http01Server::bind(&addresses, challenges.clone())
            })
            .await?;
        drop(restarted);
        Ok(())
    })
}

#[test]
fn ipv6_listener_is_ipv6_only_when_available() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let server = match Http01Server::bind(&["[::]:0".parse()?], challenges).await {
            Ok(server) => server,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                ) =>
            {
                return Ok(());
            }
            Err(error) if error.raw_os_error() == Some(nix::libc::EAFNOSUPPORT) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let port = server.local_addrs()?[0].port();
        let _v4 = StdListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
        let (stop, stopped) = oneshot::channel();
        let task = compio::runtime::spawn(server.run(async { stopped.await.unwrap() }));
        let response = request(
            SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), port),
            get(&format!("{PATH_PREFIX}{TOKEN}"), "Host: one.example\r\n"),
        )
        .await?;
        assert!(response.starts_with("HTTP/1.1 200"));
        stop.send(Instant::now()).unwrap();
        timeout(Duration::from_secs(2), task).await???;
        Ok(())
    })
}

#[test]
fn bind_failure_releases_earlier_listeners_and_challenges() -> TestResult {
    Runtime::new()?.block_on(async {
        let (_reservation, first) = reserve_listener_address()?;
        let occupied = StdListener::bind("127.0.0.1:0")?;
        let (challenges, _one, _two) = challenges();
        let result = Http01Server::bind(&[first, occupied.local_addr()?], challenges.clone()).await;
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::AddrInUse);
        let _released =
            bind_released_listener(first, Instant::now() + Duration::from_secs(2)).await?;
        assert!(challenges.lookup("one.example", TOKEN).is_none());
        Ok(())
    })
}

#[test]
fn cancellation_clears_challenges_and_pending_accepts() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let (_reservation, address) = reserve_listener_address()?;
        let server = Http01Server::bind(&[address], challenges.clone()).await?;
        assert_eq!(server.local_addrs()?, [address]);
        assert_eq!(
            bind_reusable_listener(address).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        let mut run = Box::pin(server.run(pending()));
        assert!(matches!(
            select(
                &mut run,
                pin!(compio::time::sleep(Duration::from_millis(10)))
            )
            .await,
            Either::Right(_)
        ));
        drop(run);
        assert!(challenges.lookup("one.example", TOKEN).is_none());
        let addresses = [address];
        let server =
            bind_after_release(&addresses, Instant::now() + Duration::from_secs(2), || {
                Http01Server::bind(&addresses, challenges.clone())
            })
            .await?;
        drop(server);
        Ok(())
    })
}

#[test]
fn shutdown_deadline_cancels_incomplete_connections() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let server = Http01Server::bind(&["127.0.0.1:0".parse()?], challenges.clone()).await?;
        let address = server.local_addrs()?[0];
        let (stop, stopped) = oneshot::channel();
        let task = compio::runtime::spawn(server.run(async { stopped.await.unwrap() }));
        let mut client = blocking::unblock(move || -> io::Result<StdStream> {
            let mut client = StdStream::connect(address)?;
            client.set_read_timeout(Some(Duration::from_secs(2)))?;
            client.write_all(b"GET /")?;
            Ok(client)
        })
        .await?;
        assert!(
            request(
                address,
                get(&format!("{PATH_PREFIX}{TOKEN}"), "Host: one.example\r\n")
            )
            .await?
            .starts_with("HTTP/1.1 200")
        );
        let deadline = Instant::now() + Duration::from_millis(40);
        stop.send(deadline).unwrap();
        timeout(Duration::from_secs(2), task).await???;
        assert!(Instant::now() >= deadline);
        assert!(challenges.lookup("one.example", TOKEN).is_none());
        blocking::unblock(move || -> io::Result<()> {
            let mut byte = [0];
            match client.read(&mut byte) {
                Ok(0) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => Ok(()),
                other => panic!("connection remained open: {other:?}"),
            }
        })
        .await?;
        Ok(())
    })
}

#[test]
fn real_slowloris_is_closed_at_five_second_deadline() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let server = Http01Server::bind(&["127.0.0.1:0".parse()?], challenges).await?;
        let address = server.local_addrs()?[0];
        let (stop, stopped) = oneshot::channel();
        let task = compio::runtime::spawn(server.run(async { stopped.await.unwrap() }));
        let started = Instant::now();
        let response = request(address, "GET /incomplete".into()).await?;
        assert!(response.is_empty());
        assert!(started.elapsed() >= CONNECTION_TIMEOUT);
        assert!(started.elapsed() < Duration::from_secs(7));
        stop.send(Instant::now()).unwrap();
        timeout(Duration::from_secs(2), task).await???;
        Ok(())
    })
}

struct Model {
    queued: RefCell<Vec<usize>>,
    waits: RefCell<Vec<usize>>,
    ready: RefCell<Vec<bool>>,
    wait_wakers: RefCell<Vec<Option<std::task::Waker>>>,
    live: Cell<usize>,
    peak: Cell<usize>,
    accepted: RefCell<Vec<(usize, Instant)>>,
    completed: RefCell<Vec<bool>>,
    service_wakers: RefCell<Vec<Option<std::task::Waker>>>,
    readiness_completed: Cell<usize>,
    clock: Cell<Instant>,
}

impl Model {
    fn new(endpoints: usize) -> Rc<Self> {
        Rc::new(Self {
            queued: RefCell::new(vec![0; endpoints]),
            waits: RefCell::new(vec![0; endpoints]),
            ready: RefCell::new(vec![false; endpoints]),
            wait_wakers: RefCell::new(vec![None; endpoints]),
            live: Cell::new(0),
            peak: Cell::new(0),
            accepted: RefCell::new(Vec::new()),
            completed: RefCell::new(Vec::new()),
            service_wakers: RefCell::new(Vec::new()),
            readiness_completed: Cell::new(0),
            clock: Cell::new(Instant::now()),
        })
    }

    fn incoming(&self, endpoint: usize, count: usize) {
        self.queued.borrow_mut()[endpoint] += count;
        self.ready.borrow_mut()[endpoint] = true;
        if let Some(waker) = &self.wait_wakers.borrow()[endpoint] {
            waker.wake_by_ref();
        }
    }

    fn wait(
        self: &Rc<Self>,
        endpoint: usize,
    ) -> impl Future<Output = (usize, io::Result<()>)> + use<> {
        self.waits.borrow_mut()[endpoint] += 1;
        let model = self.clone();
        poll_fn(move |context| {
            if model.ready.borrow_mut()[endpoint] {
                model.ready.borrow_mut()[endpoint] = false;
                model
                    .readiness_completed
                    .set(model.readiness_completed.get() + 1);
                Poll::Ready((endpoint, Ok(())))
            } else {
                model.wait_wakers.borrow_mut()[endpoint] = Some(context.waker().clone());
                Poll::Pending
            }
        })
    }

    fn accept(self: &Rc<Self>, endpoint: usize) -> io::Result<Accepted<ModelSocket>> {
        let mut queued = self.queued.borrow_mut();
        if queued[endpoint] == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        queued[endpoint] -= 1;
        if queued[endpoint] == 0 {
            self.ready.borrow_mut()[endpoint] = false;
        }
        let id = self.accepted.borrow().len();
        let accepted_at = self.clock.get();
        self.accepted.borrow_mut().push((endpoint, accepted_at));
        self.completed.borrow_mut().push(false);
        self.service_wakers.borrow_mut().push(None);
        self.live.set(self.live.get() + 1);
        self.peak.set(self.peak.get().max(self.live.get()));
        Ok(Accepted {
            stream: ModelSocket {
                model: self.clone(),
                id,
            },
            accepted_at,
        })
    }

    fn complete(&self, id: usize) {
        self.completed.borrow_mut()[id] = true;
        if let Some(waker) = &self.service_wakers.borrow()[id] {
            waker.wake_by_ref();
        }
    }
}

struct ModelSocket {
    model: Rc<Model>,
    id: usize,
}

impl Future for ModelSocket {
    type Output = ();
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        if self.model.completed.borrow()[self.id] {
            Poll::Ready(())
        } else {
            self.model.service_wakers.borrow_mut()[self.id] = Some(context.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for ModelSocket {
    fn drop(&mut self) {
        self.model.live.set(self.model.live.get() - 1);
    }
}

async fn drive_until<F: Future>(mut driver: Pin<&mut F>, condition: impl Fn() -> bool) {
    timeout(
        Duration::from_secs(2),
        poll_fn(|context| {
            assert!(driver.as_mut().poll(context).is_pending());
            if condition() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
}

#[test]
fn completed_readiness_at_capacity_never_owns_a_hidden_socket_or_refreshes_deadlines() -> TestResult
{
    Runtime::new()?.block_on(async {
        let model = Model::new(2);
        model.incoming(0, 32);
        let deadlines = RefCell::new(Vec::new());
        let (stop, stopped) = oneshot::channel();
        let mut driver = Box::pin(accept_connections(
            2,
            |index, retry| {
                assert!(retry.is_none());
                model.wait(index)
            },
            |index| model.accept(index),
            |socket, deadline| {
                deadlines.borrow_mut().push(deadline);
                socket
            },
            async { stopped.await.unwrap() },
            CONNECTION_TIMEOUT,
        ));
        drive_until(driver.as_mut(), || {
            model.live.get() == 32 && model.wait_wakers.borrow()[1].is_some()
        })
        .await;
        let original_deadline = deadlines.borrow()[0];
        model.incoming(1, 1);
        assert_eq!(model.accepted.borrow().len(), 32);
        drive_until(driver.as_mut(), || model.readiness_completed.get() == 1).await;
        assert_eq!(model.accepted.borrow().len(), 32);
        assert_eq!(model.live.get(), 32);
        let accepted_later = model.clock.get() + Duration::from_secs(1);
        model.clock.set(accepted_later);
        model.complete(0);
        drive_until(driver.as_mut(), || model.accepted.borrow().len() == 33).await;
        assert_eq!(model.accepted.borrow()[32], (1, accepted_later));
        assert_eq!(deadlines.borrow()[32], accepted_later + CONNECTION_TIMEOUT);
        assert_eq!(deadlines.borrow()[0], original_deadline);
        assert_eq!(model.peak.get(), 32);
        stop.send(Instant::now()).unwrap();
        let (connections, _) = driver.await;
        drop(connections);
        assert_eq!(model.live.get(), 0);
    });
    Ok(())
}

#[test]
fn idle_endpoints_do_not_reserve_capacity_and_pending_readiness_is_retained() -> TestResult {
    Runtime::new()?.block_on(async {
        let model = Model::new(40);
        model.incoming(39, 1);
        let (stop, stopped) = oneshot::channel();
        let mut driver = Box::pin(accept_connections(
            40,
            |index, _| model.wait(index),
            |index| model.accept(index),
            |socket, _| socket,
            async { stopped.await.unwrap() },
            CONNECTION_TIMEOUT,
        ));
        drive_until(driver.as_mut(), || {
            model.live.get() == 1 && model.wait_wakers.borrow().iter().all(Option::is_some)
        })
        .await;
        assert_eq!(model.accepted.borrow()[0].0, 39);
        assert!(model.waits.borrow().iter().all(|&count| count == 1));
        model.complete(0);
        drive_until(driver.as_mut(), || model.live.get() == 0).await;
        assert!(model.waits.borrow().iter().all(|&count| count == 1));
        model.ready.borrow_mut()[1] = true;
        model.wait_wakers.borrow()[1]
            .as_ref()
            .unwrap()
            .wake_by_ref();
        drive_until(driver.as_mut(), || model.waits.borrow()[1] == 2).await;
        assert_eq!(model.live.get(), 0);
        model.incoming(1, 1);
        drive_until(driver.as_mut(), || model.live.get() == 1).await;
        assert_eq!(model.accepted.borrow()[1].0, 1);
        stop.send(Instant::now()).unwrap();
        let (connections, _) = driver.await;
        drop(connections);
        assert_eq!(model.live.get(), 0);
    });
    Ok(())
}

#[test]
fn admission_covers_transport_drop_and_conversion_errors_release_capacity() -> TestResult {
    Runtime::new()?.block_on(async {
        let admission = Admission::default();
        let permit = admission.acquire().unwrap();
        struct Transport(Rc<Cell<usize>>);
        impl Drop for Transport {
            fn drop(&mut self) {
                assert_eq!(self.0.get(), 1);
            }
        }
        let transport = Transport(admission.0.clone());
        let connection = async move {
            let _transport = transport;
            pending::<()>().await;
        };
        let admitted = Admitted {
            connection: Box::pin(connection),
            _permit: permit,
        };
        drop(admitted);
        assert_eq!(admission.0.get(), 0);
        let attempts = Cell::new(0);
        let (stop, stopped) = oneshot::channel();
        let stop = Cell::new(Some(stop));
        let (connections, _) = accept_connections(
            1,
            |index, retry| {
                assert!(retry.is_some());
                stop.take().unwrap().send(Instant::now()).unwrap();
                async move {
                    pending::<()>().await;
                    (index, Ok(()))
                }
            },
            |_| -> io::Result<Accepted<()>> {
                attempts.set(attempts.get() + 1);
                let permit = admission.acquire().unwrap();
                let socket = Transport(admission.0.clone());
                drop(socket);
                drop(permit);
                Err(io::ErrorKind::Other.into())
            },
            |(), _| ready(()),
            async { stopped.await.unwrap() },
            CONNECTION_TIMEOUT,
        )
        .await;
        assert!(connections.is_empty());
        assert_eq!(attempts.get(), 1);
        assert_eq!(admission.0.get(), 0);
    });
    Ok(())
}

#[test]
fn expired_deadlines_do_not_poll_io_or_accepts() -> TestResult {
    Runtime::new()?.block_on(async {
        let deadline = Instant::now();
        assert!(
            until_deadline(
                deadline,
                poll_fn(|_| -> Poll<()> {
                    panic!("polled IO after deadline");
                })
            )
            .await
            .is_none()
        );
        let (connections, actual) = accept_connections(
            1,
            |_, _| -> std::future::Ready<(usize, io::Result<()>)> {
                panic!("waited after shutdown");
            },
            |_| -> io::Result<Accepted<()>> {
                panic!("accepted after shutdown");
            },
            |(), _| async {
                panic!("served after shutdown");
            },
            ready(deadline),
            CONNECTION_TIMEOUT,
        )
        .await;
        assert_eq!(actual, deadline);
        assert!(connections.is_empty());
    });
    Ok(())
}

#[test]
fn accept_errors_use_bounded_retry_without_holding_capacity() -> TestResult {
    Runtime::new()?.block_on(async {
        for kind in [
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::WouldBlock,
        ] {
            assert!(retry_after(&io::Error::from(kind), 0).is_none());
        }
        let model = Model::new(1);
        let attempts = Cell::new(0);
        let retry_deadline = Cell::new(None);
        let (stop, stopped) = oneshot::channel();
        let stop = Cell::new(Some(stop));
        let (connections, _) = timeout(
            Duration::from_secs(3),
            accept_connections(
                1,
                |index, retry| {
                    retry_deadline.set(retry);
                    async move {
                        sleep_until(retry.unwrap()).await;
                        (index, Ok(()))
                    }
                },
                |_| {
                    attempts.set(attempts.get() + 1);
                    if attempts.get() == 1 {
                        return Err(io::ErrorKind::Other.into());
                    }
                    assert!(Instant::now() >= retry_deadline.get().unwrap());
                    model.incoming(0, 1);
                    model.accept(0)
                },
                |socket, _| {
                    stop.take().unwrap().send(Instant::now()).unwrap();
                    socket
                },
                async { stopped.await.unwrap() },
                CONNECTION_TIMEOUT,
            ),
        )
        .await
        .unwrap();
        assert_eq!(attempts.get(), 2);
        drop(connections);
        assert_eq!(model.live.get(), 0);
    });
    Ok(())
}

#[test]
fn more_than_32_loopback_endpoints_serve_the_last_endpoint() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let addresses = vec!["127.0.0.1:0".parse()?; 40];
        let server = Http01Server::bind(&addresses, challenges).await?;
        let address = server.local_addrs()?[39];
        let (stop, stopped) = oneshot::channel();
        let task = compio::runtime::spawn(server.run(async { stopped.await.unwrap() }));
        assert!(
            request(
                address,
                get(&format!("{PATH_PREFIX}{TOKEN}"), "Host: one.example\r\n")
            )
            .await?
            .starts_with("HTTP/1.1 200")
        );
        stop.send(Instant::now()).unwrap();
        timeout(Duration::from_secs(2), task).await???;
        Ok(())
    })
}

#[test]
fn two_loopback_listeners_do_not_accept_beyond_global_capacity() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let server = Http01Server::bind(
            &["127.0.0.1:0".parse()?, "127.0.0.1:0".parse()?],
            challenges,
        )
        .await?;
        let addresses = server.local_addrs()?;
        let listeners = server.listeners.as_ref().unwrap();
        let accepted = RefCell::new(Vec::new());
        let releases = RefCell::new(Vec::new());
        let b_waiting = Cell::new(false);
        let b_ready = Cell::new(false);
        let (stop, stopped) = oneshot::channel();
        let mut driver = Box::pin(accept_connections(
            2,
            |index, retry| {
                let b_waiting = &b_waiting;
                let b_ready = &b_ready;
                async move {
                    if index == 1 {
                        b_waiting.set(true);
                    }
                    let result = wait_endpoint(index, &listeners[index], retry).await;
                    if index == 1 {
                        b_ready.set(true);
                    }
                    result
                }
            },
            |index| {
                let connection = accept_nonblocking(&listeners[index])?;
                accepted.borrow_mut().push(index);
                Ok(connection)
            },
            |stream, _| {
                let (release, released) = oneshot::channel();
                releases.borrow_mut().push(Some(release));
                async move {
                    let _stream = stream;
                    let _ = released.await;
                }
            },
            async { stopped.await.unwrap() },
            CONNECTION_TIMEOUT,
        ));
        let a = addresses[0];
        let clients = blocking::unblock(move || -> io::Result<Vec<StdStream>> {
            (0..32).map(|_| StdStream::connect(a)).collect()
        })
        .await?;
        drive_until(driver.as_mut(), || {
            accepted.borrow().len() == 32 && b_waiting.get()
        })
        .await;
        let b = addresses[1];
        let client_b = blocking::unblock(move || StdStream::connect(b)).await?;
        drive_until(driver.as_mut(), || b_ready.get()).await;
        assert_eq!(accepted.borrow().len(), 32);
        releases.borrow_mut()[0].take().unwrap().send(()).unwrap();
        drive_until(driver.as_mut(), || accepted.borrow().len() == 33).await;
        assert_eq!(accepted.borrow()[32], 1);
        stop.send(Instant::now()).unwrap();
        let (connections, _) = driver.await;
        drop(connections);
        drop((clients, client_b));
        Ok(())
    })
}

#[test]
fn real_conversion_failure_closes_socket_before_releasing_permit() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let server = Http01Server::bind(&["127.0.0.1:0".parse()?], challenges).await?;
        let address = server.local_addrs()?[0];
        let mut client = blocking::unblock(move || StdStream::connect(address)).await?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        let listener = &server.listeners.as_ref().unwrap()[0];
        listener.accept_ready().await?;
        let admission = Admission::default();
        let permit = admission.acquire().unwrap();
        let result = accept_with::<()>(listener, |stream| {
            assert_eq!(admission.0.get(), 1);
            drop(stream);
            assert_eq!(admission.0.get(), 1);
            Err(io::ErrorKind::Other.into())
        });
        assert!(result.is_err());
        assert_eq!(admission.0.get(), 1);
        drop(permit);
        assert_eq!(admission.0.get(), 0);
        blocking::unblock(move || -> io::Result<()> {
            let mut byte = [0];
            assert_eq!(client.read(&mut byte)?, 0);
            Ok(())
        })
        .await?;
        Ok(())
    })
}

#[test]
fn shutdown_clears_challenges_before_draining_connections() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let server = Http01Server::bind(&["127.0.0.1:0".parse()?], challenges.clone()).await?;
        let address = server.local_addrs()?[0];
        let (stop, stopped) = oneshot::channel();
        let task = compio::runtime::spawn(server.run(async { stopped.await.unwrap() }));
        let mut client = blocking::unblock(move || -> io::Result<StdStream> {
            let mut client = StdStream::connect(address)?;
            client.set_read_timeout(Some(Duration::from_secs(2)))?;
            client.write_all(
                format!("GET {PATH_PREFIX}{TOKEN} HTTP/1.1\r\nHost: one.example\r\n").as_bytes(),
            )?;
            Ok(client)
        })
        .await?;
        assert!(
            request(
                address,
                get(&format!("{PATH_PREFIX}{TOKEN}"), "Host: one.example\r\n")
            )
            .await?
            .starts_with("HTTP/1.1 200")
        );
        stop.send(Instant::now() + Duration::from_secs(2)).unwrap();
        timeout(
            Duration::from_secs(1),
            poll_fn(|context| {
                if challenges.lookup("one.example", TOKEN).is_none() {
                    Poll::Ready(())
                } else {
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
            }),
        )
        .await?;
        let response = blocking::unblock(move || -> io::Result<String> {
            client.write_all(b"\r\n")?;
            let mut response = String::new();
            client.read_to_string(&mut response)?;
            Ok(response)
        })
        .await?;
        assert!(response.starts_with("HTTP/1.1 404"));
        timeout(Duration::from_secs(2), task).await???;
        Ok(())
    })
}
