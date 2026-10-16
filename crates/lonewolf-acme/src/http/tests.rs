// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::error::Error;
use std::future::pending;
use std::io::{Read, Write};
use std::net::{TcpListener as StdListener, TcpStream as StdStream};

use compio::runtime::Runtime;
use compio::time::timeout;
use futures_channel::oneshot;
use futures_util::future::{Either, select};

use super::*;
use crate::{ChallengeLease, ManagedHost};

type TestResult = Result<(), Box<dyn Error>>;
const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz_012345";
const AUTHORIZATION: &str =
    "abcdefghijklmnopqrstuvwxyz_012345.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

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
        let server = Http01Server::bind(
            &["127.0.0.1:0".parse()?, "127.0.0.1:0".parse()?],
            challenges.clone(),
        )
        .await?;
        let addresses = server.local_addrs()?;
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
        let restarted = Http01Server::bind(&addresses, challenges).await?;
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
        let reserved = StdListener::bind("127.0.0.1:0")?;
        let first = reserved.local_addr()?;
        let occupied = StdListener::bind("127.0.0.1:0")?;
        drop(reserved);
        let (challenges, _one, _two) = challenges();
        let result = Http01Server::bind(&[first, occupied.local_addr()?], challenges.clone()).await;
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::AddrInUse);
        let _released = StdListener::bind(first)?;
        assert!(challenges.lookup("one.example", TOKEN).is_none());
        Ok(())
    })
}

#[test]
fn cancellation_clears_challenges_and_pending_accepts() -> TestResult {
    Runtime::new()?.block_on(async {
        let (challenges, _one, _two) = challenges();
        let server = Http01Server::bind(&["127.0.0.1:0".parse()?], challenges.clone()).await?;
        let address = server.local_addrs()?[0];
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
        let server = Http01Server::bind(&[address], challenges).await?;
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

#[test]
fn global_connection_limit_and_shutdown_are_deterministic() -> TestResult {
    Runtime::new()?.block_on(async {
        let accepts = Cell::new(0);
        let active = Rc::new(Cell::new(0));
        let peak = Cell::new(0);
        let (stop, stopped) = oneshot::channel();
        let stop = Cell::new(Some(stop));
        let next_accept = |index| {
            let accepts = &accepts;
            async move {
                accepts.set(accepts.get() + 1);
                (index, Ok(()))
            }
        };
        let (connections, _) = timeout(
            Duration::from_secs(1),
            accept_connections(
                (0..3).map(next_accept).collect(),
                next_accept,
                |(), deadline| {
                    assert!(deadline > Instant::now());
                    active.set(active.get() + 1);
                    peak.set(peak.get().max(active.get()));
                    let active = active.clone();
                    let stop = &stop;
                    async move {
                        struct Active(Rc<Cell<usize>>);
                        impl Drop for Active {
                            fn drop(&mut self) {
                                self.0.set(self.0.get() - 1);
                            }
                        }
                        let _active = Active(active.clone());
                        if active.get() == MAX_CONNECTIONS {
                            stop.take().unwrap().send(Instant::now()).unwrap();
                        }
                        pending::<()>().await;
                    }
                },
                async { stopped.await.unwrap() },
                CONNECTION_TIMEOUT,
            ),
        )
        .await?;
        assert_eq!(peak.get(), 32);
        assert_eq!(accepts.get(), 32);
        drop(connections);
        assert_eq!(active.get(), 0);
        Ok(())
    })
}

#[test]
fn pending_accept_is_not_recreated_when_connections_complete() -> TestResult {
    Runtime::new()?.block_on(async {
        let created = Cell::new(0);
        let completed = Cell::new(false);
        let next_accept = |index| {
            created.set(created.get() + 1);
            let first = created.get() == 1;
            async move {
                if !first {
                    pending::<()>().await;
                }
                (index, Ok(()))
            }
        };
        let shutdown = poll_fn(|context| {
            if completed.get() {
                Poll::Ready(Instant::now())
            } else {
                context.waker().wake_by_ref();
                Poll::Pending
            }
        });
        let (connections, _) = timeout(
            Duration::from_secs(1),
            accept_connections(
                [next_accept(0)].into_iter().collect(),
                next_accept,
                |(), _| async {
                    completed.set(true);
                },
                shutdown,
                CONNECTION_TIMEOUT,
            ),
        )
        .await?;
        assert!(connections.is_empty());
        assert_eq!(created.get(), 2);
        Ok(())
    })
}

#[test]
fn accept_errors_retry_without_starving_shutdown() -> TestResult {
    Runtime::new()?.block_on(async {
        for kind in [
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
        ] {
            let attempts = Cell::new(0);
            let result = retry_accept(
                || {
                    attempts.set(attempts.get() + 1);
                    ready(if attempts.get() == 1 {
                        Err(io::Error::from(kind))
                    } else {
                        Ok(())
                    })
                },
                0,
            )
            .await;
            assert!(result.is_ok());
            assert_eq!(attempts.get(), 2);
        }
        let attempts = Cell::new(0);
        assert!(
            timeout(
                Duration::from_millis(30),
                retry_accept::<(), _, _>(
                    || {
                        attempts.set(attempts.get() + 1);
                        ready(Err(io::Error::from(io::ErrorKind::Other)))
                    },
                    0
                )
            )
            .await
            .is_err()
        );
        assert_eq!(attempts.get(), 1);
        assert!(
            timeout(
                Duration::from_millis(30),
                retry_accept::<(), _, _>(
                    || ready(Err(io::Error::from(io::ErrorKind::Interrupted))),
                    0
                )
            )
            .await
            .is_err()
        );
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
        let next_accept = |_: usize| {
            poll_fn(|_| -> Poll<(usize, io::Result<()>)> {
                panic!("polled accept after shutdown");
            })
        };
        let (connections, actual) = accept_connections(
            [next_accept(0)].into_iter().collect(),
            next_accept,
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
fn other_accept_errors_retry_after_one_second() -> TestResult {
    Runtime::new()?.block_on(async {
        let attempts = Cell::new(0);
        let started = Instant::now();
        timeout(
            Duration::from_secs(3),
            retry_accept(
                || {
                    attempts.set(attempts.get() + 1);
                    ready(if attempts.get() == 1 {
                        Err(io::Error::from(io::ErrorKind::Other))
                    } else {
                        Ok(())
                    })
                },
                0,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(attempts.get(), 2);
        assert!(started.elapsed() >= ACCEPT_RETRY_DELAY);
    });
    Ok(())
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
