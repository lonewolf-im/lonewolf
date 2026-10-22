// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::error::Error;
use std::future::{Future, pending, poll_fn};
use std::io;
use std::net::TcpListener;
use std::pin::pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use compio::runtime::Runtime;
use compio::time::timeout;
use futures_channel::oneshot;
use futures_util::task::noop_waker;

use super::{MetricsServer, accept_connections, until_deadline};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn occupied_address_fails_to_bind() -> TestResult {
    Runtime::new()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let error = MetricsServer::bind(listener.local_addr()?)
            .await
            .err()
            .ok_or("accepted occupied address")?;
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        Ok(())
    })
}

#[test]
fn accept_backoff_allows_connections_to_complete() -> TestResult {
    Runtime::new()?.block_on(async {
        let accept_polls = Cell::new(0);
        let completed = Cell::new(false);
        let (release, released) = oneshot::channel();
        let release = Cell::new(Some(release));
        let released = Cell::new(Some(released));
        let (stop, stopped) = oneshot::channel();
        let stop = Cell::new(Some(stop));
        let connections = timeout(
            Duration::from_secs(2),
            accept_connections(
                || {
                    poll_fn(|_| {
                        accept_polls.set(accept_polls.get() + 1);
                        match accept_polls.get() {
                            1 => Poll::Ready(Ok(())),
                            2 => {
                                if let Some(release) = release.take() {
                                    assert!(release.send(()).is_ok());
                                }
                                Poll::Ready(Err(io::Error::from_raw_os_error(nix::libc::EMFILE)))
                            }
                            _ => panic!("accepted during retry delay"),
                        }
                    })
                },
                |(), _| async {
                    if let Some(released) = released.take() {
                        assert!(released.await.is_ok());
                    }
                    completed.set(true);
                    if let Some(stop) = stop.take() {
                        assert!(stop.send(()).is_ok());
                    }
                },
                async {
                    let _ = stopped.await;
                },
                Duration::from_secs(10),
                Duration::from_secs(60),
            ),
        )
        .await?;
        assert!(completed.get());
        assert_eq!(accept_polls.get(), 2);
        assert!(connections.is_empty());
        Ok(())
    })
}

#[test]
fn accept_backoff_does_not_extend_connection_deadlines() -> TestResult {
    Runtime::new()?.block_on(async {
        let accept_polls = Cell::new(0);
        let expired = Cell::new(false);
        let (stop, stopped) = oneshot::channel();
        let stop = Cell::new(Some(stop));
        let connections = timeout(
            Duration::from_secs(2),
            accept_connections(
                || {
                    poll_fn(|_| {
                        accept_polls.set(accept_polls.get() + 1);
                        match accept_polls.get() {
                            1 => Poll::Ready(Ok(())),
                            2 => Poll::Ready(Err(io::Error::from_raw_os_error(nix::libc::EMFILE))),
                            _ => panic!("accepted during retry delay"),
                        }
                    })
                },
                |(), deadline| {
                    let expired = &expired;
                    let stop = &stop;
                    async move {
                        assert!(until_deadline(deadline, pending::<()>()).await.is_none());
                        expired.set(true);
                        if let Some(stop) = stop.take() {
                            assert!(stop.send(()).is_ok());
                        }
                    }
                },
                async {
                    let _ = stopped.await;
                },
                Duration::from_millis(20),
                Duration::from_secs(60),
            ),
        )
        .await?;
        assert!(expired.get());
        assert_eq!(accept_polls.get(), 2);
        assert!(connections.is_empty());
        Ok(())
    })
}

#[test]
fn expired_connection_deadline_never_polls_work() -> TestResult {
    Runtime::new()?.block_on(async {
        let deadline = Instant::now() - Duration::from_millis(1);
        assert!(
            until_deadline(deadline, async {
                panic!("polled a connection after its deadline");
            })
            .await
            .is_none()
        );
        Ok(())
    })
}

#[test]
fn transient_accept_errors_yield_and_poll_connections_first() -> TestResult {
    Runtime::new()?.block_on(async {
        for error_kind in [
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
        ] {
            let accept_polls = Cell::new(0);
            let completed = Cell::new(false);
            let (release, released) = oneshot::channel();
            let release = Cell::new(Some(release));
            let released = Cell::new(Some(released));
            let (stop, stopped) = oneshot::channel();
            let stop = Cell::new(Some(stop));
            let mut scheduler = pin!(accept_connections(
                || {
                    poll_fn(|_| {
                        accept_polls.set(accept_polls.get() + 1);
                        match accept_polls.get() {
                            1 => Poll::Ready(Ok(())),
                            2..=33 => {
                                if let Some(release) = release.take() {
                                    assert!(release.send(()).is_ok());
                                }
                                Poll::Ready(Err(io::Error::from(error_kind)))
                            }
                            _ => Poll::Pending,
                        }
                    })
                },
                |(), _| async {
                    if let Some(released) = released.take() {
                        assert!(released.await.is_ok());
                    }
                    assert_eq!(accept_polls.get(), 2);
                    completed.set(true);
                    if let Some(stop) = stop.take() {
                        assert!(stop.send(()).is_ok());
                    }
                },
                async {
                    let _ = stopped.await;
                },
                Duration::from_secs(10),
                Duration::from_secs(60),
            ));
            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);
            assert!(scheduler.as_mut().poll(&mut context).is_pending());
            assert_eq!(accept_polls.get(), 1);
            assert!(scheduler.as_mut().poll(&mut context).is_pending());
            assert_eq!(accept_polls.get(), 2);
            let Poll::Ready(connections) = scheduler.as_mut().poll(&mut context) else {
                panic!("connection did not complete after transient accept failure");
            };
            assert!(completed.get());
            assert_eq!(accept_polls.get(), 2);
            assert!(connections.is_empty());
        }
        Ok(())
    })
}
