// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::os::fd::AsRawFd;
use std::thread;

use compio::io::AsyncRead;
use compio::runtime::Runtime;
use compio::time::timeout;
use lonewolf_util::core_dispatcher::CoreDispatcher;

use super::*;
use crate::config::TcpListenerConfig;

type TestResult = Result<(), Box<dyn Error>>;
const TIMEOUT: Duration = Duration::from_secs(5);

fn run_test(test: impl Future<Output = TestResult>) -> TestResult {
    Runtime::new()?.block_on(timeout(TIMEOUT, test))?
}

fn dispatcher() -> io::Result<CoreDispatcher> {
    let two = NonZeroUsize::MIN.saturating_add(1);
    match CoreDispatcher::new(two, two) {
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
            CoreDispatcher::new(NonZeroUsize::MIN, two)
        }
        result => result,
    }
}

#[test]
fn workers_own_distinct_sockets_on_the_same_port() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let handle = dispatcher.handle();
        let mut address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let mut tasks = Vec::with_capacity(handle.worker_count());
        let mut descriptors = Vec::with_capacity(handle.worker_count());
        let mut threads = Vec::with_capacity(handle.worker_count());
        for index in 0..handle.worker_count() {
            let (ready, readiness) = oneshot::channel();
            let task = handle
                .dispatch_at(index, move |context| async move {
                    let listener = bind(address).await?;
                    let _ = ready.send((
                        listener.local_addr()?,
                        listener.as_raw_fd(),
                        thread::current().id(),
                    ));
                    run_listener(listener, context, pending().boxed().shared(), 0).await
                })
                .await?;
            let (bound, descriptor, owner) = readiness.await?;
            if index == 0 {
                address = bound;
            }
            assert_eq!(bound, address);
            assert!(!descriptors.contains(&descriptor));
            assert_ne!(owner, thread::current().id());
            assert!(!threads.contains(&owner));
            descriptors.push(descriptor);
            threads.push(owner);
            tasks.push(task);
        }
        for _ in 0..16 {
            let mut client = TcpStream::connect(address).await?;
            assert_eq!(client.read([0; 1]).await.0?, 0);
        }
        dispatcher.shutdown(TIMEOUT).await?;
        for task in tasks {
            task.await??;
        }
        let rebound = bind(address).await?;
        rebound.close().await?;
        Ok(())
    })
}

#[test]
fn explicit_stop_closes_all_listeners_without_stopping_workers() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let handle = dispatcher.handle();
        let config = C2sConfig {
            listeners: vec![
                TcpListenerConfig {
                    address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                },
                TcpListenerConfig {
                    address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                },
            ],
        };
        let mut listeners = Listeners::start(&config, &handle).await?;
        assert_eq!(
            listeners.tasks.len(),
            config.listeners.len() * handle.worker_count()
        );
        listeners.stop();
        while let Some(result) = listeners.tasks.next().await {
            result??;
        }
        for index in 0..handle.worker_count() {
            let task = handle
                .dispatch_at(index, |context| async move { context.worker.index })
                .await?;
            assert_eq!(task.await?, index);
        }
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn failed_start_releases_previously_bound_endpoints() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let probe = bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let first = probe.local_addr()?;
        let occupied = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let config = C2sConfig {
            listeners: vec![
                TcpListenerConfig { address: first },
                TcpListenerConfig {
                    address: occupied.local_addr()?,
                },
            ],
        };
        let error = Listeners::start(&config, &dispatcher.handle())
            .await
            .err()
            .ok_or("startup succeeded")?;
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains("listener 1 on worker 0"));
        dispatcher.shutdown(TIMEOUT).await?;
        probe.close().await?;
        let _rebound = std::net::TcpListener::bind(first)?;
        Ok(())
    })
}

#[test]
fn ipv6_and_ipv4_wildcards_can_use_the_same_port() -> TestResult {
    run_test(async {
        let ipv6 = bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).await?;
        assert!(SockRef::from(&ipv6).only_v6()?);
        let port = ipv6.local_addr()?.port();
        let ipv4 = bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))).await?;
        assert_eq!(ipv4.local_addr()?.port(), port);
        ipv4.close().await?;
        ipv6.close().await?;
        Ok(())
    })
}

#[test]
fn listener_failures_reach_the_supervisor() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let (stop, _stopped) = oneshot::channel();
        let mut listeners = Listeners {
            stop: Some(stop),
            tasks: FuturesUnordered::new(),
        };
        listeners.tasks.push(
            dispatcher
                .handle()
                .dispatch_at(0, |_| async {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "listener failed"))
                })
                .await?,
        );
        assert_eq!(listeners.failure().await.kind(), io::ErrorKind::BrokenPipe);
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}
