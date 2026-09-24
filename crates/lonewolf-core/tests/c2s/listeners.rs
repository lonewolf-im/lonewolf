// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::num::NonZeroUsize;
use std::os::fd::AsRawFd;
use std::thread;

use compio::io::AsyncRead;
use compio::runtime::Runtime;
use compio::time::timeout;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_util::core_dispatcher::CoreDispatcher;

use super::*;
use crate::config::limits::{C2sLimitProfile, C2sLimits};
use crate::config::{Config, TcpListenerConfig};
use crate::hosts::HostsError;

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

fn hosts() -> Result<Hosts, HostsError> {
    let config = Config::default();
    Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())
}

fn auth() -> Result<(Arc<AuthService>, tempfile::TempDir), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let accounts = RedbAccountRepository::open(directory.path().join("accounts.redb"))?;
    let decoy = ScramDecoy::new().map_err(|error| format!("no randomness: {error:?}"))?;
    Ok((Arc::new(AuthService { accounts, decoy }), directory))
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
        let unauthenticated = Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN));
        let hosts = hosts()?;
        let (auth, _directory) = auth()?;
        for index in 0..handle.worker_count() {
            let (ready, readiness) = oneshot::channel();
            let unauthenticated = Arc::clone(&unauthenticated);
            let hosts = hosts.clone();
            let auth = Arc::clone(&auth);
            let task = handle
                .dispatch_at(index, move |context| async move {
                    let listener = bind(address).await?;
                    let _ = ready.send((
                        listener.local_addr()?,
                        listener.as_raw_fd(),
                        thread::current().id(),
                    ));
                    let profile = C2sLimitProfile::default();
                    let admission = AdmissionLimits {
                        attempts: Arc::new(AttemptLimiter::new(
                            &profile.connection_attempts_per_ip,
                        )),
                        connections: Arc::new(ConnectionLimiter::new(
                            profile.max_connections_per_ip.get(),
                        )),
                        unauthenticated,
                    };
                    run_listener(
                        listener,
                        context,
                        pending().boxed().shared(),
                        0,
                        admission,
                        StreamServices { hosts, auth },
                        StreamSettings::new(
                            profile.max_stanza_bytes,
                            &profile.incoming_xml_per_connection,
                            Duration::from_secs(
                                profile.connection_establishment_timeout_secs.get(),
                            ),
                            Duration::from_secs(profile.authentication_timeout_secs.get()),
                            GlobalChunkAllocator,
                        ),
                    )
                    .await
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
            SockRef::from(&client).shutdown(Shutdown::Write)?;
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
fn unauthenticated_capacity_is_shared_across_listeners() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let handle = dispatcher.handle();
        let unauthenticated = Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN));
        let hosts = hosts()?;
        let (auth, _directory) = auth()?;
        let mut addresses = Vec::with_capacity(2);
        let mut tasks = Vec::with_capacity(2);
        for listener_id in 0..2 {
            let (ready, readiness) = oneshot::channel();
            let unauthenticated = Arc::clone(&unauthenticated);
            let hosts = hosts.clone();
            let auth = Arc::clone(&auth);
            let task = handle
                .dispatch_at(
                    listener_id % handle.worker_count(),
                    move |context| async move {
                        let listener = bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
                        let _ = ready.send(listener.local_addr()?);
                        let profile = C2sLimitProfile::default();
                        let admission = AdmissionLimits {
                            attempts: Arc::new(AttemptLimiter::new(
                                &profile.connection_attempts_per_ip,
                            )),
                            connections: Arc::new(ConnectionLimiter::new(
                                profile.max_connections_per_ip.get(),
                            )),
                            unauthenticated,
                        };
                        run_listener(
                            listener,
                            context,
                            pending().boxed().shared(),
                            listener_id,
                            admission,
                            StreamServices { hosts, auth },
                            StreamSettings::new(
                                profile.max_stanza_bytes,
                                &profile.incoming_xml_per_connection,
                                Duration::from_secs(
                                    profile.connection_establishment_timeout_secs.get(),
                                ),
                                Duration::from_secs(profile.authentication_timeout_secs.get()),
                                GlobalChunkAllocator,
                            ),
                        )
                        .await
                    },
                )
                .await?;
            addresses.push(readiness.await?);
            tasks.push(task);
        }
        let first = TcpStream::connect(addresses[0]).await?;
        while unauthenticated.active_count() != 1 {
            compio::time::sleep(Duration::from_millis(1)).await;
        }
        let mut second = TcpStream::connect(addresses[1]).await?;
        match second.read([0; 1]).await.0 {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) => {}
            other => return Err(format!("rejected connection remained open: {other:?}").into()),
        }
        assert_eq!(unauthenticated.active_count(), 1);
        drop(first);
        while unauthenticated.active_count() != 0 {
            compio::time::sleep(Duration::from_millis(1)).await;
        }
        let third = TcpStream::connect(addresses[1]).await?;
        while unauthenticated.active_count() != 1 {
            compio::time::sleep(Duration::from_millis(1)).await;
        }
        dispatcher.shutdown(TIMEOUT).await?;
        for task in tasks {
            task.await??;
        }
        assert_eq!(unauthenticated.active_count(), 0);
        drop(third);
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
                    ..TcpListenerConfig::default()
                },
                TcpListenerConfig {
                    address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                    ..TcpListenerConfig::default()
                },
            ],
        };
        let (auth, _directory) = auth()?;
        let mut listeners = Listeners::start(
            &config,
            &C2sLimits::default(),
            hosts()?,
            auth.accounts.clone(),
            &handle,
            GlobalChunkAllocator,
        )
        .await?;
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
                TcpListenerConfig {
                    address: first,
                    ..TcpListenerConfig::default()
                },
                TcpListenerConfig {
                    address: occupied.local_addr()?,
                    ..TcpListenerConfig::default()
                },
            ],
        };
        let (auth, _directory) = auth()?;
        let error = Listeners::start(
            &config,
            &C2sLimits::default(),
            hosts()?,
            auth.accounts.clone(),
            &dispatcher.handle(),
            GlobalChunkAllocator,
        )
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
            listener_count: 0,
            worker_count: dispatcher.handle().worker_count(),
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
