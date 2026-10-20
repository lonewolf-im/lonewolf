// SPDX-License-Identifier: Apache-2.0

use std::future::pending;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use compio::runtime::Runtime;
use lonewolf_acme::{AcmeErrorKind, RetryState, StateStore, StoredCertificate, StoredHost};
use parking_lot::Mutex as PlMutex;
use rcgen::CertificateParams;
use socket2::{Domain, Protocol, Socket, Type};
use zeroize::Zeroizing;

use super::*;
use crate::config::{HostConfig, HostTlsConfig};
use crate::hosts::test_support::material;

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

async fn bind_released_listener(address: SocketAddr, deadline: Instant) -> io::Result<Socket> {
    loop {
        match bind_reusable_listener(address) {
            Ok(socket) => return Ok(socket),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("listener {address} remains in use after the cleanup deadline"),
                    ));
                }
                compio::time::sleep_until((now + Duration::from_millis(5)).min(deadline)).await;
            }
            Err(error) => return Err(error),
        }
    }
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

fn config(directory: &std::path::Path) -> Config {
    let mut config = Config::default();
    config.hosts.clear();
    config.hosts.insert(
        "example.com".into(),
        HostConfig {
            tls: Some(HostTlsConfig {
                source: HostTlsSource::LetsEncrypt,
                client_auth: None,
            }),
            ..HostConfig::default()
        },
    );
    config.letsencrypt.listen = vec!["127.0.0.1:0".parse().unwrap()];
    config.letsencrypt.state_path = directory.join("state.redb");
    config.letsencrypt.directory_url = "https://127.0.0.1:9/directory".into();
    config
}

fn certificate(start: i64, end: i64) -> Result<CertificateMaterial, Box<dyn std::error::Error>> {
    let mut parameters = CertificateParams::new(vec!["example.com".into()])?;
    parameters.not_before = time::OffsetDateTime::from_unix_timestamp(start)?;
    parameters.not_after = time::OffsetDateTime::from_unix_timestamp(end)?;
    let (certificate, key) = material(parameters)?;
    Ok(CertificateMaterial {
        chain: vec![certificate.as_ref().to_vec()],
        private_key_pkcs8: Zeroizing::new(key.secret_der().to_vec()),
    })
}

#[test]
fn unmanaged_load_never_reads_trust_opens_state_or_binds_listeners() -> TestResult {
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
        let mut config = Config::default();
        config.letsencrypt.listen = vec![occupied.local_addr()?];
        config.letsencrypt.ca_certificates_path = Some(directory.path().join("missing.pem"));
        config.letsencrypt.state_path = directory.path().join("never-created/state.redb");
        let hosts = Hosts::new(&config.hosts, None)?;
        assert!(AcmeServices::load(&config, hosts).await?.is_none());
        assert!(!directory.path().join("never-created").exists());
        Ok(())
    })
}

#[test]
fn installer_transfers_exact_prepared_validity_without_time_admission() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = config(directory.path());
    let hosts = Hosts::new(&config.hosts, None)?;
    let installer = HostInstaller {
        hosts: hosts.clone(),
    };
    let host = managed_hosts(&config)?.remove(0);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    for (start, end) in [
        (now - 200, now - 100),
        (now + 100, now + 200),
        (now - 100, now + 100),
    ] {
        let material = certificate(start, end)?;
        let prepared = installer
            .prepare(&host, &material)
            .map_err(|_| "prepare failed")?;
        assert_eq!(prepared.validity.not_before_unix, start as u64);
        assert_eq!(prepared.validity.not_after_unix, end as u64);
        assert_eq!(prepared.candidate.validity(), (start as u64, end as u64));
        if start > now || end <= now {
            assert!(
                hosts
                    .prepare_managed_certificate(
                        "example.com",
                        material
                            .chain
                            .iter()
                            .cloned()
                            .map(CertificateDer::from)
                            .collect(),
                        PrivatePkcs8KeyDer::from(material.private_key_pkcs8.to_vec()).into()
                    )
                    .is_err()
            );
        }
        installer.activate(prepared.candidate);
    }
    assert!(hosts.certified_key("example.com").is_some());
    let mut chain = certificate(now - 100, now + 100)?;
    let mut issuer = certificate(now - 50, now + 50)?;
    chain.chain.push(issuer.chain.remove(0));
    let prepared = installer
        .prepare(&host, &chain)
        .map_err(|_| "chain prepare failed")?;
    assert_eq!(
        prepared.candidate.validity(),
        ((now - 50) as u64, (now + 50) as u64)
    );
    assert_eq!(prepared.validity.not_before_unix, (now - 50) as u64);
    assert_eq!(prepared.validity.not_after_unix, (now + 50) as u64);
    Ok(())
}

#[test]
fn cache_installs_before_service_poll_and_shares_one_owner_across_host_clones() -> TestResult {
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let config = config(directory.path());
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let store = StateStore::open(
            config.letsencrypt.state_path.clone(),
            config.letsencrypt.directory_url.clone(),
        )
        .await?;
        store
            .save_host(StoredHost {
                host: managed_hosts(&config)?.remove(0),
                certificate: Some(StoredCertificate {
                    replaces: None,
                    material: certificate(now - 100, now + 1000)?,
                    not_before_unix: (now - 100) as u64,
                    not_after_unix: (now + 1000) as u64,
                    renew_at_unix: (now + 500) as u64,
                    ari_check_at_unix: (now + 500) as u64,
                    fallback_at_unix: (now + 500) as u64,
                    ari_window: None,
                    ari_failures: 0,
                }),
                order: None,
                retry: RetryState {
                    failures: 0,
                    not_before_unix: 0,
                },
            })
            .await?;
        drop(store);
        let hosts = Hosts::new(&config.hosts, None)?;
        let mut services = AcmeServices::load(&config, hosts.clone())
            .await?
            .ok_or("missing services")?;
        let expected = hosts
            .certified_key("example.com")
            .ok_or("cache was not installed")?;
        for _ in 0..8 {
            let worker = hosts.clone();
            assert!(Arc::ptr_eq(
                &expected,
                &worker
                    .certified_key("example.com")
                    .ok_or("worker missing certificate")?
            ));
        }
        assert!(
            StateStore::open(
                config.letsencrypt.state_path.clone(),
                config.letsencrypt.directory_url.clone()
            )
            .await
            .is_err()
        );
        assert!(hosts.tls_handshake("example.com").await.is_some());
        let deadline = Instant::now() + Duration::from_millis(100);
        services.run(async { deadline }).await?;
        services.drain(deadline).await?;
        Ok(())
    })
}

#[test]
fn startup_failure_releases_bound_listener_and_open_cache() -> TestResult {
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let mut config = config(directory.path());
        let (_reservation, address) = reserve_listener_address()?;
        config.letsencrypt.listen = vec![address];
        config.letsencrypt.ca_certificates_path = Some(directory.path().join("missing-trust.pem"));
        let hosts = Hosts::new(&config.hosts, None)?;
        let managed = managed_hosts(&config)?;
        let challenges = Challenges::new(&managed)?;
        let http = Http01Server::bind(&config.letsencrypt.listen, challenges.clone()).await?;
        assert_eq!(http.local_addrs()?, [address]);
        assert_eq!(
            bind_reusable_listener(address).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        let error = AcmeServices::load_bound(&config, hosts, managed, challenges, http)
            .await
            .err()
            .ok_or("unexpected startup success")?;
        let RunError::Acme {
            phase: "load",
            source,
        } = error
        else {
            return Err("unexpected startup failure".into());
        };
        let Some(ManagerError::Transport(error)) = source.downcast_ref::<ManagerError>() else {
            return Err("unexpected manager failure".into());
        };
        assert_eq!(error.kind(), AcmeErrorKind::InvalidCaBundle);
        let _listener =
            bind_released_listener(address, Instant::now() + Duration::from_secs(2)).await?;
        assert!(config.letsencrypt.state_path.exists());
        let _store = StateStore::open(
            config.letsencrypt.state_path,
            config.letsencrypt.directory_url,
        )
        .await?;
        Ok(())
    })
}

#[test]
fn loaded_unstarted_service_releases_sockets_and_can_drain_with_expired_deadline() -> TestResult {
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let mut config = config(directory.path());
        let (_reservation, address) = reserve_listener_address()?;
        config.letsencrypt.listen = vec![address];
        let hosts = Hosts::new(&config.hosts, None)?;
        let mut services = AcmeServices::load(&config, hosts)
            .await?
            .ok_or("missing service")?;
        assert_eq!(
            services
                .http
                .as_ref()
                .ok_or("missing HTTP")?
                .local_addrs()?,
            [address]
        );
        assert_eq!(
            bind_reusable_listener(address).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        services.drain(Instant::now()).await?;
        let _listener =
            bind_released_listener(address, Instant::now() + Duration::from_secs(2)).await?;
        assert!(matches!(
            services.run(pending()).await,
            Err(RunError::Acme { .. })
        ));
        Ok(())
    })
}

#[test]
fn service_pair_detects_each_failure_panic_and_unexpected_exit_without_waiting_for_peer()
-> TestResult {
    Runtime::new()?.block_on(async {
        for manager in [false, true] {
            for outcome in ["panic", "failure", "exit"] {
                let service = async {
                    match outcome {
                        "panic" => panic!("TOKEN-KEY-PEM-JWS-PROBLEM-SENTINEL"),
                        "failure" => Err(io_failure(
                            "injected",
                            io::Error::other("TOKEN-KEY-PEM-JWS-PROBLEM-SENTINEL"),
                        )),
                        _ => Ok(()),
                    }
                };
                let result = if manager {
                    run_pair(pending(), service, || false).await
                } else {
                    run_pair(service, pending(), || false).await
                };
                let error = result.err().ok_or("unexpected success")?;
                assert!(matches!(error, RunError::Acme { .. }));
                assert!(!format!("{error:?} {error}").contains("SENTINEL"));
            }
        }
        Ok(())
    })
}

#[test]
fn responder_is_polled_before_manager_and_both_receive_the_same_deadline() -> TestResult {
    Runtime::new()?.block_on(async {
        let deadline = Instant::now() + Duration::from_millis(10);
        let order = std::cell::RefCell::new(Vec::new());
        let stop = async { deadline }.shared();
        let http_stop = stop.clone();
        let manager_stop = stop.clone();
        run_pair(
            async {
                order.borrow_mut().push("HTTP");
                assert_eq!(http_stop.await, deadline);
                Ok(())
            },
            async {
                order.borrow_mut().push("manager");
                assert_eq!(manager_stop.await, deadline);
                Ok(())
            },
            || stop.peek().is_some(),
        )
        .await?;
        assert_eq!(*order.borrow(), ["HTTP", "manager"]);
        Ok(())
    })
}

#[derive(Clone)]
struct Capture(Arc<PlMutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn captured_failures_never_retain_untrusted_details() -> TestResult {
    let capture = Capture(Arc::new(PlMutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let error = io_failure(
            "HTTP",
            io::Error::other("TOKEN-KEY-PEM-JWS-PROBLEM-SENTINEL"),
        );
        tracing::error!(phase = "HTTP", error = %error, "ACME service failed");
    });
    let bytes = capture.0.lock();
    let output = std::str::from_utf8(&bytes)?;
    assert!(output.contains("ACME service failed"));
    assert!(!output.contains("SENTINEL"));
    Ok(())
}

#[test]
fn startup_registers_signal_first_and_reuses_it_after_successful_load() -> TestResult {
    use std::cell::Cell;
    use std::task::Poll;
    Runtime::new()?.block_on(async {
        let polls = Cell::new(0);
        let stop = Cell::new(false);
        let mut signal = Box::pin(futures_util::future::poll_fn(|_| {
            polls.set(polls.get() + 1);
            if stop.get() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }));
        let mut deadline = None;
        let loaded = crate::startup_until_signal(
            async {
                assert_eq!(polls.get(), 1);
                Ok(7)
            },
            signal.as_mut(),
            &mut deadline,
        )
        .await?;
        assert_eq!(loaded, Some(7));
        assert!(deadline.is_none());
        stop.set(true);
        signal.await?;
        assert_eq!(polls.get(), 2);
        let load_polled = Cell::new(false);
        let loaded = crate::startup_until_signal(
            async {
                load_polled.set(true);
                Ok(())
            },
            async { Ok(()) },
            &mut deadline,
        )
        .await?;
        assert!(loaded.is_none());
        assert!(!load_polled.get());
        assert!(deadline.is_some());
        Ok(())
    })
}

#[test]
fn startup_signal_drops_partial_resources_and_late_cache_completion_cannot_activate() -> TestResult
{
    use std::cell::Cell;
    use std::task::Poll;
    Runtime::new()?.block_on(async {
        let capture = Capture(Arc::new(PlMutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let (_reservation, address) = reserve_listener_address()?;
        let listener = bind_reusable_listener(address)?;
        assert_eq!(
            bind_reusable_listener(address).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        let (complete, completed) = futures_channel::oneshot::channel::<()>();
        let started = Cell::new(false);
        let activated = Cell::new(false);
        let signal = futures_util::future::poll_fn(|context| {
            if started.get() {
                Poll::Ready(Ok(()))
            } else {
                context.waker().wake_by_ref();
                Poll::Pending
            }
        });
        let mut deadline = None;
        let loaded = crate::startup_until_signal(
            async {
                let _listener = listener;
                started.set(true);
                let _ = completed.await;
                activated.set(true);
                Ok(())
            },
            signal,
            &mut deadline,
        )
        .await?;
        assert!(loaded.is_none());
        assert!(started.get());
        assert!(complete.send(()).is_err());
        assert!(!activated.get());
        let _listener =
            bind_released_listener(address, Instant::now() + Duration::from_secs(2)).await?;
        assert!(deadline.is_some());
        assert!(!std::str::from_utf8(&capture.0.lock())?.contains("waiting for stop signal"));
        Ok(())
    })
}

#[test]
fn startup_signal_error_remains_primary_and_drops_the_load() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut deadline = None;
        let result = crate::startup_until_signal(
            pending::<Result<(), RunError>>(),
            async { Err(io::Error::other("signal registration failed")) },
            &mut deadline,
        )
        .await;
        assert!(matches!(result, Err(RunError::Signal(_))));
        assert!(deadline.is_some());
        Ok(())
    })
}

#[test]
fn managed_host_conversion_uses_configured_xmpp_names_and_strict_alabels() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut config = config(directory.path());
    let host = config.hosts.remove("example.com").ok_or("missing host")?;
    config.hosts.insert("bücher.example".into(), host);
    let managed = managed_hosts(&config)?;
    assert_eq!(managed.len(), 1);
    assert_eq!(managed[0].xmpp_domain, "bücher.example");
    assert_eq!(managed[0].dns_name, "xn--bcher-kva.example");
    config
        .hosts
        .insert("localhost".into(), HostConfig::default());
    assert_eq!(managed_hosts(&config)?.len(), 1);
    Ok(())
}
