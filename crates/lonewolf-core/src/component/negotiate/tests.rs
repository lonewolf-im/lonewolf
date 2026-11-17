// SPDX-License-Identifier: Apache-2.0

use super::*;
use futures_rustls::TlsConnector;
use futures_util::future::join;
use futures_util::io::AsyncWriteExt as _;
use futures_util::poll;
use lonewolf_util::arena::GlobalChunkAllocator;

use crate::admission::global_limit::GlobalLimit;
use crate::component::{ComponentServices, credentials, registry::ComponentRegistry};
use crate::connection::socket::{ConnectionSocket, ConnectionTask};
use crate::hosts::Hosts;
use crate::router::{Router, local::LocalRouter};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn established_tls_without_application_bytes(shutdown: bool, cancel_close: bool) -> TestResult {
    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(
        Duration::from_secs(5),
        async {
            let config = crate::Config {
                components: toml::from_str(
                    "[domains.'muc.localhost']\nsecret='component-test-secret-0001'",
                )?,
                ..crate::Config::default()
            };
            let hosts = Hosts::new(&config.hosts, None)?;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(
                hosts
                    .certified_key("localhost")
                    .ok_or("missing certificate")?
                    .cert[0]
                    .clone(),
            )?;
            let client_config =
                rustls::ClientConfig::builder_with_provider(hosts.crypto_provider())
                    .with_safe_default_protocol_versions()?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client_config));
            let router = Router::new(hosts.clone(), LocalRouter::new(GlobalChunkAllocator));
            let directory = tempfile::tempdir()?;
            let metrics = ComponentMetrics::new(1, 1);
            let settings = Settings {
                registry: ComponentRegistry::new(
                    &config.components,
                    credentials::load(&config.components)?,
                    &config.limits.components,
                    Arc::clone(&metrics),
                ),
                limits: config.limits.components,
                hosts,
                tls_mode: ComponentTlsMode::Direct,
                timeout: Duration::from_secs(30),
                services: ComponentServices {
                    router: router.handle(),
                    storage: lonewolf_storage::RedbStorage::open(
                        directory.path().join("state.redb"),
                    )?,
                    allocator: GlobalChunkAllocator,
                },
                metrics: Arc::clone(&metrics),
            };
            let listener = crate::connection::bind(([127, 0, 0, 1], 0).into()).await?;
            let peer = TcpStream::connect(listener.local_addr()?).await?;
            let (socket, _) = listener.accept().await?;
            let admission = GlobalLimit::new(1);
            let permit = admission
                .reserve(Instant::now())
                .map_err(|_| "admission rejected")?;
            let gauge = metrics.connection_opened();
            let accounting = Accounting::new(Arc::clone(&metrics));
            let (server, client) = join(
                transport(&socket, &settings),
                connector.connect(
                    "localhost".try_into()?,
                    Box::pin(AsyncStream::new(peer.clone())),
                ),
            )
            .await;
            let connection =
                server.map_err(|failure| format!("TLS failed: {:?}", failure.error))?;
            let mut client = client?;
            let mut state = Negotiation {
                connection: Some(connection),
                progress: Progress {
                    domain: None,
                    header_sent: false,
                    peer_footer: false,
                },
                shutdown_deadline: None,
            };
            let signal = if shutdown {
                std::future::ready(Instant::now() + Duration::from_secs(4))
                    .boxed_local()
                    .shared()
            } else {
                std::future::pending().boxed_local().shared()
            };
            let result = {
                let (reader, writer) = state.connection.as_mut().ok_or("missing connection")?;
                let mut xml = Box::pin(run(reader, writer, &settings, &mut state.progress));
                assert!(poll!(xml.as_mut()).is_pending());
                let (result, deadline) =
                    select_terminal(xml, signal.clone(), accounting.started).await;
                state.shutdown_deadline = deadline;
                result
            };
            let expected = if shutdown {
                AuthOutcome::Shutdown
            } else {
                AuthOutcome::Timeout
            };
            assert_eq!(
                result
                    .as_ref()
                    .err()
                    .ok_or("unexpected authentication")?
                    .outcome
                    .as_str(),
                expected.as_str()
            );
            let mut task = Box::pin(ConnectionTask {
                _socket: ConnectionSocket(socket.clone()),
                future: Box::pin(async {
                    let _permit = permit;
                    let _gauge = gauge;
                    assert!(
                        finish(&socket, &settings, signal, 1, accounting, state, result)
                            .await
                            .is_err()
                    );
                }),
            });
            let close = async {
                let mut xml = Vec::new();
                let mut byte = [0];
                while !xml.ends_with(b"</stream:stream>") {
                    assert_eq!(client.read(&mut byte).await?, 1);
                    xml.push(byte[0]);
                }
                let xml = std::str::from_utf8(&xml)?;
                assert!(xml.starts_with("<?xml version='1.0'?><stream:stream"));
                assert!(!xml.contains(" from="));
                assert!(xml.contains(if shutdown {
                    "system-shutdown"
                } else {
                    "connection-timeout"
                }));
                if !cancel_close {
                    client.write_all(b"</stream:stream>").await?;
                    client.flush().await?;
                    assert_eq!(client.read(&mut byte).await?, 0);
                }
                Ok::<(), Box<dyn std::error::Error>>(())
            };
            if cancel_close {
                match select(pin!(close), task.as_mut()).await {
                    Either::Left((result, _)) => result?,
                    Either::Right(_) => return Err("close completed before peer footer".into()),
                }
            } else {
                let (result, ()) = join(close, task.as_mut()).await;
                result?;
            }
            drop(task);
            if cancel_close {
                match client.read(&mut [0]).await {
                    Ok(count) => assert_eq!(count, 0),
                    Err(error) => assert!(matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    )),
                }
            }
            drop(client);
            assert_eq!(admission.active(), 0);
            drop(
                admission
                    .reserve(Instant::now())
                    .map_err(|_| "admission not restored")?,
            );
            let mut root = prometheus_client::registry::Registry::default();
            metrics.register(root.sub_registry_with_prefix("lonewolf"));
            let mut output = String::new();
            prometheus_client::encoding::text::encode(&mut output, &root)?;
            for sample in [
                format!(
                    "lonewolf_component_authentications_total{{outcome=\"{}\"}} 1",
                    expected.as_str()
                ),
                "lonewolf_component_negotiation_duration_seconds_count 1".into(),
                "lonewolf_component_connections 0".into(),
                "lonewolf_component_streams 0".into(),
            ] {
                assert!(
                    output.lines().any(|line| line == sample),
                    "missing {sample}: {output}"
                );
            }
            assert_eq!(
                output
                    .lines()
                    .filter(|line| line.starts_with("lonewolf_component_authentications_total{"))
                    .count(),
                1
            );
            assert!(!output.contains("lonewolf_component_streams_closed_total"));
            listener.close().await?;
            Ok(())
        },
    ))?
}

#[test]
fn zero_application_bytes_after_server_tls_completion_timeout_closes_inside_tls() -> TestResult {
    established_tls_without_application_bytes(false, false)
}

#[test]
fn zero_application_bytes_after_server_tls_completion_shutdown_closes_inside_tls() -> TestResult {
    established_tls_without_application_bytes(true, false)
}

#[test]
fn cancelled_post_tls_close_preserves_timeout_and_releases_admission() -> TestResult {
    established_tls_without_application_bytes(false, true)
}

#[test]
fn cancelled_post_tls_close_preserves_shutdown_and_releases_admission() -> TestResult {
    established_tls_without_application_bytes(true, true)
}
