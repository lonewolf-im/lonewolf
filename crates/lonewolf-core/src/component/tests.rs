// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn accepted_socket_enables_keepalive() -> Result<(), Box<dyn std::error::Error>> {
    compio::runtime::Runtime::new()?.block_on(async {
        let listener = compio::net::TcpListener::bind("127.0.0.1:0").await?;
        let _client = TcpStream::connect(listener.local_addr()?).await?;
        let (socket, _) = listener.accept().await?;
        set_keepalive(&socket, 1);
        assert!(socket2::SockRef::from(&socket).keepalive()?);
        Ok(())
    })
}

fn cancelled_connection(poll_read: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read as _;
    use std::num::NonZeroUsize;

    use futures_util::poll;
    use lonewolf_util::arena::GlobalChunkAllocator;

    use crate::connection::socket::{ConnectionSocket, ConnectionTask};
    use crate::hosts::Hosts;
    use crate::router::{Router, local::LocalRouter};

    compio::runtime::Runtime::new()?.block_on(async {
        let mut config = crate::Config {
            components: toml::from_str(
                "[domains.'muc.localhost']\nsecret='component-test-secret-0001'",
            )?,
            ..crate::Config::default()
        };
        config.limits.components.max_inbound_connections = NonZeroUsize::MIN;
        let hosts = Hosts::new(&config.hosts, None)?;
        let router = Router::new(hosts, LocalRouter::new(GlobalChunkAllocator));
        let directory = tempfile::tempdir()?;
        let metrics = ComponentMetrics::new(1, 1);
        let registry = ComponentRegistry::new(
            &config.components,
            credentials::load(&config.components)?,
            &config.limits.components,
            Arc::clone(&metrics),
        );
        let admission = Arc::new(AdmissionLimits {
            attempts: AttemptLimiter::new(&config.limits.components.connection_attempts_per_ip),
            global: GlobalLimit::new(1),
        });
        let handler = ComponentAcceptor {
            admission: Arc::clone(&admission),
            settings: Settings {
                limits: config.limits.components.clone(),
                timeout: Duration::from_secs(30),
                registry,
                services: ComponentServices {
                    router: router.handle(),
                    storage: RedbStorage::open(directory.path().join("state.redb"))?,
                    allocator: GlobalChunkAllocator,
                },
                metrics: Arc::clone(&metrics),
            },
        };
        let listener = crate::connection::bind(([127, 0, 0, 1], 0).into()).await?;
        let mut peer = std::net::TcpStream::connect(listener.local_addr()?)?;
        peer.set_read_timeout(Some(Duration::from_secs(5)))?;
        let (socket, address) = listener.accept().await?;
        let permit = handler
            .admit(address.ip())
            .await
            .map_err(|_| "admission rejected")?;
        let mut task = Box::pin(ConnectionTask {
            _socket: ConnectionSocket(socket.clone()),
            future: Box::pin(handler.serve(
                ListenerSlot {
                    listener_id: 0,
                    worker_id: 0,
                },
                socket,
                permit,
                std::future::pending().boxed_local().shared(),
            )),
        });
        assert_eq!(admission.global.active(), 1);
        if poll_read {
            assert!(poll!(task.as_mut()).is_pending());
        }
        drop(task);
        assert_eq!(peer.read(&mut [0; 1])?, 0);
        assert_eq!(admission.global.active(), 0);
        let restored = handler
            .admit(address.ip())
            .await
            .map_err(|_| "permit was not restored")?;
        drop(restored);
        let mut root = prometheus_client::registry::Registry::default();
        metrics.register(root.sub_registry_with_prefix("lonewolf"));
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &root)?;
        for sample in [
            "lonewolf_component_connections_accepted_total{listener=\"0\"} 1",
            "lonewolf_component_authentications_total{outcome=\"shutdown\"} 1",
            "lonewolf_component_negotiation_duration_seconds_count 1",
            "lonewolf_component_connections 0",
            "lonewolf_component_streams 0",
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
    })
}

#[test]
fn unpolled_admitted_connection_records_shutdown_once_and_releases_socket_and_permit()
-> Result<(), Box<dyn std::error::Error>> {
    cancelled_connection(false)
}

#[test]
fn pending_negotiation_records_shutdown_once_and_releases_socket_and_permit()
-> Result<(), Box<dyn std::error::Error>> {
    cancelled_connection(true)
}
