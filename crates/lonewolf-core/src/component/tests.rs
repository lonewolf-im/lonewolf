// SPDX-License-Identifier: Apache-2.0

use super::*;
use futures_util::FutureExt as _;
use futures_util::future::{Either, select};
use lonewolf_xmpp::parser::StreamEvent;
use std::pin::pin;

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

fn cancelled_connection(
    poll_read: bool,
    tls_mode: ComponentTlsMode,
) -> Result<(), Box<dyn std::error::Error>> {
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
        let router = Router::new(hosts.clone(), LocalRouter::new(GlobalChunkAllocator));
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
                hosts,
                tls_mode,
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
    cancelled_connection(false, ComponentTlsMode::None)
}

#[test]
fn pending_negotiation_records_shutdown_once_and_releases_socket_and_permit()
-> Result<(), Box<dyn std::error::Error>> {
    cancelled_connection(true, ComponentTlsMode::None)
}

fn cancelled_authenticated_stream(closing: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::fmt::Write as _;
    use std::future::poll_fn;
    use std::num::NonZeroUsize;
    use std::task::Poll;

    use compio::io::compat::{AsyncReadStream, AsyncStream};
    use futures_util::io::AsyncWriteExt as _;
    use futures_util::stream::FuturesUnordered;
    use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
    use lonewolf_xmpp::parser::{ParserConfig, XmppParser};
    use sha1::{Digest as _, Sha1};
    use tokio::io::BufReader;
    use tokio_util::compat::FuturesAsyncReadCompatExt as _;

    use crate::connection::socket::{ConnectionSocket, ConnectionTask};
    use crate::hosts::Hosts;
    use crate::router::{Router, local::LocalRouter};

    compio::runtime::Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let mut config = crate::Config {
            components: toml::from_str("[domains.'muc.localhost']\nsecret='component-test-secret-0001'")?,
            ..crate::Config::default()
        };
        config.limits.components.max_inbound_connections = NonZeroUsize::MIN;
        let hosts = Hosts::new(&config.hosts, None)?;
        let router = Router::new(hosts.clone(), LocalRouter::new(GlobalChunkAllocator));
        let directory = tempfile::tempdir()?;
        let metrics = ComponentMetrics::new(1, 1);
        let registry = ComponentRegistry::new(&config.components, credentials::load(&config.components)?, &config.limits.components, Arc::clone(&metrics));
        let admission = Arc::new(AdmissionLimits { attempts: AttemptLimiter::new(&config.limits.components.connection_attempts_per_ip), global: GlobalLimit::new(1) });
        let handler = ComponentAcceptor { admission: Arc::clone(&admission), settings: Settings {
                hosts,
                tls_mode: crate::config::ComponentTlsMode::None,
            limits: config.limits.components.clone(), timeout: Duration::from_secs(30), registry: registry.clone(),
            services: ComponentServices { router: router.handle(), storage: RedbStorage::open(directory.path().join("state.redb"))?, allocator: GlobalChunkAllocator }, metrics: Arc::clone(&metrics),
        }};
        let listener = crate::connection::bind(([127, 0, 0, 1], 0).into()).await?;
        let peer = TcpStream::connect(listener.local_addr()?).await?;
        let (socket, address) = listener.accept().await?;
        let permit = handler.admit(address.ip()).await.map_err(|_| "admission rejected")?;
        let mut task = Box::pin(ConnectionTask { _socket: ConnectionSocket(socket.clone()), future: Box::pin(handler.serve(ListenerSlot { listener_id: 0, worker_id: 0 }, socket, permit, std::future::pending().boxed_local().shared())) });
        let mut writer = Box::pin(AsyncStream::new(peer.clone()));
        let mut reader = XmppParser::new(BufReader::new(Box::pin(AsyncReadStream::new(peer.clone())).compat()), ParserConfig { max_stanza_bytes: config.limits.components.max_stanza_bytes, arena: ArenaConfig::default() }, GlobalChunkAllocator);
        let authenticate = async {
            writer.write_all(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:component:accept' to='muc.localhost'>").await?;
            writer.flush().await?;
            let Some(StreamEvent::StreamStart { header, .. }) = reader.next_event().await? else { return Err("missing response header".into()); };
            let header = header.value().resolve(header.arena())?;
            let id = header.attribute("id", "")?.ok_or("missing stream ID")?;
            let mut digest = Sha1::new();
            digest.update(id.as_bytes());
            digest.update(b"component-test-secret-0001");
            let mut xml = String::from("<handshake>");
            for byte in digest.finalize() { write!(xml, "{byte:02x}")?; }
            xml.push_str("</handshake>");
            writer.write_all(xml.as_bytes()).await?;
            writer.flush().await?;
            let Some(StreamEvent::Element(handshake)) = reader.next_event().await? else { return Err("missing handshake acknowledgment".into()); };
            let handshake = handshake.value().resolve(handshake.arena())?;
            assert_eq!(handshake.name(), "handshake");
            assert_eq!(handshake.namespace(), "jabber:component:accept");
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        match select(task.as_mut(), pin!(authenticate)).await {
            Either::Left(_) => return Err("connection ended before authentication".into()),
            Either::Right((result, _)) => result?,
        }
        poll_fn(|cx| {
            assert!(task.as_mut().poll(cx).is_pending());
            if metrics.shutdown_state().streams == 1 { Poll::Ready(()) } else { Poll::Pending }
        }).await;
        assert!(matches!(registry.attach("muc.localhost"), Err(registry::AttachError::Conflict)));
        let outcome = if closing {
            let terminal = async {
                writer.write_all(b"<handshake/>").await?;
                writer.flush().await?;
                let Some(StreamEvent::Element(error)) = reader.next_event().await? else { return Err("missing stream error".into()); };
                let error = error.value().resolve(error.arena())?;
                assert_eq!(error.name(), "error");
                assert_eq!(error.namespace(), "http://etherx.jabber.org/streams");
                let mut children = error.children()?;
                let Some(Ok(lonewolf_xmpp::stanza::NodeRef::Element(condition))) = children.next() else { return Err("missing stream error condition".into()); };
                assert_eq!(condition.name(), "unsupported-stanza-type");
                assert!(children.next().is_none());
                assert!(matches!(reader.next_event().await?, Some(StreamEvent::StreamEnd)));
                Ok::<(), Box<dyn std::error::Error>>(())
            };
            match select(task.as_mut(), pin!(terminal)).await {
                Either::Left(_) => return Err("connection ended before the peer footer wait".into()),
                Either::Right((result, _)) => result?,
            }
            assert!(futures_util::poll!(task.as_mut()).is_pending());
            let active = FuturesUnordered::new();
            active.push(*std::pin::Pin::into_inner(task));
            let error = crate::connection::drain_connections(active, Instant::now(), ListenerKind::Component, |_| panic!("connection completed before the outer deadline")).await.err().ok_or("outer deadline did not expire")?;
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            assert_eq!(error.to_string(), "component connections exceeded shutdown deadline");
            StreamClose::UnsupportedStanzaType
        } else {
            drop(task);
            StreamClose::Shutdown
        };
        let compio::buf::BufResult(count, _) = compio::io::AsyncRead::read(&mut &peer, vec![0; 1]).await;
        assert_eq!(count?, 0);
        let state = metrics.shutdown_state();
        assert_eq!(state.connections, 0);
        assert_eq!(state.streams, 0);
        assert_eq!(state.authentication_success, 1);
        assert_eq!(state.authentication_total, 1);
        assert_eq!(state.streams_closed_total, 1);
        assert_eq!(state.streams_closed_shutdown, u64::from(!closing));
        let mut root = prometheus_client::registry::Registry::default();
        metrics.register(root.sub_registry_with_prefix("lonewolf"));
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &root)?;
        let sample = format!("lonewolf_component_streams_closed_total{{outcome=\"{}\"}} 1", outcome.as_str());
        assert!(output.lines().any(|line| line == sample), "missing {sample}: {output}");
        assert_eq!(output.lines().filter(|line| line.starts_with("lonewolf_component_streams_closed_total{")).count(), 1);
        assert_eq!(admission.global.active(), 0);
        let restored = handler.admit(address.ip()).await.map_err(|_| "permit was not restored")?;
        drop(restored);
        drop(registry.attach("muc.localhost").map_err(|_| "domain attachment was not released")?);
        listener.close().await?;
        Ok(())
    }))?
}

#[test]
fn authenticated_pending_read_cancellation_records_shutdown_and_releases_all_owners()
-> Result<(), Box<dyn std::error::Error>> {
    cancelled_authenticated_stream(false)
}

#[test]
fn outer_deadline_during_closure_records_the_selected_outcome_and_releases_all_owners()
-> Result<(), Box<dyn std::error::Error>> {
    cancelled_authenticated_stream(true)
}

#[test]
fn pending_direct_tls_acceptor_records_shutdown_once_and_restores_admission()
-> Result<(), Box<dyn std::error::Error>> {
    cancelled_connection(true, ComponentTlsMode::Direct)
}
