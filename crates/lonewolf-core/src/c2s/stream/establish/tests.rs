// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdTcpStream};
use std::num::NonZeroUsize;
use std::time::Duration;

use compio::runtime::Runtime;
use futures_util::FutureExt;
use lonewolf_util::arena::GlobalChunkAllocator;
use rustls::pki_types::ServerName;

use super::*;
use crate::c2s::metrics::C2sWorkerMetrics;
use crate::c2s::stream::StreamTimeouts;
use crate::config::limits::C2sLimitProfile;
use crate::config::{AuthMechanisms, Config};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const TIMEOUT: Duration = Duration::from_secs(5);

struct Wire {
    socket: StdTcpStream,
    first: Option<u8>,
}
impl Read for Wire {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.socket.read(bytes)?;
        if count > 0 && self.first.is_none() {
            self.first = Some(bytes[0]);
        }
        Ok(count)
    }
}
impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

#[test]
fn direct_client_hello_requires_known_sni_and_role_correct_optional_alpn() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(TIMEOUT * 4, async {
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, None)?;
        for (name, protocols, success) in [
            (Some("localhost"), vec![], true),
            (Some("LOCALHOST"), vec![b"xmpp-client".to_vec()], true),
            (
                Some("localhost"),
                vec![b"xmpp-server".to_vec(), b"xmpp-client".to_vec()],
                true,
            ),
            (Some("localhost"), vec![b"xmpp-server".to_vec()], false),
            (Some("unknown.test"), vec![], false),
            (None, vec![], false),
        ] {
            let listener =
                crate::connection::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            let address = listener.local_addr()?;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(hosts.certified_key("localhost").ok_or("missing key")?.cert[0].clone())?;
            let mut client = rustls::ClientConfig::builder_with_provider(hosts.crypto_provider())
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
            client.alpn_protocols = protocols;
            client.enable_sni = name.is_some();
            let client =
                std::thread::spawn(move || -> io::Result<(bool, Option<u8>, Option<Vec<u8>>)> {
                    let socket = StdTcpStream::connect(address)?;
                    socket.set_read_timeout(Some(TIMEOUT))?;
                    socket.set_write_timeout(Some(TIMEOUT))?;
                    let mut wire = Wire {
                        socket,
                        first: None,
                    };
                    let mut connection = rustls::ClientConnection::new(
                        Arc::new(client),
                        ServerName::try_from(name.unwrap_or("localhost"))
                            .map_err(io::Error::other)?,
                    )
                    .map_err(io::Error::other)?;
                    let mut result = Ok(());
                    while connection.is_handshaking() && result.is_ok() {
                        result = connection.complete_io(&mut wire).map(|_| ());
                    }
                    Ok((
                        result.is_ok(),
                        wire.first,
                        connection.alpn_protocol().map(<[_]>::to_vec),
                    ))
                });
            let (socket, _) = listener.accept().await?;
            let settings = StreamSettings::new(
                AuthMechanisms::ALL,
                &C2sLimitProfile::default(),
                StreamTimeouts {
                    establishment: TIMEOUT,
                    authentication: TIMEOUT,
                    binding: TIMEOUT,
                },
                NonZeroUsize::MIN,
                GlobalChunkAllocator,
                C2sWorkerMetrics::detached(),
            );
            let result =
                compio::time::timeout(TIMEOUT, accept_direct(socket, &hosts, &settings)).await?;
            assert_eq!(result.is_ok(), success, "{name:?}");
            if let Ok(accepted) = result {
                assert_eq!(accepted.selected_host, "localhost");
                assert_eq!(
                    accepted.server_end_point,
                    hosts
                        .tls_server_end_point("localhost")
                        .ok_or("missing binding")?
                );
            }
            let (completed, first, alpn) = client.join().map_err(|_| "client panicked")??;
            assert_eq!(completed, success, "{name:?}");
            assert!(first.is_none_or(|byte| (20..=23).contains(&byte)));
            if completed && alpn.is_some() {
                assert_eq!(alpn.as_deref(), Some(b"xmpp-client".as_slice()));
            }
            listener.close().await?;
        }
        Ok(())
    }))?
}

#[test]
fn direct_first_header_uses_sni_host_and_rejects_another_configured_host() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(TIMEOUT * 2, async {
        let hosts = crate::hosts::test_support::managed_hosts()?;
        let (certificate, key) = crate::hosts::test_support::material(
            rcgen::CertificateParams::new(vec!["example.com".into()])?,
        )?;
        hosts.prepare_managed_certificate("example.com", vec![certificate.clone()], key)?.activate();
        for (to, success) in [("", true), (" to='example.com'", true), (" to='localhost'", false)] {
            let listener = crate::connection::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            let address = listener.local_addr()?;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(certificate.clone())?;
            let client_config = Arc::new(rustls::ClientConfig::builder_with_provider(hosts.crypto_provider())
                .with_safe_default_protocol_versions()?.with_root_certificates(roots).with_no_client_auth());
            let client = std::thread::spawn(move || -> io::Result<String> {
                let socket = StdTcpStream::connect(address)?;
                socket.set_read_timeout(Some(TIMEOUT))?;
                socket.set_write_timeout(Some(TIMEOUT))?;
                let connection = rustls::ClientConnection::new(client_config, ServerName::try_from("example.com").map_err(io::Error::other)?).map_err(io::Error::other)?;
                let mut stream = rustls::StreamOwned::new(connection, socket);
                write!(stream, "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='2.0'{to}></stream:stream>")?;
                stream.flush()?;
                let mut response = String::new();
                stream.read_to_string(&mut response)?;
                Ok(response)
            });
            let (socket, _) = listener.accept().await?;
            let context = CloseContext {
                socket: socket.clone(),
                shutdown: futures_util::future::pending().boxed_local().shared(),
                phase_deadline: Some(Instant::now() + TIMEOUT),
            };
            let mut settings = StreamSettings::new(AuthMechanisms::ALL, &C2sLimitProfile::default(), StreamTimeouts {
                establishment: TIMEOUT, authentication: TIMEOUT, binding: TIMEOUT,
            }, NonZeroUsize::MIN, GlobalChunkAllocator, C2sWorkerMetrics::detached());
            settings.tls_mode = crate::config::TlsMode::Direct;
            let result = establish(socket, &hosts, &settings, context).await;
            assert_eq!(result.is_ok(), success);
            match result {
                Ok(mut established) => {
                    assert_eq!(established.session.host(), "example.com");
                    assert!(matches!(established.session.next_event().await, Ok(Some(StreamEvent::StreamEnd))));
                    assert_eq!(established.session.finish(CloseOutcome::StreamEnd).await, CloseOutcome::StreamEnd);
                }
                Err(outcome) => assert_eq!(outcome, CloseOutcome::HostUnknown),
            }
            let response = client.join().map_err(|_| "client panicked")??;
            assert!(response.contains("from='example.com'"), "{response}");
            assert!(!response.contains("<starttls"), "{response}");
            if success {
                assert!(response.contains("version='1.0'"), "{response}");
                assert!(response.contains("<mechanisms"), "{response}");
            } else {
                assert!(response.contains("<host-unknown"), "{response}");
            }
            listener.close().await?;
        }
        Ok(())
    }))?
}

#[test]
fn direct_establishment_timeout_and_shutdown_abort_before_xml() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(TIMEOUT, async {
        let hosts = Hosts::new(&Config::default().hosts, None)?;
        for shutdown in [false, true] {
            let listener = crate::connection::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            let mut peer = StdTcpStream::connect(listener.local_addr()?)?;
            peer.set_read_timeout(Some(TIMEOUT))?;
            let (socket, _) = listener.accept().await?;
            let signal = if shutdown {
                futures_util::future::ready(Instant::now()).boxed_local()
            } else {
                futures_util::future::pending().boxed_local()
            };
            let context = CloseContext {
                socket: socket.clone(),
                shutdown: signal.shared(),
                phase_deadline: Some(Instant::now() + if shutdown { TIMEOUT } else { Duration::ZERO }),
            };
            let mut settings = StreamSettings::new(AuthMechanisms::ALL, &C2sLimitProfile::default(), StreamTimeouts {
                establishment: TIMEOUT, authentication: TIMEOUT, binding: TIMEOUT,
            }, NonZeroUsize::MIN, GlobalChunkAllocator, C2sWorkerMetrics::detached());
            settings.tls_mode = crate::config::TlsMode::Direct;
            let result = establish(socket, &hosts, &settings, context).await;
            assert!(matches!(result, Err(outcome) if outcome == if shutdown { CloseOutcome::SystemShutdown } else { CloseOutcome::EstablishmentTimeout }));
            assert_eq!(peer.read(&mut [0; 1])?, 0);
            listener.close().await?;
        }
        Ok(())
    }))?
}
