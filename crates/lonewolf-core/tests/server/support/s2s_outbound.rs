// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::process::{Server, TIMEOUT};
use crate::support::{self, FOOTER, Fixture, Peer, Result};

pub const RESPONSE: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='peer.test' to='local.test'>";
pub const FEATURES: &str = "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>";
pub const EXTERNAL: &str = "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>";
pub type ReceivingPeer = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

#[derive(Debug)]
struct InitiatorVerifier(Arc<dyn ServerCertVerifier>, ServerName<'static>);
impl ClientCertVerifier for InitiatorVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        self.0
            .verify_server_cert(leaf, intermediates, &self.1, &[], now)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

pub fn config(
    fixture: &Fixture,
    name: &str,
    client_only: bool,
    untrusted: bool,
) -> Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls_graviola::default_provider());
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        fixture.roots()?,
        Arc::clone(&provider),
    )
    .build()?;
    let (cert, key) = if untrusted {
        Fixture::new()?.identity(name, client_only)?
    } else {
        fixture.identity(name, client_only)?
    };
    Ok(Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(Arc::new(InitiatorVerifier(
                verifier,
                ServerName::try_from("local.test")?,
            )))
            .with_single_cert(vec![cert], key)?,
    ))
}

pub fn expiring_config(
    fixture: &Fixture,
    until: time::OffsetDateTime,
) -> Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls_graviola::default_provider());
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        fixture.roots()?,
        Arc::clone(&provider),
    )
    .build()?;
    let (cert, key) = fixture.identity_until("peer.test", false, Some(until))?;
    Ok(Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(Arc::new(InitiatorVerifier(
                verifier,
                ServerName::try_from("local.test")?,
            )))
            .with_single_cert(vec![cert], key)?,
    ))
}

pub fn listener() -> Result<TcpListener> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener)
}

pub struct RefusedEndpoint {
    accepted: TcpStream,
    _keeper: TcpStream,
}

pub fn refused() -> Result<RefusedEndpoint> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(false)?;
    socket.set_reuse_port(false)?;
    socket.bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())?;
    socket.listen(1)?;
    let listener: TcpListener = socket.into();
    let keeper = TcpStream::connect_timeout(&listener.local_addr()?, TIMEOUT)?;
    let accepted = accept(&listener)?;
    drop(listener);
    let endpoint = RefusedEndpoint {
        accepted,
        _keeper: keeper,
    };
    let address = address(&endpoint)?;
    let deadline = Instant::now() + TIMEOUT;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "listener teardown timed out"))
    };
    loop {
        let connection = TcpStream::connect_timeout(&address, remaining()?);
        remaining()?;
        match connection {
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => return Ok(endpoint),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::NotConnected
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
            Ok(mut probe) => {
                let mut byte = [0];
                loop {
                    probe.set_read_timeout(Some(remaining()?))?;
                    let received = probe.read(&mut byte);
                    remaining()?;
                    match received {
                        Ok(0) => break,
                        Ok(_) => return Err("refusal probe received application data".into()),
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::ConnectionAborted
                                    | io::ErrorKind::NotConnected
                            ) =>
                        {
                            break;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
    }
}

pub fn address(endpoint: &RefusedEndpoint) -> Result<SocketAddr> {
    Ok(endpoint.accepted.local_addr()?)
}

pub fn start(fixture: &Fixture, endpoints: &[SocketAddr], extra: &str) -> Result<(Server, Peer)> {
    let route = endpoints
        .iter()
        .map(|address| format!("'{address}'"))
        .collect::<Vec<_>>()
        .join(",");
    let (server, address) =
        fixture.server(&format!("[s2s.routes]\n'peer.test'=[{route}]\n{extra}"))?;
    let (mut peer, _) = support::start_tls(address, fixture.client(Some("peer.test"), false)?)?;
    support::external(&mut peer, support::HEADER)?;
    support::success(&mut peer, support::AUTH)?;
    Ok((server, peer))
}

pub fn trigger(peer: &mut Peer, id: &str) -> Result {
    peer.write_all(format!("<message type='chat' from='a@peer.test/remote' to='local.test' id='{id}'><body>payload</body></message>").as_bytes())?;
    peer.flush()?;
    Ok(())
}

pub fn accept(listener: &TcpListener) -> Result<TcpStream> {
    let deadline = Instant::now() + TIMEOUT;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "accept timed out"))
    };
    listener.set_nonblocking(true)?;
    loop {
        remaining()?;
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(TIMEOUT))?;
                stream.set_write_timeout(Some(TIMEOUT))?;
                stream.set_nodelay(true)?;
                remaining()?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        let budget = remaining()?;
        let milliseconds = i32::try_from(
            budget.as_millis() + u128::from(!budget.subsec_nanos().is_multiple_of(1_000_000)),
        )?;
        let mut readiness = nix::libc::pollfd {
            fd: listener.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        // SAFETY: The live listener and initialized stack descriptor outlive this one-entry poll.
        let result = unsafe { nix::libc::poll(&mut readiness, 1, milliseconds) };
        let error = (result < 0).then(io::Error::last_os_error);
        remaining()?;
        if let Some(error) = error {
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if readiness.revents & nix::libc::POLLNVAL != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid listener").into());
        }
        if readiness.revents & (nix::libc::POLLERR | nix::libc::POLLHUP) != 0 {
            return Err(listener
                .take_error()?
                .unwrap_or_else(|| io::Error::other("listener readiness failed"))
                .into());
        }
        if result > 0 && readiness.revents & nix::libc::POLLIN == 0 {
            return Err(io::Error::other("unexpected listener readiness").into());
        }
    }
}

pub fn header(peer: &mut impl Read) -> Result<String> {
    let mut header = support::until(peer, "<stream:stream")?;
    header.push_str(&support::until(peer, ">")?);
    assert_eq!(
        header,
        "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='local.test' to='peer.test' version='1.0' xml:lang='en'>"
    );
    Ok(header)
}

pub fn starttls(stream: &mut TcpStream) -> Result {
    header(stream)?;
    stream.write_all(format!("{RESPONSE}{FEATURES}").as_bytes())?;
    assert_eq!(support::until(stream, "/>")?, support::STARTTLS);
    stream.write_all("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>".as_bytes())?;
    Ok(())
}

pub fn tls(
    stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    fixture: &Fixture,
) -> Result<ReceivingPeer> {
    let mut peer = rustls::StreamOwned::new(rustls::ServerConnection::new(config)?, stream);
    peer.conn.complete_io(&mut peer.sock)?;
    assert_eq!(peer.conn.server_name(), Some("peer.test"));
    assert_eq!(
        peer.conn
            .peer_certificates()
            .ok_or("missing initiating certificate")?,
        std::slice::from_ref(&fixture.local_certificate)
    );
    Ok(peer)
}

pub fn auth(peer: &mut ReceivingPeer) -> Result {
    header(peer)?;
    peer.write_all(format!("{RESPONSE}{EXTERNAL}").as_bytes())?;
    assert_eq!(
        support::until(peer, "</auth>")?,
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>bG9jYWwudGVzdA==</auth>"
    );
    Ok(())
}

pub fn ready(peer: &mut ReceivingPeer) -> Result {
    peer.write_all("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>".as_bytes())?;
    header(peer)?;
    peer.write_all(format!("{RESPONSE}<stream:features/>").as_bytes())?;
    peer.flush()?;
    Ok(())
}

pub fn establish(
    listener: &TcpListener,
    config: Arc<rustls::ServerConfig>,
    fixture: &Fixture,
) -> Result<ReceivingPeer> {
    let mut stream = accept(listener)?;
    starttls(&mut stream)?;
    let mut peer = tls(stream, config, fixture)?;
    auth(&mut peer)?;
    ready(&mut peer)?;
    Ok(peer)
}

pub fn reply(peer: &mut impl Read, id: &str) -> Result<String> {
    let xml = support::until(peer, "</message>")?;
    assert!(xml.contains("xmlns=\"jabber:server\""), "{xml}");
    assert!(xml.contains("type=\"error\""), "{xml}");
    assert!(xml.contains("from=\"local.test\""), "{xml}");
    assert!(xml.contains("to=\"a@peer.test/remote\""), "{xml}");
    assert!(xml.contains(&format!("id=\"{id}\"")), "{xml}");
    assert!(xml.contains("service-unavailable"), "{xml}");
    Ok(xml)
}

pub fn close(peer: &mut ReceivingPeer) -> Result {
    peer.write_all(FOOTER.as_bytes())?;
    peer.flush()?;
    assert_eq!(support::until(peer, FOOTER)?, FOOTER);
    peer.conn.send_close_notify();
    peer.flush()?;
    let mut bytes = [0; 1];
    assert_eq!(peer.read(&mut bytes)?, 0);
    Ok(())
}

pub fn outbound_auth(outcome: &str) -> String {
    format!("lonewolf_s2s_authentications_total{{direction=\"outbound\",outcome=\"{outcome}\"}}")
}
pub fn wait_zero(server: &Server) -> Result {
    support::wait_sample(
        server,
        "lonewolf_s2s_connections{direction=\"outbound\"}",
        0,
    )?;
    support::wait_sample(server, "lonewolf_s2s_streams{direction=\"outbound\"}", 0)
}
pub fn failure(server: &Server, outcome: &str) -> Result {
    support::wait_sample(server, &outbound_auth(outcome), 1)?;
    support::wait_sample(
        server,
        "lonewolf_s2s_dns_resolutions_total{outcome=\"static\"}",
        1,
    )?;
    wait_zero(server)?;
    let body = support::metrics(server)?;
    let total = authentication_total(&body)?;
    assert_eq!(total, 1, "{body}");
    assert_eq!(
        support::sample(&body, "lonewolf_s2s_outbound_links{state=\"backoff\"}")?,
        1
    );
    Ok(())
}

pub fn abort_seen(peer: &mut impl Read) -> Result {
    let mut bytes = [0; 1024];
    loop {
        match peer.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub fn shutdown(server: &mut Server) -> Result {
    let started = Instant::now();
    server.stop(nix::sys::signal::Signal::SIGTERM)?;
    assert!(started.elapsed() < Duration::from_secs(10));
    Ok(())
}

pub fn counter(body: &str, name: &str) -> Result<usize> {
    assert!(
        name == "lonewolf_s2s_stanzas_received_total{kind=\"message\"}"
            || name == "lonewolf_s2s_dns_resolutions_total{outcome=\"static\"}"
            || [
                "certificate_name",
                "sasl_failure",
                "protocol",
                "unreachable"
            ]
            .iter()
            .any(|outcome| name == outbound_auth(outcome)),
        "unknown counter: {name}"
    );
    match body.lines().find_map(|line| {
        line.strip_prefix(name)
            .and_then(|value| value.strip_prefix(' '))
    }) {
        Some(value) => Ok(value.parse()?),
        None => Ok(0),
    }
}

pub fn authentication_total(body: &str) -> Result<usize> {
    body.lines()
        .filter(|line| {
            line.starts_with("lonewolf_s2s_authentications_total{direction=\"outbound\"")
        })
        .try_fold(0, |total, line| -> Result<usize> {
            Ok(total + line.rsplit_once(' ').ok_or("sample")?.1.parse::<usize>()?)
        })
}
