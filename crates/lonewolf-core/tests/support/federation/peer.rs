// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Instant;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::pki_types::ServerName;

use super::super::xml::{CloseTransport, Element, XmlStream};
use super::super::{SASL_NAMESPACE, TIMEOUT, TLS_NAMESPACE, TestResult};

enum PeerTransport {
    Plain(TcpStream),
    Client(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
    Server(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}
impl Read for PeerTransport {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(bytes),
            Self::Client(stream) => stream.read(bytes),
            Self::Server(stream) => stream.read(bytes),
        }
    }
}
impl Write for PeerTransport {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(bytes),
            Self::Client(stream) => stream.write(bytes),
            Self::Server(stream) => stream.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Client(stream) => stream.flush(),
            Self::Server(stream) => stream.flush(),
        }
    }
}
impl CloseTransport for PeerTransport {
    fn close_notify(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.shutdown(std::net::Shutdown::Write),
            Self::Client(stream) => {
                stream.conn.send_close_notify();
                stream.flush()
            }
            Self::Server(stream) => {
                stream.conn.send_close_notify();
                stream.flush()
            }
        }
    }
}

pub struct RawS2sPeer {
    stream: XmlStream<PeerTransport>,
    from: String,
    to: String,
}
impl RawS2sPeer {
    pub fn connect(address: SocketAddr, from: &str, to: &str) -> TestResult<Self> {
        Self::connect_with_response_from(address, from, to, to)
    }
    pub fn connect_with_response_from(
        address: SocketAddr,
        from: &str,
        to: &str,
        response_from: &str,
    ) -> TestResult<Self> {
        let socket = TcpStream::connect_timeout(&address, TIMEOUT)?;
        configure(&socket)?;
        let mut peer = Self {
            stream: XmlStream::new(PeerTransport::Plain(socket)),
            from: from.into(),
            to: to.into(),
        };
        assert_header(
            &peer.stream.open_with(&opening(from, to))?,
            response_from,
            from,
        );
        Ok(peer)
    }
    pub fn expect_starttls_features(&mut self) -> TestResult {
        self.stream.features()?.assert_xml(&format!(
            "<stream:features xmlns:stream='http://etherx.jabber.org/streams'><starttls xmlns='{TLS_NAMESPACE}'><required/></starttls></stream:features>"
        ))?;
        Ok(())
    }
    pub fn start_tls(self, config: Arc<rustls::ClientConfig>) -> TestResult<Self> {
        let header = opening(&self.from, &self.to);
        let expected_to = self.from.clone();
        self.start_tls_with_header(config, &header, Some(&expected_to))
    }
    pub fn start_tls_with_header(
        mut self,
        config: Arc<rustls::ClientConfig>,
        header: &str,
        expected_to: Option<&str>,
    ) -> TestResult<Self> {
        self.stream
            .send(&format!("<starttls xmlns='{TLS_NAMESPACE}'/>"))?;
        self.stream.receive()?.assert_name(TLS_NAMESPACE, "proceed");
        assert!(!self.stream.has_buffered_input());
        let PeerTransport::Plain(socket) = self.stream.into_inner().into_inner() else {
            return Err("peer already uses TLS".into());
        };
        let connection =
            rustls::ClientConnection::new(config, ServerName::try_from(self.to.clone())?)?;
        self.stream = XmlStream::new(PeerTransport::Client(Box::new(rustls::StreamOwned::new(
            connection, socket,
        ))));
        let response = self.stream.open_with(header)?;
        assert_eq!(
            response.attribute("from"),
            Some(self.to.as_str()),
            "{response:?}"
        );
        assert_eq!(response.attribute("to"), expected_to, "{response:?}");
        assert_eq!(response.attribute("version"), Some("1.0"), "{response:?}");
        Ok(self)
    }
    pub fn expect_external_offered(&mut self) -> TestResult {
        let features = self.stream.features()?;
        features.assert_xml(&format!(
            "<stream:features xmlns:stream='http://etherx.jabber.org/streams'><mechanisms xmlns='{SASL_NAMESPACE}'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>"
        ))?;
        Ok(())
    }
    pub fn auth_external(&mut self, authzid: Option<&str>) -> TestResult {
        let text = authzid
            .map(|identity| {
                if identity.is_empty() {
                    "=".into()
                } else {
                    STANDARD.encode(identity)
                }
            })
            .unwrap_or_default();
        self.send(&format!(
            "<auth xmlns='{SASL_NAMESPACE}' mechanism='EXTERNAL'>{text}</auth>"
        ))
    }
    pub fn expect_sasl_success(&mut self) -> TestResult {
        self.receive()?.assert_name(SASL_NAMESPACE, "success");
        Ok(())
    }
    pub fn restart(mut self, from: &str, to: &str) -> TestResult<Self> {
        self.from = from.into();
        self.to = to.into();
        self.stream = self.stream.restart();
        assert_header(&self.stream.open_with(&opening(from, to))?, to, from);
        let features = self.stream.features()?;
        assert!(features.children.is_empty(), "{features:?}");
        Ok(self)
    }
    pub fn send(&mut self, xml: &str) -> TestResult {
        self.stream.send(xml)
    }
    pub fn receive(&mut self) -> TestResult<Element> {
        self.stream.receive()
    }
    pub fn expect_stream_error(&mut self, condition: &str) -> TestResult {
        let error = super::phase("stream error reply", self.receive())?;
        error.assert_name(super::super::xml::STREAM_NAMESPACE, "error");
        assert_eq!(error.children.len(), 1);
        error.child(super::super::STREAM_ERRORS, condition)?;
        self.answer_close()
    }
    pub fn close(&mut self) -> TestResult {
        super::phase("send XML footer", self.stream.send("</stream:stream>"))?;
        super::phase("receive XML footer", self.stream.expect_footer())?;
        self.complete_tls_close()
    }
    pub fn answer_close(&mut self) -> TestResult {
        super::phase("receive XML footer", self.stream.expect_footer())?;
        super::phase(
            "send reciprocal XML footer",
            self.stream.send("</stream:stream>"),
        )?;
        self.complete_tls_close()
    }
    fn complete_tls_close(&mut self) -> TestResult {
        super::phase(
            "send TLS close alert",
            self.stream.transport().close_notify().map_err(Into::into),
        )?;
        self.expect_eof()
    }
    pub fn expect_eof(&mut self) -> TestResult {
        assert!(
            !self.stream.has_buffered_input(),
            "input follows the peer footer"
        );
        let mut byte = [0];
        let count = super::phase(
            "receive TLS close alert and EOF",
            self.stream.transport().read(&mut byte).map_err(Into::into),
        )?;
        if count == 0 {
            Ok(())
        } else {
            Err("data follows the peer footer".into())
        }
    }
    pub fn protocol_version(&mut self) -> Option<rustls::ProtocolVersion> {
        match self.stream.transport() {
            PeerTransport::Plain(_) => None,
            PeerTransport::Client(stream) => stream.conn.protocol_version(),
            PeerTransport::Server(stream) => stream.conn.protocol_version(),
        }
    }
}

pub struct RawS2sListener {
    listener: TcpListener,
}
impl RawS2sListener {
    pub fn bind() -> TestResult<Self> {
        Ok(Self {
            listener: TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?,
        })
    }
    pub fn address(&self) -> TestResult<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
    pub fn set_receive_buffer_size(&self, size: usize) -> TestResult {
        socket2::SockRef::from(&self.listener).set_recv_buffer_size(size)?;
        Ok(())
    }
    pub fn accept_until_proceed(&self, from: &str, to: &str) -> TestResult<RawS2sPeer> {
        let deadline = Instant::now() + TIMEOUT;
        let socket = loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or("raw peer accept timed out")?;
            let mut descriptor = nix::libc::pollfd {
                fd: self.listener.as_raw_fd(),
                events: nix::libc::POLLIN,
                revents: 0,
            };
            // SAFETY: The listener and descriptor remain live during poll.
            let ready =
                unsafe { nix::libc::poll(&mut descriptor, 1, remaining.as_millis().try_into()?) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if ready == 0 {
                return Err("raw peer accept timed out".into());
            }
            break self.listener.accept()?.0;
        };
        configure(&socket)?;
        let mut stream = XmlStream::new(PeerTransport::Plain(socket));
        let header = stream.open_with(&opening(from, to))?;
        assert_header(&header, to, from);
        stream.send(&format!("<stream:features><starttls xmlns='{TLS_NAMESPACE}'><required/></starttls></stream:features>"))?;
        stream.receive()?.assert_name(TLS_NAMESPACE, "starttls");
        stream.send(&format!("<proceed xmlns='{TLS_NAMESPACE}'/>"))?;
        assert!(!stream.has_buffered_input());
        Ok(RawS2sPeer {
            stream,
            from: from.into(),
            to: to.into(),
        })
    }
    pub fn accept(
        &self,
        from: &str,
        to: &str,
        config: Arc<rustls::ServerConfig>,
        external: bool,
    ) -> TestResult<RawS2sPeer> {
        let peer = self.accept_until_proceed(from, to)?;
        let PeerTransport::Plain(socket) = peer.stream.into_inner().into_inner() else {
            return Err("expected plain peer transport".into());
        };
        let mut stream = XmlStream::new(PeerTransport::Server(Box::new(rustls::StreamOwned::new(
            rustls::ServerConnection::new(config)?,
            socket,
        ))));
        assert_header(&stream.open_with(&opening(from, to))?, to, from);
        if external {
            stream.send(&format!("<stream:features><mechanisms xmlns='{SASL_NAMESPACE}'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>"))?;
            let auth = stream.receive()?;
            auth.assert_name(SASL_NAMESPACE, "auth");
            assert_eq!(auth.attribute("mechanism"), Some("EXTERNAL"));
            stream.send(&format!("<success xmlns='{SASL_NAMESPACE}'/>"))?;
            stream = stream.restart();
            assert_header(&stream.open_with(&opening(from, to))?, to, from);
            stream.send("<stream:features/>")?;
        } else {
            stream.send("<stream:features/>")?;
        }
        Ok(RawS2sPeer {
            stream,
            from: from.into(),
            to: to.into(),
        })
    }
}
fn opening(from: &str, to: &str) -> String {
    format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='{from}' to='{to}'>"
    )
}
fn configure(socket: &TcpStream) -> io::Result<()> {
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    socket.set_nodelay(true)
}

pub fn client_config(
    ca: &super::FederationCa,
    key: Arc<rustls::sign::CertifiedKey>,
) -> TestResult<Arc<rustls::ClientConfig>> {
    client_config_with_versions(ca, key, rustls::DEFAULT_VERSIONS)
}

pub fn client_config_with_versions(
    ca: &super::FederationCa,
    key: Arc<rustls::sign::CertifiedKey>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> TestResult<Arc<rustls::ClientConfig>> {
    Ok(super::super::tls::with_client_certificate(
        &super::super::tls::client_config(ca.roots()?, versions)?,
        key,
    ))
}

pub fn server_config(
    ca: &super::FederationCa,
    key: Arc<rustls::sign::CertifiedKey>,
    domain: &str,
) -> TestResult<Arc<rustls::ServerConfig>> {
    server_config_with_versions(ca, key, domain, rustls::DEFAULT_VERSIONS)
}

pub fn server_config_with_versions(
    ca: &super::FederationCa,
    key: Arc<rustls::sign::CertifiedKey>,
    domain: &str,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> TestResult<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls_graviola::default_provider());
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(ca.roots()?),
        Arc::clone(&provider),
    )
    .build()?;
    Ok(Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)?
            .with_client_cert_verifier(Arc::new(PeerVerifier(
                verifier,
                ServerName::try_from(domain.to_owned())?,
            )))
            .with_cert_resolver(Arc::new(PeerKey(key))),
    ))
}
#[derive(Debug)]
struct PeerKey(Arc<rustls::sign::CertifiedKey>);
impl rustls::server::ResolvesServerCert for PeerKey {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}
#[derive(Debug)]
struct PeerVerifier(
    Arc<dyn rustls::client::danger::ServerCertVerifier>,
    ServerName<'static>,
);
impl rustls::server::danger::ClientCertVerifier for PeerVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        leaf: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.0
            .verify_server_cert(leaf, intermediates, &self.1, &[], now)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0
            .verify_tls12_signature(message, certificate, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0
            .verify_tls13_signature(message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

fn assert_header(header: &Element, from: &str, to: &str) {
    assert_eq!(header.attribute("from"), Some(from), "{header:?}");
    assert_eq!(header.attribute("to"), Some(to), "{header:?}");
    assert_eq!(header.attribute("version"), Some("1.0"), "{header:?}");
}
