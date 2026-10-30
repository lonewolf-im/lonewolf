// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use graviola::hashing::Sha256;
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey};
use rcgen::{CertificateParams, CertifiedIssuer, PublicKeyData};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};

use super::support::xml::XmlStream;
use super::support::{C2sSuite, SASL_NAMESPACE, STREAM_ERRORS, TLS_NAMESPACE, TestResult};

const TIMEOUT: Duration = Duration::from_secs(10);
const SERVICE: &str = "echo.local.test";
const FOOTER: &str = "</stream:stream>";
const STARTTLS: &str = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
const PROCEED: &str = "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
const TLS_FEATURES: &str = "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>";
const EXTERNAL_FEATURES: &str = "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>";
type SendingPeer = XmlStream<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>;

struct Signer {
    key: SigningKey<P256>,
    public: [u8; 65],
}

impl Signer {
    fn new() -> TestResult<Self> {
        let key = SigningKey::<P256> {
            private_key: StaticPrivateKey::new_random()?,
        };
        Ok(Self {
            public: key.private_key.public_key_uncompressed(),
            key,
        })
    }

    fn private(&self) -> TestResult<PrivateKeyDer<'static>> {
        let mut bytes = zeroize::Zeroizing::new([0; 512]);
        Ok(PrivatePkcs8KeyDer::from(self.key.to_pkcs8_der(&mut bytes[..])?.to_vec()).into())
    }
}

impl PublicKeyData for Signer {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut bytes = [0; 80];
        self.key
            .sign_asn1::<Sha256>(&[message], &mut bytes)
            .map(<[u8]>::to_vec)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

fn pem(label: &str, bytes: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(bytes)
    )
}

fn identity(
    issuer: &CertifiedIssuer<'_, Signer>,
    names: &[&str],
) -> TestResult<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let signer = Signer::new()?;
    let mut parameters = CertificateParams::new(
        names
            .iter()
            .map(|name| (*name).into())
            .collect::<Vec<String>>(),
    )?;
    parameters.serial_number = Some(2u64.into());
    parameters.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    Ok((
        parameters.signed_by(&signer, issuer)?.der().clone(),
        signer.private()?,
    ))
}

#[derive(Debug)]
struct ServiceVerifier(Arc<dyn ServerCertVerifier>, ServerName<'static>);

impl ClientCertVerifier for ServiceVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.0
            .verify_server_cert(leaf, intermediates, &self.1, &[], now)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0
            .verify_tls12_signature(message, certificate, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0
            .verify_tls13_signature(message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

fn opening(from: &str, to: &str) -> String {
    format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='{from}' to='{to}'>"
    )
}

fn connect(address: SocketAddr) -> TestResult<TcpStream> {
    let stream = TcpStream::connect_timeout(&address, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    Ok(stream)
}

fn accept(listener: &TcpListener) -> TestResult<TcpStream> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("return stream timed out")?;
        let mut descriptor = nix::libc::pollfd {
            fd: listener.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        // SAFETY: The live listener and stack descriptor remain valid during this call.
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
            return Err("return stream timed out".into());
        }
        assert_eq!(descriptor.revents, nix::libc::POLLIN);
        let (stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        return Ok(stream);
    }
}

fn authenticate(
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
    certificate: &CertificateDer<'_>,
) -> TestResult<SendingPeer> {
    let header = opening("peer.test", SERVICE);
    let mut plain = XmlStream::new(connect(address)?);
    assert_eq!(plain.open_with(&header)?.attribute("from"), Some(SERVICE));
    plain.features()?.assert_xml(&TLS_FEATURES.replace(
        "<stream:features>",
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>",
    ))?;
    plain.send(STARTTLS)?;
    plain.receive()?.assert_name(TLS_NAMESPACE, "proceed");
    assert!(!plain.has_buffered_input());
    let mut peer = XmlStream::new(rustls::StreamOwned::new(
        rustls::ClientConnection::new(config, ServerName::try_from(SERVICE)?)?,
        plain.into_inner().into_inner(),
    ));
    assert_eq!(peer.open_with(&header)?.attribute("from"), Some(SERVICE));
    assert_eq!(
        peer.transport().conn.peer_certificates(),
        Some(std::slice::from_ref(certificate))
    );
    peer.features()?.assert_xml(&EXTERNAL_FEATURES.replace(
        "<stream:features>",
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>",
    ))?;
    peer.send("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>=</auth>")?;
    peer.receive()?.assert_name(SASL_NAMESPACE, "success");
    let mut peer = peer.restart();
    assert_eq!(peer.open_with(&header)?.attribute("from"), Some(SERVICE));
    peer.features()?
        .assert_xml("<stream:features xmlns:stream='http://etherx.jabber.org/streams'/>")?;
    Ok(peer)
}

fn sample(body: &str, name: &str) -> TestResult<u64> {
    Ok(body
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|tail| tail.strip_prefix(' '))
        })
        .ok_or_else(|| format!("missing {name}: {body}"))?
        .parse()?)
}

#[test]
fn hosted_service_authenticates_echoes_rejects_uncovered_domains_and_closes_with_event_metrics()
-> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut root = CertificateParams::new(Vec::<String>::new())?;
    root.serial_number = Some(1u64.into());
    root.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let issuer = CertifiedIssuer::self_signed(root, Signer::new()?)?;
    let (local_certificate, local_key) =
        identity(&issuer, &["local.test", SERVICE, "uncovered.test"])?;
    let (peer_certificate, peer_key) = identity(&issuer, &["peer.test"])?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(issuer.der().clone())?;
    let provider = Arc::new(rustls_graviola::default_provider());
    let client = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(vec![peer_certificate.clone()], peer_key.clone_key())?,
    );
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .build()?;
    let server_config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(Arc::new(ServiceVerifier(
                verifier,
                ServerName::try_from(SERVICE)?,
            )))
            .with_single_cert(vec![peer_certificate], peer_key)?,
    );
    let hosts = "[hosts.'local.test']\nextensions=['test-service']\n[hosts.'local.test'.tls]\ncertificate_chain_path='service.pem'\nprivate_key_path='service.key'\n[hosts.'uncovered.test']\nextensions=['test-service']\n[hosts.'uncovered.test'.tls]\ncertificate_chain_path='service.pem'\nprivate_key_path='service.key'";
    let federation = format!(
        "[s2s]\nenabled=true\n[[s2s.listeners]]\naddress='127.0.0.1:0'\n[s2s.tls]\ntrust_anchors_path='roots.pem'\n[s2s.routes]\n'peer.test'=['{}']",
        listener.local_addr()?
    );
    let mut suite = C2sSuite::with_federation_and_setup(hosts, &federation, |directory| {
        fs::write(
            directory.join("service.pem"),
            pem("CERTIFICATE", &local_certificate),
        )?;
        fs::write(
            directory.join("service.key"),
            pem("PRIVATE KEY", local_key.secret_der()),
        )?;
        fs::write(
            directory.join("roots.pem"),
            pem("CERTIFICATE", issuer.der()),
        )?;
        Ok(())
    })?;
    let addresses = suite.s2s.as_ref().ok_or("missing S2S readiness")?;
    assert_eq!(addresses.len(), 1);
    let address = addresses[0];
    let mut inbound = authenticate(address, client, &local_certificate)?;
    inbound.send("<message type='chat' id='echo' from='alice@peer.test/desk' to='room@echo.local.test'><body>service payload</body></message>")?;
    let response = opening("peer.test", SERVICE);
    let mut plain = XmlStream::new(accept(&listener)?);
    let header = plain.open_with(&response)?;
    assert_eq!(header.attribute("from"), Some(SERVICE));
    assert_eq!(header.attribute("to"), Some("peer.test"));
    plain.send(TLS_FEATURES)?;
    plain.expect_xml(STARTTLS)?;
    plain.send(PROCEED)?;
    assert!(!plain.has_buffered_input());
    let mut outbound = XmlStream::new(rustls::StreamOwned::new(
        rustls::ServerConnection::new(server_config)?,
        plain.into_inner().into_inner(),
    ));
    assert_eq!(
        outbound.open_with(&response)?.attribute("from"),
        Some(SERVICE)
    );
    assert_eq!(outbound.transport().conn.server_name(), Some("peer.test"));
    assert_eq!(
        outbound.transport().conn.peer_certificates(),
        Some(std::slice::from_ref(&local_certificate))
    );
    outbound.send(EXTERNAL_FEATURES)?;
    outbound.expect_xml(&format!(
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>{}</auth>",
        STANDARD.encode(SERVICE)
    ))?;
    outbound.send("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    let mut outbound = outbound.restart();
    assert_eq!(
        outbound.open_with(&response)?.attribute("from"),
        Some(SERVICE)
    );
    outbound.send("<stream:features/>")?;
    outbound.expect_xml("<message xmlns='jabber:server' type='chat' id='echo' from='room@echo.local.test' to='alice@peer.test/desk'><body>service payload</body></message>")?;
    inbound.send("<presence from='alice@peer.test/desk' to='room@echo.local.test/nick'/><iq type='get' id='count' from='alice@peer.test/desk' to='echo.local.test'><query xmlns='urn:lonewolf:test:service'/></iq>")?;
    outbound.expect_xml("<iq xmlns='jabber:server' type='result' id='count' from='echo.local.test' to='alice@peer.test/desk'><query xmlns='urn:lonewolf:test:service'><count>1</count></query></iq>")?;
    inbound.send("<iq type='set' id='reject' from='alice@peer.test/desk' to='echo.local.test'><query xmlns='urn:lonewolf:test:service'/></iq>")?;
    outbound.expect_xml("<iq xmlns='jabber:server' type='error' id='reject' from='echo.local.test' to='alice@peer.test/desk'><query xmlns='urn:lonewolf:test:service'/><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The request has an invalid structure or value. Check the request format.</text></error></iq>")?;
    let mut uncovered = XmlStream::new(connect(address)?);
    uncovered.open_with(&opening("peer.test", "echo.uncovered.test"))?;
    let error = uncovered.receive()?;
    error.child(STREAM_ERRORS, "host-unknown")?;
    uncovered.close()?;
    inbound.close()?;
    outbound.send(FOOTER)?;
    outbound.expect_footer()?;
    outbound.transport().conn.send_close_notify();
    outbound.transport().flush()?;
    outbound.expect_eof()?;
    let metrics = suite.wait_for_metrics("service workflow completion", |body| {
        [
            ("lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"success\"}", 1),
            ("lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"success\"}", 1),
            ("lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"host_unknown\"}", 1),
            ("lonewolf_s2s_stanzas_received_total{kind=\"message\"}", 1),
            ("lonewolf_s2s_stanzas_received_total{kind=\"presence\"}", 1),
            ("lonewolf_s2s_stanzas_received_total{kind=\"iq\"}", 2),
            ("lonewolf_s2s_stanzas_sent_total{kind=\"message\"}", 1),
            ("lonewolf_s2s_stanzas_sent_total{kind=\"iq\"}", 2),
            ("lonewolf_s2s_streams_closed_total{direction=\"inbound\",outcome=\"stream_end\"}", 1),
            ("lonewolf_s2s_streams_closed_total{direction=\"outbound\",outcome=\"stream_end\"}", 1),
            ("lonewolf_s2s_connections{direction=\"inbound\"}", 0),
            ("lonewolf_s2s_connections{direction=\"outbound\"}", 0),
            ("lonewolf_s2s_streams{direction=\"inbound\"}", 0),
            ("lonewolf_s2s_streams{direction=\"outbound\"}", 0),
        ].into_iter().all(|(name, count)| sample(body, name).ok() == Some(count))
    })?;
    for direction in ["inbound", "outbound"] {
        for operation in ["received", "sent"] {
            assert!(
                sample(
                    &metrics,
                    &format!("lonewolf_s2s_{operation}_bytes_total{{direction=\"{direction}\"}}")
                )? > 0
            );
        }
    }
    suite.stop()?;
    Ok(())
}
