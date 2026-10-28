// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use graviola::hashing::Sha256;
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey};
use rcgen::{CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

use super::process::{Server, TIMEOUT, field, request};

pub type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
pub const FOOTER: &str = "</stream:stream>";
pub const STARTTLS: &str = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
pub const AUTH: &str =
    "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>=</auth>";
pub const HEADER: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' to='local.test' from='peer.test'>";
pub type Peer = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

struct Signer {
    key: SigningKey<P256>,
    public: [u8; 65],
}

impl Signer {
    fn new() -> Result<Self> {
        let key = SigningKey::<P256> {
            private_key: StaticPrivateKey::new_random()?,
        };
        Ok(Self {
            public: key.private_key.public_key_uncompressed(),
            key,
        })
    }
    fn private(&self) -> Result<PrivateKeyDer<'static>> {
        let mut buffer = [0; 512];
        Ok(PrivatePkcs8KeyDer::from(self.key.to_pkcs8_der(&mut buffer)?.to_vec()).into())
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
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        let mut output = [0; 80];
        self.key
            .sign_asn1::<Sha256>(&[message], &mut output)
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

pub struct Fixture {
    _directory: tempfile::TempDir,
    issuer: CertifiedIssuer<'static, Signer>,
    pub config: String,
}

impl Fixture {
    pub fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.serial_number = Some(1u64.into());
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let issuer = CertifiedIssuer::self_signed(params, Signer::new()?)?;
        let signer = Signer::new()?;
        let mut params = CertificateParams::new(vec!["local.test".to_owned()])?;
        params.serial_number = Some(2u64.into());
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let cert = params.signed_by(&signer, &issuer)?;
        let roots = directory.path().join("roots.pem");
        let chain = directory.path().join("local.pem");
        let key = directory.path().join("local.key");
        fs::write(&roots, pem("CERTIFICATE", issuer.der()))?;
        fs::write(&chain, pem("CERTIFICATE", cert.der()))?;
        fs::write(&key, pem("PRIVATE KEY", signer.private()?.secret_der()))?;
        let config = format!(
            "[[c2s.listeners]]\naddress='127.0.0.1:0'\n[[s2s.listeners]]\naddress='127.0.0.1:0'\n[s2s.tls]\ntrust_anchors_path={roots:?}\n[hosts.'local.test'.tls]\ncertificate_chain_path={chain:?}\nprivate_key_path={key:?}\n[metrics]\nenabled=true\naddress='127.0.0.1:0'\n"
        );
        Ok(Self {
            _directory: directory,
            issuer,
            config,
        })
    }

    pub fn client(
        &self,
        domain: Option<&str>,
        client_only: bool,
    ) -> Result<Arc<rustls::ClientConfig>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.issuer.der().clone())?;
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls_graviola::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots);
        Ok(Arc::new(match domain {
            None => builder.with_no_client_auth(),
            Some(domain) => {
                let (cert, key) = self.identity(domain, client_only)?;
                builder.with_client_auth_cert(vec![cert], key)?
            }
        }))
    }

    fn identity(
        &self,
        domain: &str,
        client_only: bool,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let signer = Signer::new()?;
        let mut params = CertificateParams::new(vec![domain.to_owned()])?;
        params.serial_number = Some(3u64.into());
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![if client_only {
            ExtendedKeyUsagePurpose::ClientAuth
        } else {
            ExtendedKeyUsagePurpose::ServerAuth
        }];
        Ok((
            params.signed_by(&signer, &self.issuer)?.der().clone(),
            signer.private()?,
        ))
    }

    pub fn server(&self, extra: &str) -> Result<(Server, SocketAddr)> {
        let mut server = Server::start(&format!("{}{extra}", self.config), 2)?;
        let addresses = server
            .ready_with(|readiness| readiness.s2s)?
            .ok_or("missing S2S readiness")?;
        assert_eq!(addresses.len(), 1);
        assert_ne!(addresses[0].port(), 0);
        Ok((server, addresses[0]))
    }
}

pub fn connect(address: SocketAddr) -> Result<TcpStream> {
    let tcp = TcpStream::connect_timeout(&address, TIMEOUT)?;
    tcp.set_read_timeout(Some(TIMEOUT))?;
    tcp.set_write_timeout(Some(TIMEOUT))?;
    Ok(tcp)
}

pub fn until(input: &mut impl Read, end: &str) -> Result<String> {
    let mut bytes = Vec::new();
    let mut byte = [0];
    while !bytes.ends_with(end.as_bytes()) {
        input.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.len() > 32_768 {
            return Err("XML response exceeds limit".into());
        }
    }
    Ok(String::from_utf8(bytes)?)
}

pub fn response_header(input: &mut impl Read) -> Result<String> {
    let mut header = until(input, "<stream:stream")?;
    header.push_str(&until(input, ">")?);
    assert!(header.contains("xmlns='jabber:server'"), "{header}");
    assert!(header.contains(" from='local.test'"), "{header}");
    Ok(header)
}

pub fn id(header: &str) -> Result<&str> {
    header
        .split_once(" id='")
        .and_then(|(_, tail)| tail.split_once('\''))
        .map(|(id, _)| id)
        .ok_or_else(|| "missing stream id".into())
}

pub fn start_tls(address: SocketAddr, config: Arc<rustls::ClientConfig>) -> Result<(Peer, String)> {
    let mut tcp = connect(address)?;
    tcp.write_all(HEADER.as_bytes())?;
    let first = response_header(&mut tcp)?;
    let features = until(&mut tcp, "</stream:features>")?;
    assert_eq!(
        features,
        "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"
    );
    tcp.write_all(STARTTLS.as_bytes())?;
    assert_eq!(
        until(&mut tcp, "/>")?,
        "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    );
    let conn = rustls::ClientConnection::new(config, ServerName::try_from("local.test")?)?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.conn.complete_io(&mut tls.sock)?;
    Ok((tls, first))
}

pub fn external(peer: &mut Peer, header: &str) -> Result<String> {
    peer.write_all(header.as_bytes())?;
    let header = response_header(peer)?;
    assert_eq!(
        until(peer, "</stream:features>")?,
        "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>"
    );
    Ok(header)
}

pub fn success(peer: &mut Peer, auth: &str) -> Result<String> {
    peer.write_all(auth.as_bytes())?;
    assert_eq!(
        until(peer, "/>")?,
        "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"
    );
    peer.write_all(HEADER.as_bytes())?;
    let header = response_header(peer)?;
    assert_eq!(until(peer, "/>")?, "<stream:features/>");
    Ok(header)
}

pub fn close(peer: &mut Peer) -> Result {
    peer.write_all(FOOTER.as_bytes())?;
    assert_eq!(until(peer, FOOTER)?, FOOTER);
    peer.conn.send_close_notify();
    peer.flush()?;
    assert_eq!(peer.read(&mut [0])?, 0);
    Ok(())
}

pub fn stream_error(peer: &mut impl Read, condition: &str) -> Result {
    let error = until(peer, FOOTER)?;
    assert!(
        error.contains(&format!(
            "<{condition} xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
        )) || error.contains(&format!("<{condition}/>")),
        "{error}"
    );
    assert_eq!(error.matches(FOOTER).count(), 1);
    Ok(())
}

pub fn metrics(server: &Server) -> Result<String> {
    let response = request(
        server.metrics_address().ok_or("missing metrics")?,
        "/metrics",
    )?;
    Ok(response
        .split_once("\r\n\r\n")
        .ok_or("missing metrics body")?
        .1
        .to_owned())
}

pub fn sample(body: &str, name: &str) -> Result<usize> {
    let value = body
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|value| value.strip_prefix(' '))
        })
        .ok_or_else(|| format!("missing sample {name}: {body}"))?;
    field(value, "")
}

pub fn wait_sample(server: &Server, name: &str, value: usize) -> Result {
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let body = metrics(server)?;
        if body.lines().any(|line| {
            line.strip_prefix(name)
                .is_some_and(|value| value.starts_with(' '))
        }) && sample(&body, name)? == value
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("sample {name} did not reach {value}: {body}").into());
        }
    }
}

pub fn auth_sample(outcome: &str) -> String {
    format!("lonewolf_s2s_authentications_total{{direction=\"inbound\",outcome=\"{outcome}\"}}")
}
