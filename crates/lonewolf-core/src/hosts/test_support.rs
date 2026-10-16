// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use graviola::hashing::Sha256;
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey};
use rcgen::PublicKeyData;

pub(in crate::hosts) fn pem(label: &str, der: &[u8]) -> Result<String, std::str::Utf8Error> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut output = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(chunk)?);
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    Ok(output)
}

pub(in crate::hosts) struct TestSigner {
    pub(in crate::hosts) key: SigningKey<P256>,
    public_key: [u8; 65],
}

impl TestSigner {
    pub(in crate::hosts) fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let key = SigningKey::<P256> {
            private_key: StaticPrivateKey::new_random()?,
        };
        Ok(Self {
            public_key: key.private_key.public_key_uncompressed(),
            key,
        })
    }
}

impl PublicKeyData for TestSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for TestSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut signature = [0_u8; 80];
        self.key
            .sign_asn1::<Sha256>(&[message], &mut signature)
            .map(<[u8]>::to_vec)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

pub(in crate::hosts) fn srv_name(
    value: &str,
) -> Result<x509_cert::ext::pkix::name::GeneralName, x509_cert::der::Error> {
    use x509_cert::der::asn1::{Ia5String, ObjectIdentifier};
    use x509_cert::ext::pkix::name::{GeneralName, OtherName};
    Ok(GeneralName::OtherName(OtherName {
        type_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.8.7"),
        value: (&Ia5String::new(value)?).into(),
    }))
}

pub(in crate::hosts) fn san_parameters(
    names: Vec<x509_cert::ext::pkix::name::GeneralName>,
) -> Result<rcgen::CertificateParams, Box<dyn std::error::Error>> {
    use x509_cert::der::Encode;
    let mut parameters = rcgen::CertificateParams::new(Vec::<String>::new())?;
    parameters
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 17],
            x509_cert::ext::pkix::SubjectAltName(names).to_der()?,
        ));
    Ok(parameters)
}

pub(crate) fn material(
    mut parameters: rcgen::CertificateParams,
) -> Result<
    (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    Box<dyn std::error::Error>,
> {
    let signer = TestSigner::new()?;
    parameters.serial_number = Some(1u64.into());
    let certificate = parameters.self_signed(&signer)?;
    let mut bytes = zeroize::Zeroizing::new([0; 512]);
    let key = signer.key.to_pkcs8_der(&mut bytes[..])?;
    Ok((
        certificate.der().clone(),
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.to_vec()).into(),
    ))
}

pub(crate) fn managed_hosts() -> Result<super::Hosts, super::HostsError> {
    let mut config = crate::config::Config::default();
    config.hosts.insert(
        "example.com".into(),
        crate::config::HostConfig {
            tls: Some(crate::config::HostTlsConfig {
                source: crate::config::HostTlsSource::LetsEncrypt,
                client_auth: None,
            }),
            ..crate::config::HostConfig::default()
        },
    );
    super::Hosts::new(&config.hosts, Some("localhost"))
}

pub(crate) fn handshake(
    client_config: std::sync::Arc<rustls::ClientConfig>,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> Result<rustls::ClientConnection, Box<dyn std::error::Error>> {
    let mut client = rustls::ClientConnection::new(client_config, "example.com".try_into()?)?;
    let mut server = rustls::ServerConnection::new(server_config)?;
    let mut wire = Vec::new();
    for _ in 0..32 {
        wire.clear();
        while client.wants_write() {
            client.write_tls(&mut wire)?;
        }
        if !wire.is_empty() {
            let mut input = std::io::Cursor::new(&wire);
            while input.position() < wire.len() as u64 {
                server.read_tls(&mut input)?;
                server.process_new_packets()?;
            }
        }
        wire.clear();
        while server.wants_write() {
            server.write_tls(&mut wire)?;
        }
        if !wire.is_empty() {
            let mut input = std::io::Cursor::new(&wire);
            while input.position() < wire.len() as u64 {
                client.read_tls(&mut input)?;
                client.process_new_packets()?;
            }
        }
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client.wants_write()
            && !server.wants_write()
        {
            return Ok(client);
        }
    }
    Err("in-memory TLS handshake did not complete".into())
}
