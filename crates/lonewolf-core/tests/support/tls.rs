// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use graviola::hashing::Sha256;
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey};
use rcgen::{CertificateParams, PublicKeyData};
use rustls::{ClientConfig, RootCertStore, SupportedProtocolVersion};

use super::TestResult;

pub fn configure(directory: &Path) -> TestResult<RootCertStore> {
    let key = SigningKey::<P256> {
        private_key: StaticPrivateKey::new_random()?,
    };
    let signer = TestSigner {
        public_key: key.private_key.public_key_uncompressed(),
        key,
    };
    let mut parameters =
        CertificateParams::new(vec!["localhost".into(), "other.localhost".into()])?;
    parameters.serial_number = Some(1u64.into());
    let certificate = parameters.self_signed(&signer)?;
    let mut key_bytes = [0; 512];
    let key_der = signer.key.to_pkcs8_der(&mut key_bytes)?;
    fs::write(
        directory.join("certificate.pem"),
        pem("CERTIFICATE", certificate.der())?,
    )?;
    fs::write(
        directory.join("private-key.pem"),
        pem("PRIVATE KEY", key_der)?,
    )?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate.der().clone())?;
    Ok(roots)
}

pub fn client_config(
    roots: RootCertStore,
    versions: &[&'static SupportedProtocolVersion],
) -> TestResult<ClientConfig> {
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
            .with_protocol_versions(versions)?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn pem(label: &str, der: &[u8]) -> TestResult<String> {
    let encoded = STANDARD.encode(der);
    let mut output = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(chunk)?);
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    Ok(output)
}

struct TestSigner {
    key: SigningKey<P256>,
    public_key: [u8; 65],
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
        let mut signature = [0; 80];
        self.key
            .sign_asn1::<Sha256>(&[message], &mut signature)
            .map(<[u8]>::to_vec)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}
