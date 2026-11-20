// SPDX-License-Identifier: Apache-2.0

use super::{BenchResult, failure};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use base64::{Engine, engine::general_purpose::STANDARD};
use rcgen::{CertificateParams, PublicKeyData};
use rustls::pki_types::CertificateDer;
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::Path};
use zeroize::Zeroizing;

pub(super) fn configure(directory: &Path) -> BenchResult<CertificateDer<'static>> {
    let signer = Signer(
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .map_err(|_| failure("fixture_key"))?,
    );
    let mut parameters = CertificateParams::new(vec!["localhost".into()])
        .map_err(|_| failure("fixture_certificate"))?;
    parameters.serial_number = Some(1u64.into());
    let certificate = parameters
        .self_signed(&signer)
        .map_err(|_| failure("fixture_certificate"))?;
    let key_der = signer.0.to_pkcs8v1().map_err(|_| failure("fixture_key"))?;
    let key_pem = pem("PRIVATE KEY", key_der.as_ref())?;
    write_private(&directory.join("key.pem"), key_pem.as_bytes())?;
    write_private(
        &directory.join("certificate.pem"),
        pem("CERTIFICATE", certificate.der())?.as_bytes(),
    )?;
    Ok(certificate.der().clone())
}

pub(super) fn write_private(path: &Path, data: &[u8]) -> BenchResult<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(data))
        .map_err(|_| failure("fixture_private_write"))
}

fn pem(label: &str, der: &[u8]) -> BenchResult<Zeroizing<String>> {
    let encoded = Zeroizing::new(STANDARD.encode(der));
    let mut output = Zeroizing::new(String::with_capacity(
        encoded.len() + encoded.len().div_ceil(64) + label.len() * 2 + 40,
    ));
    output.push_str(&format!("-----BEGIN {label}-----\n"));
    for chunk in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(chunk).map_err(|_| failure("fixture_pem"))?);
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    Ok(output)
}

struct Signer(EcdsaKeyPair);
impl PublicKeyData for Signer {
    fn der_bytes(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
impl rcgen::SigningKey for Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.0
            .sign(&SystemRandom::new(), message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}
