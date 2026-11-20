// SPDX-License-Identifier: Apache-2.0

use crate::CertificateMaterial;
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair,
    EcdsaSigningAlgorithm, KeyPair,
};
use hmac::{KeyInit, Mac};
use instant_acme::CertificateIdentifier;
use instant_acme::{CryptoProvider, EcCurve, Jwk, JwkThumbFields, SigningAlgorithm};
use rcgen::{CertificateParams, PublicKeyData};
use rustls::pki_types::{Der, PrivatePkcs8KeyDer};
use x509_cert::Certificate;
use x509_cert::der::{Decode, EncodeValue, SliceWriter};
use x509_cert::ext::pkix::AuthorityKeyIdentifier;
use zeroize::Zeroizing;

use crate::types::{AcmeError, AcmeErrorKind, validate_dns};

struct Provider;
static PROVIDER: CryptoProvider = CryptoProvider {
    key_provider: &Provider,
    sha256: &Provider,
    hmac: &Provider,
};

pub fn crypto_provider() -> &'static CryptoProvider {
    &PROVIDER
}

struct P256Key {
    key: EcdsaKeyPair,
    public_key: [u8; 65],
}

impl P256Key {
    fn generate(algorithm: &'static EcdsaSigningAlgorithm) -> Result<Self, AcmeError> {
        EcdsaKeyPair::generate(algorithm)
            .map_err(|_| AcmeError::new(AcmeErrorKind::Crypto))
            .and_then(Self::new)
    }

    fn from_pkcs8(
        algorithm: &'static EcdsaSigningAlgorithm,
        pkcs8: &[u8],
    ) -> Result<Self, AcmeError> {
        EcdsaKeyPair::from_pkcs8(algorithm, pkcs8)
            .map_err(|_| AcmeError::new(AcmeErrorKind::Crypto))
            .and_then(Self::new)
    }

    fn new(key: EcdsaKeyPair) -> Result<Self, AcmeError> {
        let public_key = key
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| AcmeError::new(AcmeErrorKind::Crypto))?;
        Ok(Self { key, public_key })
    }

    fn pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, AcmeError> {
        self.key
            .to_pkcs8v1()
            .map(|der| Zeroizing::new(der.as_ref().to_vec()))
            .map_err(|_| AcmeError::new(AcmeErrorKind::Crypto))
    }

    fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.key
            .sign(&SystemRandom::new(), message)
            .ok()
            .map(|signature| signature.as_ref().to_vec())
    }
}

struct AccountKey(P256Key);

pub(crate) struct CertificateSigner(P256Key);

impl CertificateSigner {
    pub(crate) fn generate() -> Result<Self, AcmeError> {
        P256Key::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).map(Self)
    }

    pub(crate) fn pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, AcmeError> {
        self.0.pkcs8()
    }
}

impl instant_acme::SigningKeyProvider for Provider {
    fn load_key(
        &self,
        pkcs8: PrivatePkcs8KeyDer<'static>,
    ) -> Result<Box<dyn instant_acme::SigningKey>, instant_acme::Error> {
        let key = P256Key::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.secret_pkcs8_der())
            .map_err(|_| instant_acme::Error::Crypto)?;
        Ok(Box::new(AccountKey(key)))
    }

    fn generate_key(
        &self,
    ) -> Result<
        (
            Box<dyn instant_acme::SigningKey>,
            PrivatePkcs8KeyDer<'static>,
        ),
        instant_acme::Error,
    > {
        let key = P256Key::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
            .map_err(|_| instant_acme::Error::Crypto)?;
        let mut der = key.pkcs8().map_err(|_| instant_acme::Error::Crypto)?;
        Ok((
            Box::new(AccountKey(key)),
            PrivatePkcs8KeyDer::from(std::mem::take(&mut *der)),
        ))
    }
}

impl instant_acme::SigningKey for AccountKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, instant_acme::Error> {
        self.0.sign(data).ok_or(instant_acme::Error::Crypto)
    }

    fn as_jwk(&self) -> Jwk<'_> {
        Jwk {
            alg: SigningAlgorithm::Es256,
            r#use: "sig",
            key: JwkThumbFields::Ec {
                crv: EcCurve::P256,
                x: &self.0.public_key[1..33],
                y: &self.0.public_key[33..65],
            },
        }
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Es256
    }
}

impl instant_acme::Sha256 for Provider {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut output = [0; 32];
        output.copy_from_slice(digest(&SHA256, data).as_ref());
        output
    }
}

struct HmacKey(hmac::Hmac<sha2::Sha256>);

impl instant_acme::HmacKeyProvider for Provider {
    fn load_key(&self, key_value: &[u8]) -> Box<dyn instant_acme::HmacKey> {
        Box::new(HmacKey(
            hmac::Hmac::<sha2::Sha256>::new_from_slice(key_value)
                .unwrap_or_else(|_| unreachable!("HMAC accepts all key lengths")),
        ))
    }
}

impl instant_acme::HmacKey for HmacKey {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = self.0.clone();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Hs256
    }
}

impl PublicKeyData for CertificateSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.0.public_key
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for CertificateSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.0.sign(message).ok_or(rcgen::Error::RemoteKeyError)
    }
}

/// Returns a fresh certificate key in PKCS#8 DER and its signed CSR in DER.
pub fn new_certificate_request(dns_name: &str) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), AcmeError> {
    validate_dns(dns_name).map_err(|_| AcmeError::new(AcmeErrorKind::InvalidInput))?;
    let signer = CertificateSigner::generate()?;
    let mut parameters = CertificateParams::new(vec![dns_name.into()])
        .map_err(|_| AcmeError::new(AcmeErrorKind::InvalidInput))?;
    parameters.distinguished_name = rcgen::DistinguishedName::new();
    parameters.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let csr = parameters
        .serialize_request(&signer)
        .map_err(|_| AcmeError::new(AcmeErrorKind::Crypto))?;
    Ok((signer.pkcs8()?, csr.der().to_vec()))
}

pub(crate) fn certificate_identifier(
    material: &CertificateMaterial,
) -> Result<CertificateIdentifier<'static>, AcmeError> {
    let invalid = || AcmeError::new(AcmeErrorKind::InvalidInput);
    let leaf = material.chain.first().ok_or_else(invalid)?;
    let certificate = Certificate::from_der(leaf).map_err(|_| invalid())?;
    let (_, aki) = certificate
        .tbs_certificate()
        .get_extension::<AuthorityKeyIdentifier>()
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let aki = aki.key_identifier.ok_or_else(invalid)?;
    let serial = certificate.tbs_certificate().serial_number();
    let mut buffer = [0u8; 21];
    let mut writer = SliceWriter::new(&mut buffer);
    serial.encode_value(&mut writer).map_err(|_| invalid())?;
    let content = writer.finish().map_err(|_| invalid())?;
    if aki.as_bytes().is_empty() || content.is_empty() {
        return Err(invalid());
    }
    Ok(CertificateIdentifier::new(Der::from(aki.as_bytes()), Der::from(content)).into_owned())
}

#[cfg(test)]
mod tests;
