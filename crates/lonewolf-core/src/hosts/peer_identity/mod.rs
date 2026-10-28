// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::fs::File;
use std::sync::Arc;
use std::time::SystemTime;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme};
use x509_cert::Certificate;
use x509_cert::der::{Decode, asn1::ObjectIdentifier};
use x509_cert::ext::pkix::ExtendedKeyUsage;

use super::client_identity::{certificate_expiration, validate_key_usage_iter, webpki_error};
use super::service_identity::{XmppService, verify_service_identity};
use super::tls_identity;
use crate::config::S2sTlsConfig;

#[derive(Debug)]
pub(crate) struct PeerTrust {
    roots: RootCertStore,
    anchor_expirations: Option<Box<[SystemTime]>>,
    provider: Arc<CryptoProvider>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PeerValidity {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) valid_until: SystemTime,
}

#[derive(Debug)]
pub(crate) enum PeerIdentityError {
    TrustAnchors,
}

impl fmt::Display for PeerIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cannot load peer trust anchors")
    }
}

impl std::error::Error for PeerIdentityError {}

impl PeerTrust {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn load(
        config: &S2sTlsConfig,
        provider: Arc<CryptoProvider>,
    ) -> Result<Arc<Self>, PeerIdentityError> {
        let mut roots = RootCertStore::empty();
        let anchor_expirations = if let Some(path) = &config.trust_anchors_path {
            let file = File::open(path).map_err(|_| PeerIdentityError::TrustAnchors)?;
            let mut expirations = Vec::new();
            for certificate in CertificateDer::pem_reader_iter(file) {
                let certificate = certificate.map_err(|_| PeerIdentityError::TrustAnchors)?;
                let expiration = certificate_expiration(&certificate)
                    .map_err(|_| PeerIdentityError::TrustAnchors)?;
                roots
                    .add(certificate)
                    .map_err(|_| PeerIdentityError::TrustAnchors)?;
                expirations.push(expiration);
            }
            if roots.is_empty() {
                return Err(PeerIdentityError::TrustAnchors);
            }
            for (index, root) in roots.roots.iter().enumerate() {
                expirations[index] = roots
                    .roots
                    .iter()
                    .zip(&expirations)
                    .filter(|(candidate, _)| *candidate == root)
                    .map(|(_, expiration)| *expiration)
                    .max()
                    .ok_or(PeerIdentityError::TrustAnchors)?;
            }
            Some(expirations.into_boxed_slice())
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            None
        };
        Ok(Arc::new(Self {
            roots,
            anchor_expirations,
            provider,
        }))
    }

    pub(crate) fn verify_chain(
        &self,
        chain: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<PeerValidity, rustls::Error> {
        let (leaf, intermediates) = chain
            .split_first()
            .ok_or(rustls::Error::NoCertificatesPresented)?;
        let end_entity = webpki::EndEntityCert::try_from(leaf).map_err(webpki_error)?;
        let path = end_entity
            .verify_for_usage(
                self.provider.signature_verification_algorithms.all,
                &self.roots.roots,
                intermediates,
                now,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(webpki_error)?;
        validate_key_usage_iter(
            leaf,
            path.intermediate_certificates()
                .map(|certificate| certificate.der()),
        )?;
        let parsed = Certificate::from_der(leaf.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let usage = parsed
            .tbs_certificate()
            .get_extension::<ExtendedKeyUsage>()
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if !usage.is_some_and(|(_, usage)| {
            usage
                .0
                .contains(&ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1"))
        }) {
            return Err(CertificateError::InvalidPurpose.into());
        }
        let expiration = |certificate: &CertificateDer<'_>| {
            certificate_expiration(certificate)
                .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))
        };
        let mut valid_until = expiration(leaf)?;
        for certificate in path.intermediate_certificates() {
            valid_until = valid_until.min(expiration(&certificate.der())?);
        }
        if let Some(expirations) = &self.anchor_expirations {
            let index = self
                .roots
                .roots
                .iter()
                .position(|anchor| std::ptr::eq(anchor, path.anchor()))
                .ok_or(rustls::Error::InvalidCertificate(
                    CertificateError::UnknownIssuer,
                ))?;
            valid_until = valid_until.min(expirations[index]);
        }
        Ok(PeerValidity { valid_until })
    }

    fn verify_parts(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<PeerValidity, rustls::Error> {
        if intermediates.is_empty() {
            return self.verify_chain(std::slice::from_ref(leaf), now);
        }
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        chain.push(CertificateDer::from(leaf.as_ref()));
        chain.extend(
            intermediates
                .iter()
                .map(|certificate| CertificateDer::from(certificate.as_ref())),
        );
        self.verify_chain(&chain, now)
    }

    pub(crate) fn verify_identity(
        &self,
        leaf: &CertificateDer<'_>,
        domain: &str,
    ) -> Result<(), rustls::Error> {
        let identity = tls_identity(domain)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::NotValidForName))?;
        verify_service_identity(leaf, &identity, XmppService::Server)
    }

    pub(crate) fn client_verifier(self: &Arc<Self>) -> Arc<dyn ClientCertVerifier> {
        Arc::clone(self) as Arc<dyn ClientCertVerifier>
    }

    pub(crate) fn server_verifier(self: &Arc<Self>) -> Arc<dyn ServerCertVerifier> {
        Arc::clone(self) as Arc<dyn ServerCertVerifier>
    }
}

impl ClientCertVerifier for PeerTrust {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verify_parts(leaf, intermediates, now)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ServerCertVerifier for PeerTrust {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.verify_parts(leaf, intermediates, now)?;
        self.verify_identity(leaf, &name.to_str())?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        ClientCertVerifier::verify_tls12_signature(self, message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        ClientCertVerifier::verify_tls13_signature(self, message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ClientCertVerifier::supported_verify_schemes(self)
    }
}

#[cfg(test)]
mod tests;
