// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use std::time::Duration;

use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_util::blocking::BlockingExecutor;
use lonewolf_xmpp::jid::Jid;
use rustls::RootCertStore;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
#[cfg(test)]
use rustls::pki_types::CertificateRevocationListDer;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use x509_cert::Certificate;
#[cfg(test)]
use x509_cert::crl::CertificateList;
use x509_cert::der::Decode;
use x509_cert::der::asn1::{ObjectIdentifier, Utf8StringRef};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{KeyUsage, SubjectAltName};

use crate::config::ClientCertificateConfig;

use super::revocation::{CrlSet, RECHECK_INTERVAL};

const XMPP_ADDR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.8.5");

#[derive(Debug)]
pub struct ClientIdentities {
    pub accounts: Box<[AccountKey]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationError {
    NotAuthorized,
    Ambiguous,
}

impl ClientIdentities {
    pub fn authorize(
        &self,
        requested: Option<&AccountKey>,
        stream_from: Option<&str>,
    ) -> Result<&AccountKey, AuthorizationError> {
        if let Some(requested) = requested {
            return self
                .accounts
                .iter()
                .find(|account| *account == requested)
                .ok_or(AuthorizationError::NotAuthorized);
        }
        if let Some(from) = stream_from
            && let Ok(account) = prepared_account(from)
            && let Some(candidate) = self
                .accounts
                .iter()
                .find(|candidate| **candidate == account)
        {
            return Ok(candidate);
        }
        match self.accounts.as_ref() {
            [account] => Ok(account),
            [] => Err(AuthorizationError::NotAuthorized),
            _ => Err(AuthorizationError::Ambiguous),
        }
    }
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotAuthorized => "certificate does not authorize the account",
            Self::Ambiguous => "certificate account selection is ambiguous",
        })
    }
}

impl Error for AuthorizationError {}

/// Extracts account candidates only; the caller must verify the certificate first.
pub fn client_identities(
    certificate: &CertificateDer<'_>,
    host: &str,
) -> Result<ClientIdentities, ClientIdentityError> {
    let parsed = Certificate::from_der(certificate.as_ref())
        .map_err(|_| ClientIdentityError::MalformedCertificate)?;
    let names = parsed
        .tbs_certificate()
        .get_extension::<SubjectAltName>()
        .map_err(|_| ClientIdentityError::MalformedIdentity)?;
    let mut accounts: Vec<AccountKey> = Vec::new();
    if let Some((_, names)) = names {
        let mut arena =
            Arena::try_new(ArenaConfig::default()).map_err(|_| ClientIdentityError::Allocation)?;
        for name in names.0 {
            let GeneralName::OtherName(name) = name else {
                continue;
            };
            if name.type_id != XMPP_ADDR {
                continue;
            }
            let value = Utf8StringRef::try_from(&name.value)
                .map_err(|_| ClientIdentityError::MalformedIdentity)?;
            let jid = Jid::parse_in(value.as_str(), &mut arena)
                .map_err(|_| ClientIdentityError::MalformedIdentity)?;
            let jid = jid
                .resolve(&arena)
                .map_err(|_| ClientIdentityError::Allocation)?;
            if jid.is_full() || jid.localpart().is_none() {
                return Err(ClientIdentityError::MalformedIdentity);
            }
            if jid.domainpart() == host
                && !accounts
                    .iter()
                    .any(|account| account.as_str() == jid.as_str())
            {
                accounts.push(
                    AccountKey::try_from(jid)
                        .map_err(|_| ClientIdentityError::MalformedIdentity)?,
                );
            }
        }
    }
    accounts.sort_unstable();
    Ok(ClientIdentities {
        accounts: accounts.into_boxed_slice(),
    })
}

fn prepared_account(text: &str) -> Result<AccountKey, ClientIdentityError> {
    let mut arena =
        Arena::try_new(ArenaConfig::default()).map_err(|_| ClientIdentityError::Allocation)?;
    let jid =
        Jid::parse_in(text, &mut arena).map_err(|_| ClientIdentityError::MalformedIdentity)?;
    let jid = jid
        .resolve(&arena)
        .map_err(|_| ClientIdentityError::Allocation)?;
    AccountKey::try_from(jid).map_err(|_| ClientIdentityError::MalformedIdentity)
}

/// Bounds authentication by chain expiration and configured CRL deadlines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientValidity {
    pub recheck_at: SystemTime,
    pub valid_until: SystemTime,
}

impl ClientValidity {
    fn at(now: SystemTime, valid_until: SystemTime) -> Result<Self, ClientIdentityError> {
        if now >= valid_until {
            return Err(ClientIdentityError::Expired);
        }
        let recheck_at = now
            .checked_add(RECHECK_INTERVAL)
            .ok_or(ClientIdentityError::InvalidTime)?
            .min(valid_until);
        Ok(Self {
            recheck_at,
            valid_until,
        })
    }

    fn check(&self, now: SystemTime) -> Result<(), ClientIdentityError> {
        if now >= self.valid_until {
            Err(ClientIdentityError::Expired)
        } else {
            Ok(())
        }
    }
}

pub struct VerifiedClient {
    identities: ClientIdentities,
    chain: Arc<[CertificateDer<'static>]>,
    policy: Arc<ClientCertificatePolicy>,
    validity: ClientValidity,
}

impl VerifiedClient {
    pub fn identities(&self) -> &ClientIdentities {
        &self.identities
    }
    pub fn policy(&self) -> &Arc<ClientCertificatePolicy> {
        &self.policy
    }
    pub fn validity(&self) -> &ClientValidity {
        &self.validity
    }
}

impl fmt::Debug for VerifiedClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedClient")
            .field("validity", &self.validity)
            .finish_non_exhaustive()
    }
}

pub struct ClientCertificatePolicy {
    host: Box<str>,
    roots: Arc<RootCertStore>,
    anchor_expirations: Box<[SystemTime]>,
    provider: Arc<CryptoProvider>,
    crls_path: PathBuf,
    verifier: Arc<dyn ClientCertVerifier>,
    blocking: BlockingExecutor,
}

impl fmt::Debug for ClientCertificatePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientCertificatePolicy")
            .finish_non_exhaustive()
    }
}

impl ClientCertificatePolicy {
    pub(super) fn load(
        host: &str,
        config: &ClientCertificateConfig,
        provider: Arc<CryptoProvider>,
        blocking: BlockingExecutor,
    ) -> Result<Arc<Self>, ClientIdentityError> {
        let file = File::open(&config.trust_anchors_path)
            .map_err(|_| ClientIdentityError::TrustAnchors)?;
        let mut roots = RootCertStore::empty();
        let mut anchor_expirations = Vec::new();
        for certificate in CertificateDer::pem_reader_iter(file) {
            let certificate = certificate.map_err(|_| ClientIdentityError::TrustAnchors)?;
            let expiration = certificate_expiration(&certificate)
                .map_err(|_| ClientIdentityError::TrustAnchors)?;
            roots
                .add(certificate)
                .map_err(|_| ClientIdentityError::TrustAnchors)?;
            anchor_expirations.push(expiration);
        }
        if roots.is_empty() {
            return Err(ClientIdentityError::TrustAnchors);
        }
        for (index, root) in roots.roots.iter().enumerate() {
            let expiration = roots
                .roots
                .iter()
                .zip(&anchor_expirations)
                .filter(|(candidate, _)| *candidate == root)
                .map(|(_, expiration)| *expiration)
                .max()
                .ok_or(ClientIdentityError::TrustAnchors)?;
            anchor_expirations[index] = expiration;
        }
        let roots = Arc::new(roots);
        let (verifier, _) = load_verifier(&roots, &provider, &config.crls_path, SystemTime::now())?;
        Ok(Arc::new(Self {
            host: host.into(),
            roots,
            anchor_expirations: anchor_expirations.into_boxed_slice(),
            provider,
            crls_path: config.crls_path.clone(),
            verifier,
            blocking,
        }))
    }

    pub(super) fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
        Arc::clone(&self.verifier)
    }

    pub(super) async fn handshake_verifier(self: &Arc<Self>) -> Arc<dyn ClientCertVerifier> {
        let policy = Arc::clone(self);
        let loaded = self
            .blocking
            .run(move || {
                load_verifier(
                    &policy.roots,
                    &policy.provider,
                    &policy.crls_path,
                    SystemTime::now(),
                )
            })
            .await;
        self.handshake_verifier_result(loaded, SystemTime::now())
    }

    fn handshake_verifier_result(
        &self,
        loaded: Result<(Arc<KeyUsageVerifier>, SystemTime), ClientIdentityError>,
        now: SystemTime,
    ) -> Arc<dyn ClientCertVerifier> {
        match loaded {
            Ok((verifier, valid_until)) if now < valid_until => verifier,
            _ => Arc::new(UnavailableRevocationVerifier {
                inner: Arc::clone(&self.verifier),
            }),
        }
    }

    pub async fn verify_client(
        self: &Arc<Self>,
        chain: Arc<[CertificateDer<'static>]>,
    ) -> Result<VerifiedClient, ClientIdentityError> {
        let policy = Arc::clone(self);
        let operation_chain = Arc::clone(&chain);
        let (identities, validity) = self
            .blocking
            .run(move || {
                let validity = policy.validate_at(&operation_chain, SystemTime::now())?;
                let leaf = operation_chain
                    .first()
                    .ok_or(ClientIdentityError::EmptyChain)?;
                let identities = client_identities(leaf, &policy.host)?;
                Ok((identities, validity))
            })
            .await?;
        validity.check(SystemTime::now())?;
        Ok(VerifiedClient {
            identities,
            chain,
            policy: Arc::clone(self),
            validity,
        })
    }

    /// Reloads required CRLs and rejects peers verified by another policy.
    pub async fn revalidate_client(
        &self,
        peer: &VerifiedClient,
    ) -> Result<ClientValidity, ClientIdentityError> {
        if !std::ptr::eq(self, peer.policy.as_ref()) {
            return Err(ClientIdentityError::PolicyMismatch);
        }
        let policy = Arc::clone(&peer.policy);
        let chain = Arc::clone(&peer.chain);
        let validity = self
            .blocking
            .run(move || policy.validate_at(&chain, SystemTime::now()))
            .await?;
        validity.check(SystemTime::now())?;
        Ok(validity)
    }

    fn validate_at(
        &self,
        chain: &[CertificateDer<'_>],
        now: SystemTime,
    ) -> Result<ClientValidity, ClientIdentityError> {
        let (leaf, intermediates) = chain.split_first().ok_or(ClientIdentityError::EmptyChain)?;
        let (verifier, mut valid_until) =
            load_verifier(&self.roots, &self.provider, &self.crls_path, now)?;
        let time = UnixTime::since_unix_epoch(
            now.duration_since(UNIX_EPOCH)
                .map_err(|_| ClientIdentityError::InvalidTime)?,
        );
        let leaf = webpki::EndEntityCert::try_from(leaf)
            .map_err(|error| ClientIdentityError::Verification(webpki_error(error)))?;
        let path = verifier
            .verify_path(&leaf, intermediates, time)
            .map_err(ClientIdentityError::Verification)?;
        valid_until = valid_until.min(certificate_expiration(&path.end_entity().der())?);
        for certificate in path.intermediate_certificates() {
            valid_until = valid_until.min(certificate_expiration(&certificate.der())?);
        }
        let anchor_index = self
            .roots
            .roots
            .iter()
            .position(|anchor| std::ptr::eq(anchor, path.anchor()))
            .ok_or(ClientIdentityError::TrustAnchors)?;
        valid_until = valid_until.min(self.anchor_expirations[anchor_index]);
        ClientValidity::at(now, valid_until)
    }
}

pub(super) fn certificate_expiration(
    certificate: &CertificateDer<'_>,
) -> Result<SystemTime, ClientIdentityError> {
    let parsed = Certificate::from_der(certificate.as_ref())
        .map_err(|_| ClientIdentityError::MalformedCertificate)?;
    UNIX_EPOCH
        .checked_add(
            parsed
                .tbs_certificate()
                .validity()
                .not_after
                .to_unix_duration(),
        )
        .ok_or(ClientIdentityError::InvalidTime)
}

fn load_verifier(
    roots: &Arc<RootCertStore>,
    provider: &Arc<CryptoProvider>,
    path: &std::path::Path,
    now: SystemTime,
) -> Result<(Arc<KeyUsageVerifier>, SystemTime), ClientIdentityError> {
    let crls = CrlSet::load(path, now).map_err(|_| ClientIdentityError::RevocationMaterial)?;
    let valid_until = crls.next_update();
    Ok((
        Arc::new(KeyUsageVerifier {
            roots: Arc::clone(roots),
            root_hint_subjects: roots.subjects(),
            crls,
            supported_algorithms: provider.signature_verification_algorithms,
        }),
        valid_until,
    ))
}

#[derive(Debug)]
struct KeyUsageVerifier {
    roots: Arc<RootCertStore>,
    root_hint_subjects: Vec<rustls::DistinguishedName>,
    crls: CrlSet,
    supported_algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl KeyUsageVerifier {
    fn verify_path<'p>(
        &'p self,
        end_entity: &'p webpki::EndEntityCert<'p>,
        intermediates: &'p [CertificateDer<'p>],
        now: UnixTime,
    ) -> Result<webpki::VerifiedPath<'p>, rustls::Error> {
        let path = self
            .crls
            .verify_path(
                end_entity,
                &self.roots.roots,
                intermediates,
                now,
                self.supported_algorithms.all,
                webpki::KeyUsage::client_auth(),
            )
            .map_err(webpki_error)?;
        validate_key_usage(&end_entity.der(), intermediates)?;
        Ok(path)
    }
}

impl ClientCertVerifier for KeyUsageVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.root_hint_subjects
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let end_entity = webpki::EndEntityCert::try_from(end_entity).map_err(webpki_error)?;
        self.verify_path(&end_entity, intermediates, now)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, signature, &self.supported_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, signature, &self.supported_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algorithms.supported_schemes()
    }
    fn requires_raw_public_keys(&self) -> bool {
        false
    }
}

pub(super) fn webpki_error(error: webpki::Error) -> rustls::Error {
    use rustls::{CertRevocationListError, CertificateError, OtherError};
    use webpki::Error::*;
    use webpki::InvalidNameContext;
    match error {
        BadDer | BadDerTime | TrailingData(_) => CertificateError::BadEncoding.into(),
        CertNotValidYet { time, not_before } => {
            CertificateError::NotValidYetContext { time, not_before }.into()
        }
        CertExpired { time, not_after } => {
            CertificateError::ExpiredContext { time, not_after }.into()
        }
        InvalidCertValidity => CertificateError::Expired.into(),
        UnknownIssuer => CertificateError::UnknownIssuer.into(),
        CertNotValidForName(InvalidNameContext {
            expected,
            presented,
        }) => CertificateError::NotValidForNameContext {
            expected,
            presented,
        }
        .into(),
        CertRevoked => CertificateError::Revoked.into(),
        UnknownRevocationStatus => CertificateError::UnknownRevocationStatus.into(),
        CrlExpired { time, next_update } => {
            CertificateError::ExpiredRevocationListContext { time, next_update }.into()
        }
        IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),

        InvalidSignatureForPublicKey => CertificateError::BadSignature.into(),
        #[allow(deprecated)]
        UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => {
            CertificateError::UnsupportedSignatureAlgorithm.into()
        }
        UnsupportedSignatureAlgorithmContext(cx) => {
            CertificateError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                supported_algorithms: cx.supported_algorithms,
            }
            .into()
        }
        UnsupportedSignatureAlgorithmForPublicKeyContext(cx) => {
            CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
            .into()
        }

        InvalidCrlSignatureForPublicKey => CertRevocationListError::BadSignature.into(),
        #[allow(deprecated)]
        UnsupportedCrlSignatureAlgorithm | UnsupportedCrlSignatureAlgorithmForPublicKey => {
            CertRevocationListError::UnsupportedSignatureAlgorithm.into()
        }
        UnsupportedCrlSignatureAlgorithmContext(cx) => {
            CertRevocationListError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                supported_algorithms: cx.supported_algorithms,
            }
            .into()
        }
        UnsupportedCrlSignatureAlgorithmForPublicKeyContext(cx) => {
            CertRevocationListError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
            .into()
        }

        #[allow(deprecated)]
        RequiredEkuNotFound => CertificateError::InvalidPurpose.into(),
        RequiredEkuNotFoundContext(webpki::RequiredEkuNotFoundContext { required, present }) => {
            CertificateError::InvalidPurposeContext {
                required: extended_key_purpose(required.oid_values()),
                presented: present
                    .into_iter()
                    .map(|eku| extended_key_purpose(eku.into_iter()))
                    .collect(),
            }
            .into()
        }

        _ => CertificateError::Other(OtherError(Arc::new(error))).into(),
    }
}

fn extended_key_purpose(values: impl Iterator<Item = usize>) -> rustls::ExtendedKeyPurpose {
    let values = values.collect::<Vec<_>>();
    match values.as_slice() {
        webpki::KeyUsage::CLIENT_AUTH_REPR => rustls::ExtendedKeyPurpose::ClientAuth,
        webpki::KeyUsage::SERVER_AUTH_REPR => rustls::ExtendedKeyPurpose::ServerAuth,
        _ => rustls::ExtendedKeyPurpose::Other(values),
    }
}

#[derive(Debug)]
struct UnavailableRevocationVerifier {
    inner: Arc<dyn ClientCertVerifier>,
}

impl ClientCertVerifier for UnavailableRevocationVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }
    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownRevocationStatus,
        ))
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

// WebPki checks EKU but omits the restrictions in the KeyUsage extension.
pub(super) fn validate_key_usage(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Result<(), rustls::Error> {
    validate_key_usage_iter(
        end_entity,
        intermediates
            .iter()
            .map(|certificate| CertificateDer::from(certificate.as_ref())),
    )
}

pub(super) fn validate_key_usage_iter<'a>(
    end_entity: &'a CertificateDer<'_>,
    intermediates: impl IntoIterator<Item = CertificateDer<'a>>,
) -> Result<(), rustls::Error> {
    for (index, certificate) in std::iter::once(CertificateDer::from(end_entity.as_ref()))
        .chain(intermediates)
        .enumerate()
    {
        let parsed = Certificate::from_der(certificate.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let usage = parsed
            .tbs_certificate()
            .get_extension::<KeyUsage>()
            .map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        if let Some((_, usage)) = usage {
            if usage.0.is_empty() {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                ));
            }
            let allowed = if index == 0 {
                usage.digital_signature()
            } else {
                usage.key_cert_sign()
            };
            if !allowed {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::InvalidPurpose,
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum ClientIdentityError {
    TrustAnchors,
    RevocationMaterial,
    MalformedCertificate,
    MalformedIdentity,
    Allocation,
    EmptyChain,
    Verification(rustls::Error),
    Expired,
    InvalidTime,
    PolicyMismatch,
}

impl fmt::Display for ClientIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TrustAnchors => "client trust anchors are empty, malformed or unavailable",
            Self::RevocationMaterial => {
                "client revocation material is empty, invalid, stale or unavailable"
            }
            Self::MalformedCertificate => "client certificate is malformed",
            Self::MalformedIdentity => "client certificate account identity is malformed",
            Self::Allocation => "client identity allocation failed",
            Self::EmptyChain => "client certificate chain is empty",
            Self::Verification(_) => "client certificate verification failed",
            Self::Expired => "client certificate validity deadline has passed",
            Self::InvalidTime => "client certificate time is invalid",
            Self::PolicyMismatch => "client certificate belongs to a different host policy",
        })
    }
}

impl Error for ClientIdentityError {}

#[cfg(test)]
pub(super) mod tests;
