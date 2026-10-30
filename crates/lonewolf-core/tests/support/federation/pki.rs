// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use graviola::hashing::Sha256;
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey};
use rcgen::{CertificateParams, CertifiedIssuer, PublicKeyData};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};

use super::super::TestResult;

pub struct FederationCa {
    issuer: CertifiedIssuer<'static, TestSigner>,
    trust_anchors: PathBuf,
    serial: std::sync::atomic::AtomicU64,
}

impl FederationCa {
    pub fn new(directory: &Path) -> TestResult<Self> {
        let mut parameters = CertificateParams::new(Vec::<String>::new())?;
        parameters.serial_number = Some(1u64.into());
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let issuer = CertifiedIssuer::self_signed(parameters, TestSigner::new()?)?;
        let trust_anchors = directory.join("trust-anchors.pem");
        fs::write(&trust_anchors, pem("CERTIFICATE", issuer.der()))?;
        Ok(Self {
            issuer,
            trust_anchors,
            serial: std::sync::atomic::AtomicU64::new(2),
        })
    }

    pub fn trust_anchors_path(&self) -> &Path {
        &self.trust_anchors
    }

    pub fn roots(&self) -> TestResult<rustls::RootCertStore> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.issuer.der().clone())?;
        Ok(roots)
    }

    pub fn server(
        &self,
        directory: &Path,
        name: &str,
        domains: &[&str],
    ) -> TestResult<Arc<CertifiedKey>> {
        self.server_until(
            directory,
            name,
            domains,
            OffsetDateTime::now_utc() + Duration::days(30),
        )
    }

    pub fn server_until(
        &self,
        directory: &Path,
        name: &str,
        domains: &[&str],
        expiry: OffsetDateTime,
    ) -> TestResult<Arc<CertifiedKey>> {
        let mut parameters = parameters(domains)?;
        parameters.not_after = expiry;
        self.issue(directory, name, parameters)
    }

    pub fn client_auth_only(
        &self,
        directory: &Path,
        domain: &str,
    ) -> TestResult<Arc<CertifiedKey>> {
        let mut parameters = parameters(&[domain])?;
        parameters.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        self.issue(directory, "client-auth-only", parameters)
    }

    pub fn without_eku(&self, directory: &Path, domain: &str) -> TestResult<Arc<CertifiedKey>> {
        let mut parameters = parameters(&[domain])?;
        parameters.extended_key_usages.clear();
        self.issue(directory, "without-eku", parameters)
    }

    pub fn wrong_name(&self, directory: &Path, domain: &str) -> TestResult<Arc<CertifiedKey>> {
        self.server(directory, "wrong-name", &[&format!("wrong.{domain}")])
    }

    pub fn expired(&self, directory: &Path, domain: &str) -> TestResult<Arc<CertifiedKey>> {
        self.server_until(
            directory,
            "expired",
            &[domain],
            OffsetDateTime::now_utc() - Duration::minutes(1),
        )
    }

    pub fn short_lived(
        &self,
        directory: &Path,
        domain: &str,
        seconds: i64,
    ) -> TestResult<Arc<CertifiedKey>> {
        self.server_until(
            directory,
            "short-lived",
            &[domain],
            OffsetDateTime::now_utc() + Duration::seconds(seconds),
        )
    }

    pub fn srv_id(&self, directory: &Path, domain: &str) -> TestResult<Arc<CertifiedKey>> {
        use x509_cert::der::{
            Encode,
            asn1::{Ia5String, ObjectIdentifier},
        };
        use x509_cert::ext::pkix::{
            SubjectAltName,
            name::{GeneralName, OtherName},
        };
        let mut parameters = parameters(&[])?;
        let name = GeneralName::OtherName(OtherName {
            type_id: ObjectIdentifier::new("1.3.6.1.5.5.7.8.7")?,
            value: (&Ia5String::new(&format!("_xmpp-server.{domain}"))?).into(),
        });
        parameters
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 17],
                SubjectAltName(vec![name]).to_der()?,
            ));
        self.issue(directory, "srv-id", parameters)
    }

    pub fn xmpp_addr(&self, directory: &Path, domain: &str) -> TestResult<Arc<CertifiedKey>> {
        let mut parameters = parameters(&[])?;
        parameters
            .subject_alt_names
            .push(rcgen::SanType::OtherName((
                vec![1, 3, 6, 1, 5, 5, 7, 8, 5],
                domain.into(),
            )));
        self.issue(directory, "xmpp-addr", parameters)
    }

    fn issue(
        &self,
        directory: &Path,
        name: &str,
        mut parameters: CertificateParams,
    ) -> TestResult<Arc<CertifiedKey>> {
        parameters.serial_number = Some(
            self.serial
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .into(),
        );
        let signer = TestSigner::new()?;
        let certificate = parameters.signed_by(&signer, &self.issuer)?;
        let mut bytes = zeroize::Zeroizing::new([0; 512]);
        let key = signer.key.to_pkcs8_der(&mut bytes[..])?;
        fs::write(
            directory.join(format!("certificate-{name}.pem")),
            pem("CERTIFICATE", certificate.der()),
        )?;
        fs::write(
            directory.join(format!("private-key-{name}.pem")),
            pem("PRIVATE KEY", key),
        )?;
        let provider = rustls_graviola::default_provider();
        let key = provider
            .key_provider
            .load_private_key(PrivatePkcs8KeyDer::from(key.to_vec()).into())?;
        Ok(Arc::new(CertifiedKey::new(
            vec![certificate.der().clone()],
            key,
        )))
    }
}

fn parameters(domains: &[&str]) -> TestResult<CertificateParams> {
    let mut parameters = CertificateParams::new(
        domains
            .iter()
            .map(|domain| (*domain).into())
            .collect::<Vec<String>>(),
    )?;
    parameters.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    parameters.not_after = OffsetDateTime::now_utc() + Duration::days(30);
    parameters.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    Ok(parameters)
}

fn pem(label: &str, bytes: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(bytes)
    )
}

struct TestSigner {
    key: SigningKey<P256>,
    public: [u8; 65],
}
impl TestSigner {
    fn new() -> TestResult<Self> {
        let key = SigningKey::<P256> {
            private_key: StaticPrivateKey::new_random()?,
        };
        Ok(Self {
            public: key.private_key.public_key_uncompressed(),
            key,
        })
    }
}
impl PublicKeyData for TestSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
impl rcgen::SigningKey for TestSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut bytes = [0; 80];
        self.key
            .sign_asn1::<Sha256>(&[message], &mut bytes)
            .map(<[u8]>::to_vec)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}
