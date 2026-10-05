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

pub struct ClientCertificates {
    issuer: rcgen::CertifiedIssuer<'static, TestSigner>,
    crls_path: std::path::PathBuf,
    pub trusted: Arc<rustls::sign::CertifiedKey>,
    pub absent_key_usage: Arc<rustls::sign::CertifiedKey>,
    pub without_xmpp_addr: Arc<rustls::sign::CertifiedKey>,
    pub malformed_xmpp_addr: Arc<rustls::sign::CertifiedKey>,
    pub rejected: Vec<(&'static str, Arc<rustls::sign::CertifiedKey>)>,
}

impl ClientCertificates {
    pub fn replace_crl(&self, revoked: bool, next_update: time::OffsetDateTime) -> TestResult {
        let now = time::OffsetDateTime::now_utc();
        let crl = rcgen::CertificateRevocationListParams {
            this_update: now - time::Duration::days(1),
            next_update,
            crl_number: 2u64.into(),
            issuing_distribution_point: None,
            revoked_certs: if revoked {
                vec![rcgen::RevokedCertParams {
                    serial_number: 42u64.into(),
                    revocation_time: now,
                    reason_code: None,
                    invalidity_date: None,
                }]
            } else {
                vec![]
            },
            key_identifier_method: rcgen::KeyIdMethod::PreSpecified(vec![1]),
        }
        .signed_by(&self.issuer)?;
        fs::write(&self.crls_path, pem("X509 CRL", crl.der())?)?;
        Ok(())
    }

    pub fn configure(directory: &Path) -> TestResult<Self> {
        use rcgen::{
            BasicConstraints, CertifiedIssuer, DnType, IsCa, KeyIdMethod, KeyUsagePurpose,
        };
        use std::io::Write as _;

        let now = time::OffsetDateTime::now_utc();
        let mut parameters = CertificateParams::new(Vec::<String>::new())?;
        parameters.serial_number = Some(1u64.into());
        parameters
            .distinguished_name
            .push(DnType::CommonName, "Client Root");
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        parameters.key_identifier_method = KeyIdMethod::PreSpecified(vec![1]);
        parameters.not_before = now - time::Duration::days(1);
        parameters.not_after = now + time::Duration::days(30);
        let root = CertifiedIssuer::self_signed(parameters.clone(), TestSigner::new()?)?;
        fs::write(
            directory.join("client-roots.pem"),
            pem("CERTIFICATE", root.der())?,
        )?;
        let crl = rcgen::CertificateRevocationListParams {
            this_update: now - time::Duration::minutes(1),
            next_update: now + time::Duration::days(1),
            crl_number: 1u64.into(),
            issuing_distribution_point: None,
            revoked_certs: vec![rcgen::RevokedCertParams {
                serial_number: 43u64.into(),
                revocation_time: now - time::Duration::minutes(1),
                reason_code: None,
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::PreSpecified(vec![1]),
        }
        .signed_by(&root)?;
        fs::write(
            directory.join("client-crls.pem"),
            pem("X509 CRL", crl.der())?,
        )?;
        let mut config = fs::OpenOptions::new()
            .append(true)
            .open(directory.join("lonewolf.toml"))?;
        writeln!(
            config,
            "\n[hosts.localhost.tls.client_auth]\ntrust_anchors_path = 'client-roots.pem'\ncrls_path = 'client-crls.pem'"
        )?;
        let trusted = client_key(
            &root,
            now,
            42,
            Some("alice@localhost"),
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        )?;
        let without_xmpp_addr = client_key(
            &root,
            now,
            42,
            None,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        )?;
        let malformed_xmpp_addr = client_key(
            &root,
            now,
            42,
            Some("alice@localhost/phone"),
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        )?;
        parameters
            .distinguished_name
            .push(DnType::CommonName, "Other Root");
        let other = CertifiedIssuer::self_signed(parameters.clone(), TestSigner::new()?)?;
        let untrusted = client_key(
            &other,
            now,
            42,
            Some("alice@localhost"),
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        )?;
        let expired = client_key(
            &root,
            now - time::Duration::days(3),
            42,
            Some("alice@localhost"),
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        )?;
        let revoked = client_key(
            &root,
            now,
            43,
            Some("alice@localhost"),
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        )?;
        let wrong_eku = client_key(
            &root,
            now,
            42,
            Some("alice@localhost"),
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        )?;
        parameters
            .distinguished_name
            .push(DnType::CommonName, "Intermediate");
        let intermediate =
            CertifiedIssuer::signed_by(parameters.clone(), TestSigner::new()?, &root)?;
        let invalid_chain = client_key(
            &intermediate,
            now,
            42,
            Some("alice@localhost"),
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        )?;
        parameters
            .distinguished_name
            .push(DnType::CommonName, "Prohibited Intermediate");
        parameters.key_usages = vec![KeyUsagePurpose::CrlSign];
        parameters.key_identifier_method = KeyIdMethod::PreSpecified(vec![2]);
        let prohibited_intermediate =
            CertifiedIssuer::signed_by(parameters, TestSigner::new()?, &root)?;
        let intermediate_crl = rcgen::CertificateRevocationListParams {
            this_update: now - time::Duration::minutes(1),
            next_update: now + time::Duration::days(1),
            crl_number: 1u64.into(),
            issuing_distribution_point: None,
            revoked_certs: vec![],
            key_identifier_method: KeyIdMethod::PreSpecified(vec![2]),
        }
        .signed_by(&prohibited_intermediate)?;
        fs::write(
            directory.join("client-crls.pem"),
            format!(
                "{}{}",
                pem("X509 CRL", crl.der())?,
                pem("X509 CRL", intermediate_crl.der())?
            ),
        )?;
        let mut prohibited_chain = client_key(
            &prohibited_intermediate,
            now,
            42,
            Some("alice@localhost"),
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        )?
        .as_ref()
        .clone();
        prohibited_chain
            .cert
            .push(prohibited_intermediate.der().clone());
        let mut leaf = CertificateParams::new(Vec::<String>::new())?;
        leaf.serial_number = Some(42u64.into());
        leaf.not_before = now - time::Duration::hours(1);
        leaf.not_after = now + time::Duration::days(1);
        leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let absent_key_usage = client_key_from_parameters(&root, leaf.clone())?;
        leaf.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
        let wrong_key_usage = client_key_from_parameters(&root, leaf.clone())?;
        leaf.key_usages.clear();
        leaf.custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 15],
                vec![0x04, 0x01, 0x80],
            ));
        let malformed_key_usage = client_key_from_parameters(&root, leaf.clone())?;
        leaf.custom_extensions.clear();
        leaf.custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 15],
                vec![0x03, 0x01, 0x00],
            ));
        let empty_key_usage = client_key_from_parameters(&root, leaf.clone())?;
        leaf.custom_extensions.clear();
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 15],
                vec![0x03, 0x02, 0x07, 0x80],
            ));
        let duplicate_key_usage = client_key_from_parameters(&root, leaf)?;
        Ok(Self {
            issuer: root,
            crls_path: directory.join("client-crls.pem"),
            trusted,
            absent_key_usage,
            without_xmpp_addr,
            malformed_xmpp_addr,
            rejected: vec![
                ("untrusted", untrusted),
                ("expired", expired),
                ("revoked", revoked),
                ("wrong EKU", wrong_eku),
                ("missing intermediate", invalid_chain),
                ("prohibited key usage", wrong_key_usage),
                (
                    "prohibited intermediate key usage",
                    Arc::new(prohibited_chain),
                ),
                ("malformed key usage", malformed_key_usage),
                ("empty key usage", empty_key_usage),
                ("duplicate key usage", duplicate_key_usage),
            ],
        })
    }
}

fn client_key(
    issuer: &rcgen::Issuer<'_, TestSigner>,
    now: time::OffsetDateTime,
    serial: u64,
    xmpp_addr: Option<&str>,
    eku: rcgen::ExtendedKeyUsagePurpose,
) -> TestResult<Arc<rustls::sign::CertifiedKey>> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.serial_number = Some(serial.into());
    parameters.not_before = now - time::Duration::hours(1);
    parameters.not_after = now + time::Duration::days(1);
    parameters.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![eku];
    if let Some(identity) = xmpp_addr {
        parameters
            .subject_alt_names
            .push(rcgen::SanType::OtherName((
                vec![1, 3, 6, 1, 5, 5, 7, 8, 5],
                identity.into(),
            )));
    }
    client_key_from_parameters(issuer, parameters)
}

fn client_key_from_parameters(
    issuer: &rcgen::Issuer<'_, TestSigner>,
    parameters: CertificateParams,
) -> TestResult<Arc<rustls::sign::CertifiedKey>> {
    let signer = TestSigner::new()?;
    let certificate = parameters.signed_by(&signer, issuer)?;
    let mut buffer = [0; 512];
    let key = signer.key.to_pkcs8_der(&mut buffer)?;
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key.to_vec()).into();
    let key = rustls_graviola::default_provider()
        .key_provider
        .load_private_key(key)?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(
        vec![certificate.der().clone()],
        key,
    )))
}

impl TestSigner {
    fn new() -> TestResult<Self> {
        let key = SigningKey::<P256> {
            private_key: StaticPrivateKey::new_random()?,
        };
        Ok(Self {
            public_key: key.private_key.public_key_uncompressed(),
            key,
        })
    }
}

pub fn with_client_certificate(
    config: &ClientConfig,
    key: Arc<rustls::sign::CertifiedKey>,
) -> Arc<ClientConfig> {
    let mut config = config.clone();
    config.client_auth_cert_resolver = Arc::new(ClientCertResolver(key));
    Arc::new(config)
}

#[derive(Debug)]
struct ClientCertResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::client::ResolvesClientCert for ClientCertResolver {
    fn resolve(
        &self,
        _: &[&[u8]],
        schemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.0
            .key
            .choose_scheme(schemes)
            .map(|_| Arc::clone(&self.0))
    }
    fn has_certs(&self) -> bool {
        true
    }
}

pub fn block_crl_reads(path: &Path) -> TestResult<Vec<u8>> {
    let original = fs::read(path)?;
    fs::remove_file(path)?;
    let status = std::process::Command::new("mkfifo").arg(path).status()?;
    if !status.success() {
        return Err("cannot create CRL read gate".into());
    }
    Ok(original)
}

pub fn wait_for_crl_reader(path: &Path) -> TestResult<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let deadline = std::time::Instant::now() + super::TIMEOUT;
    loop {
        match fs::OpenOptions::new()
            .write(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(path)
        {
            Ok(writer) => return Ok(writer),
            Err(error)
                if error.raw_os_error() == Some(nix::libc::ENXIO)
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
}
