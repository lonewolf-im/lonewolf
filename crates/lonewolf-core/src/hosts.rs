// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use graviola::hashing::Sha256;
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyUsagePurpose, PublicKeyData};
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni};
use rustls::sign::CertifiedKey;
use zeroize::Zeroizing;

use crate::config::{HostConfig, HostTlsConfig};

#[derive(Clone, Debug)]
pub struct Hosts {
    default_host_index: usize,
    hosts: Arc<[Host]>,
}

#[derive(Debug)]
struct Host {
    domain: String,
    config: HostConfig,
    certified_key: Arc<CertifiedKey>,
    tls_server_config: Arc<rustls::ServerConfig>,
}

#[derive(Debug)]
struct HostCertResolver {
    domain: String,
    certified_key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for HostCertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match hello.server_name() {
            Some(name) if !name.eq_ignore_ascii_case(&self.domain) => None,
            _ => Some(Arc::clone(&self.certified_key)),
        }
    }
}

impl Hosts {
    pub fn new(
        hosts: &BTreeMap<String, HostConfig>,
        default_host: Option<&str>,
    ) -> Result<Self, HostsError> {
        if hosts.is_empty() {
            return Err(HostsError::Empty);
        }
        let selected = match default_host {
            Some(name) if hosts.contains_key(name) => name,
            Some(name) => return Err(HostsError::UnknownDefault(name.into())),
            None if hosts.len() == 1 => hosts
                .first_key_value()
                .map(|(name, _)| name.as_str())
                .ok_or(HostsError::Empty)?,
            None => return Err(HostsError::DefaultRequired),
        };
        let provider = Arc::new(rustls_graviola::default_provider());
        let mut resolver = ResolvesServerCertUsingSni::new();
        let mut sorted_hosts = Vec::with_capacity(hosts.len());
        for (domain, config) in hosts {
            let certified_key = match config.tls.as_ref() {
                Some(tls) => load_certified_key(domain, tls, &provider)?,
                None if domain == "localhost" => generate_localhost_key(&provider)?,
                None => return Err(HostsError::MissingTls(domain.clone())),
            };
            resolver
                .add(domain, certified_key.clone())
                .map_err(|source| HostsError::InvalidCertificate {
                    domain: domain.clone(),
                    source,
                })?;
            let certified_key = Arc::new(certified_key);
            let tls_server_config =
                rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                    .with_safe_default_protocol_versions()
                    .map_err(HostsError::TlsConfiguration)?
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(HostCertResolver {
                        domain: domain.clone(),
                        certified_key: Arc::clone(&certified_key),
                    }));
            sorted_hosts.push(Host {
                domain: domain.clone(),
                config: config.clone(),
                certified_key,
                tls_server_config: Arc::new(tls_server_config),
            });
        }
        let default_host_index = sorted_hosts
            .binary_search_by(|host| host.domain.as_str().cmp(selected))
            .map_err(|_| HostsError::UnknownDefault(selected.into()))?;
        Ok(Self {
            default_host_index,
            hosts: sorted_hosts.into(),
        })
    }

    pub fn default_host_name(&self) -> &str {
        &self.hosts[self.default_host_index].domain
    }

    /// The input must be a normalized XMPP domainpart.
    pub fn is_local_host(&self, domain: &str) -> bool {
        self.find_host(domain).is_some()
    }

    pub fn host_names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.hosts.iter().map(|host| host.domain.as_str())
    }

    pub fn tls_config(&self, domain: &str) -> Option<&HostTlsConfig> {
        self.find_host(domain)?.config.tls.as_ref()
    }

    pub fn certified_key(&self, domain: &str) -> Option<&CertifiedKey> {
        Some(&self.find_host(domain)?.certified_key)
    }

    pub fn tls_server_config(&self, domain: &str) -> Option<&Arc<rustls::ServerConfig>> {
        Some(&self.find_host(domain)?.tls_server_config)
    }

    fn find_host(&self, domain: &str) -> Option<&Host> {
        let index = self
            .hosts
            .binary_search_by(|host| host.domain.as_str().cmp(domain))
            .ok()?;
        self.hosts.get(index)
    }
}

fn load_certified_key(
    domain: &str,
    tls: &HostTlsConfig,
    provider: &rustls::crypto::CryptoProvider,
) -> Result<CertifiedKey, HostsError> {
    let certificate_file =
        File::open(&tls.certificate_chain_path).map_err(|source| HostsError::ReadCertificate {
            domain: domain.into(),
            path: tls.certificate_chain_path.clone(),
            source,
        })?;
    let certificates = CertificateDer::pem_reader_iter(certificate_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| HostsError::ReadCertificate {
            domain: domain.into(),
            path: tls.certificate_chain_path.clone(),
            source: io::Error::other(source),
        })?;
    if certificates.is_empty() {
        return Err(HostsError::NoCertificates(domain.into()));
    }

    let key_file =
        File::open(&tls.private_key_path).map_err(|source| HostsError::ReadPrivateKey {
            domain: domain.into(),
            path: tls.private_key_path.clone(),
            source,
        })?;
    let key = PrivateKeyDer::from_pem_reader(key_file).map_err(|source| match source {
        PemError::NoItemsFound => HostsError::NoPrivateKey(domain.into()),
        source => HostsError::ReadPrivateKey {
            domain: domain.into(),
            path: tls.private_key_path.clone(),
            source: io::Error::other(source),
        },
    })?;
    certified_key(domain, certificates, key, provider)
}

fn certified_key(
    domain: &str,
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    provider: &rustls::crypto::CryptoProvider,
) -> Result<CertifiedKey, HostsError> {
    let certified_key = CertifiedKey::from_der(certificates, key, provider).map_err(|source| {
        HostsError::InvalidCertificate {
            domain: domain.into(),
            source,
        }
    })?;
    certified_key
        .keys_match()
        .map_err(|source| HostsError::InvalidCertificate {
            domain: domain.into(),
            source,
        })?;
    Ok(certified_key)
}

fn generate_localhost_key(
    provider: &rustls::crypto::CryptoProvider,
) -> Result<CertifiedKey, HostsError> {
    let key = SigningKey::<P256> {
        private_key: StaticPrivateKey::new_random()
            .map_err(|error| HostsError::GenerateLocalhost(format!("{error:?}")))?,
    };
    let mut parameters =
        CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into(), "::1".into()])
            .map_err(|error| HostsError::GenerateLocalhost(error.to_string()))?;
    let now = time::OffsetDateTime::now_utc();
    let mut serial_number = [0_u8; 16];
    graviola::random::fill(&mut serial_number)
        .map_err(|error| HostsError::GenerateLocalhost(format!("{error:?}")))?;
    parameters.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_number));
    parameters.not_before = now - time::Duration::days(1);
    parameters.not_after = now + time::Duration::days(30);
    parameters.distinguished_name = rcgen::DistinguishedName::new();
    parameters
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let signer = LocalhostSigner {
        public_key: key.private_key.public_key_uncompressed(),
        key,
    };
    let certificate = parameters
        .self_signed(&signer)
        .map_err(|error| HostsError::GenerateLocalhost(error.to_string()))?;
    let mut key_bytes = Zeroizing::new([0_u8; 512]);
    let key_der = signer
        .key
        .to_pkcs8_der(&mut key_bytes[..])
        .map_err(|error| HostsError::GenerateLocalhost(format!("{error:?}")))?;
    certified_key(
        "localhost",
        vec![certificate.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec())),
        provider,
    )
}

struct LocalhostSigner {
    key: SigningKey<P256>,
    public_key: [u8; 65],
}

impl PublicKeyData for LocalhostSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for LocalhostSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut signature = [0_u8; 80];
        self.key
            .sign_asn1::<Sha256>(&[message], &mut signature)
            .map(<[u8]>::to_vec)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

#[derive(Debug)]
pub enum HostsError {
    Empty,
    DefaultRequired,
    UnknownDefault(String),
    MissingTls(String),
    ReadCertificate {
        domain: String,
        path: PathBuf,
        source: io::Error,
    },
    NoCertificates(String),
    ReadPrivateKey {
        domain: String,
        path: PathBuf,
        source: io::Error,
    },
    NoPrivateKey(String),
    InvalidCertificate {
        domain: String,
        source: rustls::Error,
    },
    TlsConfiguration(rustls::Error),
    GenerateLocalhost(String),
}

impl fmt::Display for HostsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("hosts must define at least one domain"),
            Self::DefaultRequired => {
                formatter.write_str("xmpp.default_host is required when multiple hosts are defined")
            }
            Self::UnknownDefault(name) => {
                write!(
                    formatter,
                    "xmpp.default_host references unknown host {name:?}"
                )
            }
            Self::MissingTls(domain) => write!(formatter, "hosts.{domain}.tls is required"),
            Self::ReadCertificate {
                domain,
                path,
                source,
            } => write!(
                formatter,
                "cannot read certificate chain for hosts.{domain} from {}: {source}",
                path.display()
            ),
            Self::NoCertificates(domain) => {
                write!(formatter, "hosts.{domain} has no PEM certificates")
            }
            Self::ReadPrivateKey {
                domain,
                path,
                source,
            } => write!(
                formatter,
                "cannot read private key for hosts.{domain} from {}: {source}",
                path.display()
            ),
            Self::NoPrivateKey(domain) => {
                write!(formatter, "hosts.{domain} has no PEM private key")
            }
            Self::InvalidCertificate { domain, source } => {
                write!(
                    formatter,
                    "invalid TLS material for hosts.{domain}: {source}"
                )
            }
            Self::TlsConfiguration(source) => {
                write!(formatter, "cannot initialize TLS server: {source}")
            }
            Self::GenerateLocalhost(reason) => {
                write!(
                    formatter,
                    "cannot generate localhost TLS certificate: {reason}"
                )
            }
        }
    }
}

impl Error for HostsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReadCertificate { source, .. } | Self::ReadPrivateKey { source, .. } => {
                Some(source)
            }
            Self::InvalidCertificate { source, .. } => Some(source),
            _ => None,
        }
    }
}
