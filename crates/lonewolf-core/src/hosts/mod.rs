// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use graviola::hashing::{Hash, Sha256, Sha384, Sha512};
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey};
use parking_lot::RwLock as PlRwLock;
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyUsagePurpose, PublicKeyData};
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{
    CertificateDer, DnsName, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage, SubjectAltName, name::GeneralName};
use zeroize::Zeroizing;

use crate::config::{HostConfig, HostTlsConfig, HostTlsSource};
use lonewolf_util::blocking::BlockingExecutor;

pub mod client_identity;
pub(crate) mod peer_identity;
pub(crate) mod revocation;
pub(crate) mod service_identity;

use client_identity::{ClientCertificatePolicy, ClientIdentityError};
use peer_identity::PeerTrust;
use service_identity::{XmppService, verify_service_identity};

#[derive(Clone, Debug)]
pub struct Hosts {
    default_host_index: usize,
    hosts: Arc<[Host]>,
}

#[derive(Debug)]
struct Host {
    domain: String,
    config: HostConfig,
    tls: Arc<PlRwLock<Option<Arc<TlsSnapshot>>>>,
    tls_builder: rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>,
    client_certificate_policy: Option<Arc<ClientCertificatePolicy>>,
}

pub struct TlsHandshake {
    pub config: Arc<rustls::ServerConfig>,
    pub server_end_point: Arc<[u8]>,
}

struct TlsSnapshot {
    certified_key: Arc<CertifiedKey>,
    resolver: Arc<HostCertResolver>,
    config: Arc<rustls::ServerConfig>,
    server_end_point: Arc<[u8]>,
    validity: Option<(u64, u64)>,
}

pub struct PreparedCertificate {
    target: Arc<PlRwLock<Option<Arc<TlsSnapshot>>>>,
    snapshot: Arc<TlsSnapshot>,
    validity: (u64, u64),
}

impl PreparedCertificate {
    /// Returns the full-chain validity interval in Unix seconds.
    pub fn validity(&self) -> (u64, u64) {
        self.validity
    }

    /// Publishes the prepared generation without revalidation.
    pub fn activate(self) {
        let previous = self.target.write().replace(self.snapshot);
        drop(previous);
    }
}

impl fmt::Debug for TlsSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsSnapshot")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for TlsHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsHandshake")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PreparedCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCertificate")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct HostCertResolver {
    identity: ServerName<'static>,
    certified_key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for HostCertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match (hello.server_name(), &self.identity) {
            (None, _) => Some(Arc::clone(&self.certified_key)),
            (Some(name), ServerName::DnsName(identity))
                if name.eq_ignore_ascii_case(identity.as_ref()) =>
            {
                Some(Arc::clone(&self.certified_key))
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
struct HostClientCertResolver {
    tls: Arc<PlRwLock<Option<Arc<TlsSnapshot>>>>,
}

impl rustls::client::ResolvesClientCert for HostClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let snapshot = self.tls.read();
        let snapshot = snapshot.as_ref()?;
        if !snapshot.is_current()
            || snapshot
                .certified_key
                .key
                .choose_scheme(sigschemes)
                .is_none()
        {
            return None;
        }
        Some(Arc::clone(&snapshot.certified_key))
    }

    fn has_certs(&self) -> bool {
        self.tls
            .read()
            .as_ref()
            .is_some_and(|snapshot| snapshot.is_current())
    }
}

#[derive(Debug)]
struct ServiceCertResolver {
    identity: ServerName<'static>,
    snapshot: Arc<TlsSnapshot>,
}

impl ResolvesServerCert for ServiceCertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if !self.snapshot.is_current() {
            return None;
        }
        match (hello.server_name(), &self.identity) {
            (None, _) => Some(Arc::clone(&self.snapshot.certified_key)),
            (Some(name), ServerName::DnsName(identity))
                if name.eq_ignore_ascii_case(identity.as_ref()) =>
            {
                Some(Arc::clone(&self.snapshot.certified_key))
            }
            _ => None,
        }
    }
}

impl rustls::client::ResolvesClientCert for ServiceCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        if !self.snapshot.is_current()
            || self
                .snapshot
                .certified_key
                .key
                .choose_scheme(sigschemes)
                .is_none()
        {
            return None;
        }
        Some(Arc::clone(&self.snapshot.certified_key))
    }

    fn has_certs(&self) -> bool {
        self.snapshot.is_current()
    }
}

impl TlsSnapshot {
    fn is_current(&self) -> bool {
        self.validity.is_none_or(|(start, end)| {
            let now = UnixTime::now().as_secs();
            now >= start && now < end
        })
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
        let mut sorted_hosts = Vec::with_capacity(hosts.len());
        let blocking = BlockingExecutor::new(const { NonZeroUsize::new(2).unwrap() });
        for (domain, config) in hosts {
            let identity = tls_identity(domain)?;
            let client_certificate_policy = config
                .tls
                .as_ref()
                .and_then(|tls| tls.client_auth.as_ref())
                .map(|client| {
                    ClientCertificatePolicy::load(
                        domain,
                        client,
                        Arc::clone(&provider),
                        blocking.clone(),
                    )
                })
                .transpose()
                .map_err(|source| HostsError::ClientCertificates {
                    domain: domain.clone(),
                    source,
                })?;
            let tls_builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .map_err(HostsError::TlsConfiguration)?;
            let certified_key = match config.tls.as_ref() {
                Some(HostTlsConfig {
                    source: HostTlsSource::LetsEncrypt,
                    ..
                }) => None,
                Some(tls) => Some(load_certified_key(domain, tls, &provider)?),
                None if domain == "localhost" => Some(generate_localhost_key(&provider)?),
                None => return Err(HostsError::MissingTls(domain.clone())),
            };
            let snapshot = certified_key
                .map(|key| {
                    make_snapshot(
                        domain,
                        identity,
                        key,
                        &tls_builder,
                        client_certificate_policy.as_ref(),
                        None,
                    )
                })
                .transpose()?;
            sorted_hosts.push(Host {
                domain: domain.clone(),
                config: config.clone(),
                tls: Arc::new(PlRwLock::new(snapshot.map(Arc::new))),
                tls_builder,
                client_certificate_policy,
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

    pub fn certified_key(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        let snapshot = self.snapshot(domain)?;
        Some(Arc::clone(&snapshot.certified_key))
    }

    /// Admission captures one generation before any client-verifier refresh.
    pub async fn tls_handshake(&self, domain: &str) -> Option<TlsHandshake> {
        let host = self.find_host(domain)?;
        let snapshot = self.snapshot(domain)?;
        if snapshot.validity.is_some_and(|(start, end)| {
            let now = UnixTime::now().as_secs();
            now < start || now >= end
        }) {
            return None;
        }
        let config = if let Some(policy) = &host.client_certificate_policy {
            let verifier = policy.handshake_verifier().await;
            // Fresh resumption state prevents reuse of an older client-certificate verdict.
            let mut config = host
                .tls_builder
                .clone()
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(snapshot.resolver.clone());
            config.require_ems = true;
            Arc::new(config)
        } else {
            Arc::clone(&snapshot.config)
        };
        Some(TlsHandshake {
            config,
            server_end_point: Arc::clone(&snapshot.server_end_point),
        })
    }

    pub(crate) fn crypto_provider(&self) -> Arc<rustls::crypto::CryptoProvider> {
        Arc::clone(
            self.hosts[self.default_host_index]
                .tls_builder
                .crypto_provider(),
        )
    }

    pub(crate) fn federates(&self, domain: &str) -> bool {
        self.find_host(domain).is_some_and(|host| {
            host.config.federation
                && host.config.tls.is_some()
                && crate::config::managed_dns_name(domain).is_ok()
        })
    }

    pub(crate) fn certificate_host_for(&self, domain: &str) -> Option<&str> {
        self.certificate_snapshot_for(domain)
            .map(|(host, _)| host.domain.as_str())
    }

    fn certificate_snapshot_for(&self, domain: &str) -> Option<(&Host, Arc<TlsSnapshot>)> {
        let identity = tls_identity(domain).ok()?;
        for host in self
            .hosts
            .iter()
            .filter(|host| self.federates(&host.domain))
        {
            let Some(snapshot) = host.tls.read().clone() else {
                continue;
            };
            if snapshot.is_current()
                && snapshot.certified_key.cert.first().is_some_and(|leaf| {
                    verify_service_identity(leaf, &identity, XmppService::Server).is_ok()
                })
            {
                return Some((host, snapshot));
            }
        }
        None
    }

    pub(crate) fn s2s_server_config(
        &self,
        domain: &str,
        trust: &Arc<PeerTrust>,
    ) -> Option<Arc<rustls::ServerConfig>> {
        let (host, resolver): (_, Arc<dyn ResolvesServerCert>) =
            if let Some(host) = self.find_host(domain) {
                let snapshot = self.snapshot(domain)?;
                if !snapshot.is_current() {
                    return None;
                }
                (host, snapshot.resolver.clone())
            } else {
                let (host, snapshot) = self.certificate_snapshot_for(domain)?;
                (
                    host,
                    Arc::new(ServiceCertResolver {
                        identity: tls_identity(domain).ok()?,
                        snapshot,
                    }),
                )
            };
        Some(Arc::new(
            host.tls_builder
                .clone()
                .with_client_cert_verifier(trust.client_verifier())
                .with_cert_resolver(resolver),
        ))
    }

    pub(crate) fn s2s_client_config(
        &self,
        domain: &str,
        trust: &Arc<PeerTrust>,
    ) -> Option<Arc<rustls::ClientConfig>> {
        let resolver: Arc<dyn rustls::client::ResolvesClientCert> =
            if let Some(host) = self.find_host(domain) {
                Arc::new(HostClientCertResolver {
                    tls: Arc::clone(&host.tls),
                })
            } else {
                let (_, snapshot) = self.certificate_snapshot_for(domain)?;
                Arc::new(ServiceCertResolver {
                    identity: tls_identity(domain).ok()?,
                    snapshot,
                })
            };
        let config = rustls::ClientConfig::builder_with_provider(self.crypto_provider())
            .with_safe_default_protocol_versions()
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(trust.server_verifier())
            .with_client_cert_resolver(resolver);
        Some(Arc::new(config))
    }

    pub fn tls_server_end_point(&self, domain: &str) -> Option<Arc<[u8]>> {
        let snapshot = self.snapshot(domain)?;
        Some(Arc::clone(&snapshot.server_end_point))
    }

    pub fn prepare_managed_certificate(
        &self,
        domain: &str,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<PreparedCertificate, HostsError> {
        let prepared = self.prepare_managed_material(domain, chain, key)?;
        let now = UnixTime::now().as_secs();
        let error = if now < prepared.validity.0 {
            Some(rustls::CertificateError::NotValidYet)
        } else if now >= prepared.validity.1 {
            Some(rustls::CertificateError::Expired)
        } else {
            None
        };
        if let Some(source) = error {
            return Err(HostsError::InvalidCertificate {
                domain: domain.into(),
                source: source.into(),
            });
        }
        Ok(prepared)
    }

    pub(crate) fn prepare_managed_material(
        &self,
        domain: &str,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<PreparedCertificate, HostsError> {
        let host = self
            .find_host(domain)
            .filter(|host| {
                matches!(
                    host.config.tls.as_ref().map(|tls| &tls.source),
                    Some(HostTlsSource::LetsEncrypt)
                )
            })
            .ok_or_else(|| HostsError::NotManaged(domain.into()))?;
        let identity = tls_identity(domain)?;
        let validity = managed_validity(domain, &identity, &chain)?;
        let key = certified_key(domain, chain, key, host.tls_builder.crypto_provider())?;
        let snapshot = make_snapshot(
            domain,
            identity,
            key,
            &host.tls_builder,
            host.client_certificate_policy.as_ref(),
            Some(validity),
        )?;
        Ok(PreparedCertificate {
            target: Arc::clone(&host.tls),
            snapshot: Arc::new(snapshot),
            validity,
        })
    }

    fn snapshot(&self, domain: &str) -> Option<Arc<TlsSnapshot>> {
        self.find_host(domain)?.tls.read().clone()
    }

    pub fn client_certificate_policy(&self, domain: &str) -> Option<&Arc<ClientCertificatePolicy>> {
        self.find_host(domain)?.client_certificate_policy.as_ref()
    }

    fn find_host(&self, domain: &str) -> Option<&Host> {
        let index = self
            .hosts
            .binary_search_by(|host| host.domain.as_str().cmp(domain))
            .ok()?;
        self.hosts.get(index)
    }
}

fn make_snapshot(
    domain: &str,
    identity: ServerName<'static>,
    key: CertifiedKey,
    builder: &rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>,
    policy: Option<&Arc<ClientCertificatePolicy>>,
    validity: Option<(u64, u64)>,
) -> Result<TlsSnapshot, HostsError> {
    key.end_entity_cert()
        .and_then(|certificate| {
            verify_service_identity(certificate, &identity, XmppService::Client)
        })
        .map_err(|source| HostsError::InvalidCertificate {
            domain: domain.into(),
            source,
        })?;
    let endpoint = key
        .cert
        .first()
        .and_then(|certificate| tls_server_end_point(certificate.as_ref()))
        .ok_or_else(|| HostsError::UnsupportedChannelBinding(domain.into()))?;
    let certified_key = Arc::new(key);
    let resolver = Arc::new(HostCertResolver {
        identity,
        certified_key: Arc::clone(&certified_key),
    });
    let verifier = policy.map_or_else(
        rustls::server::WebPkiClientVerifier::no_client_auth,
        |policy| policy.verifier(),
    );
    let mut config = builder
        .clone()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver.clone());
    // TLS 1.2 exporters need an extended master secret for channel binding.
    config.require_ems = true;
    Ok(TlsSnapshot {
        certified_key,
        resolver,
        config: Arc::new(config),
        server_end_point: endpoint.into(),
        validity,
    })
}

fn managed_validity(
    domain: &str,
    identity: &ServerName<'_>,
    chain: &[CertificateDer<'_>],
) -> Result<(u64, u64), HostsError> {
    let invalid = |source| HostsError::InvalidCertificate {
        domain: domain.into(),
        source,
    };
    let ServerName::DnsName(identity) = identity else {
        return Err(invalid(rustls::CertificateError::NotValidForName.into()));
    };
    if chain.is_empty() {
        return Err(HostsError::NoCertificates(domain.into()));
    }
    let mut start = 0;
    let mut end = u64::MAX;
    for (index, certificate) in chain.iter().enumerate() {
        let parsed = Certificate::from_der(certificate.as_ref())
            .map_err(|_| invalid(rustls::CertificateError::BadEncoding.into()))?;
        if index == 0 {
            let names = parsed
                .tbs_certificate()
                .get_extension::<SubjectAltName>()
                .map_err(|_| invalid(rustls::CertificateError::BadEncoding.into()))?;
            let exact_name = names.is_some_and(|(_, names)| {
                matches!(names.0.as_slice(), [GeneralName::DnsName(name)] if name.as_str().eq_ignore_ascii_case(identity.as_ref()))
            });
            if !exact_name {
                return Err(invalid(rustls::CertificateError::NotValidForName.into()));
            }
        }
        let tbs = parsed.tbs_certificate();
        if let Some((_, usage)) = tbs
            .get_extension::<KeyUsage>()
            .map_err(|_| invalid(rustls::CertificateError::BadEncoding.into()))?
            && !(if index == 0 {
                usage.digital_signature()
            } else {
                usage.key_cert_sign()
            })
        {
            return Err(invalid(rustls::CertificateError::InvalidPurpose.into()));
        }
        if let Some((_, usage)) = tbs
            .get_extension::<ExtendedKeyUsage>()
            .map_err(|_| invalid(rustls::CertificateError::BadEncoding.into()))?
            && !usage.0.iter().any(|oid| {
                *oid == x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1")
            })
        {
            return Err(invalid(rustls::CertificateError::InvalidPurpose.into()));
        }
        let validity = tbs.validity();
        let before = validity.not_before.to_unix_duration().as_secs();
        let after = validity.not_after.to_unix_duration().as_secs();
        if before >= after {
            return Err(invalid(rustls::CertificateError::BadEncoding.into()));
        }
        start = start.max(before);
        end = end.min(after);
    }
    if start >= end {
        return Err(invalid(rustls::CertificateError::BadEncoding.into()));
    }
    Ok((start, end))
}

pub(crate) fn tls_identity(domain: &str) -> Result<ServerName<'static>, HostsError> {
    let invalid = || HostsError::InvalidCertificate {
        domain: domain.into(),
        source: rustls::Error::General("invalid TLS identity".into()),
    };
    if domain.starts_with('[') {
        let address = domain
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .and_then(|inner| inner.parse::<Ipv6Addr>().ok())
            .ok_or_else(invalid)?;
        return Ok(ServerName::IpAddress(address.into()));
    }
    if let Ok(address) = domain.parse::<Ipv4Addr>() {
        return Ok(ServerName::IpAddress(address.into()));
    }
    let ascii = idna::domain_to_ascii_strict(domain).map_err(|_| invalid())?;
    let name = DnsName::try_from(ascii).map_err(|_| invalid())?;
    Ok(ServerName::DnsName(name))
}

fn tls_server_end_point(certificate: &[u8]) -> Option<Vec<u8>> {
    let parsed = Certificate::from_der(certificate).ok()?;
    let oid = parsed.signature_algorithm().oid.to_string();
    let digest = match oid.as_str() {
        "1.2.840.113549.1.1.5" | "1.2.840.113549.1.1.4" => Sha256::hash(certificate),
        "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" | "2.16.840.1.101.3.4.3.2" => {
            Sha256::hash(certificate)
        }
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => Sha384::hash(certificate),
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => Sha512::hash(certificate),
        _ => return None,
    };
    Some(digest.as_ref().to_vec())
}

fn load_certified_key(
    domain: &str,
    tls: &HostTlsConfig,
    provider: &rustls::crypto::CryptoProvider,
) -> Result<CertifiedKey, HostsError> {
    let HostTlsSource::Files {
        certificate_chain_path,
        private_key_path,
    } = &tls.source
    else {
        return Err(HostsError::NotManaged(domain.into()));
    };
    let certificate_file =
        File::open(certificate_chain_path).map_err(|source| HostsError::ReadCertificate {
            domain: domain.into(),
            path: certificate_chain_path.clone(),
            source,
        })?;
    let certificates = CertificateDer::pem_reader_iter(certificate_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| HostsError::ReadCertificate {
            domain: domain.into(),
            path: certificate_chain_path.clone(),
            source: io::Error::other(source),
        })?;
    if certificates.is_empty() {
        return Err(HostsError::NoCertificates(domain.into()));
    }

    let key_file = File::open(private_key_path).map_err(|source| HostsError::ReadPrivateKey {
        domain: domain.into(),
        path: private_key_path.clone(),
        source,
    })?;
    let key = PrivateKeyDer::from_pem_reader(key_file).map_err(|source| match source {
        PemError::NoItemsFound => HostsError::NoPrivateKey(domain.into()),
        source => HostsError::ReadPrivateKey {
            domain: domain.into(),
            path: private_key_path.clone(),
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
    NotManaged(String),
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
    ClientCertificates {
        domain: String,
        source: ClientIdentityError,
    },
    UnsupportedChannelBinding(String),
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
            Self::NotManaged(domain) => {
                write!(formatter, "hosts.{domain} is not a managed TLS host")
            }
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
            Self::ClientCertificates { domain, source } => write!(
                formatter,
                "invalid client certificate policy for hosts.{domain}: {source}"
            ),
            Self::UnsupportedChannelBinding(domain) => write!(
                formatter,
                "TLS certificate for hosts.{domain} has no supported signature hash for tls-server-end-point channel binding"
            ),
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
            Self::ClientCertificates { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
