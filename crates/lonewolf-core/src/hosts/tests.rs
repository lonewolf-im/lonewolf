// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::{Config, HostConfig, HostTlsConfig, HostTlsSource};
use crate::hosts::test_support::{TestSigner, pem};
use crate::hosts::{Hosts, HostsError};
use graviola::signing::eddsa::Ed25519SigningKey;
use rcgen::{CertificateParams, PublicKeyData};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use x509_cert::der::{Decode, Encode};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn pending_managed_hosts_still_validate_client_certificate_policy() -> TestResult {
    for domain in ["example.com", "localhost"] {
        let configured = BTreeMap::from([(
            domain.into(),
            HostConfig {
                tls: Some(HostTlsConfig {
                    source: HostTlsSource::LetsEncrypt,
                    client_auth: Some(crate::config::ClientCertificateConfig {
                        trust_anchors_path: "missing-roots.pem".into(),
                        crls_path: "missing-crls.pem".into(),
                    }),
                }),
                ..HostConfig::default()
            },
        )]);
        let error = Hosts::new(&configured, None)
            .err()
            .ok_or("managed host accepted")?;
        assert!(
            matches!(&error, HostsError::ClientCertificates { domain: name, .. } if name == domain)
        );
    }
    Ok(())
}

#[test]
fn idn_host_initializes_with_an_alabel_certificate() -> TestResult {
    assert_host_identity("bücher.example", "xn--bcher-kva.example")
}

#[test]
fn ipv4_host_initializes_with_an_ip_certificate() -> TestResult {
    assert_host_identity("192.0.2.1", "192.0.2.1")
}

#[test]
fn ipv6_host_initializes_with_an_ip_certificate() -> TestResult {
    assert_host_identity("[2001:db8::1]", "2001:db8::1")
}

fn assert_host_identity(domain: &str, certificate_identity: &str) -> TestResult {
    let directory = tempfile::tempdir()?;
    let tls = test_tls_files(&directory, certificate_identity, "identity")?;
    let configured = BTreeMap::from([(
        domain.into(),
        HostConfig {
            tls: Some(tls),
            ..HostConfig::default()
        },
    )]);
    let hosts = Hosts::new(&configured, None)?;
    assert_eq!(hosts.default_host_name(), domain);
    assert!(hosts.is_local_host(domain));
    assert!(hosts.certified_key(domain).is_some());
    assert_eq!(
        hosts
            .tls_server_end_point(domain)
            .map(|digest| digest.len()),
        Some(32)
    );
    Ok(())
}

#[test]
fn tls_identities_use_ascii_dns_and_typed_ip_addresses() -> TestResult {
    use rustls::pki_types::ServerName;
    assert_eq!(
        super::tls_identity("bücher.example")?,
        ServerName::try_from("xn--bcher-kva.example")?
    );
    assert_eq!(
        super::tls_identity("localhost")?,
        ServerName::try_from("localhost")?
    );
    assert_eq!(
        super::tls_identity("192.0.2.1")?,
        ServerName::try_from("192.0.2.1")?
    );
    assert_eq!(
        super::tls_identity("[2001:db8::1]")?,
        ServerName::try_from("2001:db8::1")?
    );
    for domain in [
        "",
        "[not-ip]",
        "[192.0.2.1]",
        "[2001:db8::1",
        "2001:db8::1",
        "[fe80::1%eth0]",
        "[fe80::1%25eth0]",
        "bad_domain.example",
        "-bad.example",
        "192.0.2.999",
    ] {
        assert!(super::tls_identity(domain).is_err(), "{domain}");
    }
    Ok(())
}

#[test]
fn dns_and_ip_san_mismatches_are_rejected() -> TestResult {
    let directory = tempfile::tempdir()?;
    for (domain, san) in [
        (
            "bücher.example",
            rcgen::SanType::DnsName("other.example".try_into()?),
        ),
        ("192.0.2.1", rcgen::SanType::IpAddress("192.0.2.2".parse()?)),
        (
            "[2001:db8::1]",
            rcgen::SanType::IpAddress("2001:db8::2".parse()?),
        ),
        (
            "192.0.2.1",
            rcgen::SanType::DnsName("192.0.2.1".try_into()?),
        ),
        (
            "[2001:db8::1]",
            rcgen::SanType::DnsName("2001:db8::1".try_into()?),
        ),
    ] {
        let mut parameters = CertificateParams::new(Vec::<String>::new())?;
        parameters.subject_alt_names.push(san);
        let tls = test_tls_parameters(&directory, parameters, "mismatch")?;
        let configured = BTreeMap::from([(
            domain.into(),
            HostConfig {
                tls: Some(tls),
                ..HostConfig::default()
            },
        )]);
        assert!(
            matches!(
                Hosts::new(&configured, None),
                Err(HostsError::InvalidCertificate {
                    source: rustls::Error::InvalidCertificate(
                        rustls::CertificateError::NotValidForName
                            | rustls::CertificateError::NotValidForNameContext { .. }
                    ),
                    ..
                })
            ),
            "{domain}"
        );
    }
    Ok(())
}

#[test]
fn single_host_is_the_default_and_has_generated_tls() -> TestResult {
    let config = Config::default();
    let hosts = Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
    let next_start = Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;

    assert_eq!(hosts.default_host_name(), "localhost");
    assert_eq!(hosts.host_names().collect::<Vec<_>>(), ["localhost"]);
    assert!(hosts.is_local_host("localhost"));
    assert!(!hosts.is_local_host("other.example"));
    assert!(hosts.tls_config("localhost").is_none());
    assert_eq!(
        hosts
            .tls_server_end_point("localhost")
            .map(|digest| digest.len()),
        Some(32)
    );
    let localhost = hosts
        .certified_key("localhost")
        .ok_or("missing certificate")?;
    localhost.keys_match()?;
    assert_ne!(
        localhost.cert,
        next_start
            .certified_key("localhost")
            .ok_or("missing next certificate")?
            .cert
    );
    Ok(())
}

#[test]
fn explicit_default_selects_a_host_and_tls_stays_per_host() -> TestResult {
    let directory = tempfile::tempdir()?;
    let tls = test_tls_files(&directory, "example.com", "one")?;
    let mut config = Config::default();
    config.hosts.insert(
        "example.com".into(),
        HostConfig {
            tls: Some(tls.clone()),
            ..HostConfig::default()
        },
    );
    let hosts = Hosts::new(&config.hosts, Some("example.com"))?;
    config.hosts.clear();

    assert_eq!(hosts.default_host_name(), "example.com");
    assert_eq!(
        hosts.host_names().collect::<Vec<_>>(),
        ["example.com", "localhost"]
    );
    assert!(hosts.is_local_host("example.com"));
    assert!(!hosts.is_local_host("EXAMPLE.COM"));
    assert!(hosts.tls_config("localhost").is_none());
    assert_eq!(hosts.tls_config("example.com"), Some(&tls));
    hosts
        .certified_key("example.com")
        .ok_or("missing certificate")?
        .keys_match()?;
    Ok(())
}

#[test]
fn sorted_hosts_support_exact_domain_lookups() -> TestResult {
    let directory = tempfile::tempdir()?;
    let alpha_tls = test_tls_files(&directory, "alpha.example", "alpha")?;
    let zeta_tls = test_tls_files(&directory, "zeta.example", "zeta")?;
    let mut config = Config::default();
    config.hosts.insert(
        "zeta.example".into(),
        HostConfig {
            tls: Some(zeta_tls.clone()),
            ..HostConfig::default()
        },
    );
    config.hosts.insert(
        "alpha.example".into(),
        HostConfig {
            tls: Some(alpha_tls.clone()),
            ..HostConfig::default()
        },
    );
    let hosts = Hosts::new(&config.hosts, Some("localhost"))?;

    assert_eq!(
        hosts.host_names().collect::<Vec<_>>(),
        ["alpha.example", "localhost", "zeta.example"]
    );
    assert_eq!(hosts.tls_config("alpha.example"), Some(&alpha_tls));
    assert_eq!(hosts.tls_config("zeta.example"), Some(&zeta_tls));
    for domain in ["alpha.example", "localhost", "zeta.example"] {
        assert!(hosts.is_local_host(domain));
        assert!(hosts.certified_key(domain).is_some());
    }
    for domain in ["aardvark.example", "middle.example", "zzzz.example"] {
        assert!(!hosts.is_local_host(domain));
        assert!(hosts.certified_key(domain).is_none());
    }
    Ok(())
}

#[test]
fn certificate_files_are_checked_during_bootstrap() -> TestResult {
    let directory = tempfile::tempdir()?;
    let tls = test_tls_files(&directory, "example.com", "one")?;
    let mut config = Config::default();
    config.hosts.clear();
    config.hosts.insert(
        "example.com".into(),
        HostConfig {
            tls: Some(tls.clone()),
            ..HostConfig::default()
        },
    );
    let hosts = Hosts::new(&config.hosts, None)?;
    assert_eq!(hosts.default_host_name(), "example.com");

    let other = test_tls_files(&directory, "other.example", "other")?;
    config
        .hosts
        .get_mut("example.com")
        .ok_or("missing host")?
        .tls = Some(other);
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::InvalidCertificate { .. })
    ));

    config
        .hosts
        .get_mut("example.com")
        .ok_or("missing host")?
        .tls = Some(HostTlsConfig {
        source: HostTlsSource::Files {
            certificate_chain_path: file_paths(&tls)?.0.to_path_buf(),
            private_key_path: PathBuf::from("missing.key"),
        },
        client_auth: None,
    });
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::ReadPrivateKey { .. })
    ));
    Ok(())
}

#[test]
fn mismatched_private_key_is_rejected() -> TestResult {
    let directory = tempfile::tempdir()?;
    let tls = test_tls_files(&directory, "example.com", "one")?;
    let other = test_tls_files(&directory, "example.com", "other")?;
    let mut config = Config::default();
    config.hosts.clear();
    config.hosts.insert(
        "example.com".into(),
        HostConfig {
            tls: Some(HostTlsConfig {
                source: HostTlsSource::Files {
                    certificate_chain_path: file_paths(&tls)?.0.to_path_buf(),
                    private_key_path: file_paths(&other)?.1.to_path_buf(),
                },
                client_auth: None,
            }),
            ..HostConfig::default()
        },
    );
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::InvalidCertificate { .. })
    ));
    Ok(())
}

#[test]
fn empty_and_malformed_certificate_files_are_rejected() -> TestResult {
    let directory = tempfile::tempdir()?;
    let tls = test_tls_files(&directory, "example.com", "one")?;
    let mut config = Config::default();
    config.hosts.clear();
    config.hosts.insert(
        "example.com".into(),
        HostConfig {
            tls: Some(tls.clone()),
            ..HostConfig::default()
        },
    );

    let (certificate_chain_path, _) = file_paths(&tls)?;
    fs::write(certificate_chain_path, b"")?;
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::NoCertificates(_))
    ));

    fs::write(
        certificate_chain_path,
        b"-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n",
    )?;
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::ReadCertificate { .. })
    ));

    fs::write(certificate_chain_path, pem("CERTIFICATE", b"not DER")?)?;
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::InvalidCertificate { .. })
    ));

    let restored = test_tls_files(&directory, "example.com", "restored")?;
    fs::write(file_paths(&restored)?.1, b"")?;
    config
        .hosts
        .get_mut("example.com")
        .ok_or("missing host")?
        .tls = Some(restored);
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::NoPrivateKey(_))
    ));
    Ok(())
}

#[test]
fn configured_localhost_certificate_replaces_generated_certificate() -> TestResult {
    let directory = tempfile::tempdir()?;
    let tls = test_tls_files(&directory, "localhost", "one")?;
    let mut config = Config::default();
    config.hosts.get_mut("localhost").ok_or("missing host")?.tls = Some(tls.clone());
    let hosts = Hosts::new(&config.hosts, None)?;

    assert_eq!(hosts.tls_config("localhost"), Some(&tls));
    hosts
        .certified_key("localhost")
        .ok_or("missing certificate")?
        .keys_match()?;
    Ok(())
}

#[test]
fn hashless_certificate_signature_is_rejected_at_bootstrap() -> TestResult {
    let directory = tempfile::tempdir()?;
    let key = Ed25519SigningKey::generate()?;
    let signer = Ed25519TestSigner {
        public_key: key.public_key().as_bytes(),
        key,
    };
    let mut parameters = CertificateParams::new(vec!["example.com".into()])?;
    parameters.serial_number = Some(rcgen::SerialNumber::from(1_u64));
    let certificate = parameters.self_signed(&signer)?;
    let certificate_chain_path = directory.path().join("ed25519-cert.pem");
    let private_key_path = directory.path().join("ed25519-key.pem");
    fs::write(
        &certificate_chain_path,
        pem("CERTIFICATE", certificate.der())?,
    )?;
    let mut private_key = [0_u8; 512];
    fs::write(
        &private_key_path,
        pem("PRIVATE KEY", signer.key.to_pkcs8_der(&mut private_key)?)?,
    )?;
    let mut config = Config::default();
    config.hosts.clear();
    config.hosts.insert(
        "example.com".into(),
        HostConfig {
            tls: Some(HostTlsConfig {
                source: HostTlsSource::Files {
                    certificate_chain_path,
                    private_key_path,
                },
                client_auth: None,
            }),
            ..HostConfig::default()
        },
    );
    let error = Hosts::new(&config.hosts, None)
        .err()
        .ok_or("hashless certificate accepted")?;
    assert!(
        matches!(error, HostsError::UnsupportedChannelBinding(domain) if domain == "example.com")
    );
    Ok(())
}

#[test]
fn invalid_default_selection_is_rejected() {
    let empty = BTreeMap::new();
    assert!(matches!(Hosts::new(&empty, None), Err(HostsError::Empty)));

    let mut config = Config::default();
    config
        .hosts
        .insert("example.com".into(), HostConfig::default());
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::DefaultRequired)
    ));
    assert!(matches!(
        Hosts::new(&config.hosts, Some("missing.example")),
        Err(HostsError::UnknownDefault(name)) if name == "missing.example"
    ));
    assert!(matches!(
        Hosts::new(&config.hosts, Some("example.com")),
        Err(HostsError::MissingTls(name)) if name == "example.com"
    ));
}

#[test]
fn hosts_can_be_shared_across_workers() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Hosts>();
}

#[test]
fn cloned_hosts_share_the_loaded_registry() -> TestResult {
    let config = Config::default();
    let hosts = Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
    let cloned = hosts.clone();

    assert_eq!(cloned.default_host_name(), "localhost");
    assert!(std::sync::Arc::ptr_eq(
        &hosts
            .certified_key("localhost")
            .ok_or("missing certificate")?,
        &cloned
            .certified_key("localhost")
            .ok_or("missing cloned certificate")?
    ));
    drop(hosts);
    assert!(cloned.is_local_host("localhost"));
    Ok(())
}

fn test_tls_files(
    directory: &TempDir,
    domain: &str,
    suffix: &str,
) -> Result<HostTlsConfig, Box<dyn Error>> {
    test_tls_parameters(
        directory,
        CertificateParams::new(vec![domain.into()])?,
        suffix,
    )
}

fn file_paths(tls: &HostTlsConfig) -> Result<(&Path, &Path), Box<dyn Error>> {
    match &tls.source {
        HostTlsSource::Files {
            certificate_chain_path,
            private_key_path,
        } => Ok((certificate_chain_path, private_key_path)),
        HostTlsSource::LetsEncrypt => Err("expected file TLS source".into()),
    }
}

fn test_tls_parameters(
    directory: &TempDir,
    mut parameters: CertificateParams,
    suffix: &str,
) -> Result<HostTlsConfig, Box<dyn Error>> {
    let signer = TestSigner::new()?;
    parameters.serial_number = Some(rcgen::SerialNumber::from(1_u64));
    let certificate = parameters.self_signed(&signer)?;
    let mut private_key = [0_u8; 512];
    let private_key = signer.key.to_pkcs8_der(&mut private_key)?;
    let certificate_chain_path = directory.path().join(format!("certificate-{suffix}.pem"));
    let private_key_path = directory.path().join(format!("private-key-{suffix}.pem"));
    fs::write(
        &certificate_chain_path,
        pem("CERTIFICATE", certificate.der())?,
    )?;
    fs::write(&private_key_path, pem("PRIVATE KEY", private_key)?)?;
    Ok(HostTlsConfig {
        source: HostTlsSource::Files {
            certificate_chain_path,
            private_key_path,
        },
        client_auth: None,
    })
}

struct Ed25519TestSigner {
    key: Ed25519SigningKey,
    public_key: [u8; 32],
}

impl PublicKeyData for Ed25519TestSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

impl rcgen::SigningKey for Ed25519TestSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.key.sign(message).to_vec())
    }
}

#[test]
fn client_certificate_material_is_checked_during_bootstrap() -> TestResult {
    use super::client_identity::tests::Fixture;
    let fixture = Fixture::new()?;
    let mut tls = test_tls_files(&fixture.directory, "localhost", "client")?;
    tls.client_auth = Some(fixture.config.clone());
    let mut config = Config::default();
    config.hosts.get_mut("localhost").ok_or("missing host")?.tls = Some(tls);
    let hosts = Hosts::new(&config.hosts, None)?;
    let policy = hosts
        .client_certificate_policy("localhost")
        .ok_or("missing policy")?;
    assert!(policy.verifier().offer_client_auth());
    assert!(!policy.verifier().client_auth_mandatory());
    assert!(hosts.client_certificate_policy("other").is_none());
    assert!(std::sync::Arc::ptr_eq(
        policy,
        hosts
            .clone()
            .client_certificate_policy("localhost")
            .ok_or("missing cloned policy")?
    ));
    for material in [
        b"".as_slice(),
        b"broken PEM",
        b"-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n",
    ] {
        fs::write(&fixture.config.trust_anchors_path, material)?;
        assert!(matches!(
            Hosts::new(&config.hosts, None),
            Err(HostsError::ClientCertificates { .. })
        ));
    }
    fs::write(
        &fixture.config.trust_anchors_path,
        pem("CERTIFICATE", b"not DER")?,
    )?;
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::ClientCertificates { .. })
    ));
    fs::remove_file(&fixture.config.trust_anchors_path)?;
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::ClientCertificates { .. })
    ));
    Ok(())
}

#[test]
fn required_crls_cannot_be_missing_empty_malformed_stale_or_unusable_at_bootstrap() -> TestResult {
    use super::client_identity::tests::Fixture;
    use rustls::pki_types::pem::PemObject;
    let fixture = Fixture::new()?;
    let mut tls = test_tls_files(&fixture.directory, "localhost", "crl")?;
    tls.client_auth = Some(fixture.config.clone());
    let mut config = Config::default();
    config.hosts.get_mut("localhost").ok_or("missing host")?.tls = Some(tls);
    let der =
        rustls::pki_types::CertificateRevocationListDer::from_pem_file(&fixture.config.crls_path)?;
    let parsed: x509_cert::crl::CertificateList =
        x509_cert::crl::CertificateList::from_der(der.as_ref())?;
    for material in [
        b"".as_slice(),
        b"broken PEM",
        b"-----BEGIN X509 CRL-----\n!\n-----END X509 CRL-----\n",
    ] {
        fs::write(&fixture.config.crls_path, material)?;
        assert!(matches!(
            Hosts::new(&config.hosts, None),
            Err(HostsError::ClientCertificates { .. })
        ));
    }
    fs::write(&fixture.config.crls_path, pem("X509 CRL", b"not DER")?)?;
    assert!(Hosts::new(&config.hosts, None).is_err());
    for next_update in [None, Some(parsed.tbs_cert_list.this_update)] {
        let mut invalid = parsed.clone();
        invalid.tbs_cert_list.next_update = next_update;
        fs::write(
            &fixture.config.crls_path,
            pem("X509 CRL", &invalid.to_der()?)?,
        )?;
        assert!(Hosts::new(&config.hosts, None).is_err());
    }
    let mut unsupported = parsed;
    unsupported.signature_algorithm.oid =
        x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4");
    fs::write(
        &fixture.config.crls_path,
        pem("X509 CRL", &unsupported.to_der()?)?,
    )?;
    assert!(Hosts::new(&config.hosts, None).is_err());
    fs::remove_file(&fixture.config.crls_path)?;
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::ClientCertificates { .. })
    ));
    Ok(())
}

#[test]
fn refreshed_host_configs_keep_session_caches_separate() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let fixture = super::client_identity::tests::Fixture::new()?;
        let mut tls = test_tls_files(&fixture.directory, "localhost", "fresh")?;
        tls.client_auth = Some(fixture.config.clone());
        let mut config = Config::default();
        config.hosts.get_mut("localhost").ok_or("missing host")?.tls = Some(tls);
        let hosts = Hosts::new(&config.hosts, None)?;
        let first = hosts
            .tls_handshake("localhost")
            .await
            .ok_or("missing first TLS config")?
            .config;
        let second = hosts
            .tls_handshake("localhost")
            .await
            .ok_or("missing second TLS config")?
            .config;
        assert!(first.require_ems && second.require_ems);
        assert!(!std::sync::Arc::ptr_eq(
            &first.session_storage,
            &second.session_storage
        ));
        assert!(!std::sync::Arc::ptr_eq(&first.ticketer, &second.ticketer));
        assert!(std::sync::Arc::ptr_eq(
            &first.cert_resolver,
            &second.cert_resolver
        ));
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, None)?;
        let first = hosts
            .tls_handshake("localhost")
            .await
            .ok_or("missing cached TLS config")?
            .config;
        let second = hosts
            .tls_handshake("localhost")
            .await
            .ok_or("missing cached TLS config")?
            .config;
        assert!(std::sync::Arc::ptr_eq(&first, &second));
        assert!(hosts.tls_handshake("unknown").await.is_none());
        Ok(())
    })
}

#[test]
fn srv_client_identity_initializes_a_host_without_a_dns_identity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let parameters = super::test_support::san_parameters(vec![super::test_support::srv_name(
        "_xmpp-client.example.com",
    )?])?;
    let tls = test_tls_parameters(&directory, parameters, "srv-client")?;
    let configured = BTreeMap::from([(
        "example.com".into(),
        HostConfig {
            tls: Some(tls),
            ..HostConfig::default()
        },
    )]);
    let hosts = Hosts::new(&configured, None)?;
    assert_eq!(hosts.default_host_name(), "example.com");
    assert_eq!(
        hosts
            .tls_server_end_point("example.com")
            .map(|digest| digest.len()),
        Some(32)
    );
    Ok(())
}

#[test]
fn server_service_and_unusable_srv_ids_cannot_initialize_a_client_host() -> TestResult {
    use x509_cert::der::asn1::Utf8StringRef;
    use x509_cert::ext::pkix::name::{GeneralName, OtherName};
    for name in [
        super::test_support::srv_name("_xmpp-server.example.com")?,
        super::test_support::srv_name("_xmpp-client.other.example.com")?,
        super::test_support::srv_name("_xmpp-client._tcp.example.com")?,
        GeneralName::OtherName(OtherName {
            type_id: x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.8.7"),
            value: Utf8StringRef::new("_xmpp-client.example.com")?.into(),
        }),
    ] {
        let directory = tempfile::tempdir()?;
        let tls = test_tls_parameters(
            &directory,
            super::test_support::san_parameters(vec![name])?,
            "unusable-srv",
        )?;
        let configured = BTreeMap::from([(
            "example.com".into(),
            HostConfig {
                tls: Some(tls),
                ..HostConfig::default()
            },
        )]);
        assert!(matches!(
            Hosts::new(&configured, None),
            Err(HostsError::InvalidCertificate {
                source: rustls::Error::InvalidCertificate(
                    rustls::CertificateError::NotValidForName
                        | rustls::CertificateError::NotValidForNameContext { .. }
                ),
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn managed_publication_keeps_captured_generations_and_resumption_coherent() -> TestResult {
    use super::test_support::{handshake, managed_hosts, material};
    use std::sync::Arc;
    compio::runtime::Runtime::new()?.block_on(async {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let hosts = managed_hosts()?;
            assert!(hosts.is_local_host("example.com"));
            assert!(hosts.certified_key("example.com").is_none());
            assert!(hosts.tls_handshake("example.com").await.is_none());
            assert!(hosts.tls_handshake("localhost").await.is_some());
            let (a, key_a) = material(CertificateParams::new(vec!["example.com".into()])?)?;
            let (b, key_b) = material(CertificateParams::new(vec!["example.com".into()])?)?;
            let prepared_a =
                hosts.prepare_managed_certificate("example.com", vec![a.clone()], key_a)?;
            assert!(hosts.certified_key("example.com").is_none());
            prepared_a.activate();
            let selected_a = hosts
                .tls_handshake("example.com")
                .await
                .ok_or("missing A")?;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(a.clone())?;
            roots.add(b.clone())?;
            let client = Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls_graviola::default_provider(),
                ))
                .with_protocol_versions(&[version])?
                .with_root_certificates(roots)
                .with_no_client_auth(),
            );
            let first = handshake(Arc::clone(&client), Arc::clone(&selected_a.config))?;
            assert_eq!(first.handshake_kind(), Some(rustls::HandshakeKind::Full));
            assert_eq!(first.peer_certificates().ok_or("missing A chain")?[0], a);
            let second = handshake(Arc::clone(&client), Arc::clone(&selected_a.config))?;
            assert_eq!(
                second.handshake_kind(),
                Some(rustls::HandshakeKind::Resumed)
            );
            hosts
                .prepare_managed_certificate("example.com", vec![b.clone()], key_b)?
                .activate();
            let selected_b = hosts
                .tls_handshake("example.com")
                .await
                .ok_or("missing B")?;
            assert!(!Arc::ptr_eq(
                &selected_a.config.session_storage,
                &selected_b.config.session_storage
            ));
            assert!(!Arc::ptr_eq(
                &selected_a.config.ticketer,
                &selected_b.config.ticketer
            ));
            assert_ne!(selected_a.server_end_point, selected_b.server_end_point);
            let captured = handshake(Arc::clone(&client), Arc::clone(&selected_a.config))?;
            assert_eq!(
                captured
                    .peer_certificates()
                    .ok_or("missing captured A chain")?[0],
                a
            );
            assert_eq!(
                selected_a.server_end_point.as_ref(),
                &Sha256::digest(a.as_ref())[..]
            );
            let renewed = handshake(Arc::clone(&client), Arc::clone(&selected_b.config))?;
            assert_eq!(renewed.handshake_kind(), Some(rustls::HandshakeKind::Full));
            assert_eq!(renewed.peer_certificates().ok_or("missing B chain")?[0], b);
            assert_eq!(
                selected_b.server_end_point.as_ref(),
                &Sha256::digest(b.as_ref())[..]
            );
            let repeated = handshake(client, selected_b.config)?;
            assert_eq!(
                repeated.handshake_kind(),
                Some(rustls::HandshakeKind::Resumed)
            );
        }
        Ok(())
    })
}

#[test]
fn managed_preparation_rejects_invalid_material_without_publication() -> TestResult {
    use super::test_support::{managed_hosts, material};
    use rustls::pki_types::CertificateDer;
    use std::sync::Arc;
    let hosts = managed_hosts()?;
    let parameters = || CertificateParams::new(vec!["example.com".into()]);
    let (good, key) = material(parameters()?)?;
    hosts
        .prepare_managed_certificate("example.com", vec![good.clone()], key.clone_key())?
        .activate();
    let original = hosts.certified_key("example.com").ok_or("missing key")?;
    let original_digest = hosts
        .tls_server_end_point("example.com")
        .ok_or("missing digest")?;
    let now = time::OffsetDateTime::now_utc();
    let mut invalid = Vec::new();
    for names in [
        vec!["wrong.example"],
        vec!["*.example.com"],
        vec!["example.com", "extra.example"],
        vec!["example.com", "192.0.2.1"],
    ] {
        let (certificate, key) = material(CertificateParams::new(
            names.into_iter().map(String::from).collect::<Vec<_>>(),
        )?)?;
        invalid.push((vec![certificate], key));
    }
    let ip_parameters = super::test_support::san_parameters(vec![
        x509_cert::ext::pkix::name::GeneralName::IpAddress(x509_cert::der::asn1::OctetString::new(
            [192, 0, 2, 1],
        )?),
    ])?;
    let (ip, ip_key) = material(ip_parameters)?;
    invalid.push((vec![ip], ip_key));
    let srv_parameters = super::test_support::san_parameters(vec![super::test_support::srv_name(
        "_xmpp-client.example.com",
    )?])?;
    let (srv, srv_key) = material(srv_parameters)?;
    invalid.push((vec![srv], srv_key));
    for (start, end) in [
        (now - time::Duration::days(2), now - time::Duration::days(1)),
        (now + time::Duration::days(1), now + time::Duration::days(2)),
    ] {
        let mut parameters = parameters()?;
        parameters.not_before = start;
        parameters.not_after = end;
        let (certificate, key) = material(parameters)?;
        invalid.push((vec![certificate], key));
    }
    let (_, wrong_key) = material(parameters()?)?;
    invalid.push((vec![good.clone()], wrong_key));
    invalid.push((Vec::new(), key.clone_key()));
    invalid.push((vec![CertificateDer::from(vec![1, 2, 3])], key.clone_key()));
    invalid.push((
        vec![good.clone(), CertificateDer::from(vec![1, 2, 3])],
        key.clone_key(),
    ));
    let ed_key = Ed25519SigningKey::generate()?;
    let signer = Ed25519TestSigner {
        public_key: ed_key.public_key().as_bytes(),
        key: ed_key,
    };
    let mut ed_parameters = parameters()?;
    ed_parameters.serial_number = Some(1u64.into());
    let unsupported = ed_parameters.self_signed(&signer)?;
    let mut bytes = zeroize::Zeroizing::new([0; 512]);
    let ed_key = rustls::pki_types::PrivatePkcs8KeyDer::from(
        signer.key.to_pkcs8_der(&mut bytes[..])?.to_vec(),
    );
    assert!(matches!(
        hosts.prepare_managed_certificate(
            "example.com",
            vec![unsupported.der().clone()],
            ed_key.into()
        ),
        Err(HostsError::UnsupportedChannelBinding(_))
    ));
    for (chain, key) in invalid {
        assert!(
            hosts
                .prepare_managed_certificate("example.com", chain, key)
                .is_err()
        );
        assert!(Arc::ptr_eq(
            &original,
            &hosts.certified_key("example.com").ok_or("lost key")?
        ));
        assert!(Arc::ptr_eq(
            &original_digest,
            &hosts
                .tls_server_end_point("example.com")
                .ok_or("lost digest")?
        ));
    }
    for name in ["unknown.example", "localhost"] {
        assert!(matches!(
            hosts.prepare_managed_certificate(name, vec![good.clone()], key.clone_key()),
            Err(HostsError::NotManaged(_))
        ));
    }
    Ok(())
}

#[test]
fn managed_lifetime_intersects_the_whole_chain_and_expiry_blocks_new_admission() -> TestResult {
    use super::test_support::{managed_hosts, material};
    use rustls::pki_types::UnixTime;
    compio::runtime::Runtime::new()?.block_on(async {
        let hosts = managed_hosts()?;
        let now = time::OffsetDateTime::now_utc().replace_nanosecond(0)?;
        let mut leaf = CertificateParams::new(vec!["example.com".into()])?;
        leaf.not_before = now - time::Duration::days(1);
        leaf.not_after = now + time::Duration::days(1);
        let (leaf, key) = material(leaf)?;
        let mut issuer = CertificateParams::new(Vec::<String>::new())?;
        issuer.not_before = now - time::Duration::hours(1);
        issuer.not_after = now + time::Duration::hours(1);
        let (issuer, _) = material(issuer)?;
        let mut prepared = hosts.prepare_managed_certificate(
            "example.com",
            vec![leaf.clone(), issuer],
            key.clone_key(),
        )?;
        assert_eq!(
            prepared.validity(),
            (
                (now - time::Duration::hours(1)).unix_timestamp() as u64,
                (now + time::Duration::hours(1)).unix_timestamp() as u64
            )
        );
        assert!(hosts.tls_handshake("example.com").await.is_none());
        prepared.activate();
        let admitted = hosts
            .tls_handshake("example.com")
            .await
            .ok_or("missing admitted generation")?;
        prepared = hosts.prepare_managed_certificate(
            "example.com",
            vec![leaf.clone()],
            key.clone_key(),
        )?;
        std::sync::Arc::get_mut(&mut prepared.snapshot)
            .ok_or("shared prepared generation")?
            .validity = Some((0, UnixTime::now().as_secs()));
        prepared.activate();
        assert!(hosts.tls_handshake("example.com").await.is_none());
        assert!(!admitted.server_end_point.is_empty());
        let mut expired_issuer = CertificateParams::new(Vec::<String>::new())?;
        expired_issuer.not_after = now - time::Duration::hours(1);
        let (expired_issuer, _) = material(expired_issuer)?;
        assert!(
            hosts
                .prepare_managed_certificate("example.com", vec![leaf, expired_issuer], key)
                .is_err()
        );
        Ok(())
    })
}

#[test]
fn concurrent_handshake_readers_observe_only_complete_generations() -> TestResult {
    use super::test_support::{managed_hosts, material};
    use std::sync::{Arc, Barrier};
    let hosts = managed_hosts()?;
    let (a, key_a) = material(CertificateParams::new(vec!["example.com".into()])?)?;
    let (b, key_b) = material(CertificateParams::new(vec!["example.com".into()])?)?;
    hosts
        .prepare_managed_certificate("example.com", vec![a.clone()], key_a.clone_key())?
        .activate();
    let digest_a = Sha256::digest(a.as_ref());
    let digest_b = Sha256::digest(b.as_ref());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(a.clone())?;
    roots.add(b.clone())?;
    let mut client =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
    client.resumption = rustls::client::Resumption::disabled();
    let client = Arc::new(client);
    let barrier = Arc::new(Barrier::new(5));
    let readers = (0..4)
        .map(|_| {
            let hosts = hosts.clone();
            let barrier = Arc::clone(&barrier);
            let digest_a = digest_a.to_vec();
            let digest_b = digest_b.to_vec();
            let client = Arc::clone(&client);
            std::thread::spawn(move || -> Result<(), String> {
                let runtime = compio::runtime::Runtime::new().map_err(|error| error.to_string())?;
                barrier.wait();
                runtime.block_on(async {
                    for _ in 0..20 {
                        let selected = hosts
                            .tls_handshake("example.com")
                            .await
                            .ok_or("missing generation")?;
                        let peer =
                            super::test_support::handshake(Arc::clone(&client), selected.config)
                                .map_err(|error| error.to_string())?;
                        let certificate =
                            &peer.peer_certificates().ok_or("missing peer certificate")?[0];
                        let digest = Sha256::digest(certificate.as_ref());
                        assert_eq!(selected.server_end_point.as_ref(), &digest[..]);
                        assert!(
                            selected.server_end_point.as_ref() == digest_a
                                || selected.server_end_point.as_ref() == digest_b
                        );
                    }
                    Ok(())
                })
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    for _ in 0..20 {
        hosts
            .prepare_managed_certificate("example.com", vec![b.clone()], key_b.clone_key())?
            .activate();
        hosts
            .prepare_managed_certificate("example.com", vec![a.clone()], key_a.clone_key())?
            .activate();
    }
    for reader in readers {
        reader
            .join()
            .map_err(|_| "reader panicked")?
            .map_err(std::io::Error::other)?;
    }
    Ok(())
}

#[test]
fn managed_material_preparation_checks_structure_without_time_admission() -> TestResult {
    use super::test_support::{managed_hosts, material};
    let hosts = managed_hosts()?;
    let now = time::OffsetDateTime::now_utc().replace_nanosecond(0)?;
    for (start, end) in [
        (now - time::Duration::days(2), now - time::Duration::days(1)),
        (now + time::Duration::days(1), now + time::Duration::days(2)),
    ] {
        let mut leaf = CertificateParams::new(vec!["example.com".into()])?;
        leaf.not_before = start;
        leaf.not_after = end;
        let (leaf, key) = material(leaf)?;
        let prepared =
            hosts.prepare_managed_material("example.com", vec![leaf.clone()], key.clone_key())?;
        assert_eq!(
            prepared.validity(),
            (start.unix_timestamp() as u64, end.unix_timestamp() as u64)
        );
        assert!(hosts.certified_key("example.com").is_none());
        assert!(
            hosts
                .prepare_managed_certificate("example.com", vec![leaf.clone()], key.clone_key())
                .is_err()
        );
        let (_, wrong_key) = material(CertificateParams::new(vec!["example.com".into()])?)?;
        assert!(
            hosts
                .prepare_managed_material("example.com", vec![leaf.clone()], wrong_key)
                .is_err()
        );
        assert!(
            hosts
                .prepare_managed_material(
                    "example.com",
                    vec![
                        leaf.clone(),
                        rustls::pki_types::CertificateDer::from(vec![1, 2, 3])
                    ],
                    key.clone_key()
                )
                .is_err()
        );
        let mut wrong_name = CertificateParams::new(vec!["wrong.example".into()])?;
        wrong_name.not_before = start;
        wrong_name.not_after = end;
        let (wrong, wrong_key) = material(wrong_name)?;
        assert!(
            hosts
                .prepare_managed_material("example.com", vec![wrong], wrong_key)
                .is_err()
        );
        let mut disjoint = CertificateParams::new(Vec::<String>::new())?;
        disjoint.not_before = end;
        disjoint.not_after = end + time::Duration::days(1);
        let (disjoint, _) = material(disjoint)?;
        assert!(
            hosts
                .prepare_managed_material("example.com", vec![leaf], key)
                .is_ok()
        );
        let (leaf, key) = material({
            let mut params = CertificateParams::new(vec!["example.com".into()])?;
            params.not_before = start;
            params.not_after = end;
            params
        })?;
        assert!(
            hosts
                .prepare_managed_material("example.com", vec![leaf, disjoint], key)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn managed_usage_extensions_apply_to_every_chain_member_including_unavailable_material()
-> TestResult {
    use super::test_support::{managed_hosts, material};
    use rcgen::{CustomExtension, ExtendedKeyUsagePurpose, KeyUsagePurpose};
    let hosts = managed_hosts()?;
    let now = time::OffsetDateTime::now_utc();
    let signature = vec![3, 2, 7, 128];
    let signing = vec![3, 2, 2, 4];
    let server = vec![48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1];
    let any = vec![48, 6, 6, 4, 85, 29, 37, 0];
    for (start, end) in [
        (now - time::Duration::days(2), now - time::Duration::days(1)),
        (now + time::Duration::days(1), now + time::Duration::days(2)),
        (now - time::Duration::days(1), now + time::Duration::days(1)),
    ] {
        for issuer in [false, true] {
            for (oid, contents, valid) in [
                (vec![2, 5, 29, 15], signature.clone(), !issuer),
                (vec![2, 5, 29, 15], signing.clone(), issuer),
                (vec![2, 5, 29, 15], vec![3, 1, 0], false),
                (vec![2, 5, 29, 15], vec![1], false),
                (vec![2, 5, 29, 37], server.clone(), true),
                (vec![2, 5, 29, 37], any.clone(), false),
                (vec![2, 5, 29, 37], vec![48, 0], false),
                (vec![2, 5, 29, 37], vec![1], false),
            ] {
                for critical in [false, true] {
                    let mut params = CertificateParams::new(vec!["example.com".into()])?;
                    params.not_before = start;
                    params.not_after = end;
                    let mut extension = CustomExtension::from_oid_content(&oid, contents.clone());
                    extension.set_criticality(critical);
                    params.custom_extensions.push(extension);
                    let (member, key) = material(params)?;
                    let (chain, key) = if issuer {
                        let mut leaf = CertificateParams::new(vec!["example.com".into()])?;
                        leaf.not_before = start;
                        leaf.not_after = end;
                        let (leaf, key) = material(leaf)?;
                        (vec![leaf, member], key)
                    } else {
                        (vec![member], key)
                    };
                    assert_eq!(
                        hosts
                            .prepare_managed_material("example.com", chain, key)
                            .is_ok(),
                        valid,
                        "issuer={issuer}, oid={oid:?}, contents={contents:?}"
                    );
                }
            }
            for eku in [false, true] {
                let mut params = CertificateParams::new(vec!["example.com".into()])?;
                params.not_before = start;
                params.not_after = end;
                if eku {
                    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
                    params
                        .custom_extensions
                        .push(CustomExtension::from_oid_content(
                            &[2, 5, 29, 37],
                            server.clone(),
                        ));
                } else {
                    params.key_usages = vec![if issuer {
                        KeyUsagePurpose::KeyCertSign
                    } else {
                        KeyUsagePurpose::DigitalSignature
                    }];
                    params
                        .custom_extensions
                        .push(CustomExtension::from_oid_content(
                            &[2, 5, 29, 15],
                            if issuer {
                                signing.clone()
                            } else {
                                signature.clone()
                            },
                        ));
                }
                let (member, key) = material(params)?;
                let (chain, key) = if issuer {
                    let mut leaf = CertificateParams::new(vec!["example.com".into()])?;
                    leaf.not_before = start;
                    leaf.not_after = end;
                    let (leaf, key) = material(leaf)?;
                    (vec![leaf, member], key)
                } else {
                    (vec![member], key)
                };
                assert!(
                    hosts
                        .prepare_managed_material("example.com", chain, key)
                        .is_err()
                );
            }
        }
        let mut leaf = CertificateParams::new(vec!["example.com".into()])?;
        leaf.not_before = start;
        leaf.not_after = end;
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let (leaf, key) = material(leaf)?;
        let mut issuer = CertificateParams::new(Vec::<String>::new())?;
        issuer.not_before = start;
        issuer.not_after = end;
        issuer.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        issuer.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let (issuer, _) = material(issuer)?;
        assert!(
            hosts
                .prepare_managed_material("example.com", vec![leaf, issuer], key)
                .is_ok()
        );
    }
    for reverse in [false, true] {
        let mut invalid = CertificateParams::new(vec!["example.com".into()])?;
        invalid.not_before = now;
        invalid.not_after = if reverse {
            now - time::Duration::days(1)
        } else {
            now
        };
        let (invalid, key) = material(invalid)?;
        assert!(
            hosts
                .prepare_managed_material("example.com", vec![invalid], key)
                .is_err()
        );
    }
    Ok(())
}
