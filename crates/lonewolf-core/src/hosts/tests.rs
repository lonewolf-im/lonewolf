// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use crate::config::{Config, HostConfig, HostTlsConfig};
use crate::hosts::test_support::{TestSigner, pem};
use crate::hosts::{Hosts, HostsError};
use graviola::signing::eddsa::Ed25519SigningKey;
use rcgen::{CertificateParams, PublicKeyData};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

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
        hosts.tls_server_end_point("localhost").map(<[u8]>::len),
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
        certificate_chain_path: tls.certificate_chain_path,
        private_key_path: PathBuf::from("missing.key"),
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
                certificate_chain_path: tls.certificate_chain_path,
                private_key_path: other.private_key_path,
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

    fs::write(&tls.certificate_chain_path, b"")?;
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::NoCertificates(_))
    ));

    fs::write(
        &tls.certificate_chain_path,
        b"-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n",
    )?;
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::ReadCertificate { .. })
    ));

    fs::write(&tls.certificate_chain_path, pem("CERTIFICATE", b"not DER")?)?;
    assert!(matches!(
        Hosts::new(&config.hosts, None),
        Err(HostsError::InvalidCertificate { .. })
    ));

    let restored = test_tls_files(&directory, "example.com", "restored")?;
    fs::write(&restored.private_key_path, b"")?;
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
                certificate_chain_path,
                private_key_path,
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
    assert!(std::ptr::eq(
        hosts
            .certified_key("localhost")
            .ok_or("missing certificate")?,
        cloned
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
    let signer = TestSigner::new()?;
    let mut parameters = CertificateParams::new(vec![domain.into()])?;
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
        certificate_chain_path,
        private_key_path,
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
    use x509_cert::der::{Decode, Encode};
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
            .tls_server_config("localhost")
            .await
            .ok_or("missing first TLS config")?;
        let second = hosts
            .tls_server_config("localhost")
            .await
            .ok_or("missing second TLS config")?;
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
            .tls_server_config("localhost")
            .await
            .ok_or("missing cached TLS config")?;
        let second = hosts
            .tls_server_config("localhost")
            .await
            .ok_or("missing cached TLS config")?;
        assert!(std::sync::Arc::ptr_eq(&first, &second));
        assert!(hosts.tls_server_config("unknown").await.is_none());
        Ok(())
    })
}
