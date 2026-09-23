// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use base64::Engine;
use graviola::hashing::Sha256;
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey};
use lonewolf_core::config::{Config, HostConfig, HostTlsConfig};
use lonewolf_core::hosts::{Hosts, HostsError};
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
fn certificate_files_are_checked_during_bootstrap() -> TestResult {
    let directory = tempfile::tempdir()?;
    let tls = test_tls_files(&directory, "example.com", "one")?;
    let mut config = Config::default();
    config.hosts.clear();
    config.hosts.insert(
        "example.com".into(),
        HostConfig {
            tls: Some(tls.clone()),
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
            }),
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

fn test_tls_files(
    directory: &TempDir,
    domain: &str,
    suffix: &str,
) -> Result<HostTlsConfig, Box<dyn Error>> {
    let key = SigningKey::<P256> {
        private_key: StaticPrivateKey::new_random()?,
    };
    let signer = TestSigner {
        public_key: key.private_key.public_key_uncompressed(),
        key,
    };
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
    })
}

fn pem(label: &str, der: &[u8]) -> Result<String, std::str::Utf8Error> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
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
        let mut signature = [0_u8; 80];
        self.key
            .sign_asn1::<Sha256>(&[message], &mut signature)
            .map(<[u8]>::to_vec)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}
