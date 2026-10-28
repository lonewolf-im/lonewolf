// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fs;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyUsagePurpose,
};
use x509_cert::der::asn1::{Ia5String, Utf8StringRef};
use x509_cert::ext::pkix::name::{GeneralName, OtherName};

use super::*;
use crate::config::{HostConfig, HostTlsConfig, HostTlsSource};
use crate::hosts::{
    Hosts,
    test_support::{TestSigner, handshake_named, pem, san_parameters, srv_name},
};

type TestResult<T = ()> = Result<T, Box<dyn StdError>>;

struct Fixture {
    directory: tempfile::TempDir,
    root: CertifiedIssuer<'static, TestSigner>,
    config: S2sTlsConfig,
    now: time::OffsetDateTime,
}

fn ca_parameters(
    name: &str,
    now: time::OffsetDateTime,
    days: i64,
) -> TestResult<CertificateParams> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.serial_number = Some(1u64.into());
    parameters.distinguished_name.push(DnType::CommonName, name);
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    parameters.not_before = now - time::Duration::days(1);
    parameters.not_after = now + time::Duration::days(days);
    Ok(parameters)
}

fn leaf_parameters(
    names: Vec<GeneralName>,
    now: time::OffsetDateTime,
) -> TestResult<CertificateParams> {
    let mut parameters = san_parameters(names)?;
    parameters.serial_number = Some(2u64.into());
    parameters.not_before = now - time::Duration::days(1);
    parameters.not_after = now + time::Duration::days(10);
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    Ok(parameters)
}

fn dns_name(value: &str) -> TestResult<GeneralName> {
    Ok(GeneralName::DnsName(Ia5String::new(value)?))
}

impl Fixture {
    fn new(root_days: i64) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let now = time::OffsetDateTime::now_utc();
        let root = CertifiedIssuer::self_signed(
            ca_parameters("Root", now, root_days)?,
            TestSigner::new()?,
        )?;
        let path = directory.path().join("roots.pem");
        fs::write(&path, pem("CERTIFICATE", root.der())?)?;
        Ok(Self {
            directory,
            root,
            now,
            config: S2sTlsConfig {
                trust_anchors_path: Some(path),
            },
        })
    }

    fn trust(&self) -> TestResult<Arc<PeerTrust>> {
        Ok(PeerTrust::load(
            &self.config,
            Arc::new(rustls_graviola::default_provider()),
        )?)
    }

    fn time(&self) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(self.now.unix_timestamp() as u64))
    }

    fn parameters(&self) -> TestResult<CertificateParams> {
        leaf_parameters(vec![dns_name("example.test")?], self.now)
    }

    fn leaf(&self, parameters: CertificateParams) -> TestResult<CertificateDer<'static>> {
        Ok(parameters
            .signed_by(&TestSigner::new()?, &self.root)?
            .der()
            .clone())
    }

    fn hosts(&self, client_only: bool) -> TestResult<Hosts> {
        let mut configs = BTreeMap::new();
        for domain in ["a.test", "b.test", "example.test", "127.0.0.1"] {
            let mut params = CertificateParams::new(vec![domain.into()])?;
            params.serial_number = Some(3u64.into());
            params.extended_key_usages = vec![if client_only && domain == "b.test" {
                ExtendedKeyUsagePurpose::ClientAuth
            } else {
                ExtendedKeyUsagePurpose::ServerAuth
            }];
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let signer = TestSigner::new()?;
            let cert = params.signed_by(&signer, &self.root)?;
            let certificate_chain_path = self.directory.path().join(format!("{domain}.pem"));
            let private_key_path = self.directory.path().join(format!("{domain}.key"));
            fs::write(&certificate_chain_path, pem("CERTIFICATE", cert.der())?)?;
            let mut buffer = zeroize::Zeroizing::new([0; 512]);
            let key = signer.key.to_pkcs8_der(&mut buffer[..])?;
            fs::write(&private_key_path, pem("PRIVATE KEY", key)?)?;
            configs.insert(
                domain.into(),
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
        }
        configs.insert("localhost".into(), HostConfig::default());
        configs.get_mut("a.test").ok_or("missing host")?.federation = false;
        Ok(Hosts::new(&configs, Some("localhost"))?)
    }
}

#[test]
fn server_identifiers_and_server_auth_eku_verify_in_both_directions() -> TestResult {
    let fixture = Fixture::new(30)?;
    let trust = fixture.trust()?;
    for (name, reference) in [
        (dns_name("example.test")?, "example.test"),
        (dns_name("*.example.test")?, "one.example.test"),
        (srv_name("_xmpp-server.example.test")?, "example.test"),
        (
            GeneralName::OtherName(OtherName {
                type_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.8.5"),
                value: Utf8StringRef::new("example.test")?.into(),
            }),
            "example.test",
        ),
    ] {
        for dual_use in [false, true] {
            let mut parameters = leaf_parameters(vec![name.clone()], fixture.now)?;
            if dual_use {
                parameters
                    .extended_key_usages
                    .push(ExtendedKeyUsagePurpose::ClientAuth);
            }
            let leaf = fixture.leaf(parameters)?;
            assert_eq!(
                trust
                    .verify_chain(std::slice::from_ref(&leaf), fixture.time())?
                    .valid_until,
                certificate_expiration(&leaf)?
            );
            trust.verify_identity(&leaf, reference)?;
            trust
                .client_verifier()
                .verify_client_cert(&leaf, &[], fixture.time())?;
            trust.server_verifier().verify_server_cert(
                &leaf,
                &[],
                &tls_identity(reference)?,
                &[],
                fixture.time(),
            )?;
        }
    }
    Ok(())
}

#[test]
fn incorrect_names_fail_outbound_but_inbound_defers_the_name_check() -> TestResult {
    let fixture = Fixture::new(30)?;
    let trust = fixture.trust()?;
    for (name, reference) in [
        (dns_name("wrong.test")?, "example.test"),
        (srv_name("_xmpp-client.example.test")?, "example.test"),
        (dns_name("*.example.test")?, "two.one.example.test"),
    ] {
        let leaf = fixture.leaf(leaf_parameters(vec![name], fixture.now)?)?;
        trust
            .client_verifier()
            .verify_client_cert(&leaf, &[], fixture.time())?;
        assert!(matches!(
            trust.verify_identity(&leaf, reference),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
            ))
        ));
        assert!(matches!(
            trust.server_verifier().verify_server_cert(
                &leaf,
                &[],
                &tls_identity(reference)?,
                &[],
                fixture.time()
            ),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
            ))
        ));
    }
    let mut params = leaf_parameters(Vec::new(), fixture.now)?;
    params.custom_extensions.clear();
    params
        .distinguished_name
        .push(DnType::CommonName, "example.test");
    assert!(
        trust
            .verify_identity(&fixture.leaf(params)?, "example.test")
            .is_err()
    );
    assert!(
        trust
            .verify_identity(&fixture.leaf(fixture.parameters()?)?, "bad domain")
            .is_err()
    );
    Ok(())
}

#[test]
fn client_only_missing_and_any_eku_and_bad_leaf_key_usage_are_rejected() -> TestResult {
    let fixture = Fixture::new(30)?;
    let trust = fixture.trust()?;
    for usage in [
        vec![ExtendedKeyUsagePurpose::ClientAuth],
        Vec::new(),
        vec![ExtendedKeyUsagePurpose::Any],
    ] {
        let mut params = fixture.parameters()?;
        params.extended_key_usages = usage;
        let leaf = fixture.leaf(params)?;
        assert!(matches!(
            trust.verify_chain(std::slice::from_ref(&leaf), fixture.time()),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. }
            ))
        ));
        assert!(
            trust
                .client_verifier()
                .verify_client_cert(&leaf, &[], fixture.time())
                .is_err()
        );
        assert!(
            trust
                .server_verifier()
                .verify_server_cert(
                    &leaf,
                    &[],
                    &tls_identity("example.test")?,
                    &[],
                    fixture.time()
                )
                .is_err()
        );
    }
    let mut params = fixture.parameters()?;
    params.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
    assert_eq!(
        trust.verify_chain(&[fixture.leaf(params)?], fixture.time()),
        Err(CertificateError::InvalidPurpose.into())
    );
    Ok(())
}

#[test]
fn untrusted_missing_and_invalid_chains_return_typed_errors() -> TestResult {
    let fixture = Fixture::new(30)?;
    let trust = fixture.trust()?;
    assert_eq!(
        trust.verify_chain(&[], fixture.time()),
        Err(rustls::Error::NoCertificatesPresented)
    );
    assert_eq!(
        trust.verify_chain(&[CertificateDer::from(&b"bad der"[..])], fixture.time()),
        Err(CertificateError::BadEncoding.into())
    );
    let other = CertifiedIssuer::self_signed(
        ca_parameters("Unknown Root", fixture.now, 30)?,
        TestSigner::new()?,
    )?;
    let untrusted = fixture
        .parameters()?
        .signed_by(&TestSigner::new()?, &other)?;
    assert_eq!(
        trust.verify_chain(&[untrusted.der().clone()], fixture.time()),
        Err(CertificateError::UnknownIssuer.into())
    );
    let intermediate = CertifiedIssuer::signed_by(
        ca_parameters("Intermediate", fixture.now, 20)?,
        TestSigner::new()?,
        &fixture.root,
    )?;
    let leaf = fixture
        .parameters()?
        .signed_by(&TestSigner::new()?, &intermediate)?
        .der()
        .clone();
    assert_eq!(
        trust.verify_chain(&[leaf], fixture.time()),
        Err(CertificateError::UnknownIssuer.into())
    );
    for expired in [true, false] {
        let mut params = fixture.parameters()?;
        if expired {
            params.not_after = fixture.now - time::Duration::seconds(1);
        } else {
            params.not_before = fixture.now + time::Duration::days(1);
        }
        let result = trust.verify_chain(&[fixture.leaf(params)?], fixture.time());
        if expired {
            assert!(matches!(
                result,
                Err(rustls::Error::InvalidCertificate(
                    CertificateError::Expired | CertificateError::ExpiredContext { .. }
                ))
            ));
        } else {
            assert!(matches!(
                result,
                Err(rustls::Error::InvalidCertificate(
                    CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. }
                ))
            ));
        }
    }
    Ok(())
}

#[test]
fn only_the_verified_path_and_its_anchor_bound_validity() -> TestResult {
    for (root_days, intermediate_days, leaf_days) in [(2, 5, 10), (30, 2, 10), (30, 20, 2)] {
        let fixture = Fixture::new(root_days)?;
        let trust = fixture.trust()?;
        let intermediate = CertifiedIssuer::signed_by(
            ca_parameters("Intermediate", fixture.now, intermediate_days)?,
            TestSigner::new()?,
            &fixture.root,
        )?;
        let mut params = fixture.parameters()?;
        params.not_after = fixture.now + time::Duration::days(leaf_days);
        let leaf = params
            .signed_by(&TestSigner::new()?, &intermediate)?
            .der()
            .clone();
        let mut unused_params = ca_parameters("Unused", fixture.now, -1)?;
        unused_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let unrelated = CertifiedIssuer::self_signed(unused_params, TestSigner::new()?)?;
        let expected = [
            certificate_expiration(fixture.root.der())?,
            certificate_expiration(intermediate.der())?,
            certificate_expiration(&leaf)?,
        ]
        .into_iter()
        .min()
        .ok_or("no expiry")?;
        let chain = [
            leaf,
            unrelated.der().clone(),
            intermediate.der().clone(),
            fixture.root.der().clone(),
        ];
        let result = trust.verify_chain(&chain, fixture.time())?;
        assert_eq!(result.valid_until, expected);
        trust
            .client_verifier()
            .verify_client_cert(&chain[0], &chain[1..], fixture.time())?;
        trust.server_verifier().verify_server_cert(
            &chain[0],
            &chain[1..],
            &tls_identity("example.test")?,
            &[],
            fixture.time(),
        )?;
    }
    Ok(())
}

#[test]
fn trust_loading_uses_exact_configured_roots_or_bundled_roots() -> TestResult {
    let fixture = Fixture::new(30)?;
    let provider = Arc::new(rustls_graviola::default_provider());
    let bundled = PeerTrust::load(&S2sTlsConfig::default(), Arc::clone(&provider))?;
    assert_eq!(bundled.roots.len(), webpki_roots::TLS_SERVER_ROOTS.len());
    assert!(!bundled.roots.is_empty());
    assert!(bundled.anchor_expirations.is_none());
    assert_eq!(
        bundled.verify_chain(&[fixture.leaf(fixture.parameters()?)?], fixture.time()),
        Err(CertificateError::UnknownIssuer.into())
    );
    let path = fixture
        .config
        .trust_anchors_path
        .as_ref()
        .ok_or("no path")?;
    for content in [
        "",
        "not certificates",
        "-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----\n",
    ] {
        fs::write(path, content)?;
        assert!(matches!(
            PeerTrust::load(&fixture.config, Arc::clone(&provider)),
            Err(PeerIdentityError::TrustAnchors)
        ));
    }
    fs::remove_file(path)?;
    assert!(matches!(
        PeerTrust::load(&fixture.config, provider),
        Err(PeerIdentityError::TrustAnchors)
    ));
    Ok(())
}

#[test]
fn inbound_requests_optional_certificates_without_ca_hints() -> TestResult {
    let trust = Fixture::new(30)?.trust()?;
    let verifier = trust.client_verifier();
    assert!(verifier.offer_client_auth());
    assert!(!verifier.client_auth_mandatory());
    assert!(verifier.root_hint_subjects().is_empty());
    assert!(!verifier.supported_verify_schemes().is_empty());
    Ok(())
}

#[test]
fn s2s_handshakes_exchange_server_auth_chains_and_reject_client_auth_only() -> TestResult {
    for client_only in [false, true] {
        let fixture = Fixture::new(30)?;
        let hosts = fixture.hosts(client_only)?;
        let trust = PeerTrust::load(&fixture.config, hosts.crypto_provider())?;
        let server = hosts
            .s2s_server_config("a.test", &trust)
            .ok_or("no server config")?;
        let client = hosts
            .s2s_client_config("b.test", &trust)
            .ok_or("no client config")?;
        assert!(!server.require_ems);
        let result = handshake_named(client, server, "a.test");
        if client_only {
            let error = result.err().ok_or("client-only certificate accepted")?;
            assert!(matches!(
                error.downcast_ref::<rustls::Error>(),
                Some(rustls::Error::InvalidCertificate(
                    CertificateError::InvalidPurpose
                        | CertificateError::InvalidPurposeContext { .. }
                ))
            ));
        } else {
            let (client, server) = result?;
            assert_eq!(
                client.peer_certificates(),
                Some(
                    hosts
                        .certified_key("a.test")
                        .ok_or("no server cert")?
                        .cert
                        .as_slice()
                )
            );
            assert_eq!(
                server.peer_certificates(),
                Some(
                    hosts
                        .certified_key("b.test")
                        .ok_or("no client cert")?
                        .cert
                        .as_slice()
                )
            );
            assert_eq!(client.handshake_kind(), Some(rustls::HandshakeKind::Full));
            assert_eq!(server.handshake_kind(), Some(rustls::HandshakeKind::Full));
        }
    }
    Ok(())
}

#[test]
fn federation_requires_opt_in_configured_tls_and_a_public_dns_name() -> TestResult {
    let fixture = Fixture::new(30)?;
    let hosts = fixture.hosts(false)?;
    let trust = fixture.trust()?;
    assert!(hosts.federates("example.test"));
    for domain in ["a.test", "localhost", "127.0.0.1", "unknown.test"] {
        assert!(!hosts.federates(domain));
    }
    assert!(hosts.s2s_server_config("unknown.test", &trust).is_none());
    assert!(hosts.s2s_client_config("unknown.test", &trust).is_none());
    assert!(hosts.s2s_client_config("localhost", &trust).is_some());
    let managed = crate::hosts::test_support::managed_hosts()?;
    assert!(managed.federates("example.com"));
    assert!(managed.s2s_server_config("example.com", &trust).is_none());
    assert!(managed.s2s_client_config("example.com", &trust).is_some());
    Ok(())
}

fn signed_material(
    fixture: &Fixture,
    domain: &str,
) -> TestResult<(
    Vec<CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let signer = TestSigner::new()?;
    let params = leaf_parameters(vec![dns_name(domain)?], fixture.now)?;
    let leaf = params.signed_by(&signer, &fixture.root)?.der().clone();
    let mut buffer = zeroize::Zeroizing::new([0; 512]);
    let key = signer.key.to_pkcs8_der(&mut buffer[..])?;
    Ok((
        vec![leaf],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.to_vec()).into(),
    ))
}

#[test]
fn new_handshakes_use_the_live_client_generation_and_selected_server_generation() -> TestResult {
    let fixture = Fixture::new(30)?;
    let trust = fixture.trust()?;
    let peers = fixture.hosts(false)?;
    let managed = crate::hosts::test_support::managed_hosts()?;
    let client = managed
        .s2s_client_config("example.com", &trust)
        .ok_or("no client config")?;
    let schemes = trust.client_verifier().supported_verify_schemes();
    assert!(!client.client_auth_cert_resolver.has_certs());
    assert!(
        client
            .client_auth_cert_resolver
            .resolve(&[], &schemes)
            .is_none()
    );
    let mut captured = None;
    for generation in 0..2 {
        let (chain, key) = signed_material(&fixture, "example.com")?;
        managed
            .prepare_managed_certificate("example.com", chain.clone(), key)?
            .activate();
        assert!(client.client_auth_cert_resolver.has_certs());
        assert_eq!(
            client
                .client_auth_cert_resolver
                .resolve(&[], &schemes)
                .ok_or("no client cert")?
                .cert,
            chain
        );
        assert!(client.client_auth_cert_resolver.resolve(&[], &[]).is_none());
        let (_, server) = handshake_named(
            Arc::clone(&client),
            peers
                .s2s_server_config("a.test", &trust)
                .ok_or("no peer server")?,
            "a.test",
        )?;
        assert_eq!(server.peer_certificates(), Some(chain.as_slice()));
        let selected = managed
            .s2s_server_config("example.com", &trust)
            .ok_or("no managed server")?;
        let (peer, _) = handshake_named(
            peers
                .s2s_client_config("b.test", &trust)
                .ok_or("no peer client")?,
            Arc::clone(&selected),
            "example.com",
        )?;
        assert_eq!(peer.peer_certificates(), Some(chain.as_slice()));
        if generation == 0 {
            captured = Some((selected, chain));
        }
    }
    let (selected, old_chain) = captured.ok_or("no captured server")?;
    let (peer, _) = handshake_named(
        peers
            .s2s_client_config("b.test", &trust)
            .ok_or("no peer client")?,
        selected,
        "example.com",
    )?;
    assert_eq!(peer.peer_certificates(), Some(old_chain.as_slice()));
    assert_ne!(
        managed
            .certified_key("example.com")
            .ok_or("no current key")?
            .cert,
        old_chain
    );
    Ok(())
}

#[test]
fn unavailable_generations_are_not_presented_in_either_direction() -> TestResult {
    let fixture = Fixture::new(30)?;
    let trust = fixture.trust()?;
    let managed = crate::hosts::test_support::managed_hosts()?;
    let client = managed
        .s2s_client_config("example.com", &trust)
        .ok_or("no client config")?;
    let schemes = trust.client_verifier().supported_verify_schemes();
    let now = UnixTime::now().as_secs();
    for validity in [(0, now), (now + 3600, now + 7200)] {
        let (chain, key) = signed_material(&fixture, "example.com")?;
        let mut prepared = managed.prepare_managed_certificate("example.com", chain, key)?;
        Arc::get_mut(&mut prepared.snapshot)
            .ok_or("snapshot shared")?
            .validity = Some(validity);
        prepared.activate();
        assert!(managed.s2s_server_config("example.com", &trust).is_none());
        assert!(!client.client_auth_cert_resolver.has_certs());
        assert!(
            client
                .client_auth_cert_resolver
                .resolve(&[], &schemes)
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn optional_inbound_auth_accepts_a_peer_without_a_certificate() -> TestResult {
    let fixture = Fixture::new(30)?;
    let trust = fixture.trust()?;
    let hosts = fixture.hosts(false)?;
    let client = rustls::ClientConfig::builder_with_provider(hosts.crypto_provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(trust.server_verifier())
        .with_no_client_auth();
    let (_, server) = handshake_named(
        Arc::new(client),
        hosts
            .s2s_server_config("a.test", &trust)
            .ok_or("no server")?,
        "a.test",
    )?;
    assert!(server.peer_certificates().is_none());
    Ok(())
}

#[test]
fn a_ca_key_usage_without_cert_sign_is_rejected() -> TestResult {
    let fixture = Fixture::new(30)?;
    let trust = fixture.trust()?;
    let mut params = ca_parameters("Intermediate", fixture.now, 20)?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let intermediate = CertifiedIssuer::signed_by(params, TestSigner::new()?, &fixture.root)?;
    let leaf = fixture
        .parameters()?
        .signed_by(&TestSigner::new()?, &intermediate)?
        .der()
        .clone();
    let chain = [leaf, intermediate.der().clone()];
    assert_eq!(
        trust.verify_chain(&chain, fixture.time()),
        Err(CertificateError::InvalidPurpose.into())
    );
    assert_eq!(
        trust
            .client_verifier()
            .verify_client_cert(&chain[0], &chain[1..], fixture.time())
            .map(|_| ()),
        Err(CertificateError::InvalidPurpose.into())
    );
    assert_eq!(
        trust
            .server_verifier()
            .verify_server_cert(
                &chain[0],
                &chain[1..],
                &tls_identity("example.test")?,
                &[],
                fixture.time()
            )
            .map(|_| ()),
        Err(CertificateError::InvalidPurpose.into())
    );
    Ok(())
}

#[test]
fn equivalent_anchor_renewals_use_the_latest_expiry_and_wrong_keys_do_not_extend_it() -> TestResult
{
    let fixture = Fixture::new(2)?;
    let leaf = fixture.leaf(fixture.parameters()?)?;
    let renewed = ca_parameters("Root", fixture.now, 20)?.self_signed(fixture.root.key())?;
    let unrelated =
        CertifiedIssuer::self_signed(ca_parameters("Root", fixture.now, 30)?, TestSigner::new()?)?;
    let path = fixture
        .config
        .trust_anchors_path
        .as_ref()
        .ok_or("no anchor path")?;
    for anchors in [
        [fixture.root.der(), renewed.der()],
        [renewed.der(), fixture.root.der()],
    ] {
        let bundle = format!(
            "{}{}{}",
            pem("CERTIFICATE", anchors[0])?,
            pem("CERTIFICATE", anchors[1])?,
            pem("CERTIFICATE", unrelated.der())?
        );
        fs::write(path, bundle)?;
        let trust = fixture.trust()?;
        assert_eq!(
            trust
                .verify_chain(std::slice::from_ref(&leaf), fixture.time())?
                .valid_until,
            certificate_expiration(&leaf)?
        );
    }
    fs::write(
        path,
        format!(
            "{}{}",
            pem("CERTIFICATE", fixture.root.der())?,
            pem("CERTIFICATE", unrelated.der())?
        ),
    )?;
    assert_eq!(
        fixture
            .trust()?
            .verify_chain(&[leaf], fixture.time())?
            .valid_until,
        certificate_expiration(fixture.root.der())?
    );
    Ok(())
}
