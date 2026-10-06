// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::mpsc;
use std::task::{Context, Poll, Waker};
use std::thread;

use crate::hosts::test_support::{TestSigner, pem};
use compio::runtime::Runtime;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyUsagePurpose, OtherNameValue, RevokedCertParams,
    SanType,
};
use x509_cert::der::{Encode, asn1::Ia5String};
use x509_cert::ext::pkix::name::OtherName;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const TIMEOUT: Duration = Duration::from_secs(5);

pub(in crate::hosts) struct Fixture {
    pub(in crate::hosts) directory: tempfile::TempDir,
    root: CertifiedIssuer<'static, TestSigner>,
    pub(in crate::hosts) config: ClientCertificateConfig,
    pub(in crate::hosts) chain: Arc<[CertificateDer<'static>]>,
    now: SystemTime,
}

impl Fixture {
    pub(in crate::hosts) fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let now = SystemTime::now();
        let time = time::OffsetDateTime::from(now);
        let root =
            CertifiedIssuer::self_signed(ca_parameters("Root", time, 1)?, TestSigner::new()?)?;
        let config = ClientCertificateConfig {
            trust_anchors_path: directory.path().join("roots.pem"),
            crls_path: directory.path().join("crls.pem"),
        };
        fs::write(&config.trust_anchors_path, pem("CERTIFICATE", root.der())?)?;
        let leaf = leaf_parameters(&["alice@localhost"], time, time + time::Duration::days(1))?
            .signed_by(&TestSigner::new()?, &root)?;
        let fixture = Self {
            directory,
            root,
            config,
            chain: Arc::from([leaf.der().clone()]),
            now,
        };
        fixture.write_crl(false, time + time::Duration::hours(2))?;
        Ok(fixture)
    }

    fn write_crl(&self, revoked: bool, next_update: time::OffsetDateTime) -> TestResult {
        let crl = crl(&self.root, self.now, next_update, revoked)?;
        fs::write(&self.config.crls_path, pem("X509 CRL", crl.der())?)?;
        Ok(())
    }

    pub(in crate::hosts) fn policy(&self) -> TestResult<Arc<ClientCertificatePolicy>> {
        self.policy_with_executor(BlockingExecutor::new(
            const { NonZeroUsize::new(2).unwrap() },
        ))
    }

    fn policy_with_executor(
        &self,
        blocking: BlockingExecutor,
    ) -> TestResult<Arc<ClientCertificatePolicy>> {
        Ok(ClientCertificatePolicy::load(
            "localhost",
            &self.config,
            Arc::new(rustls_graviola::default_provider()),
            blocking,
        )?)
    }

    fn leaf(&self, names: &[&str], expires: SystemTime) -> TestResult<CertificateDer<'static>> {
        Ok(leaf_parameters(names, self.now.into(), expires.into())?
            .signed_by(&TestSigner::new()?, &self.root)?
            .der()
            .clone())
    }
}

fn leaf_parameters(
    names: &[&str],
    now: time::OffsetDateTime,
    expires: time::OffsetDateTime,
) -> TestResult<CertificateParams> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.serial_number = Some(42u64.into());
    parameters.not_before = now - time::Duration::hours(1);
    parameters.not_after = expires;
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    parameters.subject_alt_names = names
        .iter()
        .map(|name| {
            SanType::OtherName((
                vec![1, 3, 6, 1, 5, 5, 7, 8, 5],
                OtherNameValue::Utf8String((*name).into()),
            ))
        })
        .collect();
    Ok(parameters)
}

fn ca_parameters(name: &str, now: time::OffsetDateTime, id: u8) -> TestResult<CertificateParams> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.serial_number = Some(u64::from(id).into());
    parameters.distinguished_name.push(DnType::CommonName, name);
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    parameters.key_identifier_method = KeyIdMethod::PreSpecified(vec![id]);
    parameters.not_before = now - time::Duration::hours(1);
    parameters.not_after = now + time::Duration::days(30);
    Ok(parameters)
}

fn crl(
    root: &CertifiedIssuer<'_, TestSigner>,
    now: SystemTime,
    next_update: time::OffsetDateTime,
    revoked: bool,
) -> TestResult<rcgen::CertificateRevocationList> {
    Ok(CertificateRevocationListParams {
        this_update: time::OffsetDateTime::from(now) - time::Duration::minutes(1),
        next_update,
        crl_number: 1u64.into(),
        issuing_distribution_point: None,
        revoked_certs: if revoked {
            vec![RevokedCertParams {
                serial_number: 42u64.into(),
                revocation_time: now.into(),
                reason_code: None,
                invalidity_date: None,
            }]
        } else {
            vec![]
        },
        key_identifier_method: KeyIdMethod::PreSpecified(vec![1]),
    }
    .signed_by(root)?)
}

#[test]
fn xmpp_accounts_are_prepared_deduplicated_and_host_filtered() -> TestResult {
    let fixture = Fixture::new()?;
    let leaf = fixture.leaf(
        &[
            "ALICE@LOCALHOST",
            "alice@localhost",
            "JÜLIA@localhost",
            "jülia@localhost",
            "other@elsewhere",
            "bob@localhost",
        ],
        fixture.now + Duration::from_secs(86400),
    )?;
    let accounts = client_identities(&leaf, "localhost")?;
    assert_eq!(
        accounts
            .accounts
            .iter()
            .map(AccountKey::as_str)
            .collect::<Vec<_>>(),
        ["alice@localhost", "bob@localhost", "jülia@localhost"]
    );
    Ok(())
}

#[test]
fn malformed_full_domain_only_and_wrong_asn1_xmpp_accounts_fail() -> TestResult {
    let fixture = Fixture::new()?;
    for identity in [
        "alice@localhost/phone",
        "localhost",
        "@localhost",
        "alice@bad domain",
    ] {
        let leaf = fixture.leaf(&[identity], fixture.now + Duration::from_secs(86400))?;
        assert!(matches!(
            client_identities(&leaf, "localhost"),
            Err(ClientIdentityError::MalformedIdentity)
        ));
    }
    let mut parameters = leaf_parameters(
        &[],
        fixture.now.into(),
        (fixture.now + Duration::from_secs(86400)).into(),
    )?;
    let san = SubjectAltName(vec![GeneralName::OtherName(OtherName {
        type_id: XMPP_ADDR,
        value: (&Ia5String::new("alice@localhost")?).into(),
    })]);
    parameters
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 17],
            san.to_der()?,
        ));
    let leaf = parameters
        .signed_by(&TestSigner::new()?, &fixture.root)?
        .der()
        .clone();
    assert!(matches!(
        client_identities(&leaf, "localhost"),
        Err(ClientIdentityError::MalformedIdentity)
    ));
    Ok(())
}

#[test]
fn cn_dns_email_and_other_oids_do_not_supply_accounts() -> TestResult {
    let fixture = Fixture::new()?;
    let mut parameters = leaf_parameters(
        &[],
        fixture.now.into(),
        (fixture.now + Duration::from_secs(86400)).into(),
    )?;
    parameters
        .distinguished_name
        .push(DnType::CommonName, "alice@localhost");
    parameters.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::Rfc822Name("alice@localhost".try_into()?),
        SanType::OtherName((vec![1, 2, 3, 4], "alice@localhost".into())),
    ];
    let certificate = parameters.signed_by(&TestSigner::new()?, &fixture.root)?;
    assert!(
        client_identities(certificate.der(), "localhost")?
            .accounts
            .is_empty()
    );
    assert!(
        client_identities(&fixture.chain[0], "elsewhere")?
            .accounts
            .is_empty()
    );
    Ok(())
}

#[test]
fn explicit_account_then_protected_from_then_single_candidate_selects_identity() -> TestResult {
    let fixture = Fixture::new()?;
    let certificate = fixture.leaf(
        &["alice@localhost", "bob@localhost"],
        fixture.now + Duration::from_secs(86400),
    )?;
    let identities = client_identities(&certificate, "localhost")?;
    let bob = prepared_account("bob@localhost")?;
    let other = prepared_account("carol@localhost")?;
    assert_eq!(
        identities.authorize(Some(&bob), Some("alice@localhost"))?,
        &bob
    );
    assert_eq!(identities.authorize(None, Some("BOB@LOCALHOST"))?, &bob);
    assert_eq!(
        identities.authorize(Some(&other), Some("alice@localhost")),
        Err(AuthorizationError::NotAuthorized)
    );
    for from in [
        None,
        Some("carol@localhost"),
        Some("alice@localhost/phone"),
        Some("invalid"),
    ] {
        assert_eq!(
            identities.authorize(None, from),
            Err(AuthorizationError::Ambiguous)
        );
    }
    let single = client_identities(&fixture.chain[0], "localhost")?;
    assert_eq!(
        single.authorize(None, Some("carol@localhost"))?.as_str(),
        "alice@localhost"
    );
    let empty = client_identities(&fixture.chain[0], "elsewhere")?;
    assert_eq!(
        empty.authorize(None, None),
        Err(AuthorizationError::NotAuthorized)
    );
    Ok(())
}

#[test]
fn revalidation_uses_refreshed_crls_and_keeps_peer_provenance() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new()?;
        let policy = fixture.policy()?;
        let peer = policy.verify_client(Arc::clone(&fixture.chain)).await?;
        assert_eq!(peer.identities().accounts[0].as_str(), "alice@localhost");
        assert!(Arc::ptr_eq(peer.policy(), &policy));
        let next_update = time::OffsetDateTime::from(fixture.now) + time::Duration::minutes(30);
        fixture.write_crl(false, next_update)?;
        let validity = policy.revalidate_client(&peer).await?;
        assert_eq!(
            validity.valid_until.duration_since(UNIX_EPOCH)?.as_secs(),
            SystemTime::from(next_update)
                .duration_since(UNIX_EPOCH)?
                .as_secs()
        );
        assert_eq!(validity.recheck_at, validity.valid_until);
        assert!(peer.validity().valid_until > validity.valid_until);
        assert!(Arc::ptr_eq(&peer.chain, &fixture.chain));
        assert_eq!(peer.identities().accounts[0].as_str(), "alice@localhost");
        let other = fixture.policy()?;
        assert!(matches!(
            other.revalidate_client(&peer).await,
            Err(ClientIdentityError::PolicyMismatch)
        ));
        fixture.write_crl(true, next_update)?;
        assert!(matches!(
            policy.revalidate_client(&peer).await,
            Err(ClientIdentityError::Verification(
                rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked)
            ))
        ));
        Ok(())
    })
}

#[test]
fn revalidation_fails_closed_on_missing_empty_malformed_stale_or_unusable_crls() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new()?;
        let policy = fixture.policy()?;
        let peer = policy.verify_client(Arc::clone(&fixture.chain)).await?;
        for material in [
            b"".as_slice(),
            b"broken PEM",
            b"-----BEGIN X509 CRL-----\n!\n-----END X509 CRL-----\n",
        ] {
            fs::write(&fixture.config.crls_path, material)?;
            assert!(matches!(
                policy.revalidate_client(&peer).await,
                Err(ClientIdentityError::RevocationMaterial)
            ));
        }
        fs::write(&fixture.config.crls_path, pem("X509 CRL", b"not DER")?)?;
        assert!(policy.revalidate_client(&peer).await.is_err());
        fixture.write_crl(
            false,
            time::OffsetDateTime::from(fixture.now) - time::Duration::seconds(1),
        )?;
        assert!(policy.revalidate_client(&peer).await.is_err());
        fixture.write_crl(
            false,
            time::OffsetDateTime::from(fixture.now) + time::Duration::hours(2),
        )?;
        let der = CertificateRevocationListDer::from_pem_file(&fixture.config.crls_path)?;
        let mut invalid: CertificateList = CertificateList::from_der(der.as_ref())?;
        invalid.signature = x509_cert::der::asn1::BitString::from_bytes(&[0; 8])?;
        fs::write(
            &fixture.config.crls_path,
            pem("X509 CRL", &invalid.to_der()?)?,
        )?;
        assert!(matches!(
            policy.revalidate_client(&peer).await,
            Err(ClientIdentityError::Verification(_))
        ));
        fs::remove_file(&fixture.config.crls_path)?;
        assert!(matches!(
            policy.revalidate_client(&peer).await,
            Err(ClientIdentityError::RevocationMaterial)
        ));
        Ok(())
    })
}

#[test]
fn deadlines_stop_at_leaf_intermediate_crl_or_one_hour() -> TestResult {
    let fixture = Fixture::new()?;
    let policy = fixture.policy()?;
    let initial = policy.validate_at(&fixture.chain, fixture.now)?;
    assert_eq!(initial.recheck_at, fixture.now + RECHECK_INTERVAL);
    let soon = fixture.now + Duration::from_secs(600);
    let leaf = fixture.leaf(&["alice@localhost"], soon)?;
    let validity = policy.validate_at(std::slice::from_ref(&leaf), fixture.now)?;
    assert!(
        policy
            .validate_at(&[leaf], soon + Duration::from_secs(1))
            .is_err()
    );
    assert_eq!(
        validity.valid_until.duration_since(UNIX_EPOCH)?.as_secs(),
        soon.duration_since(UNIX_EPOCH)?.as_secs()
    );
    assert_eq!(validity.recheck_at, validity.valid_until);
    assert!(validity.check(validity.valid_until).is_err());
    assert!(
        policy
            .validate_at(&fixture.chain, initial.valid_until)
            .is_err()
    );

    let mut params = ca_parameters("Intermediate", fixture.now.into(), 2)?;
    params.not_after = soon.into();
    let intermediate = CertifiedIssuer::signed_by(params, TestSigner::new()?, &fixture.root)?;
    let leaf = leaf_parameters(
        &["alice@localhost"],
        fixture.now.into(),
        (fixture.now + Duration::from_secs(86400)).into(),
    )?
    .signed_by(&TestSigner::new()?, &intermediate)?;
    let intermediate_crl = crl(
        &intermediate,
        fixture.now,
        (fixture.now + Duration::from_secs(7200)).into(),
        false,
    )?;
    let root_crl = crl(
        &fixture.root,
        fixture.now,
        (fixture.now + Duration::from_secs(7200)).into(),
        false,
    )?;
    fs::write(
        &fixture.config.crls_path,
        format!(
            "{}{}",
            pem("X509 CRL", root_crl.der())?,
            pem("X509 CRL", intermediate_crl.der())?
        ),
    )?;
    let chain = [leaf.der().clone(), intermediate.der().clone()];
    let validity = policy.validate_at(&chain, fixture.now)?;
    assert_eq!(
        validity.valid_until.duration_since(UNIX_EPOCH)?.as_secs(),
        soon.duration_since(UNIX_EPOCH)?.as_secs()
    );
    assert!(
        policy
            .validate_at(&chain, soon + Duration::from_secs(1))
            .is_err()
    );
    fs::write(
        &fixture.config.crls_path,
        pem("X509 CRL", intermediate_crl.der())?,
    )?;
    assert!(matches!(
        policy.validate_at(&chain, fixture.now),
        Err(ClientIdentityError::Verification(_))
    ));
    Ok(())
}

#[test]
fn host_policies_share_bounded_work_off_the_caller_thread_and_survive_cancellation() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new()?;
        let executor = BlockingExecutor::new(NonZeroUsize::MIN);
        let first = fixture.policy_with_executor(executor.clone())?;
        let second = fixture.policy_with_executor(executor)?;
        let (started, entered) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let mut holding = Box::pin(first.blocking.run(move || {
            let _ = started.send(thread::current().id());
            gate.recv_timeout(TIMEOUT)
        }));
        assert!(poll(holding.as_mut()).is_pending());
        assert_ne!(entered.recv_timeout(TIMEOUT)?, thread::current().id());
        let mut waiting = Box::pin(second.verify_client(Arc::clone(&fixture.chain)));
        assert!(poll(waiting.as_mut()).is_pending());
        drop(holding);
        assert!(poll(waiting.as_mut()).is_pending());
        release.send(())?;
        let peer = waiting.await?;
        assert_eq!(peer.identities().accounts[0].as_str(), "alice@localhost");
        Ok(())
    })
}

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn key_usage_restrictions_apply_to_leaf_and_presented_intermediates() -> TestResult {
    let fixture = Fixture::new()?;
    let policy = fixture.policy()?;
    for usage in [
        vec![],
        vec![KeyUsagePurpose::DigitalSignature],
        vec![KeyUsagePurpose::KeyEncipherment],
    ] {
        let allowed = usage.is_empty() || usage.contains(&KeyUsagePurpose::DigitalSignature);
        let mut params = leaf_parameters(
            &["alice@localhost"],
            fixture.now.into(),
            (fixture.now + Duration::from_secs(86400)).into(),
        )?;
        params.key_usages = usage;
        let leaf = params.signed_by(&TestSigner::new()?, &fixture.root)?;
        assert_eq!(
            policy
                .validate_at(&[leaf.der().clone()], fixture.now)
                .is_ok(),
            allowed
        );
    }
    let mut params = ca_parameters("Intermediate", fixture.now.into(), 2)?;
    params.key_usages = vec![KeyUsagePurpose::CrlSign];
    let intermediate = CertifiedIssuer::signed_by(params, TestSigner::new()?, &fixture.root)?;
    let leaf = leaf_parameters(
        &["alice@localhost"],
        fixture.now.into(),
        (fixture.now + Duration::from_secs(86400)).into(),
    )?
    .signed_by(&TestSigner::new()?, &intermediate)?;
    let root_crl = crl(
        &fixture.root,
        fixture.now,
        (fixture.now + Duration::from_secs(7200)).into(),
        false,
    )?;
    let intermediate_crl = crl(
        &intermediate,
        fixture.now,
        (fixture.now + Duration::from_secs(7200)).into(),
        false,
    )?;
    fs::write(
        &fixture.config.crls_path,
        format!(
            "{}{}",
            pem("X509 CRL", root_crl.der())?,
            pem("X509 CRL", intermediate_crl.der())?
        ),
    )?;
    assert!(matches!(
        policy.validate_at(
            &[leaf.der().clone(), intermediate.der().clone()],
            fixture.now
        ),
        Err(ClientIdentityError::Verification(
            rustls::Error::InvalidCertificate(rustls::CertificateError::InvalidPurpose)
        ))
    ));
    Ok(())
}

#[test]
fn malformed_duplicate_and_empty_key_usage_are_rejected() -> TestResult {
    let fixture = Fixture::new()?;
    for (usage, duplicate) in [
        (vec![0x04, 0x01, 0x80], false),
        (vec![0x03, 0x01, 0x00], false),
        (vec![0x03, 0x02, 0x07, 0x80], true),
    ] {
        let mut params = leaf_parameters(
            &["alice@localhost"],
            fixture.now.into(),
            (fixture.now + Duration::from_secs(86400)).into(),
        )?;
        if !duplicate {
            params.key_usages.clear();
        }
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 15],
                usage,
            ));
        let leaf = params.signed_by(&TestSigner::new()?, &fixture.root)?;
        assert!(matches!(
            validate_key_usage(leaf.der(), &[]),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding
            ))
        ));
        assert!(
            fixture
                .policy()?
                .validate_at(&[leaf.der().clone()], fixture.now)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn handshake_verifier_reloads_after_the_startup_crl_expires() -> TestResult {
    let fixture = Fixture::new()?;
    let old_deadline = fixture.now + Duration::from_secs(600);
    fixture.write_crl(false, old_deadline.into())?;
    let policy = fixture.policy()?;
    let now = old_deadline + Duration::from_secs(1);
    let time = UnixTime::since_unix_epoch(now.duration_since(UNIX_EPOCH)?);
    assert!(
        policy
            .verifier
            .verify_client_cert(&fixture.chain[0], &[], time)
            .is_err()
    );
    fixture.write_crl(false, (fixture.now + Duration::from_secs(7200)).into())?;
    let loaded = load_verifier(&policy.roots, &policy.provider, &policy.crls_path, now);
    let refreshed = policy.handshake_verifier_result(loaded, now);
    refreshed.verify_client_cert(&fixture.chain[0], &[], time)?;
    fixture.write_crl(true, (fixture.now + Duration::from_secs(7200)).into())?;
    let loaded = load_verifier(&policy.roots, &policy.provider, &policy.crls_path, now);
    let revoked = policy.handshake_verifier_result(loaded, now);
    assert!(matches!(
        revoked.verify_client_cert(&fixture.chain[0], &[], time),
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::Revoked
        ))
    ));
    Ok(())
}

#[test]
fn unavailable_or_delayed_handshake_material_keeps_auth_optional_and_rejects_certificates()
-> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new()?;
        let policy = fixture.policy()?;
        let time = UnixTime::since_unix_epoch(fixture.now.duration_since(UNIX_EPOCH)?);
        let loaded = load_verifier(
            &policy.roots,
            &policy.provider,
            &policy.crls_path,
            fixture.now,
        )?;
        let unavailable = policy.handshake_verifier_result(Ok(loaded.clone()), loaded.1);
        assert!(unavailable.offer_client_auth());
        assert!(!unavailable.client_auth_mandatory());
        assert!(
            unavailable
                .verify_client_cert(&fixture.chain[0], &[], time)
                .is_err()
        );
        for material in [
            b"".as_slice(),
            b"broken PEM",
            b"-----BEGIN X509 CRL-----\n!\n-----END X509 CRL-----\n",
        ] {
            fs::write(&fixture.config.crls_path, material)?;
            let unavailable = policy.handshake_verifier().await;
            assert!(unavailable.offer_client_auth());
            assert!(!unavailable.client_auth_mandatory());
            assert!(std::ptr::eq(
                unavailable.root_hint_subjects(),
                policy.verifier.root_hint_subjects()
            ));
            assert_eq!(
                unavailable.supported_verify_schemes(),
                policy.verifier.supported_verify_schemes()
            );
            assert!(matches!(
                unavailable.verify_client_cert(&fixture.chain[0], &[], time),
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownRevocationStatus
                ))
            ));
        }
        fs::remove_file(&fixture.config.crls_path)?;
        assert!(
            policy
                .handshake_verifier()
                .await
                .verify_client_cert(&fixture.chain[0], &[], time)
                .is_err()
        );
        Ok(())
    })
}
