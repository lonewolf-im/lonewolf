// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyUsagePurpose, RevokedCertParams,
};
use rustls::RootCertStore;
use x509_cert::der::Encode;

use crate::hosts::test_support::{TestSigner, pem};

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

fn issuer(name: &str) -> TestResult<CertifiedIssuer<'static, TestSigner>> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.serial_number = Some(1u64.into());
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.key_identifier_method = KeyIdMethod::PreSpecified(vec![1]);
    params.not_before = (now() - Duration::from_secs(3600)).into();
    params.not_after = (now() + Duration::from_secs(86400)).into();
    Ok(CertifiedIssuer::self_signed(params, TestSigner::new()?)?)
}

fn crl(
    issuer: &CertifiedIssuer<'_, TestSigner>,
    this_update: SystemTime,
    next_update: SystemTime,
    revoked: bool,
) -> TestResult<rcgen::CertificateRevocationList> {
    Ok(CertificateRevocationListParams {
        this_update: this_update.into(),
        next_update: next_update.into(),
        crl_number: 1u64.into(),
        issuing_distribution_point: None,
        revoked_certs: if revoked {
            vec![RevokedCertParams {
                serial_number: 42u64.into(),
                revocation_time: this_update.into(),
                reason_code: None,
                invalidity_date: None,
            }]
        } else {
            Vec::new()
        },
        key_identifier_method: KeyIdMethod::PreSpecified(vec![1]),
    }
    .signed_by(issuer)?)
}

#[test]
fn parsing_rejects_invalid_stale_and_future_crls() -> TestResult {
    let issuer = issuer("Root")?;
    let now = now();
    let before = now - Duration::from_secs(60);
    let after = now + Duration::from_secs(3600);
    assert!(matches!(
        parse_crl(b"garbage", now),
        Err(CrlLoadError::Invalid)
    ));
    for (this, next, error) in [
        (
            before - Duration::from_secs(60),
            before,
            CrlLoadError::Stale,
        ),
        (after, after + Duration::from_secs(60), CrlLoadError::Stale),
        (before, now, CrlLoadError::Stale),
    ] {
        let der = crl(&issuer, this, next, false)?;
        assert!(matches!(parse_crl(der.der(), now), Err(actual) if actual == error));
    }
    let der = crl(&issuer, before, after, false)?;
    let parsed = parse_crl(der.der(), now).map_err(|error| format!("{error:?}"))?;
    assert_eq!(parsed.next_update, after);

    let mut invalid: CertificateList = CertificateList::from_der(der.der())?;
    invalid.tbs_cert_list.next_update = None;
    assert!(matches!(
        parse_crl(&invalid.to_der()?, now),
        Err(CrlLoadError::Invalid)
    ));
    invalid.tbs_cert_list.next_update = Some(invalid.tbs_cert_list.this_update);
    assert!(matches!(
        parse_crl(&invalid.to_der()?, now),
        Err(CrlLoadError::Invalid)
    ));
    Ok(())
}

#[test]
fn loading_requires_crls_and_uses_the_earliest_deadline() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("crls.pem");
    let now = now();
    assert!(matches!(
        CrlSet::load(&path, now),
        Err(CrlLoadError::Unreadable)
    ));
    fs::write(&path, b"")?;
    assert!(matches!(
        CrlSet::load(&path, now),
        Err(CrlLoadError::Invalid)
    ));
    let issuer = issuer("Root")?;
    fs::write(&path, pem("CERTIFICATE", issuer.der())?)?;
    assert!(matches!(
        CrlSet::load(&path, now),
        Err(CrlLoadError::Invalid)
    ));
    fs::write(
        &path,
        "-----BEGIN X509 CRL-----\n!\n-----END X509 CRL-----\n",
    )?;
    assert!(matches!(
        CrlSet::load(&path, now),
        Err(CrlLoadError::Invalid)
    ));
    let before = now - Duration::from_secs(60);
    let earlier = now + Duration::from_secs(600);
    let later = now + Duration::from_secs(3600);
    let first = crl(&issuer, before, later, false)?;
    let second = crl(&issuer, before, earlier, false)?;
    fs::write(
        &path,
        format!(
            "{}{}",
            pem("X509 CRL", first.der())?,
            pem("X509 CRL", second.der())?
        ),
    )?;
    let set = CrlSet::load(&path, now).map_err(|error| format!("{error:?}"))?;
    assert_eq!(set.next_update(), earlier);
    let stale = crl(&issuer, before - Duration::from_secs(60), before, false)?;
    fs::write(&path, pem("X509 CRL", stale.der())?)?;
    assert!(matches!(CrlSet::load(&path, now), Err(CrlLoadError::Stale)));
    Ok(())
}

fn verify(
    root: &CertifiedIssuer<'_, TestSigner>,
    crl: &rcgen::CertificateRevocationList,
    leaf_usage: ExtendedKeyUsagePurpose,
    usage: webpki::KeyUsage,
    unknown: webpki::UnknownStatusPolicy,
    expiration: webpki::ExpirationPolicy,
) -> TestResult<Result<(), webpki::Error>> {
    let now = now();
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.serial_number = Some(42u64.into());
    params.not_before = (now - Duration::from_secs(3600)).into();
    params.not_after = (now + Duration::from_secs(86400)).into();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![leaf_usage];
    let leaf = params.signed_by(&TestSigner::new()?, root)?;
    let mut roots = RootCertStore::empty();
    roots.add(root.der().clone())?;
    let end_entity = webpki::EndEntityCert::try_from(leaf.der())?;
    let crl =
        webpki::CertRevocationList::Owned(webpki::OwnedCertRevocationList::from_der(crl.der())?);
    let crls = [&crl];
    Ok(verify_with_crls(
        &end_entity,
        &roots.roots,
        &[],
        UnixTime::since_unix_epoch(now.duration_since(UNIX_EPOCH)?),
        rustls_graviola::default_provider()
            .signature_verification_algorithms
            .all,
        usage,
        RevocationRules {
            crls: &crls,
            unknown,
            expiration,
        },
    )
    .map(|_| ()))
}

#[test]
fn verification_enforces_revocation_and_unknown_status_policies() -> TestResult {
    let root = issuer("Root")?;
    let unrelated = issuer("Unrelated")?;
    let before = now() - Duration::from_secs(60);
    let after = now() + Duration::from_secs(3600);
    let revoked = crl(&root, before, after, true)?;
    let unrelated = crl(&unrelated, before, after, false)?;
    for (unknown, expiration, unrelated_result) in [
        (
            webpki::UnknownStatusPolicy::Deny,
            webpki::ExpirationPolicy::Enforce,
            Err(webpki::Error::UnknownRevocationStatus),
        ),
        (
            webpki::UnknownStatusPolicy::Allow,
            webpki::ExpirationPolicy::Ignore,
            Ok(()),
        ),
    ] {
        assert_eq!(
            verify(
                &root,
                &revoked,
                ExtendedKeyUsagePurpose::ClientAuth,
                webpki::KeyUsage::client_auth(),
                unknown,
                expiration
            )?,
            Err(webpki::Error::CertRevoked)
        );
        assert_eq!(
            verify(
                &root,
                &unrelated,
                ExtendedKeyUsagePurpose::ClientAuth,
                webpki::KeyUsage::client_auth(),
                unknown,
                expiration
            )?,
            unrelated_result
        );
    }
    let stale = crl(&root, before - Duration::from_secs(60), before, true)?;
    assert_eq!(
        verify(
            &root,
            &stale,
            ExtendedKeyUsagePurpose::ClientAuth,
            webpki::KeyUsage::client_auth(),
            webpki::UnknownStatusPolicy::Allow,
            webpki::ExpirationPolicy::Ignore
        )?,
        Err(webpki::Error::CertRevoked)
    );
    Ok(())
}

#[test]
fn verification_uses_the_requested_key_usage() -> TestResult {
    let root = issuer("Root")?;
    let crl = crl(
        &root,
        now() - Duration::from_secs(60),
        now() + Duration::from_secs(3600),
        false,
    )?;
    let client = verify(
        &root,
        &crl,
        ExtendedKeyUsagePurpose::ServerAuth,
        webpki::KeyUsage::client_auth(),
        webpki::UnknownStatusPolicy::Deny,
        webpki::ExpirationPolicy::Enforce,
    )?;
    assert!(matches!(
        client,
        Err(webpki::Error::RequiredEkuNotFoundContext(_))
    ));
    assert_eq!(
        verify(
            &root,
            &crl,
            ExtendedKeyUsagePurpose::ServerAuth,
            webpki::KeyUsage::server_auth(),
            webpki::UnknownStatusPolicy::Deny,
            webpki::ExpirationPolicy::Enforce
        )?,
        Ok(())
    );
    Ok(())
}

#[test]
fn crl_metadata_preserves_numeric_order_and_accounts_for_serials() -> TestResult {
    let root = issuer("Root")?;
    let now = now();
    let this_update = now - Duration::from_secs(60);
    let next_update = now + Duration::from_secs(3600);
    let mut numbers = Vec::new();
    for number in [1u64, 255, 256] {
        let crl = CertificateRevocationListParams {
            this_update: this_update.into(),
            next_update: next_update.into(),
            crl_number: number.into(),
            issuing_distribution_point: None,
            revoked_certs: [1u64, 255, 256]
                .into_iter()
                .map(|serial| RevokedCertParams {
                    serial_number: serial.into(),
                    revocation_time: this_update.into(),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::PreSpecified(vec![1]),
        }
        .signed_by(&root)?;
        let parsed = parse_crl(crl.der(), now).map_err(|error| format!("{error:?}"))?;
        assert_eq!(parsed.this_update, this_update);
        assert_eq!(parsed.next_update, next_update);
        let decoded: CertificateList = CertificateList::from_der(crl.der())?;
        let serial_cost: usize = decoded
            .tbs_cert_list
            .revoked_certificates
            .iter()
            .flatten()
            .map(|entry| 2 * entry.serial_number.as_bytes().len() + 128)
            .sum();
        assert_eq!(parsed.cost, crl.der().len() + 512 + serial_cost);
        numbers.push(parsed.crl_number.ok_or("missing CRL number")?);
    }
    assert!(numbers[0] < numbers[1]);
    assert!(numbers[1] < numbers[2]);
    assert_eq!(CrlNumber::new(&[0, 0, 1]), CrlNumber::new(&[1]));
    assert_eq!(CrlNumber::new(&[0]), CrlNumber::new(&[]));
    let crl = crl(&root, this_update, next_update, false)?;
    let mut parsed: CertificateList = CertificateList::from_der(crl.der())?;
    let extensions = parsed
        .tbs_cert_list
        .crl_extensions
        .as_mut()
        .ok_or("no extensions")?;
    extensions.retain(|extension| extension.extn_id != X509CrlNumber::OID);
    assert!(
        parse_crl(&parsed.to_der()?, now)
            .map_err(|error| format!("{error:?}"))?
            .crl_number
            .is_none()
    );
    parsed
        .tbs_cert_list
        .crl_extensions
        .as_mut()
        .ok_or("no extensions")?
        .push(x509_cert::ext::Extension {
            extn_id: X509CrlNumber::OID,
            critical: false,
            extn_value: x509_cert::der::asn1::OctetString::new(&b"invalid"[..])?,
        });
    assert!(matches!(
        parse_crl(&parsed.to_der()?, now),
        Err(CrlLoadError::Invalid)
    ));
    Ok(())
}

#[test]
fn cost_limit_precedes_webpki_owned_parsing_and_accepts_exact_cost() -> TestResult {
    let root = issuer("Root")?;
    let now = now();
    let der = crl(
        &root,
        now - Duration::from_secs(60),
        now + Duration::from_secs(3600),
        false,
    )?;
    let parsed = parse_crl(der.der(), now).map_err(|error| format!("{error:?}"))?;
    assert!(
        parse_crl_with_cost_limit(der.der(), now, parsed.cost)
            .map_err(|error| format!("{error:?}"))?
            .is_some()
    );
    assert!(
        parse_crl_with_cost_limit(der.der(), now, parsed.cost - 1)
            .map_err(|error| format!("{error:?}"))?
            .is_none()
    );
    let mut unsupported: CertificateList = CertificateList::from_der(der.der())?;
    unsupported.tbs_cert_list.version = x509_cert::Version::V1;
    let unsupported = unsupported.to_der()?;
    assert!(
        parse_crl_with_cost_limit(&unsupported, now, 0)
            .map_err(|error| format!("{error:?}"))?
            .is_none()
    );
    assert!(matches!(
        parse_crl(&unsupported, now),
        Err(CrlLoadError::Invalid)
    ));
    Ok(())
}
