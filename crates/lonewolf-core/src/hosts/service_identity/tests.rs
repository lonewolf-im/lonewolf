// SPDX-License-Identifier: Apache-2.0

use std::error::Error as StdError;

use rcgen::{CertificateParams, CustomExtension, DnType};
use x509_cert::der::asn1::{Any, Ia5String, Utf8StringRef};
use x509_cert::der::{Encode, Tag};
use x509_cert::ext::pkix::name::OtherName;

use super::*;
use crate::hosts::test_support::{TestSigner, san_parameters, srv_name};
use crate::hosts::tls_identity;

type TestResult<T = ()> = Result<T, Box<dyn StdError>>;

fn certificate(names: Vec<GeneralName>) -> TestResult<CertificateDer<'static>> {
    sign(san_parameters(names)?)
}

fn sign(mut parameters: CertificateParams) -> TestResult<CertificateDer<'static>> {
    parameters.serial_number = Some(rcgen::SerialNumber::from(1_u64));
    Ok(parameters.self_signed(&TestSigner::new()?)?.der().clone())
}

fn dns_name(name: &str) -> TestResult<GeneralName> {
    Ok(GeneralName::DnsName(Ia5String::new(name)?))
}

fn utf8_srv_name(name: &str) -> TestResult<GeneralName> {
    Ok(GeneralName::OtherName(OtherName {
        type_id: SRV_ID,
        value: Utf8StringRef::new(name)?.into(),
    }))
}

fn assert_mismatch(
    certificate: &CertificateDer<'_>,
    identity: &ServerName<'_>,
    service: XmppService,
) -> TestResult {
    let expected =
        rustls::client::verify_server_name(&ParsedCertificate::try_from(certificate)?, identity);
    assert!(matches!(
        expected,
        Err(Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
        ))
    ));
    assert_eq!(
        verify_service_identity(certificate, identity, service),
        expected
    );
    Ok(())
}

#[test]
fn srv_ids_match_only_their_own_service_and_domain() -> TestResult {
    for (label, service, other) in [
        ("_xmpp-client", XmppService::Client, XmppService::Server),
        ("_xmpp-server", XmppService::Server, XmppService::Client),
    ] {
        let certificate = certificate(vec![srv_name(&format!("{label}.example.com"))?])?;
        let identity = tls_identity("example.com")?;
        verify_service_identity(&certificate, &identity, service)?;
        assert_mismatch(&certificate, &identity, other)?;
        assert_mismatch(&certificate, &tls_identity("other.example.com")?, service)?;
    }
    Ok(())
}

#[test]
fn srv_ids_match_ascii_case_and_alabel_reference_domains() -> TestResult {
    for (domain, presented, service) in [
        (
            "example.com",
            "_XmPp-ClIeNt.ExAmPlE.CoM",
            XmppService::Client,
        ),
        (
            "example.com",
            "_XmPp-SeRvEr.ExAmPlE.CoM",
            XmppService::Server,
        ),
        (
            "bücher.example",
            "_xmpp-client.XN--BCHER-KVA.example",
            XmppService::Client,
        ),
    ] {
        verify_service_identity(
            &certificate(vec![srv_name(presented)?])?,
            &tls_identity(domain)?,
            service,
        )?;
    }
    Ok(())
}

#[test]
fn utf8_srv_ids_do_not_replace_ia5_srv_ids() -> TestResult {
    let identity = tls_identity("example.com")?;
    assert_mismatch(
        &certificate(vec![utf8_srv_name("_xmpp-client.example.com")?])?,
        &identity,
        XmppService::Client,
    )?;
    for first in [true, false] {
        let mut names = vec![
            utf8_srv_name("_xmpp-client.example.com")?,
            srv_name("_xmpp-client.example.com")?,
        ];
        if !first {
            names.reverse();
        }
        verify_service_identity(&certificate(names)?, &identity, XmppService::Client)?;
    }
    Ok(())
}

#[test]
fn individually_unusable_srv_ids_do_not_hide_a_later_valid_identifier() -> TestResult {
    let identity = tls_identity("example.com")?;
    let mut invalid = Vec::new();
    for value in [
        "",
        ".example.com",
        "_xmpp-client",
        "_xmpp-client.",
        "_xmpp-client..example.com",
        "_xmpp-client.bad_name.example.com",
        "_xmpp-client.-example.com",
        "_xmpp-client.example-.com",
        "_xmpp-client.example.com\0",
        "_xmpp-client._tcp.example.com",
        "*.example.com",
        "_xmpp-*.example.com",
        "_xmpp-client.other.com",
        "_xmpp-server.example.com",
    ] {
        invalid.push(srv_name(value)?);
    }
    invalid.push(GeneralName::OtherName(OtherName {
        type_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.8.5"),
        value: (&Ia5String::new("_xmpp-client.example.com")?).into(),
    }));
    invalid.push(GeneralName::OtherName(OtherName {
        type_id: SRV_ID,
        value: Any::new(Tag::Ia5String, vec![0xff])?,
    }));
    for name in invalid {
        assert_mismatch(
            &certificate(vec![name.clone()])?,
            &identity,
            XmppService::Client,
        )?;
        for first in [true, false] {
            let mut names = vec![name.clone(), srv_name("_xmpp-client.example.com")?];
            if !first {
                names.reverse();
            }
            verify_service_identity(&certificate(names)?, &identity, XmppService::Client)?;
        }
    }
    Ok(())
}

#[test]
fn matching_dns_id_remains_sufficient_with_another_srv_service() -> TestResult {
    for first in [true, false] {
        let mut names = vec![
            srv_name("_xmpp-server.example.com")?,
            dns_name("example.com")?,
        ];
        if !first {
            names.reverse();
        }
        verify_service_identity(
            &certificate(names)?,
            &tls_identity("example.com")?,
            XmppService::Client,
        )?;
    }
    Ok(())
}

#[test]
fn wrong_dns_and_srv_ids_do_not_hide_a_matching_srv_id() -> TestResult {
    for first in [true, false] {
        let mut names = vec![
            dns_name("wrong.example.com")?,
            srv_name("_xmpp-server.example.com")?,
            srv_name("_xmpp-client.example.com")?,
        ];
        if !first {
            names.reverse();
        }
        verify_service_identity(
            &certificate(names)?,
            &tls_identity("example.com")?,
            XmppService::Client,
        )?;
    }
    Ok(())
}

#[test]
fn service_and_domain_are_not_combined_from_different_srv_ids() -> TestResult {
    assert_mismatch(
        &certificate(vec![
            srv_name("_xmpp-client.other.com")?,
            srv_name("_xmpp-server.example.com")?,
        ])?,
        &tls_identity("example.com")?,
        XmppService::Client,
    )
}

#[test]
fn srv_wildcards_match_exactly_one_complete_domain_label() -> TestResult {
    let valid = certificate(vec![srv_name("_xmpp-client.*.example.com")?])?;
    verify_service_identity(
        &valid,
        &tls_identity("one.example.com")?,
        XmppService::Client,
    )?;
    for domain in ["example.com", "two.one.example.com", "other.com"] {
        assert_mismatch(&valid, &tls_identity(domain)?, XmppService::Client)?;
    }
    for name in [
        "_xmpp-client.f*.example.com",
        "_xmpp-client.*foo.example.com",
        "_xmpp-client.*.*.com",
        "_xmpp-client.foo.*.com",
        "_xmpp-client.*.",
        "_xmpp-client.*..example.com",
        "_xmpp-*.one.example.com",
    ] {
        assert_mismatch(
            &certificate(vec![srv_name(name)?])?,
            &tls_identity("foo.example.com")?,
            XmppService::Client,
        )?;
    }
    Ok(())
}

#[test]
fn dns_wildcards_and_ip_sans_keep_their_rustls_behavior() -> TestResult {
    let dns = certificate(vec![dns_name("*.example.com")?])?;
    verify_service_identity(&dns, &tls_identity("one.example.com")?, XmppService::Client)?;
    assert_mismatch(
        &dns,
        &tls_identity("two.one.example.com")?,
        XmppService::Client,
    )?;
    for address in ["192.0.2.1", "2001:db8::1"] {
        let identity = ServerName::IpAddress(address.parse::<std::net::IpAddr>()?.into());
        let certificate = certificate(vec![GeneralName::from(
            address.parse::<std::net::IpAddr>()?,
        )])?;
        verify_service_identity(&certificate, &identity, XmppService::Client)?;
        verify_service_identity(&certificate, &identity, XmppService::Server)?;
    }
    Ok(())
}

#[test]
fn typed_ip_references_have_no_dns_or_srv_fallback() -> TestResult {
    for address in ["192.0.2.1", "2001:db8::1"] {
        let identity = ServerName::IpAddress(address.parse::<std::net::IpAddr>()?.into());
        let certificate = certificate(vec![
            dns_name(address)?,
            srv_name(&format!("_xmpp-client.{address}"))?,
            srv_name(&format!("_xmpp-server.{address}"))?,
        ])?;
        assert_mismatch(&certificate, &identity, XmppService::Client)?;
        assert_mismatch(&certificate, &identity, XmppService::Server)?;
    }
    Ok(())
}

#[test]
fn malformed_san_container_is_fatal_even_with_a_matching_identifier() -> TestResult {
    for name in [
        dns_name("example.com")?,
        srv_name("_xmpp-client.example.com")?,
    ] {
        for first in [true, false] {
            let encoded = SubjectAltName(vec![name.clone()]).to_der()?;
            let encoded = Any::from_der(&encoded)?;
            let mut content = encoded.value().to_vec();
            let malformed = [0xa0, 0x01, 0x06];
            if first {
                content.extend_from_slice(&malformed);
            } else {
                content.splice(0..0, malformed);
            }
            let mut parameters = CertificateParams::new(Vec::<String>::new())?;
            parameters
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[2, 5, 29, 17],
                    Any::new(Tag::Sequence, content)?.to_der()?,
                ));
            let certificate = sign(parameters)?;
            assert_eq!(
                verify_service_identity(
                    &certificate,
                    &tls_identity("example.com")?,
                    XmppService::Client
                ),
                Err(Error::InvalidCertificate(CertificateError::BadEncoding))
            );
        }
    }
    Ok(())
}

#[test]
fn absent_san_does_not_enable_common_name_fallback() -> TestResult {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters
        .distinguished_name
        .push(DnType::CommonName, "example.com");
    let certificate = sign(parameters)?;
    assert_mismatch(
        &certificate,
        &tls_identity("example.com")?,
        XmppService::Client,
    )
}

#[test]
fn malformed_certificate_is_bad_encoding() -> TestResult {
    assert_eq!(
        verify_service_identity(
            &CertificateDer::from(&b"not DER"[..]),
            &tls_identity("example.com")?,
            XmppService::Client
        ),
        Err(Error::InvalidCertificate(CertificateError::BadEncoding))
    );
    Ok(())
}

fn xmpp_name(value: &str) -> TestResult<GeneralName> {
    Ok(GeneralName::OtherName(OtherName {
        type_id: XMPP_ADDR,
        value: Utf8StringRef::new(value)?.into(),
    }))
}

#[test]
fn xmpp_addresses_authorize_only_server_domains() -> TestResult {
    for (presented, reference) in [
        ("example.com", "example.com"),
        ("EXAMPLE.com", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("xn--bcher-kva.example", "bücher.example"),
    ] {
        let leaf = certificate(vec![xmpp_name(presented)?])?;
        let identity = tls_identity(reference)?;
        verify_service_identity(&leaf, &identity, XmppService::Server)?;
        assert_mismatch(&leaf, &identity, XmppService::Client)?;
    }
    Ok(())
}

#[test]
fn unusable_xmpp_addresses_do_not_authorize_a_server_or_hide_a_valid_name() -> TestResult {
    let identity = tls_identity("example.com")?;
    let mut invalid = vec![GeneralName::OtherName(OtherName {
        type_id: XMPP_ADDR,
        value: (&Ia5String::new("example.com")?).into(),
    })];
    for value in [
        "",
        "alice@example.com",
        "example.com/resource",
        "alice@example.com/resource",
        "other.com",
        "*.example.com",
        "example.com\0",
        "example.com/",
    ] {
        invalid.push(xmpp_name(value)?);
    }
    for name in invalid {
        assert_mismatch(
            &certificate(vec![name.clone()])?,
            &identity,
            XmppService::Server,
        )?;
        for first in [true, false] {
            let mut names = vec![name.clone(), xmpp_name("example.com")?];
            if !first {
                names.reverse();
            }
            verify_service_identity(&certificate(names)?, &identity, XmppService::Server)?;
        }
    }
    Ok(())
}
