// SPDX-License-Identifier: Apache-2.0

use rustls::pki_types::{CertificateDer, DnsName, ServerName};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, Error};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::asn1::{Ia5StringRef, ObjectIdentifier};
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

const SRV_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.8.7");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XmppService {
    Client,
    Server,
}

/// Checks name and service correspondence, without authenticating the peer.
/// Callers must also verify trust, validity, usage, revocation, and key possession.
pub(crate) fn verify_service_identity(
    certificate: &CertificateDer<'_>,
    identity: &ServerName<'_>,
    service: XmppService,
) -> Result<(), Error> {
    let parsed = Certificate::from_der(certificate.as_ref())
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let names = parsed
        .tbs_certificate()
        .get_extension::<SubjectAltName>()
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let certificate = ParsedCertificate::try_from(certificate)?;
    let mismatch = match rustls::client::verify_server_name(&certificate, identity) {
        Ok(()) => return Ok(()),
        Err(
            error @ Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            ),
        ) => error,
        Err(error) => return Err(error),
    };
    let ServerName::DnsName(identity) = identity else {
        return Err(mismatch);
    };
    if let Some((_, names)) = names {
        for name in names.0 {
            let GeneralName::OtherName(name) = name else {
                continue;
            };
            if name.type_id != SRV_ID {
                continue;
            }
            let Ok(value) = Ia5StringRef::try_from(&name.value) else {
                continue;
            };
            let Some((label, domain)) = value.as_str().split_once('.') else {
                continue;
            };
            if from_srv_label(label) == Some(service) && matches_domain(domain, identity) {
                return Ok(());
            }
        }
    }
    Err(mismatch)
}

fn from_srv_label(label: &str) -> Option<XmppService> {
    if label.eq_ignore_ascii_case("_xmpp-client") {
        Some(XmppService::Client)
    } else if label.eq_ignore_ascii_case("_xmpp-server") {
        Some(XmppService::Server)
    } else {
        None
    }
}

fn matches_domain(domain: &str, identity: &DnsName<'_>) -> bool {
    let reference = identity.as_ref();
    let reference = reference.strip_suffix('.').unwrap_or(reference);
    let (suffix, reference) = match domain.strip_prefix("*.") {
        Some(suffix) => match reference.split_once('.') {
            Some((label, reference)) if !label.is_empty() => (suffix, reference),
            _ => return false,
        },
        None => (domain, reference),
    };
    if domain.len() > 253
        || !suffix.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return false;
    }
    suffix.eq_ignore_ascii_case(reference)
}

#[cfg(test)]
mod tests;
