// SPDX-License-Identifier: Apache-2.0

use std::cmp::Ordering;
use std::fs::File;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, SignatureVerificationAlgorithm, TrustAnchor,
    UnixTime,
};
use x509_cert::crl::CertificateList;
use x509_cert::der::{Decode, oid::AssociatedOid};
use x509_cert::ext::pkix::CrlNumber as X509CrlNumber;

pub(crate) const RECHECK_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CrlLoadError {
    Unreadable,
    Invalid,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CrlNumber(Box<[u8]>);

impl CrlNumber {
    fn new(bytes: &[u8]) -> Self {
        let start = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len());
        Self(bytes[start..].into())
    }
}

impl Ord for CrlNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for CrlNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub(crate) struct ParsedCrl {
    pub(crate) crl: webpki::CertRevocationList<'static>,
    pub(crate) this_update: SystemTime,
    pub(crate) crl_number: Option<CrlNumber>,
    /// Estimated bytes retained by the owned CRL.
    pub(crate) cost: usize,
    pub(crate) next_update: SystemTime,
}

pub(crate) fn parse_crl(der: &[u8], now: SystemTime) -> Result<ParsedCrl, CrlLoadError> {
    parse_crl_with_cost_limit(der, now, usize::MAX)?.ok_or(CrlLoadError::Invalid)
}

/// Returns None when the estimated retained CRL cost exceeds max_cost.
pub(crate) fn parse_crl_with_cost_limit(
    der: &[u8],
    now: SystemTime,
    max_cost: usize,
) -> Result<Option<ParsedCrl>, CrlLoadError> {
    let parsed: CertificateList =
        CertificateList::from_der(der).map_err(|_| CrlLoadError::Invalid)?;
    let this_update = UNIX_EPOCH
        .checked_add(parsed.tbs_cert_list.this_update.to_unix_duration())
        .ok_or(CrlLoadError::Invalid)?;
    let next_update = parsed
        .tbs_cert_list
        .next_update
        .ok_or(CrlLoadError::Invalid)?;
    let next_update = UNIX_EPOCH
        .checked_add(next_update.to_unix_duration())
        .ok_or(CrlLoadError::Invalid)?;
    if next_update <= this_update {
        return Err(CrlLoadError::Invalid);
    }
    if this_update > now || next_update <= now {
        return Err(CrlLoadError::Stale);
    }
    let mut crl_number = None;
    for extension in parsed.tbs_cert_list.crl_extensions.iter().flatten() {
        if extension.extn_id == X509CrlNumber::OID {
            let number = X509CrlNumber::from_der(extension.extn_value.as_bytes())
                .map_err(|_| CrlLoadError::Invalid)?;
            crl_number = Some(CrlNumber::new(number.0.as_bytes()));
        }
    }
    let cost = parsed
        .tbs_cert_list
        .revoked_certificates
        .iter()
        .flatten()
        .try_fold(
            der.len().checked_add(512).ok_or(CrlLoadError::Invalid)?,
            |cost, entry| {
                entry
                    .serial_number
                    .as_bytes()
                    .len()
                    .checked_mul(2)
                    .and_then(|size| size.checked_add(128))
                    .and_then(|size| cost.checked_add(size))
                    .ok_or(CrlLoadError::Invalid)
            },
        )?;
    if cost > max_cost {
        return Ok(None);
    }
    drop(parsed);
    let crl = webpki::OwnedCertRevocationList::from_der(der).map_err(|_| CrlLoadError::Invalid)?;
    Ok(Some(ParsedCrl {
        crl: webpki::CertRevocationList::Owned(crl),
        this_update,
        crl_number,
        cost,
        next_update,
    }))
}

#[derive(Debug)]
pub(crate) struct CrlSet {
    crls: Vec<webpki::CertRevocationList<'static>>,
    next_update: SystemTime,
}

impl CrlSet {
    /// Performs blocking file I/O.
    pub(crate) fn load(path: &Path, now: SystemTime) -> Result<Self, CrlLoadError> {
        let file = File::open(path).map_err(|_| CrlLoadError::Unreadable)?;
        let mut crls = Vec::new();
        let mut next_update = None;
        for der in CertificateRevocationListDer::pem_reader_iter(file) {
            let der = der.map_err(|_| CrlLoadError::Invalid)?;
            let parsed = parse_crl(der.as_ref(), now)?;
            next_update = Some(
                next_update.map_or(parsed.next_update, |deadline: SystemTime| {
                    deadline.min(parsed.next_update)
                }),
            );
            crls.push(parsed.crl);
        }
        Ok(Self {
            crls,
            next_update: next_update.ok_or(CrlLoadError::Invalid)?,
        })
    }

    pub(crate) fn next_update(&self) -> SystemTime {
        self.next_update
    }

    pub(crate) fn verify_path<'p>(
        &'p self,
        end_entity: &'p webpki::EndEntityCert<'p>,
        anchors: &'p [TrustAnchor<'_>],
        intermediates: &'p [CertificateDer<'p>],
        now: UnixTime,
        algorithms: &[&dyn SignatureVerificationAlgorithm],
        usage: webpki::KeyUsage,
    ) -> Result<webpki::VerifiedPath<'p>, webpki::Error> {
        let crls = self.crls.iter().collect::<Vec<_>>();
        verify_with_crls(
            end_entity,
            anchors,
            intermediates,
            now,
            algorithms,
            usage,
            RevocationRules {
                crls: &crls,
                unknown: webpki::UnknownStatusPolicy::Deny,
                expiration: webpki::ExpirationPolicy::Enforce,
            },
        )
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RevocationRules<'a> {
    pub(crate) crls: &'a [&'a webpki::CertRevocationList<'a>],
    pub(crate) unknown: webpki::UnknownStatusPolicy,
    pub(crate) expiration: webpki::ExpirationPolicy,
}

pub(crate) fn verify_with_crls<'p>(
    end_entity: &'p webpki::EndEntityCert<'p>,
    anchors: &'p [TrustAnchor<'_>],
    intermediates: &'p [CertificateDer<'p>],
    now: UnixTime,
    algorithms: &[&dyn SignatureVerificationAlgorithm],
    usage: webpki::KeyUsage,
    rules: RevocationRules<'_>,
) -> Result<webpki::VerifiedPath<'p>, webpki::Error> {
    let revocation = webpki::RevocationOptionsBuilder::new(rules.crls)
        .map_err(|_| webpki::Error::UnknownRevocationStatus)?
        .with_depth(webpki::RevocationCheckDepth::Chain)
        .with_status_policy(rules.unknown)
        .with_expiration_policy(rules.expiration)
        .build();
    end_entity.verify_for_usage(
        algorithms,
        anchors,
        intermediates,
        now,
        usage,
        Some(revocation),
        None,
    )
}

#[cfg(test)]
mod tests;
