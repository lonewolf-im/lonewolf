// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::Uri;
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;
use serde::de::{DeserializeOwned, Error as _, IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

pub(crate) const MAX_RECORD: usize = 2 * 1024 * 1024;
const MAX_CHAIN: usize = 1024 * 1024;
const MAX_KEY: usize = 16 * 1024;
const MAX_CREDENTIALS: usize = 64 * 1024;
const MAX_URL: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeErrorKind {
    InvalidInput,
    Crypto,
    InvalidCaBundle,
    Unavailable,
    Timeout,
    Closed,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcmeError {
    kind: AcmeErrorKind,
    status: Option<u16>,
}

impl AcmeError {
    pub(crate) fn new(kind: AcmeErrorKind) -> Self {
        Self { kind, status: None }
    }

    pub(crate) fn with_status(kind: AcmeErrorKind, status: u16) -> Self {
        Self {
            kind,
            status: Some(status),
        }
    }

    pub fn kind(&self) -> AcmeErrorKind {
        self.kind
    }
    pub fn status(&self) -> Option<u16> {
        self.status
    }
}

impl fmt::Display for AcmeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ACME {:?}", self.kind)?;
        if let Some(status) = self.status {
            write!(formatter, " (status {status})")?;
        }
        Ok(())
    }
}

impl std::error::Error for AcmeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    InvalidData,
    CorruptData,
    UnsupportedData,
    Unavailable,
    UnsafePath,
    StateUncertain,
    Closed,
    DeadlineElapsed,
    Other,
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidData => "invalid ACME state input",
            Self::CorruptData => "corrupt ACME state",
            Self::UnsupportedData => "unsupported ACME state",
            Self::Unavailable => "ACME state unavailable",
            Self::UnsafePath => "ACME state path is not private regular storage",
            Self::StateUncertain => "ACME state commit is uncertain; reopen required",
            Self::Closed => "ACME state admission is closed",
            Self::DeadlineElapsed => "ACME state drain deadline elapsed",
            Self::Other => "ACME state operation failed",
        })
    }
}

impl std::error::Error for StateError {}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateMaterial {
    #[serde(with = "chain_bytes")]
    pub chain: Vec<Vec<u8>>,
    #[serde(with = "key_bytes")]
    pub private_key_pkcs8: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedHost {
    #[serde(deserialize_with = "xmpp_name")]
    pub xmpp_domain: String,
    #[serde(deserialize_with = "dns_name")]
    pub dns_name: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredAccount {
    #[serde(with = "key_bytes")]
    pub key_pkcs8: Zeroizing<Vec<u8>>,
    #[serde(with = "credential_bytes")]
    pub credentials_json: Option<Zeroizing<Vec<u8>>>,
    pub retry: RetryState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryState {
    pub failures: u32,
    pub not_before_unix: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingOrder {
    #[serde(with = "optional_url")]
    pub url: Option<String>,
    #[serde(with = "replacement_intent")]
    pub replaces: Option<String>,
    #[serde(with = "key_bytes")]
    pub key_pkcs8: Zeroizing<Vec<u8>>,
    #[serde(with = "csr_bytes")]
    pub csr_der: Vec<u8>,
    pub started_unix: u64,
    pub expires_unix: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCertificate {
    pub material: CertificateMaterial,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub renew_at_unix: u64,
    pub ari_check_at_unix: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredHost {
    pub host: ManagedHost,
    pub certificate: Option<StoredCertificate>,
    pub order: Option<PendingOrder>,
    pub retry: RetryState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateValidity {
    pub not_before_unix: u64,
    pub not_after_unix: u64,
}

pub struct PreparedInstall<T> {
    pub candidate: T,
    pub validity: CertificateValidity,
}

pub trait Installer: Send + Sync + 'static {
    type Prepared: Send + 'static;
    /// Validates chain validity, identity, usages, key match, and binding material.
    /// Returns validity from the same generation as the candidate.
    fn prepare(
        &self,
        host: &ManagedHost,
        material: &CertificateMaterial,
    ) -> Result<PreparedInstall<Self::Prepared>, InstallError>;
    /// Publishes a prepared generation without fallible work.
    fn activate(&self, prepared: Self::Prepared);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallError {
    NotYetValid,
    Expired,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
    Network,
    Timeout,
    RateLimited,
    Authorization,
    Protocol,
    Material,
    Account,
    State,
    Deferred,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptFailure {
    pub kind: FailureKind,
    pub status: Option<u16>,
    pub state_error: Option<StateError>,
    pub retry_not_before: Option<SystemTime>,
    /// True only after the terminal order and retry update are durably committed.
    pub terminal_order: bool,
}

impl fmt::Display for AttemptFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ACME attempt {:?}", self.kind)
    }
}

impl std::error::Error for AttemptFailure {}

impl From<StateError> for AttemptFailure {
    fn from(error: StateError) -> Self {
        Self {
            kind: FailureKind::State,
            status: None,
            state_error: Some(error),
            retry_not_before: None,
            terminal_order: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptSuccess {
    pub validity: CertificateValidity,
}

pub(crate) fn validate_url(value: &str) -> Result<(), StateError> {
    if value.len() > MAX_URL || value.chars().any(|ch| ch.is_whitespace() || ch == '#') {
        return Err(StateError::InvalidData);
    }
    let uri: Uri = value.parse().map_err(|_| StateError::InvalidData)?;
    let authority = uri.authority().ok_or(StateError::InvalidData)?;
    let host = authority.host();
    let valid_port = authority.as_str() == host
        || authority.port().is_some_and(|port| {
            port.as_u16() != 0
                && port.as_str().bytes().all(|byte| byte.is_ascii_digit())
                && authority.as_str().len() == host.len() + 1 + port.as_str().len()
        });
    let invalid_ipv6 = host.strip_prefix('[').is_some_and(|inner| {
        inner
            .strip_suffix(']')
            .is_none_or(|address| address.parse::<Ipv6Addr>().is_err())
    });
    if uri.scheme_str() != Some("https")
        || authority.as_str().contains('@')
        || host.is_empty()
        || !valid_port
        || invalid_ipv6
        || uri.path().is_empty()
    {
        return Err(StateError::InvalidData);
    }
    Ok(())
}

pub(crate) fn validate_dns(value: &str) -> Result<(), StateError> {
    let ascii = idna::domain_to_ascii_strict(value).map_err(|_| StateError::InvalidData)?;
    if ascii != value
        || ascii.parse::<IpAddr>().is_ok()
        || ascii.len() > 253
        || !ascii.contains('.')
        || ascii.ends_with(".localhost")
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(StateError::InvalidData);
    }
    Ok(())
}

fn timestamp(value: u64) -> Result<(), StateError> {
    if value > i64::MAX as u64 || UNIX_EPOCH.checked_add(Duration::from_secs(value)).is_none() {
        return Err(StateError::InvalidData);
    }
    Ok(())
}

fn key(value: &[u8]) -> Result<(), StateError> {
    if value.is_empty() || value.len() > MAX_KEY {
        return Err(StateError::InvalidData);
    }
    Ok(())
}

impl StoredAccount {
    pub(crate) fn validate(&self) -> Result<(), StateError> {
        key(&self.key_pkcs8)?;
        timestamp(self.retry.not_before_unix)?;
        if let Some(credentials) = &self.credentials_json {
            if credentials.len() > MAX_CREDENTIALS {
                return Err(StateError::InvalidData);
            }
            let mut deserializer = serde_json::Deserializer::from_slice(credentials);
            IgnoredAny::deserialize(&mut deserializer).map_err(|_| StateError::InvalidData)?;
            deserializer.end().map_err(|_| StateError::InvalidData)?;
        }
        Ok(())
    }
}

impl StoredHost {
    pub(crate) fn validate(&self) -> Result<(), StateError> {
        validate_dns(&self.host.dns_name)?;
        if self.host.xmpp_domain.len() > 1023 {
            return Err(StateError::InvalidData);
        }
        let mut arena = Arena::try_new(ArenaConfig::default()).map_err(|_| StateError::Other)?;
        let jid = Jid::from_parts_in(None, &self.host.xmpp_domain, None, &mut arena)
            .map_err(|_| StateError::InvalidData)?;
        let normalized = jid.resolve(&arena).map_err(|_| StateError::Other)?;
        if normalized.domainpart() != self.host.xmpp_domain
            || idna::domain_to_ascii_strict(&self.host.xmpp_domain)
                .map_err(|_| StateError::InvalidData)?
                != self.host.dns_name
        {
            return Err(StateError::InvalidData);
        }
        timestamp(self.retry.not_before_unix)?;
        if let Some(certificate) = &self.certificate {
            let chain = &certificate.material.chain;
            if chain.is_empty()
                || chain.len() > 16
                || chain.iter().any(Vec::is_empty)
                || chain.iter().map(Vec::len).sum::<usize>() > MAX_CHAIN
                || certificate.not_before_unix >= certificate.not_after_unix
            {
                return Err(StateError::InvalidData);
            }
            key(&certificate.material.private_key_pkcs8)?;
            for value in [
                certificate.not_before_unix,
                certificate.not_after_unix,
                certificate.renew_at_unix,
                certificate.ari_check_at_unix,
            ] {
                timestamp(value)?;
            }
        }
        if let Some(order) = &self.order {
            if let Some(replaces) = &order.replaces {
                validate_replacement(replaces)?;
                let certificate = self.certificate.as_ref().ok_or(StateError::InvalidData)?;
                let expected = crate::crypto::certificate_identifier(&certificate.material)
                    .map_err(|_| StateError::InvalidData)?;
                if expected.to_string() != *replaces {
                    return Err(StateError::InvalidData);
                }
            }
            key(&order.key_pkcs8)?;
            if order.csr_der.is_empty() || order.csr_der.len() > MAX_RECORD {
                return Err(StateError::InvalidData);
            }
            if let Some(url) = &order.url {
                validate_url(url)?;
            }
            timestamp(order.started_unix)?;
            if let Some(expires) = order.expires_unix {
                timestamp(expires)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn encode(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>, StateError> {
    struct BoundedWriter(Zeroizing<Vec<u8>>);
    impl Write for BoundedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > MAX_RECORD - self.0.len() {
                return Err(io::Error::other("ACME record limit exceeded"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = BoundedWriter(Zeroizing::new(Vec::with_capacity(MAX_RECORD)));
    serde_json::to_writer(&mut writer, value).map_err(|_| StateError::InvalidData)?;
    Ok(writer.0)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StateError> {
    if bytes.len() > MAX_RECORD {
        return Err(StateError::CorruptData);
    }
    serde_json::from_slice(bytes).map_err(|_| StateError::CorruptData)
}

fn bounded_string<'de, D: Deserializer<'de>, const LIMIT: usize>(
    deserializer: D,
) -> Result<String, D::Error> {
    struct StringVisitor<const LIMIT: usize>;
    impl<'de, const LIMIT: usize> Visitor<'de> for StringVisitor<LIMIT> {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bounded text")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.len() > LIMIT {
                return Err(E::custom("text limit exceeded"));
            }
            Ok(value.to_owned())
        }
    }
    deserializer.deserialize_str(StringVisitor::<LIMIT>)
}

pub(crate) fn url_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded_string::<D, MAX_URL>(deserializer)
}

fn xmpp_name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded_string::<D, 1023>(deserializer)
}

fn dns_name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded_string::<D, 253>(deserializer)
}

mod optional_url {
    use super::*;

    pub(super) fn serialize<S: Serializer>(
        value: &Option<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<String>, D::Error> {
        #[derive(Deserialize)]
        struct Url(#[serde(deserialize_with = "url_string")] String);
        Option::<Url>::deserialize(deserializer).map(|value| value.map(|url| url.0))
    }
}

fn validate_replacement(value: &str) -> Result<(), StateError> {
    if value.len() > MAX_RECORD {
        return Err(StateError::InvalidData);
    }
    let (aki, serial) = value.split_once('.').ok_or(StateError::InvalidData)?;
    let aki = URL_SAFE_NO_PAD
        .decode(aki)
        .map_err(|_| StateError::InvalidData)?;
    let serial = URL_SAFE_NO_PAD
        .decode(serial)
        .map_err(|_| StateError::InvalidData)?;
    if aki.is_empty()
        || serial.is_empty()
        || serial.len() > 21
        || serial[0] & 0x80 != 0
        || serial.len() > 1 && serial[0] == 0 && serial[1] & 0x80 == 0
    {
        return Err(StateError::InvalidData);
    }
    Ok(())
}

mod replacement_intent {
    use super::*;
    pub(super) fn serialize<S: Serializer>(
        value: &Option<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<String>, D::Error> {
        fn identifier<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
            let value = bounded_string::<D, MAX_RECORD>(deserializer)?;
            validate_replacement(&value).map_err(D::Error::custom)?;
            Ok(value)
        }
        #[derive(Deserialize)]
        struct Intent(#[serde(deserialize_with = "identifier")] String);
        Option::<Intent>::deserialize(deserializer).map(|value| value.map(|intent| intent.0))
    }
}

fn secret<'de, D: Deserializer<'de>, const LIMIT: usize>(
    deserializer: D,
) -> Result<Zeroizing<Vec<u8>>, D::Error> {
    struct SecretVisitor<const LIMIT: usize>;
    impl<'de, const LIMIT: usize> Visitor<'de> for SecretVisitor<LIMIT> {
        type Value = Zeroizing<Vec<u8>>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bounded secret bytes")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut bytes = Zeroizing::new(Vec::with_capacity(LIMIT));
            while let Some(byte) = sequence.next_element::<u8>()? {
                if bytes.len() == LIMIT {
                    return Err(A::Error::custom("secret limit exceeded"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_seq(SecretVisitor::<LIMIT>)
}

mod key_bytes {
    use super::*;

    pub(super) fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        secret::<D, MAX_KEY>(deserializer)
    }
}

mod credential_bytes {
    use super::*;

    pub(super) fn serialize<S: Serializer>(
        value: &Option<Zeroizing<Vec<u8>>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.as_deref().serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, D::Error> {
        struct OptionalVisitor;
        impl<'de> Visitor<'de> for OptionalVisitor {
            type Value = Option<Zeroizing<Vec<u8>>>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("optional bounded credential bytes")
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                secret::<D, MAX_CREDENTIALS>(deserializer).map(Some)
            }
        }
        deserializer.deserialize_option(OptionalVisitor)
    }
}

fn public_bytes<'de, D: Deserializer<'de>, const LIMIT: usize>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    struct BytesVisitor<const LIMIT: usize>;
    impl<'de, const LIMIT: usize> Visitor<'de> for BytesVisitor<LIMIT> {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bounded bytes")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.len() > LIMIT.div_ceil(3) * 4 {
                return Err(E::custom("byte limit exceeded"));
            }
            let bytes = STANDARD
                .decode(value)
                .map_err(|_| E::custom("invalid bytes"))?;
            if bytes.len() > LIMIT {
                return Err(E::custom("byte limit exceeded"));
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_str(BytesVisitor::<LIMIT>)
}

mod csr_bytes {
    use super::*;

    pub(super) fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        public_bytes::<D, MAX_RECORD>(deserializer)
    }
}

mod chain_bytes {
    use super::*;

    pub(super) fn serialize<S: Serializer>(
        value: &[Vec<u8>],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq as _;

        struct CertificateBytes<'a>(&'a [u8]);
        impl Serialize for CertificateBytes<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&STANDARD.encode(self.0))
            }
        }
        let mut sequence = serializer.serialize_seq(Some(value.len()))?;
        for certificate in value {
            sequence.serialize_element(&CertificateBytes(certificate))?;
        }
        sequence.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        struct CertificateBytes(Vec<u8>);
        impl<'de> Deserialize<'de> for CertificateBytes {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                public_bytes::<D, MAX_CHAIN>(deserializer).map(Self)
            }
        }
        struct ChainVisitor;
        impl<'de> Visitor<'de> for ChainVisitor {
            type Value = Vec<Vec<u8>>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded certificate chain")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut chain = Vec::new();
                let mut total = 0;
                while let Some(CertificateBytes(bytes)) = sequence.next_element()? {
                    total += bytes.len();
                    if chain.len() == 16 || total > MAX_CHAIN {
                        return Err(A::Error::custom("certificate chain limit exceeded"));
                    }
                    chain.push(bytes);
                }
                Ok(chain)
            }
        }
        deserializer.deserialize_seq(ChainVisitor)
    }
}

#[cfg(test)]
mod tests;
