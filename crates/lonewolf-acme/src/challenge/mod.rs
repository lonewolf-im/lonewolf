// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use hyper::body::Bytes;
use parking_lot::Mutex as PlMutex;

use crate::ManagedHost;
use crate::types::validate_dns;

const MAX_CHALLENGES: usize = 64;

#[derive(Clone)]
pub struct Challenges {
    inner: Arc<PlMutex<Registry>>,
}

struct Registry {
    hosts: HashMap<Box<str>, Option<Arc<Entry>>>,
    active: usize,
}

struct Entry {
    token: Box<str>,
    authorization: Bytes,
}

#[must_use = "Dropping the lease removes its challenge."]
pub struct ChallengeLease {
    challenges: Challenges,
    host: Box<str>,
    entry: Arc<Entry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeError {
    InvalidHost,
    InvalidToken,
    InvalidAuthorization,
    UnconfiguredHost,
    AlreadyPublished,
    Capacity,
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidHost => "invalid challenge host",
            Self::InvalidToken => "invalid challenge token",
            Self::InvalidAuthorization => "invalid challenge authorization",
            Self::UnconfiguredHost => "unconfigured challenge host",
            Self::AlreadyPublished => "challenge host already owned",
            Self::Capacity => "challenge capacity reached",
        })
    }
}

impl std::error::Error for ChallengeError {}

impl Challenges {
    pub fn new(hosts: &[ManagedHost]) -> Result<Self, ChallengeError> {
        let mut allowed = HashMap::with_capacity(hosts.len());
        for host in hosts {
            validate_dns(&host.dns_name).map_err(|_| ChallengeError::InvalidHost)?;
            if allowed
                .insert(Box::<str>::from(host.dns_name.as_str()), None)
                .is_some()
            {
                return Err(ChallengeError::InvalidHost);
            }
        }
        Ok(Self {
            inner: Arc::new(PlMutex::new(Registry {
                hosts: allowed,
                active: 0,
            })),
        })
    }

    pub fn publish(
        &self,
        dns_name: &str,
        token: &str,
        key_authorization: &str,
    ) -> Result<ChallengeLease, ChallengeError> {
        if !valid_token(token) {
            return Err(ChallengeError::InvalidToken);
        }
        let suffix = key_authorization
            .strip_prefix(token)
            .and_then(|value| value.strip_prefix('.'))
            .filter(|value| value.len() == 43 && value.bytes().all(base64url));
        if suffix.is_none() {
            return Err(ChallengeError::InvalidAuthorization);
        }
        let mut registry = self.inner.lock();
        match registry.hosts.get(dns_name) {
            None => return Err(ChallengeError::UnconfiguredHost),
            Some(Some(_)) => return Err(ChallengeError::AlreadyPublished),
            Some(None) => {}
        }
        if registry.active == MAX_CHALLENGES {
            return Err(ChallengeError::Capacity);
        }
        let entry = Arc::new(Entry {
            token: token.into(),
            authorization: Bytes::copy_from_slice(key_authorization.as_bytes()),
        });
        if let Some(slot) = registry.hosts.get_mut(dns_name) {
            *slot = Some(entry.clone());
        }
        registry.active += 1;
        Ok(ChallengeLease {
            challenges: self.clone(),
            host: dns_name.into(),
            entry,
        })
    }

    /// Removes all entries without letting old leases remove later publications.
    pub fn clear(&self) {
        let mut registry = self.inner.lock();
        for slot in registry.hosts.values_mut() {
            *slot = None;
        }
        registry.active = 0;
    }

    pub(crate) fn lookup(&self, host: &str, token: &str) -> Option<Bytes> {
        let registry = self.inner.lock();
        registry
            .hosts
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(host))
            .and_then(|(_, slot)| slot.as_ref())
            .filter(|entry| entry.token.as_ref() == token)
            .map(|entry| entry.authorization.clone())
    }
}

impl Drop for ChallengeLease {
    fn drop(&mut self) {
        let mut registry = self.challenges.inner.lock();
        if let Some(slot) = registry.hosts.get_mut(self.host.as_ref())
            && slot
                .as_ref()
                .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry))
        {
            *slot = None;
            registry.active -= 1;
        }
    }
}

pub(crate) fn valid_token(token: &str) -> bool {
    (22..=256).contains(&token.len()) && token.bytes().all(base64url)
}

fn base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

#[cfg(test)]
mod tests;
