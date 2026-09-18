// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::num::NonZeroU32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScramHash {
    Sha1,
    Sha256,
}

#[derive(Clone)]
pub struct ScramVerifierData<const N: usize> {
    salt: [u8; 16],
    iterations: NonZeroU32,
    stored_key: [u8; N],
    server_key: [u8; N],
}

pub type ScramSha1Verifier = ScramVerifierData<20>;
pub type ScramSha256Verifier = ScramVerifierData<32>;

impl<const N: usize> ScramVerifierData<N> {
    pub fn new(
        salt: [u8; 16],
        iterations: NonZeroU32,
        stored_key: [u8; N],
        server_key: [u8; N],
    ) -> Self {
        Self {
            salt,
            iterations,
            stored_key,
            server_key,
        }
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    pub fn iterations(&self) -> NonZeroU32 {
        self.iterations
    }

    pub fn stored_key(&self) -> &[u8; N] {
        &self.stored_key
    }

    pub fn server_key(&self) -> &[u8; N] {
        &self.server_key
    }
}

impl<const N: usize> fmt::Debug for ScramVerifierData<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScramVerifierData")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub enum ScramVerifier {
    Sha1(ScramSha1Verifier),
    Sha256(ScramSha256Verifier),
}

impl ScramVerifier {
    pub fn hash(&self) -> ScramHash {
        match self {
            Self::Sha1(_) => ScramHash::Sha1,
            Self::Sha256(_) => ScramHash::Sha256,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScramCredentials {
    sha1: Option<ScramSha1Verifier>,
    sha256: Option<ScramSha256Verifier>,
}

impl ScramCredentials {
    pub fn new(verifier: ScramVerifier) -> Self {
        match verifier {
            ScramVerifier::Sha1(verifier) => Self {
                sha1: Some(verifier),
                sha256: None,
            },
            ScramVerifier::Sha256(verifier) => Self {
                sha1: None,
                sha256: Some(verifier),
            },
        }
    }

    pub fn both(sha1: ScramSha1Verifier, sha256: ScramSha256Verifier) -> Self {
        Self {
            sha1: Some(sha1),
            sha256: Some(sha256),
        }
    }

    pub fn sha1(&self) -> Option<&ScramSha1Verifier> {
        self.sha1.as_ref()
    }

    pub fn sha256(&self) -> Option<&ScramSha256Verifier> {
        self.sha256.as_ref()
    }
}
