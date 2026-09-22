// SPDX-License-Identifier: Apache-2.0

//! Prepares passwords with SASLprep and derives SCRAM verifiers.
//!
//! Derivation blocks the caller for the full configured iteration count.

use std::borrow::Cow;
use std::error::Error;
use std::fmt;
use std::num::NonZeroU32;

use hmac::digest::Output;
use hmac::{EagerHash, Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScramIterations(NonZeroU32);

impl ScramIterations {
    pub const MIN: u32 = 4096;

    /// Enforces the minimum cost for newly derived verifiers.
    ///
    /// # Errors
    ///
    /// Returns [`ScramError::InvalidIterations`] below [`Self::MIN`].
    pub fn new(iterations: u32) -> Result<Self, ScramError> {
        NonZeroU32::new(iterations)
            .filter(|iterations| iterations.get() >= Self::MIN)
            .map(Self)
            .ok_or(ScramError::InvalidIterations)
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

#[derive(Debug)]
pub enum ScramError {
    InvalidIterations,
    InvalidPassword,
    RandomUnavailable(getrandom::Error),
    DerivationFailed,
}

impl fmt::Display for ScramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIterations => "SCRAM iteration count must be at least 4096",
            Self::InvalidPassword => "password is not valid for SCRAM",
            Self::RandomUnavailable(_) => "secure random source is unavailable",
            Self::DerivationFailed => "SCRAM key derivation failed",
        })
    }
}

impl Error for ScramError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RandomUnavailable(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScramHash {
    Sha1,
    Sha256,
}

/// Retains verifier keys without erasing them on drop.
///
/// `Debug` hides all fields.
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
    /// Accepts stored values without validating their keys or minimum cost.
    ///
    /// Use [`ScramVerifier::generate`] to create credentials from a password.
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
    /// Derives a verifier with a fresh cryptographic salt.
    ///
    /// The password must pass SASLprep and remain nonempty. The caller retains
    /// responsibility for erasing its password buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ScramError::InvalidPassword`] for a rejected password,
    /// [`ScramError::RandomUnavailable`] if salt generation fails, or
    /// [`ScramError::DerivationFailed`] if HMAC initialization fails.
    pub fn generate(
        hash: ScramHash,
        password: &str,
        iterations: ScramIterations,
    ) -> Result<Self, ScramError> {
        Self::generate_with_salt_source(hash, password, iterations, getrandom::fill)
    }

    /// Derives a verifier using a caller-supplied salt.
    ///
    /// Password preparation and ownership follow [`Self::generate`]. New
    /// credentials need an independently generated cryptographic salt.
    ///
    /// # Errors
    ///
    /// Returns [`ScramError::InvalidPassword`] for a rejected password or
    /// [`ScramError::DerivationFailed`] if HMAC initialization fails.
    pub fn derive(
        hash: ScramHash,
        password: &str,
        salt: [u8; 16],
        iterations: ScramIterations,
    ) -> Result<Self, ScramError> {
        let password = PreparedPassword::new(password)?;
        Self::derive_prepared(hash, password.0.as_bytes(), salt, iterations)
    }

    fn generate_with_salt_source(
        hash: ScramHash,
        password: &str,
        iterations: ScramIterations,
        fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
    ) -> Result<Self, ScramError> {
        let password = PreparedPassword::new(password)?;
        let mut salt = [0; 16];
        fill(&mut salt).map_err(ScramError::RandomUnavailable)?;
        Self::derive_prepared(hash, password.0.as_bytes(), salt, iterations)
    }

    fn derive_prepared(
        hash: ScramHash,
        password: &[u8],
        salt: [u8; 16],
        iterations: ScramIterations,
    ) -> Result<Self, ScramError> {
        Ok(match hash {
            ScramHash::Sha1 => {
                let (stored_key, server_key) =
                    derive_keys::<Sha1, 20>(password, &salt, iterations)?;
                Self::Sha1(ScramSha1Verifier::new(
                    salt,
                    iterations.0,
                    stored_key,
                    server_key,
                ))
            }
            ScramHash::Sha256 => {
                let (stored_key, server_key) =
                    derive_keys::<Sha256, 32>(password, &salt, iterations)?;
                Self::Sha256(ScramSha256Verifier::new(
                    salt,
                    iterations.0,
                    stored_key,
                    server_key,
                ))
            }
        })
    }

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

struct PreparedPassword<'a>(Cow<'a, str>);

impl<'a> PreparedPassword<'a> {
    fn new(password: &'a str) -> Result<Self, ScramError> {
        // Normalization can hide code points that SASLprep treats as unassigned.
        if password
            .chars()
            .any(stringprep::tables::unassigned_code_point)
        {
            return Err(ScramError::InvalidPassword);
        }
        let prepared =
            Self(stringprep::saslprep(password).map_err(|_| ScramError::InvalidPassword)?);
        if prepared.0.is_empty() {
            return Err(ScramError::InvalidPassword);
        }
        Ok(prepared)
    }
}

impl Drop for PreparedPassword<'_> {
    fn drop(&mut self) {
        if let Cow::Owned(password) = &mut self.0 {
            password.zeroize();
        }
    }
}

fn derive_keys<H: EagerHash, const N: usize>(
    password: &[u8],
    salt: &[u8],
    iterations: ScramIterations,
) -> Result<([u8; N], [u8; N]), ScramError>
where
    [u8; N]: From<Output<H>> + From<Output<Hmac<H>>>,
{
    let mut salted_password = Zeroizing::new([0; N]);
    pbkdf2::pbkdf2_hmac::<H>(password, salt, iterations.get(), salted_password.as_mut());
    let client_key = Zeroizing::new(keyed_hash::<H, N>(&salted_password[..], b"Client Key")?);
    let stored_key = H::digest(&client_key[..]).into();
    let server_key = keyed_hash::<H, N>(&salted_password[..], b"Server Key")?;
    Ok((stored_key, server_key))
}

fn keyed_hash<H: EagerHash, const N: usize>(key: &[u8], data: &[u8]) -> Result<[u8; N], ScramError>
where
    [u8; N]: From<Output<Hmac<H>>>,
{
    let mut hmac = Hmac::<H>::new_from_slice(key).map_err(|_| ScramError::DerivationFailed)?;
    hmac.update(data);
    Ok(hmac.finalize().into_bytes().into())
}

#[cfg(test)]
#[path = "scram_tests.rs"]
mod tests;
