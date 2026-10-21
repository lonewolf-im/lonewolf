// SPDX-License-Identifier: Apache-2.0

pub mod redb;

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;

use crate::StorageError;
use crate::account::AccountKey;

pub const MAX_VCARD_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VCardQuota {
    pub max_bytes: NonZeroUsize,
}

impl Default for VCardQuota {
    fn default() -> Self {
        Self {
            max_bytes: const { NonZeroUsize::new(262_144).unwrap() },
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct StoredVCard {
    pub xml: Box<str>,
}

impl fmt::Debug for StoredVCard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredVCard")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum VCardError {
    NoAccount,
    QuotaExceeded,
    Storage(StorageError),
}

pub trait VCardReads {
    /// Returns bounded UTF-8 data without checking XML or account existence.
    fn vcard(
        &self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<Option<StoredVCard>, VCardError>> + Send;
}

pub trait VCardWrites {
    /// Requires an account and enforces both byte limits before changing the row.
    fn replace_vcard(
        &mut self,
        owner: &AccountKey,
        xml: &str,
        quota: VCardQuota,
    ) -> impl Future<Output = Result<(), VCardError>> + Send;

    /// Succeeds when the account or row is absent.
    fn delete_vcard(
        &mut self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<(), VCardError>> + Send;
}

impl fmt::Display for VCardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAccount => formatter.write_str("vCard owner has no account"),
            Self::QuotaExceeded => formatter.write_str("vCard exceeds the byte limit"),
            Self::Storage(error) => write!(formatter, "vCard storage failed: {error}"),
        }
    }
}

impl Error for VCardError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NoAccount | Self::QuotaExceeded => None,
            Self::Storage(error) => Some(error),
        }
    }
}

impl From<StorageError> for VCardError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[cfg(test)]
mod tests;
