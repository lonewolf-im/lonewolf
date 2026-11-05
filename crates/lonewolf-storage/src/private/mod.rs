// SPDX-License-Identifier: Apache-2.0

pub mod redb;

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;

use crate::StorageError;
use crate::account::AccountKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateXmlQuota {
    pub max_items: NonZeroUsize,
    /// Counts the stored XML bytes of all elements of one account.
    pub max_bytes: NonZeroUsize,
}

impl Default for PrivateXmlQuota {
    fn default() -> Self {
        Self {
            max_items: const { NonZeroUsize::new(50).unwrap() },
            max_bytes: const { NonZeroUsize::new(2_097_152).unwrap() },
        }
    }
}

#[derive(Clone, Copy)]
pub struct PrivateXmlChange<'a> {
    pub namespace: &'a str,
    pub name: &'a str,
    /// `None` removes the element.
    pub xml: Option<&'a str>,
}

impl fmt::Debug for PrivateXmlChange<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateXmlChange")
            .finish_non_exhaustive()
    }
}

#[derive(Eq, PartialEq)]
pub struct StoredPrivateXml {
    pub xml: Box<str>,
}

impl fmt::Debug for StoredPrivateXml {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredPrivateXml")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum PrivateXmlError {
    NoAccount,
    QuotaExceeded,
    Storage(StorageError),
}

pub trait PrivateXmlReads {
    /// Returns UTF-8 data without checking XML, account existence, or current quotas.
    fn private_xml(
        &self,
        owner: &AccountKey,
        namespace: &str,
        name: &str,
    ) -> impl Future<Output = Result<Option<StoredPrivateXml>, PrivateXmlError>> + Send;
}

/// Drop the transaction after a [`PrivateXmlError::Storage`] error to abort every change.
pub trait PrivateXmlWrites {
    /// Applies changes in order, so the last change to an element wins.
    ///
    /// Requires an account; element count and byte total must each fit the quota or not grow.
    /// `NoAccount` and `QuotaExceeded` leave the transaction unchanged and committable.
    fn update_private_xml(
        &mut self,
        owner: &AccountKey,
        changes: &[PrivateXmlChange<'_>],
        quota: PrivateXmlQuota,
    ) -> impl Future<Output = Result<(), PrivateXmlError>> + Send;

    /// Removes every element without reading it and succeeds when nothing is stored.
    fn clear_private_xml(
        &mut self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<(), PrivateXmlError>> + Send;
}

impl fmt::Display for PrivateXmlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAccount => formatter.write_str("private XML owner has no account"),
            Self::QuotaExceeded => formatter.write_str("private XML exceeds the account quota"),
            Self::Storage(error) => write!(formatter, "private XML storage failed: {error}"),
        }
    }
}

impl Error for PrivateXmlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NoAccount | Self::QuotaExceeded => None,
            Self::Storage(error) => Some(error),
        }
    }
}

impl From<StorageError> for PrivateXmlError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[cfg(test)]
mod tests;
