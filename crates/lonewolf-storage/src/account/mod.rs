// SPDX-License-Identifier: Apache-2.0

//! Separates account metadata from credentials and defines atomic mutations.

pub mod redb;

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;

use lonewolf_auth::scram::{ScramCredentials, ScramHash, ScramVerifier};

use crate::StorageError;

mod key;

pub use key::{AccountKey, AccountKeyError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    pub key: AccountKey,
}

#[derive(Debug)]
pub struct NewAccount {
    pub key: AccountKey,
    pub credentials: ScramCredentials,
}

#[derive(Debug)]
pub enum AccountError {
    AlreadyExists,
    NotFound,
    /// The account's record is gone but its deletion has not finished, so the JID cannot
    /// be reused yet.
    Deleting,
    UnsupportedIterations,
    Storage(StorageError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountState {
    Active,
    /// The record is gone and the deletion's cleanup has not finished.
    Deleting,
    Absent,
}

/// Account reads available on any transaction.
pub trait AccountReads {
    /// Returns `None` if the account is absent.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::Storage`] if storage fails or the stored record is invalid.
    fn account(
        &self,
        key: &AccountKey,
    ) -> impl Future<Output = Result<Option<Account>, AccountError>> + Send;

    /// Returns `None` if the account or the requested hash is absent.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::Storage`] if storage fails or the stored record is invalid.
    fn scram(
        &self,
        key: &AccountKey,
        hash: ScramHash,
    ) -> impl Future<Output = Result<Option<ScramVerifier>, AccountError>> + Send;

    /// Returns up to `limit` accounts in canonical key order, starting after `after`.
    ///
    /// A missing `after` key is a valid cursor: listing resumes at the next stored key.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::Storage`] if storage fails or a stored record or key is
    /// invalid.
    fn accounts_after(
        &self,
        after: Option<&AccountKey>,
        limit: NonZeroUsize,
    ) -> impl Future<Output = Result<Vec<Account>, AccountError>> + Send;

    fn account_state(
        &self,
        key: &AccountKey,
    ) -> impl Future<Output = Result<AccountState, AccountError>> + Send;

    /// The accounts whose deletion began but did not finish, in canonical key order.
    fn unfinished_deletions(
        &self,
    ) -> impl Future<Output = Result<Vec<AccountKey>, AccountError>> + Send;
}

/// Account writes, each taking effect when the transaction commits.
pub trait AccountWrites {
    /// Creates the account and its credentials without replacement.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::AlreadyExists`] if the key exists,
    /// [`AccountError::Deleting`] while a deletion of the key is unfinished,
    /// [`AccountError::UnsupportedIterations`] for a non-policy verifier,
    /// or [`AccountError::Storage`] if storage fails.
    fn create_account(
        &mut self,
        account: NewAccount,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;

    /// Removes the account's record and credentials and marks the key as deleting, so
    /// no account can be created for it until [`Self::finish_account_deletion`].
    ///
    /// Returns whether a record existed. Calling it again for a key that is already
    /// deleting keeps the mark and returns `false`, so a retry can finish an earlier
    /// failure.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::Storage`] if storage fails or the stored record is invalid.
    fn begin_account_deletion(
        &mut self,
        key: &AccountKey,
    ) -> impl Future<Output = Result<bool, AccountError>> + Send;

    /// Clears the deleting mark once every subsystem has forgotten the account.
    fn finish_account_deletion(
        &mut self,
        key: &AccountKey,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;

    /// Replaces all credentials, removing any omitted hashes.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::NotFound`] if the account is absent,
    /// [`AccountError::UnsupportedIterations`] for a non-policy verifier,
    /// or [`AccountError::Storage`] if storage fails.
    fn replace_credentials(
        &mut self,
        key: &AccountKey,
        credentials: ScramCredentials,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
}

impl fmt::Display for AccountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => formatter.write_str("account already exists"),
            Self::NotFound => formatter.write_str("account not found"),
            Self::Deleting => formatter.write_str("account deletion has not finished"),
            Self::UnsupportedIterations => {
                formatter.write_str("SCRAM iteration count is not supported")
            }
            Self::Storage(error) => write!(formatter, "account storage failed: {error}"),
        }
    }
}

impl Error for AccountError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StorageError> for AccountError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[cfg(test)]
mod tests;
