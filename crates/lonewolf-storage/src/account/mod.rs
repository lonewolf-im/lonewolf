// SPDX-License-Identifier: Apache-2.0

//! Separates account metadata from credentials and defines atomic mutations.

pub mod redb;

use std::error::Error;
use std::fmt;
use std::future::Future;

use futures_util::Stream;
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
    UnsupportedIterations,
    Storage(StorageError),
}

pub trait AccountRepository: Send + Sync {
    /// Creates the account and its credentials atomically without replacement.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::AlreadyExists`] if the key exists,
    /// [`AccountError::UnsupportedIterations`] for a non-policy verifier,
    /// or [`AccountError::Storage`] if storage fails.
    fn create(&self, account: NewAccount) -> impl Future<Output = Result<(), AccountError>> + Send;

    /// Returns `None` if the account is absent.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::Storage`] if storage fails.
    fn get(
        &self,
        key: &AccountKey,
    ) -> impl Future<Output = Result<Option<Account>, AccountError>> + Send;

    /// Reads accounts on demand in ascending canonical key order.
    ///
    /// The cursor is exclusive and need not exist. The stream holds one
    /// snapshot from its first read until it ends or is dropped.
    ///
    /// # Errors
    ///
    /// Yields [`AccountError::Storage`] on the first storage failure, then ends.
    fn list(
        &self,
        after: Option<AccountKey>,
    ) -> impl Stream<Item = Result<Account, AccountError>> + Send;

    /// Removes the account and all credentials atomically.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::NotFound`] if the account is absent, or
    /// [`AccountError::Storage`] if storage fails.
    fn delete(&self, key: &AccountKey) -> impl Future<Output = Result<(), AccountError>> + Send;

    /// Returns `None` if the account or the requested hash is absent.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::Storage`] if storage fails.
    fn get_scram(
        &self,
        key: &AccountKey,
        hash: ScramHash,
    ) -> impl Future<Output = Result<Option<ScramVerifier>, AccountError>> + Send;

    /// Replaces all credentials atomically, removing any omitted hashes.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::NotFound`] if the account is absent,
    /// [`AccountError::UnsupportedIterations`] for a non-policy verifier,
    /// or [`AccountError::Storage`] if storage fails.
    fn replace_credentials(
        &self,
        key: &AccountKey,
        credentials: ScramCredentials,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
}

impl fmt::Display for AccountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => formatter.write_str("account already exists"),
            Self::NotFound => formatter.write_str("account not found"),
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
