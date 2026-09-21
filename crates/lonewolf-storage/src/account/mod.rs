// SPDX-License-Identifier: Apache-2.0

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountPageSize(usize);

impl AccountPageSize {
    pub const MAX: usize = 500;

    /// Accepts account counts from 1 through 500.
    pub fn new(size: usize) -> Option<Self> {
        (1..=Self::MAX).contains(&size).then_some(Self(size))
    }

    pub fn get(self) -> usize {
        self.0
    }
}

#[derive(Debug)]
pub enum AccountError {
    AlreadyExists,
    NotFound,
    Storage(StorageError),
}

pub trait AccountRepository {
    fn create(&self, account: NewAccount) -> impl Future<Output = Result<(), AccountError>>;

    fn get(&self, key: &AccountKey) -> impl Future<Output = Result<Option<Account>, AccountError>>;

    /// Yields accounts in ascending canonical-key order, strictly after the cursor.
    /// The cursor need not exist. Buffers at most one batch, fetched on demand.
    /// Releases each snapshot before yielding. Batches can observe concurrent changes.
    /// Yields the first error and then ends.
    fn list(
        &self,
        after: Option<AccountKey>,
        batch_size: AccountPageSize,
    ) -> impl Stream<Item = Result<Account, AccountError>>;

    /// Removes the account and all credentials atomically. Fails if the account is absent.
    fn delete(&self, key: &AccountKey) -> impl Future<Output = Result<(), AccountError>>;

    fn get_scram(
        &self,
        key: &AccountKey,
        hash: ScramHash,
    ) -> impl Future<Output = Result<Option<ScramVerifier>, AccountError>>;

    fn replace_credentials(
        &self,
        key: &AccountKey,
        credentials: ScramCredentials,
    ) -> impl Future<Output = Result<(), AccountError>>;
}

impl fmt::Display for AccountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => formatter.write_str("account already exists"),
            Self::NotFound => formatter.write_str("account not found"),
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
