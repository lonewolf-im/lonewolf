// SPDX-License-Identifier: Apache-2.0

pub mod redb;

use std::error::Error;
use std::fmt;
use std::future::Future;

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
    Storage(StorageError),
}

pub trait AccountRepository {
    fn create(&self, account: NewAccount) -> impl Future<Output = Result<(), AccountError>>;

    fn get(&self, key: &AccountKey) -> impl Future<Output = Result<Option<Account>, AccountError>>;

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
