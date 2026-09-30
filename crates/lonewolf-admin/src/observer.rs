// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use lonewolf_storage::account::{AccountError, AccountKey, AccountWrites};
use lonewolf_storage::{Storage, StorageError, WriteTransaction};

/// Why a deletion failed, kept apart so callers can tell an unavailable store and an
/// uncertain commit from every other failure.
#[derive(Debug)]
pub enum DeleterError {
    Storage(StorageError),
    /// A failure before the deletion committed; nothing changed.
    Other(Box<dyn Error + Send + Sync>),
}

impl fmt::Display for DeleterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "account deletion storage failed: {error}"),
            Self::Other(error) => write!(formatter, "account deletion failed: {error}"),
        }
    }
}

impl Error for DeleterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::Other(error) => Some(error.as_ref()),
        }
    }
}

impl From<StorageError> for DeleterError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<AccountError> for DeleterError {
    fn from(error: AccountError) -> Self {
        match error {
            AccountError::Storage(error) => Self::Storage(error),
            error => Self::Other(Box::new(error)),
        }
    }
}

/// Deletes accounts on behalf of every subsystem that keeps state per account, so the
/// record and that state go together.
pub trait AccountDeleter: Send + Sync {
    /// Removes the account's record and every trace the server keeps of it, and
    /// returns whether a record existed. Nothing changes when it fails, so a retry is
    /// always safe. An error is logged, so it must not name the account.
    fn delete<'a>(
        &'a self,
        account: &'a AccountKey,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DeleterError>> + Send + 'a>>;
}

/// Removes only the account record, for deployments without per-account subsystems.
pub struct RecordDeleter<S> {
    storage: S,
}

impl<S: Storage> RecordDeleter<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }
}

impl<S: Storage> AccountDeleter for RecordDeleter<S> {
    fn delete<'a>(
        &'a self,
        account: &'a AccountKey,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DeleterError>> + Send + 'a>> {
        Box::pin(async move {
            let mut transaction = self.storage.begin_write().await?;
            let existed = match transaction.delete_account(account).await {
                Ok(()) => true,
                Err(AccountError::NotFound) => false,
                Err(error) => return Err(error.into()),
            };
            transaction.commit().await?;
            Ok(existed)
        })
    }
}
