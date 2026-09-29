// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::future::Future;
use std::pin::Pin;

use lonewolf_storage::account::AccountKey;

pub type ObserverError = Box<dyn Error + Send + Sync>;

/// Follows account changes on behalf of subsystems that keep state per account.
pub trait AccountObserver: Send + Sync {
    /// Runs before an existing account's record is deleted, while the record still
    /// blocks a new account with the same JID. An error aborts the deletion and is
    /// reported as an internal error, so a retry runs this again.
    fn deleting<'a>(
        &'a self,
        account: &'a AccountKey,
    ) -> Pin<Box<dyn Future<Output = Result<(), ObserverError>> + Send + 'a>>;
}

/// Ignores account changes, for deployments without per-account subsystems.
pub struct NoopObserver;

impl AccountObserver for NoopObserver {
    fn deleting<'a>(
        &'a self,
        _: &'a AccountKey,
    ) -> Pin<Box<dyn Future<Output = Result<(), ObserverError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
