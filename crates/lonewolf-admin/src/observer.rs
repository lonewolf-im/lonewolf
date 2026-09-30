// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::future::Future;
use std::pin::Pin;

use lonewolf_storage::account::AccountKey;

pub type ObserverError = Box<dyn Error + Send + Sync>;

/// Follows account changes on behalf of subsystems that keep state per account.
pub trait AccountObserver: Send + Sync {
    /// Runs after the deletion of an account's record has committed, while the service
    /// still holds the account's lifecycle lock so no account with the same JID can be
    /// created until it returns. It also runs when the record was already gone, so a
    /// retry can finish an earlier failure. An error is reported as an internal error.
    fn deleted<'a>(
        &'a self,
        account: &'a AccountKey,
    ) -> Pin<Box<dyn Future<Output = Result<(), ObserverError>> + Send + 'a>>;
}

/// Ignores account changes, for deployments without per-account subsystems.
pub struct NoopObserver;

impl AccountObserver for NoopObserver {
    fn deleted<'a>(
        &'a self,
        _: &'a AccountKey,
    ) -> Pin<Box<dyn Future<Output = Result<(), ObserverError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
