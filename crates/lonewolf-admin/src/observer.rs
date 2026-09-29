// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::future::Future;
use std::pin::Pin;

use lonewolf_storage::account::AccountKey;

pub type ObserverError = Box<dyn Error + Send + Sync>;

/// Follows account changes on behalf of subsystems that keep state per account.
pub trait AccountObserver: Send + Sync {
    /// Runs after an account's record was deleted; the request completes when it returns.
    /// An error is reported to the caller as an internal error, but the deletion stands.
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
