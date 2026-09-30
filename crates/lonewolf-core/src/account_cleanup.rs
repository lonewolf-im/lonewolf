// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_channel::{Receiver, Sender};
use futures_channel::oneshot;
use lonewolf_admin::{AccountObserver, ObserverError};
use lonewolf_storage::account::{AccountKey, AccountReads, AccountWrites};
use lonewolf_storage::{Storage, WriteTransaction};
use lonewolf_util::arena::ChunkAllocator;

use crate::delivery::RouterDelivery;
use crate::router::RouterHandle;

const QUEUE_CAPACITY: usize = 16;

pub(crate) struct CleanupRequest {
    account: AccountKey,
    done: oneshot::Sender<Result<(), ObserverError>>,
}

/// Forwards account deletions from the admin service to the core runtime, where the
/// extensions can run, and completes the request once they have and the account's
/// sessions are gone.
pub(crate) struct AccountCleanup {
    requests: Sender<CleanupRequest>,
}

pub(crate) fn channel() -> (Arc<AccountCleanup>, Receiver<CleanupRequest>) {
    let (requests, receiver) = async_channel::bounded(QUEUE_CAPACITY);
    (Arc::new(AccountCleanup { requests }), receiver)
}

impl AccountObserver for AccountCleanup {
    fn deleted<'a>(
        &'a self,
        account: &'a AccountKey,
    ) -> Pin<Box<dyn Future<Output = Result<(), ObserverError>> + Send + 'a>> {
        Box::pin(async move {
            let (done, completed) = oneshot::channel();
            self.requests
                .send(CleanupRequest {
                    account: account.clone(),
                    done,
                })
                .await
                .map_err(|_| observer_error("account cleanup is not running"))?;
            completed
                .await
                .map_err(|_| observer_error("account cleanup was interrupted"))?
        })
    }
}

/// Serves cleanup requests until the admin service drops its sender.
pub(crate) async fn run<A: ChunkAllocator + Clone>(
    requests: Receiver<CleanupRequest>,
    router: &RouterHandle<A>,
    allocator: &A,
) {
    while let Ok(request) = requests.recv().await {
        let result = forget(&request.account, router, allocator).await;
        let _ = request.done.send(result);
    }
}

/// Finishes the deletions an earlier run began but did not complete, and returns how
/// many there were.
pub(crate) async fn resume<A: ChunkAllocator + Clone, S: Storage>(
    storage: &S,
    router: &RouterHandle<A>,
    allocator: &A,
) -> Result<usize, ObserverError> {
    let unfinished = storage.begin_read().await?.unfinished_deletions().await?;
    for account in &unfinished {
        forget(account, router, allocator).await?;
        let mut transaction = storage.begin_write().await?;
        transaction.finish_account_deletion(account).await?;
        transaction.commit().await?;
    }
    Ok(unfinished.len())
}

/// Runs every extension's cleanup for the account, then ends its sessions so their
/// disconnect broadcasts to an empty audience.
async fn forget<A: ChunkAllocator + Clone>(
    account: &AccountKey,
    router: &RouterHandle<A>,
    allocator: &A,
) -> Result<(), ObserverError> {
    let delivery = RouterDelivery {
        router,
        allocator,
        session: None,
    };
    let mut result = Ok(());
    for extension in router.extensions(account.domain()) {
        if let Err(error) = extension.account_deleted(account, &delivery).await {
            tracing::error!(
                extension = extension.name(),
                error = ?error,
                "account cleanup failed"
            );
            result = Err(observer_error(
                "an extension failed to clean up the account",
            ));
        }
    }
    if let Err(error) = router.retire_account(account).await {
        tracing::error!(error = ?error, "account session termination failed");
        result = result.and(Err(observer_error(
            "the account's sessions could not be terminated",
        )));
    }
    result
}

fn observer_error(message: &'static str) -> ObserverError {
    Box::from(message)
}
