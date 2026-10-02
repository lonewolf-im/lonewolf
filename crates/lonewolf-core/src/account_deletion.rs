// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_channel::{Receiver, Sender};
use futures_channel::oneshot;
use lonewolf_admin::{AccountDeleter, DeleterError};
use lonewolf_storage::account::{AccountError, AccountKey, AccountWrites};
use lonewolf_storage::offline::{OfflineError, OfflineWrites};
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::ChunkAllocator;

use crate::delivery::RouterDelivery;
use crate::router::RouterHandle;

const QUEUE_CAPACITY: usize = 16;

pub(crate) struct DeletionRequest {
    account: AccountKey,
    done: oneshot::Sender<Result<bool, DeleterError>>,
}

/// Deletion completes after commit, notifications, and session retirement.
pub(crate) struct AccountDeletion {
    requests: Sender<DeletionRequest>,
}

pub(crate) fn channel() -> (Arc<AccountDeletion>, Receiver<DeletionRequest>) {
    let (requests, receiver) = async_channel::bounded(QUEUE_CAPACITY);
    (Arc::new(AccountDeletion { requests }), receiver)
}

impl AccountDeleter for AccountDeletion {
    fn delete<'a>(
        &'a self,
        account: &'a AccountKey,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DeleterError>> + Send + 'a>> {
        Box::pin(async move {
            let (done, completed) = oneshot::channel();
            self.requests
                .send(DeletionRequest {
                    account: account.clone(),
                    done,
                })
                .await
                .map_err(|_| deleter_error("account deletion is not running"))?;
            completed
                .await
                .map_err(|_| deleter_error("account deletion was interrupted"))?
        })
    }
}

pub(crate) async fn run<A: ChunkAllocator + Clone>(
    requests: Receiver<DeletionRequest>,
    storage: &RedbStorage,
    router: &RouterHandle<A>,
    allocator: &A,
) {
    while let Ok(request) = requests.recv().await {
        let result = delete(&request.account, storage, router, allocator).await;
        let _ = request.done.send(result);
    }
}

/// Notification and retirement failures do not fail a committed deletion.
async fn delete<A: ChunkAllocator + Clone>(
    account: &AccountKey,
    storage: &RedbStorage,
    router: &RouterHandle<A>,
    allocator: &A,
) -> Result<bool, DeleterError> {
    let extensions = router.extensions(account.domain());
    let delivery = RouterDelivery::new(router, allocator, None);
    let mut transaction = storage.begin_write().await?;
    let existed = match transaction.delete_account(account).await {
        Ok(()) => true,
        Err(AccountError::NotFound) => false,
        Err(error) => return Err(error.into()),
    };
    let mut accounts = vec![account.clone()];
    let mut deliveries = Vec::with_capacity(extensions.len());
    for extension in extensions {
        let effects = extension
            .forget_account(&mut transaction, account, &delivery)
            .await
            .map_err(|error| {
                tracing::error!(
                    extension = extension.name(),
                    error = ?error,
                    "account deletion aborted"
                );
                deleter_error("an extension could not forget the account")
            })?;
        accounts.extend(effects.accounts);
        deliveries.push((extension.name(), effects.deliver));
    }
    transaction
        .clear_offline_messages(account)
        .await
        .map_err(|error| match error {
            OfflineError::Storage(error) => DeleterError::from(error),
            error => DeleterError::Other(Box::new(error)),
        })?;
    let ((), mut ticket) = router.order().fix(accounts, transaction.commit()).await?;
    tracing::info!(
        operation = "cleanup",
        outcome = "committed",
        "offline account state cleared"
    );
    ticket.turn().await;
    for (extension, deliver) in deliveries {
        if let Err(error) = deliver(&delivery).await {
            tracing::error!(
                extension,
                error = ?error,
                "account deletion notifications failed"
            );
        }
    }
    // Sessions end after the commit so their disconnect broadcasts to an empty audience.
    if let Err(error) = router.retire_account(account).await {
        tracing::error!(error = ?error, "account session termination failed");
    }
    drop(ticket);
    Ok(existed)
}

fn deleter_error(message: &'static str) -> DeleterError {
    DeleterError::Other(Box::from(message))
}
