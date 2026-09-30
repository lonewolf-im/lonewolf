// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_channel::{Receiver, Sender};
use futures_channel::oneshot;
use lonewolf_admin::{AccountDeleter, DeleterError};
use lonewolf_storage::account::{AccountError, AccountKey, AccountWrites};
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::ChunkAllocator;

use crate::delivery::RouterDelivery;
use crate::router::RouterHandle;

const QUEUE_CAPACITY: usize = 16;

pub(crate) struct DeletionRequest {
    account: AccountKey,
    done: oneshot::Sender<Result<bool, DeleterError>>,
}

/// Forwards account deletions from the admin service to the core runtime, where the
/// extensions take part, and completes each request once its transaction committed,
/// its notifications went out, and the account's sessions are gone.
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

/// Serves deletion requests until the admin service drops its sender.
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

/// Removes the account's record and every extension's state for it in one transaction,
/// then delivers what the extensions returned, in order with every other delivery to
/// the accounts they named, and ends the account's sessions.
///
/// Only the transaction can fail the deletion. Once it committed the account is gone,
/// so a failed notification or session termination is logged and the deletion still
/// reports success.
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
    let ((), mut ticket) = router.order().fix(accounts, transaction.commit()).await?;
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
