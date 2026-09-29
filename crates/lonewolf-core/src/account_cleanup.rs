// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_channel::{Receiver, Sender};
use futures_channel::oneshot;
use lonewolf_admin::{AccountObserver, ObserverError};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;

use crate::delivery::RouterDelivery;
use crate::router::RouterHandle;

const QUEUE_CAPACITY: usize = 16;

pub(crate) struct CleanupRequest {
    account: AccountKey,
    done: oneshot::Sender<Result<(), ObserverError>>,
}

/// Forwards pending account deletions from the admin service to the core runtime,
/// where the extensions can run, and completes the request once they have.
pub(crate) struct AccountCleanup {
    requests: Sender<CleanupRequest>,
}

pub(crate) fn channel() -> (Arc<AccountCleanup>, Receiver<CleanupRequest>) {
    let (requests, receiver) = async_channel::bounded(QUEUE_CAPACITY);
    (Arc::new(AccountCleanup { requests }), receiver)
}

impl AccountObserver for AccountCleanup {
    fn deleting<'a>(
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
    let delivery = RouterDelivery {
        router,
        allocator,
        session: None,
    };
    while let Ok(request) = requests.recv().await {
        let mut result = Ok(());
        for extension in router.extensions(request.account.domain()) {
            if let Err(error) = extension
                .account_deleting(&request.account, &delivery)
                .await
            {
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
        let _ = request.done.send(result);
    }
}

fn observer_error(message: &'static str) -> ObserverError {
    Box::from(message)
}
