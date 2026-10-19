// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;

use crate::delivery::{HandlerError, HostLookup};
use crate::{Deliver, ExtensionFuture};

pub trait AccountHandler<A: ChunkAllocator, S: Storage>: Send + Sync {
    /// Deletes only this handler's state namespace using the writer's initial snapshot.
    /// The caller opens `before` under exclusive writer admission and delivers after commit under a global barrier.
    fn forget_account<'a>(
        &'a self,
        transaction: &'a mut S::Write,
        account: &'a AccountKey,
        before: Arc<S::Read>,
        hosts: &'a dyn HostLookup,
    ) -> ExtensionFuture<'a, Result<Deliver<A>, HandlerError>>;
}
