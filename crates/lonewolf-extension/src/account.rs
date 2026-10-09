// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;

use crate::delivery::{HandlerError, HostLookup};
use crate::{Effects, ExtensionFuture};

pub trait AccountHandler<A: ChunkAllocator, S: Storage>: Send + Sync {
    /// Clears account state inside the deletion transaction and returns post-commit deliveries.
    fn forget_account<'a>(
        &'a self,
        transaction: &'a mut S::Write,
        account: &'a AccountKey,
        hosts: &'a dyn HostLookup,
    ) -> ExtensionFuture<'a, Result<Effects<A>, HandlerError>>;
}
