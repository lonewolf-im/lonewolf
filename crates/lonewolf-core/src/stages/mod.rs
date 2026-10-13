// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::RedbStorage;
use lonewolf_storage::account::AccountKeyError;
use lonewolf_util::arena::{ArenaError, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::JidError;
use lonewolf_xmpp::stanza::BuildError;

use crate::delivery::WorkHandle;
use crate::router::RouterHandle;

pub(crate) mod message;
pub(crate) mod policy;
pub(crate) mod service;

pub(crate) struct Stage<'s, A: ChunkAllocator> {
    pub(crate) router: &'s RouterHandle<A>,
    pub(crate) storage: &'s RedbStorage,
    pub(crate) allocator: &'s A,
    pub(crate) work: &'s WorkHandle,
}

/// The stage could not finish, so the caller ends the stream it serves.
#[derive(Debug)]
pub(crate) struct StageFailure;

impl From<HandleError> for StageFailure {
    fn from(_: HandleError) -> Self {
        Self
    }
}

impl From<ArenaError> for StageFailure {
    fn from(_: ArenaError) -> Self {
        Self
    }
}

impl From<BuildError> for StageFailure {
    fn from(_: BuildError) -> Self {
        Self
    }
}

impl From<JidError> for StageFailure {
    fn from(_: JidError) -> Self {
        Self
    }
}

impl From<AccountKeyError> for StageFailure {
    fn from(_: AccountKeyError) -> Self {
        Self
    }
}
