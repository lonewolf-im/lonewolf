// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::time::SystemTime;

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::RoutedStanza;

use crate::ExtensionFuture;
use crate::delivery::HandlerError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveDirection {
    Sent,
    Received,
}

/// An entry ID unique within its owner's archive.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArchiveId(u64);

impl ArchiveId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ArchiveId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub struct ArchiveRequest<'a, A: ChunkAllocator> {
    /// The local account whose archive receives the entry.
    pub owner: &'a AccountKey,
    pub direction: ArchiveDirection,
    /// The recipient of a sent message or the sender of a received one.
    pub peer: JidRef<'a>,
    /// The accepted message before the server adds its stanza ID.
    pub stanza: &'a RoutedStanza<A>,
    pub received_at: SystemTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveOutcome {
    Archived(ArchiveId),
    Skipped,
}

pub type ArchiveFuture<'a> = ExtensionFuture<'a, Result<ArchiveOutcome, HandlerError>>;

pub trait ArchiveHandler<A: ChunkAllocator, S: Storage>: Send + Sync {
    /// Decides whether the request needs a write without storage access.
    fn selects(&self, request: &ArchiveRequest<'_, A>) -> bool;

    /// Writes inside the transaction that the server commits before routing.
    fn archive<'a>(
        &'a self,
        request: ArchiveRequest<'a, A>,
        transaction: &'a mut S::Write,
        scratch: &'a mut Arena<A>,
    ) -> ArchiveFuture<'a>;
}
