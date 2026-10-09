// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::{OfflineSequence, StoredMessage};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaErrorCondition};

use crate::ExtensionFuture;
use crate::delivery::HandlerError;
use crate::presence::PresenceFuture;

pub struct UndeliverableMessage<'a, A: ChunkAllocator> {
    pub recipient: &'a AccountKey,
    /// The `from` address is the authenticated sender.
    pub stanza: &'a RoutedStanza<A>,
    /// The server receive time determines the delay stamp.
    pub received_at: SystemTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOutcome {
    Stored(OfflineSequence),
    /// The sender receives no reply.
    Discarded,
}

pub struct Backlog {
    /// Messages are in sequence order.
    pub messages: Vec<StoredMessage>,
    /// The highest sequence in `messages`.
    pub through: OfflineSequence,
}

pub type StoreFuture<'a> = ExtensionFuture<'a, Result<StoreOutcome, HandlerError>>;

/// Futures run on the connection worker and can be cancelled on shutdown.
pub trait MessageHandler<A: ChunkAllocator, S: Storage>: Send + Sync {
    /// Stores a message when the recipient has no resource with non-negative priority.
    fn store<'a>(
        &'a self,
        _message: UndeliverableMessage<'a, A>,
        _transaction: &'a mut S::Write,
        _scratch: &'a mut Arena<A>,
    ) -> StoreFuture<'a> {
        Box::pin(async { Err(StanzaErrorCondition::ServiceUnavailable.into()) })
    }

    /// Reads messages from the availability snapshot for a newly eligible resource.
    fn backlog<'a>(
        &'a self,
        _account: &'a AccountKey,
        _transaction: &'a S::Read,
    ) -> PresenceFuture<'a, Option<Backlog>> {
        Box::pin(async { Ok(None) })
    }

    /// Removes messages through `through` after a session delivers the replayed copies.
    fn acknowledge<'a>(
        &'a self,
        _account: &'a AccountKey,
        _through: OfflineSequence,
        _transaction: &'a mut S::Write,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async { Ok(()) })
    }

    /// Removes a stored message after a session delivers its live copy; the row may already be gone.
    fn acknowledge_one<'a>(
        &'a self,
        _account: &'a AccountKey,
        _sequence: OfflineSequence,
        _transaction: &'a mut S::Write,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async { Ok(()) })
    }
}
