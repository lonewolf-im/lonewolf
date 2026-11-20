// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::{OfflinePage, OfflineSequence};
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
    /// The recipient has no account; ingress decides whether to reply.
    NoRecipient,
}

pub struct Backlog {
    /// The highest stored sequence in the availability snapshot.
    pub through: OfflineSequence,
    /// The first page; later pages come from [`MessageHandler::backlog_page`].
    pub page: OfflinePage,
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

    /// Reads the first backlog page from the availability snapshot for a newly eligible resource.
    fn backlog<'a>(
        &'a self,
        _account: &'a AccountKey,
        _transaction: &'a S::Read,
    ) -> PresenceFuture<'a, Option<Backlog>> {
        Box::pin(async { Ok(None) })
    }

    /// Refills `page` with stored messages after `after` and up to `through`.
    fn backlog_page<'a>(
        &'a self,
        _account: &'a AccountKey,
        _transaction: &'a S::Read,
        _after: OfflineSequence,
        _through: OfflineSequence,
        _page: OfflinePage,
    ) -> PresenceFuture<'a, OfflinePage> {
        Box::pin(async { Ok(OfflinePage::new()) })
    }

    /// Checks whether a preloaded message still exists in the current replay snapshot.
    fn replay_contains<'a>(
        &'a self,
        account: &'a AccountKey,
        sequence: OfflineSequence,
        transaction: &'a S::Read,
    ) -> PresenceFuture<'a, bool> {
        Box::pin(async move {
            if let Some(after) = sequence.get().checked_sub(1) {
                let page = self
                    .backlog_page(
                        account,
                        transaction,
                        OfflineSequence::new(after),
                        sequence,
                        OfflinePage::new(),
                    )
                    .await?;
                if page.iter().any(|(entry, _)| entry.sequence == sequence) {
                    return Ok(true);
                }
            }
            // Single-page handlers can rely on the default empty range reader.
            Ok(self
                .backlog(account, transaction)
                .await?
                .is_some_and(|backlog| {
                    backlog
                        .page
                        .iter()
                        .any(|(entry, _)| entry.sequence == sequence)
                }))
        })
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
