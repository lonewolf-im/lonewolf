// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::message::MessageHandler;
use lonewolf_storage::RedbStorage;
use lonewolf_storage::offline::OfflineSequence;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::Stanza;

use super::presence::{AvailabilityHandlers, PresenceOutcome};
use super::{Outbox, OutboxWriter, Output, ReplayPolicy};
use crate::router::{RoutedStanza, RouterHandle};

/// Counts stanzas the session hands to its writer, starting at one.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct OutputSequence(u64);

impl OutputSequence {
    pub(super) fn next(self) -> Self {
        Self(self.0 + 1)
    }

    #[cfg(test)]
    pub(super) const fn new(value: u64) -> Self {
        Self(value)
    }
}

pub(super) enum Outgoing<A: ChunkAllocator> {
    Routed(RoutedStanza<A>),
    Owned { stanza: Stanza, arena: Arena<A> },
}

/// The writer must flush the corresponding output sequence before storage can release the copy.
pub(super) enum Release<A: ChunkAllocator> {
    Message {
        handler: Arc<dyn MessageHandler<A, RedbStorage>>,
        sequence: OfflineSequence,
    },
    Backlog {
        handler: Arc<dyn MessageHandler<A, RedbStorage>>,
        through: OfflineSequence,
    },
    BacklogMessages {
        handler: Arc<dyn MessageHandler<A, RedbStorage>>,
        sequences: Vec<OfflineSequence>,
    },
}

impl<A: ChunkAllocator + Clone, W: OutboxWriter<A>> Outbox<'_, A, W> {
    pub(super) fn queue_presence(
        &mut self,
        outcome: PresenceOutcome<A>,
        handlers: AvailabilityHandlers<A>,
        router: &RouterHandle<A>,
        resource: &str,
    ) {
        // The router's mailbox cut keeps earlier sibling updates ahead of this echo.
        self.delivered(outcome.preceding);
        self.routed(outcome.siblings);
        self.push(Output::Routed(outcome.echo));
        self.queue
            .extend(outcome.replay.into_iter().map(Output::Presence));
        if let (Some(page), Some(handler)) = (outcome.requests, handlers.presence)
            && (!page.is_empty() || !page.is_complete())
        {
            self.push(Output::Requests {
                page,
                resource: resource.into(),
                handler,
                router: router.clone(),
            });
        }
        if let Some(backlog) = outcome.backlog
            && let Some(handler) = handlers.messages
        {
            let policy = router.has_explicit_policy().then(|| ReplayPolicy {
                router: router.clone(),
                resource: resource.into(),
            });
            self.push(Output::Offline {
                backlog,
                handler,
                policy,
            });
        }
    }
}
