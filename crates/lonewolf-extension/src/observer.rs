// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::RoutedStanza;

use crate::archive::ArchiveId;
use crate::delivery::{Delivery, DeliveryFuture, SessionId};
use crate::presence::PresenceTransition;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageRole {
    Sent,
    Received,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageOutcome {
    /// A local session mailbox admitted the message.
    Routed,
    /// The offline fallback stored the message.
    Stored,
    /// A service accepted the message.
    Forwarded,
    /// The sender received an error.
    Rejected,
    /// The message was discarded without a reply.
    Discarded,
}

pub struct MessageEvent<'a, A: ChunkAllocator> {
    pub account: &'a AccountKey,
    pub role: MessageRole,
    /// The message as routed, including its stanza ID.
    pub stanza: &'a RoutedStanza<A>,
    pub outcome: MessageOutcome,
    /// This account's archive entry for the message.
    pub archived: Option<ArchiveId>,
    /// Sessions of `account` that already have the message: its sender and routed recipients.
    pub holders: &'a [SessionId],
    /// The error queued for the local sender when the outcome is `Rejected`.
    pub rejection: Option<&'a RoutedStanza<A>>,
}

impl<A: ChunkAllocator> Copy for MessageEvent<'_, A> {}

impl<A: ChunkAllocator> Clone for MessageEvent<'_, A> {
    fn clone(&self) -> Self {
        *self
    }
}

pub trait MessageObserver<A: ChunkAllocator, S: Storage>: Send + Sync {
    /// Runs after the outcome is known and cannot change the message.
    /// Read transactions must end before a delivery starts.
    fn observe<'a>(
        &'a self,
        event: MessageEvent<'a, A>,
        storage: &'a S,
        delivery: &'a dyn Delivery<A>,
    ) -> DeliveryFuture<'a>;
}

pub enum SessionEvent<'a, A: ChunkAllocator> {
    /// The resource is bound and can receive stanzas.
    Bound,
    Presence {
        transition: PresenceTransition,
        stanza: &'a RoutedStanza<A>,
    },
    Ended,
}

impl<A: ChunkAllocator> Copy for SessionEvent<'_, A> {}

impl<A: ChunkAllocator> Clone for SessionEvent<'_, A> {
    fn clone(&self) -> Self {
        *self
    }
}

pub struct SessionChange<'a, A: ChunkAllocator> {
    /// The resource's full JID.
    pub session: JidRef<'a>,
    pub event: SessionEvent<'a, A>,
}

impl<A: ChunkAllocator> Copy for SessionChange<'_, A> {}

impl<A: ChunkAllocator> Clone for SessionChange<'_, A> {
    fn clone(&self) -> Self {
        *self
    }
}

pub trait SessionObserver<A: ChunkAllocator, S: Storage>: Send + Sync {
    /// Runs after the change and cannot change the session.
    fn session_changed<'a>(
        &'a self,
        change: SessionChange<'a, A>,
        storage: &'a S,
        delivery: &'a dyn Delivery<A>,
    ) -> DeliveryFuture<'a>;
}
