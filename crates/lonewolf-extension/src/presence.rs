// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::{PendingSubscription, RosterJid};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{PresenceType, RoutedStanza, StanzaErrorCondition};

use crate::delivery::{HandlerError, HostLookup};
use crate::{Effects, ExtensionFuture, RegistrationError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceRequestType {
    Available,
    Unavailable,
    Subscribe,
    Subscribed,
    Unsubscribe,
    Unsubscribed,
    Probe,
}

impl PresenceRequestType {
    pub const ALL: [Self; 7] = [
        Self::Available,
        Self::Unavailable,
        Self::Subscribe,
        Self::Subscribed,
        Self::Unsubscribe,
        Self::Unsubscribed,
        Self::Probe,
    ];

    pub const fn from_subscription_stanza(value: PresenceType) -> Option<Self> {
        match value {
            PresenceType::Subscribe => Some(Self::Subscribe),
            PresenceType::Subscribed => Some(Self::Subscribed),
            PresenceType::Unsubscribe => Some(Self::Unsubscribe),
            PresenceType::Unsubscribed => Some(Self::Unsubscribed),
            PresenceType::Available
            | PresenceType::Unavailable
            | PresenceType::Probe
            | PresenceType::Error => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceTransition {
    Initial,
    Update,
    Unavailable,
}

pub struct PresenceUpdate<'a> {
    /// The authenticated full JID, independent of the client's `from` attribute.
    pub sender: JidRef<'a>,
    pub transition: PresenceTransition,
}

pub struct PresenceRequest<'a, A: ChunkAllocator> {
    pub kind: PresenceRequestType,
    /// The authenticated full JID while authorizing, and the bare JID while receiving.
    pub sender: JidRef<'a>,
    pub target: JidRef<'a>,
    pub stanza: &'a RoutedStanza<A>,
}

pub struct PresenceAudience {
    /// Bare JIDs that receive the resource's availability.
    pub subscribers: Vec<RosterJid>,
    /// Stored subscription requests to replay once the resource becomes available.
    pub pending: Vec<PendingSubscription>,
    /// Accounts whose current presence a newly available resource receives.
    pub contacts: Vec<AccountKey>,
}

pub type PresenceFuture<'a, T> = ExtensionFuture<'a, Result<T, HandlerError>>;
pub type ReceiveFuture<'a, A> = ExtensionFuture<'a, Result<Effects<A>, HandlerError>>;

pub trait PresenceHandler<A: ChunkAllocator, S: Storage>: Send + Sync {
    fn visibility<'a>(
        &'a self,
        _owner: &'a AccountKey,
        _observer: JidRef<'a>,
        _transaction: &'a S::Read,
    ) -> PresenceFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    /// Selects who receives an availability change from one consistent snapshot; the
    /// server performs the broadcast in order with the sender's other deliveries.
    fn audience<'a>(
        &'a self,
        _update: PresenceUpdate<'a>,
        _transaction: &'a S::Read,
    ) -> PresenceFuture<'a, Option<PresenceAudience>> {
        Box::pin(async { Ok(None) })
    }

    /// Authorizes a subscription presence on the sender's host before it is routed.
    fn authorize<'a>(&'a self, _request: PresenceRequest<'a, A>) -> PresenceFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Applies a subscription presence on the target's host inside the transaction and
    /// returns what to deliver once it commits.
    fn receive<'a>(
        &'a self,
        _request: PresenceRequest<'a, A>,
        _transaction: &'a mut S::Write,
        _hosts: &'a dyn HostLookup,
    ) -> ReceiveFuture<'a, A> {
        Box::pin(async { Err(StanzaErrorCondition::ServiceUnavailable.into()) })
    }
}

pub struct PresenceRegistry<A: ChunkAllocator, S: Storage> {
    handlers: [Option<Arc<dyn PresenceHandler<A, S>>>; PresenceRequestType::ALL.len()],
}

impl<A: ChunkAllocator, S: Storage> Default for PresenceRegistry<A, S> {
    fn default() -> Self {
        Self {
            handlers: [const { None }; PresenceRequestType::ALL.len()],
        }
    }
}

impl<A: ChunkAllocator, S: Storage> PresenceRegistry<A, S> {
    pub(crate) fn register(
        &mut self,
        kind: PresenceRequestType,
        handler: Arc<dyn PresenceHandler<A, S>>,
    ) -> Result<(), RegistrationError> {
        let slot = &mut self.handlers[kind as usize];
        if slot.is_some() {
            return Err(RegistrationError::DuplicatePresenceRoute(kind));
        }
        *slot = Some(handler);
        Ok(())
    }

    pub fn find(&self, kind: PresenceRequestType) -> Option<&dyn PresenceHandler<A, S>> {
        self.handlers[kind as usize].as_deref()
    }
}
