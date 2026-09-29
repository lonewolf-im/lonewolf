// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::{PendingSubscription, RosterJid};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{PresenceType, RoutedStanza, StanzaErrorCondition};

use crate::delivery::{Delivery, HandlerError};
use crate::order::OrderGuard;
use crate::{ExtensionFuture, RegistrationError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceRequestType {
    Available,
    Unavailable,
    Subscribe,
    Subscribed,
    Unsubscribe,
    Unsubscribed,
}

impl PresenceRequestType {
    pub const ALL: [Self; 6] = [
        Self::Available,
        Self::Unavailable,
        Self::Subscribe,
        Self::Subscribed,
        Self::Unsubscribe,
        Self::Unsubscribed,
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
    /// The resource becomes available.
    Initial,
    /// An available resource changes its presence.
    Update,
    Unavailable,
}

/// An undirected availability change of a bound resource.
pub struct PresenceUpdate<'a> {
    /// The authenticated full JID, independent of the client's `from` attribute.
    pub sender: JidRef<'a>,
    pub transition: PresenceTransition,
}

/// A subscription presence exchanged between two accounts.
pub struct PresenceRequest<'a, A: ChunkAllocator> {
    pub kind: PresenceRequestType,
    /// The authenticated full JID while authorizing, and the bare JID while receiving.
    pub sender: JidRef<'a>,
    pub target: JidRef<'a>,
    /// The stanza with `sender` as its `from` attribute.
    pub stanza: &'a RoutedStanza<A>,
}

/// The recipients of an availability change.
pub struct PresenceAudience {
    _order: Option<OrderGuard>,
    /// Bare JIDs that receive the resource's availability.
    pub subscribers: Vec<RosterJid>,
    /// Stored subscription requests to replay once the resource becomes available.
    pub pending: Vec<PendingSubscription>,
    /// Accounts whose current presence a newly available resource receives.
    pub contacts: Vec<AccountKey>,
}

impl PresenceAudience {
    /// The order guard is released when the audience is dropped, after the server broadcast.
    pub fn new(
        order: Option<OrderGuard>,
        subscribers: Vec<RosterJid>,
        pending: Vec<PendingSubscription>,
        contacts: Vec<AccountKey>,
    ) -> Self {
        Self {
            _order: order,
            subscribers,
            pending,
            contacts,
        }
    }
}

pub type PresenceFuture<'a, T> = ExtensionFuture<'a, Result<T, StanzaErrorCondition>>;
pub type ReceiveFuture<'a> = ExtensionFuture<'a, Result<(), HandlerError>>;

/// Every future runs on the connection worker and can be cancelled on shutdown.
/// A stanza error condition is answered to the request sender.
pub trait PresenceHandler<A: ChunkAllocator>: Send + Sync {
    /// Selects who receives an availability change; the server performs the broadcast.
    fn audience<'a>(
        &'a self,
        _update: PresenceUpdate<'a>,
    ) -> PresenceFuture<'a, Option<PresenceAudience>> {
        Box::pin(async { Ok(None) })
    }

    /// Authorizes a subscription presence on the sender's host before it is routed.
    fn authorize<'a>(&'a self, _request: PresenceRequest<'a, A>) -> PresenceFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Applies a subscription presence on the target's host and performs its deliveries.
    fn receive<'a>(
        &'a self,
        _request: PresenceRequest<'a, A>,
        _delivery: &'a dyn Delivery<A>,
    ) -> ReceiveFuture<'a> {
        Box::pin(async { Err(StanzaErrorCondition::ServiceUnavailable.into()) })
    }
}

pub struct PresenceRegistry<A: ChunkAllocator> {
    handlers: [Option<Arc<dyn PresenceHandler<A>>>; PresenceRequestType::ALL.len()],
}

impl<A: ChunkAllocator> Default for PresenceRegistry<A> {
    fn default() -> Self {
        Self {
            handlers: [const { None }; PresenceRequestType::ALL.len()],
        }
    }
}

impl<A: ChunkAllocator> PresenceRegistry<A> {
    pub(crate) fn register(
        &mut self,
        kind: PresenceRequestType,
        handler: Arc<dyn PresenceHandler<A>>,
    ) -> Result<(), RegistrationError> {
        let slot = &mut self.handlers[kind as usize];
        if slot.is_some() {
            return Err(RegistrationError::DuplicatePresenceRoute(kind));
        }
        *slot = Some(handler);
        Ok(())
    }

    pub fn find(&self, kind: PresenceRequestType) -> Option<&dyn PresenceHandler<A>> {
        self.handlers[kind as usize].as_deref()
    }

    pub(crate) fn registrations(
        &self,
    ) -> impl Iterator<Item = (PresenceRequestType, Arc<dyn PresenceHandler<A>>)> + '_ {
        PresenceRequestType::ALL
            .into_iter()
            .zip(&self.handlers)
            .filter_map(|(kind, handler)| {
                handler.as_ref().map(|handler| (kind, Arc::clone(handler)))
            })
    }
}
