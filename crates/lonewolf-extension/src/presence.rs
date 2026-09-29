// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use lonewolf_storage::roster::{PendingSubscription, RosterItem, RosterJid, RosterMutation};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{PresenceType, StanzaErrorCondition, StanzaRef};
use smallvec::SmallVec;

use crate::RegistrationError;
use crate::roster::RosterOrder;

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

/// An undirected availability change of a bound resource.
pub struct PresenceUpdate<'a> {
    /// The authenticated full JID, independent of the client's `from` attribute.
    pub sender: JidRef<'a>,
    pub available: bool,
}

/// A subscription presence exchanged between two accounts.
pub struct PresenceRequest<'a, A: ChunkAllocator> {
    pub kind: PresenceRequestType,
    /// The authenticated full JID while authorizing, and the bare JID while receiving.
    pub sender: JidRef<'a>,
    pub target: JidRef<'a>,
    /// The stanza with `sender` as its `from` attribute.
    pub stanza: StanzaRef<'a, Arena<A>>,
}

/// The recipients of an availability change.
pub struct PresenceBroadcast {
    _order: Option<RosterOrder>,
    pub subscribers: Vec<RosterJid>,
    /// Stored subscription requests to replay once the resource becomes available.
    pub pending: Vec<PendingSubscription>,
}

impl PresenceBroadcast {
    /// The order guard is released when the broadcast is dropped.
    pub fn new(
        order: Option<RosterOrder>,
        subscribers: Vec<RosterJid>,
        pending: Vec<PendingSubscription>,
    ) -> Self {
        Self {
            _order: order,
            subscribers,
            pending,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Party {
    Sender,
    Target,
}

/// One delivery the server performs after a subscription presence was applied.
pub enum SubscriptionStep {
    /// Deliver the presence to the target's available resources.
    DeliverToAvailable,
    /// Deliver the presence to the target's roster-interested resources.
    DeliverToInterested,
    /// Deliver a `subscribed` reply to the sender's roster-interested resources.
    ApproveSender,
    PushRoster(Party, RosterMutation<RosterItem>),
    DeliverCurrentPresence {
        from: Party,
        to: Party,
    },
    DeliverUnavailablePresence {
        from: Party,
        to: Party,
    },
}

pub type SubscriptionSteps = SmallVec<[SubscriptionStep; 4]>;

/// The deliveries a received subscription presence requires, in protocol order.
#[derive(Default)]
pub struct SubscriptionEffect {
    order: Option<RosterOrder>,
    steps: SubscriptionSteps,
}

impl SubscriptionEffect {
    /// The order guard must outlive every step.
    pub fn new(order: Option<RosterOrder>, steps: SubscriptionSteps) -> Self {
        Self { order, steps }
    }

    pub fn into_parts(self) -> (Option<RosterOrder>, SubscriptionSteps) {
        (self.order, self.steps)
    }
}

pub type PresenceFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, StanzaErrorCondition>> + 'a>>;

/// Every future runs on the connection worker and can be cancelled on shutdown.
/// An error sends a stanza error to the request sender.
pub trait PresenceHandler<A: ChunkAllocator>: Send + Sync {
    /// Selects the recipients of an availability change; `None` broadcasts nothing.
    fn update<'a>(
        &'a self,
        _update: PresenceUpdate<'a>,
    ) -> PresenceFuture<'a, Option<PresenceBroadcast>> {
        Box::pin(async { Ok(None) })
    }

    /// Authorizes a subscription presence on the sender's host before it is routed.
    fn authorize<'a>(&'a self, _request: PresenceRequest<'a, A>) -> PresenceFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Applies a subscription presence on the target's host.
    fn receive<'a>(
        &'a self,
        _request: PresenceRequest<'a, A>,
    ) -> PresenceFuture<'a, SubscriptionEffect> {
        Box::pin(async { Err(StanzaErrorCondition::ServiceUnavailable) })
    }
}

pub struct PresenceRegistration<A: ChunkAllocator> {
    kind: PresenceRequestType,
    handler: Arc<dyn PresenceHandler<A>>,
}

impl<A: ChunkAllocator> PresenceRegistration<A> {
    pub fn new(kind: PresenceRequestType, handler: Arc<dyn PresenceHandler<A>>) -> Self {
        Self { kind, handler }
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
    pub fn register(
        &mut self,
        registration: PresenceRegistration<A>,
    ) -> Result<(), RegistrationError> {
        let slot = &mut self.handlers[registration.kind as usize];
        if slot.is_some() {
            return Err(RegistrationError::DuplicatePresenceRoute(registration.kind));
        }
        *slot = Some(registration.handler);
        Ok(())
    }

    pub fn find(&self, kind: PresenceRequestType) -> Option<&dyn PresenceHandler<A>> {
        self.handlers[kind as usize].as_deref()
    }

    pub(crate) fn registrations(&self) -> impl Iterator<Item = PresenceRegistration<A>> + '_ {
        PresenceRequestType::ALL
            .into_iter()
            .zip(&self.handlers)
            .filter_map(|(kind, handler)| {
                handler
                    .as_ref()
                    .map(|handler| PresenceRegistration::new(kind, Arc::clone(handler)))
            })
    }
}
