// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use lonewolf_storage::roster::PendingSubscription;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{PresenceType, StanzaErrorCondition, StanzaRef};

use crate::RegistrationError;
use crate::roster::{RosterOrder, RosterPush};

/// The direction relative to the local account.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PresenceDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PresenceRequestType {
    Available,
    Subscribe,
    Subscribed,
    Unsubscribe,
    Unsubscribed,
}

impl PresenceRequestType {
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PresenceRoute {
    pub direction: PresenceDirection,
    pub kind: PresenceRequestType,
}

pub struct PresenceRequest<'a, A: ChunkAllocator> {
    pub direction: PresenceDirection,
    pub kind: PresenceRequestType,
    /// The authenticated bound JID, independent of the client's `from` attribute.
    pub sender: JidRef<'a>,
    pub target: JidRef<'a>,
    /// The complete stanza with `sender` as its `from` attribute.
    pub stanza: StanzaRef<'a, Arena<A>>,
}

pub struct AcceptedPresence<'a> {
    pub direction: PresenceDirection,
    pub kind: PresenceRequestType,
    pub sender: JidRef<'a>,
    pub target: JidRef<'a>,
}

#[derive(Default)]
pub enum PresenceEffect {
    #[default]
    None,
    Route,
    Accept,
    Deliver(RosterOrder),
    DeliverThenPushRoster(RosterPush),
    Replay {
        order: RosterOrder,
        pending: Vec<PendingSubscription>,
    },
    PushRoster(Option<RosterPush>),
}

pub type PresenceResult = Result<PresenceEffect, StanzaErrorCondition>;
pub type PresenceFuture<'a> = Pin<Box<dyn Future<Output = PresenceResult> + 'a>>;

pub trait PresenceHandler<A: ChunkAllocator>: Send + Sync {
    /// A successful result applies the returned effect without a reply.
    /// An error sends a stanza error to the request sender.
    /// The future runs on the connection worker and can be cancelled on shutdown.
    fn handle<'a>(&'a self, request: PresenceRequest<'a, A>) -> PresenceFuture<'a>;

    /// Applies sender state after the routed request is accepted.
    fn accepted<'a>(&'a self, _request: AcceptedPresence<'a>) -> PresenceFuture<'a> {
        Box::pin(async { Ok(PresenceEffect::None) })
    }
}

pub struct PresenceRegistration<A: ChunkAllocator> {
    route: PresenceRoute,
    handler: Arc<dyn PresenceHandler<A>>,
}

impl<A: ChunkAllocator> PresenceRegistration<A> {
    pub fn new(route: PresenceRoute, handler: Arc<dyn PresenceHandler<A>>) -> Self {
        Self { route, handler }
    }
}

impl<A: ChunkAllocator> Clone for PresenceRegistration<A> {
    fn clone(&self) -> Self {
        Self {
            route: self.route,
            handler: Arc::clone(&self.handler),
        }
    }
}

pub struct PresenceRegistry<A: ChunkAllocator> {
    handlers: Vec<PresenceRegistration<A>>,
}

impl<A: ChunkAllocator> Default for PresenceRegistry<A> {
    fn default() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }
}

impl<A: ChunkAllocator> PresenceRegistry<A> {
    pub fn register(&mut self, handler: PresenceRegistration<A>) -> Result<(), RegistrationError> {
        match self
            .handlers
            .binary_search_by_key(&handler.route, |entry| entry.route)
        {
            Ok(_) => Err(RegistrationError::DuplicatePresenceRoute(handler.route)),
            Err(index) => {
                self.handlers.insert(index, handler);
                Ok(())
            }
        }
    }

    pub fn find(
        &self,
        direction: PresenceDirection,
        kind: PresenceRequestType,
    ) -> Option<&dyn PresenceHandler<A>> {
        let route = PresenceRoute { direction, kind };
        let index = self
            .handlers
            .binary_search_by_key(&route, |entry| entry.route)
            .ok()?;
        Some(self.handlers[index].handler.as_ref())
    }

    pub(crate) fn registrations(&self) -> &[PresenceRegistration<A>] {
        &self.handlers
    }
}
