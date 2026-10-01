// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;

use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaError, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{Jid, JidError};
use lonewolf_xmpp::stanza::{BuildError, RoutedStanza, Stanza, StanzaErrorCondition, WriteError};

use crate::ExtensionFuture;

/// A marker a handler attaches to a bound resource to select it for later deliveries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTag {
    /// The resource requested the roster and receives roster pushes.
    Interested,
}

impl SessionTag {
    const COUNT: usize = 1;

    const fn index(self) -> usize {
        self as usize
    }
}

/// The tags a resource carries, each with the view of storage its handler had when the
/// resource acquired it. Every effect of a later view reaches the resource or evicts it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionTags {
    since: [Option<u64>; SessionTag::COUNT],
}

impl SessionTags {
    /// Attaches `tag`; a tag the resource already carries keeps its original view.
    pub const fn insert(&mut self, tag: SessionTag, since: u64) {
        if self.since[tag.index()].is_none() {
            self.since[tag.index()] = Some(since);
        }
    }

    pub const fn contains(self, tag: SessionTag) -> bool {
        self.since[tag.index()].is_some()
    }

    /// The view since which the resource carries `tag`.
    pub const fn since(self, tag: SessionTag) -> Option<u64> {
        self.since[tag.index()]
    }
}

/// The server could not perform a delivery, so the client stream is closed instead of answered.
#[derive(Debug)]
pub struct DeliveryError;

impl fmt::Display for DeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("stanza delivery failed")
    }
}

impl Error for DeliveryError {}

impl From<ArenaError> for DeliveryError {
    fn from(_: ArenaError) -> Self {
        Self
    }
}

impl From<BuildError> for DeliveryError {
    fn from(_: BuildError) -> Self {
        Self
    }
}

impl From<HandleError> for DeliveryError {
    fn from(_: HandleError) -> Self {
        Self
    }
}

impl From<JidError> for DeliveryError {
    fn from(_: JidError) -> Self {
        Self
    }
}

impl From<WriteError> for DeliveryError {
    fn from(_: WriteError) -> Self {
        Self
    }
}

/// A handler failure while its transaction is open, answered to the client as a stanza
/// error; the transaction aborts.
#[derive(Debug)]
pub enum HandlerError {
    Stanza(StanzaErrorCondition),
}

impl From<StanzaErrorCondition> for HandlerError {
    fn from(condition: StanzaErrorCondition) -> Self {
        Self::Stanza(condition)
    }
}

pub type DeliveryFuture<'a> = ExtensionFuture<'a, Result<(), DeliveryError>>;

/// Builds the stanza for one recipient resource, addressed to the supplied full JID.
pub type StanzaFactory<A> =
    Box<dyn FnMut(Jid, &mut Arena<A>) -> Result<Stanza, DeliveryError> + Send>;

/// Answers which domains this server hosts.
pub trait HostLookup {
    /// Whether this server hosts `domain`, so its accounts can be reached locally.
    fn is_local_host(&self, domain: &str) -> bool;
}

/// Routing and session operations the server performs for a handler's effects.
/// Every method runs on the connection worker of the request being handled.
pub trait Delivery<A: ChunkAllocator>: HostLookup {
    /// Allocates an arena for stanzas the handler builds.
    fn arena(&self) -> Result<Arena<A>, DeliveryError>;

    /// Attaches `tag` to the requesting resource, with `since` as the handler's view of
    /// storage. A tag the resource already carries keeps its earlier view.
    fn tag_session<'a>(&'a self, tag: SessionTag, since: u64) -> DeliveryFuture<'a>;

    /// Delivers a presence to the available resources of its bare `to` JID.
    /// An offline target is not an error.
    fn to_available<'a>(&'a self, stanza: RoutedStanza<A>) -> DeliveryFuture<'a>;

    /// Delivers a presence to the resources of its bare `to` JID that carry `tag`.
    fn to_tagged<'a>(&'a self, tag: SessionTag, stanza: RoutedStanza<A>) -> DeliveryFuture<'a>;

    /// Builds and delivers one stanza per resource of `account` that carries `tag`.
    fn push_to_tagged<'a>(
        &'a self,
        account: &'a AccountKey,
        tag: SessionTag,
        build: StanzaFactory<A>,
    ) -> DeliveryFuture<'a>;

    /// Delivers the presence of every available resource of `from` to `to`.
    fn current_presence<'a>(
        &'a self,
        from: &'a AccountKey,
        to: &'a AccountKey,
    ) -> DeliveryFuture<'a>;

    /// Delivers unavailable presence from every resource of `from` to `to`.
    fn unavailable_presence<'a>(
        &'a self,
        from: &'a AccountKey,
        to: &'a AccountKey,
    ) -> DeliveryFuture<'a>;
}
