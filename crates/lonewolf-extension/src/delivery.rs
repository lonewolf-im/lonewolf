// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;
use std::time::Duration;

use lonewolf_storage::StorageErrorKind;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaError, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{Jid, JidError};
use lonewolf_xmpp::stanza::{BuildError, RoutedStanza, Stanza, StanzaErrorCondition, WriteError};

use crate::{Deliver, ExtensionFuture};

/// A marker a handler attaches to a bound resource to select it for later deliveries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTag {
    /// The resource requested the roster and receives roster pushes.
    Interested,
}

impl SessionTag {
    const fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionTags(u8);

impl SessionTags {
    pub const fn insert(&mut self, tag: SessionTag) {
        self.0 |= tag.bit();
    }

    pub const fn contains(self, tag: SessionTag) -> bool {
        self.0 & tag.bit() != 0
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
    Storage(StorageErrorKind),
    Delivery,
}

impl FailureKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Storage(StorageErrorKind::Unavailable) => "storage_unavailable",
            Self::Storage(StorageErrorKind::CorruptData) => "storage_corrupt_data",
            Self::Storage(StorageErrorKind::UnsupportedVersion) => "storage_unsupported_version",
            Self::Storage(StorageErrorKind::CommitUnknown) => "storage_commit_unknown",
            Self::Storage(StorageErrorKind::Other) => "storage_other",
            Self::Delivery => "delivery",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub kind: FailureKind,
    pub operation: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandlerError {
    Stanza(StanzaErrorCondition),
    Described {
        condition: StanzaErrorCondition,
        text: lonewolf_xmpp::stanza::StanzaErrorText,
    },
    Internal {
        condition: StanzaErrorCondition,
        failure: Failure,
    },
}

impl HandlerError {
    pub const fn described(
        condition: StanzaErrorCondition,
        text: lonewolf_xmpp::stanza::StanzaErrorText,
    ) -> Self {
        Self::Described { condition, text }
    }

    pub const fn text(&self) -> lonewolf_xmpp::stanza::StanzaErrorText {
        match self {
            Self::Described { text, .. } => *text,
            _ => self.condition().default_text(),
        }
    }

    pub const fn condition(&self) -> StanzaErrorCondition {
        match self {
            Self::Stanza(condition)
            | Self::Described { condition, .. }
            | Self::Internal { condition, .. } => *condition,
        }
    }

    pub const fn failure(&self) -> Option<Failure> {
        match self {
            Self::Stanza(_) | Self::Described { .. } => None,
            Self::Internal { failure, .. } => Some(*failure),
        }
    }
}

impl From<StanzaErrorCondition> for HandlerError {
    fn from(condition: StanzaErrorCondition) -> Self {
        Self::Stanza(condition)
    }
}

pub type DeliveryFuture<'a> = ExtensionFuture<'a, Result<(), DeliveryError>>;
pub type IqResponseFuture<'a, A> = ExtensionFuture<'a, Result<RoutedStanza<A>, DeliveryError>>;

/// Builds the stanza for one recipient resource, addressed to the supplied full JID.
pub type StanzaFactory<A> =
    Box<dyn FnMut(Jid, &mut Arena<A>) -> Result<Stanza, DeliveryError> + Send>;

pub trait HostLookup {
    fn is_local_host(&self, domain: &str) -> bool;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundResource {
    pub resource: Box<str>,
    /// The resource has sent available presence and has not withdrawn it.
    pub available: bool,
}

pub trait SessionLookup {
    /// Lists the live resources bound to a local account, sorted by resource.
    fn resources<'a>(
        &'a self,
        account: &'a AccountKey,
    ) -> ExtensionFuture<'a, Result<Vec<BoundResource>, DeliveryError>>;
}

/// Every method runs on the connection worker of the request being handled.
pub trait Delivery<A: ChunkAllocator>: HostLookup {
    fn arena(&self) -> Result<Arena<A>, DeliveryError>;

    /// Sends an IQ get or set from a served domain to a bound resource and waits for its result or error.
    /// Never await the session whose stanza is being handled: it reads its next stanza only after the current one.
    fn request_iq<'a>(
        &'a self,
        request: RoutedStanza<A>,
        timeout: Duration,
    ) -> IqResponseFuture<'a, A> {
        let _ = (request, timeout);
        Box::pin(async { Err(DeliveryError) })
    }

    /// Runs work independently on this worker with its own delivery handle; shutdown cancels it.
    fn detach(&self, work: Deliver<A>) -> Result<(), DeliveryError> {
        let _ = work;
        Err(DeliveryError)
    }

    fn tag_session<'a>(&'a self, tag: SessionTag) -> DeliveryFuture<'a>;

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

    /// Evicts tagged resources whose committed roster state cannot be sent safely.
    fn retire_tagged<'a>(&'a self, account: &'a AccountKey, tag: SessionTag) -> DeliveryFuture<'a>;

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
