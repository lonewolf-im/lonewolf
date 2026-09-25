// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::io;
use std::num::NonZeroUsize;

use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator, HandleError, SharedArena};
use lonewolf_xmpp::parser::Parsed;
use lonewolf_xmpp::stanza::{Stanza, StanzaRef, StanzaType};

use crate::hosts::Hosts;

pub mod local;

pub use local::Registration;
use local::{LocalRouter, LocalRouterHandle};

/// Dispatches stanzas by destination domain.
pub struct Router<A: ChunkAllocator> {
    local: LocalRouter<A>,
    handle: RouterHandle<A>,
}

pub struct RouterHandle<A: ChunkAllocator> {
    hosts: Hosts,
    local: LocalRouterHandle<A>,
}

/// Retains the parsed stanza and its immutable arena across workers.
pub struct RoutedStanza<A: ChunkAllocator> {
    stanza: Stanza,
    arena: SharedArena<A>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterError {
    InvalidTarget,
    RemoteUnsupported,
    InvalidResource,
    ResourceLimit,
    NotFound,
    Busy,
    Unavailable,
    Stopped,
}

impl<A: ChunkAllocator> Router<A> {
    pub fn new(hosts: Hosts, local: LocalRouter<A>) -> Self {
        let handle = RouterHandle {
            hosts,
            local: local.handle(),
        };
        Self { local, handle }
    }

    pub fn handle(&self) -> RouterHandle<A> {
        self.handle.clone()
    }

    pub async fn shutdown(self) -> io::Result<()> {
        self.local.shutdown().await
    }
}

impl<A: ChunkAllocator> Clone for RouterHandle<A> {
    fn clone(&self) -> Self {
        Self {
            hosts: self.hosts.clone(),
            local: self.local.clone(),
        }
    }
}

impl<A: ChunkAllocator> RouterHandle<A> {
    /// Applies the incoming listener's limit to resources on all listeners.
    pub async fn register(
        &self,
        account: &AccountKey,
        requested: Option<&str>,
        limit: NonZeroUsize,
    ) -> Result<Registration<A>, RouterError> {
        if !self.hosts.is_local_host(account.domain()) {
            return Err(RouterError::RemoteUnsupported);
        }
        self.local.register(account, requested, limit).await
    }

    /// Enqueues a stanza for a connected full JID without waiting for socket I/O.
    pub async fn route_full(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if !self.hosts.is_local_host(to.domainpart()) {
            return Err(RouterError::RemoteUnsupported);
        }
        self.local.deliver_full(stanza).await
    }

    pub async fn route_message(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        if !matches!(view.stanza_type(), StanzaType::Message(_)) {
            return Err(RouterError::InvalidTarget);
        }
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if !self.hosts.is_local_host(to.domainpart()) {
            return Err(RouterError::RemoteUnsupported);
        }
        if to.localpart().is_none() {
            return Err(RouterError::NotFound);
        }
        if to.resourcepart().is_some() {
            self.local.deliver_message(stanza).await
        } else {
            self.local.deliver_bare(stanza).await
        }
    }
}

impl<A: ChunkAllocator> RoutedStanza<A> {
    pub fn from_parsed(parsed: Parsed<Stanza, A>) -> Self {
        let (stanza, arena) = parsed.into_parts();
        Self::from_parts(stanza, arena)
    }

    pub(crate) fn from_parts(stanza: Stanza, arena: Arena<A>) -> Self {
        Self {
            stanza,
            arena: arena.freeze(),
        }
    }

    pub(crate) fn from_parts_pair(first: Stanza, second: Stanza, arena: Arena<A>) -> (Self, Self) {
        let arena = arena.freeze();
        (
            Self {
                stanza: first,
                arena: arena.clone(),
            },
            Self {
                stanza: second,
                arena,
            },
        )
    }

    pub fn resolve(&self) -> Result<StanzaRef<'_, SharedArena<A>>, HandleError> {
        self.stanza.resolve(&self.arena)
    }
}

impl<A: ChunkAllocator> Clone for RoutedStanza<A> {
    fn clone(&self) -> Self {
        Self {
            stanza: self.stanza,
            arena: self.arena.clone(),
        }
    }
}

impl fmt::Display for RouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTarget => "destination JID is invalid",
            Self::RemoteUnsupported => "remote routing is unavailable",
            Self::InvalidResource => "resource identifier is invalid",
            Self::ResourceLimit => "account resource limit reached",
            Self::NotFound => "destination resource is not connected",
            Self::Busy => "destination resource cannot accept a stanza",
            Self::Unavailable => "router cannot register a resource",
            Self::Stopped => "router has stopped",
        })
    }
}

impl std::error::Error for RouterError {}
