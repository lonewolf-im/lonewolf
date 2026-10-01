// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lonewolf_extension::delivery::SessionTag;
use lonewolf_extension::iq::IqRegistry;
use lonewolf_extension::presence::PresenceRegistry;
use lonewolf_extension::{Extension, ExtensionRegistry};
use lonewolf_storage::RedbStorage;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::RosterJid;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{PresenceType, Stanza, StanzaNamespace, StanzaType};

use crate::hosts::Hosts;
use crate::order::Order;

pub mod local;

pub use local::Registration;
use local::{LocalRouter, LocalRouterHandle};
pub(crate) use local::{Mailbox, SessionHandle, release_deferred};
pub use lonewolf_xmpp::stanza::RoutedStanza;

pub struct Router<A: ChunkAllocator> {
    local: LocalRouter<A>,
    handle: RouterHandle<A>,
}

pub struct RouterHandle<A: ChunkAllocator> {
    hosts: Hosts,
    local: LocalRouterHandle<A>,
    extensions: Arc<BTreeMap<String, ExtensionRegistry<A, RedbStorage>>>,
    order: Arc<Order>,
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

impl<A: ChunkAllocator + Clone> Router<A> {
    pub fn new(hosts: Hosts, local: LocalRouter<A>) -> Self {
        let handle = RouterHandle {
            hosts,
            local: local.handle(),
            extensions: Arc::default(),
            order: Order::new(),
        };
        Self { local, handle }
    }

    pub fn handle(&self) -> RouterHandle<A> {
        self.handle.clone()
    }

    pub(crate) fn with_extensions(
        mut self,
        extensions: BTreeMap<String, ExtensionRegistry<A, RedbStorage>>,
    ) -> Self {
        self.handle.extensions = Arc::new(extensions);
        self
    }

    pub async fn shutdown(self) -> io::Result<()> {
        self.local.shutdown().await
    }
}

impl<A: ChunkAllocator + Clone> Clone for RouterHandle<A> {
    fn clone(&self) -> Self {
        Self {
            hosts: self.hosts.clone(),
            local: self.local.clone(),
            extensions: Arc::clone(&self.extensions),
            order: Arc::clone(&self.order),
        }
    }
}

impl<A: ChunkAllocator + Clone> RouterHandle<A> {
    pub(crate) fn is_local_host(&self, domain: &str) -> bool {
        self.hosts.is_local_host(domain)
    }

    pub(crate) fn iq_handlers(&self, domain: &str) -> Option<&IqRegistry<A, RedbStorage>> {
        self.extensions.get(domain).map(ExtensionRegistry::iq)
    }

    pub(crate) fn presence_handlers(
        &self,
        domain: &str,
    ) -> Option<&PresenceRegistry<A, RedbStorage>> {
        self.extensions.get(domain).map(ExtensionRegistry::presence)
    }

    /// The stream features of the extensions enabled for `domain`, as XML.
    pub(crate) fn stream_features(&self, domain: &str) -> &str {
        self.extensions
            .get(domain)
            .map_or("", ExtensionRegistry::stream_features)
    }

    /// The per-account delivery order shared by every handler on this node.
    pub(crate) fn order(&self) -> &Arc<Order> {
        &self.order
    }

    /// The extensions enabled for `domain`, or none for an unknown host.
    pub(crate) fn extensions(&self, domain: &str) -> &[Arc<dyn Extension<A, RedbStorage>>] {
        self.extensions
            .get(domain)
            .map_or(&[], ExtensionRegistry::extensions)
    }

    /// Removes every session bound to `account` and ends each stream as account deleted.
    pub(crate) async fn retire_account(&self, account: &AccountKey) -> Result<(), RouterError> {
        self.local.retire_account(account).await
    }

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

    pub(crate) async fn route_presence(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        if !matches!(view.stanza_type(), StanzaType::Presence(_)) {
            return Err(RouterError::InvalidTarget);
        }
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if !self.hosts.is_local_host(to.domainpart()) {
            return Err(RouterError::RemoteUnsupported);
        }
        if to.localpart().is_none() || to.resourcepart().is_some() {
            return Err(RouterError::InvalidTarget);
        }
        self.local.deliver_presence(stanza).await
    }

    pub(crate) async fn route_presence_to_tagged(
        &self,
        tag: SessionTag,
        stanza: RoutedStanza<A>,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        if !matches!(view.stanza_type(), StanzaType::Presence(_)) {
            return Err(RouterError::InvalidTarget);
        }
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if !self.hosts.is_local_host(to.domainpart()) {
            return Err(RouterError::RemoteUnsupported);
        }
        if to.localpart().is_none() || to.resourcepart().is_some() {
            return Err(RouterError::InvalidTarget);
        }
        self.local.deliver_presence_to_tagged(tag, stanza).await
    }

    pub(crate) async fn route_current_presence(
        &self,
        source: &AccountKey,
        target: &AccountKey,
    ) -> Result<(), RouterError> {
        if !self.hosts.is_local_host(source.domain()) || !self.hosts.is_local_host(target.domain())
        {
            return Err(RouterError::RemoteUnsupported);
        }
        for stanza in self.current_presence(source, target).await? {
            match self.local.deliver_presence(stanza).await {
                Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Returns the presence of every available resource of `source`, addressed to `target`.
    pub(crate) async fn current_presence(
        &self,
        source: &AccountKey,
        target: &AccountKey,
    ) -> Result<Vec<RoutedStanza<A>>, RouterError> {
        let snapshot = self.local.presence_snapshot(source).await?;
        let mut stanzas = Vec::with_capacity(snapshot.len());
        for stanza in &snapshot {
            stanzas.push(self.readdress(stanza, target)?);
        }
        Ok(stanzas)
    }

    fn readdress(
        &self,
        stanza: &RoutedStanza<A>,
        target: &AccountKey,
    ) -> Result<RoutedStanza<A>, RouterError> {
        let mut arena = Arena::try_new_in(Default::default(), self.local.allocator())
            .map_err(|_| RouterError::Unavailable)?;
        let target =
            Jid::parse_in(target.as_str(), &mut arena).map_err(|_| RouterError::InvalidTarget)?;
        let stanza = stanza
            .resolve()
            .map_err(|_| RouterError::Unavailable)?
            .to_builder_in(&mut arena)
            .map_err(|_| RouterError::Unavailable)?
            .to(Some(target))
            .map_err(|_| RouterError::Unavailable)?
            .build()
            .map_err(|_| RouterError::Unavailable)?;
        Ok(RoutedStanza::from_parts(stanza, arena))
    }

    pub(crate) async fn route_unavailable_presence(
        &self,
        source: &AccountKey,
        target: &AccountKey,
    ) -> Result<(), RouterError> {
        if !self.hosts.is_local_host(source.domain()) || !self.hosts.is_local_host(target.domain())
        {
            return Err(RouterError::RemoteUnsupported);
        }
        for stanza in self.local.withdrawal_snapshot(source).await? {
            let mut arena = Arena::try_new_in(Default::default(), self.local.allocator())
                .map_err(|_| RouterError::Unavailable)?;
            let from = stanza
                .resolve()
                .map_err(|_| RouterError::Unavailable)?
                .from()
                .map_err(|_| RouterError::Unavailable)?
                .ok_or(RouterError::Unavailable)?;
            let from =
                Jid::parse_in(from.as_str(), &mut arena).map_err(|_| RouterError::Unavailable)?;
            let target = Jid::parse_in(target.as_str(), &mut arena)
                .map_err(|_| RouterError::InvalidTarget)?;
            let stanza = Stanza::builder_in(
                StanzaType::Presence(PresenceType::Unavailable),
                StanzaNamespace::Client,
                &mut arena,
            )
            .from(Some(from))
            .map_err(|_| RouterError::Unavailable)?
            .to(Some(target))
            .map_err(|_| RouterError::Unavailable)?
            .build()
            .map_err(|_| RouterError::Unavailable)?;
            match self
                .local
                .deliver_presence(RoutedStanza::from_parts(stanza, arena))
                .await
            {
                Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(crate) async fn broadcast_presence(
        &self,
        source: &RoutedStanza<A>,
        subscribers: &[RosterJid],
    ) -> Result<(), RouterError> {
        let view = source.resolve().map_err(|_| RouterError::Unavailable)?;
        if !matches!(
            view.stanza_type(),
            StanzaType::Presence(PresenceType::Available | PresenceType::Unavailable)
        ) {
            return Err(RouterError::InvalidTarget);
        }
        for subscriber in subscribers {
            let mut arena = Arena::try_new_in(Default::default(), self.local.allocator())
                .map_err(|_| RouterError::Unavailable)?;
            let target = Jid::parse_in(subscriber.as_str(), &mut arena)
                .map_err(|_| RouterError::InvalidTarget)?;
            if !self.hosts.is_local_host(
                target
                    .resolve(&arena)
                    .map_err(|_| RouterError::Unavailable)?
                    .domainpart(),
            ) {
                continue;
            }
            let stanza = view
                .to_builder_in(&mut arena)
                .map_err(|_| RouterError::Unavailable)?
                .to(Some(target))
                .map_err(|_| RouterError::Unavailable)?
                .build()
                .map_err(|_| RouterError::Unavailable)?;
            match self
                .route_presence(RoutedStanza::from_parts(stanza, arena))
                .await
            {
                Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Builds and enqueues one stanza for each resource carrying `tag`.
    ///
    /// The builder receives the destination full JID and must not block the
    /// router worker. Each stanza must use that JID. Build failures retire all
    /// tagged sessions. Mailbox failures retire the affected session.
    pub async fn route_to_tagged(
        &self,
        account: &AccountKey,
        tag: SessionTag,
        build: impl FnMut(&str) -> Result<RoutedStanza<A>, RouterError> + Send + 'static,
    ) -> Result<(), RouterError> {
        if !self.hosts.is_local_host(account.domain()) {
            return Err(RouterError::RemoteUnsupported);
        }
        self.local.deliver_to_tagged(account, tag, build).await
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

#[cfg(test)]
mod tests;
