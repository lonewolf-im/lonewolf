// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use lonewolf_extension::ExtensionRegistry;
use lonewolf_extension::account::AccountHandler;
use lonewolf_extension::archive::ArchiveHandler;
use lonewolf_extension::delivery::SessionTag;
use lonewolf_extension::discovery::Discovery;
use lonewolf_extension::iq::IqRegistry;
use lonewolf_extension::message::MessageHandler;
use lonewolf_extension::observer::{MessageObserver, SessionObserver};
use lonewolf_extension::policy::PolicyHandler;
use lonewolf_extension::presence::{PresenceDecorator, PresenceRegistry};
use lonewolf_extension::service::ServiceHandler;
use lonewolf_storage::RedbStorage;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::RosterJid;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidRef};
use lonewolf_xmpp::stanza::{Element, PresenceType, Stanza, StanzaNamespace, StanzaType};

use crate::hosts::Hosts;
use crate::order::Order;
use crate::stages::service::{ServicePresenceGate, ServicePresenceGates};
pub(crate) use local::ResourceMatch;

pub(crate) mod iq_requests;
pub(crate) mod local;

use iq_requests::IqRequests;

const MAX_DETACHED: usize = 4096;

#[derive(Clone, Default)]
pub(crate) struct DetachedWork {
    active: Arc<AtomicUsize>,
}

pub(crate) struct DetachedGuard {
    active: Arc<AtomicUsize>,
}

impl DetachedWork {
    pub(crate) fn try_start(&self) -> Option<DetachedGuard> {
        self.active
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                (active < MAX_DETACHED).then_some(active + 1)
            })
            .ok()
            .map(|_| DetachedGuard {
                active: Arc::clone(&self.active),
            })
    }
}

impl Drop for DetachedGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod detached_tests {
    use super::*;

    #[test]
    fn detached_work_limit_is_shared_and_dropped_guards_free_slots()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = DetachedWork::default();
        let other = work.clone();
        let mut guards = Vec::with_capacity(MAX_DETACHED);
        for _ in 0..MAX_DETACHED {
            guards.push(work.try_start().ok_or("available detached slot")?);
        }
        assert!(other.try_start().is_none());
        drop(guards.pop());
        let replacement = other.try_start().ok_or("released detached slot")?;
        assert!(work.try_start().is_none());
        drop(guards);
        drop(replacement);
        assert_eq!(work.active.load(Ordering::Relaxed), 0);
        Ok(())
    }
}

pub(crate) use local::Registration;
use local::SessionLiveness;
use local::{LocalRouter, LocalRouterHandle};
pub(crate) use local::{Mailbox, MailboxEntry, SessionHandle, StoredRelease, release_deferred};
pub(crate) use lonewolf_xmpp::stanza::RoutedStanza;

pub(crate) struct Router<A: ChunkAllocator> {
    local: LocalRouter<A>,
    handle: RouterHandle<A>,
}

pub(crate) struct RouterHandle<A: ChunkAllocator> {
    hosts: Hosts,
    local: LocalRouterHandle<A>,
    extensions: Arc<BTreeMap<String, ExtensionRegistry<A, RedbStorage>>>,
    services: Arc<BTreeMap<String, ServiceRoute<A>>>,
    service_presence: Option<Arc<ServicePresenceGates>>,
    order: Arc<Order>,
    iq_requests: Arc<IqRequests<A>>,
    detached_work: DetachedWork,
}

pub(crate) struct ServiceRoute<A: ChunkAllocator> {
    pub(crate) domain: Arc<str>,
    pub(crate) handler: Arc<dyn ServiceHandler<A, RedbStorage>>,
}

impl<A: ChunkAllocator> Clone for ServiceRoute<A> {
    fn clone(&self) -> Self {
        Self {
            domain: Arc::clone(&self.domain),
            handler: Arc::clone(&self.handler),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Destination {
    Server,
    /// A resource of a served domain, which no session can bind.
    ServerResource,
    Account,
    Resource,
    Service,
    Remote,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouterFailure {
    pub shard_id: usize,
}

impl fmt::Display for RouterFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "router shard {} panicked", self.shard_id)
    }
}

impl std::error::Error for RouterFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouterState {
    Running,
    Stopping,
    Failed(RouterFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouterError {
    InvalidTarget,
    RemoteUnsupported,
    InvalidResource,
    ResourceLimit,
    DirectedPresenceLimit,
    NotFound,
    Offline,
    Busy,
    Unavailable,
    Stopped,
}

impl<A: ChunkAllocator + Clone> Router<A> {
    pub(crate) fn new(hosts: Hosts, local: LocalRouter<A>) -> Self {
        let handle = RouterHandle {
            hosts,
            local: local.handle(),
            extensions: Arc::default(),
            services: Arc::default(),
            service_presence: None,
            order: Order::new(),
            iq_requests: IqRequests::new(),
            detached_work: DetachedWork::default(),
        };
        Self { local, handle }
    }

    pub(crate) fn handle(&self) -> RouterHandle<A> {
        self.handle.clone()
    }

    pub(crate) fn with_extensions(
        mut self,
        extensions: BTreeMap<String, ExtensionRegistry<A, RedbStorage>>,
    ) -> Self {
        self.handle.extensions = Arc::new(extensions);
        self
    }

    pub(crate) fn state(&self) -> RouterState {
        self.local.state()
    }

    pub(crate) fn with_services(mut self, services: BTreeMap<String, ServiceRoute<A>>) -> Self {
        self.handle.service_presence = (!services.is_empty()).then(Arc::default);
        self.handle.services = Arc::new(services);
        self
    }

    pub(crate) fn stop(&self) {
        self.local.stop();
    }

    pub(crate) async fn failure(&mut self) -> RouterFailure {
        self.local.failure().await
    }

    pub(crate) async fn shutdown(self) -> io::Result<()> {
        self.local.shutdown().await
    }
}

impl<A: ChunkAllocator + Clone> Clone for RouterHandle<A> {
    fn clone(&self) -> Self {
        Self {
            hosts: self.hosts.clone(),
            local: self.local.clone(),
            extensions: Arc::clone(&self.extensions),
            services: Arc::clone(&self.services),
            service_presence: self.service_presence.clone(),
            order: Arc::clone(&self.order),
            iq_requests: Arc::clone(&self.iq_requests),
            detached_work: self.detached_work.clone(),
        }
    }
}

impl<A: ChunkAllocator + Clone> RouterHandle<A> {
    pub(crate) fn iq_requests(&self) -> &Arc<IqRequests<A>> {
        &self.iq_requests
    }

    pub(crate) fn detached_work(&self) -> &DetachedWork {
        &self.detached_work
    }

    pub(crate) fn state(&self) -> RouterState {
        self.local.state()
    }

    pub(crate) fn is_local_host(&self, domain: &str) -> bool {
        self.hosts.is_local_host(domain)
    }

    pub(crate) fn destination(&self, to: JidRef<'_>) -> Destination {
        if !self.hosts.is_local_host(to.domainpart()) {
            return if self.services.contains_key(to.domainpart()) {
                Destination::Service
            } else {
                Destination::Remote
            };
        }
        match (to.localpart(), to.resourcepart()) {
            (None, None) => Destination::Server,
            (None, Some(_)) => Destination::ServerResource,
            (Some(_), None) => Destination::Account,
            (Some(_), Some(_)) => Destination::Resource,
        }
    }

    pub(crate) fn service(&self, domain: &str) -> Option<&ServiceRoute<A>> {
        self.services.get(domain)
    }

    pub(crate) fn service_presence_gate(&self, source: &str) -> Option<Arc<ServicePresenceGate>> {
        self.service_presence
            .as_ref()
            .map(|gates| gates.gate(source))
    }

    pub(crate) fn iq_handlers(&self, domain: &str) -> Option<&IqRegistry<A, RedbStorage>> {
        self.extensions.get(domain).map(ExtensionRegistry::iq)
    }

    pub(crate) fn archive_handler(
        &self,
        domain: &str,
    ) -> Option<&Arc<dyn ArchiveHandler<A, RedbStorage>>> {
        self.extensions
            .get(domain)
            .and_then(ExtensionRegistry::archive)
    }

    #[expect(clippy::type_complexity)]
    pub(crate) fn message_observers(
        &self,
        domain: &str,
    ) -> &[(&'static str, Arc<dyn MessageObserver<A, RedbStorage>>)] {
        self.extensions
            .get(domain)
            .map_or(&[], ExtensionRegistry::message_observers)
    }

    #[expect(clippy::type_complexity)]
    pub(crate) fn session_observers(
        &self,
        domain: &str,
    ) -> &[(&'static str, Arc<dyn SessionObserver<A, RedbStorage>>)] {
        self.extensions
            .get(domain)
            .map_or(&[], ExtensionRegistry::session_observers)
    }

    #[expect(clippy::type_complexity)]
    pub(crate) fn presence_decorations(
        &self,
        domain: &str,
    ) -> &[(
        &'static str,
        &'static str,
        &'static str,
        Arc<dyn PresenceDecorator<A, RedbStorage>>,
    )] {
        self.extensions
            .get(domain)
            .map_or(&[], ExtensionRegistry::presence_decorations)
    }

    pub(crate) fn policies(
        &self,
        domain: &str,
    ) -> &[(&'static str, Arc<dyn PolicyHandler<RedbStorage>>)] {
        self.extensions
            .get(domain)
            .map_or(&[], ExtensionRegistry::policies)
    }

    pub(crate) fn discovery(&self, domain: &str) -> Option<&Arc<Discovery>> {
        self.extensions
            .get(domain)
            .map(ExtensionRegistry::discovery)
    }

    pub(crate) fn presence_handlers(
        &self,
        domain: &str,
    ) -> Option<&PresenceRegistry<A, RedbStorage>> {
        self.extensions.get(domain).map(ExtensionRegistry::presence)
    }

    pub(crate) fn message_handler(
        &self,
        domain: &str,
    ) -> Option<&Arc<dyn MessageHandler<A, RedbStorage>>> {
        self.extensions
            .get(domain)
            .and_then(ExtensionRegistry::messages)
    }

    pub(crate) fn stream_features(&self, domain: &str) -> &str {
        self.extensions
            .get(domain)
            .map_or("", ExtensionRegistry::stream_features)
    }

    pub(crate) fn order(&self) -> &Arc<Order> {
        &self.order
    }

    #[expect(clippy::type_complexity)]
    pub(crate) fn account_handlers(
        &self,
        domain: &str,
    ) -> &[(&'static str, Arc<dyn AccountHandler<A, RedbStorage>>)] {
        self.extensions
            .get(domain)
            .map_or(&[], ExtensionRegistry::account_handlers)
    }

    pub(crate) async fn retire_account(&self, account: &AccountKey) -> Result<(), RouterError> {
        self.local.retire_account(account).await
    }

    pub(crate) async fn resource_match(
        &self,
        account: &AccountKey,
        resource: &str,
    ) -> Result<Option<ResourceMatch>, RouterError> {
        if !self.is_local_host(account.domain()) {
            return Err(RouterError::RemoteUnsupported);
        }
        self.local.resource_match(account, resource).await
    }

    #[cfg(test)]
    pub(crate) async fn has_directed_grant(
        &self,
        source: &AccountKey,
        resource: &str,
        observer: JidRef<'_>,
    ) -> Result<bool, RouterError> {
        self.local
            .has_directed_grant(source, resource, observer)
            .await
    }

    /// Applies the incoming listener's limit to resources on all listeners.
    pub(crate) async fn register(
        &self,
        account: &AccountKey,
        requested: Option<&str>,
        limit: NonZeroUsize,
    ) -> Result<Registration<A>, RouterError> {
        if self.state() != RouterState::Running {
            return Err(RouterError::Stopped);
        }
        if !self.hosts.is_local_host(account.domain()) {
            return Err(RouterError::RemoteUnsupported);
        }
        self.local.register(account, requested, limit).await
    }

    /// Enqueues a stanza for a connected full JID without waiting for socket I/O.
    pub(crate) async fn route_full(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
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

    /// The caller holds the source and target account tickets through admission.
    #[cfg(test)]
    pub(crate) async fn route_iq_request(
        &self,
        stanza: RoutedStanza<A>,
        subscribed: bool,
    ) -> Result<(), RouterError> {
        self.route_iq_request_guarded(stanza, subscribed, None)
            .await
    }

    pub(crate) async fn route_iq_request_guarded(
        &self,
        stanza: RoutedStanza<A>,
        subscribed: bool,
        source: Option<SessionLiveness>,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if !self.is_local_host(to.domainpart()) {
            return Err(RouterError::RemoteUnsupported);
        }
        self.local
            .deliver_iq_request(stanza, subscribed, source)
            .await
    }

    pub(crate) async fn route_full_guarded(
        &self,
        stanza: RoutedStanza<A>,
        source: SessionLiveness,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if !self.is_local_host(to.domainpart()) {
            return Err(RouterError::RemoteUnsupported);
        }
        self.local.deliver_full_guarded(stanza, source).await
    }

    pub(crate) async fn route_message(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        self.route_message_with(stanza, None).await
    }

    pub(crate) async fn route_stored_message(
        &self,
        stanza: RoutedStanza<A>,
        release: StoredRelease<A>,
    ) -> Result<(), RouterError> {
        self.route_message_with(stanza, Some(release)).await
    }

    async fn route_message_with(
        &self,
        stanza: RoutedStanza<A>,
        release: Option<StoredRelease<A>>,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        if !matches!(view.stanza_type(), StanzaType::Message(_)) {
            return Err(RouterError::InvalidTarget);
        }
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let destination = self.destination(to);
        match destination {
            Destination::Service | Destination::Remote => Err(RouterError::RemoteUnsupported),
            Destination::Server | Destination::ServerResource => Err(RouterError::NotFound),
            Destination::Resource => self.local.deliver_message(stanza, release).await,
            Destination::Account => self.local.deliver_bare(stanza, release).await,
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

    pub(crate) async fn route_presence_error(
        &self,
        stanza: RoutedStanza<A>,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        if view.stanza_type() != StanzaType::Presence(PresenceType::Error) {
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
            return Err(RouterError::InvalidTarget);
        }
        if to.resourcepart().is_some() {
            self.route_full(stanza).await
        } else {
            self.local.deliver_presence_error(stanza).await
        }
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

    /// The caller holds both account tickets through mailbox admission.
    pub(crate) async fn probe_presence(
        &self,
        requester: &SessionHandle<A>,
        request: &RoutedStanza<A>,
        subscribed: bool,
    ) -> Result<(), RouterError> {
        let target = request
            .resolve()
            .map_err(|_| RouterError::InvalidTarget)?
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if !self.is_local_host(target.domainpart()) {
            return Err(RouterError::RemoteUnsupported);
        }
        self.local.probe(requester, request, subscribed).await
    }

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

    /// Absent or busy recipients and nonlocal or domain-only targets are not errors.
    pub(crate) async fn route_directed_presence(
        &self,
        stanza: RoutedStanza<A>,
    ) -> Result<(), RouterError> {
        let full = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            if !matches!(view.stanza_type(), StanzaType::Presence(_)) {
                return Err(RouterError::InvalidTarget);
            }
            let to = view
                .to()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            match self.destination(to) {
                Destination::Resource => true,
                Destination::Account => false,
                Destination::Server
                | Destination::ServerResource
                | Destination::Service
                | Destination::Remote => {
                    return Ok(());
                }
            }
        };
        let delivered = if full {
            self.local.deliver_full(stanza).await
        } else {
            self.local.deliver_presence(stanza).await
        };
        match delivered {
            Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn send_directed<'r>(
        &self,
        source: &RoutedStanza<A>,
        recipients: impl IntoIterator<Item = &'r str>,
    ) -> Result<(), RouterError> {
        let view = source.resolve().map_err(|_| RouterError::Unavailable)?;
        for recipient in recipients {
            let mut arena = Arena::try_new_in(Default::default(), self.local.allocator())
                .map_err(|_| RouterError::Unavailable)?;
            let Ok(target) = Jid::parse_in(recipient, &mut arena) else {
                continue;
            };
            let stanza = view
                .to_builder_in(&mut arena)
                .map_err(|_| RouterError::Unavailable)?
                .to(Some(target))
                .map_err(|_| RouterError::Unavailable)?
                .build()
                .map_err(|_| RouterError::Unavailable)?;
            self.route_directed_presence(RoutedStanza::from_parts(stanza, arena))
                .await?;
        }
        Ok(())
    }

    /// The builder must use the supplied full JID and must not block the calling thread.
    /// Build failures retire all tagged sessions; mailbox failures retire the affected session.
    pub(crate) async fn route_to_tagged(
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

fn probe_current<A: ChunkAllocator>(
    request: &RoutedStanza<A>,
    presence: &RoutedStanza<A>,
    allocator: A,
) -> Result<RoutedStanza<A>, RouterError> {
    let mut arena =
        Arena::try_new_in(Default::default(), allocator).map_err(|_| RouterError::Unavailable)?;
    let observer = request
        .resolve()
        .map_err(|_| RouterError::InvalidTarget)?
        .from()
        .map_err(|_| RouterError::InvalidTarget)?
        .ok_or(RouterError::InvalidTarget)?;
    let to = Jid::parse_in(observer.as_str(), &mut arena).map_err(|_| RouterError::Unavailable)?;
    let stanza = presence
        .resolve()
        .map_err(|_| RouterError::Unavailable)?
        .to_builder_in(&mut arena)
        .and_then(|builder| builder.to(Some(to)))
        .and_then(|builder| builder.build())
        .map_err(|_| RouterError::Unavailable)?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}

fn probe_reply<A: ChunkAllocator>(
    request: &RoutedStanza<A>,
    from: &str,
    kind: PresenceType,
    id: Option<&str>,
    at: Option<SystemTime>,
    allocator: A,
) -> Result<RoutedStanza<A>, RouterError> {
    let mut arena =
        Arena::try_new_in(Default::default(), allocator).map_err(|_| RouterError::Unavailable)?;
    let view = request.resolve().map_err(|_| RouterError::InvalidTarget)?;
    let observer = view
        .from()
        .map_err(|_| RouterError::InvalidTarget)?
        .ok_or(RouterError::InvalidTarget)?;
    let to = Jid::parse_in(observer.as_str(), &mut arena).map_err(|_| RouterError::Unavailable)?;
    let from = Jid::parse_in(from, &mut arena).map_err(|_| RouterError::Unavailable)?;
    let delay = at
        .map(|at| {
            let seconds = at
                .duration_since(UNIX_EPOCH)
                .map_err(|_| RouterError::Unavailable)?
                .as_secs();
            let seconds = i64::try_from(seconds).map_err(|_| RouterError::Unavailable)?;
            let time = time::OffsetDateTime::from_unix_timestamp(seconds)
                .map_err(|_| RouterError::Unavailable)?;
            let mut stamp = [0; 20];
            let written = time
                .format_into(
                    &mut stamp.as_mut_slice(),
                    &time::format_description::well_known::Rfc3339,
                )
                .map_err(|_| RouterError::Unavailable)?;
            let stamp =
                std::str::from_utf8(&stamp[..written]).map_err(|_| RouterError::Unavailable)?;
            Element::builder_in("delay", "urn:xmpp:delay", &mut arena)
                .and_then(|builder| builder.attribute("stamp", "", stamp))
                .and_then(|builder| builder.build())
                .map_err(|_| RouterError::Unavailable)
        })
        .transpose()?;
    let mut builder = Stanza::builder_in(
        StanzaType::Presence(kind),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(from))
    .and_then(|builder| builder.to(Some(to)))
    .and_then(|builder| builder.id(id))
    .map_err(|_| RouterError::Unavailable)?;
    if let Some(delay) = delay {
        builder = builder.child(delay).map_err(|_| RouterError::Unavailable)?;
    }
    let stanza = builder.build().map_err(|_| RouterError::Unavailable)?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}

impl fmt::Display for RouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTarget => "destination JID is invalid",
            Self::RemoteUnsupported => "remote routing is unavailable",
            Self::InvalidResource => "resource identifier is invalid",
            Self::ResourceLimit => "account resource limit reached",
            Self::DirectedPresenceLimit => "resource directed-presence recipient limit reached",
            Self::NotFound => "destination resource is not connected",
            Self::Offline => "destination account has no eligible resource",
            Self::Busy => "destination resource cannot accept a stanza",
            Self::Unavailable => "router cannot register a resource",
            Self::Stopped => "router has stopped",
        })
    }
}

impl std::error::Error for RouterError {}

#[cfg(test)]
mod tests;
