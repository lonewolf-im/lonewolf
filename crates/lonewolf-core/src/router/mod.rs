// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use lonewolf_extension::delivery::SessionTag;
use lonewolf_extension::iq::IqRegistry;
use lonewolf_extension::message::MessageHandler;
use lonewolf_extension::presence::{PresenceRegistry, PresenceRequestType};
use lonewolf_extension::{Extension, ExtensionRegistry};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::RosterJid;
use lonewolf_storage::{RedbStorage, Storage};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidRef};
use lonewolf_xmpp::stanza::{Element, PresenceType, Stanza, StanzaNamespace, StanzaType};

use crate::delivery::{Pending, WorkGuard};
use crate::hosts::Hosts;
use crate::order::Order;
pub(crate) use local::{DirectedRecipient, PresenceSource};

pub mod local;

pub use local::Registration;
use local::SessionLiveness;
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
    Offline,
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

    pub(crate) fn extensions(&self, domain: &str) -> &[Arc<dyn Extension<A, RedbStorage>>] {
        self.extensions
            .get(domain)
            .map_or(&[], ExtensionRegistry::extensions)
    }

    pub(crate) async fn retire_account(&self, account: &AccountKey) -> Result<(), RouterError> {
        self.local.retire_account(account).await
    }

    #[cfg_attr(not(test), allow(dead_code))]
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn with_presence_access(
        &self,
        guard: WorkGuard,
        storage: RedbStorage,
        source: AccountKey,
        resource: Option<Box<str>>,
        observer: DirectedRecipient,
        build: impl for<'a> FnMut(PresenceSource<'a, A>) -> Result<Option<RoutedStanza<A>>, RouterError>
        + Send
        + 'static,
    ) -> Pending<Result<(), RouterError>> {
        let router = self.clone();
        Pending::spawn(guard, async move {
            let mut arena = Arena::try_new_in(Default::default(), router.local.allocator())
                .map_err(|_| RouterError::Unavailable)?;
            let jid = Jid::parse_in(observer.as_str(), &mut arena)
                .map_err(|_| RouterError::InvalidTarget)?;
            let jid = jid
                .resolve(&arena)
                .map_err(|_| RouterError::InvalidTarget)?;
            let observer_account =
                AccountKey::try_from(jid.bare()).map_err(|_| RouterError::InvalidTarget)?;
            if !router.is_local_host(source.domain())
                || !router.is_local_host(observer_account.domain())
            {
                return Err(RouterError::RemoteUnsupported);
            }
            let mut accounts = vec![source.clone()];
            if observer_account != source {
                accounts.push(observer_account);
            }
            let (transaction, mut ticket) = router
                .order
                .fix(accounts, storage.begin_read())
                .await
                .map_err(|_| RouterError::Unavailable)?;
            let subscribed = match router
                .presence_handlers(source.domain())
                .and_then(|handlers| handlers.find(PresenceRequestType::Available))
            {
                Some(handler) => handler
                    .visibility(&source, jid, &transaction)
                    .await
                    .map_err(|_| RouterError::Unavailable)?,
                None => false,
            };
            ticket.turn().await;
            let deliveries = router
                .local
                .presence_access(&source, resource, observer, subscribed, Box::new(build))
                .await?;
            for delivery in deliveries {
                match router.local.authorized_delivery(delivery).await {
                    Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })
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

    /// Hold the source and target account tickets through admission.
    #[cfg_attr(not(test), allow(dead_code))]
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
        for delivery in self
            .local
            .probe_snapshot(requester, request, subscribed)
            .await?
        {
            match self.local.authorized_delivery(delivery).await {
                Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
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
            if !self.hosts.is_local_host(to.domainpart()) || to.localpart().is_none() {
                return Ok(());
            }
            to.resourcepart().is_some()
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

    /// The builder must use the supplied full JID and must not block the router worker.
    /// Build failures retire all tagged sessions; mailbox failures retire the affected session.
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
    .and_then(|builder| builder.id(view.id()?))
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
