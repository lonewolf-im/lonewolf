// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, VecDeque};
use std::mem;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use async_channel::{Receiver, Sender, TrySendError};
use futures_channel::oneshot;
use futures_util::FutureExt;
use lonewolf_extension::delivery::{SessionTag, SessionTags};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{IqType, MessageType, PresenceType, StanzaType};
use parking_lot::Mutex as PlMutex;

use super::registration::{
    DirectedWithdrawal, Links, MailboxEntry, PresenceChange, Registration, ResourceMatch,
    RetireCause, Retired, SessionHandle, SessionLiveness, SharedDirectedWithdrawal, Withdrawal,
    take_queued,
};
use super::shards::LocalRouterHandle;
#[cfg(test)]
use crate::config::limits::default_max_directed_presence_recipients_per_resource;
use crate::router::{RoutedStanza, RouterError, RouterState};

const LAST_UNAVAILABLE_PER_SHARD: usize = 64;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DirectedRecipient(Box<str>);

impl DirectedRecipient {
    pub(crate) fn new(jid: JidRef<'_>) -> Self {
        Self(jid.as_str().into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    fn bare(&self) -> &str {
        self.0.split_once('/').map_or(&self.0, |(bare, _)| bare)
    }

    fn matches_prepared(&self, observer: &Self) -> bool {
        self == observer || (!self.0.contains('/') && self.bare() == observer.bare())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PresenceAccess {
    pub(crate) subscribed: bool,
    pub(crate) directed: bool,
}

pub(crate) struct PresenceSource<'a, A: ChunkAllocator> {
    pub(crate) resource: &'a str,
    pub(crate) presence: Option<&'a RoutedStanza<A>>,
    pub(crate) access: PresenceAccess,
}

fn take_directed(grants: &mut Vec<DirectedRecipient>, token: u64) -> DirectedWithdrawal {
    DirectedWithdrawal {
        source_token: token,
        recipients: mem::take(grants),
    }
}

struct RetiredPresence<A: ChunkAllocator> {
    resource: Box<str>,
    stanza: RoutedStanza<A>,
}

pub(super) struct Session<A: ChunkAllocator> {
    token: u64,
    alive: Arc<AtomicBool>,
    outbound: Sender<MailboxEntry<A>>,
    inbound: Receiver<MailboxEntry<A>>,
    pub(super) priority: Option<i8>,
    tags: SessionTags,
    presence: Option<RoutedStanza<A>>,
    unavailable: Option<RoutedStanza<A>>,
    directed: Vec<DirectedRecipient>,
    retired: oneshot::Sender<Retired<A>>,
}

impl<A: ChunkAllocator> Session<A> {
    fn accepts_bare_message(&self) -> bool {
        self.alive.load(Ordering::Acquire)
            && !self.outbound.is_closed()
            && self.priority.is_some_and(|priority| priority >= 0)
    }
}

struct LastUnavailable {
    at: SystemTime,
}

pub(super) struct Shard<A: ChunkAllocator> {
    max_directed_presence_recipients_per_resource: NonZeroUsize,
    last_unavailable: VecDeque<(Box<str>, LastUnavailable)>,
    accounts: HashMap<Box<str>, HashMap<Box<str>, Session<A>>>,
    retiring: HashMap<Box<str>, HashMap<u64, RetiredPresence<A>>>,
    next_token: u64,
    pub(super) terminated: bool,
}

impl<A: ChunkAllocator> Shard<A> {
    pub(super) fn cleanup(&mut self, account: &AccountKey, resource: &str, token: u64) {
        self.remove(account.as_str(), resource, token, RetireCause::Evicted);
        self.finish_presence(account, token);
    }

    fn remove(&mut self, account: &str, resource: &str, token: u64, cause: RetireCause) {
        let had_available = self.has_available(account);
        let mut retiring = Vec::new();
        if let Some(sessions) = self.accounts.get_mut(account) {
            let mut pending = Vec::new();
            Self::remove_session(
                sessions,
                resource,
                token,
                cause,
                &mut pending,
                &mut retiring,
            );
            while let Some((resource, token)) = pending.pop() {
                Self::remove_session(
                    sessions,
                    &resource,
                    token,
                    cause,
                    &mut pending,
                    &mut retiring,
                );
            }
            if sessions.is_empty() {
                self.accounts.remove(account);
            }
        }
        if cause == RetireCause::Evicted && had_available && !self.has_available(account) {
            self.record_last_unavailable(account);
        }
        for (token, presence) in retiring {
            self.retiring
                .entry(account.into())
                .or_default()
                .insert(token, presence);
        }
    }

    fn remove_session(
        sessions: &mut HashMap<Box<str>, Session<A>>,
        resource: &str,
        token: u64,
        cause: RetireCause,
        pending: &mut Vec<(Box<str>, u64)>,
        retiring: &mut Vec<(u64, RetiredPresence<A>)>,
    ) {
        if sessions
            .get(resource)
            .is_none_or(|session| session.token != token)
        {
            return;
        }
        if let Some(mut session) = sessions.remove(resource) {
            session.alive.store(false, Ordering::Release);
            if let Some(unavailable) = session.unavailable.as_ref() {
                for (recipient_resource, recipient) in sessions.iter() {
                    if recipient.alive.load(Ordering::Acquire)
                        && recipient.priority.is_some()
                        && recipient
                            .outbound
                            .try_send(MailboxEntry::new(unavailable.clone()))
                            .is_err()
                    {
                        pending.push((recipient_resource.clone(), recipient.token));
                    }
                }
            }
            if let (Some(stanza), Some(_)) = (session.presence, session.unavailable.as_ref()) {
                retiring.push((
                    token,
                    RetiredPresence {
                        resource: resource.into(),
                        stanza,
                    },
                ));
            }
            // Report retirement before closing the mailbox so the stream can observe its cause.
            let _ = session.retired.send(Retired {
                cause,
                unavailable: session.unavailable,
                directed: SharedDirectedWithdrawal(Arc::new(PlMutex::new(Some(take_directed(
                    &mut session.directed,
                    token,
                ))))),
            });
            session.outbound.close();
        }
    }

    pub(super) fn finish_presence(&mut self, account: &AccountKey, token: u64) {
        if let Some(retiring) = self.retiring.get_mut(account.as_str()) {
            retiring.remove(&token);
            if retiring.is_empty() {
                self.retiring.remove(account.as_str());
            }
        }
    }

    fn has_available(&self, account: &str) -> bool {
        self.accounts
            .get(account)
            .is_some_and(|sessions| sessions.values().any(|session| session.priority.is_some()))
    }

    fn record_last_unavailable(&mut self, account: &str) {
        if self
            .last_unavailable
            .iter()
            .any(|(known, _)| known.as_ref() == account)
        {
            return;
        }
        if self.last_unavailable.len() == LAST_UNAVAILABLE_PER_SHARD {
            self.last_unavailable.pop_front();
        }
        self.last_unavailable.push_back((
            account.into(),
            LastUnavailable {
                at: SystemTime::now(),
            },
        ));
    }

    pub(super) fn tag(
        &mut self,
        account: &AccountKey,
        resource: &str,
        token: u64,
        tag: SessionTag,
    ) -> Result<(), RouterError> {
        let session = self
            .accounts
            .get_mut(account.as_str())
            .and_then(|sessions| sessions.get_mut(resource))
            .ok_or(RouterError::NotFound)?;
        if session.token != token || !session.alive.load(Ordering::Acquire) {
            return Err(RouterError::NotFound);
        }
        session.tags.insert(tag);
        Ok(())
    }

    pub(super) fn presence(
        &mut self,
        account: &AccountKey,
        resource: &str,
        token: u64,
        priority: Option<i8>,
        stanza: RoutedStanza<A>,
        unavailable: Option<RoutedStanza<A>>,
    ) -> Result<PresenceChange<A>, RouterError> {
        let had_available = self.has_available(account.as_str());
        let (change, siblings) = {
            let sessions = self
                .accounts
                .get(account.as_str())
                .ok_or(RouterError::NotFound)?;
            let source = sessions.get(resource).ok_or(RouterError::NotFound)?;
            if source.token != token || !source.alive.load(Ordering::Acquire) {
                return Err(RouterError::NotFound);
            }
            let became_available = priority.is_some() && source.priority.is_none();
            let became_eligible = priority.is_some_and(|priority| priority >= 0)
                && source.priority.is_none_or(|priority| priority < 0);
            let became_unavailable = priority.is_none() && source.priority.is_some();
            let preceding = take_queued(&source.inbound);
            let siblings = if became_available {
                sessions
                    .values()
                    .filter(|session| session.token != token)
                    .filter_map(|session| session.presence.as_ref())
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
            (
                (
                    became_available,
                    became_eligible,
                    became_unavailable,
                    preceding,
                ),
                siblings,
            )
        };

        let mut failed = Vec::new();
        let directed;
        {
            let sessions = self
                .accounts
                .get_mut(account.as_str())
                .ok_or(RouterError::NotFound)?;
            let source = sessions.get_mut(resource).ok_or(RouterError::NotFound)?;
            directed = if priority.is_none() {
                take_directed(&mut source.directed, token)
            } else {
                DirectedWithdrawal {
                    source_token: token,
                    recipients: Vec::new(),
                }
            };
            source.priority = priority;
            source.unavailable = unavailable;
            for (recipient_resource, session) in sessions.iter() {
                if session.token != token
                    && session.alive.load(Ordering::Acquire)
                    && session.priority.is_some()
                    && session
                        .outbound
                        .try_send(MailboxEntry::new(stanza.clone()))
                        .is_err()
                {
                    failed.push((recipient_resource.clone(), session.token));
                }
            }
            if let Some(source) = sessions.get_mut(resource) {
                source.presence = priority.map(|_| stanza);
            }
        }
        for (recipient_resource, recipient_token) in failed {
            self.remove(
                account.as_str(),
                &recipient_resource,
                recipient_token,
                RetireCause::Evicted,
            );
        }
        if priority.is_some() {
            self.last_unavailable
                .retain(|(known, _)| known.as_ref() != account.as_str());
        } else if had_available && !self.has_available(account.as_str()) {
            self.record_last_unavailable(account.as_str());
        }
        let (became_available, became_eligible, became_unavailable, preceding) = change;
        Ok(PresenceChange {
            became_available,
            became_eligible,
            became_unavailable,
            preceding,
            siblings,
            directed,
        })
    }

    pub(super) fn end_presence(
        &mut self,
        account: &AccountKey,
        resource: &str,
        token: u64,
    ) -> Result<Withdrawal<A>, RouterError> {
        let had_available = self.has_available(account.as_str());
        let sessions = self
            .accounts
            .get_mut(account.as_str())
            .ok_or(RouterError::NotFound)?;
        let source = sessions.get_mut(resource).ok_or(RouterError::NotFound)?;
        if source.token != token || !source.alive.load(Ordering::Acquire) {
            return Err(RouterError::NotFound);
        }
        source.alive.store(false, Ordering::Release);
        source.outbound.close();
        source.priority = None;
        let presence = source.presence.take();
        let unavailable = source.unavailable.take();
        let directed = take_directed(&mut source.directed, token);
        if let Some(stanza) = unavailable.as_ref() {
            let mut failed = Vec::new();
            for (recipient_resource, recipient) in sessions.iter() {
                if recipient.token != token
                    && recipient.alive.load(Ordering::Acquire)
                    && recipient.priority.is_some()
                    && recipient
                        .outbound
                        .try_send(MailboxEntry::new(stanza.clone()))
                        .is_err()
                {
                    failed.push((recipient_resource.clone(), recipient.token));
                }
            }
            for (recipient_resource, recipient_token) in failed {
                self.remove(
                    account.as_str(),
                    &recipient_resource,
                    recipient_token,
                    RetireCause::Evicted,
                );
            }
        }
        if let (Some(stanza), Some(_)) = (presence, unavailable.as_ref()) {
            self.retiring
                .entry(account.as_str().into())
                .or_default()
                .insert(
                    token,
                    RetiredPresence {
                        resource: resource.into(),
                        stanza,
                    },
                );
        }
        if had_available && !self.has_available(account.as_str()) {
            self.record_last_unavailable(account.as_str());
        }
        Ok(Withdrawal {
            unavailable,
            directed,
        })
    }

    pub(super) fn replacement_is_available(
        &self,
        account: &AccountKey,
        resource: &str,
        token: u64,
    ) -> bool {
        self.accounts
            .get(account.as_str())
            .and_then(|sessions| sessions.get(resource))
            .is_some_and(|session| {
                session.token != token
                    && session.alive.load(Ordering::Acquire)
                    && session.priority.is_some()
            })
    }

    pub(super) fn record_directed_presence(
        &mut self,
        account: &AccountKey,
        resource: &str,
        token: u64,
        recipient: DirectedRecipient,
        available: bool,
    ) -> Result<(), RouterError> {
        let source = self
            .accounts
            .get_mut(account.as_str())
            .and_then(|sessions| sessions.get_mut(resource))
            .ok_or(RouterError::NotFound)?;
        if source.token != token
            || !source.alive.load(Ordering::Acquire)
            || source.outbound.is_closed()
        {
            return Err(RouterError::NotFound);
        }
        if recipient.bare() == account.as_str() {
            return Ok(());
        }
        let known = source.directed.iter().position(|grant| *grant == recipient);
        match (available, known) {
            (true, None) => {
                if source.directed.len() >= self.max_directed_presence_recipients_per_resource.get()
                {
                    return Err(RouterError::DirectedPresenceLimit);
                }
                source.directed.push(recipient);
            }
            (false, Some(index)) => {
                source.directed.swap_remove(index);
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn terminate(&mut self) {
        self.terminated = true;
        for sessions in self.accounts.values() {
            for session in sessions.values() {
                session.alive.store(false, Ordering::Release);
            }
        }
        let directed = SharedDirectedWithdrawal(Arc::new(PlMutex::new(None)));
        for (_, sessions) in self.accounts.drain() {
            for (_, session) in sessions {
                let _ = session.retired.send(Retired {
                    cause: RetireCause::RouterStopped,
                    unavailable: None,
                    directed: directed.clone(),
                });
                session.outbound.close();
                while session.inbound.try_recv().is_ok() {}
            }
        }
        self.retiring.clear();
        self.last_unavailable.clear();
    }
}

impl<A: ChunkAllocator + Clone> Shard<A> {
    #[cfg(test)]
    fn new() -> Self {
        Self::with_directed_presence_limit(default_max_directed_presence_recipients_per_resource())
    }

    pub(super) fn with_directed_presence_limit(
        max_directed_presence_recipients_per_resource: NonZeroUsize,
    ) -> Self {
        Self {
            max_directed_presence_recipients_per_resource,
            last_unavailable: VecDeque::new(),
            accounts: HashMap::new(),
            retiring: HashMap::new(),
            next_token: 0,
            terminated: false,
        }
    }

    pub(super) fn resource_match(
        &self,
        account: &AccountKey,
        resource: &str,
    ) -> Option<ResourceMatch> {
        self.accounts
            .get(account.as_str())
            .and_then(|sessions| sessions.get(resource))
            .filter(|session| {
                session.alive.load(Ordering::Acquire) && !session.outbound.is_closed()
            })
            .map(|session| ResourceMatch {
                token: session.token,
            })
    }

    #[cfg(test)]
    pub(super) fn has_directed_grant(
        &self,
        account: &AccountKey,
        resource: &str,
        observer: &DirectedRecipient,
    ) -> bool {
        self.accounts
            .get(account.as_str())
            .and_then(|sessions| sessions.get(resource))
            .is_some_and(|session| {
                session.alive.load(Ordering::Acquire)
                    && !session.outbound.is_closed()
                    && session
                        .directed
                        .iter()
                        .any(|grant| grant.matches_prepared(observer))
            })
    }

    pub(super) fn register(
        &mut self,
        account: AccountKey,
        requested: Option<Box<str>>,
        limit: NonZeroUsize,
        outbound: Sender<MailboxEntry<A>>,
        inbound: Receiver<MailboxEntry<A>>,
        router: LocalRouterHandle<A>,
    ) -> Result<Registration<A>, RouterError> {
        if router.state() != RouterState::Running {
            return Err(RouterError::Stopped);
        }
        let shard = router.shard_index(account.as_str());
        if let Some(sessions) = self.accounts.get(account.as_str()) {
            let stale: Vec<_> = sessions
                .iter()
                .filter(|(_, session)| {
                    !session.alive.load(Ordering::Acquire) || session.outbound.is_closed()
                })
                .map(|(resource, session)| (resource.clone(), session.token))
                .collect();
            for (resource, token) in stale {
                self.remove(account.as_str(), &resource, token, RetireCause::Evicted);
            }
        }
        let sessions = self.accounts.entry(account.as_str().into()).or_default();
        if sessions.len() >= limit.get() {
            return Err(RouterError::ResourceLimit);
        }
        let token = self
            .next_token
            .checked_add(1)
            .ok_or(RouterError::Unavailable)?;
        self.next_token = token;
        let resource = match requested {
            Some(resource) if !sessions.contains_key(resource.as_ref()) => resource,
            _ => loop {
                let mut random = [0; 16];
                graviola::random::fill(&mut random).map_err(|_| RouterError::Unavailable)?;
                let candidate = format!("lw-{:032x}", u128::from_be_bytes(random)).into_boxed_str();
                if !sessions.contains_key(candidate.as_ref()) {
                    break candidate;
                }
            },
        };
        let (retired, retired_reply) = oneshot::channel();
        let alive = Arc::new(AtomicBool::new(true));
        let mailbox = outbound.downgrade();
        sessions.insert(
            resource.clone(),
            Session {
                token,
                alive: Arc::clone(&alive),
                outbound,
                inbound: inbound.clone(),
                priority: None,
                tags: SessionTags::default(),
                presence: None,
                unavailable: None,
                directed: Vec::new(),
                retired,
            },
        );
        Ok(Registration {
            account,
            resource,
            token,
            alive,
            links: mem::ManuallyDrop::new(Links {
                retired: retired_reply.shared(),
                inbound,
                mailbox,
                shard,
                router,
            }),
        })
    }

    fn presence_access(
        &self,
        account: &AccountKey,
        resource: Option<&str>,
        observer: &DirectedRecipient,
        subscribed: bool,
        build: &mut impl for<'a> FnMut(
            PresenceSource<'a, A>,
        ) -> Result<Option<RoutedStanza<A>>, RouterError>,
    ) -> Result<Vec<RoutedStanza<A>>, RouterError> {
        let mut deliveries = Vec::new();
        let Some(sessions) = self.accounts.get(account.as_str()) else {
            return Ok(deliveries);
        };
        for (name, session) in sessions {
            if resource.is_some_and(|resource| resource != name.as_ref())
                || !session.alive.load(Ordering::Acquire)
                || session.outbound.is_closed()
            {
                continue;
            }
            let access = PresenceAccess {
                subscribed,
                directed: session
                    .directed
                    .iter()
                    .any(|grant| grant.matches_prepared(observer)),
            };
            let ordinary_access = subscribed || account.as_str() == observer.bare();
            if !ordinary_access && !access.directed {
                continue;
            }
            let Some(stanza) = build(PresenceSource {
                resource: name,
                presence: session.presence.as_ref(),
                access,
            })?
            else {
                continue;
            };
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            let to = view
                .to()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            if to.as_str() != observer.as_str() {
                return Err(RouterError::InvalidTarget);
            }
            deliveries.push(stanza);
        }
        Ok(deliveries)
    }

    pub(super) fn probe(
        &self,
        requester: &SessionHandle<A>,
        request: &RoutedStanza<A>,
        subscribed: bool,
    ) -> Result<Option<RoutedStanza<A>>, RouterError> {
        let view = request.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let observer = view
            .from()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if !requester.matches(observer)
            || view.stanza_type() != StanzaType::Presence(PresenceType::Probe)
        {
            return Err(RouterError::InvalidTarget);
        }
        let target = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let owner = AccountKey::try_from(target.bare()).map_err(|_| RouterError::InvalidTarget)?;
        let ordinary = subscribed || owner.as_str() == observer.bare().as_str();
        let full = target.resourcepart().is_some();
        let mut build = |source: PresenceSource<'_, A>| {
            if !full && ordinary {
                return source
                    .presence
                    .map(|presence| {
                        crate::router::probe_current(
                            request,
                            presence,
                            requester.router.allocator(),
                        )
                    })
                    .transpose();
            }
            if source.presence.is_none() && !source.access.directed {
                return Ok(None);
            }
            let from = format!("{}/{}", owner.as_str(), source.resource);
            crate::router::probe_reply(
                request,
                &from,
                PresenceType::Available,
                None,
                requester.router.allocator(),
            )
            .map(Some)
        };
        let mut deliveries = self.presence_access(
            &owner,
            target.resourcepart(),
            &DirectedRecipient::new(observer),
            subscribed,
            &mut build,
        )?;
        let mut unavailable = None;
        if deliveries.is_empty() {
            let (from, kind, at) = if ordinary {
                (
                    target.as_str(),
                    PresenceType::Unavailable,
                    if full {
                        None
                    } else {
                        self.last_unavailable
                            .iter()
                            .find(|(account, _)| account.as_ref() == target.bare().as_str())
                            .map(|(_, value)| value.at)
                    },
                )
            } else {
                (target.bare().as_str(), PresenceType::Unsubscribed, None)
            };
            let stanza =
                crate::router::probe_reply(request, from, kind, at, requester.router.allocator())?;
            if kind == PresenceType::Unavailable {
                unavailable = Some(stanza.clone());
            }
            deliveries.push(stanza);
        }
        if !requester.liveness.is_alive() {
            return Ok(None);
        }
        let Some(sender) = requester.mailbox.upgrade() else {
            return Ok(None);
        };
        for stanza in deliveries {
            match sender.try_send(MailboxEntry::new(stanza)) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Closed(_)) => return Ok(None),
            }
        }
        Ok(unavailable)
    }

    pub(super) fn prune_directed(
        &mut self,
        stanza: &RoutedStanza<A>,
        token: Option<u64>,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        if view.stanza_type() != StanzaType::Presence(PresenceType::Unavailable) {
            return Ok(());
        }
        let Some(sender) = view.from().map_err(|_| RouterError::InvalidTarget)? else {
            return Ok(());
        };
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let Some(sessions) = self.accounts.get_mut(to.bare().as_str()) else {
            return Ok(());
        };
        for (resource, session) in sessions {
            if to
                .resourcepart()
                .is_some_and(|target| target != resource.as_ref())
                || token.is_some_and(|token| session.token != token)
                || !session.alive.load(Ordering::Acquire)
            {
                continue;
            }
            session.directed.retain(|grant| {
                if sender.resourcepart().is_some() {
                    grant.as_str() != sender.as_str()
                } else {
                    grant.bare() != sender.as_str()
                }
            });
        }
        Ok(())
    }

    pub(super) fn deliver(
        &mut self,
        stanza: RoutedStanza<A>,
        fallback_chat: bool,
    ) -> Result<(), RouterError> {
        self.deliver_with_guard(stanza, fallback_chat, || true)
    }

    pub(super) fn deliver_with_guard(
        &mut self,
        stanza: RoutedStanza<A>,
        fallback_chat: bool,
        valid: impl Fn() -> bool,
    ) -> Result<(), RouterError> {
        self.prune_directed(&stanza, None)?;
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let account = to.bare();
        let resource = to.resourcepart().ok_or(RouterError::InvalidTarget)?;
        let account = account.as_str();
        let recipient = self
            .accounts
            .get(account)
            .and_then(|sessions| sessions.get(resource));
        let result = recipient.map(|session| {
            let delivery = if !valid() {
                Ok(())
            } else if session.alive.load(Ordering::Acquire) {
                session
                    .outbound
                    .try_send(MailboxEntry::new(stanza.clone()))
                    .map_err(mailbox_error)
            } else {
                Err(RouterError::NotFound)
            };
            (session.token, delivery)
        });
        if let Some((token, Err(RouterError::NotFound))) = result {
            self.remove(account, resource, token, RetireCause::Evicted);
        }
        match result.map_or(Err(RouterError::NotFound), |(_, result)| result) {
            Err(RouterError::NotFound)
                if fallback_chat
                    && view.stanza_type() == StanzaType::Message(MessageType::Chat) =>
            {
                self.deliver_bare(stanza, true)
            }
            result => result,
        }
    }

    pub(super) fn deliver_iq_request(
        &mut self,
        stanza: RoutedStanza<A>,
        subscribed: bool,
        source: Option<SessionLiveness>,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        if !matches!(
            view.stanza_type(),
            StanzaType::Iq(IqType::Get | IqType::Set)
        ) {
            return Err(RouterError::InvalidTarget);
        }
        let observer = view
            .from()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let resource = to.resourcepart().ok_or(RouterError::InvalidTarget)?;
        let session = self
            .accounts
            .get(to.bare().as_str())
            .and_then(|sessions| sessions.get(resource))
            .ok_or(RouterError::NotFound)?;
        if !session.alive.load(Ordering::Acquire) || session.outbound.is_closed() {
            let token = session.token;
            self.remove(to.bare().as_str(), resource, token, RetireCause::Evicted);
            return Err(RouterError::NotFound);
        }
        if !subscribed
            && to.bare() != observer.bare()
            && !session.directed.iter().any(|grant| {
                grant.as_str() == observer.as_str()
                    || (!grant.as_str().contains('/') && grant.as_str() == observer.bare().as_str())
            })
        {
            return Err(RouterError::NotFound);
        }
        self.deliver_with_guard(stanza, false, || {
            source.as_ref().is_none_or(SessionLiveness::is_alive)
        })
    }

    pub(super) fn deliver_bare(
        &mut self,
        stanza: RoutedStanza<A>,
        allow_full: bool,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let sessions = self
            .accounts
            .get(to.bare().as_str())
            .ok_or(match view.stanza_type() {
                StanzaType::Message(
                    MessageType::Normal | MessageType::Chat | MessageType::Headline,
                ) => RouterError::Offline,
                _ => RouterError::NotFound,
            })?;
        if !allow_full && to.resourcepart().is_some() {
            return Err(RouterError::InvalidTarget);
        }
        match view.stanza_type() {
            StanzaType::Message(MessageType::Normal | MessageType::Chat) => {
                let recipient = sessions
                    .values()
                    .filter(|session| session.accepts_bare_message())
                    .max_by_key(|session| (session.priority, std::cmp::Reverse(session.token)))
                    .ok_or(RouterError::Offline)?;
                enqueue_bare_message(sessions, recipient, stanza)
            }
            StanzaType::Message(MessageType::Headline) => {
                let mut delivered = false;
                let mut busy = false;
                for session in sessions
                    .values()
                    .filter(|session| session.accepts_bare_message())
                {
                    match session.outbound.try_send(MailboxEntry::new(stanza.clone())) {
                        Ok(()) => delivered = true,
                        Err(TrySendError::Full(_)) => busy = true,
                        Err(TrySendError::Closed(_)) => {}
                    }
                }
                if delivered {
                    Ok(())
                } else if busy {
                    Err(RouterError::Busy)
                } else {
                    Err(RouterError::Offline)
                }
            }
            _ => Err(RouterError::InvalidTarget),
        }
    }

    pub(super) fn deliver_presence(
        &mut self,
        stanza: RoutedStanza<A>,
        source: Option<&SessionLiveness>,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if to.resourcepart().is_some()
            || !matches!(
                view.stanza_type(),
                StanzaType::Presence(
                    PresenceType::Available
                        | PresenceType::Unavailable
                        | PresenceType::Subscribe
                        | PresenceType::Subscribed
                        | PresenceType::Unsubscribe
                        | PresenceType::Unsubscribed
                )
            )
        {
            return Err(RouterError::InvalidTarget);
        }
        self.deliver_presence_where_with_guard(
            stanza,
            |session| session.priority.is_some(),
            || source.is_none_or(SessionLiveness::is_alive),
        )
    }

    pub(super) fn deliver_presence_to_tagged(
        &mut self,
        tag: SessionTag,
        stanza: RoutedStanza<A>,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if to.resourcepart().is_some() || !matches!(view.stanza_type(), StanzaType::Presence(_)) {
            return Err(RouterError::InvalidTarget);
        }
        match self.deliver_presence_where(stanza, |session| session.tags.contains(tag)) {
            Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(super) fn deliver_presence_where(
        &mut self,
        stanza: RoutedStanza<A>,
        select: impl Fn(&Session<A>) -> bool,
    ) -> Result<(), RouterError> {
        self.deliver_presence_where_with_guard(stanza, select, || true)
    }

    fn deliver_presence_where_with_guard(
        &mut self,
        stanza: RoutedStanza<A>,
        select: impl Fn(&Session<A>) -> bool,
        valid: impl Fn() -> bool,
    ) -> Result<(), RouterError> {
        self.prune_directed(&stanza, None)?;
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let account = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?
            .as_str();
        let sessions = self.accounts.get(account).ok_or(RouterError::NotFound)?;
        let mut delivered = false;
        let mut busy = false;
        let mut failed = Vec::new();
        for (resource, session) in sessions {
            if !select(session) {
                continue;
            }
            if !session.alive.load(Ordering::Acquire) || session.outbound.is_closed() {
                failed.push((resource.clone(), session.token));
                continue;
            }
            if !valid() {
                continue;
            }
            match session.outbound.try_send(MailboxEntry::new(stanza.clone())) {
                Ok(()) => delivered = true,
                Err(TrySendError::Full(_)) => {
                    busy = true;
                    failed.push((resource.clone(), session.token));
                }
                Err(TrySendError::Closed(_)) => {
                    failed.push((resource.clone(), session.token));
                }
            }
        }
        for (resource, token) in failed {
            self.remove(account, &resource, token, RetireCause::Evicted);
        }
        if delivered {
            Ok(())
        } else if busy {
            Err(RouterError::Busy)
        } else {
            Err(RouterError::NotFound)
        }
    }

    pub(super) fn presence_snapshot(&self, account: &AccountKey) -> Vec<RoutedStanza<A>> {
        self.accounts
            .get(account.as_str())
            .into_iter()
            .flat_map(|sessions| sessions.values())
            .filter(|session| session.alive.load(Ordering::Acquire))
            .filter_map(|session| session.presence.clone())
            .collect()
    }

    pub(super) fn withdrawal_snapshot(&self, account: &AccountKey) -> Vec<RoutedStanza<A>> {
        let mut snapshot = self.presence_snapshot(account);
        if let Some(retiring) = self.retiring.get(account.as_str()) {
            for (token, presence) in retiring {
                let replaced = self
                    .accounts
                    .get(account.as_str())
                    .and_then(|sessions| sessions.get(presence.resource.as_ref()))
                    .is_some_and(|session| {
                        session.token != *token
                            && session.alive.load(Ordering::Acquire)
                            && session.presence.is_some()
                    });
                if !replaced {
                    snapshot.push(presence.stanza.clone());
                }
            }
        }
        snapshot
    }

    pub(super) fn deliver_to_tagged(
        &mut self,
        account: &AccountKey,
        tag: SessionTag,
        build: &mut impl FnMut(&str) -> Result<RoutedStanza<A>, RouterError>,
    ) -> Result<(), RouterError> {
        let Some(sessions) = self.accounts.get(account.as_str()) else {
            return Ok(());
        };
        if sessions.values().all(|session| !session.tags.contains(tag)) {
            return Ok(());
        }
        let max_resource_len = sessions
            .keys()
            .map(|resource| resource.len())
            .max()
            .unwrap_or(0);
        let mut full_jid = String::with_capacity(account.as_str().len() + 1 + max_resource_len);
        let mut deliveries = Vec::with_capacity(sessions.len());
        let mut failed = Vec::new();
        let mut build_error = None;
        for (resource, session) in sessions {
            if !session.tags.contains(tag) {
                continue;
            }
            if !session.alive.load(Ordering::Acquire) || session.outbound.is_closed() {
                failed.push((resource.clone(), session.token));
                continue;
            }
            full_jid.clear();
            full_jid.push_str(account.as_str());
            full_jid.push('/');
            full_jid.push_str(resource);
            let stanza = match build(&full_jid).and_then(|stanza| {
                validate_target(&stanza, &full_jid)?;
                Ok(stanza)
            }) {
                Ok(stanza) => stanza,
                Err(error) => {
                    build_error = Some(error);
                    break;
                }
            };
            deliveries.push((resource.clone(), session.token, stanza));
        }
        if let Some(error) = build_error {
            let failed = sessions
                .iter()
                .filter(|(_, session)| session.tags.contains(tag))
                .map(|(resource, session)| (resource.clone(), session.token))
                .collect::<Vec<_>>();
            for (resource, token) in failed {
                self.remove(account.as_str(), &resource, token, RetireCause::Evicted);
            }
            return Err(error);
        }
        if let Some(sessions) = self.accounts.get(account.as_str()) {
            for (resource, token, stanza) in deliveries {
                let Some(session) = sessions.get(resource.as_ref()) else {
                    continue;
                };
                if session.token == token
                    && (!session.alive.load(Ordering::Acquire)
                        || session
                            .outbound
                            .try_send(MailboxEntry::new(stanza))
                            .is_err())
                {
                    failed.push((resource, token));
                }
            }
        }
        for (resource, token) in failed {
            self.remove(account.as_str(), &resource, token, RetireCause::Evicted);
        }
        Ok(())
    }

    pub(super) fn retire_account(&mut self, account: &AccountKey) {
        self.last_unavailable
            .retain(|(known, _)| known.as_ref() != account.as_str());
        let Some(sessions) = self.accounts.get(account.as_str()) else {
            return;
        };
        let bound: Vec<_> = sessions
            .iter()
            .map(|(resource, session)| (resource.clone(), session.token))
            .collect();
        for (resource, token) in bound {
            self.remove(
                account.as_str(),
                &resource,
                token,
                RetireCause::AccountDeleted,
            );
        }
    }
}

fn validate_target<A: ChunkAllocator>(
    stanza: &RoutedStanza<A>,
    expected: &str,
) -> Result<(), RouterError> {
    let target = stanza
        .resolve()
        .map_err(|_| RouterError::InvalidTarget)?
        .to()
        .map_err(|_| RouterError::InvalidTarget)?
        .ok_or(RouterError::InvalidTarget)?;
    if target.as_str() == expected {
        Ok(())
    } else {
        Err(RouterError::InvalidTarget)
    }
}

fn mailbox_error<T>(error: TrySendError<T>) -> RouterError {
    match error {
        TrySendError::Full(_) => RouterError::Busy,
        TrySendError::Closed(_) => RouterError::NotFound,
    }
}

fn enqueue_bare_message<A: ChunkAllocator>(
    sessions: &HashMap<Box<str>, Session<A>>,
    recipient: &Session<A>,
    stanza: RoutedStanza<A>,
) -> Result<(), RouterError> {
    match recipient.outbound.try_send(MailboxEntry::new(stanza)) {
        Err(TrySendError::Closed(_)) if !sessions.values().any(Session::accepts_bare_message) => {
            Err(RouterError::Offline)
        }
        result => result.map_err(mailbox_error),
    }
}

#[cfg(test)]
mod tests;
