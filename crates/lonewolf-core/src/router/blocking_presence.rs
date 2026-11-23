// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, HashSet};

use lonewolf_extension::blocking::BlockingPresenceChange;
use lonewolf_extension::policy::{Direction, Verdict};
use lonewolf_extension::presence::PresenceRequestType;
use lonewolf_storage::RedbRead;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::blocking::BlockDelta;
use lonewolf_storage::roster::{RosterJid, RosterReads, SubscriptionState};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidRef};
use lonewolf_xmpp::stanza::{PresenceType, Stanza, StanzaNamespace, StanzaType};

use super::local::{DirectedRecipient, SessionLiveness};
use super::{DeliveryScope, Destination, RoutedStanza, RouterError, RouterHandle};
use crate::order::PendingDirectedGrant;
use crate::stages::policy::{self, Check};

pub(super) struct BlockingPresenceSource<A: ChunkAllocator> {
    pub(super) resource: Box<str>,
    pub(super) current: Option<RoutedStanza<A>>,
    pub(super) published: bool,
    pub(super) directed: Vec<DirectedRecipient>,
    pub(super) liveness: Option<SessionLiveness>,
}

impl<A: ChunkAllocator> BlockingPresenceSource<A> {
    fn can_send(&self, kind: PresenceType) -> bool {
        kind == PresenceType::Unavailable
            || (self.current.is_some()
                && self
                    .liveness
                    .as_ref()
                    .is_some_and(SessionLiveness::is_alive))
    }

    fn restoration_guard(&self, kind: PresenceType) -> Option<&SessionLiveness> {
        self.liveness
            .as_ref()
            .filter(|_| kind == PresenceType::Available)
    }
}

struct Rules<'a> {
    before: HashSet<&'a str>,
    after: HashSet<&'a str>,
    after_full: HashSet<&'a str>,
    changed_full: BTreeMap<&'a str, Vec<&'a str>>,
}

impl<'a> Rules<'a> {
    fn new(delta: &'a BlockDelta) -> Self {
        let before = delta.before_rules().map(|rule| rule.as_str()).collect();
        let after: HashSet<_> = delta.after_rules().map(|rule| rule.as_str()).collect();
        let after_full = after
            .iter()
            .filter_map(|rule| rule.split_once('/').map(|(bare, _)| bare))
            .collect();
        let mut changed_full = BTreeMap::<_, Vec<_>>::new();
        for full in delta.inserted.iter().chain(&delta.removed) {
            if let Some((bare, _)) = full.as_str().split_once('/') {
                changed_full.entry(bare).or_default().push(full.as_str());
            }
        }
        Self {
            before,
            after,
            after_full,
            changed_full,
        }
    }

    fn transition(&self, peer: JidRef<'_>) -> Option<PresenceType> {
        self.transition_at(peer.as_str(), peer.bare().as_str(), peer.domainpart())
    }

    fn transition_at(&self, full: &str, bare: &str, domain: &str) -> Option<PresenceType> {
        let covered = |rules: &HashSet<&str>| {
            rules.contains(full) || rules.contains(bare) || rules.contains(domain)
        };
        match (covered(&self.before), covered(&self.after)) {
            (false, true) => Some(PresenceType::Unavailable),
            (true, false) => Some(PresenceType::Available),
            _ => None,
        }
    }

    fn bare_transitions_at<'b>(
        &'b self,
        bare: &'b str,
        domain: &'b str,
    ) -> impl Iterator<Item = PresenceType> + 'b {
        self.transition_at(bare, bare, domain).into_iter().chain(
            self.changed_full
                .get(bare)
                .into_iter()
                .flatten()
                .filter_map(move |full| self.transition_at(full, bare, domain)),
        )
    }

    fn withdraws_grant(&self, address: &str, bare: &str, domain: &str) -> bool {
        let unavailable = PresenceType::Unavailable;
        if address == bare {
            self.bare_transitions_at(bare, domain)
                .any(|kind| kind == unavailable)
        } else {
            self.transition_at(address, bare, domain) == Some(unavailable)
        }
    }
}

#[derive(Default)]
struct Observer<'a> {
    subscribed: bool,
    directed_bare: bool,
    directed_full: BTreeSet<&'a str>,
}

struct Transition<'a, A: ChunkAllocator> {
    router: &'a RouterHandle<A>,
    before: &'a RedbRead,
    owner: &'a AccountKey,
    rules: Rules<'a>,
    scope: DeliveryScope,
}

impl<A: ChunkAllocator + Clone> RouterHandle<A> {
    pub(crate) async fn blocking_subscribers(
        &self,
        owner: &AccountKey,
        before: &RedbRead,
    ) -> Result<Vec<RosterJid>, RouterError> {
        let Some(quota) = self
            .presence_handlers(owner.domain())
            .and_then(|handlers| handlers.find(PresenceRequestType::Available))
            .and_then(|handler| handler.blocklist_roster_quota(owner))
        else {
            return Ok(Vec::new());
        };
        let roster = before
            .roster(owner, quota)
            .await
            .map_err(|_| RouterError::Unavailable)?;
        Ok(roster
            .items
            .into_iter()
            .filter(|item| {
                item.jid.as_str() != owner.as_str()
                    && matches!(
                        item.subscription.state,
                        SubscriptionState::From | SubscriptionState::Both
                    )
            })
            .map(|item| item.jid)
            .collect())
    }

    pub(crate) fn extend_blocking_roster_accounts(
        &self,
        change: &BlockingPresenceChange,
        subscribers: &[RosterJid],
        accounts: &mut Vec<AccountKey>,
    ) {
        let rules = Rules::new(change.delta());
        accounts.extend(
            subscribers
                .iter()
                .filter(|peer| {
                    self.is_local_host(peer.domain())
                        && rules
                            .bare_transitions_at(peer.as_str(), peer.domain())
                            .next()
                            .is_some()
                })
                .filter_map(|peer| AccountKey::try_from(peer).ok()),
        );
    }

    pub(crate) async fn extend_blocking_directed_accounts(
        &self,
        change: &BlockingPresenceChange,
        pending: Vec<PendingDirectedGrant>,
        accounts: &mut Vec<AccountKey>,
    ) -> Result<(), RouterError> {
        if change.delta().inserted.is_empty() {
            return Ok(());
        }
        let rules = Rules::new(change.delta());
        let directed = self
            .local
            .blocking_directed_recipients(change.owner(), |address| {
                let bare = bare_address(address);
                bare.split_once('@').is_some_and(|(_, domain)| {
                    self.is_local_host(domain) && rules.withdraws_grant(address, bare, domain)
                })
            })
            .await?;
        accounts.extend(pending.into_iter().filter_map(|grant| {
            let bare = grant.account.as_str();
            let address = grant.full.as_deref().unwrap_or(bare);
            rules
                .withdraws_grant(address, bare, grant.account.domain())
                .then_some(grant.account)
        }));
        for recipient in directed {
            let (username, domain) = bare_address(recipient.as_str())
                .split_once('@')
                .ok_or(RouterError::InvalidTarget)?;
            let mut arena = Arena::try_new_in(Default::default(), self.local.allocator())
                .map_err(|_| RouterError::Unavailable)?;
            let peer = Jid::from_trusted_parts_in(Some(username), domain, None, &mut arena)
                .map_err(|_| RouterError::Unavailable)?
                .resolve(&arena)
                .map_err(|_| RouterError::Unavailable)?;
            accounts.push(AccountKey::try_from(peer).map_err(|_| RouterError::InvalidTarget)?);
        }
        Ok(())
    }

    pub(crate) async fn route_blocking_presence(
        &self,
        change: &BlockingPresenceChange,
        before: &RedbRead,
        scope: DeliveryScope,
        subscribers: Option<&[RosterJid]>,
    ) -> Result<(), RouterError> {
        let owner = change.owner();
        if !self.is_local_host(owner.domain()) {
            return Err(RouterError::InvalidTarget);
        }
        let transition = Transition {
            router: self,
            before,
            owner,
            rules: Rules::new(change.delta()),
            scope,
        };
        let sources = self
            .local
            .blocking_presence_sources(owner, !change.delta().inserted.is_empty())
            .await?;
        let fetched;
        let subscribers = match subscribers {
            Some(prepared) => prepared,
            None if sources.iter().any(|source| source.published) => {
                fetched = self.blocking_subscribers(owner, before).await?;
                &fetched
            }
            None => &[],
        };
        for source in &sources {
            transition
                .send(source, if source.published { subscribers } else { &[] })
                .await?;
        }
        Ok(())
    }
}

impl<A: ChunkAllocator + Clone> Transition<'_, A> {
    async fn send(
        &self,
        source: &BlockingPresenceSource<A>,
        subscribers: &[RosterJid],
    ) -> Result<(), RouterError> {
        let allocator = self.router.local.allocator();
        let mut source_arena = Arena::try_new_in(Default::default(), allocator.clone())
            .map_err(|_| RouterError::Unavailable)?;
        let from = Jid::from_trusted_parts_in(
            Some(self.owner.username()),
            self.owner.domain(),
            Some(&source.resource),
            &mut source_arena,
        )
        .map_err(|_| RouterError::Unavailable)?
        .resolve(&source_arena)
        .map_err(|_| RouterError::Unavailable)?;
        let mut observers = BTreeMap::<_, Observer<'_>>::new();
        for subscriber in subscribers {
            observers.entry(subscriber.as_str()).or_default().subscribed = true;
        }
        for grant in &source.directed {
            let address = grant.as_str();
            if let Some((bare, _)) = address.split_once('/') {
                observers
                    .entry(bare)
                    .or_default()
                    .directed_full
                    .insert(address);
            } else {
                observers.entry(address).or_default().directed_bare = true;
            }
        }
        for (bare, observer) in observers {
            if bare == self.owner.as_str() {
                continue;
            }
            let mut arena = Arena::try_new_in(Default::default(), allocator.clone())
                .map_err(|_| RouterError::Unavailable)?;
            let peer = Jid::parse_in(bare, &mut arena).map_err(|_| RouterError::InvalidTarget)?;
            let peer = peer.resolve(&arena).map_err(|_| RouterError::Unavailable)?;
            if self
                .rules
                .bare_transitions_at(peer.as_str(), peer.domainpart())
                .next()
                .is_none()
            {
                continue;
            }
            match self.router.destination(peer) {
                Destination::Account => self.send_local(source, from, peer, observer).await?,
                Destination::Remote if self.router.federation_enabled() => {
                    self.send_external(source, from, peer, observer, false)
                        .await?;
                }
                Destination::Service
                    if self.scope.allows_components()
                        && self.router.is_component_domain(peer.domainpart()) =>
                {
                    self.send_external(source, from, peer, observer, true)
                        .await?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn send_local(
        &self,
        source: &BlockingPresenceSource<A>,
        from: JidRef<'_>,
        peer: JidRef<'_>,
        observer: Observer<'_>,
    ) -> Result<(), RouterError> {
        let account = AccountKey::try_from(peer).map_err(|_| RouterError::InvalidTarget)?;
        for target in self.router.local.presence_targets(&account).await? {
            let mut arena = Arena::try_new_in(Default::default(), self.router.local.allocator())
                .map_err(|_| RouterError::Unavailable)?;
            let to = Jid::from_trusted_parts_in(
                peer.localpart(),
                peer.domainpart(),
                Some(&target.resource),
                &mut arena,
            )
            .map_err(|_| RouterError::Unavailable)?;
            let to = to.resolve(&arena).map_err(|_| RouterError::Unavailable)?;
            let Some(kind) = self.rules.transition(to) else {
                continue;
            };
            if !source.can_send(kind) {
                continue;
            }
            let directed =
                kind == PresenceType::Unavailable && observer.directed_full.contains(to.as_str());
            let allowed_bare = target.available
                && (observer.subscribed
                    || (kind == PresenceType::Unavailable && observer.directed_bare));
            if !(directed || allowed_bare) {
                continue;
            }
            if !self.allowed(to, kind).await? {
                continue;
            }
            if !self.router.policies(account.domain()).is_empty() {
                let checks = [Check {
                    account: &account,
                    direction: Direction::Inbound,
                    peer: from,
                }];
                if policy::evaluate_in(
                    self.router,
                    self.before,
                    StanzaType::Presence(kind),
                    &checks,
                )
                .await
                .map_err(|_| RouterError::Unavailable)?
                    != Verdict::Allow
                {
                    continue;
                }
            }
            let stanza = self.stanza(source, from, to, kind)?;
            match self
                .router
                .local
                .deliver_blocking_presence(
                    stanza,
                    target.session,
                    !directed,
                    source.restoration_guard(kind),
                )
                .await
            {
                Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    async fn send_external(
        &self,
        source: &BlockingPresenceSource<A>,
        from: JidRef<'_>,
        bare: JidRef<'_>,
        observer: Observer<'_>,
        component: bool,
    ) -> Result<(), RouterError> {
        let broad = self.rules.transition(bare);
        let bare_eligible = match broad {
            Some(PresenceType::Unavailable) => observer.subscribed || observer.directed_bare,
            Some(PresenceType::Available) => {
                observer.subscribed && !self.rules.after_full.contains(bare.as_str())
            }
            _ => false,
        };
        if let Some(kind) = broad.filter(|_| bare_eligible) {
            return self
                .deliver_external(source, from, bare, kind, component)
                .await;
        }
        let mut destinations = observer.directed_full;
        if (observer.subscribed || observer.directed_bare)
            && let Some(changed) = self.rules.changed_full.get(bare.as_str())
        {
            destinations.extend(changed.iter().copied());
        }
        for destination in destinations {
            let mut arena = Arena::try_new_in(Default::default(), self.router.local.allocator())
                .map_err(|_| RouterError::Unavailable)?;
            let peer =
                Jid::parse_in(destination, &mut arena).map_err(|_| RouterError::InvalidTarget)?;
            let peer = peer.resolve(&arena).map_err(|_| RouterError::Unavailable)?;
            if let Some(kind) = self.rules.transition(peer)
                && (observer.subscribed || kind == PresenceType::Unavailable)
            {
                self.deliver_external(source, from, peer, kind, component)
                    .await?;
            }
        }
        Ok(())
    }

    async fn deliver_external(
        &self,
        source: &BlockingPresenceSource<A>,
        from: JidRef<'_>,
        to: JidRef<'_>,
        kind: PresenceType,
        component: bool,
    ) -> Result<(), RouterError> {
        if source.can_send(kind) && self.allowed(to, kind).await? {
            let stanza = self.stanza(source, from, to, kind)?;
            self.router.route_external_roster_presence(
                stanza,
                component,
                source.restoration_guard(kind),
            )?;
        }
        Ok(())
    }

    async fn allowed(&self, peer: JidRef<'_>, kind: PresenceType) -> Result<bool, RouterError> {
        policy::allows_block_transition(self.router, self.before, self.owner, peer, kind)
            .await
            .map_err(|_| RouterError::Unavailable)
    }

    fn stanza(
        &self,
        source: &BlockingPresenceSource<A>,
        from: JidRef<'_>,
        to: JidRef<'_>,
        kind: PresenceType,
    ) -> Result<RoutedStanza<A>, RouterError> {
        if kind == PresenceType::Available {
            let current = source.current.as_ref().ok_or(RouterError::InvalidTarget)?;
            return self.router.readdress(current, to.as_str());
        }
        let mut arena = Arena::try_new_in(Default::default(), self.router.local.allocator())
            .map_err(|_| RouterError::Unavailable)?;
        let from =
            Jid::parse_in(from.as_str(), &mut arena).map_err(|_| RouterError::InvalidTarget)?;
        let to = Jid::parse_in(to.as_str(), &mut arena).map_err(|_| RouterError::InvalidTarget)?;
        let stanza = Stanza::builder_in(
            StanzaType::Presence(PresenceType::Unavailable),
            StanzaNamespace::Client,
            &mut arena,
        )
        .from(Some(from))
        .map_err(|_| RouterError::Unavailable)?
        .to(Some(to))
        .map_err(|_| RouterError::Unavailable)?
        .build()
        .map_err(|_| RouterError::Unavailable)?;
        Ok(RoutedStanza::from_parts(stanza, arena))
    }
}

fn bare_address(text: &str) -> &str {
    text.split_once('/').map_or(text, |(bare, _)| bare)
}
