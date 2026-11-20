// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::policy::{Direction, PolicyHandler, PolicyRequest, Verdict};
use lonewolf_extension::presence::PresenceAudience;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::PendingPage;
use lonewolf_storage::{RedbRead, RedbStorage, Storage};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidRef};
use lonewolf_xmpp::stanza::{PresenceType, StanzaType};

use super::{Stage, StageFailure};
use crate::delivery::{report_failure, report_handler_failure, storage_failure};
use crate::router::{Destination, RouterHandle};

pub(crate) struct Check<'a> {
    pub(crate) account: &'a AccountKey,
    pub(crate) direction: Direction,
    pub(crate) peer: JidRef<'a>,
}

#[derive(Clone, Copy)]
pub(crate) enum Selection {
    All,
    Explicit,
    Standard,
}

impl Selection {
    fn includes(self, handler: &dyn PolicyHandler<RedbStorage>) -> bool {
        match self {
            Self::All => true,
            Self::Explicit => handler.checks_explicit_addresses(),
            Self::Standard => !handler.checks_explicit_addresses(),
        }
    }

    pub(crate) fn configured<A: ChunkAllocator + Clone>(
        self,
        router: &RouterHandle<A>,
        domain: &str,
    ) -> bool {
        router
            .policies(domain)
            .iter()
            .any(|(_, handler)| self.includes(handler.as_ref()))
    }
}

pub(crate) async fn evaluate<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    kind: StanzaType,
    checks: &[Check<'_>],
) -> Result<Verdict, StageFailure> {
    evaluate_with(stage.router, stage.storage, kind, checks).await
}

pub(crate) async fn evaluate_with<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    storage: &RedbStorage,
    kind: StanzaType,
    checks: &[Check<'_>],
) -> Result<Verdict, StageFailure> {
    evaluate_selected(router, storage, kind, checks, Selection::All).await
}

pub(crate) async fn evaluate_selected<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    storage: &RedbStorage,
    kind: StanzaType,
    checks: &[Check<'_>],
    selection: Selection,
) -> Result<Verdict, StageFailure> {
    if checks
        .iter()
        .all(|check| !selection.configured(router, check.account.domain()))
    {
        return Ok(Verdict::Allow);
    }
    let transaction = storage.begin_read().await.map_err(|error| {
        report_failure(
            storage_failure(error, "policy_begin_read"),
            checks[0].account,
        );
        StageFailure
    })?;
    evaluate_selected_in(router, &transaction, kind, checks, selection).await
}

pub(crate) async fn evaluate_in<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    transaction: &RedbRead,
    kind: StanzaType,
    checks: &[Check<'_>],
) -> Result<Verdict, StageFailure> {
    evaluate_selected_in(router, transaction, kind, checks, Selection::All).await
}

pub(crate) async fn evaluate_selected_in<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    transaction: &RedbRead,
    kind: StanzaType,
    checks: &[Check<'_>],
    selection: Selection,
) -> Result<Verdict, StageFailure> {
    let mut verdict = Verdict::Allow;
    let mut decided_by = None;
    'checks: for check in checks {
        for (name, handler) in router.policies(check.account.domain()) {
            if !selection.includes(handler.as_ref()) {
                continue;
            }
            let next = match handler
                .check(
                    PolicyRequest {
                        account: check.account,
                        direction: check.direction,
                        peer: check.peer,
                        kind,
                    },
                    transaction,
                )
                .await
            {
                Ok(verdict) => verdict,
                Err(error) => {
                    report_handler_failure(&error, check.account);
                    Verdict::Reject {
                        condition: error.condition(),
                        application: None,
                        text: Some(error.text()),
                    }
                }
            };
            let next = match (check.direction, next) {
                (Direction::Inbound, Verdict::OutboundBlocked) => Verdict::Drop,
                (_, next) => next,
            };
            let strictest = verdict.strictest(next);
            if strictest != verdict {
                decided_by = Some((check, name));
            }
            verdict = strictest;
            if matches!(verdict, Verdict::Drop | Verdict::OutboundBlocked) {
                break 'checks;
            }
        }
    }
    let verdict = verdict.for_stanza(kind);
    if let Some((check, name)) = decided_by {
        tracing::debug!(
            account_jid = ?check.account.as_str(),
            direction = ?check.direction,
            stanza_kind = kind.kind().as_str(),
            extension = name,
            outcome = if verdict == Verdict::Drop { "dropped" } else { "rejected" },
            "policy decided"
        );
    }
    Ok(verdict)
}

pub(crate) struct PresencePolicy<'a, A: ChunkAllocator> {
    pub(crate) router: &'a RouterHandle<A>,
    pub(crate) snapshot: &'a RedbRead,
}

impl<A: ChunkAllocator + Clone> PresencePolicy<'_, A> {
    pub(crate) fn applies(&self, from: JidRef<'_>, to: JidRef<'_>) -> bool {
        from.bare() != to.bare()
            && [from, to].into_iter().any(|jid| {
                self.router.is_local_host(jid.domainpart())
                    && jid.localpart().is_some()
                    && Selection::Explicit.configured(self.router, jid.domainpart())
            })
    }

    pub(crate) async fn allows_outbound(
        &self,
        sender: &AccountKey,
        recipient: JidRef<'_>,
        kind: StanzaType,
    ) -> Result<bool, StageFailure> {
        let checks = [Check {
            account: sender,
            direction: Direction::Outbound,
            peer: recipient,
        }];
        Ok(evaluate_selected_in(
            self.router,
            self.snapshot,
            kind,
            &checks,
            Selection::Explicit,
        )
        .await?
            == Verdict::Allow)
    }

    pub(crate) async fn allows(
        &self,
        from: JidRef<'_>,
        to: JidRef<'_>,
        kind: StanzaType,
    ) -> Result<bool, StageFailure> {
        if !self.applies(from, to) {
            return Ok(true);
        }
        let local = |jid: JidRef<'_>| {
            (self.router.is_local_host(jid.domainpart()) && jid.localpart().is_some())
                .then(|| AccountKey::try_from(jid.bare()))
                .transpose()
        };
        let sender = local(from)?;
        let recipient = local(to)?;
        let account = sender.as_ref().or(recipient.as_ref()).ok_or(StageFailure)?;
        let checks = [
            Check {
                account: sender.as_ref().unwrap_or(account),
                direction: Direction::Outbound,
                peer: to,
            },
            Check {
                account: recipient.as_ref().unwrap_or(account),
                direction: Direction::Inbound,
                peer: from,
            },
        ];
        let checks =
            &checks[usize::from(sender.is_none())..if recipient.is_some() { 2 } else { 1 }];
        Ok(evaluate_selected_in(
            self.router,
            self.snapshot,
            kind,
            checks,
            Selection::Explicit,
        )
        .await?
            == Verdict::Allow)
    }
}

/// Uses the audience snapshot so policy checks keep its ordering guarantees.
pub(crate) async fn filter_audience<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    transaction: &RedbRead,
    allocator: &A,
    owner: &AccountKey,
    sender: JidRef<'_>,
    kind: StanzaType,
    audience: &mut PresenceAudience,
) -> Result<(), StageFailure> {
    let has_policy = |text: &str| {
        let bare = text.split_once('/').map_or(text, |(bare, _)| bare);
        let domain = bare.split_once('@').map_or(bare, |(_, domain)| domain);
        !router.policies(domain).is_empty()
    };
    let owner_has_policy = !router.policies(owner.domain()).is_empty();
    if !owner_has_policy
        && !audience
            .subscribers
            .iter()
            .any(|jid| has_policy(jid.as_str()))
        && !audience
            .contacts
            .iter()
            .any(|account| has_policy(account.as_str()))
        && !audience
            .pending
            .as_ref()
            .is_some_and(|page| page.iter().any(|(sender, _)| has_policy(sender.as_str())))
    {
        return Ok(());
    }
    let mut scratch = Arena::try_new_in(Default::default(), allocator.clone())?;
    let mut allowed = Vec::with_capacity(audience.subscribers.len());
    for subscriber in &audience.subscribers {
        let jid = Jid::parse_in(subscriber.as_str(), &mut scratch)?;
        let peer = jid.resolve(&scratch)?;
        if peer.bare().as_str() == owner.as_str() {
            allowed.push(true);
            continue;
        }
        let recipient = if router.destination(peer) == Destination::Account {
            Some(AccountKey::try_from(peer)?)
        } else {
            None
        };
        let checks = [
            Check {
                account: owner,
                direction: Direction::Outbound,
                peer,
            },
            Check {
                account: recipient.as_ref().unwrap_or(owner),
                direction: Direction::Inbound,
                peer: sender,
            },
        ];
        let checks = &checks[..if recipient.is_some() { 2 } else { 1 }];
        allowed.push(evaluate_in(router, transaction, kind, checks).await? == Verdict::Allow);
    }
    retain_allowed(&mut audience.subscribers, allowed);
    let mut allowed = Vec::with_capacity(audience.contacts.len());
    for contact in &audience.contacts {
        let jid = Jid::parse_in(contact.as_str(), &mut scratch)?;
        let peer = jid.resolve(&scratch)?;
        if contact == owner {
            allowed.push(true);
            continue;
        }
        let checks = [
            Check {
                account: contact,
                direction: Direction::Outbound,
                peer: sender,
            },
            Check {
                account: owner,
                direction: Direction::Inbound,
                peer,
            },
        ];
        allowed.push(evaluate_in(router, transaction, kind, &checks).await? == Verdict::Allow);
    }
    retain_allowed(&mut audience.contacts, allowed);
    let federated = router.federation_enabled();
    if owner_has_policy
        && (federated
            || audience
                .probes
                .iter()
                .any(|contact| router.is_component_domain(contact.domain())))
    {
        let mut allowed = Vec::with_capacity(audience.probes.len());
        for contact in &audience.probes {
            let domain = contact.domain();
            if router.is_local_host(domain) || (!federated && !router.is_component_domain(domain)) {
                allowed.push(true);
                continue;
            }
            let jid = Jid::parse_in(contact.as_str(), &mut scratch)?;
            let peer = jid.resolve(&scratch)?.bare();
            let checks = [Check {
                account: owner,
                direction: Direction::Outbound,
                peer,
            }];
            allowed.push(
                evaluate_in(
                    router,
                    transaction,
                    StanzaType::Presence(PresenceType::Probe),
                    &checks,
                )
                .await?
                    == Verdict::Allow,
            );
        }
        retain_allowed(&mut audience.probes, allowed);
    }
    if let Some(page) = audience.pending.as_mut() {
        filter_pending(
            router,
            transaction,
            allocator,
            (owner, sender.resourcepart()),
            kind,
            page,
        )
        .await?;
    }
    Ok(())
}

/// Drops refused requests using the same snapshot that supplied the page.
pub(crate) async fn filter_pending<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    transaction: &RedbRead,
    allocator: &A,
    (owner, resource): (&AccountKey, Option<&str>),
    kind: StanzaType,
    page: &mut PendingPage,
) -> Result<(), StageFailure> {
    let has_sender_policy = || {
        router.has_explicit_presence_policy()
            && page
                .iter()
                .any(|(sender, _)| Selection::Explicit.configured(router, sender.domain()))
    };
    if page.is_empty() || (router.policies(owner.domain()).is_empty() && !has_sender_policy()) {
        return Ok(());
    }
    let mut scratch = Arena::try_new_in(Default::default(), allocator.clone())?;
    let to = Jid::from_trusted_parts_in(
        Some(owner.username()),
        owner.domain(),
        resource,
        &mut scratch,
    )?;
    let policy = PresencePolicy {
        router,
        snapshot: transaction,
    };
    let mut allowed = Vec::with_capacity(page.len());
    for (sender, _) in page.iter() {
        let jid = Jid::parse_in(sender.as_str(), &mut scratch)?;
        let peer = jid.resolve(&scratch)?;
        if peer.bare().as_str() == owner.as_str() {
            allowed.push(true);
            continue;
        }
        if !policy
            .allows(
                peer,
                to.resolve(&scratch)?,
                StanzaType::Presence(PresenceType::Subscribe),
            )
            .await?
        {
            allowed.push(false);
            continue;
        }
        let checks = [Check {
            account: owner,
            direction: Direction::Inbound,
            peer,
        }];
        allowed.push(
            evaluate_selected_in(router, transaction, kind, &checks, Selection::Standard).await?
                == Verdict::Allow,
        );
    }
    let mut allowed = allowed.into_iter();
    page.retain(|_, _| allowed.next() == Some(true));
    Ok(())
}

fn retain_allowed<T>(members: &mut Vec<T>, allowed: Vec<bool>) {
    let mut index = 0;
    members.retain(|_| {
        let keep = allowed[index];
        index += 1;
        keep
    });
}
