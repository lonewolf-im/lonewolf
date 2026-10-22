// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::policy::{Direction, PolicyRequest, Verdict};
use lonewolf_extension::presence::PresenceAudience;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{RedbRead, Storage};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidRef};
use lonewolf_xmpp::stanza::StanzaType;

use super::{Stage, StageFailure};
use crate::delivery::{report_failure, report_handler_failure, storage_failure};
use crate::router::{Destination, RouterHandle};

pub(crate) struct Check<'a> {
    pub(crate) account: &'a AccountKey,
    pub(crate) direction: Direction,
    pub(crate) peer: JidRef<'a>,
}

pub(crate) async fn evaluate<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    kind: StanzaType,
    checks: &[Check<'_>],
) -> Result<Verdict, StageFailure> {
    if checks
        .iter()
        .all(|check| stage.router.policies(check.account.domain()).is_empty())
    {
        return Ok(Verdict::Allow);
    }
    let transaction = stage.storage.begin_read().await.map_err(|error| {
        report_failure(
            storage_failure(error, "policy_begin_read"),
            checks[0].account,
        );
        StageFailure
    })?;
    evaluate_in(stage.router, &transaction, kind, checks).await
}

pub(crate) async fn evaluate_in<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    transaction: &RedbRead,
    kind: StanzaType,
    checks: &[Check<'_>],
) -> Result<Verdict, StageFailure> {
    let mut verdict = Verdict::Allow;
    let mut decided_by = None;
    'checks: for check in checks {
        for (name, handler) in router.policies(check.account.domain()) {
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
            let strictest = verdict.strictest(next);
            if strictest != verdict {
                decided_by = Some((check, name));
            }
            verdict = strictest;
            if verdict == Verdict::Drop {
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
    if router.policies(owner.domain()).is_empty()
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
            .iter()
            .any(|request| has_policy(request.sender.as_str()))
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
    let mut allowed = Vec::with_capacity(audience.pending.len());
    for request in &audience.pending {
        let jid = Jid::parse_in(request.sender.as_str(), &mut scratch)?;
        let peer = jid.resolve(&scratch)?;
        if peer.bare().as_str() == owner.as_str() {
            allowed.push(true);
            continue;
        }
        let checks = [Check {
            account: owner,
            direction: Direction::Inbound,
            peer,
        }];
        allowed.push(evaluate_in(router, transaction, kind, &checks).await? == Verdict::Allow);
    }
    retain_allowed(&mut audience.pending, allowed);
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
