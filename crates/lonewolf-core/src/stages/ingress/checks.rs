// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::archive::ArchiveId;
use lonewolf_extension::observer::{MessageEvent, MessageOutcome, MessageRole};
use lonewolf_extension::policy::{Direction, Verdict};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{RedbRead, RedbStorage, Storage};
use lonewolf_util::arena::{ArenaRead, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaKind, StanzaRef};

use super::Origin;
use crate::delivery::{RouterDelivery, report_failure, storage_failure};
use crate::order::Ticket;
use crate::router::local::SessionHandle;
use crate::router::{Destination, RouterHandle};
use crate::stages::message::DeliveryOutcome;
use crate::stages::{Stage, StageFailure, observe, policy};

pub(crate) struct Parties {
    pub(crate) local_recipient: bool,
    pub(crate) same_account: bool,
    pub(crate) recipient: Option<AccountKey>,
}

pub(crate) fn parties<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    origin: &Origin<'_, A>,
    to: JidRef<'_>,
    kind: StanzaKind,
) -> Result<Parties, StageFailure> {
    parties_for(router, origin.sender(), to, kind)
}

pub(crate) fn parties_for<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    sender: Option<&AccountKey>,
    to: JidRef<'_>,
    kind: StanzaKind,
) -> Result<Parties, StageFailure> {
    let local_recipient = matches!(
        router.destination(to),
        Destination::Account | Destination::Resource
    );
    let same_account = sender.is_some_and(|sender| sender.as_str() == to.bare().as_str());
    let recipient_needed = local_recipient
        && ((!same_account && !router.policies(to.domainpart()).is_empty())
            || (kind == StanzaKind::Message
                && (router.archive_handler(to.domainpart()).is_some()
                    || !router.message_observers(to.domainpart()).is_empty())));
    Ok(Parties {
        local_recipient,
        same_account,
        recipient: recipient_needed
            .then(|| AccountKey::try_from(to.bare()))
            .transpose()?,
    })
}

pub(crate) fn policy_applies<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    origin: &Origin<'_, A>,
    to: JidRef<'_>,
    parties: &Parties,
) -> bool {
    policy_applies_for(
        router,
        origin.sender().map(|sender| sender.domain()),
        parties.same_account,
    ) || policy_applies_for(
        router,
        parties.local_recipient.then_some(to.domainpart()),
        parties.same_account,
    )
}

pub(crate) fn policy_applies_for<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    domain: Option<&str>,
    same_account: bool,
) -> bool {
    !same_account && domain.is_some_and(|domain| !router.policies(domain).is_empty())
}

pub(crate) enum Snapshot<'t> {
    Fresh,
    Ordered(&'t RedbRead),
}

pub(crate) async fn fix_explicit_snapshot<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    storage: &RedbStorage,
    source: Option<&AccountKey>,
    recipient: Option<&AccountKey>,
) -> Result<Option<(RedbRead, Ticket)>, StageFailure> {
    if !explicit_applies(router, source, recipient) {
        return Ok(None);
    }
    let identity = source.or(recipient).ok_or(StageFailure)?;
    let accounts = source.into_iter().chain(recipient).cloned().collect();
    router
        .order()
        .fix(accounts, storage.begin_read())
        .await
        .map(Some)
        .map_err(|error| {
            report_failure(
                storage_failure(error, "addressed_policy_begin_read"),
                identity,
            );
            StageFailure
        })
}

pub(crate) fn explicit_applies<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    source: Option<&AccountKey>,
    recipient: Option<&AccountKey>,
) -> bool {
    source != recipient
        && source
            .into_iter()
            .chain(recipient)
            .any(|account| policy::Selection::Explicit.configured(router, account.domain()))
}

pub(crate) async fn check<A: ChunkAllocator + Clone, R: ArenaRead>(
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
    view: &StanzaRef<'_, R>,
    parties: &Parties,
    snapshot: Snapshot<'_>,
) -> Result<Verdict, StageFailure> {
    let to = view.to()?.ok_or(StageFailure)?;
    if !policy_applies(stage.router, origin, to, parties) {
        return Ok(Verdict::Allow);
    }
    check_from(
        stage.router,
        stage.storage,
        origin.sender(),
        parties.recipient.as_ref(),
        view,
        None,
        snapshot,
    )
    .await
}

pub(crate) async fn check_from<A: ChunkAllocator + Clone, R: ArenaRead>(
    router: &RouterHandle<A>,
    storage: &RedbStorage,
    source: Option<&AccountKey>,
    recipient: Option<&AccountKey>,
    view: &StanzaRef<'_, R>,
    authenticated_from: Option<JidRef<'_>>,
    snapshot: Snapshot<'_>,
) -> Result<Verdict, StageFailure> {
    check_selected(
        (router, storage),
        source,
        recipient,
        view,
        authenticated_from,
        snapshot,
        policy::Selection::All,
    )
    .await
}

pub(crate) async fn check_selected<A: ChunkAllocator + Clone, R: ArenaRead>(
    (router, storage): (&RouterHandle<A>, &RedbStorage),
    source: Option<&AccountKey>,
    recipient: Option<&AccountKey>,
    view: &StanzaRef<'_, R>,
    authenticated_from: Option<JidRef<'_>>,
    snapshot: Snapshot<'_>,
    selection: policy::Selection,
) -> Result<Verdict, StageFailure> {
    let to = view
        .to()?
        .or_else(|| {
            (view.kind() == StanzaKind::Iq)
                .then_some(authenticated_from)
                .flatten()
                .map(|sender| sender.bare())
        })
        .ok_or(StageFailure)?;
    if source.is_some_and(|source| source.as_str() == to.bare().as_str())
        || (source.is_none_or(|source| !selection.configured(router, source.domain()))
            && recipient.is_none_or(|recipient| !selection.configured(router, recipient.domain())))
    {
        return Ok(Verdict::Allow);
    }
    let from = match authenticated_from {
        Some(sender) => sender,
        None => view.from()?.ok_or(StageFailure)?,
    };
    let Some(account) = source.or(recipient) else {
        return Ok(Verdict::Allow);
    };
    let checks = [
        policy::Check {
            account: source.unwrap_or(account),
            direction: Direction::Outbound,
            peer: to,
        },
        policy::Check {
            account: recipient.unwrap_or(account),
            direction: Direction::Inbound,
            peer: from,
        },
    ];
    let checks = &checks[usize::from(source.is_none())..if recipient.is_some() { 2 } else { 1 }];
    match snapshot {
        Snapshot::Fresh => {
            policy::evaluate_selected(router, storage, view.stanza_type(), checks, selection).await
        }
        Snapshot::Ordered(transaction) => {
            policy::evaluate_selected_in(router, transaction, view.stanza_type(), checks, selection)
                .await
        }
    }
}

#[cfg(test)]
pub(crate) async fn observe_message<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
    parties: &Parties,
    stanza: &RoutedStanza<A>,
    outcome: &DeliveryOutcome<A>,
    archived: (Option<ArchiveId>, Option<ArchiveId>),
    rejection: Option<&RoutedStanza<A>>,
) {
    let session = origin.session().map(crate::router::Registration::handle);
    observe_from(
        stage,
        session.as_ref(),
        parties,
        stanza,
        outcome,
        archived,
        rejection,
    )
    .await;
}

pub(crate) async fn observe_from<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    session: Option<&SessionHandle<A>>,
    parties: &Parties,
    stanza: &RoutedStanza<A>,
    outcome: &DeliveryOutcome<A>,
    archived: (Option<ArchiveId>, Option<ArchiveId>),
    rejection: Option<&RoutedStanza<A>>,
) {
    let admitted = match outcome {
        DeliveryOutcome::Routed { admitted } | DeliveryOutcome::Stored { admitted } => {
            admitted.as_slice()
        }
        DeliveryOutcome::Retired
        | DeliveryOutcome::Policy { .. }
        | DeliveryOutcome::Discarded
        | DeliveryOutcome::Rejected { .. } => &[],
    };
    let sender = session.map(SessionHandle::session_id);
    let combined = if parties.same_account {
        let mut holders = Vec::with_capacity(1 + admitted.len());
        holders.extend(sender);
        holders.extend_from_slice(admitted);
        holders
    } else {
        Vec::new()
    };
    let delivery = RouterDelivery::with_session(stage.router, stage.allocator, session.cloned());
    let outcome = MessageOutcome::from(outcome);
    if let Some(session) = session {
        observe::message(
            stage,
            &delivery,
            MessageEvent {
                account: session.account(),
                role: MessageRole::Sent,
                stanza,
                outcome,
                archived: archived.0,
                holders: if parties.same_account {
                    &combined
                } else {
                    sender.as_slice()
                },
                rejection,
            },
        )
        .await;
    }
    if matches!(outcome, MessageOutcome::Routed | MessageOutcome::Stored)
        && let Some(recipient) = parties.recipient.as_ref()
    {
        observe::message(
            stage,
            &delivery,
            MessageEvent {
                account: recipient,
                role: MessageRole::Received,
                stanza,
                outcome,
                archived: archived.1,
                holders: if parties.same_account {
                    &combined
                } else {
                    admitted
                },
                rejection: None,
            },
        )
        .await;
    }
}
