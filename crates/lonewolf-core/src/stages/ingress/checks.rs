// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::archive::ArchiveId;
use lonewolf_extension::observer::{MessageEvent, MessageOutcome, MessageRole};
use lonewolf_extension::policy::{Direction, Verdict};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{RedbRead, RedbStorage};
use lonewolf_util::arena::{ArenaRead, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaKind, StanzaRef};

use super::Origin;
use crate::delivery::RouterDelivery;
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
    let local_recipient = matches!(
        router.destination(to),
        Destination::Account | Destination::Resource
    );
    let same_account = origin
        .sender()
        .is_some_and(|sender| sender.as_str() == to.bare().as_str());
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
        || (source.is_none_or(|source| router.policies(source.domain()).is_empty())
            && recipient.is_none_or(|recipient| router.policies(recipient.domain()).is_empty()))
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
        Snapshot::Fresh => policy::evaluate_with(router, storage, view.stanza_type(), checks).await,
        Snapshot::Ordered(transaction) => {
            policy::evaluate_in(router, transaction, view.stanza_type(), checks).await
        }
    }
}

pub(crate) async fn observe_message<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
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
        DeliveryOutcome::Discarded | DeliveryOutcome::Rejected { .. } => &[],
    };
    let sender = origin.session().map(|session| session.session_id());
    let combined = if parties.same_account {
        let mut holders = Vec::with_capacity(1 + admitted.len());
        holders.extend(sender);
        holders.extend_from_slice(admitted);
        holders
    } else {
        Vec::new()
    };
    let delivery = RouterDelivery::new(stage.router, stage.allocator, origin.session());
    let outcome = MessageOutcome::from(outcome);
    if let Some(session) = origin.session() {
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
