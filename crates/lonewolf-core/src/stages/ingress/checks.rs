// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::archive::ArchiveId;
use lonewolf_extension::observer::{MessageEvent, MessageOutcome, MessageRole};
use lonewolf_extension::policy::{Direction, Verdict};
use lonewolf_storage::RedbRead;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{ChunkAllocator, SharedArena};
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
    !parties.same_account
        && (origin
            .sender()
            .is_some_and(|sender| !router.policies(sender.domain()).is_empty())
            || (parties.local_recipient && !router.policies(to.domainpart()).is_empty()))
}

pub(crate) enum Snapshot<'t> {
    Fresh,
    #[cfg_attr(not(test), expect(dead_code))]
    Ordered(&'t RedbRead),
}

pub(crate) async fn check<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
    view: &StanzaRef<'_, SharedArena<A>>,
    parties: &Parties,
    snapshot: Snapshot<'_>,
) -> Result<Verdict, StageFailure> {
    let to = view.to()?.ok_or(StageFailure)?;
    if !policy_applies(stage.router, origin, to, parties) {
        return Ok(Verdict::Allow);
    }
    let from = view.from()?.ok_or(StageFailure)?;
    let Some(account) = origin.sender().or(parties.recipient.as_ref()) else {
        return Ok(Verdict::Allow);
    };
    let checks = [
        policy::Check {
            account,
            direction: Direction::Outbound,
            peer: to,
        },
        policy::Check {
            account: parties.recipient.as_ref().unwrap_or(account),
            direction: Direction::Inbound,
            peer: from,
        },
    ];
    let checks = &checks
        [usize::from(origin.sender().is_none())..if parties.recipient.is_some() { 2 } else { 1 }];
    match snapshot {
        Snapshot::Fresh => policy::evaluate(stage, view.stanza_type(), checks).await,
        Snapshot::Ordered(transaction) => {
            policy::evaluate_in(stage.router, transaction, view.stanza_type(), checks).await
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
