// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::policy::Verdict;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{
    ApplicationCondition, MessageType, RoutedStanza, StanzaErrorCondition, StanzaErrorText,
};

use super::checks::{self, Snapshot};
use super::{Origin, outbound_blocked_reply, rejection_reply};
use crate::router::local::SessionHandle;
use crate::stages::message::{self, DeliveryOutcome, MissingRecipientPolicy};
use crate::stages::{Stage, StageFailure, archive};

pub(crate) enum Reply<A: ChunkAllocator> {
    Error {
        stanza: RoutedStanza<A>,
        condition: StanzaErrorCondition,
        application: Option<ApplicationCondition>,
        text: StanzaErrorText,
    },
    Built(RoutedStanza<A>),
}

pub(crate) enum MessageDisposition<A: ChunkAllocator> {
    Done,
    Reply(Reply<A>),
}

pub(crate) async fn handle<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
    routed: RoutedStanza<A>,
    kind: MessageType,
) -> Result<MessageDisposition<A>, StageFailure> {
    let session = origin.session().map(crate::router::Registration::handle);
    let missing_recipient = if matches!(origin, Origin::Service { .. }) {
        MissingRecipientPolicy::Reject
    } else {
        MissingRecipientPolicy::Discard
    };
    handle_from(stage, session.as_ref(), routed, kind, missing_recipient).await
}

pub(crate) async fn handle_from<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    session: Option<&SessionHandle<A>>,
    routed: RoutedStanza<A>,
    kind: MessageType,
    missing_recipient: MissingRecipientPolicy,
) -> Result<MessageDisposition<A>, StageFailure> {
    let view = routed.resolve()?;
    let to = view.to()?.ok_or(StageFailure)?;
    let sender = session.map(SessionHandle::account);
    let parties = checks::parties_for(stage.router, sender, to, view.kind())?;
    let ordered = checks::fix_explicit_snapshot(
        stage.router,
        stage.storage,
        sender,
        parties.recipient.as_ref(),
    )
    .await?;
    let snapshot = ordered
        .as_ref()
        .map_or(Snapshot::Fresh, |(read, _)| Snapshot::Ordered(read));
    let verdict = checks::check_from(
        stage.router,
        stage.storage,
        sender,
        parties.recipient.as_ref(),
        &view,
        None,
        snapshot,
    )
    .await?;
    if verdict != Verdict::Allow {
        return policy_disposition(stage.allocator, routed, verdict);
    }
    let mut admission = ordered.map(|(_, ticket)| ticket);
    if let Some(ticket) = &mut admission {
        ticket.turn().await;
    }
    let liveness = session.map(SessionHandle::liveness);
    if liveness.is_some_and(|session| !session.is_alive()) {
        return Ok(MessageDisposition::Done);
    }
    let archive_needed = sender
        .is_some_and(|sender| stage.router.archive_handler(sender.domain()).is_some())
        || (parties.local_recipient && stage.router.archive_handler(to.domainpart()).is_some());
    let archived = if archive_needed {
        archive::archive_addressed(stage, routed, sender, parties.recipient.as_ref(), liveness)
            .await?
    } else {
        archive::ArchiveStep::Accepted(archive::Archived {
            stanza: routed,
            sent: None,
            received: None,
        })
    };
    let archive::Archived {
        stanza,
        sent,
        received,
    } = match archived {
        archive::ArchiveStep::Accepted(archived) => archived,
        archive::ArchiveStep::Rejected {
            stanza,
            condition,
            text,
        } => {
            return Ok(MessageDisposition::Reply(Reply::Error {
                stanza,
                condition,
                application: None,
                text,
            }));
        }
    };
    let view = stanza.resolve()?;
    let to = view.to()?.ok_or(StageFailure)?;
    let observed = (sender
        .is_some_and(|sender| !stage.router.message_observers(sender.domain()).is_empty())
        || (parties.local_recipient
            && !stage.router.message_observers(to.domainpart()).is_empty()))
    .then(|| stanza.clone());
    let outcome = message::deliver_addressed(
        stage,
        stanza,
        kind,
        missing_recipient,
        sender,
        liveness,
        admission,
    )
    .await?;
    let outcome = match outcome {
        DeliveryOutcome::Retired => return Ok(MessageDisposition::Done),
        DeliveryOutcome::Policy { stanza, verdict } => {
            return policy_disposition(stage.allocator, stanza, verdict);
        }
        accepted => accepted,
    };
    let rejection = match (&observed, session, &outcome) {
        (
            Some(_),
            Some(_),
            DeliveryOutcome::Rejected {
                stanza,
                condition,
                text,
            },
        ) => Some(rejection_reply(
            stage.allocator,
            stanza,
            *condition,
            None,
            *text,
        )?),
        _ => None,
    };
    if let Some(observed) = observed {
        checks::observe_from(
            stage,
            session,
            &parties,
            &observed,
            &outcome,
            (sent, received),
            rejection.as_ref(),
        )
        .await;
    }
    Ok(match outcome {
        DeliveryOutcome::Rejected {
            stanza,
            condition,
            text,
        } => MessageDisposition::Reply(match rejection {
            Some(reply) => Reply::Built(reply),
            None => Reply::Error {
                stanza,
                condition,
                application: None,
                text,
            },
        }),
        DeliveryOutcome::Routed { .. }
        | DeliveryOutcome::Stored { .. }
        | DeliveryOutcome::Discarded
        | DeliveryOutcome::Retired
        | DeliveryOutcome::Policy { .. } => MessageDisposition::Done,
    })
}

fn policy_disposition<A: ChunkAllocator + Clone>(
    allocator: &A,
    stanza: RoutedStanza<A>,
    verdict: Verdict,
) -> Result<MessageDisposition<A>, StageFailure> {
    Ok(match verdict {
        Verdict::Allow | Verdict::Drop => MessageDisposition::Done,
        Verdict::OutboundBlocked => {
            MessageDisposition::Reply(Reply::Built(outbound_blocked_reply(allocator, &stanza)?))
        }
        Verdict::Reject {
            condition,
            application,
            text,
        } => MessageDisposition::Reply(Reply::Error {
            stanza,
            condition,
            application,
            text: text.unwrap_or_else(|| condition.default_text()),
        }),
    })
}
