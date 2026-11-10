// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::policy::Verdict;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{
    ApplicationCondition, MessageType, RoutedStanza, StanzaErrorCondition, StanzaErrorText,
};

use super::checks::{self, Snapshot};
use super::{Origin, rejection_reply};
use crate::stages::message::{self, DeliveryOutcome};
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
    let view = routed.resolve()?;
    let to = view.to()?.ok_or(StageFailure)?;
    let parties = checks::parties(stage.router, origin, to, view.kind())?;
    match checks::check(stage, origin, &view, &parties, Snapshot::Fresh).await? {
        Verdict::Allow => {}
        Verdict::Drop => return Ok(MessageDisposition::Done),
        Verdict::Reject {
            condition,
            application,
            text,
        } => {
            return Ok(MessageDisposition::Reply(Reply::Error {
                stanza: routed,
                condition,
                application,
                text: text.unwrap_or_else(|| condition.default_text()),
            }));
        }
    }
    let archive_needed = origin
        .sender()
        .is_some_and(|sender| stage.router.archive_handler(sender.domain()).is_some())
        || (parties.local_recipient && stage.router.archive_handler(to.domainpart()).is_some());
    let archived = if archive_needed {
        archive::archive(stage, routed, origin.sender(), parties.recipient.as_ref()).await?
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
    let observed = (origin
        .sender()
        .is_some_and(|sender| !stage.router.message_observers(sender.domain()).is_empty())
        || (parties.local_recipient
            && !stage.router.message_observers(to.domainpart()).is_empty()))
    .then(|| stanza.clone());
    let outcome = message::deliver(stage, stanza, kind).await?;
    let rejection = match (&observed, origin.session(), &outcome) {
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
        checks::observe_message(
            stage,
            origin,
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
        | DeliveryOutcome::Discarded => MessageDisposition::Done,
    })
}
