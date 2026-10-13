// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::time::SystemTime;

use lonewolf_extension::archive::{ArchiveDirection, ArchiveId, ArchiveOutcome, ArchiveRequest};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::stanza::{Element, MessageType, StanzaErrorCondition, StanzaType};

use super::{Stage, StageFailure};
use crate::delivery::{report_failure, report_handler_failure, storage_failure};
use crate::router::RoutedStanza;

pub(crate) const STANZA_ID_NAMESPACE: &str = "urn:xmpp:sid:0";

pub(crate) struct Archived<A: ChunkAllocator> {
    pub(crate) stanza: RoutedStanza<A>,
    pub(crate) sent: Option<ArchiveId>,
    pub(crate) received: Option<ArchiveId>,
}

pub(crate) enum ArchiveStep<A: ChunkAllocator> {
    Accepted(Archived<A>),
    Rejected {
        stanza: RoutedStanza<A>,
        condition: StanzaErrorCondition,
    },
}

/// Commits the local sender's and recipient's entries in one transaction before routing.
pub(crate) async fn archive<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    routed: RoutedStanza<A>,
    sender: Option<&AccountKey>,
    recipient: Option<&AccountKey>,
) -> Result<ArchiveStep<A>, StageFailure> {
    let view = routed.resolve()?;
    if view.stanza_type() == StanzaType::Message(MessageType::Error) {
        return Ok(ArchiveStep::Accepted(Archived {
            stanza: routed,
            sent: None,
            received: None,
        }));
    }
    let recipient = recipient.filter(|recipient| Some(*recipient) != sender);
    let sent_handler = sender.and_then(|owner| stage.router.archive_handler(owner.domain()));
    let received_handler = recipient.and_then(|owner| stage.router.archive_handler(owner.domain()));
    if sent_handler.is_none() && received_handler.is_none() {
        return Ok(ArchiveStep::Accepted(Archived {
            stanza: routed,
            sent: None,
            received: None,
        }));
    }
    let received_at = SystemTime::now();
    let sent_request = sender
        .zip(sent_handler)
        .map(|(owner, handler)| {
            let request = ArchiveRequest {
                owner,
                direction: ArchiveDirection::Sent,
                peer: view.to()?.ok_or(StageFailure)?,
                stanza: &routed,
                received_at,
            };
            Ok::<_, StageFailure>(handler.selects(&request).then_some((handler, request)))
        })
        .transpose()?
        .flatten();
    let received_request = recipient
        .zip(received_handler)
        .map(|(owner, handler)| {
            let request = ArchiveRequest {
                owner,
                direction: ArchiveDirection::Received,
                peer: view.from()?.ok_or(StageFailure)?,
                stanza: &routed,
                received_at,
            };
            Ok::<_, StageFailure>(handler.selects(&request).then_some((handler, request)))
        })
        .transpose()?
        .flatten();
    let mut sent = None;
    let mut received = None;
    if sent_request.is_some() || received_request.is_some() {
        let owner = sent_request
            .as_ref()
            .or(received_request.as_ref())
            .ok_or(StageFailure)?
            .1
            .owner;
        let mut transaction = stage.storage.begin_write().await.map_err(|error| {
            report_failure(storage_failure(error, "archive_begin_write"), owner);
            StageFailure
        })?;
        let mut scratch = Arena::try_new_in(ArenaConfig::default(), stage.allocator.clone())?;
        let mut failure = None;
        for (selected, id) in [(sent_request, &mut sent), (received_request, &mut received)] {
            if let Some((handler, request)) = selected {
                let owner = request.owner;
                match handler
                    .archive(request, &mut transaction, &mut scratch)
                    .await
                {
                    Ok(ArchiveOutcome::Archived(archived)) => *id = Some(archived),
                    Ok(ArchiveOutcome::Skipped) => {}
                    Err(error) => {
                        failure = Some((owner, error));
                        break;
                    }
                }
            }
        }
        if let Some((owner, error)) = failure {
            drop(transaction);
            report_handler_failure(&error, owner);
            return Ok(ArchiveStep::Rejected {
                stanza: routed,
                condition: error.condition(),
            });
        }
        if sent.is_some() || received.is_some() {
            transaction.commit().await.map_err(|error| {
                report_failure(storage_failure(error, "archive_commit"), owner);
                StageFailure
            })?;
        }
    }
    if let Some(recipient) = recipient.filter(|_| received_handler.is_some()) {
        let spoofed = |child: &lonewolf_xmpp::stanza::ElementRef<'_, _>| {
            Ok::<_, lonewolf_util::arena::HandleError>(
                child.name() == "stanza-id"
                    && child.namespace() == STANZA_ID_NAMESPACE
                    && child.attribute("by", "")? == Some(recipient.as_str()),
            )
        };
        let mut has_spoofed = false;
        for child in view.children()? {
            if spoofed(&child?)? {
                has_spoofed = true;
                break;
            }
        }
        if has_spoofed || received.is_some() {
            let mut arena = Arena::try_new_in(ArenaConfig::default(), stage.allocator.clone())?;
            let child = if let Some(id) = received {
                let mut buffer = [0; 20];
                let mut output = buffer.as_mut_slice();
                write!(&mut output, "{id}").map_err(|_| StageFailure)?;
                let written = 20 - output.len();
                let id = std::str::from_utf8(&buffer[..written]).map_err(|_| StageFailure)?;
                Some(
                    Element::builder_in("stanza-id", STANZA_ID_NAMESPACE, &mut arena)?
                        .attribute("id", "", id)?
                        .attribute("by", "", recipient.as_str())?
                        .build()?,
                )
            } else {
                None
            };
            let mut builder =
                view.to_builder_in_filtered(&mut arena, |child| Ok(!spoofed(child)?))?;
            if let Some(child) = child {
                builder = builder.child(child)?;
            }
            let stanza = builder.build()?;
            return Ok(ArchiveStep::Accepted(Archived {
                stanza: RoutedStanza::from_parts(stanza, arena),
                sent,
                received,
            }));
        }
    }
    Ok(ArchiveStep::Accepted(Archived {
        stanza: routed,
        sent,
        received,
    }))
}
