// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::message::{StoreOutcome, UndeliverableMessage};
use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::stanza::{MessageType, StanzaErrorCondition};

use super::{Stage, StageFailure};
use crate::delivery::{
    Pending, StoredDelivery, commit_and_store, report_failure, report_handler_failure,
    storage_failure,
};
use crate::router::{RoutedStanza, RouterError};

pub(crate) enum DeliveryOutcome<A: ChunkAllocator> {
    /// A session mailbox admitted the message.
    Routed,
    /// The offline fallback committed the message.
    Stored,
    /// RFC 6121 or the offline fallback discards the message without a reply.
    Discarded,
    /// The sender must receive this error.
    Rejected {
        stanza: RoutedStanza<A>,
        condition: StanzaErrorCondition,
    },
}

enum StorePreparation<A: ChunkAllocator> {
    Rejected {
        stanza: RoutedStanza<A>,
        error: HandlerError,
    },
    Discarded,
    Committed(Pending<Result<(), crate::delivery::EffectsError>>),
}

/// Delivers a message with an authenticated `from` to its local destination.
pub(crate) async fn deliver<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    routed: RoutedStanza<A>,
    kind: MessageType,
) -> Result<DeliveryOutcome<A>, StageFailure> {
    let bare = routed
        .resolve()?
        .to()?
        .ok_or(StageFailure)?
        .resourcepart()
        .is_none();
    if bare && kind == MessageType::Error {
        return Ok(DeliveryOutcome::Discarded);
    }
    if bare && kind == MessageType::Groupchat {
        return Ok(DeliveryOutcome::Rejected {
            stanza: routed,
            condition: StanzaErrorCondition::ServiceUnavailable,
        });
    }
    if let Err(error) = stage.router.route_message(routed.clone()).await {
        if kind == MessageType::Error
            || (bare && kind == MessageType::Headline && error == RouterError::NotFound)
            || (kind == MessageType::Headline && error == RouterError::Offline)
        {
            return Ok(DeliveryOutcome::Discarded);
        }
        if error == RouterError::Offline && matches!(kind, MessageType::Normal | MessageType::Chat)
        {
            return store(stage, routed).await;
        }
        let condition = match error {
            RouterError::Busy | RouterError::ResourceLimit | RouterError::DirectedPresenceLimit => {
                StanzaErrorCondition::ResourceConstraint
            }
            RouterError::InvalidTarget | RouterError::InvalidResource => {
                StanzaErrorCondition::BadRequest
            }
            RouterError::NotFound | RouterError::Offline | RouterError::RemoteUnsupported => {
                StanzaErrorCondition::ServiceUnavailable
            }
            RouterError::Unavailable | RouterError::Stopped => {
                return Err(StageFailure);
            }
        };
        return Ok(DeliveryOutcome::Rejected {
            stanza: routed,
            condition,
        });
    }
    Ok(DeliveryOutcome::Routed)
}

async fn store<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    routed: RoutedStanza<A>,
) -> Result<DeliveryOutcome<A>, StageFailure> {
    let recipient = AccountKey::try_from(routed.resolve()?.to()?.ok_or(StageFailure)?.bare())
        .map_err(|_| StageFailure)?;
    let Some(handler) = stage.router.message_handler(recipient.domain()).cloned() else {
        tracing::info!(
            operation = "store",
            outcome = "rejected",
            reason = "missing_handler",
            recipient_jid = ?recipient.as_str(),
            "offline message policy decided"
        );
        return Ok(DeliveryOutcome::Rejected {
            stanza: routed,
            condition: StanzaErrorCondition::ServiceUnavailable,
        });
    };
    let bytes = if tracing::enabled!(tracing::Level::INFO) {
        stanza_bytes(&routed)?
    } else {
        0
    };
    let prepare = async {
        let mut transaction = stage.storage.begin_write().await.map_err(|error| {
            report_failure(
                storage_failure(error, "offline_store_begin_write"),
                &recipient,
            );
            StageFailure
        })?;
        let mut scratch = Arena::try_new_in(ArenaConfig::default(), stage.allocator.clone())?;
        let outcome = handler
            .store(
                UndeliverableMessage {
                    recipient: &recipient,
                    stanza: &routed,
                    received_at: SystemTime::now(),
                },
                &mut transaction,
                &mut scratch,
            )
            .await;
        drop(scratch);
        Ok::<_, StageFailure>(match outcome {
            Err(error) => {
                drop(transaction);
                report_handler_failure(&error, &recipient);
                StorePreparation::Rejected {
                    stanza: routed,
                    error,
                }
            }
            Ok(StoreOutcome::Discarded) => {
                drop(transaction);
                StorePreparation::Discarded
            }
            Ok(StoreOutcome::Stored(sequence)) => StorePreparation::Committed(commit_and_store(
                stage.work.start(),
                stage.router.clone(),
                transaction,
                handler,
                StoredDelivery {
                    recipient,
                    sequence,
                    stanza: routed,
                    bytes,
                },
            )),
        })
    };
    match prepare.await? {
        StorePreparation::Rejected { stanza, error } => Ok(DeliveryOutcome::Rejected {
            stanza,
            condition: error.condition(),
        }),
        StorePreparation::Discarded => Ok(DeliveryOutcome::Discarded),
        StorePreparation::Committed(pending) => {
            pending
                .finished()
                .await
                .ok_or(StageFailure)?
                .map_err(|_| StageFailure)?;
            Ok(DeliveryOutcome::Stored)
        }
    }
}

fn stanza_bytes<A: ChunkAllocator>(stanza: &RoutedStanza<A>) -> Result<usize, StageFailure> {
    struct Counter(usize);
    impl std::fmt::Write for Counter {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            self.0 = self.0.checked_add(text.len()).ok_or(std::fmt::Error)?;
            Ok(())
        }
    }
    let mut counter = Counter(0);
    stanza
        .resolve()?
        .write_xml(&mut counter)
        .map_err(|_| StageFailure)?;
    Ok(counter.0)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
