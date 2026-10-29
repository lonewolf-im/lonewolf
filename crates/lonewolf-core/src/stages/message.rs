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
use crate::router::metrics::MessageOutcome;
use crate::router::{Admitted, Destination, RoutedStanza, RouterError};

pub(crate) enum DeliveryOutcome<A: ChunkAllocator> {
    Routed {
        admitted: Admitted,
    },
    Stored {
        admitted: Admitted,
    },
    /// RFC 6121 or the offline fallback discards the message without a reply.
    Discarded,
    Rejected {
        stanza: RoutedStanza<A>,
        condition: StanzaErrorCondition,
        text: lonewolf_xmpp::stanza::StanzaErrorText,
    },
}

enum StorePreparation<A: ChunkAllocator> {
    Rejected {
        stanza: RoutedStanza<A>,
        error: HandlerError,
    },
    Discarded,
    Committed(Pending<Result<Admitted, crate::delivery::EffectsError>>),
}

/// Requires a stanza with an authenticated sender.
pub(crate) async fn deliver<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    routed: RoutedStanza<A>,
    kind: MessageType,
) -> Result<DeliveryOutcome<A>, StageFailure> {
    let result = deliver_unrecorded(stage, routed, kind).await;
    let outcome = match &result {
        Ok(DeliveryOutcome::Routed { .. }) => MessageOutcome::Routed,
        Ok(DeliveryOutcome::Stored { .. }) => MessageOutcome::Stored,
        Ok(DeliveryOutcome::Discarded) => MessageOutcome::Discarded,
        Ok(DeliveryOutcome::Rejected { .. }) => MessageOutcome::Rejected,
        Err(_) => MessageOutcome::Failed,
    };
    stage.router.metrics().message(outcome);
    result
}

async fn deliver_unrecorded<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    routed: RoutedStanza<A>,
    kind: MessageType,
) -> Result<DeliveryOutcome<A>, StageFailure> {
    let (bare, destination) = {
        let view = routed.resolve()?;
        let to = view.to()?.ok_or(StageFailure)?;
        (to.resourcepart().is_none(), stage.router.destination(to))
    };
    if bare
        && kind == MessageType::Error
        && !(destination == Destination::Remote && stage.router.federation_enabled())
    {
        return Ok(DeliveryOutcome::Discarded);
    }
    if bare && kind == MessageType::Groupchat && destination != Destination::Remote {
        return Ok(DeliveryOutcome::Rejected {
            stanza: routed,
            condition: StanzaErrorCondition::ServiceUnavailable,
            text: StanzaErrorCondition::ServiceUnavailable.default_text(),
        });
    }
    let admitted = match stage.router.route_message(routed.clone()).await {
        Ok(admitted) => admitted,
        Err(error) => {
            if kind == MessageType::Error
                || (bare && kind == MessageType::Headline && error == RouterError::NotFound)
                || (kind == MessageType::Headline && error == RouterError::Offline)
            {
                return Ok(DeliveryOutcome::Discarded);
            }
            if error == RouterError::Offline
                && matches!(kind, MessageType::Normal | MessageType::Chat)
            {
                return store(stage, routed).await;
            }
            let condition = match error {
                RouterError::Busy
                | RouterError::ResourceLimit
                | RouterError::DirectedPresenceLimit => StanzaErrorCondition::ResourceConstraint,
                RouterError::InvalidTarget | RouterError::InvalidResource => {
                    StanzaErrorCondition::BadRequest
                }
                RouterError::RemoteUnsupported if destination == Destination::Remote => {
                    StanzaErrorCondition::RemoteServerNotFound
                }
                RouterError::RemoteNotFound => StanzaErrorCondition::RemoteServerNotFound,
                RouterError::RemoteTimeout => StanzaErrorCondition::RemoteServerTimeout,
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
                text: condition.default_text(),
            });
        }
    };
    Ok(DeliveryOutcome::Routed { admitted })
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
            text: StanzaErrorCondition::ServiceUnavailable.default_text(),
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
            Ok(StoreOutcome::Discarded | StoreOutcome::NoRecipient) => {
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
            text: error.text(),
        }),
        StorePreparation::Discarded => Ok(DeliveryOutcome::Discarded),
        StorePreparation::Committed(pending) => {
            let admitted = pending
                .finished()
                .await
                .ok_or(StageFailure)?
                .map_err(|_| StageFailure)?;
            Ok(DeliveryOutcome::Stored { admitted })
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
