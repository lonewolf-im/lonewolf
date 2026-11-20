// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

use lonewolf_extension::delivery::{HandlerError, SessionId};
use lonewolf_extension::message::{StoreOutcome, UndeliverableMessage};
use lonewolf_extension::policy::{Direction, Verdict};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{RedbRead, Storage};
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{MessageType, StanzaErrorCondition, StanzaType};

use super::{Stage, StageFailure};
use crate::delivery::{
    Pending, StoredDelivery, commit_and_store, report_failure, report_handler_failure,
    storage_failure,
};
use crate::order::Ticket;
use crate::router::local::SessionLiveness;
use crate::router::metrics::MessageOutcome;
use crate::router::{Admitted, Destination, RoutedStanza, RouterError, RouterHandle};
use crate::stages::ingress::checks::{self, Snapshot};
use crate::stages::policy::{self, Check, Selection};

#[derive(Clone, Copy)]
pub(crate) enum MissingRecipientPolicy {
    Discard,
    Reject,
}

pub(crate) enum DeliveryOutcome<A: ChunkAllocator> {
    Routed {
        admitted: Admitted,
        copies: Option<Vec<SessionId>>,
    },
    Stored {
        admitted: Admitted,
        copies: Option<Vec<SessionId>>,
    },
    /// RFC 6121 or the offline fallback discards the message without a reply.
    Discarded,
    Retired,
    Policy {
        stanza: RoutedStanza<A>,
        verdict: Verdict,
    },
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
    Retired,
    Policy {
        stanza: RoutedStanza<A>,
        verdict: Verdict,
    },
    Committed(Pending<Result<crate::delivery::StoreAdmission, crate::delivery::EffectsError>>),
}

pub(crate) enum MessageRecipients {
    Allowed(Option<Vec<SessionId>>),
    Refused(Verdict),
}

pub(crate) async fn concrete_recipients<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    allocator: &A,
    snapshot: Option<&RedbRead>,
    source: Option<&AccountKey>,
    recipient: Option<&AccountKey>,
    stanza: &RoutedStanza<A>,
) -> Result<MessageRecipients, StageFailure> {
    let (Some(snapshot), Some(source), Some(recipient)) = (snapshot, source, recipient) else {
        return Ok(MessageRecipients::Allowed(None));
    };
    if source == recipient || !Selection::Explicit.configured(router, source.domain()) {
        return Ok(MessageRecipients::Allowed(None));
    }
    let view = stanza.resolve()?;
    let kind = view.stanza_type();
    let StanzaType::Message(message_kind) = kind else {
        return Err(StageFailure);
    };
    let to = view.to()?.ok_or(StageFailure)?;
    if to.is_bare() && matches!(message_kind, MessageType::Error | MessageType::Groupchat) {
        return Ok(MessageRecipients::Allowed(None));
    }
    let targets = router
        .message_targets(recipient, to.resourcepart(), message_kind)
        .await
        .map_err(|_| StageFailure)?;
    if targets.is_empty() {
        return Ok(MessageRecipients::Allowed(Some(Vec::new())));
    }
    let has_direct = targets.iter().any(|target| target.direct);
    let mut allowed = Vec::with_capacity(targets.len());
    let mut has_allowed_original = false;
    let mut refusal = Verdict::Allow;
    let mut arena = Arena::try_new_in(ArenaConfig::default(), allocator.clone())?;
    for target in targets {
        let verdict = if target.direct {
            Verdict::Allow
        } else {
            let jid = Jid::from_trusted_parts_in(
                to.localpart(),
                to.domainpart(),
                Some(&target.resource),
                &mut arena,
            )?;
            let checks = [Check {
                account: source,
                direction: Direction::Outbound,
                peer: jid.resolve(&arena)?,
            }];
            policy::evaluate_selected_in(router, snapshot, kind, &checks, Selection::Explicit)
                .await?
        };
        if verdict == Verdict::Allow {
            allowed.push(target.session);
            has_allowed_original |= target.direct || (!has_direct && target.bare);
        } else if !has_direct && target.bare {
            refusal = refusal.strictest(verdict);
        }
    }
    if !has_allowed_original && refusal != Verdict::Allow {
        return Ok(MessageRecipients::Refused(refusal));
    }
    Ok(MessageRecipients::Allowed(Some(allowed)))
}

pub(crate) struct DeliveryAdmission<'a> {
    pub(crate) source: Option<&'a AccountKey>,
    pub(crate) liveness: Option<&'a SessionLiveness>,
    pub(crate) ticket: Option<Ticket>,
    pub(crate) recipients: Option<Vec<SessionId>>,
}

/// Requires a stanza with an authenticated sender.
pub(crate) async fn deliver_addressed<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    routed: RoutedStanza<A>,
    kind: MessageType,
    missing_recipient: MissingRecipientPolicy,
    admission: DeliveryAdmission<'_>,
) -> Result<DeliveryOutcome<A>, StageFailure> {
    let result = deliver_unrecorded(stage, routed, kind, missing_recipient, admission).await;
    let outcome = match &result {
        Ok(DeliveryOutcome::Routed { .. }) => MessageOutcome::Routed,
        Ok(DeliveryOutcome::Stored { .. }) => MessageOutcome::Stored,
        Ok(DeliveryOutcome::Discarded) => MessageOutcome::Discarded,
        Ok(DeliveryOutcome::Retired | DeliveryOutcome::Policy { .. }) => return result,
        Ok(DeliveryOutcome::Rejected { .. }) => MessageOutcome::Rejected,
        Err(_) => MessageOutcome::Failed,
    };
    stage.router.metrics().message(outcome);
    result
}

#[cfg(test)]
pub(crate) async fn deliver<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    stanza: RoutedStanza<A>,
    kind: MessageType,
    missing_recipient: MissingRecipientPolicy,
) -> Result<DeliveryOutcome<A>, StageFailure> {
    deliver_addressed(
        stage,
        stanza,
        kind,
        missing_recipient,
        DeliveryAdmission {
            source: None,
            liveness: None,
            ticket: None,
            recipients: None,
        },
    )
    .await
}

async fn deliver_unrecorded<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    routed: RoutedStanza<A>,
    kind: MessageType,
    missing_recipient: MissingRecipientPolicy,
    admission: DeliveryAdmission<'_>,
) -> Result<DeliveryOutcome<A>, StageFailure> {
    let DeliveryAdmission {
        source,
        liveness,
        ticket,
        recipients,
    } = admission;
    if liveness.is_some_and(|session| !session.is_alive()) {
        return Ok(DeliveryOutcome::Retired);
    }
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
    let route = stage
        .router
        .route_addressed_message(routed.clone(), liveness.cloned(), recipients.as_deref())
        .await;
    let admitted = match route {
        Ok(Some(admitted)) => admitted,
        Ok(None) => return Ok(DeliveryOutcome::Retired),
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
                drop(ticket);
                return store(stage, routed, missing_recipient, source, liveness).await;
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
    Ok(DeliveryOutcome::Routed {
        admitted,
        copies: recipients,
    })
}

async fn store<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    routed: RoutedStanza<A>,
    missing_recipient: MissingRecipientPolicy,
    source: Option<&AccountKey>,
    liveness: Option<&SessionLiveness>,
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
        if liveness.is_some_and(|session| !session.is_alive()) {
            return Ok(StorePreparation::Retired);
        }
        let snapshot = if checks::explicit_applies(stage.router, source, Some(&recipient)) {
            let snapshot = stage.storage.begin_read().await.map_err(|error| {
                report_failure(
                    storage_failure(error, "offline_store_policy_begin_read"),
                    &recipient,
                );
                StageFailure
            })?;
            let verdict = checks::check_selected(
                (stage.router, stage.storage),
                source,
                Some(&recipient),
                &routed.resolve()?,
                None,
                Snapshot::Ordered(&snapshot),
                Selection::Explicit,
            )
            .await?;
            if verdict != Verdict::Allow {
                return Ok(StorePreparation::Policy {
                    stanza: routed,
                    verdict,
                });
            }
            source
                .filter(|source| Selection::Explicit.configured(stage.router, source.domain()))
                .map(|_| snapshot)
        } else {
            None
        };
        if liveness.is_some_and(|session| !session.is_alive()) {
            return Ok(StorePreparation::Retired);
        }
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
        if liveness.is_some_and(|session| !session.is_alive()) {
            return Ok(StorePreparation::Retired);
        }
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
            Ok(StoreOutcome::NoRecipient) => {
                drop(transaction);
                match missing_recipient {
                    MissingRecipientPolicy::Discard => StorePreparation::Discarded,
                    MissingRecipientPolicy::Reject => StorePreparation::Rejected {
                        stanza: routed,
                        error: StanzaErrorCondition::ServiceUnavailable.into(),
                    },
                }
            }
            Ok(StoreOutcome::Stored(sequence)) => StorePreparation::Committed(commit_and_store(
                stage.work.start(),
                stage.router.clone(),
                transaction,
                handler,
                StoredDelivery {
                    source: source.cloned(),
                    recipient,
                    sequence,
                    stanza: routed,
                    bytes,
                    policy: snapshot.map(|snapshot| (stage.allocator.clone(), snapshot)),
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
        StorePreparation::Retired => Ok(DeliveryOutcome::Retired),
        StorePreparation::Policy { stanza, verdict } => {
            Ok(DeliveryOutcome::Policy { stanza, verdict })
        }
        StorePreparation::Committed(pending) => {
            let admission = pending
                .finished()
                .await
                .ok_or(StageFailure)?
                .map_err(|_| StageFailure)?;
            Ok(DeliveryOutcome::Stored {
                admitted: admission.admitted,
                copies: admission.copies,
            })
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
