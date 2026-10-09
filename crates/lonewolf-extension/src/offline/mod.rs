// SPDX-License-Identifier: Apache-2.0

mod xml;

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::{OfflineError, OfflineReads, OfflineSequence, OfflineWrites};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{MessageType, StanzaErrorCondition, StanzaType};

use crate::account::AccountHandler;
use crate::delivery::{Failure, FailureKind, HandlerError, HostLookup};
use crate::message::{Backlog, MessageHandler, StoreFuture, StoreOutcome, UndeliverableMessage};
use crate::presence::PresenceFuture;
use crate::{Effects, Extension, ExtensionFuture, RegistrationError, Slots};

pub const NAME: &str = "offline";
const DEFAULT_MAX_MESSAGES_PER_ACCOUNT: NonZeroU32 = NonZeroU32::new(100).unwrap();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfflineLimits {
    pub max_messages_per_account: NonZeroU32,
}

impl Default for OfflineLimits {
    fn default() -> Self {
        Self {
            max_messages_per_account: DEFAULT_MAX_MESSAGES_PER_ACCOUNT,
        }
    }
}

pub struct Offline {
    limits: BTreeMap<Box<str>, OfflineLimits>,
}

impl Offline {
    /// Hosts without a limits entry use the default.
    pub fn new(limits: BTreeMap<Box<str>, OfflineLimits>) -> Self {
        Self { limits }
    }
}

impl<A: ChunkAllocator, S: Storage> Extension<A, S> for Offline {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, S>,
    ) -> Result<(), RegistrationError> {
        slots.account(self.clone());
        slots.offline(self)
    }
}

impl<A: ChunkAllocator, S: Storage> AccountHandler<A, S> for Offline {
    fn forget_account<'a>(
        &'a self,
        transaction: &'a mut S::Write,
        account: &'a AccountKey,
        _hosts: &'a dyn HostLookup,
    ) -> ExtensionFuture<'a, Result<Effects<A>, HandlerError>> {
        Box::pin(async move {
            transaction
                .clear_offline_messages(account)
                .await
                .map_err(|error| offline_error(error, "offline_clear"))?;
            Ok(Effects::none())
        })
    }
}

impl<A: ChunkAllocator, S: Storage> MessageHandler<A, S> for Offline {
    fn store<'a>(
        &'a self,
        message: UndeliverableMessage<'a, A>,
        transaction: &'a mut S::Write,
        scratch: &'a mut Arena<A>,
    ) -> StoreFuture<'a> {
        Box::pin(async move {
            let view = message
                .stanza
                .resolve()
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            if !matches!(
                view.stanza_type(),
                StanzaType::Message(MessageType::Normal | MessageType::Chat)
            ) {
                tracing::info!(
                    operation = "store",
                    outcome = "rejected",
                    reason = "unsupported_type",
                    recipient_jid = ?message.recipient.as_str(),
                    "offline message policy decided"
                );
                return Err(StanzaErrorCondition::ServiceUnavailable.into());
            }
            if xml::chat_state_only(&view)? {
                tracing::info!(
                    operation = "store",
                    outcome = "discarded",
                    reason = "chat_state_only",
                    recipient_jid = ?message.recipient.as_str(),
                    "offline message policy decided"
                );
                return Ok(StoreOutcome::Discarded);
            }
            let limits = self
                .limits
                .get(message.recipient.domain())
                .copied()
                .unwrap_or_default();
            let message_count = transaction
                .offline_count(message.recipient)
                .await
                .map_err(|error| store_error(error, message.recipient, "offline_count"))?;
            if message_count >= limits.max_messages_per_account.get() as usize {
                tracing::info!(
                    operation = "store",
                    outcome = "rejected",
                    reason = "quota_exceeded",
                    message_count,
                    limit = limits.max_messages_per_account.get(),
                    recipient_jid = ?message.recipient.as_str(),
                    "offline message policy decided"
                );
                return Err(StanzaErrorCondition::ResourceConstraint.into());
            }
            let (stored_at, stanza) = xml::stamped(&message, scratch)?;
            let sequence = transaction
                .push_offline_message(message.recipient, stored_at, stanza.as_bytes())
                .await
                .map_err(|error| store_error(error, message.recipient, "offline_push"))?;
            Ok(StoreOutcome::Stored(sequence))
        })
    }

    fn backlog<'a>(
        &'a self,
        account: &'a AccountKey,
        transaction: &'a S::Read,
    ) -> PresenceFuture<'a, Option<Backlog>> {
        Box::pin(async move {
            let messages = transaction
                .offline_messages(account)
                .await
                .map_err(|error| offline_error(error, "offline_backlog"))?;
            tracing::info!(
                operation = "backlog",
                outcome = if messages.is_empty() {
                    "empty"
                } else {
                    "available"
                },
                message_count = messages.len(),
                owner_jid = ?account.as_str(),
                "offline backlog snapshot read"
            );
            let Some(last) = messages.last() else {
                return Ok(None);
            };
            let through = last.sequence;
            Ok(Some(Backlog { messages, through }))
        })
    }

    fn acknowledge<'a>(
        &'a self,
        account: &'a AccountKey,
        through: OfflineSequence,
        transaction: &'a mut S::Write,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            transaction
                .remove_offline_messages_through(account, through)
                .await
                .map_err(|error| offline_error(error, "offline_acknowledge"))?;
            Ok(())
        })
    }

    fn acknowledge_one<'a>(
        &'a self,
        account: &'a AccountKey,
        sequence: OfflineSequence,
        transaction: &'a mut S::Write,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            transaction
                .remove_offline_message(account, sequence)
                .await
                .map_err(|error| offline_error(error, "offline_acknowledge"))?;
            Ok(())
        })
    }
}

fn store_error(
    error: OfflineError,
    recipient: &AccountKey,
    operation: &'static str,
) -> HandlerError {
    let reason = match &error {
        OfflineError::NoAccount => "no_account",
        OfflineError::ValueTooLarge => "value_too_large",
        OfflineError::Storage(_) => return offline_error(error, operation),
    };
    tracing::info!(
        operation = "store",
        outcome = "rejected",
        reason,
        recipient_jid = ?recipient.as_str(),
        "offline message policy decided"
    );
    offline_error(error, operation)
}

fn offline_error(error: OfflineError, operation: &'static str) -> HandlerError {
    match error {
        OfflineError::NoAccount => StanzaErrorCondition::ServiceUnavailable.into(),
        OfflineError::ValueTooLarge => StanzaErrorCondition::ResourceConstraint.into(),
        OfflineError::Storage(error) => HandlerError::Internal {
            condition: StanzaErrorCondition::InternalServerError,
            failure: Failure {
                kind: FailureKind::Storage(error.kind()),
                operation,
            },
        },
    }
}

#[cfg(test)]
mod tests;
