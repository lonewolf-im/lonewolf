// SPDX-License-Identifier: Apache-2.0

mod xml;

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::{OfflineError, OfflineReads, OfflineSequence, OfflineWrites};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{MessageType, StanzaErrorCondition, StanzaType};

use crate::delivery::{HandlerError, HostLookup};
use crate::iq::IqHandler;
use crate::message::{Backlog, MessageHandler, StoreFuture, StoreOutcome, UndeliverableMessage};
use crate::presence::{PresenceFuture, PresenceHandler};
use crate::{Effects, Extension, ExtensionFuture};

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

impl<A: ChunkAllocator, S: Storage> IqHandler<A, S> for Offline {}

impl<A: ChunkAllocator, S: Storage> PresenceHandler<A, S> for Offline {}

impl<A: ChunkAllocator, S: Storage> Extension<A, S> for Offline {
    fn name(&self) -> &'static str {
        NAME
    }

    fn stores_messages(&self) -> bool {
        true
    }

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
                .map_err(offline_error)?;
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
                return Err(StanzaErrorCondition::ServiceUnavailable.into());
            }
            if xml::chat_state_only(&view)? {
                return Ok(StoreOutcome::Discarded);
            }
            let limits = self
                .limits
                .get(message.recipient.domain())
                .copied()
                .unwrap_or_default();
            if transaction
                .offline_count(message.recipient)
                .await
                .map_err(offline_error)?
                >= limits.max_messages_per_account.get() as usize
            {
                return Err(StanzaErrorCondition::ResourceConstraint.into());
            }
            let (stored_at, stanza) = xml::stamped(&message, scratch)?;
            let sequence = transaction
                .push_offline_message(message.recipient, stored_at, stanza.as_bytes())
                .await
                .map_err(offline_error)?;
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
                .map_err(offline_error)?;
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
                .map_err(offline_error)?;
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
                .map_err(offline_error)?;
            Ok(())
        })
    }
}

fn offline_error(error: OfflineError) -> StanzaErrorCondition {
    match error {
        OfflineError::NoAccount => StanzaErrorCondition::ServiceUnavailable,
        OfflineError::ValueTooLarge => StanzaErrorCondition::ResourceConstraint,
        OfflineError::Storage(_) => StanzaErrorCondition::InternalServerError,
    }
}

#[cfg(test)]
mod tests;
