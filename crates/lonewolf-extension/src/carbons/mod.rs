// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{StanzaErrorCondition, StanzaErrorText, StanzaNamespace};

use crate::delivery::{Delivery, DeliveryFuture, HandlerError, SessionTag, TagChange};
use crate::discovery::DiscoScope;
use crate::iq::{IqError, IqRequest, SessionIqHandler, SessionIqReply};
use crate::observer::{MessageEvent, MessageObserver, MessageOutcome, MessageRole};
use crate::{Extension, RegistrationError, Slots};

pub const NAME: &str = "carbons";
pub const NAMESPACE: &str = "urn:xmpp:carbons:2";
pub const RULES_FEATURE: &str = "urn:xmpp:carbons:rules:0";

pub mod copy;
pub mod rules;

#[derive(Default)]
pub struct Carbons;

impl<A: ChunkAllocator, S: Storage> Extension<A, S> for Carbons {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, S>,
    ) -> Result<(), RegistrationError> {
        slots.session_iq(NAMESPACE, "enable", self.clone())?;
        slots.session_iq(NAMESPACE, "disable", self.clone())?;
        slots.disco_feature(DiscoScope::Server, NAMESPACE);
        slots.disco_feature(DiscoScope::Server, RULES_FEATURE);
        slots.message_observer(self);
        Ok(())
    }
}

impl<A: ChunkAllocator> SessionIqHandler<A> for Carbons {
    fn set(
        &self,
        request: IqRequest<'_, A>,
        _response: &mut Arena<A>,
    ) -> Result<SessionIqReply, IqError> {
        if request.target.as_str() != request.sender.bare().as_str() {
            return Err(HandlerError::described(
                StanzaErrorCondition::NotAllowed,
                StanzaErrorText::Static(
                    "Carbons can be changed only for your own session. Omit the destination or use your bare JID.",
                ),
            ).into());
        }
        let (change, operation) = match request.payload.name() {
            "enable" => (TagChange::Insert(SessionTag::Carbons), "carbons_enable"),
            "disable" => (TagChange::Remove(SessionTag::Carbons), "carbons_disable"),
            _ => return Err(StanzaErrorCondition::ServiceUnavailable.into()),
        };
        tracing::debug!(
            operation,
            outcome = "requested",
            session_jid = ?request.sender.as_str(),
            "carbons state change requested"
        );
        Ok(SessionIqReply {
            payload: None,
            change: Some(change),
        })
    }
}

impl<A: ChunkAllocator, S: Storage> MessageObserver<A, S> for Carbons {
    fn observe<'a>(
        &'a self,
        event: MessageEvent<'a, A>,
        _storage: &'a S,
        delivery: &'a dyn Delivery<A>,
    ) -> DeliveryFuture<'a> {
        Box::pin(async move {
            let view = event.stanza.resolve()?;
            if view.namespace() != StanzaNamespace::Client
                || !rules::eligible(&view, event.role, event.account)?
                || (event.role == MessageRole::Received
                    && !matches!(
                        event.outcome,
                        MessageOutcome::Routed | MessageOutcome::Stored
                    ))
            {
                return Ok(());
            }
            let originals = [
                Some(copy::Original {
                    stanza: event.stanza,
                    role: event.role,
                    archived: (event.role == MessageRole::Sent)
                        .then_some(event.archived)
                        .flatten(),
                }),
                if event.role == MessageRole::Sent && event.outcome == MessageOutcome::Rejected {
                    event.rejection.map(|stanza| copy::Original {
                        stanza,
                        role: MessageRole::Received,
                        archived: None,
                    })
                } else {
                    None
                },
            ];
            for original in originals.into_iter().flatten() {
                delivery
                    .copy_to_tagged(
                        event.account,
                        SessionTag::Carbons,
                        event.holders,
                        Box::new(move |targets| {
                            let copies = copy::build(
                                event.account,
                                original,
                                delivery,
                                targets,
                                delivery.arena()?,
                            )?;
                            if copies.is_empty() {
                                tracing::debug!(
                                    operation = "carbons_copy",
                                    outcome = "skipped",
                                    reason = "tree_limit",
                                    account_jid = ?event.account.as_str(),
                                    "carbons copies skipped"
                                );
                            }
                            Ok(copies)
                        }),
                    )
                    .await?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
