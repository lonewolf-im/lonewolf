// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stanza::StanzaNamespace;
use lonewolf_xmpp::stream::StreamErrorCondition;

use super::ingress::Context;
use super::metrics::{ComponentMetrics, StreamClose};
use crate::router::RoutedStanza;

pub(crate) fn violation_close(condition: StreamErrorCondition) -> StreamClose {
    match condition {
        StreamErrorCondition::ImproperAddressing => StreamClose::ImproperAddressing,
        StreamErrorCondition::InvalidFrom => StreamClose::InvalidFrom,
        StreamErrorCondition::InvalidNamespace => StreamClose::InvalidNamespace,
        StreamErrorCondition::UnsupportedStanzaType => StreamClose::UnsupportedStanzaType,
        StreamErrorCondition::InternalServerError => StreamClose::InternalError,
        _ => StreamClose::ProtocolError,
    }
}

pub(crate) fn validate(
    namespace: StanzaNamespace,
    from: Option<JidRef<'_>>,
    to: Option<JidRef<'_>>,
    domain: &str,
) -> Result<(), StreamErrorCondition> {
    if namespace != StanzaNamespace::ComponentAccept {
        return Err(StreamErrorCondition::InvalidNamespace);
    }
    let (Some(from), Some(_)) = (from, to) else {
        return Err(StreamErrorCondition::ImproperAddressing);
    };
    if from.domainpart() != domain {
        return Err(StreamErrorCondition::InvalidFrom);
    }
    Ok(())
}

pub(crate) async fn process<A, F>(
    event: StreamEvent<A>,
    domain: &str,
    metrics: &ComponentMetrics,
    context: &Context<A>,
    deliver: F,
) -> Result<(), StreamErrorCondition>
where
    A: ChunkAllocator + Clone + 'static,
    F: AsyncFnOnce(RoutedStanza<A>) -> Result<(), StreamErrorCondition>,
{
    match event {
        StreamEvent::Stanza(parsed) => {
            {
                let view = parsed
                    .value()
                    .resolve(parsed.arena())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                validate(
                    view.namespace(),
                    view.from()
                        .map_err(|_| StreamErrorCondition::InternalServerError)?,
                    view.to()
                        .map_err(|_| StreamErrorCondition::InternalServerError)?,
                    domain,
                )?;
                metrics.stanza_received(view.kind());
            }
            let (stanza, mut arena) = parsed.into_parts();
            let stanza = stanza
                .rescope_derive_in(StanzaNamespace::Client, &mut arena)
                .map_err(|_| StreamErrorCondition::InternalServerError)?;
            deliver(RoutedStanza::from_parts(stanza, arena)).await
        }
        StreamEvent::RejectedStanza(parsed) => {
            let rejected = parsed.value();
            if rejected.namespace() != StanzaNamespace::ComponentAccept {
                return Err(StreamErrorCondition::InvalidNamespace);
            }
            if rejected.invalid_from() || rejected.invalid_to() {
                return Err(StreamErrorCondition::ImproperAddressing);
            }
            validate(
                rejected.namespace(),
                rejected
                    .from(parsed.arena())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?,
                rejected
                    .to(parsed.arena())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?,
                domain,
            )?;
            metrics.stanza_received(rejected.kind());
            if rejected.can_reply() {
                let mut output = Arena::try_new_in(Default::default(), context.allocator.clone())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let sender = rejected
                    .from(parsed.arena())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?
                    .ok_or(StreamErrorCondition::ImproperAddressing)?
                    .clone_in(&mut output)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let target = rejected
                    .to(parsed.arena())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?
                    .ok_or(StreamErrorCondition::ImproperAddressing)?
                    .clone_in(&mut output)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let (rejected, mut arena) = parsed.into_parts();
                let sender = sender
                    .resolve(&output)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?
                    .clone_in(&mut arena)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let target = target
                    .resolve(&output)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?
                    .clone_in(&mut arena)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let reply = rejected
                    .error_in(sender, target, &mut arena)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let reply = reply
                    .resolve(&arena)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let reply = reply
                    .rescope_in(StanzaNamespace::Client, &mut output)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let _ = context.registry.reply(
                    domain,
                    context.connection_id,
                    RoutedStanza::from_parts(reply, output),
                );
            }
            Ok(())
        }
        StreamEvent::Element(parsed) => {
            let element = parsed
                .value()
                .resolve(parsed.arena())
                .map_err(|_| StreamErrorCondition::InternalServerError)?;
            if matches!(element.name(), "message" | "iq" | "presence")
                && element.namespace() != "jabber:component:accept"
            {
                Err(StreamErrorCondition::InvalidNamespace)
            } else {
                Err(StreamErrorCondition::UnsupportedStanzaType)
            }
        }
        _ => Err(StreamErrorCondition::UnsupportedStanzaType),
    }
}

#[cfg(test)]
mod tests;
