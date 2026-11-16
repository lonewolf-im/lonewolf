// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{IqType, MessageType, RoutedStanza, StanzaErrorCondition, StanzaType};

use super::registry::ComponentRegistry;
use crate::delivery::WorkHandle;
use crate::router::RouterHandle;
use crate::stages::{StageFailure, ingress::rejection_reply};

pub(crate) struct Context<A: ChunkAllocator> {
    #[allow(dead_code)]
    pub(crate) router: RouterHandle<A>,
    #[allow(dead_code)]
    pub(crate) storage: RedbStorage,
    pub(crate) allocator: A,
    #[allow(dead_code)]
    pub(crate) work: WorkHandle,
    pub(crate) registry: ComponentRegistry<A>,
    pub(crate) connection_id: u64,
}

#[derive(Debug)]
pub(crate) struct IngressFailure;
impl From<StageFailure> for IngressFailure {
    fn from(_: StageFailure) -> Self {
        Self
    }
}

pub(crate) async fn dispatch<A: ChunkAllocator + Clone + 'static>(
    context: &Context<A>,
    domain: &str,
    stanza: RoutedStanza<A>,
) -> Result<(), IngressFailure> {
    let view = stanza.resolve().map_err(|_| IngressFailure)?;
    if matches!(view.stanza_type(), StanzaType::Message(kind) if kind != MessageType::Error)
        || matches!(
            view.stanza_type(),
            StanzaType::Iq(IqType::Get | IqType::Set)
        )
    {
        let condition = StanzaErrorCondition::ServiceUnavailable;
        let reply = rejection_reply(
            &context.allocator,
            &stanza,
            condition,
            None,
            condition.default_text(),
        )?;
        let _ = context.registry.reply(domain, context.connection_id, reply);
    } else {
        tracing::debug!(
            component_domain = domain,
            stanza_kind = view.kind().as_str(),
            "component stanza dropped"
        );
    }
    Ok(())
}
