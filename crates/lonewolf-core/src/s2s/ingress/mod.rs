// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{IqType, MessageType, StanzaErrorCondition, StanzaType};

use super::log_domain;
use crate::delivery::WorkHandle;
use crate::router::{RoutedStanza, RouterHandle};
use crate::stages::StageFailure;

pub(crate) struct InboundPeer {
    pub(crate) local: Box<str>,
    pub(crate) remote: Box<str>,
    pub(crate) connection_id: u64,
}

#[derive(Clone)]
pub(crate) struct IngressServices<A: ChunkAllocator> {
    pub(crate) router: RouterHandle<A>,
    pub(crate) storage: RedbStorage,
    pub(crate) allocator: A,
}

pub(crate) struct IngressContext<A: ChunkAllocator> {
    pub(crate) router: RouterHandle<A>,
    #[allow(dead_code)]
    pub(crate) storage: RedbStorage,
    pub(crate) allocator: A,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) work: WorkHandle,
}

#[derive(Debug)]
pub(crate) struct IngressFailure;

impl From<StageFailure> for IngressFailure {
    fn from(_: StageFailure) -> Self {
        Self
    }
}

fn reply<A: ChunkAllocator + Clone>(
    stanza: &RoutedStanza<A>,
    allocator: A,
) -> Result<Option<RoutedStanza<A>>, IngressFailure> {
    let source = stanza.resolve().map_err(|_| IngressFailure)?;
    if !matches!(source.stanza_type(), StanzaType::Message(kind) if kind != MessageType::Error)
        && !matches!(
            source.stanza_type(),
            StanzaType::Iq(IqType::Get | IqType::Set)
        )
    {
        return Ok(None);
    }
    let mut arena = Arena::try_new_in(Default::default(), allocator).map_err(|_| IngressFailure)?;
    let source = source.clone_in(&mut arena).map_err(|_| IngressFailure)?;
    let condition = StanzaErrorCondition::ServiceUnavailable;
    let reply = source
        .error_reply_described_in(&mut arena, condition, None, condition.default_text())
        .map_err(|_| IngressFailure)?
        .build()
        .map_err(|_| IngressFailure)?;
    Ok(Some(RoutedStanza::from_parts(reply, arena)))
}

pub(crate) async fn dispatch<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    peer: &InboundPeer,
    stanza: RoutedStanza<A>,
) -> Result<(), IngressFailure> {
    if let Some(reply) = reply(&stanza, context.allocator.clone())? {
        let _ = context.router.route_remote(reply);
    } else {
        let view = stanza.resolve().map_err(|_| IngressFailure)?;
        tracing::debug!(stanza_kind = view.kind().as_str(), remote_domain = %log_domain(&peer.remote), "s2s stanza discarded");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
