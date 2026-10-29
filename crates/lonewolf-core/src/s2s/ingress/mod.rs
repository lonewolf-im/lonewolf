// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{
    ApplicationCondition, IqType, MessageType, StanzaErrorCondition, StanzaErrorText, StanzaType,
};

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
    pub(crate) storage: RedbStorage,
    pub(crate) allocator: A,
    pub(crate) work: WorkHandle,
}

#[derive(Debug)]
pub(crate) struct IngressFailure;

impl From<StageFailure> for IngressFailure {
    fn from(_: StageFailure) -> Self {
        Self
    }
}

mod iq;
mod message;
mod presence;

pub(crate) fn reply_error<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    original: &RoutedStanza<A>,
    condition: StanzaErrorCondition,
    application: Option<ApplicationCondition>,
    text: StanzaErrorText,
) -> Result<(), IngressFailure> {
    let source = original.resolve().map_err(|_| IngressFailure)?;
    if !matches!(source.stanza_type(), StanzaType::Message(kind) if kind != MessageType::Error)
        && !matches!(
            source.stanza_type(),
            StanzaType::Iq(IqType::Get | IqType::Set)
        )
    {
        return Ok(());
    }
    let mut arena = Arena::try_new_in(Default::default(), context.allocator.clone())
        .map_err(|_| IngressFailure)?;
    let source = source.clone_in(&mut arena).map_err(|_| IngressFailure)?;
    let reply = source
        .error_reply_described_in(&mut arena, condition, application, text)
        .map_err(|_| IngressFailure)?
        .build()
        .map_err(|_| IngressFailure)?;
    let _ = context
        .router
        .route_remote(RoutedStanza::from_parts(reply, arena));
    Ok(())
}

pub(crate) async fn dispatch<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    peer: &InboundPeer,
    stanza: RoutedStanza<A>,
) -> Result<(), IngressFailure> {
    let kind = stanza.resolve().map_err(|_| IngressFailure)?.stanza_type();
    match kind {
        StanzaType::Message(kind) => message::handle(context, peer, stanza, kind).await,
        StanzaType::Iq(kind) => iq::handle(context, peer, stanza, kind).await,
        StanzaType::Presence(kind) => presence::handle(context, peer, stanza, kind).await,
    }
}

#[cfg(test)]
mod tests;
