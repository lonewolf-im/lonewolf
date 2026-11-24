// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::StanzaType;

use crate::delivery::WorkHandle;
use crate::router::{Destination, RoutedStanza, RouterHandle};
use crate::stages::ingress::{
    Origin,
    peer::{self, PeerReply},
};
use crate::stages::{
    Stage, StageFailure,
    service::{self, ServiceOutcome},
};

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

mod presence;
pub(crate) mod receive;

pub(crate) async fn dispatch<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    peer: &InboundPeer,
    stanza: RoutedStanza<A>,
) -> Result<(), IngressFailure> {
    let view = stanza.resolve().map_err(|_| IngressFailure)?;
    let target = view.to().map_err(|_| IngressFailure)?;
    let stage = Stage {
        router: &context.router,
        storage: &context.storage,
        allocator: &context.allocator,
        work: &context.work,
    };
    let reply = PeerReply::Federation(&context.router);
    if let Some(route) = target.and_then(|to| context.router.service(to.domainpart())) {
        if let ServiceOutcome::Rejected {
            stanza,
            condition,
            text,
        } = service::dispatch(&stage, route, stanza).await?
        {
            reply.reject(&context.allocator, &stanza, condition, None, text)?;
        }
        return Ok(());
    }
    let origin = Origin::Remote {
        local: &peer.local,
        remote: &peer.remote,
    };
    let outcome = match view.stanza_type() {
        StanzaType::Message(kind) => {
            let target = target.ok_or(IngressFailure)?;
            if matches!(
                context.router.destination(target),
                Destination::Service | Destination::Remote
            ) {
                return Err(IngressFailure);
            }
            peer::complete_message(&stage, &origin, &reply, stanza, kind).await
        }
        StanzaType::Iq(kind) => {
            let target = target.ok_or(IngressFailure)?;
            view.from()
                .map_err(|_| IngressFailure)?
                .ok_or(IngressFailure)?;
            let destination = context.router.destination(target);
            peer::complete_iq(&stage, &origin, &reply, stanza, destination, kind).await
        }
        StanzaType::Presence(kind) => return presence::handle(&stage, stanza, kind).await,
    };
    outcome.map_err(Into::into)
}

#[cfg(test)]
mod tests;
