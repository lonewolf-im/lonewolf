// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::MessageType;

use super::{InboundPeer, IngressContext, IngressFailure, reply_error};
use crate::router::{Destination, RoutedStanza};
use crate::stages::Stage;
use crate::stages::ingress::Origin;
use crate::stages::ingress::message::{self, MessageDisposition, Reply};

pub(crate) async fn handle<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    peer: &InboundPeer,
    routed: RoutedStanza<A>,
    kind: MessageType,
) -> Result<(), IngressFailure> {
    let stage = Stage {
        router: &context.router,
        storage: &context.storage,
        allocator: &context.allocator,
        work: &context.work,
    };
    let view = routed.resolve().map_err(|_| IngressFailure)?;
    let to = view
        .to()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    if matches!(
        context.router.destination(to),
        Destination::Service | Destination::Remote
    ) {
        return Err(IngressFailure);
    }
    let origin = Origin::Remote {
        local: &peer.local,
        remote: &peer.remote,
    };
    match message::handle(&stage, &origin, routed, kind).await? {
        MessageDisposition::Done => Ok(()),
        MessageDisposition::Reply(Reply::Error {
            stanza,
            condition,
            application,
            text,
        }) => reply_error(context, &stanza, condition, application, text),
        MessageDisposition::Reply(Reply::Built(reply)) => context
            .router
            .route_remote(reply)
            .map_err(|_| IngressFailure),
    }
}
