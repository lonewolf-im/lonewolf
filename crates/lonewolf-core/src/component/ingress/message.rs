// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::MessageType;

use super::{Context, IngressFailure, reply_error};
use crate::router::RoutedStanza;
use crate::stages::Stage;
use crate::stages::ingress::Origin;
use crate::stages::ingress::message::{self, MessageDisposition, Reply};

pub(super) async fn handle<A: ChunkAllocator + Clone + 'static>(
    context: &Context<A>,
    domain: &str,
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
    routed: RoutedStanza<A>,
    kind: MessageType,
) -> Result<(), IngressFailure> {
    match message::handle(stage, origin, routed, kind).await? {
        MessageDisposition::Done => Ok(()),
        MessageDisposition::Reply(Reply::Error {
            stanza,
            condition,
            application,
            text,
        }) => reply_error(context, domain, &stanza, condition, application, text),
        MessageDisposition::Reply(Reply::Built(reply)) => {
            let _ = context.registry.reply(domain, context.connection_id, reply);
            Ok(())
        }
    }
}
