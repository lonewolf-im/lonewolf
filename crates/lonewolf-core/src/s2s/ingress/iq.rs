// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::IqType;

use super::{InboundPeer, IngressContext, IngressFailure, reply_error};
use crate::router::RoutedStanza;
use crate::stages::Stage;
use crate::stages::ingress::Origin;
use crate::stages::ingress::iq::{self as ingress_iq, AnswerStanzas, IqDisposition, IqInput};
use crate::stages::iq::ReplyError;

impl From<ReplyError> for IngressFailure {
    fn from(_: ReplyError) -> Self {
        Self
    }
}

pub(crate) async fn handle<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    peer: &InboundPeer,
    routed: RoutedStanza<A>,
    kind: IqType,
) -> Result<(), IngressFailure> {
    let origin: Origin<'_, A> = Origin::Remote {
        local: &peer.local,
        remote: &peer.remote,
    };
    let stage = Stage {
        router: &context.router,
        storage: &context.storage,
        allocator: &context.allocator,
        work: &context.work,
    };
    let view = routed.resolve().map_err(|_| IngressFailure)?;
    let target = view
        .to()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    view.from()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let destination = context.router.destination(target);
    if let Some(error) = crate::stages::iq::destination_error(&context.router, None, &view)? {
        let rendered = ingress_iq::render_routed_omitted_error(
            &context.allocator,
            &routed,
            error.condition(),
            error.handler_error().text(),
        )?;
        let _ = context.router.route_remote(rendered.stanza);
        drop(rendered.retained_source);
        return Ok(());
    }
    let disposition =
        ingress_iq::handle(&stage, &origin, IqInput::Routed(routed), destination, kind).await?;
    let answer = match disposition {
        IqDisposition::Done => return Ok(()),
        IqDisposition::PolicyRejected {
            input: IqInput::Routed(routed),
            condition,
            application,
            text,
        } => {
            return reply_error(context, &routed, condition, application, text);
        }
        IqDisposition::PolicyRejected { .. } => return Err(IngressFailure),
        IqDisposition::Unavailable {
            input: IqInput::Routed(routed),
            condition,
            ..
        } => return reply_error(context, &routed, condition, None, condition.default_text()),
        IqDisposition::Unavailable { .. } | IqDisposition::SessionIq { .. } => {
            return Err(IngressFailure);
        }
        IqDisposition::Answer(answer) => answer,
        IqDisposition::Ordered(pending) => pending.finished().await.ok_or(IngressFailure)??.answer,
    };
    match ingress_iq::render_answer(&origin, &context.allocator, answer)? {
        AnswerStanzas::One { stanza, arena } => {
            let _ = context
                .router
                .route_remote(RoutedStanza::from_parts(stanza, arena));
        }
        AnswerStanzas::Shared(stanzas) => {
            for stanza in stanzas {
                let _ = context.router.route_remote(stanza);
            }
        }
    }
    Ok(())
}
