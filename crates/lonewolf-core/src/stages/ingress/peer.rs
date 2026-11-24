// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{
    ApplicationCondition, IqType, MessageType, RoutedStanza, StanzaErrorCondition, StanzaErrorText,
};

use super::iq::{self, AnswerStanzas, IqDisposition, IqInput};
use super::message::{self, MessageDisposition, Reply};
use super::{Origin, peer_rejection_reply};
use crate::component::registry::ComponentRegistry;
use crate::router::{Destination, RouterHandle};
use crate::stages::{Stage, StageFailure};

pub(crate) mod presence;

pub(crate) enum PeerReply<'a, A: ChunkAllocator> {
    Federation(&'a RouterHandle<A>),
    Component {
        registry: &'a ComponentRegistry<A>,
        domain: &'a str,
        connection_id: &'a u64,
    },
}

impl<A: ChunkAllocator + Clone + 'static> PeerReply<'_, A> {
    pub(crate) fn send(&self, stanza: RoutedStanza<A>) {
        match *self {
            Self::Federation(router) => {
                let _ = router.route_remote(stanza);
            }
            Self::Component {
                registry,
                domain,
                connection_id,
            } => {
                let _ = registry.reply(domain, *connection_id, stanza);
            }
        }
    }

    pub(crate) fn reject(
        &self,
        allocator: &A,
        source: &RoutedStanza<A>,
        condition: StanzaErrorCondition,
        application: Option<ApplicationCondition>,
        text: StanzaErrorText,
    ) -> Result<(), StageFailure> {
        if let Some(stanza) = peer_rejection_reply(allocator, source, condition, application, text)?
        {
            self.send(stanza);
        }
        Ok(())
    }
}

pub(crate) async fn complete_message<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
    reply: &PeerReply<'_, A>,
    routed: RoutedStanza<A>,
    kind: MessageType,
) -> Result<(), StageFailure> {
    match message::handle(stage, origin, routed, kind).await? {
        MessageDisposition::Done => {}
        MessageDisposition::Reply(Reply::Error {
            stanza,
            condition,
            application,
            text,
        }) => reply.reject(stage.allocator, &stanza, condition, application, text)?,
        MessageDisposition::Reply(Reply::Built(stanza)) => reply.send(stanza),
    }
    Ok(())
}

pub(crate) async fn complete_iq<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
    reply: &PeerReply<'_, A>,
    routed: RoutedStanza<A>,
    destination: Destination,
    kind: IqType,
) -> Result<(), StageFailure> {
    if let Some(error) =
        crate::stages::iq::destination_error(stage.router, None, &routed.resolve()?)
            .map_err(|_| StageFailure)?
    {
        let rendered = iq::render_routed_omitted_error(
            stage.allocator,
            &routed,
            error.condition(),
            error.handler_error().text(),
        )
        .map_err(|_| StageFailure)?;
        reply.send(rendered.stanza);
        drop(rendered.retained_source);
        return Ok(());
    }
    let disposition = iq::handle(stage, origin, IqInput::Routed(routed), destination, kind).await?;
    let answer = match disposition {
        IqDisposition::Done | IqDisposition::OutboundBlocked(_) => return Ok(()),
        IqDisposition::PolicyRejected {
            input: IqInput::Routed(routed),
            condition,
            application,
            text,
        } => return reply.reject(stage.allocator, &routed, condition, application, text),
        IqDisposition::Unavailable {
            input: IqInput::Routed(routed),
            condition,
            ..
        } => {
            return reply.reject(
                stage.allocator,
                &routed,
                condition,
                None,
                condition.default_text(),
            );
        }
        IqDisposition::PolicyRejected { .. }
        | IqDisposition::Unavailable { .. }
        | IqDisposition::SessionIq { .. } => return Err(StageFailure),
        IqDisposition::Answer(answer) => answer,
        IqDisposition::Ordered(pending) => pending.finished().await.ok_or(StageFailure)??.answer,
    };
    match iq::render_answer(origin, stage.allocator, answer).map_err(|_| StageFailure)? {
        AnswerStanzas::One { stanza, arena } => reply.send(RoutedStanza::from_parts(stanza, arena)),
        AnswerStanzas::Shared(stanzas) => {
            for stanza in stanzas {
                reply.send(stanza);
            }
        }
    }
    Ok(())
}
