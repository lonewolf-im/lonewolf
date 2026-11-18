// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{
    ApplicationCondition, IqType, MessageType, PresenceType, RoutedStanza, StanzaErrorCondition,
    StanzaErrorText, StanzaType,
};

use super::registry::ComponentRegistry;
use crate::delivery::WorkHandle;
use crate::router::RouterHandle;
use crate::stages::ingress::{Origin, presence::SubscriptionReceipt};
use crate::stages::{
    Stage, StageFailure,
    service::{self, ComponentReplyTarget, ServiceOutcome},
};

mod iq;
mod message;
mod presence;

pub(crate) struct Context<A: ChunkAllocator> {
    pub(crate) router: RouterHandle<A>,
    pub(crate) storage: RedbStorage,
    pub(crate) allocator: A,
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

pub(crate) fn reply_error<A: ChunkAllocator + Clone + 'static>(
    context: &Context<A>,
    domain: &str,
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
                | StanzaType::Presence(
                    PresenceType::Subscribe
                        | PresenceType::Subscribed
                        | PresenceType::Unsubscribe
                        | PresenceType::Unsubscribed,
                )
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
    let _ = context.registry.reply(
        domain,
        context.connection_id,
        RoutedStanza::from_parts(reply, arena),
    );
    Ok(())
}

pub(super) fn apply_subscription_receipt<A: ChunkAllocator + Clone + 'static>(
    context: &Context<A>,
    domain: &str,
    receipt: SubscriptionReceipt<A>,
) {
    let (stanza, condition, text) = match receipt {
        SubscriptionReceipt::Done
        | SubscriptionReceipt::Failed {
            committed: true, ..
        } => return,
        SubscriptionReceipt::NoHandler { stanza } => {
            let condition = StanzaErrorCondition::ServiceUnavailable;
            (stanza, condition, condition.default_text())
        }
        SubscriptionReceipt::Rejected {
            stanza,
            condition,
            text,
        } => (stanza, condition, text),
        SubscriptionReceipt::Failed {
            stanza,
            committed: false,
        } => {
            let condition = StanzaErrorCondition::InternalServerError;
            (stanza, condition, condition.default_text())
        }
    };
    let _ = reply_error(context, domain, &stanza, condition, None, text);
}

pub(crate) async fn dispatch<A: ChunkAllocator + Clone + 'static>(
    context: &Context<A>,
    domain: &str,
    stanza: RoutedStanza<A>,
) -> Result<(), IngressFailure> {
    let stage = Stage {
        router: &context.router,
        storage: &context.storage,
        allocator: &context.allocator,
        work: &context.work,
    };
    let origin = Origin::Service { domain };
    let view = stanza.resolve().map_err(|_| IngressFailure)?;
    let target = view
        .to()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    if let Some(route) = context.router.service(target.domainpart()) {
        let reply_target = ComponentReplyTarget {
            registry: &context.registry,
            domain,
            connection_id: context.connection_id,
        };
        if let ServiceOutcome::Rejected {
            stanza,
            condition,
            text,
        } = service::dispatch_with_component_reply(&stage, route, stanza, Some(reply_target))
            .await?
        {
            reply_error(context, domain, &stanza, condition, None, text)?;
        }
        return Ok(());
    }
    match view.stanza_type() {
        StanzaType::Message(kind) => {
            message::handle(context, domain, &stage, &origin, stanza, kind).await
        }
        StanzaType::Iq(kind) => iq::handle(context, domain, &stage, &origin, stanza, kind).await,
        StanzaType::Presence(kind) => presence::handle(context, domain, &stage, stanza, kind).await,
    }
}
