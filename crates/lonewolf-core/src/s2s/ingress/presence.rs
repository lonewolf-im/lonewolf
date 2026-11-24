// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::presence::PresenceRequestType;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{PresenceType, StanzaErrorCondition};

use super::IngressFailure;
use crate::router::{Destination, RoutedStanza};
use crate::stages::Stage;
use crate::stages::ingress::{
    peer::{PeerReply, presence as peer_presence},
    presence::{SubscriptionIngress, SubscriptionReceipt, receive_subscription},
};

pub(super) async fn handle<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    routed: RoutedStanza<A>,
    kind: PresenceType,
) -> Result<(), IngressFailure> {
    if let Some(kind) = PresenceRequestType::from_subscription_stanza(kind) {
        return subscription(stage, routed, kind).await;
    }
    let view = routed.resolve().map_err(|_| IngressFailure)?;
    let target = view
        .to()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    view.from()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let destination = stage.router.destination(target);
    if !matches!(destination, Destination::Account | Destination::Resource) {
        return Ok(());
    }
    let account = AccountKey::try_from(target.bare()).map_err(|_| IngressFailure)?;
    if kind == PresenceType::Probe {
        if let Some(replies) = peer_presence::probe(stage, account, &routed).await? {
            for reply in replies {
                stage
                    .router
                    .route_remote_or_bounce(reply.stanza)
                    .map_err(|_| IngressFailure)?;
            }
        }
        return Ok(());
    }
    let Some(admission) = peer_presence::admit(stage, &account, &view, kind).await? else {
        return Ok(());
    };
    admission
        .deliver(
            kind,
            peer_presence::route(stage.router, routed, destination, kind),
        )
        .await
        .map_err(Into::into)
}

async fn subscription<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    routed: RoutedStanza<A>,
    kind: PresenceRequestType,
) -> Result<(), IngressFailure> {
    let reply = PeerReply::Federation(stage.router);
    let outcome =
        match receive_subscription(stage, routed, kind, SubscriptionIngress::Federated).await? {
            SubscriptionReceipt::Done => Ok(()),
            SubscriptionReceipt::NoHandler { stanza } => {
                let condition = StanzaErrorCondition::ServiceUnavailable;
                reply.reject(
                    stage.allocator,
                    &stanza,
                    condition,
                    None,
                    condition.default_text(),
                )
            }
            SubscriptionReceipt::Rejected {
                stanza,
                condition,
                text,
            } => reply.reject(stage.allocator, &stanza, condition, None, text),
            SubscriptionReceipt::Failed { .. } => return Err(IngressFailure),
        };
    outcome.map_err(Into::into)
}
