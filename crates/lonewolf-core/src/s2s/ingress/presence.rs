// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::policy::Verdict;
use lonewolf_extension::presence::PresenceRequestType;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{PresenceType, StanzaErrorCondition};

use super::{InboundPeer, IngressContext, IngressFailure, reply_error};
use crate::router::{Destination, RoutedStanza, RouterError};
use crate::stages::Stage;
use crate::stages::ingress::{
    checks::{Snapshot, check_selected, fix_explicit_snapshot},
    presence::{
        ProbeAuthorization, SubscriptionIngress, SubscriptionReceipt, authorize_probe,
        receive_subscription,
    },
};
use crate::stages::policy::Selection;

pub(crate) async fn handle<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    _peer: &InboundPeer,
    routed: RoutedStanza<A>,
    kind: PresenceType,
) -> Result<(), IngressFailure> {
    if let Some(kind) = PresenceRequestType::from_subscription_stanza(kind) {
        return subscription(context, routed, kind).await;
    }
    let view = routed.resolve().map_err(|_| IngressFailure)?;
    let target = view
        .to()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    view.from()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let destination = context.router.destination(target);
    if !matches!(destination, Destination::Account | Destination::Resource) {
        return Ok(());
    }
    let account = AccountKey::try_from(target.bare()).map_err(|_| IngressFailure)?;
    if kind == PresenceType::Probe {
        let ProbeAuthorization::Granted(grant) = authorize_probe(
            context.router.clone(),
            context.storage.clone(),
            None,
            Some(account),
            &routed,
            true,
        )
        .await?
        else {
            return Ok(());
        };
        let replies = context
            .router
            .probe_remote(&routed, grant.subscribed, grant.snapshot.as_ref())
            .await
            .map_err(|_| IngressFailure)?;
        for reply in replies.into_iter().filter(|reply| reply.is_current()) {
            context
                .router
                .route_remote_or_bounce(reply.stanza)
                .map_err(|_| IngressFailure)?;
        }
        drop(grant.ticket);
        return Ok(());
    }
    let selection = if kind == PresenceType::Error {
        Selection::Explicit
    } else {
        Selection::All
    };
    let ordered =
        fix_explicit_snapshot(&context.router, &context.storage, None, Some(&account)).await?;
    let snapshot = ordered
        .as_ref()
        .map_or(Snapshot::Fresh, |(read, _)| Snapshot::Ordered(read));
    if check_selected(
        (&context.router, &context.storage),
        None,
        Some(&account),
        &view,
        None,
        snapshot,
        selection,
    )
    .await?
        != Verdict::Allow
    {
        return Ok(());
    }
    let mut admission = ordered.map(|(_, ticket)| ticket);
    if let Some(ticket) = &mut admission {
        ticket.turn().await;
    }
    let result = if kind == PresenceType::Error {
        context.router.route_presence_error(routed).await
    } else if destination == Destination::Resource {
        context.router.route_full(routed).await
    } else {
        context.router.route_presence(routed).await
    };
    match result {
        Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
        Err(RouterError::InvalidTarget) if kind == PresenceType::Error => Ok(()),
        Err(_) => Err(IngressFailure),
    }
}

async fn subscription<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    routed: RoutedStanza<A>,
    kind: PresenceRequestType,
) -> Result<(), IngressFailure> {
    let stage = Stage {
        router: &context.router,
        storage: &context.storage,
        allocator: &context.allocator,
        work: &context.work,
    };
    match receive_subscription(&stage, routed, kind, SubscriptionIngress::Federated).await? {
        SubscriptionReceipt::Done => Ok(()),
        SubscriptionReceipt::NoHandler { stanza } => {
            let condition = StanzaErrorCondition::ServiceUnavailable;
            reply_error(context, &stanza, condition, None, condition.default_text())
        }
        SubscriptionReceipt::Rejected {
            stanza,
            condition,
            text,
        } => reply_error(context, &stanza, condition, None, text),
        SubscriptionReceipt::Failed { .. } => Err(IngressFailure),
    }
}
