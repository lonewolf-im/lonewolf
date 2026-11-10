// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::policy::Verdict;
use lonewolf_extension::presence::{PresenceRequest, PresenceRequestType};
use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{PresenceType, StanzaErrorCondition};

use super::{InboundPeer, IngressContext, IngressFailure, reply_error};
use crate::delivery::{
    EffectsDiagnostics, EffectsIdentity, RouterDelivery, commit_and_deliver, report_failure,
    report_handler_failure, storage_failure,
};
use crate::router::{Destination, RoutedStanza, RouterError};
use crate::stages::ingress::{
    checks::{Snapshot, check_from},
    presence::authorize_probe,
};

pub(crate) async fn handle<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    _peer: &InboundPeer,
    routed: RoutedStanza<A>,
    kind: PresenceType,
) -> Result<(), IngressFailure> {
    if let Some(kind) = PresenceRequestType::from_subscription_stanza(kind) {
        return subscription(context, routed, kind).await;
    }
    if kind == PresenceType::Error {
        return match context.router.route_presence_error(routed).await {
            Ok(())
            | Err(RouterError::NotFound | RouterError::Busy | RouterError::InvalidTarget) => Ok(()),
            Err(_) => Err(IngressFailure),
        };
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
        let Some(grant) = authorize_probe(
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
            .probe_remote(&routed, grant.subscribed)
            .await
            .map_err(|_| IngressFailure)?;
        for reply in replies {
            context
                .router
                .route_remote_or_bounce(reply)
                .map_err(|_| IngressFailure)?;
        }
        drop(grant.ticket);
        return Ok(());
    }
    if check_from(
        &context.router,
        &context.storage,
        None,
        Some(&account),
        &view,
        None,
        Snapshot::Fresh,
    )
    .await?
        != Verdict::Allow
    {
        return Ok(());
    }
    let result = if destination == Destination::Resource {
        context.router.route_full(routed).await
    } else {
        context.router.route_presence(routed).await
    };
    match result {
        Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
        Err(_) => Err(IngressFailure),
    }
}

async fn subscription<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    routed: RoutedStanza<A>,
    kind: PresenceRequestType,
) -> Result<(), IngressFailure> {
    let view = routed.resolve().map_err(|_| IngressFailure)?;
    let target = view
        .to()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    if !matches!(
        context.router.destination(target),
        Destination::Account | Destination::Resource
    ) {
        return Ok(());
    }
    let sender = view
        .from()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let mut arena = Arena::try_new_in(Default::default(), context.allocator.clone())
        .map_err(|_| IngressFailure)?;
    let sender = sender
        .bare()
        .clone_in(&mut arena)
        .map_err(|_| IngressFailure)?;
    let target = target
        .bare()
        .clone_in(&mut arena)
        .map_err(|_| IngressFailure)?;
    let stanza = view
        .to_builder_in(&mut arena)
        .map_err(|_| IngressFailure)?
        .from(Some(sender))
        .map_err(|_| IngressFailure)?
        .to(Some(target))
        .map_err(|_| IngressFailure)?
        .build()
        .map_err(|_| IngressFailure)?;
    let routed = RoutedStanza::from_parts(stanza, arena);
    let view = routed.resolve().map_err(|_| IngressFailure)?;
    let target = view
        .to()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let sender = view
        .from()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let owner = AccountKey::try_from(target).map_err(|_| IngressFailure)?;
    if check_from(
        &context.router,
        &context.storage,
        None,
        Some(&owner),
        &view,
        None,
        Snapshot::Fresh,
    )
    .await?
        != Verdict::Allow
    {
        return Ok(());
    }
    let Some(handler) = context
        .router
        .presence_handlers(target.domainpart())
        .and_then(|handlers| handlers.find(kind))
    else {
        let condition = StanzaErrorCondition::ServiceUnavailable;
        return reply_error(context, &routed, condition, None, condition.default_text());
    };
    let delivery = RouterDelivery::new(&context.router, &context.allocator, None);
    let mut transaction = context.storage.begin_write().await.map_err(|error| {
        report_failure(
            storage_failure(error, "presence_subscription_begin_write"),
            &owner,
        );
        IngressFailure
    })?;
    match handler
        .receive(
            PresenceRequest {
                kind,
                sender,
                target,
                stanza: &routed,
            },
            &mut transaction,
            &delivery,
        )
        .await
    {
        Ok(effects) => {
            let pending = commit_and_deliver(
                context.work.start(),
                Arc::clone(context.router.order()),
                transaction,
                effects,
                delivery,
                None,
                EffectsDiagnostics {
                    identity: EffectsIdentity::Account(owner),
                    commit_operation: "presence_subscription_commit",
                    delivery_operation: "presence_subscription_effects",
                },
            );
            pending
                .finished()
                .await
                .ok_or(IngressFailure)?
                .map_err(|_| IngressFailure)?;
            Ok(())
        }
        Err(error) => {
            drop(transaction);
            report_handler_failure(&error, &owner);
            reply_error(context, &routed, error.condition(), None, error.text())
        }
    }
}
