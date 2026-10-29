// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::policy::{Direction, Verdict};
use lonewolf_extension::presence::PresenceRequestType;
use lonewolf_storage::Storage;
use lonewolf_storage::account::{AccountKey, AccountReads};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::PresenceType;

use super::{InboundPeer, IngressContext, IngressFailure};
use crate::delivery::{report_failure, report_handler_failure, storage_failure};
use crate::router::{Destination, RoutedStanza, RouterError};
use crate::s2s::log_domain;
use crate::stages::{Stage, policy};

pub(crate) async fn handle<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    peer: &InboundPeer,
    routed: RoutedStanza<A>,
    kind: PresenceType,
) -> Result<(), IngressFailure> {
    if matches!(
        kind,
        PresenceType::Subscribe
            | PresenceType::Subscribed
            | PresenceType::Unsubscribe
            | PresenceType::Unsubscribed
    ) {
        tracing::debug!(stanza_kind = "presence", remote_domain = %log_domain(&peer.remote), "s2s subscription discarded");
        return Ok(());
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
    let sender = view
        .from()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let destination = context.router.destination(target);
    if !matches!(destination, Destination::Account | Destination::Resource) {
        return Ok(());
    }
    let account = AccountKey::try_from(target.bare()).map_err(|_| IngressFailure)?;
    let checks = [policy::Check {
        account: &account,
        direction: Direction::Inbound,
        peer: sender,
    }];
    if kind == PresenceType::Probe {
        let (transaction, mut ticket) = Arc::clone(context.router.order())
            .fix(vec![account.clone()], context.storage.begin_read())
            .await
            .map_err(|error| {
                report_failure(
                    storage_failure(error, "presence_probe_begin_read"),
                    &account,
                );
                IngressFailure
            })?;
        let exists = transaction
            .account(&account)
            .await
            .map_err(|_| IngressFailure)?
            .is_some();
        let subscribed = if exists {
            match context
                .router
                .presence_handlers(account.domain())
                .and_then(|handlers| handlers.find(PresenceRequestType::Probe))
            {
                Some(handler) => handler
                    .visibility(&account, sender, &transaction)
                    .await
                    .map_err(|error| {
                        report_handler_failure(&error, &account);
                        IngressFailure
                    })?,
                None => false,
            }
        } else {
            false
        };
        if policy::evaluate_in(&context.router, &transaction, view.stanza_type(), &checks).await?
            != Verdict::Allow
        {
            return Ok(());
        }
        drop(transaction);
        ticket.turn().await;
        let replies = context
            .router
            .probe_remote(&routed, subscribed)
            .await
            .map_err(|_| IngressFailure)?;
        for reply in replies {
            context
                .router
                .route_remote_or_bounce(reply)
                .map_err(|_| IngressFailure)?;
        }
        drop(ticket);
        return Ok(());
    }
    let stage = Stage {
        router: &context.router,
        storage: &context.storage,
        allocator: &context.allocator,
        work: &context.work,
    };
    if policy::evaluate(&stage, view.stanza_type(), &checks).await? != Verdict::Allow {
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
