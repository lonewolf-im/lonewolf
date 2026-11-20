// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::policy::Verdict;
use lonewolf_extension::presence::PresenceRequestType;
use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::PresenceType;

use super::{Context, IngressFailure, apply_subscription_receipt};
use crate::component::metrics::DropReason;
use crate::delivery::{report_failure, report_handler_failure, storage_failure};
use crate::router::{Destination, RoutedStanza, RouterError};
use crate::stages::Stage;
use crate::stages::ingress::{
    checks::{Snapshot, check_selected, fix_explicit_snapshot},
    presence::{ProbeAuthorization, SubscriptionIngress, authorize_probe, receive_subscription},
};
use crate::stages::policy::Selection;

#[cfg(test)]
mod tests;

pub(super) async fn handle<A: ChunkAllocator + Clone + 'static>(
    context: &Context<A>,
    domain: &str,
    stage: &Stage<'_, A>,
    routed: RoutedStanza<A>,
    kind: PresenceType,
) -> Result<(), IngressFailure> {
    let view = routed.resolve().map_err(|_| IngressFailure)?;
    let target = view
        .to()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let destination = context.router.destination(target);
    match destination {
        Destination::Remote => {
            if kind == PresenceType::Error {
                let _ = context.router.route_remote(routed);
            } else {
                let _ = context.router.route_remote_or_bounce(routed);
            }
            return Ok(());
        }
        Destination::Account | Destination::Resource => {}
        Destination::Server | Destination::ServerResource | Destination::Service => return Ok(()),
    }
    let subscription = PresenceRequestType::from_subscription_stanza(kind);
    if let Some(kind) = subscription
        && context
            .router
            .presence_handlers(target.domainpart())
            .and_then(|handlers| handlers.find(kind))
            .is_some()
    {
        let receipt =
            receive_subscription(stage, routed, kind, SubscriptionIngress::Component).await?;
        apply_subscription_receipt(context, domain, receipt);
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
            let _ = context
                .registry
                .reply(domain, context.connection_id, reply.stanza);
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
    if kind == PresenceType::Available
        && destination == Destination::Account
        && let Some(handler) = context
            .router
            .presence_handlers(account.domain())
            .and_then(|handlers| handlers.find(PresenceRequestType::Available))
    {
        let sender = view
            .from()
            .map_err(|_| IngressFailure)?
            .ok_or(IngressFailure)?
            .bare();
        let fresh;
        let transaction = if let Some((transaction, _)) = &ordered {
            transaction
        } else {
            fresh = match context.storage.begin_read().await {
                Ok(transaction) => transaction,
                Err(error) => {
                    report_failure(
                        storage_failure(error, "presence_filter_begin_read"),
                        &account,
                    );
                    return Ok(());
                }
            };
            &fresh
        };
        match handler
            .accepts_presence(&account, sender, transaction)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                context
                    .registry
                    .metrics()
                    .dropped(DropReason::PresenceNotSubscribed, 1);
                tracing::debug!(
                    outcome = "not_subscribed",
                    account_jid = ?account.as_str(),
                    contact_jid = ?sender.as_str(),
                    "component presence dropped"
                );
                return Ok(());
            }
            Err(error) => {
                report_handler_failure(&error, &account);
                return Ok(());
            }
        }
    }
    let mut admission = ordered.map(|(_, ticket)| ticket);
    if let Some(ticket) = &mut admission {
        ticket.turn().await;
    }
    let result = if kind == PresenceType::Error {
        context.router.route_presence_error(routed).await
    } else if subscription.is_some() {
        context.router.route_subscription_presence(routed).await
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
