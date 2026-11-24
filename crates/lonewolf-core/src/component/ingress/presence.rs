// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::presence::PresenceRequestType;
use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::PresenceType;

use super::{Context, IngressFailure, apply_subscription_receipt};
use crate::component::metrics::DropReason;
use crate::delivery::{report_failure, report_handler_failure, storage_failure};
use crate::router::{Destination, RoutedStanza};
use crate::stages::Stage;
use crate::stages::ingress::{
    peer::{PeerReply, presence as peer_presence},
    presence::{SubscriptionIngress, receive_subscription},
};

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
        if let Some(replies) = peer_presence::probe(stage, account, &routed).await? {
            let peer = PeerReply::Component {
                registry: &context.registry,
                domain,
                connection_id: &context.connection_id,
            };
            for reply in replies {
                peer.send(reply.stanza);
            }
        }
        return Ok(());
    }
    let Some(admission) = peer_presence::admit(stage, &account, &view, kind).await? else {
        return Ok(());
    };
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
        let transaction = if let Some(transaction) = admission.read() {
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
    admission
        .deliver(kind, async {
            if subscription.is_some() {
                context.router.route_subscription_presence(routed).await
            } else {
                peer_presence::route(&context.router, routed, destination, kind).await
            }
        })
        .await
        .map_err(Into::into)
}
