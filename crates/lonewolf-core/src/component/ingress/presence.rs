// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::policy::Verdict;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::PresenceType;

use super::{Context, IngressFailure};
use crate::router::{Destination, RoutedStanza, RouterError};
use crate::stages::ingress::{
    checks::{Snapshot, check_from},
    presence::authorize_probe,
};

pub(super) async fn handle<A: ChunkAllocator + Clone + 'static>(
    context: &Context<A>,
    domain: &str,
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
    if kind == PresenceType::Error {
        return match context.router.route_presence_error(routed).await {
            Ok(())
            | Err(RouterError::NotFound | RouterError::Busy | RouterError::InvalidTarget) => Ok(()),
            Err(_) => Err(IngressFailure),
        };
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
            let _ = context.registry.reply(domain, context.connection_id, reply);
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
    let result = if matches!(
        kind,
        PresenceType::Subscribe
            | PresenceType::Subscribed
            | PresenceType::Unsubscribe
            | PresenceType::Unsubscribed
    ) {
        context.router.route_subscription_presence(routed).await
    } else if destination == Destination::Resource {
        context.router.route_full(routed).await
    } else {
        context.router.route_presence(routed).await
    };
    match result {
        Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
        Err(_) => Err(IngressFailure),
    }
}
