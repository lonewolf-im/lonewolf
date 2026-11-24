// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::policy::Verdict;
use lonewolf_storage::RedbRead;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{ArenaRead, ChunkAllocator};
use lonewolf_xmpp::stanza::{PresenceType, StanzaRef};

use crate::order::Ticket;
use crate::router::{Destination, PresenceDelivery, RoutedStanza, RouterError, RouterHandle};
use crate::stages::ingress::checks::{Snapshot, check_selected, fix_explicit_snapshot};
use crate::stages::ingress::presence::{ProbeAuthorization, ProbeGrant, authorize_probe};
use crate::stages::policy::Selection;
use crate::stages::{Stage, StageFailure};

pub(crate) struct ProbeReplies<A: ChunkAllocator> {
    replies: std::vec::IntoIter<PresenceDelivery<A>>,
    _grant: ProbeGrant,
}

impl<A: ChunkAllocator> Iterator for ProbeReplies<A> {
    type Item = PresenceDelivery<A>;

    fn next(&mut self) -> Option<Self::Item> {
        self.replies.find(PresenceDelivery::is_current)
    }
}

pub(crate) async fn probe<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    account: AccountKey,
    routed: &RoutedStanza<A>,
) -> Result<Option<ProbeReplies<A>>, StageFailure> {
    let ProbeAuthorization::Granted(grant) = authorize_probe(
        stage.router.clone(),
        stage.storage.clone(),
        None,
        Some(account),
        routed,
        true,
    )
    .await?
    else {
        return Ok(None);
    };
    let replies = stage
        .router
        .probe_remote(routed, grant.subscribed, grant.snapshot.as_ref())
        .await
        .map_err(|_| StageFailure)?;
    Ok(Some(ProbeReplies {
        replies: replies.into_iter(),
        _grant: grant,
    }))
}

pub(crate) struct PresenceAdmission {
    ordered: Option<(RedbRead, Ticket)>,
}

impl PresenceAdmission {
    pub(crate) fn read(&self) -> Option<&RedbRead> {
        self.ordered.as_ref().map(|(read, _)| read)
    }

    pub(crate) async fn deliver(
        self,
        kind: PresenceType,
        route: impl Future<Output = Result<(), RouterError>>,
    ) -> Result<(), StageFailure> {
        let mut ticket = self.ordered.map(|(_, ticket)| ticket);
        if let Some(ticket) = &mut ticket {
            ticket.turn().await;
        }
        match route.await {
            Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
            Err(RouterError::InvalidTarget) if kind == PresenceType::Error => Ok(()),
            Err(_) => Err(StageFailure),
        }
    }
}

pub(crate) async fn admit<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    account: &AccountKey,
    view: &StanzaRef<'_, impl ArenaRead>,
    kind: PresenceType,
) -> Result<Option<PresenceAdmission>, StageFailure> {
    let selection = if kind == PresenceType::Error {
        Selection::Explicit
    } else {
        Selection::All
    };
    let admission = PresenceAdmission {
        ordered: fix_explicit_snapshot(stage.router, stage.storage, None, Some(account)).await?,
    };
    let snapshot = admission.read().map_or(Snapshot::Fresh, Snapshot::Ordered);
    let verdict = check_selected(
        (stage.router, stage.storage),
        None,
        Some(account),
        view,
        None,
        snapshot,
        selection,
    )
    .await?;
    Ok((verdict == Verdict::Allow).then_some(admission))
}

pub(crate) async fn route<A: ChunkAllocator + Clone + 'static>(
    router: &RouterHandle<A>,
    routed: RoutedStanza<A>,
    destination: Destination,
    kind: PresenceType,
) -> Result<(), RouterError> {
    if kind == PresenceType::Error {
        router.route_presence_error(routed).await
    } else if destination == Destination::Resource {
        router.route_full(routed).await
    } else {
        router.route_presence(routed).await
    }
}
