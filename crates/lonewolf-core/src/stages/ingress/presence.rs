// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::policy::Verdict;
use lonewolf_extension::presence::{PresenceRequest, PresenceRequestType};
use lonewolf_storage::account::{AccountKey, AccountReads};
use lonewolf_storage::{RedbStorage, Storage};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{StanzaErrorCondition, StanzaErrorText};

use super::checks::{Snapshot, check_selected};
use crate::delivery::{
    EffectsDiagnostics, EffectsError, EffectsIdentity, RouterDelivery, commit_and_deliver,
    report_failure, report_handler_failure, storage_failure,
};
use crate::order::Ticket;
use crate::router::{DeliveryScope, Destination, RoutedStanza, RouterHandle};
use crate::stages::policy::Selection;
use crate::stages::{Stage, StageFailure};

pub(crate) struct ProbeGrant {
    pub(crate) subscribed: bool,
    pub(crate) ticket: Ticket,
}

pub(crate) enum ProbeAuthorization {
    Granted(ProbeGrant),
    OutboundBlocked,
    Denied,
}

pub(crate) async fn authorize_probe<A: ChunkAllocator + Clone + 'static>(
    router: RouterHandle<A>,
    storage: RedbStorage,
    sender: Option<AccountKey>,
    target: Option<AccountKey>,
    routed: &RoutedStanza<A>,
    check_account_exists: bool,
) -> Result<ProbeAuthorization, StageFailure> {
    let identity = target.as_ref().or(sender.as_ref()).ok_or(StageFailure)?;
    let accounts = sender
        .iter()
        .chain(
            target
                .iter()
                .filter(|target| sender.as_ref() != Some(*target)),
        )
        .cloned()
        .collect();
    let (transaction, mut ticket) = router
        .order()
        .fix(accounts, storage.begin_read())
        .await
        .map_err(|error| {
            report_failure(
                storage_failure(error, "presence_probe_begin_read"),
                identity,
            );
            StageFailure
        })?;
    let view = routed.resolve()?;
    let observer = view.from()?.ok_or(StageFailure)?;
    match check_selected(
        (&router, &storage),
        sender.as_ref(),
        target.as_ref(),
        &view,
        None,
        Snapshot::Ordered(&transaction),
        Selection::Explicit,
    )
    .await?
    {
        Verdict::Allow => {}
        Verdict::OutboundBlocked => return Ok(ProbeAuthorization::OutboundBlocked),
        Verdict::Drop | Verdict::Reject { .. } => return Ok(ProbeAuthorization::Denied),
    }
    let subscribed = if let Some(target) = target.as_ref() {
        let exists = !check_account_exists
            || transaction
                .account(target)
                .await
                .map_err(|_| StageFailure)?
                .is_some();
        if exists {
            match router
                .presence_handlers(target.domain())
                .and_then(|handlers| handlers.find(PresenceRequestType::Probe))
            {
                Some(handler) => handler
                    .visibility(target, observer, &transaction)
                    .await
                    .map_err(|error| {
                        report_handler_failure(&error, target);
                        StageFailure
                    })?,
                None => false,
            }
        } else {
            false
        }
    } else {
        false
    };
    let verdict = check_selected(
        (&router, &storage),
        sender.as_ref(),
        target.as_ref(),
        &view,
        None,
        Snapshot::Ordered(&transaction),
        Selection::Standard,
    )
    .await?;
    drop(transaction);
    match verdict {
        Verdict::Allow => {
            ticket.turn().await;
            Ok(ProbeAuthorization::Granted(ProbeGrant {
                subscribed,
                ticket,
            }))
        }
        Verdict::OutboundBlocked => Ok(ProbeAuthorization::OutboundBlocked),
        Verdict::Drop | Verdict::Reject { .. } => Ok(ProbeAuthorization::Denied),
    }
}

pub(crate) enum SubscriptionIngress {
    Federated,
    Component,
}

pub(crate) enum SubscriptionReceipt<A: ChunkAllocator> {
    Done,
    NoHandler {
        stanza: RoutedStanza<A>,
    },
    Rejected {
        stanza: RoutedStanza<A>,
        condition: StanzaErrorCondition,
        text: StanzaErrorText,
    },
    Failed {
        stanza: RoutedStanza<A>,
        committed: bool,
    },
}

pub(crate) async fn receive_subscription<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    addressed: RoutedStanza<A>,
    kind: PresenceRequestType,
    ingress: SubscriptionIngress,
) -> Result<SubscriptionReceipt<A>, StageFailure> {
    let view = addressed.resolve()?;
    let target = view.to()?.ok_or(StageFailure)?;
    if !matches!(
        stage.router.destination(target),
        Destination::Account | Destination::Resource
    ) {
        return Ok(SubscriptionReceipt::Done);
    }
    let owner = AccountKey::try_from(target.bare())?;
    let handler = stage
        .router
        .presence_handlers(target.domainpart())
        .and_then(|handlers| handlers.find(kind));
    let explicit_policy = Selection::Explicit.configured(stage.router, owner.domain());
    if handler.is_none()
        && explicit_policy
        && check_selected(
            (stage.router, stage.storage),
            None,
            Some(&owner),
            &view,
            None,
            Snapshot::Fresh,
            Selection::Explicit,
        )
        .await?
            != Verdict::Allow
    {
        return Ok(SubscriptionReceipt::Done);
    }
    let sender = view.from()?.ok_or(StageFailure)?;
    let mut arena = Arena::try_new_in(Default::default(), stage.allocator.clone())?;
    let sender = sender.bare().clone_in(&mut arena)?;
    let target = target.bare().clone_in(&mut arena)?;
    let stanza = view
        .to_builder_in(&mut arena)?
        .from(Some(sender))?
        .to(Some(target))?
        .build()?;
    let routed = RoutedStanza::from_parts(stanza, arena);
    let view = routed.resolve()?;
    let target = view.to()?.ok_or(StageFailure)?;
    let sender = view.from()?.ok_or(StageFailure)?;
    match check_selected(
        (stage.router, stage.storage),
        None,
        Some(&owner),
        &view,
        None,
        Snapshot::Fresh,
        Selection::Standard,
    )
    .await
    {
        Ok(Verdict::Allow) => {}
        Ok(_) => return Ok(SubscriptionReceipt::Done),
        Err(_) => {
            return Ok(SubscriptionReceipt::Failed {
                stanza: routed,
                committed: false,
            });
        }
    }
    let Some(handler) = handler else {
        return Ok(SubscriptionReceipt::NoHandler { stanza: routed });
    };
    let mut transaction = match stage.storage.begin_write().await {
        Ok(transaction) => transaction,
        Err(error) => {
            report_failure(
                storage_failure(error, "presence_subscription_begin_write"),
                &owner,
            );
            return Ok(SubscriptionReceipt::Failed {
                stanza: routed,
                committed: false,
            });
        }
    };
    if explicit_policy {
        let snapshot = stage.storage.begin_read().await.map_err(|error| {
            report_failure(
                storage_failure(error, "presence_subscription_policy_begin_read"),
                &owner,
            );
            StageFailure
        })?;
        if check_selected(
            (stage.router, stage.storage),
            None,
            Some(&owner),
            &addressed.resolve()?,
            None,
            Snapshot::Ordered(&snapshot),
            Selection::Explicit,
        )
        .await?
            != Verdict::Allow
        {
            return Ok(SubscriptionReceipt::Done);
        }
    }
    let scope = match ingress {
        SubscriptionIngress::Federated => DeliveryScope::FederationOnly,
        SubscriptionIngress::Component => DeliveryScope::ComponentAware,
    };
    let delivery = RouterDelivery::new(stage.router, stage.allocator, None).with_scope(scope);
    let effects = match handler
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
        Ok(effects) => effects,
        Err(error) => {
            drop(transaction);
            report_handler_failure(&error, &owner);
            return Ok(SubscriptionReceipt::Rejected {
                stanza: routed,
                condition: error.condition(),
                text: error.text(),
            });
        }
    };
    let pending = commit_and_deliver(
        stage.work.start(),
        Arc::clone(stage.router.order()),
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
    Ok(match pending.finished().await.ok_or(StageFailure)? {
        Ok(_) => SubscriptionReceipt::Done,
        Err(error) => SubscriptionReceipt::Failed {
            stanza: routed,
            committed: matches!(error, EffectsError::Delivery(_)),
        },
    })
}
