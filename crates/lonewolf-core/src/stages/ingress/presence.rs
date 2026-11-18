// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::policy::Verdict;
use lonewolf_extension::presence::{PresenceRequest, PresenceRequestType};
use lonewolf_storage::account::{AccountKey, AccountReads};
use lonewolf_storage::{RedbStorage, Storage};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{StanzaErrorCondition, StanzaErrorText};

use super::checks::{Snapshot, check_from};
use crate::delivery::{
    EffectsDiagnostics, EffectsError, EffectsIdentity, RouterDelivery, commit_and_deliver,
    report_failure, report_handler_failure, storage_failure,
};
use crate::order::Ticket;
use crate::router::{DeliveryScope, Destination, RoutedStanza, RouterHandle};
use crate::stages::{Stage, StageFailure};

pub(crate) struct ProbeGrant {
    pub(crate) subscribed: bool,
    pub(crate) ticket: Ticket,
}

pub(crate) async fn authorize_probe<A: ChunkAllocator + Clone + 'static>(
    router: RouterHandle<A>,
    storage: RedbStorage,
    sender: Option<AccountKey>,
    target: Option<AccountKey>,
    routed: &RoutedStanza<A>,
    check_account_exists: bool,
) -> Result<Option<ProbeGrant>, StageFailure> {
    let local = sender.is_some() && target.is_some();
    let (accounts, sender) = match (sender, target.as_ref()) {
        (Some(sender), Some(target)) => {
            let mut accounts = vec![sender];
            if &accounts[0] != target {
                accounts.push(target.clone());
            }
            (accounts, None)
        }
        (Some(sender), None) => (vec![sender.clone()], Some(sender)),
        (None, Some(target)) => (vec![target.clone()], None),
        (None, None) => return Err(StageFailure),
    };
    let identity = target.as_ref().or(sender.as_ref()).ok_or(StageFailure)?;
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
    let (subscribed, verdict) = if let Some(target) = target.as_ref() {
        let observer = view.from()?.ok_or(StageFailure)?;
        let exists = !check_account_exists
            || transaction
                .account(target)
                .await
                .map_err(|_| StageFailure)?
                .is_some();
        let subscribed = if exists {
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
        };
        let verdict = if local {
            if observer.bare().as_str() != target.as_str()
                && (!router.policies(observer.domainpart()).is_empty()
                    || !router.policies(target.domain()).is_empty())
            {
                let prober = AccountKey::try_from(observer.bare())?;
                view.to()?.ok_or(StageFailure)?;
                check_from(
                    &router,
                    &storage,
                    Some(&prober),
                    Some(target),
                    &view,
                    None,
                    Snapshot::Ordered(&transaction),
                )
                .await?
            } else {
                Verdict::Allow
            }
        } else {
            check_from(
                &router,
                &storage,
                None,
                Some(target),
                &view,
                None,
                Snapshot::Ordered(&transaction),
            )
            .await?
        };
        (subscribed, verdict)
    } else {
        view.to()?.ok_or(StageFailure)?;
        let verdict = check_from(
            &router,
            &storage,
            sender.as_ref(),
            None,
            &view,
            None,
            Snapshot::Ordered(&transaction),
        )
        .await?;
        (false, verdict)
    };
    drop(transaction);
    if verdict != Verdict::Allow {
        return Ok(None);
    }
    ticket.turn().await;
    Ok(Some(ProbeGrant { subscribed, ticket }))
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
    routed: RoutedStanza<A>,
    kind: PresenceRequestType,
    ingress: SubscriptionIngress,
) -> Result<SubscriptionReceipt<A>, StageFailure> {
    let view = routed.resolve()?;
    let target = view.to()?.ok_or(StageFailure)?;
    if !matches!(
        stage.router.destination(target),
        Destination::Account | Destination::Resource
    ) {
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
    let owner = AccountKey::try_from(target)?;
    match check_from(
        stage.router,
        stage.storage,
        None,
        Some(&owner),
        &view,
        None,
        Snapshot::Fresh,
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
    let Some(handler) = stage
        .router
        .presence_handlers(target.domainpart())
        .and_then(|handlers| handlers.find(kind))
    else {
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
