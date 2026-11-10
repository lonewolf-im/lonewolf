// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::policy::Verdict;
use lonewolf_extension::presence::PresenceRequestType;
use lonewolf_storage::account::{AccountKey, AccountReads};
use lonewolf_storage::{RedbStorage, Storage};
use lonewolf_util::arena::ChunkAllocator;

use super::checks::{Snapshot, check_from};
use crate::delivery::{report_failure, report_handler_failure, storage_failure};
use crate::order::Ticket;
use crate::router::{RoutedStanza, RouterHandle};
use crate::stages::StageFailure;

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
