// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::sync::Arc;

use lonewolf_storage::account::{AccountKey, AccountReads};
use lonewolf_storage::roster::{
    RosterError, RosterJid, RosterMutation, RosterReads, RosterSubscription, RosterVersion,
    SubscriptionState,
};
use lonewolf_storage::{ReadTransaction, WriteTransaction};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaErrorCondition};

use super::state::{self, Cancellation, Removal, RequestOutcome, grants};
use super::{
    account_exists, push_change, push_removal, push_roster, require_account, roster_error, xml,
};
use crate::Effects;
use crate::delivery::{Delivery, DeliveryError, HandlerError, HostLookup, SessionTag};
use crate::presence::{PresenceRequest, PresenceRequestType, PresenceSend};

#[derive(Default)]
struct Retirements {
    accounts: Vec<AccountKey>,
}

impl Retirements {
    fn extract(&mut self, owner: &AccountKey, change: &mut state::ItemMutation) {
        if matches!(change, Some(state::ItemChange::Unavailable { .. })) {
            if !self.accounts.contains(owner) {
                if self.accounts.is_empty() {
                    self.accounts.reserve_exact(2);
                }
                self.accounts.push(owner.clone());
            }
            *change = None;
        }
    }

    async fn finish<A: ChunkAllocator>(
        self,
        result: Result<(), DeliveryError>,
        delivery: &dyn Delivery<A>,
    ) -> Result<(), DeliveryError> {
        let mut failure = result.err();
        for account in self.accounts {
            if let Err(error) = delivery
                .retire_tagged(&account, SessionTag::Interested)
                .await
            {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

pub(super) async fn send_subscription<A: ChunkAllocator, W: WriteTransaction>(
    roster: &super::Roster,
    transaction: &mut W,
    request: PresenceRequest<'_, A>,
) -> Result<PresenceSend<A>, HandlerError> {
    if !matches!(
        request.kind,
        PresenceRequestType::Subscribed | PresenceRequestType::Unsubscribed
    ) || request.target.localpart().is_none()
        || request.target.resourcepart().is_some()
    {
        return Ok(PresenceSend::Continue);
    }
    let owner = AccountKey::try_from(request.sender.bare())
        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    let contact = RosterJid::from(request.target);
    require_account(transaction, &owner).await?;
    let item = transaction
        .roster_subscription(&owner, &contact)
        .await
        .map_err(|error| roster_error(error, "roster_read"))?;
    let pending = transaction
        .pending_request_exists(&owner, &contact)
        .await
        .map_err(|error| roster_error(error, "roster_read"))?;
    let granted = item.is_some_and(|item| grants(item.state));
    let mutation = match request.kind {
        PresenceRequestType::Subscribed if granted => None,
        PresenceRequestType::Subscribed if !pending => {
            state::update_subscription(roster, transaction, &owner, &contact, state::pre_approve)
                .await
                .map_err(|error| roster_error(error, "roster_write"))?
        }
        PresenceRequestType::Unsubscribed if !granted && !pending => {
            state::update_existing_subscription(
                roster,
                transaction,
                &owner,
                &contact,
                |mut subscription| {
                    if !subscription.approved {
                        return None;
                    }
                    subscription.approved = false;
                    Some(subscription)
                },
            )
            .await
            .map_err(|error| roster_error(error, "roster_write"))?
        }
        _ => return Ok(PresenceSend::Continue),
    };
    Ok(PresenceSend::Handled(Effects::new(
        vec![owner.clone()],
        move |delivery| {
            Box::pin(async move {
                let mut retirements = Retirements::default();
                let mut mutation = mutation;
                retirements.extract(&owner, &mut mutation);
                let result = async {
                    if let Some(mutation) = mutation {
                        push_change(&owner, mutation, delivery).await?;
                    }
                    Ok(())
                }
                .await;
                retirements.finish(result, delivery).await
            })
        },
    )))
}

pub(super) struct Parties {
    sender: AccountKey,
    target: AccountKey,
    sender_jid: RosterJid,
    target_jid: RosterJid,
}

impl Parties {
    /// A domain-only target cannot hold a roster, so it is reported as unavailable.
    pub(super) fn new<A: ChunkAllocator>(
        request: &PresenceRequest<'_, A>,
    ) -> Result<Self, StanzaErrorCondition> {
        let sender = request.sender.bare();
        let target = request.target.bare();
        Ok(Self {
            sender: AccountKey::try_from(sender)
                .map_err(|_| StanzaErrorCondition::InternalServerError)?,
            target: AccountKey::try_from(target)
                .map_err(|_| StanzaErrorCondition::ServiceUnavailable)?,
            sender_jid: RosterJid::from(sender),
            target_jid: RosterJid::from(target),
        })
    }

    fn accounts(&self) -> Vec<AccountKey> {
        vec![self.sender.clone(), self.target.clone()]
    }
}

async fn check_parties(
    transaction: &impl AccountReads,
    parties: &Parties,
) -> Result<bool, HandlerError> {
    require_account(transaction, &parties.sender).await?;
    account_exists(transaction, &parties.target, "roster_write").await
}

pub(super) async fn request_subscription<A: ChunkAllocator, W: WriteTransaction>(
    roster: &super::Roster,
    transaction: &mut W,
    parties: Parties,
    stanza: &RoutedStanza<A>,
    max_pending_subscription_requests: NonZeroUsize,
) -> Result<Effects<A>, HandlerError> {
    if !check_parties(transaction, &parties).await? {
        return Err(StanzaErrorCondition::ServiceUnavailable.into());
    }
    let mut request = String::new();
    stanza
        .resolve()
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
        .write_xml(&mut request)
        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    let accounts = parties.accounts();
    let Parties {
        sender,
        target,
        sender_jid,
        target_jid,
    } = parties;
    let outcome = match state::request_subscription(
        roster,
        transaction,
        &sender,
        sender_jid,
        &target,
        &target_jid,
        request.into_bytes().into_boxed_slice(),
        max_pending_subscription_requests,
    )
    .await
    .map_err(|error| match error {
        lonewolf_storage::roster::RosterError::PendingLimitExceeded => HandlerError::described(
            StanzaErrorCondition::ResourceConstraint,
            lonewolf_xmpp::stanza::StanzaErrorText::Limit {
                prefix: "The recipient's pending subscription request limit of ",
                max: max_pending_subscription_requests.get(),
                suffix: " has been reached. Retry after the recipient handles pending requests.",
            },
        ),
        error => roster_error(error, "roster_write"),
    })? {
        RequestOutcome::ContactMissing => {
            return Err(StanzaErrorCondition::ServiceUnavailable.into());
        }
        outcome => outcome,
    };
    let stanza = stanza.clone();
    Ok(Effects::new(accounts, move |delivery| {
        let (outcome_name, item_count) = match &outcome {
            RequestOutcome::Pending { push } => ("pending", usize::from(push.is_some())),
            RequestOutcome::AutoApproved { approved: Some(_) } => ("auto_approved", 1),
            RequestOutcome::PreApproved { grantor, requester } => (
                "pre_approved",
                usize::from(grantor.is_some()) + usize::from(requester.is_some()),
            ),
            RequestOutcome::AutoApproved { approved: None } | RequestOutcome::ContactMissing => {
                ("no_change", 0)
            }
        };
        tracing::info!(
            operation = "subscribe",
            outcome = outcome_name,
            item_count,
            sender_jid = ?sender.as_str(),
            recipient_jid = ?target.as_str(),
            "roster operation committed"
        );
        Box::pin(async move {
            let mut retirements = Retirements::default();
            let mut outcome = outcome;
            let auto_changed =
                matches!(&outcome, RequestOutcome::AutoApproved { approved: Some(_) });
            match &mut outcome {
                RequestOutcome::Pending { push } => retirements.extract(&sender, push),
                RequestOutcome::AutoApproved { approved } => retirements.extract(&sender, approved),
                RequestOutcome::PreApproved { grantor, requester } => {
                    retirements.extract(&target, grantor);
                    retirements.extract(&sender, requester);
                }
                RequestOutcome::ContactMissing => {}
            }
            let result = async {
                match outcome {
                    RequestOutcome::Pending { push } => {
                        delivery.to_available(stanza).await?;
                        if let Some(mutation) = push {
                            push_change(&sender, mutation, delivery).await?;
                        }
                        Ok(())
                    }
                    RequestOutcome::AutoApproved { approved } if auto_changed => {
                        let approval = xml::approval_reply(&stanza, delivery.arena()?)?;
                        delivery.to_tagged(SessionTag::Interested, approval).await?;
                        if let Some(mutation) = approved {
                            push_change(&sender, mutation, delivery).await?;
                        }
                        delivery.current_presence(&target, &sender).await
                    }
                    RequestOutcome::PreApproved { grantor, requester } => {
                        if let Some(mutation) = grantor {
                            push_change(&target, mutation, delivery).await?;
                        }
                        let approval = xml::approval_reply(&stanza, delivery.arena()?)?;
                        delivery.to_tagged(SessionTag::Interested, approval).await?;
                        if let Some(mutation) = requester {
                            push_change(&sender, mutation, delivery).await?;
                        }
                        delivery.current_presence(&target, &sender).await
                    }
                    RequestOutcome::AutoApproved { .. } | RequestOutcome::ContactMissing => Ok(()),
                }
            }
            .await;
            retirements.finish(result, delivery).await
        })
    }))
}

pub(super) async fn approve_subscription<A: ChunkAllocator, W: WriteTransaction>(
    roster: &super::Roster,
    transaction: &mut W,
    parties: Parties,
    stanza: &RoutedStanza<A>,
) -> Result<Effects<A>, HandlerError> {
    if !check_parties(transaction, &parties).await? {
        return Ok(Effects::new(Vec::new(), move |_| {
            tracing::info!(
                operation = "approve",
                outcome = "processed",
                item_count = 0,
                sender_jid = ?parties.sender.as_str(),
                recipient_jid = ?parties.target.as_str(),
                "roster operation committed"
            );
            Box::pin(async { Ok(()) })
        }));
    }
    let accounts = parties.accounts();
    let Parties {
        sender,
        target,
        sender_jid,
        target_jid,
    } = parties;
    let target_mutation = state::update_subscription(
        roster,
        transaction,
        &target,
        &sender_jid,
        state::approve_pending_out,
    )
    .await
    .map_err(|error| roster_error(error, "roster_write"))?;
    let sender_mutation =
        state::resolve_pending(roster, transaction, &sender, &target_jid, state::grant)
            .await
            .map_err(|error| roster_error(error, "roster_write"))?;
    // An approval with no request to resolve is kept as a pre-approval and never routed.
    let pre_approval = match sender_mutation {
        Some(_) => None,
        None => state::update_subscription(
            roster,
            transaction,
            &sender,
            &target_jid,
            state::pre_approve,
        )
        .await
        .map_err(|error| roster_error(error, "roster_write"))?,
    };
    let stanza = stanza.clone();
    Ok(Effects::new(accounts, move |delivery| {
        let item_count = usize::from(target_mutation.is_some())
            + usize::from(sender_mutation.is_some())
            + usize::from(pre_approval.is_some());
        let outcome = if pre_approval.is_some() {
            "pre_approved"
        } else if item_count != 0 {
            "approved"
        } else {
            "processed"
        };
        tracing::info!(
            operation = "approve",
            outcome,
            item_count,
            sender_jid = ?sender.as_str(),
            recipient_jid = ?target.as_str(),
            "roster operation committed"
        );
        Box::pin(async move {
            let mut retirements = Retirements::default();
            let mut target_mutation = target_mutation;
            let mut sender_mutation = sender_mutation;
            let mut pre_approval = pre_approval;
            let target_changed = target_mutation.is_some();
            let sender_changed = sender_mutation.is_some();
            retirements.extract(&target, &mut target_mutation);
            retirements.extract(&sender, &mut sender_mutation);
            retirements.extract(&sender, &mut pre_approval);
            let result = async {
                if target_changed {
                    delivery.to_tagged(SessionTag::Interested, stanza).await?;
                }
                if let Some(mutation) = target_mutation {
                    push_change(&target, mutation, delivery).await?;
                }
                if let Some(mutation) = sender_mutation {
                    push_change(&sender, mutation, delivery).await?;
                }
                if sender_changed {
                    delivery.current_presence(&sender, &target).await?;
                }
                if let Some(mutation) = pre_approval {
                    push_change(&sender, mutation, delivery).await?;
                }
                Ok(())
            }
            .await;
            retirements.finish(result, delivery).await
        })
    }))
}

pub(super) async fn cancel_subscription<A: ChunkAllocator, W: WriteTransaction>(
    roster: &super::Roster,
    transaction: &mut W,
    parties: Parties,
    stanza: &RoutedStanza<A>,
) -> Result<Effects<A>, HandlerError> {
    let subscriber_exists = check_parties(transaction, &parties).await?;
    let accounts = parties.accounts();
    let Parties {
        sender,
        target,
        sender_jid,
        target_jid,
    } = parties;
    let outcome = state::cancel_subscription(
        roster,
        transaction,
        &sender,
        &target_jid,
        subscriber_exists.then_some((&target, &sender_jid)),
    )
    .await
    .map_err(|error| roster_error(error, "roster_write"))?;
    let stanza = stanza.clone();
    Ok(Effects::new(accounts, move |delivery| {
        let item_count =
            usize::from(outcome.subscriber.is_some()) + usize::from(outcome.grantor.is_some());
        tracing::info!(
            operation = "cancel",
            outcome = if item_count != 0 || outcome.route || outcome.send_unavailable {
                "cancelled"
            } else {
                "processed"
            },
            item_count,
            sender_jid = ?sender.as_str(),
            recipient_jid = ?target.as_str(),
            "roster operation committed"
        );
        Box::pin(async move {
            let mut retirements = Retirements::default();
            let mut outcome = outcome;
            retirements.extract(&target, &mut outcome.subscriber);
            retirements.extract(&sender, &mut outcome.grantor);
            let result = async {
                if outcome.send_unavailable {
                    delivery.unavailable_presence(&sender, &target).await?;
                }
                if outcome.route {
                    delivery.to_tagged(SessionTag::Interested, stanza).await?;
                }
                if let Some(mutation) = outcome.subscriber {
                    push_change(&target, mutation, delivery).await?;
                }
                if let Some(mutation) = outcome.grantor {
                    push_change(&sender, mutation, delivery).await?;
                }
                Ok(())
            }
            .await;
            retirements.finish(result, delivery).await
        })
    }))
}

pub(super) async fn withdraw_subscription<A: ChunkAllocator, W: WriteTransaction>(
    roster: &super::Roster,
    transaction: &mut W,
    parties: Parties,
    stanza: &RoutedStanza<A>,
) -> Result<Effects<A>, HandlerError> {
    let contact_exists = check_parties(transaction, &parties).await?;
    let accounts = parties.accounts();
    let Parties {
        sender,
        target,
        sender_jid,
        target_jid,
    } = parties;
    let outcome = state::unsubscribe(
        roster,
        transaction,
        &sender,
        &target_jid,
        contact_exists.then_some((&target, &sender_jid)),
    )
    .await
    .map_err(|error| roster_error(error, "roster_write"))?;
    let stanza = stanza.clone();
    Ok(Effects::new(accounts, move |delivery| {
        let item_count =
            usize::from(outcome.contact.is_some()) + usize::from(outcome.subscriber.is_some());
        tracing::info!(
            operation = "unsubscribe",
            outcome = if item_count != 0 || outcome.notify_contact {
                "withdrawn"
            } else {
                "processed"
            },
            item_count,
            sender_jid = ?sender.as_str(),
            recipient_jid = ?target.as_str(),
            "roster operation committed"
        );
        Box::pin(async move {
            let mut retirements = Retirements::default();
            let mut outcome = outcome;
            retirements.extract(&target, &mut outcome.contact);
            retirements.extract(&sender, &mut outcome.subscriber);
            let result = async {
                if outcome.notify_contact {
                    delivery.to_tagged(SessionTag::Interested, stanza).await?;
                }
                if let Some(mutation) = outcome.contact {
                    push_change(&target, mutation, delivery).await?;
                }
                if let Some(mutation) = outcome.subscriber {
                    push_change(&sender, mutation, delivery).await?;
                }
                if outcome.send_unavailable {
                    delivery.unavailable_presence(&target, &sender).await?;
                }
                Ok(())
            }
            .await;
            retirements.finish(result, delivery).await
        })
    }))
}

/// Withdraw and cancel in the same order as separate subscription requests.
pub(super) async fn remove_item<A: ChunkAllocator, W: WriteTransaction>(
    roster: &super::Roster,
    transaction: &mut W,
    owner: AccountKey,
    contact: RosterJid,
    owner_jid: RosterJid,
    hosts: &dyn HostLookup,
) -> Result<Effects<A>, HandlerError> {
    require_account(transaction, &owner).await?;
    let contact_account = stored_local_account(transaction, &contact, hosts).await?;
    let removal = state::remove_item(
        roster,
        transaction,
        &owner,
        &owner_jid,
        &contact,
        contact_account.as_ref(),
    )
    .await
    .map_err(|error| roster_error(error, "roster_write"))?
    .ok_or(StanzaErrorCondition::ItemNotFound)?;
    let mut accounts = vec![owner.clone()];
    accounts.extend(contact_account.clone());
    Ok(Effects::new(accounts, move |delivery| {
        tracing::info!(
            operation = "remove",
            outcome = "removed",
            item_count = 1,
            owner_jid = ?owner.as_str(),
            contact_jid = ?contact.as_str(),
            "roster operation committed"
        );
        Box::pin(async move {
            let mut retirements = Retirements::default();
            let mut removal = removal;
            if let Some(contact) = &contact_account {
                retirements.extract(contact, &mut removal.contact);
            }
            let result = async {
                push_removal(&owner, contact, removal.version, delivery).await?;
                if let Some(contact_account) = contact_account {
                    let contact_granted =
                        notify_removed_contact(&owner, &contact_account, removal, delivery).await?;
                    if contact_granted {
                        delivery
                            .unavailable_presence(&contact_account, &owner)
                            .await?;
                    }
                }
                Ok(())
            }
            .await;
            retirements.finish(result, delivery).await
        })
    }))
}

#[derive(Clone, Copy)]
struct CleanupProjection {
    owner: Option<RosterSubscription>,
    pending: bool,
    counterpart: Option<RosterSubscription>,
    changed: Option<RosterSubscription>,
}

fn cleanup_projection(
    owner: Option<RosterSubscription>,
    pending: bool,
    counterpart: Option<RosterSubscription>,
) -> CleanupProjection {
    let changed = counterpart.and_then(|old| {
        let next = if owner.is_some() {
            RosterSubscription {
                state: SubscriptionState::None,
                pending_out: false,
                approved: old.approved,
            }
        } else {
            RosterSubscription {
                state: match old.state {
                    SubscriptionState::To => SubscriptionState::None,
                    SubscriptionState::Both => SubscriptionState::From,
                    state => state,
                },
                pending_out: false,
                approved: old.approved,
            }
        };
        (next != old).then_some(next)
    });
    CleanupProjection {
        owner,
        pending,
        counterpart,
        changed,
    }
}

async fn cleanup_version(
    before: &impl RosterReads,
    contact: &AccountKey,
) -> Result<RosterVersion, RosterError> {
    before
        .roster_version(contact)
        .await?
        .get()
        .checked_add(1)
        .map(RosterVersion::new)
        .ok_or(RosterError::ValueTooLarge)
}

async fn prepare_cleanup<W: WriteTransaction>(
    transaction: &mut W,
    before: &W::Snapshot,
    owner: &AccountKey,
    owner_jid: &RosterJid,
    contact: &RosterJid,
    projection: CleanupProjection,
    counterpart: Option<&AccountKey>,
) -> Result<(), HandlerError> {
    let operation = async {
        if projection.owner.is_some() {
            transaction
                .remove_roster_subscription(owner, contact)
                .await?;
        }
        transaction.remove_pending_request(owner, contact).await?;
        if let Some(account) = counterpart {
            if projection.owner.is_some() {
                transaction
                    .remove_pending_request(account, owner_jid)
                    .await?;
            }
            if let Some(subscription) = projection.changed {
                let expected = cleanup_version(before, account).await?;
                let actual = transaction
                    .set_roster_subscription(before, account, owner_jid, subscription)
                    .await?;
                if actual != Some(expected) {
                    return Err(lonewolf_storage::StorageError::new(
                        lonewolf_storage::StorageErrorKind::CorruptData,
                    )
                    .into());
                }
            }
        }
        Ok::<_, RosterError>(())
    }
    .await;
    operation.map_err(|error| roster_error(error, "roster_cleanup"))
}

pub(super) async fn forget_account<
    A: ChunkAllocator,
    W: WriteTransaction + lonewolf_storage::roster::RosterWrites<Snapshot = R>,
    R: ReadTransaction + 'static,
>(
    roster: &super::Roster,
    transaction: &mut W,
    account: &AccountKey,
    before: Arc<R>,
    hosts: &dyn HostLookup,
) -> Result<crate::Deliver<A>, HandlerError> {
    let owner_jid = RosterJid::from(account);
    let mut after = None;
    let mut item_count = 0usize;
    while let Some((contact, subscription)) = before
        .next_roster_subscription(account, after.as_ref())
        .await
        .map_err(|e| roster_error(e, "roster_cleanup"))?
    {
        let counterpart = stored_local_account(before.as_ref(), &contact, hosts)
            .await?
            .filter(|contact| contact != account);
        let other = match &counterpart {
            Some(other) => before
                .roster_subscription(other, &owner_jid)
                .await
                .map_err(|e| roster_error(e, "roster_cleanup"))?,
            None => None,
        };
        let pending = before
            .pending_request_exists(account, &contact)
            .await
            .map_err(|e| roster_error(e, "roster_cleanup"))?;
        prepare_cleanup(
            transaction,
            before.as_ref(),
            account,
            &owner_jid,
            &contact,
            cleanup_projection(Some(subscription), pending, other),
            counterpart.as_ref(),
        )
        .await?;
        after = Some(contact);
        item_count += 1;
    }
    after = None;
    let mut pending_count = 0usize;
    while let Some(sender) = before
        .next_pending_sender(account, after.as_ref())
        .await
        .map_err(|e| roster_error(e, "roster_cleanup"))?
    {
        if before
            .roster_subscription(account, &sender)
            .await
            .map_err(|e| roster_error(e, "roster_cleanup"))?
            .is_none()
        {
            let counterpart = stored_local_account(before.as_ref(), &sender, hosts)
                .await?
                .filter(|contact| contact != account);
            let other = match &counterpart {
                Some(other) => before
                    .roster_subscription(other, &owner_jid)
                    .await
                    .map_err(|e| roster_error(e, "roster_cleanup"))?,
                None => None,
            };
            prepare_cleanup(
                transaction,
                before.as_ref(),
                account,
                &owner_jid,
                &sender,
                cleanup_projection(None, true, other),
                counterpart.as_ref(),
            )
            .await?;
        }
        after = Some(sender);
        pending_count += 1;
    }
    transaction
        .clear_roster(account)
        .await
        .map_err(|e| roster_error(e, "roster_cleanup"))?;
    let owner = account.clone();
    let quotas = super::Roster::new(roster.limits.clone());
    Ok(Box::new(move |delivery| {
        Box::pin(async move {
            tracing::info!(operation="cleanup",outcome="committed",item_count,pending_count,owner_jid=?owner.as_str(),"roster operation committed");
            let mut failure = None;
            let mut after = None;
            while let Some((contact, subscription)) = before
                .next_roster_subscription(&owner, after.as_ref())
                .await
                .map_err(|_| DeliveryError)?
            {
                let counterpart = stored_local_account(before.as_ref(), &contact, delivery)
                    .await
                    .map_err(|_| DeliveryError)?
                    .filter(|contact| contact != &owner);
                if let Some(counterpart) = counterpart {
                    let other = before
                        .roster_subscription(&counterpart, &owner_jid)
                        .await
                        .map_err(|_| DeliveryError)?;
                    let pending = before
                        .pending_request_exists(&owner, &contact)
                        .await
                        .map_err(|_| DeliveryError)?;
                    let projection = cleanup_projection(Some(subscription), pending, other);
                    let removal = Removal {
                        version: RosterVersion::new(0),
                        subscription: projection.owner.unwrap_or_default(),
                        pending_request: projection.pending,
                        contact_before: projection.counterpart,
                        contact: None,
                    };
                    if let Err(error) =
                        notify_removed_contact(&owner, &counterpart, removal, delivery).await
                    {
                        failure.get_or_insert(error);
                        after = Some(contact);
                        continue;
                    }
                    if let Err(error) = replay_cleanup_push(
                        &quotas,
                        before.as_ref(),
                        &counterpart,
                        &owner_jid,
                        projection.changed,
                        delivery,
                    )
                    .await
                    {
                        failure.get_or_insert(error);
                    }
                }
                after = Some(contact);
            }
            after = None;
            while let Some(sender) = before
                .next_pending_sender(&owner, after.as_ref())
                .await
                .map_err(|_| DeliveryError)?
            {
                if before
                    .roster_subscription(&owner, &sender)
                    .await
                    .map_err(|_| DeliveryError)?
                    .is_none()
                {
                    let counterpart = stored_local_account(before.as_ref(), &sender, delivery)
                        .await
                        .map_err(|_| DeliveryError)?
                        .filter(|contact| contact != &owner);
                    if let Some(counterpart) = counterpart {
                        let other = before
                            .roster_subscription(&counterpart, &owner_jid)
                            .await
                            .map_err(|_| DeliveryError)?;
                        let projection = cleanup_projection(None, true, other);
                        let cancellation = Cancellation {
                            route: true,
                            send_unavailable: false,
                            grantor: None,
                            subscriber: None,
                        };
                        if let Err(error) =
                            notify_cancelled_requester(&owner, &counterpart, cancellation, delivery)
                                .await
                        {
                            failure.get_or_insert(error);
                            after = Some(sender);
                            continue;
                        }
                        if let Err(error) = replay_cleanup_push(
                            &quotas,
                            before.as_ref(),
                            &counterpart,
                            &owner_jid,
                            projection.changed,
                            delivery,
                        )
                        .await
                        {
                            failure.get_or_insert(error);
                        }
                    }
                }
                after = Some(sender);
            }
            failure.map_or(Ok(()), Err)
        })
    }))
}

async fn replay_cleanup_push<A: ChunkAllocator>(
    roster: &super::Roster,
    before: &impl RosterReads,
    contact: &AccountKey,
    owner: &RosterJid,
    changed: Option<RosterSubscription>,
    delivery: &dyn Delivery<A>,
) -> Result<(), DeliveryError> {
    let Some(subscription) = changed else {
        return Ok(());
    };
    let mutation = async {
        let version = cleanup_version(before, contact).await?;
        let mut item = before
            .roster_item(contact, owner, roster.quota(contact))
            .await?
            .ok_or_else(|| {
                lonewolf_storage::StorageError::new(lonewolf_storage::StorageErrorKind::CorruptData)
            })?;
        item.subscription = subscription;
        Ok::<_, RosterError>(RosterMutation {
            version,
            value: item,
        })
    }
    .await;
    match mutation {
        Ok(mutation) => push_roster(contact, mutation, delivery).await,
        Err(RosterError::QuotaExceeded) => {
            delivery
                .retire_tagged(contact, SessionTag::Interested)
                .await
        }
        Err(_) => {
            let _ = delivery
                .retire_tagged(contact, SessionTag::Interested)
                .await;
            Err(DeliveryError)
        }
    }
}

async fn stored_local_account(
    transaction: &impl AccountReads,
    jid: &RosterJid,
    hosts: &dyn HostLookup,
) -> Result<Option<AccountKey>, HandlerError> {
    match local_candidate(jid, hosts) {
        Some(candidate) if account_exists(transaction, &candidate, "roster_write").await? => {
            Ok(Some(candidate))
        }
        _ => Ok(None),
    }
}

async fn notify_cancelled_requester<A: ChunkAllocator>(
    owner: &AccountKey,
    sender: &AccountKey,
    cancellation: Cancellation,
    delivery: &dyn Delivery<A>,
) -> Result<(), DeliveryError> {
    if cancellation.route {
        let (_, cancelled) = xml::subscription_withdrawals(owner, sender, delivery.arena()?)?;
        delivery
            .to_tagged(SessionTag::Interested, cancelled)
            .await?;
    }
    if let Some(mutation) = cancellation.subscriber {
        push_change(sender, mutation, delivery).await?;
    }
    Ok(())
}

/// Reveal each side's resource addresses only under that side's grant.
/// Returns whether the contact granted the owner.
async fn notify_removed_contact<A: ChunkAllocator>(
    owner: &AccountKey,
    contact: &AccountKey,
    removal: Removal,
    delivery: &dyn Delivery<A>,
) -> Result<bool, DeliveryError> {
    let owner_granted = grants(removal.subscription.state);
    let contact_granted = grants(removal.contact_before.unwrap_or_default().state);
    let cancel = owner_granted || removal.pending_request;
    if owner_granted {
        delivery.unavailable_presence(owner, contact).await?;
    }
    if contact_granted || cancel {
        let (withdrawal, cancellation) =
            xml::subscription_withdrawals(owner, contact, delivery.arena()?)?;
        if contact_granted {
            delivery
                .to_tagged(SessionTag::Interested, withdrawal)
                .await?;
        }
        if cancel {
            delivery
                .to_tagged(SessionTag::Interested, cancellation)
                .await?;
        }
    }
    if let Some(mutation) = removal.contact {
        push_change(contact, mutation, delivery).await?;
    }
    Ok(contact_granted)
}

fn local_candidate(jid: &RosterJid, hosts: &dyn HostLookup) -> Option<AccountKey> {
    AccountKey::try_from(jid)
        .ok()
        .filter(|account| hosts.is_local_host(account.domain()))
}
