// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::WriteTransaction;
use lonewolf_storage::account::{AccountKey, AccountReads};
use lonewolf_storage::roster::RosterJid;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaErrorCondition};

use super::state::{self, Cancellation, Removal, RequestOutcome, grants};
use super::{account_exists, push_removal, push_roster, require_account, xml};
use crate::Effects;
use crate::delivery::{Delivery, DeliveryError, HandlerError, HostLookup, SessionTag};
use crate::presence::PresenceRequest;

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
) -> Result<bool, StanzaErrorCondition> {
    require_account(transaction, &parties.sender).await?;
    account_exists(transaction, &parties.target).await
}

pub(super) async fn request_subscription<A: ChunkAllocator, W: WriteTransaction>(
    transaction: &mut W,
    parties: Parties,
    stanza: &RoutedStanza<A>,
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
        transaction,
        &sender,
        sender_jid,
        &target,
        &target_jid,
        request.into_bytes().into_boxed_slice(),
    )
    .await?
    {
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
            "roster operation committed"
        );
        Box::pin(async move {
            match outcome {
                RequestOutcome::Pending { push } => {
                    delivery.to_available(stanza).await?;
                    if let Some(mutation) = push {
                        push_roster(&sender, mutation, delivery).await?;
                    }
                    Ok(())
                }
                RequestOutcome::AutoApproved {
                    approved: Some(mutation),
                } => {
                    let approval = xml::approval_reply(&stanza, delivery.arena()?)?;
                    delivery.to_tagged(SessionTag::Interested, approval).await?;
                    push_roster(&sender, mutation, delivery).await?;
                    delivery.current_presence(&target, &sender).await
                }
                RequestOutcome::PreApproved { grantor, requester } => {
                    if let Some(mutation) = grantor {
                        push_roster(&target, mutation, delivery).await?;
                    }
                    let approval = xml::approval_reply(&stanza, delivery.arena()?)?;
                    delivery.to_tagged(SessionTag::Interested, approval).await?;
                    if let Some(mutation) = requester {
                        push_roster(&sender, mutation, delivery).await?;
                    }
                    delivery.current_presence(&target, &sender).await
                }
                RequestOutcome::AutoApproved { approved: None }
                | RequestOutcome::ContactMissing => Ok(()),
            }
        })
    }))
}

pub(super) async fn approve_subscription<A: ChunkAllocator, W: WriteTransaction>(
    transaction: &mut W,
    parties: Parties,
    stanza: &RoutedStanza<A>,
) -> Result<Effects<A>, HandlerError> {
    if !check_parties(transaction, &parties).await? {
        return Ok(Effects::new(Vec::new(), |_| {
            tracing::info!(
                operation = "approve",
                outcome = "processed",
                item_count = 0,
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
        transaction,
        &target,
        &sender_jid,
        state::approve_pending_out,
    )
    .await?;
    let sender_mutation =
        state::resolve_pending(transaction, &sender, &target_jid, state::grant).await?;
    // An approval with no request to resolve is kept as a pre-approval and never routed.
    let pre_approval = match sender_mutation {
        Some(_) => None,
        None => {
            state::update_subscription(transaction, &sender, &target_jid, state::pre_approve)
                .await?
        }
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
            "roster operation committed"
        );
        Box::pin(async move {
            if let Some(mutation) = target_mutation {
                delivery.to_tagged(SessionTag::Interested, stanza).await?;
                push_roster(&target, mutation, delivery).await?;
            }
            if let Some(mutation) = sender_mutation {
                push_roster(&sender, mutation, delivery).await?;
                delivery.current_presence(&sender, &target).await?;
            }
            if let Some(mutation) = pre_approval {
                push_roster(&sender, mutation, delivery).await?;
            }
            Ok(())
        })
    }))
}

pub(super) async fn cancel_subscription<A: ChunkAllocator, W: WriteTransaction>(
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
        transaction,
        &sender,
        &target_jid,
        subscriber_exists.then_some((&target, &sender_jid)),
    )
    .await?;
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
            "roster operation committed"
        );
        Box::pin(async move {
            if outcome.send_unavailable {
                delivery.unavailable_presence(&sender, &target).await?;
            }
            if outcome.route {
                delivery.to_tagged(SessionTag::Interested, stanza).await?;
            }
            if let Some(mutation) = outcome.subscriber {
                push_roster(&target, mutation, delivery).await?;
            }
            if let Some(mutation) = outcome.grantor {
                push_roster(&sender, mutation, delivery).await?;
            }
            Ok(())
        })
    }))
}

pub(super) async fn withdraw_subscription<A: ChunkAllocator, W: WriteTransaction>(
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
        transaction,
        &sender,
        &target_jid,
        contact_exists.then_some((&target, &sender_jid)),
    )
    .await?;
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
            "roster operation committed"
        );
        Box::pin(async move {
            if outcome.notify_contact {
                delivery.to_tagged(SessionTag::Interested, stanza).await?;
            }
            if let Some(mutation) = outcome.contact {
                push_roster(&target, mutation, delivery).await?;
            }
            if let Some(mutation) = outcome.subscriber {
                push_roster(&sender, mutation, delivery).await?;
            }
            if outcome.notify_contact {
                delivery.unavailable_presence(&target, &sender).await?;
            }
            Ok(())
        })
    }))
}

/// Withdraw and cancel in the same order as separate subscription requests.
pub(super) async fn remove_item<A: ChunkAllocator, W: WriteTransaction>(
    transaction: &mut W,
    owner: AccountKey,
    contact: RosterJid,
    owner_jid: RosterJid,
    hosts: &dyn HostLookup,
) -> Result<Effects<A>, HandlerError> {
    require_account(transaction, &owner).await?;
    let contact_account = stored_local_account(transaction, &contact, hosts).await?;
    let removal = state::remove_item(
        transaction,
        &owner,
        &owner_jid,
        &contact,
        contact_account.as_ref(),
    )
    .await?
    .ok_or(StanzaErrorCondition::ItemNotFound)?;
    let mut accounts = vec![owner.clone()];
    accounts.extend(contact_account.clone());
    Ok(Effects::new(accounts, move |delivery| {
        tracing::info!(
            operation = "remove",
            outcome = "removed",
            item_count = 1,
            "roster operation committed"
        );
        Box::pin(async move {
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
        })
    }))
}

/// Continue cleanup notifications after a failure and return the first error.
pub(super) async fn forget_account<A: ChunkAllocator, W: WriteTransaction>(
    transaction: &mut W,
    account: &AccountKey,
    hosts: &dyn HostLookup,
) -> Result<Effects<A>, HandlerError> {
    let account_jid = RosterJid::from(account);
    let items = transaction.roster(account).await?.items;
    let requests = transaction.pending_requests(account).await?;
    let item_count = items.len();
    let pending_count = requests.len();
    let mut removals = Vec::new();
    for item in items {
        let contact = stored_local_account(transaction, &item.jid, hosts).await?;
        let removal = state::remove_item(
            transaction,
            account,
            &account_jid,
            &item.jid,
            contact.as_ref(),
        )
        .await?;
        if let (Some(removal), Some(contact)) = (removal, contact) {
            removals.push((contact, removal));
        }
    }
    let mut cancellations = Vec::new();
    for request in requests {
        let sender = stored_local_account(transaction, &request.sender, hosts).await?;
        let cancellation = state::cancel_subscription(
            transaction,
            account,
            &request.sender,
            sender.as_ref().map(|sender| (sender, &account_jid)),
        )
        .await?;
        if let Some(sender) = sender {
            cancellations.push((sender, cancellation));
        }
    }
    transaction.clear_roster(account).await?;
    let mut accounts = Vec::with_capacity(1 + removals.len() + cancellations.len());
    accounts.push(account.clone());
    accounts.extend(removals.iter().map(|(contact, _)| contact.clone()));
    accounts.extend(cancellations.iter().map(|(sender, _)| sender.clone()));
    let owner = account.clone();
    Ok(Effects::new(accounts, move |delivery| {
        tracing::info!(
            operation = "cleanup",
            outcome = "committed",
            item_count,
            pending_count,
            removal_count = removals.len(),
            cancellation_count = cancellations.len(),
            "roster operation committed"
        );
        Box::pin(async move {
            let mut failure = None;
            for (contact, removal) in removals {
                if let Err(error) =
                    notify_removed_contact(&owner, &contact, removal, delivery).await
                {
                    failure.get_or_insert(error);
                }
            }
            for (sender, cancellation) in cancellations {
                if let Err(error) =
                    notify_cancelled_requester(&owner, &sender, cancellation, delivery).await
                {
                    failure.get_or_insert(error);
                }
            }
            failure.map_or(Ok(()), Err)
        })
    }))
}

async fn stored_local_account(
    transaction: &impl AccountReads,
    jid: &RosterJid,
    hosts: &dyn HostLookup,
) -> Result<Option<AccountKey>, StanzaErrorCondition> {
    match local_candidate(jid, hosts) {
        Some(candidate) if account_exists(transaction, &candidate).await? => Ok(Some(candidate)),
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
        push_roster(sender, mutation, delivery).await?;
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
        push_roster(contact, mutation, delivery).await?;
    }
    Ok(contact_granted)
}

fn local_candidate(jid: &RosterJid, hosts: &dyn HostLookup) -> Option<AccountKey> {
    AccountKey::try_from(jid)
        .ok()
        .filter(|account| hosts.is_local_host(account.domain()))
}
