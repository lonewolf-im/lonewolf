// SPDX-License-Identifier: Apache-2.0

use futures_executor::block_on;

use super::{TestResult, item, jid, key, pending, read, write};
use crate::account::AccountKey;
use crate::roster::{
    PendingResolution, RosterJid, RosterReads, RosterSubscription, RosterVersion, RosterWrites,
    SubscriptionRequestOutcome, SubscriptionState,
};
use crate::{Storage, WriteTransaction};

async fn set_subscription<S: Storage>(
    storage: &S,
    owner: &AccountKey,
    contact: &RosterJid,
    subscription: RosterSubscription,
) -> TestResult {
    write(storage, async |tx| {
        tx.update_subscription(owner, contact, move |_| Some(subscription))
            .await
    })
    .await?;
    Ok(())
}

fn state(state: SubscriptionState) -> RosterSubscription {
    RosterSubscription {
        state,
        pending_out: false,
        approved: false,
    }
}

pub(crate) fn new_roster_is_empty_at_version_zero<S: Storage>(storage: S) -> TestResult {
    let alice = key("alice@example.com")?;
    block_on(async {
        let snapshot = read(&storage, async |tx| tx.roster(&alice).await).await?;
        assert_eq!(snapshot.version, RosterVersion::default());
        assert!(snapshot.items.is_empty());
        Ok(())
    })
}

pub(crate) fn upsert_stores_editable_fields_and_advances_version<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let contact = jid("BOB@EXAMPLE.COM")?;
    let update = item("BOB@EXAMPLE.COM", Some("Bob"), &["Friends", "Work"])?;
    block_on(async {
        let mutation = write(&storage, async |tx| tx.upsert(&owner, update).await).await?;
        assert_eq!(mutation.version.get(), 1);
        assert_eq!(mutation.value.jid, contact);
        assert_eq!(mutation.value.name.as_deref(), Some("Bob"));
        assert_eq!(
            [
                mutation.value.groups[0].as_ref(),
                mutation.value.groups[1].as_ref()
            ],
            ["Friends", "Work"]
        );
        let reader = storage.begin_read().await?;
        assert_eq!(
            reader.roster_item(&owner, &contact).await?,
            Some(mutation.value)
        );
        let snapshot = reader.roster(&owner).await?;
        assert_eq!(snapshot.version.get(), 1);
        assert_eq!(snapshot.items.len(), 1);
        Ok(())
    })
}

pub(crate) fn editable_and_subscription_updates_preserve_each_other<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    let original = item("bob@example.com", Some("Bob"), &["Friends"])?;
    let renamed = item("bob@example.com", Some("Robert"), &["Work"])?;
    let subscription = RosterSubscription {
        state: SubscriptionState::Both,
        pending_out: true,
        approved: true,
    };
    block_on(async {
        write(&storage, async |tx| tx.upsert(&owner, original).await).await?;
        let changed = write(&storage, async |tx| {
            tx.update_subscription(&owner, &contact, move |_| Some(subscription))
                .await
        })
        .await?
        .ok_or("subscription was not changed")?;
        assert_eq!(changed.version.get(), 2);
        assert_eq!(changed.value.name.as_deref(), Some("Bob"));
        assert_eq!(changed.value.subscription, subscription);

        let changed = write(&storage, async |tx| tx.upsert(&owner, renamed).await).await?;
        assert_eq!(changed.version.get(), 3);
        assert_eq!(changed.value.name.as_deref(), Some("Robert"));
        assert_eq!(changed.value.subscription, subscription);
        Ok(())
    })
}

pub(crate) fn remove_roster_item_returns_the_old_item_and_only_advances_an_existing_roster<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    let update = item("bob@example.com", Some("Bob"), &[])?;
    block_on(async {
        write(&storage, async |tx| tx.upsert(&owner, update).await).await?;
        let mut writer = storage.begin_write().await?;
        let removed = writer
            .remove_roster_item(&owner, &contact)
            .await?
            .ok_or("missing removal")?;
        assert_eq!(removed.version.get(), 2);
        assert_eq!(removed.value.name.as_deref(), Some("Bob"));
        assert!(writer.roster_item(&owner, &contact).await?.is_none());
        assert!(writer.remove_roster_item(&owner, &contact).await?.is_none());
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        assert!(reader.roster_item(&owner, &contact).await?.is_none());
        assert_eq!(reader.roster(&owner).await?.version.get(), 2);
        Ok(())
    })
}

pub(crate) fn pending_request_is_deduplicated_by_sender_and_can_be_removed<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let sender = jid("bob@example.com")?;
    let first = pending("bob@example.com", b"<presence id='first'/>")?;
    let last = pending("bob@example.com", b"<presence id='last'/>")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer.put_pending_request(&owner, first).await?;
        writer.put_pending_request(&owner, last).await?;
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        let requests = reader.pending_requests(&owner).await?;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].sender, sender);
        assert_eq!(requests[0].stanza.as_ref(), b"<presence id='last'/>");
        assert_eq!(
            reader.pending_request(&owner, &sender).await?,
            Some(requests[0].clone())
        );
        drop(reader);

        let mut writer = storage.begin_write().await?;
        assert!(writer.remove_pending_request(&owner, &sender).await?);
        assert!(!writer.remove_pending_request(&owner, &sender).await?);
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        assert!(reader.pending_requests(&owner).await?.is_empty());
        assert!(reader.pending_request(&owner, &sender).await?.is_none());
        Ok(())
    })
}

pub(crate) fn resolving_a_pending_request_removes_it_and_applies_the_transition<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let sender = jid("bob@example.com")?;
    let request = pending("bob@example.com", b"<presence type='subscribe'/>")?;
    let repeated = pending("bob@example.com", b"<presence type='subscribe'/>")?;
    block_on(async {
        assert!(
            write(&storage, async |tx| {
                tx.resolve_pending(&owner, &sender, |_| None).await
            })
            .await?
            .is_none()
        );

        write(&storage, async |tx| {
            tx.put_pending_request(&owner, request).await
        })
        .await?;
        let resolution = write(&storage, async |tx| {
            tx.resolve_pending(&owner, &sender, |mut current| {
                current.state = SubscriptionState::From;
                Some(current)
            })
            .await
        })
        .await?
        .ok_or("missing pending request")?;
        let mutation = resolution.mutation.ok_or("subscription was not changed")?;
        assert_eq!(mutation.version.get(), 1);
        assert_eq!(mutation.value.subscription.state, SubscriptionState::From);
        let reader = storage.begin_read().await?;
        assert!(reader.pending_requests(&owner).await?.is_empty());
        assert_eq!(
            reader.roster_item(&owner, &sender).await?,
            Some(mutation.value)
        );
        drop(reader);

        write(&storage, async |tx| {
            tx.put_pending_request(&owner, repeated).await
        })
        .await?;
        let denied = write(&storage, async |tx| {
            tx.resolve_pending(&owner, &sender, |_| None).await
        })
        .await?;
        assert_eq!(denied, Some(PendingResolution { mutation: None }));
        let reader = storage.begin_read().await?;
        assert!(reader.pending_requests(&owner).await?.is_empty());
        assert_eq!(reader.roster(&owner).await?.version.get(), 1);
        Ok(())
    })
}

pub(crate) fn subscription_request_updates_the_sender_and_recipient_in_one_transaction<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = key("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    let first = pending("alice@example.com", b"<presence id='first'/>")?;
    let last = pending("alice@example.com", b"<presence id='last'/>")?;
    block_on(async {
        let outcome = write(&storage, async |tx| {
            tx.request_subscription(&alice, &bob_jid, &bob, first).await
        })
        .await?;
        let SubscriptionRequestOutcome::Pending {
            mutation: Some(mutation),
        } = outcome
        else {
            return Err("subscription was not changed".into());
        };
        assert_eq!(mutation.version.get(), 1);
        assert!(mutation.value.subscription.pending_out);
        let reader = storage.begin_read().await?;
        assert_eq!(
            reader.roster_item(&alice, &bob_jid).await?,
            Some(mutation.value)
        );
        let requests = reader.pending_requests(&bob).await?;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].sender, alice_jid);
        assert_eq!(requests[0].stanza.as_ref(), b"<presence id='first'/>");
        drop(reader);

        let repeated = write(&storage, async |tx| {
            tx.request_subscription(&alice, &bob_jid, &bob, last).await
        })
        .await?;
        assert_eq!(
            repeated,
            SubscriptionRequestOutcome::Pending { mutation: None }
        );
        let reader = storage.begin_read().await?;
        assert_eq!(reader.roster(&alice).await?.version.get(), 1);
        assert_eq!(
            reader.pending_requests(&bob).await?[0].stanza.as_ref(),
            b"<presence id='last'/>"
        );
        Ok(())
    })
}

pub(crate) fn established_subscription_requests_are_automatically_approved_without_changes<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    for (index, (subscriber_state, recipient_state)) in [
        (SubscriptionState::To, SubscriptionState::From),
        (SubscriptionState::Both, SubscriptionState::Both),
    ]
    .into_iter()
    .enumerate()
    {
        let alice = key(&format!("alice{index}@example.com"))?;
        let bob = key(&format!("bob{index}@example.com"))?;
        let alice_jid = RosterJid::from(&alice);
        let bob_jid = RosterJid::from(&bob);
        let request = pending(alice.as_str(), b"<presence id='repeat'/>")?;
        block_on(async {
            set_subscription(&storage, &alice, &bob_jid, state(subscriber_state)).await?;
            set_subscription(&storage, &bob, &alice_jid, state(recipient_state)).await?;

            let outcome = write(&storage, async |tx| {
                tx.request_subscription(&alice, &bob_jid, &bob, request)
                    .await
            })
            .await?;
            assert_eq!(
                outcome,
                SubscriptionRequestOutcome::AutoApprove { mutation: None }
            );
            let reader = storage.begin_read().await?;
            assert!(reader.pending_requests(&bob).await?.is_empty());
            let alice_roster = reader.roster(&alice).await?;
            assert_eq!(alice_roster.version.get(), 1);
            assert_eq!(alice_roster.items[0].subscription.state, subscriber_state);
            assert!(!alice_roster.items[0].subscription.pending_out);
            assert_eq!(reader.roster(&bob).await?.version.get(), 1);
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

pub(crate) fn automatic_approval_resolves_an_outstanding_request<S: Storage>(
    storage: S,
) -> TestResult {
    for (index, (subscriber_state, recipient_state, approved_state)) in [
        (
            SubscriptionState::None,
            SubscriptionState::From,
            SubscriptionState::To,
        ),
        (
            SubscriptionState::From,
            SubscriptionState::Both,
            SubscriptionState::Both,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let alice = key(&format!("alice{index}@example.com"))?;
        let bob = key(&format!("bob{index}@example.com"))?;
        let alice_jid = RosterJid::from(&alice);
        let bob_jid = RosterJid::from(&bob);
        let request = pending(alice.as_str(), b"<presence id='repeat'/>")?;
        block_on(async {
            set_subscription(
                &storage,
                &alice,
                &bob_jid,
                RosterSubscription {
                    state: subscriber_state,
                    pending_out: true,
                    approved: false,
                },
            )
            .await?;
            set_subscription(&storage, &bob, &alice_jid, state(recipient_state)).await?;

            let outcome = write(&storage, async |tx| {
                tx.request_subscription(&alice, &bob_jid, &bob, request)
                    .await
            })
            .await?;
            let SubscriptionRequestOutcome::AutoApprove {
                mutation: Some(mutation),
            } = outcome
            else {
                return Err("outstanding request was not approved".into());
            };
            assert_eq!(mutation.version.get(), 2);
            assert_eq!(mutation.value.subscription.state, approved_state);
            assert!(!mutation.value.subscription.pending_out);
            let reader = storage.begin_read().await?;
            assert!(reader.pending_requests(&bob).await?.is_empty());
            assert_eq!(reader.roster(&alice).await?.version.get(), 2);
            assert_eq!(reader.roster(&bob).await?.version.get(), 1);
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

pub(crate) fn denying_a_pending_request_clears_both_sides_without_changing_the_grantor_roster<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = key("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    let request = pending("alice@example.com", b"<presence type='subscribe'/>")?;
    block_on(async {
        write(&storage, async |tx| {
            tx.request_subscription(&alice, &bob_jid, &bob, request)
                .await
        })
        .await?;

        let cancellation = write(&storage, async |tx| {
            tx.cancel_subscription(&bob, &alice_jid, Some((&alice, &bob_jid)))
                .await
        })
        .await?;
        assert!(cancellation.route);
        assert!(!cancellation.send_unavailable);
        assert!(cancellation.grantor.is_none());
        let cleared = cancellation.subscriber.ok_or("missing roster change")?;
        assert_eq!(cleared.version.get(), 2);
        assert_eq!(cleared.value.subscription.state, SubscriptionState::None);
        assert!(!cleared.value.subscription.pending_out);
        let reader = storage.begin_read().await?;
        assert!(reader.pending_requests(&bob).await?.is_empty());
        assert_eq!(reader.roster(&bob).await?.version.get(), 0);
        drop(reader);

        let repeated = write(&storage, async |tx| {
            tx.cancel_subscription(&bob, &alice_jid, Some((&alice, &bob_jid)))
                .await
        })
        .await?;
        assert!(!repeated.route);
        assert_eq!(
            read(&storage, async |tx| tx.roster(&alice).await)
                .await?
                .version
                .get(),
            2
        );
        Ok(())
    })
}

pub(crate) fn revoking_a_mutual_subscription_keeps_the_reverse_grant<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = key("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    block_on(async {
        for (owner, contact) in [(&alice, &bob_jid), (&bob, &alice_jid)] {
            set_subscription(&storage, owner, contact, state(SubscriptionState::Both)).await?;
        }

        let cancellation = write(&storage, async |tx| {
            tx.cancel_subscription(&bob, &alice_jid, Some((&alice, &bob_jid)))
                .await
        })
        .await?;
        assert!(cancellation.route);
        assert!(cancellation.send_unavailable);
        assert_eq!(
            cancellation
                .grantor
                .ok_or("missing grantor change")?
                .value
                .subscription
                .state,
            SubscriptionState::To
        );
        assert_eq!(
            cancellation
                .subscriber
                .ok_or("missing subscriber change")?
                .value
                .subscription
                .state,
            SubscriptionState::From
        );
        let reader = storage.begin_read().await?;
        assert_eq!(reader.roster(&alice).await?.version.get(), 2);
        assert_eq!(reader.roster(&bob).await?.version.get(), 2);
        Ok(())
    })
}

pub(crate) fn denying_a_crossed_request_keeps_the_reverse_subscription<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = key("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    let request = pending("alice@example.com", b"<presence type='subscribe'/>")?;
    block_on(async {
        set_subscription(
            &storage,
            &alice,
            &bob_jid,
            RosterSubscription {
                state: SubscriptionState::From,
                pending_out: true,
                approved: false,
            },
        )
        .await?;
        set_subscription(&storage, &bob, &alice_jid, state(SubscriptionState::To)).await?;
        write(&storage, async |tx| {
            tx.put_pending_request(&bob, request).await
        })
        .await?;

        let cancellation = write(&storage, async |tx| {
            tx.cancel_subscription(&bob, &alice_jid, Some((&alice, &bob_jid)))
                .await
        })
        .await?;
        assert!(cancellation.route);
        assert!(!cancellation.send_unavailable);
        assert!(cancellation.grantor.is_none());
        assert_eq!(
            cancellation
                .subscriber
                .ok_or("missing sender change")?
                .value
                .subscription,
            state(SubscriptionState::From)
        );
        let reader = storage.begin_read().await?;
        assert!(reader.pending_requests(&bob).await?.is_empty());
        assert_eq!(reader.roster(&bob).await?.version.get(), 1);
        Ok(())
    })
}

pub(crate) fn clearing_preapproval_does_not_notify_the_contact<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = key("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    block_on(async {
        set_subscription(
            &storage,
            &bob,
            &alice_jid,
            RosterSubscription {
                approved: true,
                ..RosterSubscription::default()
            },
        )
        .await?;

        let cancellation = write(&storage, async |tx| {
            tx.cancel_subscription(&bob, &alice_jid, Some((&alice, &bob_jid)))
                .await
        })
        .await?;
        assert!(!cancellation.route);
        assert!(!cancellation.send_unavailable);
        assert!(cancellation.subscriber.is_none());
        assert!(
            !cancellation
                .grantor
                .ok_or("missing grantor change")?
                .value
                .subscription
                .approved
        );
        let reader = storage.begin_read().await?;
        assert_eq!(reader.roster(&bob).await?.version.get(), 2);
        assert_eq!(reader.roster(&alice).await?.version.get(), 0);
        Ok(())
    })
}

pub(crate) fn cancellation_clears_the_grantor_when_the_subscriber_is_missing<S: Storage>(
    storage: S,
) -> TestResult {
    let bob = key("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let request = pending("alice@example.com", b"<presence type='subscribe'/>")?;
    block_on(async {
        set_subscription(&storage, &bob, &alice_jid, state(SubscriptionState::From)).await?;
        write(&storage, async |tx| {
            tx.put_pending_request(&bob, request).await
        })
        .await?;

        let cancellation = write(&storage, async |tx| {
            tx.cancel_subscription(&bob, &alice_jid, None).await
        })
        .await?;
        assert!(!cancellation.route);
        assert!(!cancellation.send_unavailable);
        assert!(cancellation.subscriber.is_none());
        assert_eq!(
            cancellation
                .grantor
                .ok_or("missing grantor change")?
                .value
                .subscription
                .state,
            SubscriptionState::None
        );
        let reader = storage.begin_read().await?;
        assert!(reader.pending_requests(&bob).await?.is_empty());
        assert_eq!(reader.roster(&bob).await?.version.get(), 2);
        Ok(())
    })
}

pub(crate) fn self_subscription_cancellation_writes_one_final_roster_version<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let request = pending("alice@example.com", b"<presence type='subscribe'/>")?;
    block_on(async {
        set_subscription(&storage, &alice, &alice_jid, state(SubscriptionState::Both)).await?;
        write(&storage, async |tx| {
            tx.put_pending_request(&alice, request).await
        })
        .await?;

        let cancellation = write(&storage, async |tx| {
            tx.cancel_subscription(&alice, &alice_jid, Some((&alice, &alice_jid)))
                .await
        })
        .await?;
        assert!(cancellation.route);
        assert!(cancellation.send_unavailable);
        assert!(cancellation.subscriber.is_none());
        let mutation = cancellation.grantor.ok_or("missing roster change")?;
        assert_eq!(mutation.version.get(), 2);
        assert_eq!(mutation.value.subscription, RosterSubscription::default());
        let reader = storage.begin_read().await?;
        assert_eq!(reader.roster(&alice).await?.version.get(), 2);
        assert!(reader.pending_requests(&alice).await?.is_empty());
        Ok(())
    })
}

pub(crate) fn unsubscribe_keeps_the_reverse_grant_and_does_not_advance_versions_twice<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = key("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    block_on(async {
        for (owner, contact) in [(&alice, &bob_jid), (&bob, &alice_jid)] {
            set_subscription(
                &storage,
                owner,
                contact,
                RosterSubscription {
                    state: SubscriptionState::Both,
                    pending_out: false,
                    approved: true,
                },
            )
            .await?;
        }

        let withdrawal = write(&storage, async |tx| {
            tx.unsubscribe(&alice, &bob_jid, Some((&bob, &alice_jid)))
                .await
        })
        .await?;
        assert!(withdrawal.notify_contact);
        let subscriber = withdrawal.subscriber.ok_or("missing subscriber change")?;
        assert_eq!(subscriber.version.get(), 2);
        assert_eq!(subscriber.value.subscription.state, SubscriptionState::From);
        assert!(subscriber.value.subscription.approved);
        let contact = withdrawal.contact.ok_or("missing contact change")?;
        assert_eq!(contact.version.get(), 2);
        assert_eq!(contact.value.subscription.state, SubscriptionState::To);
        assert!(contact.value.subscription.approved);

        let repeated = write(&storage, async |tx| {
            tx.unsubscribe(&alice, &bob_jid, Some((&bob, &alice_jid)))
                .await
        })
        .await?;
        assert!(!repeated.notify_contact);
        assert!(repeated.subscriber.is_none());
        assert!(repeated.contact.is_none());
        let reader = storage.begin_read().await?;
        assert_eq!(reader.roster(&alice).await?.version.get(), 2);
        assert_eq!(reader.roster(&bob).await?.version.get(), 2);
        Ok(())
    })
}

pub(crate) fn unsubscribe_from_self_writes_one_roster_version<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    block_on(async {
        set_subscription(&storage, &alice, &alice_jid, state(SubscriptionState::Both)).await?;

        let withdrawal = write(&storage, async |tx| {
            tx.unsubscribe(&alice, &alice_jid, Some((&alice, &alice_jid)))
                .await
        })
        .await?;
        assert!(withdrawal.notify_contact);
        assert!(withdrawal.contact.is_none());
        let subscriber = withdrawal.subscriber.ok_or("missing roster change")?;
        assert_eq!(subscriber.version.get(), 2);
        assert_eq!(subscriber.value.subscription.state, SubscriptionState::None);
        assert_eq!(
            read(&storage, async |tx| tx.roster(&alice).await)
                .await?
                .version
                .get(),
            2
        );
        Ok(())
    })
}

pub(crate) fn unsubscribe_clears_a_stale_subscription_after_the_contact_is_deleted<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    block_on(async {
        set_subscription(&storage, &alice, &bob_jid, state(SubscriptionState::To)).await?;

        let withdrawal = write(&storage, async |tx| {
            tx.unsubscribe(&alice, &bob_jid, None).await
        })
        .await?;
        assert!(!withdrawal.notify_contact);
        assert!(withdrawal.contact.is_none());
        let subscriber = withdrawal.subscriber.ok_or("missing roster change")?;
        assert_eq!(subscriber.value.subscription.state, SubscriptionState::None);
        assert_eq!(
            read(&storage, async |tx| tx.roster(&alice).await)
                .await?
                .version
                .get(),
            2
        );
        Ok(())
    })
}

pub(crate) fn clear_roster_removes_one_owners_items_version_and_pending_requests<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let carol = key("carol@example.com")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        for owner in [&alice, &carol] {
            writer
                .upsert(owner, item("bob@example.com", None, &[])?)
                .await?;
            writer
                .put_pending_request(owner, pending("bob@example.com", b"<presence/>")?)
                .await?;
        }
        writer.commit().await?;

        write(&storage, async |tx| tx.clear_roster(&alice).await).await?;
        let reader = storage.begin_read().await?;
        let cleared = reader.roster(&alice).await?;
        assert_eq!(cleared.version.get(), 0);
        assert!(cleared.items.is_empty());
        assert!(reader.pending_requests(&alice).await?.is_empty());
        assert_eq!(reader.roster(&carol).await?.items.len(), 1);
        assert_eq!(reader.pending_requests(&carol).await?.len(), 1);
        Ok(())
    })
}

pub(crate) fn rosters_are_isolated_by_owner_and_sorted_by_contact<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let carol = key("carol@example.com")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        for contact in ["zara@example.com", "bob@example.com"] {
            writer.upsert(&alice, item(contact, None, &[])?).await?;
        }
        writer
            .upsert(&carol, item("dave@example.com", None, &[])?)
            .await?;
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        let snapshot = reader.roster(&alice).await?;
        assert_eq!(snapshot.version.get(), 2);
        assert_eq!(snapshot.items[0].jid.as_str(), "bob@example.com");
        assert_eq!(snapshot.items[1].jid.as_str(), "zara@example.com");
        assert_eq!(reader.roster(&carol).await?.items.len(), 1);
        Ok(())
    })
}

pub(crate) fn subscription_update_reads_and_changes_state_in_one_write<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        assert!(
            writer
                .update_subscription(&owner, &contact, |_| None)
                .await?
                .is_none()
        );
        assert!(writer.roster_item(&owner, &contact).await?.is_none());
        let first = writer
            .update_subscription(&owner, &contact, |current| {
                assert_eq!(current, RosterSubscription::default());
                Some(RosterSubscription {
                    state: SubscriptionState::To,
                    pending_out: true,
                    approved: false,
                })
            })
            .await?
            .ok_or("subscription was not changed")?;
        assert_eq!(first.version.get(), 1);
        writer.commit().await?;

        let second = write(&storage, async |tx| {
            tx.update_subscription(&owner, &contact, |mut current| {
                assert_eq!(current.state, SubscriptionState::To);
                current.pending_out = false;
                Some(current)
            })
            .await
        })
        .await?
        .ok_or("subscription was not changed")?;
        assert_eq!(second.version.get(), 2);
        assert_eq!(second.value.subscription.state, SubscriptionState::To);
        assert!(!second.value.subscription.pending_out);
        assert!(
            write(&storage, async |tx| {
                tx.update_subscription(&owner, &contact, |_| None).await
            })
            .await?
            .is_none()
        );
        assert_eq!(
            read(&storage, async |tx| tx.roster(&owner).await)
                .await?
                .version
                .get(),
            2
        );
        Ok(())
    })
}

pub(crate) fn item_removal_clears_the_contact_and_both_pending_requests<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = key("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    block_on(async {
        set_subscription(&storage, &alice, &bob_jid, state(SubscriptionState::Both)).await?;
        set_subscription(
            &storage,
            &bob,
            &alice_jid,
            RosterSubscription {
                state: SubscriptionState::Both,
                pending_out: false,
                approved: true,
            },
        )
        .await?;
        let mut writer = storage.begin_write().await?;
        writer
            .put_pending_request(
                &alice,
                pending("bob@example.com", b"<presence type='subscribe'/>")?,
            )
            .await?;
        writer
            .put_pending_request(
                &bob,
                pending("alice@example.com", b"<presence type='subscribe'/>")?,
            )
            .await?;
        writer.commit().await?;

        let removal = write(&storage, async |tx| {
            tx.remove_item(&alice, &bob_jid, Some((&bob, &alice_jid)))
                .await
        })
        .await?
        .ok_or("missing removal")?;
        assert_eq!(removal.version.get(), 2);
        assert_eq!(removal.subscription.state, SubscriptionState::Both);
        assert_eq!(
            removal.contact_before,
            Some(RosterSubscription {
                state: SubscriptionState::Both,
                pending_out: false,
                approved: true,
            })
        );
        assert!(removal.pending_request);
        let contact = removal.contact.ok_or("missing contact change")?;
        assert_eq!(contact.version.get(), 2);
        assert_eq!(
            contact.value.subscription,
            RosterSubscription {
                state: SubscriptionState::None,
                pending_out: false,
                approved: true,
            }
        );
        let reader = storage.begin_read().await?;
        assert!(reader.roster(&alice).await?.items.is_empty());
        assert!(reader.pending_requests(&alice).await?.is_empty());
        assert!(reader.pending_requests(&bob).await?.is_empty());
        assert_eq!(
            reader
                .roster_item(&bob, &alice_jid)
                .await?
                .ok_or("missing contact item")?
                .subscription
                .state,
            SubscriptionState::None
        );
        Ok(())
    })
}

pub(crate) fn item_removal_without_a_local_contact_changes_only_the_owner<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    block_on(async {
        set_subscription(
            &storage,
            &alice,
            &bob_jid,
            RosterSubscription {
                state: SubscriptionState::None,
                pending_out: true,
                approved: false,
            },
        )
        .await?;

        let removal = write(&storage, async |tx| {
            tx.remove_item(&alice, &bob_jid, None).await
        })
        .await?
        .ok_or("missing removal")?;
        assert_eq!(removal.version.get(), 2);
        assert!(removal.subscription.pending_out);
        assert!(removal.contact_before.is_none());
        assert!(!removal.pending_request);
        assert!(removal.contact.is_none());
        assert!(
            read(&storage, async |tx| tx.roster(&alice).await)
                .await?
                .items
                .is_empty()
        );
        Ok(())
    })
}

pub(crate) fn removing_a_missing_item_writes_nothing<S: Storage>(storage: S) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = key("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    block_on(async {
        assert!(
            write(&storage, async |tx| {
                tx.remove_item(&alice, &bob_jid, Some((&bob, &alice_jid)))
                    .await
            })
            .await?
            .is_none()
        );
        let reader = storage.begin_read().await?;
        assert_eq!(reader.roster(&alice).await?.version.get(), 0);
        assert_eq!(reader.roster(&bob).await?.version.get(), 0);
        Ok(())
    })
}
