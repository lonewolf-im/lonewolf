// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use futures_executor::block_on;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::{
    PendingSubscription, RosterError, RosterItem, RosterJid, RosterReads, RosterSubscription,
    RosterWrites, SubscriptionState,
};
use lonewolf_storage::{RedbWrite, Storage, WriteTransaction};

use super::{TestRoster, account, create_account, item, pending, roster as empty_roster, snapshot};
use crate::roster::state::{self, RequestOutcome};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn roster() -> (tempfile::TempDir, TestRoster) {
    let (directory, roster) = empty_roster();
    for jid in ["alice@example.com", "bob@example.com"] {
        create_account(&roster, &account(jid));
    }
    (directory, roster)
}

fn jid(input: &str) -> RosterJid {
    RosterJid::from(&account(input))
}

fn subscription(state: SubscriptionState) -> RosterSubscription {
    RosterSubscription {
        state,
        pending_out: false,
        approved: false,
    }
}

fn stanza(bytes: &[u8]) -> Box<[u8]> {
    Box::from(bytes)
}

fn request(sender: &str, stanza: &[u8]) -> PendingSubscription {
    PendingSubscription {
        sender: jid(sender),
        stanza: Box::from(stanza),
    }
}

fn write<T>(
    roster: &TestRoster,
    operation: impl AsyncFnOnce(&mut RedbWrite) -> Result<T, RosterError>,
) -> Result<T, RosterError> {
    block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        let value = operation(&mut transaction).await?;
        transaction.commit().await?;
        Ok(value)
    })
}

fn set_subscription(
    roster: &TestRoster,
    owner: &AccountKey,
    contact: &RosterJid,
    subscription: RosterSubscription,
) -> Result<(), RosterError> {
    let item = RosterItem {
        subscription,
        ..state::bare_item(contact.clone())
    };
    write(roster, async |tx| {
        tx.put_roster_item(owner, &item).await?;
        Ok(())
    })
}

fn put_pending(
    roster: &TestRoster,
    owner: &AccountKey,
    request: PendingSubscription,
) -> Result<(), RosterError> {
    write(roster, async |tx| {
        tx.put_pending_request(owner, request, std::num::NonZeroUsize::MAX)
            .await
    })
}

fn version(roster: &TestRoster, owner: &AccountKey) -> u64 {
    snapshot(roster, owner).version.get()
}

#[test]
fn subscription_update_creates_a_bare_item_when_absent() -> TestResult {
    let (_directory, roster) = roster();
    let owner = account("alice@example.com");
    let contact = jid("bob@example.com");
    let created = write(&roster, async |tx| {
        state::update_subscription(tx, &owner, &contact, |current| {
            assert_eq!(current, RosterSubscription::default());
            Some(subscription(SubscriptionState::From))
        })
        .await
    })?
    .ok_or("subscription was not changed")?;
    assert_eq!(created.version.get(), 1);
    assert_eq!(
        created.value,
        RosterItem {
            subscription: subscription(SubscriptionState::From),
            ..state::bare_item(contact.clone())
        }
    );
    assert_eq!(item(&roster, &owner, &contact), Some(created.value));
    Ok(())
}

#[test]
fn existing_subscription_update_leaves_an_absent_item_absent() -> TestResult {
    let (_directory, roster) = roster();
    let owner = account("alice@example.com");
    let contact = jid("bob@example.com");
    let skipped = write(&roster, async |tx| {
        state::update_existing_subscription(tx, &owner, &contact, |_| {
            Some(subscription(SubscriptionState::From))
        })
        .await
    })?;
    assert!(skipped.is_none());
    assert!(item(&roster, &owner, &contact).is_none());
    assert_eq!(version(&roster, &owner), 0);
    Ok(())
}

#[test]
fn subscription_update_preserves_editable_fields() -> TestResult {
    let (_directory, roster) = roster();
    let owner = account("alice@example.com");
    let contact = jid("bob@example.com");
    let named = RosterItem {
        name: Some(Box::from("Bob")),
        groups: vec![Box::from("Friends")],
        ..state::bare_item(contact.clone())
    };
    write(&roster, async |tx| {
        tx.put_roster_item(&owner, &named).await?;
        Ok(())
    })?;
    let changed = RosterSubscription {
        state: SubscriptionState::Both,
        pending_out: true,
        approved: true,
    };
    let updated = write(&roster, async |tx| {
        state::update_subscription(tx, &owner, &contact, |_| Some(changed)).await
    })?
    .ok_or("subscription was not changed")?;
    assert_eq!(updated.version.get(), 2);
    assert_eq!(
        updated.value,
        RosterItem {
            subscription: changed,
            ..named
        }
    );
    assert_eq!(item(&roster, &owner, &contact), Some(updated.value));
    Ok(())
}

#[test]
fn subscription_update_reads_and_changes_state_in_one_write() -> TestResult {
    let (_directory, roster) = roster();
    let owner = account("alice@example.com");
    let contact = jid("bob@example.com");
    let first = write(&roster, async |tx| {
        assert!(
            state::update_subscription(tx, &owner, &contact, |_| None)
                .await?
                .is_none()
        );
        assert!(tx.roster_item(&owner, &contact).await?.is_none());
        state::update_subscription(tx, &owner, &contact, |current| {
            assert_eq!(current, RosterSubscription::default());
            Some(RosterSubscription {
                state: SubscriptionState::To,
                pending_out: true,
                approved: false,
            })
        })
        .await
    })?
    .ok_or("subscription was not changed")?;
    assert_eq!(first.version.get(), 1);

    let second = write(&roster, async |tx| {
        state::update_subscription(tx, &owner, &contact, |mut current| {
            assert_eq!(current.state, SubscriptionState::To);
            current.pending_out = false;
            Some(current)
        })
        .await
    })?
    .ok_or("subscription was not changed")?;
    assert_eq!(second.version.get(), 2);
    assert_eq!(second.value.subscription.state, SubscriptionState::To);
    assert!(!second.value.subscription.pending_out);
    assert!(
        write(&roster, async |tx| {
            state::update_subscription(tx, &owner, &contact, |_| None).await
        })?
        .is_none()
    );
    assert_eq!(version(&roster, &owner), 2);
    Ok(())
}

#[test]
fn resolving_without_a_pending_request_writes_nothing() -> TestResult {
    let (_directory, roster) = roster();
    let owner = account("alice@example.com");
    let sender = jid("bob@example.com");
    let resolution = write(&roster, async |tx| {
        state::resolve_pending(tx, &owner, &sender, |mut current| {
            current.state = SubscriptionState::From;
            Some(current)
        })
        .await
    })?;
    assert!(resolution.is_none());
    assert!(item(&roster, &owner, &sender).is_none());
    assert_eq!(version(&roster, &owner), 0);
    Ok(())
}

#[test]
fn resolving_a_pending_request_removes_it_and_applies_the_transition() -> TestResult {
    let (_directory, roster) = roster();
    let owner = account("alice@example.com");
    let sender = jid("bob@example.com");
    put_pending(
        &roster,
        &owner,
        request("bob@example.com", b"<presence type='subscribe'/>"),
    )?;
    let resolved = write(&roster, async |tx| {
        state::resolve_pending(tx, &owner, &sender, |mut current| {
            current.state = SubscriptionState::From;
            Some(current)
        })
        .await
    })?
    .ok_or("missing pending request")?;
    assert_eq!(resolved.version.get(), 1);
    assert_eq!(resolved.value.subscription.state, SubscriptionState::From);
    assert!(pending(&roster, &owner).is_empty());
    assert_eq!(item(&roster, &owner, &sender), Some(resolved.value));

    put_pending(
        &roster,
        &owner,
        request("bob@example.com", b"<presence type='subscribe'/>"),
    )?;
    let denied = write(&roster, async |tx| {
        state::resolve_pending(tx, &owner, &sender, |_| None).await
    })?;
    assert!(denied.is_none());
    assert!(pending(&roster, &owner).is_empty());
    assert_eq!(version(&roster, &owner), 1);
    Ok(())
}

#[test]
fn subscription_request_updates_the_sender_and_recipient_in_one_transaction() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    let alice_jid = RosterJid::from(&alice);
    let bob_jid = RosterJid::from(&bob);
    let outcome = write(&roster, async |tx| {
        state::request_subscription(
            tx,
            &alice,
            RosterJid::from(&alice),
            &bob,
            &bob_jid,
            stanza(b"<presence id='first'/>"),
            std::num::NonZeroUsize::MAX,
        )
        .await
    })?;
    let RequestOutcome::Pending { push: Some(push) } = outcome else {
        return Err("subscription was not changed".into());
    };
    assert_eq!(push.version.get(), 1);
    assert!(push.value.subscription.pending_out);
    assert_eq!(item(&roster, &alice, &bob_jid), Some(push.value));
    let requests = pending(&roster, &bob);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].sender, alice_jid);
    assert_eq!(requests[0].stanza.as_ref(), b"<presence id='first'/>");

    let repeated = write(&roster, async |tx| {
        state::request_subscription(
            tx,
            &alice,
            RosterJid::from(&alice),
            &bob,
            &bob_jid,
            stanza(b"<presence id='last'/>"),
            std::num::NonZeroUsize::MAX,
        )
        .await
    })?;
    assert!(matches!(repeated, RequestOutcome::Pending { push: None }));
    assert_eq!(version(&roster, &alice), 1);
    assert_eq!(
        pending(&roster, &bob)[0].stanza.as_ref(),
        b"<presence id='last'/>"
    );
    Ok(())
}

#[test]
fn established_subscription_requests_are_automatically_approved_without_changes() -> TestResult {
    let (_directory, roster) = roster();
    for (index, (subscriber_state, recipient_state)) in [
        (SubscriptionState::To, SubscriptionState::From),
        (SubscriptionState::Both, SubscriptionState::Both),
    ]
    .into_iter()
    .enumerate()
    {
        let alice = account(&format!("alice{index}@example.com"));
        let bob = account(&format!("bob{index}@example.com"));
        create_account(&roster, &alice);
        create_account(&roster, &bob);
        let alice_jid = RosterJid::from(&alice);
        let bob_jid = RosterJid::from(&bob);
        set_subscription(&roster, &alice, &bob_jid, subscription(subscriber_state))?;
        set_subscription(&roster, &bob, &alice_jid, subscription(recipient_state))?;

        let outcome = write(&roster, async |tx| {
            state::request_subscription(
                tx,
                &alice,
                RosterJid::from(&alice),
                &bob,
                &bob_jid,
                stanza(b"<presence id='repeat'/>"),
                std::num::NonZeroUsize::MAX,
            )
            .await
        })?;
        assert!(matches!(
            outcome,
            RequestOutcome::AutoApproved { approved: None }
        ));
        assert!(pending(&roster, &bob).is_empty());
        let alice_roster = snapshot(&roster, &alice);
        assert_eq!(alice_roster.version.get(), 1);
        assert_eq!(alice_roster.items[0].subscription.state, subscriber_state);
        assert!(!alice_roster.items[0].subscription.pending_out);
        assert_eq!(version(&roster, &bob), 1);
    }
    Ok(())
}

#[test]
fn automatic_approval_resolves_an_outstanding_request() -> TestResult {
    let (_directory, roster) = roster();
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
        let alice = account(&format!("alice{index}@example.com"));
        let bob = account(&format!("bob{index}@example.com"));
        create_account(&roster, &alice);
        create_account(&roster, &bob);
        let alice_jid = RosterJid::from(&alice);
        let bob_jid = RosterJid::from(&bob);
        set_subscription(
            &roster,
            &alice,
            &bob_jid,
            RosterSubscription {
                state: subscriber_state,
                pending_out: true,
                approved: false,
            },
        )?;
        set_subscription(&roster, &bob, &alice_jid, subscription(recipient_state))?;

        let outcome = write(&roster, async |tx| {
            state::request_subscription(
                tx,
                &alice,
                RosterJid::from(&alice),
                &bob,
                &bob_jid,
                stanza(b"<presence id='repeat'/>"),
                std::num::NonZeroUsize::MAX,
            )
            .await
        })?;
        let RequestOutcome::AutoApproved {
            approved: Some(approved),
        } = outcome
        else {
            return Err("outstanding request was not approved".into());
        };
        assert_eq!(approved.version.get(), 2);
        assert_eq!(approved.value.subscription.state, approved_state);
        assert!(!approved.value.subscription.pending_out);
        assert!(pending(&roster, &bob).is_empty());
        assert_eq!(version(&roster, &alice), 2);
        assert_eq!(version(&roster, &bob), 1);
    }
    Ok(())
}

#[test]
fn denying_a_pending_request_clears_both_sides_without_changing_the_grantor_roster() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    let alice_jid = RosterJid::from(&alice);
    let bob_jid = RosterJid::from(&bob);
    write(&roster, async |tx| {
        state::request_subscription(
            tx,
            &alice,
            RosterJid::from(&alice),
            &bob,
            &bob_jid,
            stanza(b"<presence type='subscribe'/>"),
            std::num::NonZeroUsize::MAX,
        )
        .await
    })?;

    let cancellation = write(&roster, async |tx| {
        state::cancel_subscription(tx, &bob, &alice_jid, Some((&alice, &bob_jid))).await
    })?;
    assert!(cancellation.route);
    assert!(!cancellation.send_unavailable);
    assert!(cancellation.grantor.is_none());
    let cleared = cancellation.subscriber.ok_or("missing roster change")?;
    assert_eq!(cleared.version.get(), 2);
    assert_eq!(cleared.value.subscription.state, SubscriptionState::None);
    assert!(!cleared.value.subscription.pending_out);
    assert!(pending(&roster, &bob).is_empty());
    assert_eq!(version(&roster, &bob), 0);

    let repeated = write(&roster, async |tx| {
        state::cancel_subscription(tx, &bob, &alice_jid, Some((&alice, &bob_jid))).await
    })?;
    assert!(!repeated.route);
    assert_eq!(version(&roster, &alice), 2);
    Ok(())
}

#[test]
fn revoking_a_mutual_subscription_keeps_the_reverse_grant() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    let alice_jid = RosterJid::from(&alice);
    let bob_jid = RosterJid::from(&bob);
    for (owner, contact) in [(&alice, &bob_jid), (&bob, &alice_jid)] {
        set_subscription(
            &roster,
            owner,
            contact,
            subscription(SubscriptionState::Both),
        )?;
    }

    let cancellation = write(&roster, async |tx| {
        state::cancel_subscription(tx, &bob, &alice_jid, Some((&alice, &bob_jid))).await
    })?;
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
    assert_eq!(version(&roster, &alice), 2);
    assert_eq!(version(&roster, &bob), 2);
    Ok(())
}

#[test]
fn denying_a_crossed_request_keeps_the_reverse_subscription() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    let alice_jid = RosterJid::from(&alice);
    let bob_jid = RosterJid::from(&bob);
    set_subscription(
        &roster,
        &alice,
        &bob_jid,
        RosterSubscription {
            state: SubscriptionState::From,
            pending_out: true,
            approved: false,
        },
    )?;
    set_subscription(
        &roster,
        &bob,
        &alice_jid,
        subscription(SubscriptionState::To),
    )?;
    put_pending(
        &roster,
        &bob,
        request("alice@example.com", b"<presence type='subscribe'/>"),
    )?;

    let cancellation = write(&roster, async |tx| {
        state::cancel_subscription(tx, &bob, &alice_jid, Some((&alice, &bob_jid))).await
    })?;
    assert!(cancellation.route);
    assert!(!cancellation.send_unavailable);
    assert!(cancellation.grantor.is_none());
    assert_eq!(
        cancellation
            .subscriber
            .ok_or("missing sender change")?
            .value
            .subscription,
        subscription(SubscriptionState::From)
    );
    assert!(pending(&roster, &bob).is_empty());
    assert_eq!(version(&roster, &bob), 1);
    Ok(())
}

#[test]
fn clearing_preapproval_does_not_notify_the_contact() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    let alice_jid = RosterJid::from(&alice);
    let bob_jid = RosterJid::from(&bob);
    set_subscription(
        &roster,
        &bob,
        &alice_jid,
        RosterSubscription {
            approved: true,
            ..RosterSubscription::default()
        },
    )?;

    let cancellation = write(&roster, async |tx| {
        state::cancel_subscription(tx, &bob, &alice_jid, Some((&alice, &bob_jid))).await
    })?;
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
    assert_eq!(version(&roster, &bob), 2);
    assert_eq!(version(&roster, &alice), 0);
    Ok(())
}

#[test]
fn cancellation_clears_the_grantor_when_the_subscriber_is_missing() -> TestResult {
    let (_directory, roster) = roster();
    let bob = account("bob@example.com");
    let alice_jid = jid("alice@example.com");
    set_subscription(
        &roster,
        &bob,
        &alice_jid,
        subscription(SubscriptionState::From),
    )?;
    put_pending(
        &roster,
        &bob,
        request("alice@example.com", b"<presence type='subscribe'/>"),
    )?;

    let cancellation = write(&roster, async |tx| {
        state::cancel_subscription(tx, &bob, &alice_jid, None).await
    })?;
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
    assert!(pending(&roster, &bob).is_empty());
    assert_eq!(version(&roster, &bob), 2);
    Ok(())
}

#[test]
fn self_subscription_cancellation_writes_one_final_roster_version() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let alice_jid = RosterJid::from(&alice);
    set_subscription(
        &roster,
        &alice,
        &alice_jid,
        subscription(SubscriptionState::Both),
    )?;
    put_pending(
        &roster,
        &alice,
        request("alice@example.com", b"<presence type='subscribe'/>"),
    )?;

    let cancellation = write(&roster, async |tx| {
        state::cancel_subscription(tx, &alice, &alice_jid, Some((&alice, &alice_jid))).await
    })?;
    assert!(cancellation.route);
    assert!(cancellation.send_unavailable);
    assert!(cancellation.subscriber.is_none());
    let grantor = cancellation.grantor.ok_or("missing roster change")?;
    assert_eq!(grantor.version.get(), 2);
    assert_eq!(grantor.value.subscription, RosterSubscription::default());
    assert_eq!(version(&roster, &alice), 2);
    assert!(pending(&roster, &alice).is_empty());
    Ok(())
}

#[test]
fn unsubscribe_keeps_the_reverse_grant_and_does_not_advance_versions_twice() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    let alice_jid = RosterJid::from(&alice);
    let bob_jid = RosterJid::from(&bob);
    for (owner, contact) in [(&alice, &bob_jid), (&bob, &alice_jid)] {
        set_subscription(
            &roster,
            owner,
            contact,
            RosterSubscription {
                state: SubscriptionState::Both,
                pending_out: false,
                approved: true,
            },
        )?;
    }

    let withdrawal = write(&roster, async |tx| {
        state::unsubscribe(tx, &alice, &bob_jid, Some((&bob, &alice_jid))).await
    })?;
    assert!(withdrawal.notify_contact);
    let subscriber = withdrawal.subscriber.ok_or("missing subscriber change")?;
    assert_eq!(subscriber.version.get(), 2);
    assert_eq!(subscriber.value.subscription.state, SubscriptionState::From);
    assert!(subscriber.value.subscription.approved);
    let contact = withdrawal.contact.ok_or("missing contact change")?;
    assert_eq!(contact.version.get(), 2);
    assert_eq!(contact.value.subscription.state, SubscriptionState::To);
    assert!(contact.value.subscription.approved);

    let repeated = write(&roster, async |tx| {
        state::unsubscribe(tx, &alice, &bob_jid, Some((&bob, &alice_jid))).await
    })?;
    assert!(!repeated.notify_contact);
    assert!(repeated.subscriber.is_none());
    assert!(repeated.contact.is_none());
    assert_eq!(version(&roster, &alice), 2);
    assert_eq!(version(&roster, &bob), 2);
    Ok(())
}

#[test]
fn unsubscribe_from_self_writes_one_roster_version() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let alice_jid = RosterJid::from(&alice);
    set_subscription(
        &roster,
        &alice,
        &alice_jid,
        subscription(SubscriptionState::Both),
    )?;

    let withdrawal = write(&roster, async |tx| {
        state::unsubscribe(tx, &alice, &alice_jid, Some((&alice, &alice_jid))).await
    })?;
    assert!(withdrawal.notify_contact);
    assert!(withdrawal.contact.is_none());
    let subscriber = withdrawal.subscriber.ok_or("missing roster change")?;
    assert_eq!(subscriber.version.get(), 2);
    assert_eq!(subscriber.value.subscription.state, SubscriptionState::None);
    assert_eq!(version(&roster, &alice), 2);
    Ok(())
}

#[test]
fn unsubscribe_clears_a_stale_subscription_after_the_contact_is_deleted() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let bob_jid = jid("bob@example.com");
    set_subscription(
        &roster,
        &alice,
        &bob_jid,
        subscription(SubscriptionState::To),
    )?;

    let withdrawal = write(&roster, async |tx| {
        state::unsubscribe(tx, &alice, &bob_jid, None).await
    })?;
    assert!(!withdrawal.notify_contact);
    assert!(withdrawal.contact.is_none());
    let subscriber = withdrawal.subscriber.ok_or("missing roster change")?;
    assert_eq!(subscriber.value.subscription.state, SubscriptionState::None);
    assert_eq!(version(&roster, &alice), 2);
    Ok(())
}

#[test]
fn item_removal_clears_the_contact_and_both_pending_requests() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    let alice_jid = RosterJid::from(&alice);
    let bob_jid = RosterJid::from(&bob);
    let preapproved = RosterSubscription {
        state: SubscriptionState::Both,
        pending_out: false,
        approved: true,
    };
    set_subscription(
        &roster,
        &alice,
        &bob_jid,
        subscription(SubscriptionState::Both),
    )?;
    set_subscription(&roster, &bob, &alice_jid, preapproved)?;
    put_pending(
        &roster,
        &alice,
        request("bob@example.com", b"<presence type='subscribe'/>"),
    )?;
    put_pending(
        &roster,
        &bob,
        request("alice@example.com", b"<presence type='subscribe'/>"),
    )?;

    let removal = write(&roster, async |tx| {
        state::remove_item(tx, &alice, &alice_jid, &bob_jid, Some(&bob)).await
    })?
    .ok_or("missing removal")?;
    assert_eq!(removal.version.get(), 2);
    assert_eq!(removal.subscription.state, SubscriptionState::Both);
    assert_eq!(removal.contact_before, Some(preapproved));
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
    assert!(snapshot(&roster, &alice).items.is_empty());
    assert!(pending(&roster, &alice).is_empty());
    assert!(pending(&roster, &bob).is_empty());
    assert_eq!(
        item(&roster, &bob, &alice_jid)
            .ok_or("missing contact item")?
            .subscription
            .state,
        SubscriptionState::None
    );
    Ok(())
}

#[test]
fn item_removal_without_a_local_contact_changes_only_the_owner() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let alice_jid = RosterJid::from(&alice);
    let bob_jid = jid("bob@example.com");
    set_subscription(
        &roster,
        &alice,
        &bob_jid,
        RosterSubscription {
            state: SubscriptionState::None,
            pending_out: true,
            approved: false,
        },
    )?;

    let removal = write(&roster, async |tx| {
        state::remove_item(tx, &alice, &alice_jid, &bob_jid, None).await
    })?
    .ok_or("missing removal")?;
    assert_eq!(removal.version.get(), 2);
    assert!(removal.subscription.pending_out);
    assert!(removal.contact_before.is_none());
    assert!(!removal.pending_request);
    assert!(removal.contact.is_none());
    assert!(snapshot(&roster, &alice).items.is_empty());
    Ok(())
}

#[test]
fn removing_a_missing_item_writes_nothing() -> TestResult {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    let alice_jid = RosterJid::from(&alice);
    let bob_jid = RosterJid::from(&bob);
    assert!(
        write(&roster, async |tx| {
            state::remove_item(tx, &alice, &alice_jid, &bob_jid, Some(&bob)).await
        })?
        .is_none()
    );
    assert_eq!(version(&roster, &alice), 0);
    assert_eq!(version(&roster, &bob), 0);
    Ok(())
}

#[test]
fn pre_approval_is_noted_only_for_a_contact_the_owner_does_not_grant() {
    let pre_approved =
        |state| state::pre_approve(subscription(state)).map(|subscription| subscription.approved);
    assert_eq!(pre_approved(SubscriptionState::None), Some(true));
    assert_eq!(pre_approved(SubscriptionState::To), Some(true));
    assert_eq!(pre_approved(SubscriptionState::From), None);
    assert_eq!(pre_approved(SubscriptionState::Both), None);
    let noted = RosterSubscription {
        approved: true,
        ..subscription(SubscriptionState::None)
    };
    assert_eq!(state::pre_approve(noted), None);
}

#[test]
fn a_pre_approved_request_grants_the_requester_and_consumes_the_pre_approval() -> TestResult {
    let (_directory, roster) = roster();
    for (index, (grantor_before, grantor_after)) in [
        (SubscriptionState::None, SubscriptionState::From),
        (SubscriptionState::To, SubscriptionState::Both),
    ]
    .into_iter()
    .enumerate()
    {
        let alice = account(&format!("alice{index}@example.com"));
        let bob = account(&format!("bob{index}@example.com"));
        create_account(&roster, &alice);
        create_account(&roster, &bob);
        let alice_jid = RosterJid::from(&alice);
        let bob_jid = RosterJid::from(&bob);
        let pre_approval = RosterSubscription {
            approved: true,
            ..subscription(grantor_before)
        };
        set_subscription(&roster, &bob, &alice_jid, pre_approval)?;

        let outcome = write(&roster, async |tx| {
            state::request_subscription(
                tx,
                &alice,
                alice_jid.clone(),
                &bob,
                &bob_jid,
                stanza(b"<presence id='request'/>"),
                std::num::NonZeroUsize::MAX,
            )
            .await
        })?;
        let RequestOutcome::PreApproved {
            grantor: Some(grantor),
            requester: Some(requester),
        } = outcome
        else {
            return Err("request was not answered from the pre-approval".into());
        };
        assert_eq!(grantor.value.subscription, subscription(grantor_after));
        assert_eq!(
            requester.value.subscription,
            subscription(SubscriptionState::To)
        );
        assert!(pending(&roster, &bob).is_empty());
        assert_eq!(
            snapshot(&roster, &bob).items[0].subscription,
            subscription(grantor_after)
        );
    }
    Ok(())
}

#[test]
fn pending_overflow_preserves_both_rosters_and_reverse_requests() -> TestResult {
    for existing_item in [false, true] {
        let (_directory, roster) = roster();
        let alice = account("alice@example.com");
        let bob = account("bob@example.com");
        let bob_jid = RosterJid::from(&bob);
        if existing_item {
            write(&roster, async |tx| {
                tx.put_roster_item(
                    &alice,
                    &RosterItem {
                        name: Some("Bob".into()),
                        groups: vec!["Friends".into()],
                        ..state::bare_item(bob_jid.clone())
                    },
                )
                .await
            })?;
        }
        put_pending(&roster, &bob, request("carol@example.com", b"full"))?;
        put_pending(&roster, &alice, request("bob@example.com", b"reverse"))?;
        let alice_before = snapshot(&roster, &alice);
        let bob_before = snapshot(&roster, &bob);
        block_on(async {
            let mut tx = roster.storage.begin_write().await?;
            assert!(matches!(
                state::request_subscription(
                    &mut tx,
                    &alice,
                    RosterJid::from(&alice),
                    &bob,
                    &bob_jid,
                    stanza(b"rejected"),
                    std::num::NonZeroUsize::MIN
                )
                .await,
                Err(RosterError::PendingLimitExceeded)
            ));
            tx.commit().await?;
            TestResult::Ok(())
        })?;
        assert_eq!(snapshot(&roster, &alice), alice_before);
        assert_eq!(snapshot(&roster, &bob), bob_before);
        assert_eq!(
            pending(&roster, &bob),
            [request("carol@example.com", b"full")]
        );
        assert_eq!(
            pending(&roster, &alice),
            [request("bob@example.com", b"reverse")]
        );
    }
    Ok(())
}

#[test]
fn granted_and_preapproved_requests_bypass_a_full_pending_queue() -> TestResult {
    for preapproved in [false, true] {
        let (_directory, roster) = roster();
        let alice = account("alice@example.com");
        let bob = account("bob@example.com");
        let alice_jid = RosterJid::from(&alice);
        let bob_jid = RosterJid::from(&bob);
        put_pending(&roster, &bob, request("carol@example.com", b"full"))?;
        set_subscription(
            &roster,
            &bob,
            &alice_jid,
            RosterSubscription {
                state: if preapproved {
                    SubscriptionState::None
                } else {
                    SubscriptionState::From
                },
                approved: preapproved,
                pending_out: false,
            },
        )?;
        set_subscription(
            &roster,
            &alice,
            &bob_jid,
            RosterSubscription {
                pending_out: true,
                ..RosterSubscription::default()
            },
        )?;
        let outcome = write(&roster, async |tx| {
            state::request_subscription(
                tx,
                &alice,
                alice_jid,
                &bob,
                &bob_jid,
                stanza(b"approved"),
                std::num::NonZeroUsize::MIN,
            )
            .await
        })?;
        assert!(if preapproved {
            matches!(outcome, RequestOutcome::PreApproved { .. })
        } else {
            matches!(outcome, RequestOutcome::AutoApproved { approved: Some(_) })
        });
        assert_eq!(
            pending(&roster, &bob),
            [request("carol@example.com", b"full")]
        );
        let granted = item(&roster, &alice, &bob_jid).ok_or("missing grant")?;
        assert_eq!(granted.subscription.state, SubscriptionState::To);
        assert!(!granted.subscription.pending_out);
    }
    Ok(())
}
