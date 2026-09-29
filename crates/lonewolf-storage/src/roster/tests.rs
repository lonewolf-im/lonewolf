// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use futures_executor::block_on;
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;
use redb::Database;
use redb::backends::InMemoryBackend;

use super::redb::RedbRosterRepository;
use super::{
    PendingSubscription, RosterItemUpdate, RosterJid, RosterRepository, RosterSubscription,
    RosterVersion, SubscriptionRequestOutcome, SubscriptionState,
};
use crate::RedbDatabase;
use crate::account::AccountKey;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn owner(input: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(input, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

fn jid(input: &str) -> TestResult<RosterJid> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(input, &mut arena)?;
    Ok(RosterJid::from(jid.resolve(&arena)?))
}

fn repository() -> TestResult<RedbRosterRepository> {
    let database = Database::builder()
        .set_cache_size(1024 * 1024)
        .create_with_backend(InMemoryBackend::new())?;
    Ok(RedbRosterRepository::from_database(RedbDatabase::new(
        database,
    ))?)
}

#[test]
fn new_roster_is_empty_at_version_zero() -> TestResult {
    let snapshot = block_on(repository()?.snapshot(&owner("alice@example.com")?))?;
    assert_eq!(snapshot.version, RosterVersion::default());
    assert!(snapshot.items.is_empty());
    Ok(())
}

#[test]
fn upsert_stores_editable_fields_and_advances_version() -> TestResult {
    let repository = repository()?;
    let owner = owner("alice@example.com")?;
    let contact = jid("BOB@EXAMPLE.COM")?;
    let mutation = block_on(repository.upsert(
        &owner,
        RosterItemUpdate {
            jid: contact.clone(),
            name: Some("Bob".into()),
            groups: vec!["Friends".into(), "Work".into()],
        },
    ))?;

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
    assert_eq!(
        block_on(repository.get(&owner, &contact))?,
        Some(mutation.value)
    );
    let snapshot = block_on(repository.snapshot(&owner))?;
    assert_eq!(snapshot.version.get(), 1);
    assert_eq!(snapshot.items.len(), 1);
    Ok(())
}

#[test]
fn editable_and_subscription_updates_preserve_each_other() -> TestResult {
    let repository = repository()?;
    let owner = owner("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    block_on(repository.upsert(
        &owner,
        RosterItemUpdate {
            jid: contact.clone(),
            name: Some("Bob".into()),
            groups: vec!["Friends".into()],
        },
    ))?;
    let subscription = RosterSubscription {
        state: SubscriptionState::Both,
        pending_out: true,
        approved: true,
    };
    let changed =
        block_on(repository.update_subscription(&owner, &contact, move |_| Some(subscription)))?
            .ok_or("subscription was not changed")?;
    assert_eq!(changed.version.get(), 2);
    assert_eq!(changed.value.name.as_deref(), Some("Bob"));
    assert_eq!(changed.value.subscription, subscription);

    let changed = block_on(repository.upsert(
        &owner,
        RosterItemUpdate {
            jid: contact.clone(),
            name: Some("Robert".into()),
            groups: vec!["Work".into()],
        },
    ))?;
    assert_eq!(changed.version.get(), 3);
    assert_eq!(changed.value.subscription, subscription);
    Ok(())
}

#[test]
fn remove_returns_the_old_item_and_only_advances_an_existing_roster() -> TestResult {
    let repository = repository()?;
    let owner = owner("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    block_on(repository.upsert(
        &owner,
        RosterItemUpdate {
            jid: contact.clone(),
            name: Some("Bob".into()),
            groups: Vec::new(),
        },
    ))?;

    let removed = block_on(repository.remove(&owner, &contact))?.ok_or("missing removal")?;
    assert_eq!(removed.version.get(), 2);
    assert_eq!(removed.value.name.as_deref(), Some("Bob"));
    assert!(block_on(repository.get(&owner, &contact))?.is_none());
    assert!(block_on(repository.remove(&owner, &contact))?.is_none());
    assert_eq!(block_on(repository.snapshot(&owner))?.version.get(), 2);
    Ok(())
}

#[test]
fn pending_subscription_is_deduplicated_by_sender_and_can_be_removed() -> TestResult {
    let repository = repository()?;
    let owner = owner("alice@example.com")?;
    let sender = jid("bob@example.com")?;
    for stanza in [
        b"<presence id='first'/>".as_slice(),
        b"<presence id='last'/>".as_slice(),
    ] {
        block_on(repository.put_pending(
            &owner,
            PendingSubscription {
                sender: sender.clone(),
                stanza: stanza.into(),
            },
        ))?;
    }

    let pending = block_on(repository.pending(&owner))?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].sender, sender);
    assert_eq!(pending[0].stanza.as_ref(), b"<presence id='last'/>");
    assert!(block_on(repository.remove_pending(&owner, &sender))?);
    assert!(!block_on(repository.remove_pending(&owner, &sender))?);
    assert!(block_on(repository.pending(&owner))?.is_empty());
    Ok(())
}

#[test]
fn subscription_request_updates_the_sender_and_recipient_in_one_write() -> TestResult {
    let repository = repository()?;
    let alice = owner("alice@example.com")?;
    let bob = owner("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;

    let outcome = block_on(repository.request_subscription(
        &alice,
        &bob_jid,
        &bob,
        PendingSubscription {
            sender: alice_jid.clone(),
            stanza: b"<presence id='first'/>".as_slice().into(),
        },
    ))?;
    let SubscriptionRequestOutcome::Pending {
        mutation: Some(mutation),
    } = outcome
    else {
        return Err("subscription was not changed".into());
    };

    assert_eq!(mutation.version.get(), 1);
    assert!(mutation.value.subscription.pending_out);
    assert_eq!(
        block_on(repository.get(&alice, &bob_jid))?,
        Some(mutation.value)
    );
    let pending = block_on(repository.pending(&bob))?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].sender, alice_jid);
    assert_eq!(pending[0].stanza.as_ref(), b"<presence id='first'/>");

    let repeated = block_on(repository.request_subscription(
        &alice,
        &bob_jid,
        &bob,
        PendingSubscription {
            sender: alice_jid,
            stanza: b"<presence id='last'/>".as_slice().into(),
        },
    ))?;
    assert_eq!(
        repeated,
        SubscriptionRequestOutcome::Pending { mutation: None }
    );
    assert_eq!(block_on(repository.snapshot(&alice))?.version.get(), 1);
    assert_eq!(
        block_on(repository.pending(&bob))?[0].stanza.as_ref(),
        b"<presence id='last'/>"
    );
    Ok(())
}

#[test]
fn established_subscription_requests_are_automatically_approved_without_changes() -> TestResult {
    for (subscriber_state, recipient_state) in [
        (SubscriptionState::To, SubscriptionState::From),
        (SubscriptionState::Both, SubscriptionState::Both),
    ] {
        let repository = repository()?;
        let alice = owner("alice@example.com")?;
        let bob = owner("bob@example.com")?;
        let alice_jid = jid("alice@example.com")?;
        let bob_jid = jid("bob@example.com")?;
        block_on(
            repository.update_subscription(&alice, &bob_jid, move |mut current| {
                current.state = subscriber_state;
                Some(current)
            }),
        )?;
        block_on(
            repository.update_subscription(&bob, &alice_jid, move |mut current| {
                current.state = recipient_state;
                Some(current)
            }),
        )?;

        let outcome = block_on(repository.request_subscription(
            &alice,
            &bob_jid,
            &bob,
            PendingSubscription {
                sender: alice_jid.clone(),
                stanza: b"<presence id='repeat'/>".as_slice().into(),
            },
        ))?;

        assert_eq!(
            outcome,
            SubscriptionRequestOutcome::AutoApprove { mutation: None }
        );
        assert!(block_on(repository.pending(&bob))?.is_empty());
        let alice_roster = block_on(repository.snapshot(&alice))?;
        assert_eq!(alice_roster.version.get(), 1);
        assert_eq!(alice_roster.items[0].subscription.state, subscriber_state);
        assert!(!alice_roster.items[0].subscription.pending_out);
        assert_eq!(block_on(repository.snapshot(&bob))?.version.get(), 1);
    }
    Ok(())
}

#[test]
fn automatic_approval_resolves_an_outstanding_request_in_one_write() -> TestResult {
    for (subscriber_state, recipient_state, approved_state) in [
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
    ] {
        let repository = repository()?;
        let alice = owner("alice@example.com")?;
        let bob = owner("bob@example.com")?;
        let alice_jid = jid("alice@example.com")?;
        let bob_jid = jid("bob@example.com")?;
        block_on(
            repository.update_subscription(&alice, &bob_jid, move |mut current| {
                current.state = subscriber_state;
                current.pending_out = true;
                Some(current)
            }),
        )?;
        block_on(
            repository.update_subscription(&bob, &alice_jid, move |mut current| {
                current.state = recipient_state;
                Some(current)
            }),
        )?;

        let outcome = block_on(repository.request_subscription(
            &alice,
            &bob_jid,
            &bob,
            PendingSubscription {
                sender: alice_jid,
                stanza: b"<presence id='repeat'/>".as_slice().into(),
            },
        ))?;
        let SubscriptionRequestOutcome::AutoApprove {
            mutation: Some(mutation),
        } = outcome
        else {
            return Err("outstanding request was not approved".into());
        };
        assert_eq!(mutation.version.get(), 2);
        assert_eq!(mutation.value.subscription.state, approved_state);
        assert!(!mutation.value.subscription.pending_out);
        assert!(block_on(repository.pending(&bob))?.is_empty());
        assert_eq!(block_on(repository.snapshot(&alice))?.version.get(), 2);
        assert_eq!(block_on(repository.snapshot(&bob))?.version.get(), 1);
    }
    Ok(())
}

#[test]
fn denying_a_pending_request_clears_both_sides_without_changing_the_grantor_roster() -> TestResult {
    let repository = repository()?;
    let alice = owner("alice@example.com")?;
    let bob = owner("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    block_on(repository.request_subscription(
        &alice,
        &bob_jid,
        &bob,
        PendingSubscription {
            sender: alice_jid.clone(),
            stanza: b"<presence type='subscribe'/>".as_slice().into(),
        },
    ))?;

    let cancellation =
        block_on(repository.cancel_subscription(&bob, &alice_jid, &alice, &bob_jid))?;
    assert!(cancellation.route);
    assert!(!cancellation.send_unavailable);
    assert!(cancellation.grantor.is_none());
    let cleared = cancellation.subscriber.ok_or("missing roster change")?;
    assert_eq!(cleared.version.get(), 2);
    assert_eq!(cleared.value.subscription.state, SubscriptionState::None);
    assert!(!cleared.value.subscription.pending_out);
    assert!(block_on(repository.pending(&bob))?.is_empty());
    assert_eq!(block_on(repository.snapshot(&bob))?.version.get(), 0);
    assert!(!block_on(repository.cancel_subscription(&bob, &alice_jid, &alice, &bob_jid))?.route);
    assert_eq!(block_on(repository.snapshot(&alice))?.version.get(), 2);
    Ok(())
}

#[test]
fn revoking_a_mutual_subscription_keeps_the_reverse_grant() -> TestResult {
    let repository = repository()?;
    let alice = owner("alice@example.com")?;
    let bob = owner("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    for (owner, contact) in [(&alice, &bob_jid), (&bob, &alice_jid)] {
        block_on(repository.update_subscription(owner, contact, |_| {
            Some(RosterSubscription {
                state: SubscriptionState::Both,
                pending_out: false,
                approved: false,
            })
        }))?;
    }

    let cancellation =
        block_on(repository.cancel_subscription(&bob, &alice_jid, &alice, &bob_jid))?;
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
    assert_eq!(block_on(repository.snapshot(&alice))?.version.get(), 2);
    assert_eq!(block_on(repository.snapshot(&bob))?.version.get(), 2);
    Ok(())
}

#[test]
fn denying_a_crossed_request_keeps_the_reverse_subscription() -> TestResult {
    let repository = repository()?;
    let alice = owner("alice@example.com")?;
    let bob = owner("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    block_on(repository.update_subscription(&alice, &bob_jid, |_| {
        Some(RosterSubscription {
            state: SubscriptionState::From,
            pending_out: true,
            approved: false,
        })
    }))?;
    block_on(repository.update_subscription(&bob, &alice_jid, |_| {
        Some(RosterSubscription {
            state: SubscriptionState::To,
            pending_out: false,
            approved: false,
        })
    }))?;
    block_on(repository.put_pending(
        &bob,
        PendingSubscription {
            sender: alice_jid.clone(),
            stanza: b"<presence type='subscribe'/>".as_slice().into(),
        },
    ))?;

    let cancellation =
        block_on(repository.cancel_subscription(&bob, &alice_jid, &alice, &bob_jid))?;
    assert!(cancellation.route);
    assert!(!cancellation.send_unavailable);
    assert!(cancellation.grantor.is_none());
    assert_eq!(
        cancellation
            .subscriber
            .ok_or("missing sender change")?
            .value
            .subscription,
        RosterSubscription {
            state: SubscriptionState::From,
            pending_out: false,
            approved: false,
        }
    );
    assert!(block_on(repository.pending(&bob))?.is_empty());
    assert_eq!(block_on(repository.snapshot(&bob))?.version.get(), 1);
    Ok(())
}

#[test]
fn clearing_preapproval_does_not_notify_the_contact() -> TestResult {
    let repository = repository()?;
    let alice = owner("alice@example.com")?;
    let bob = owner("bob@example.com")?;
    let alice_jid = jid("alice@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    block_on(repository.update_subscription(&bob, &alice_jid, |_| {
        Some(RosterSubscription {
            approved: true,
            ..RosterSubscription::default()
        })
    }))?;

    let cancellation =
        block_on(repository.cancel_subscription(&bob, &alice_jid, &alice, &bob_jid))?;
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
    assert_eq!(block_on(repository.snapshot(&bob))?.version.get(), 2);
    assert_eq!(block_on(repository.snapshot(&alice))?.version.get(), 0);
    Ok(())
}

#[test]
fn delete_all_removes_one_owners_roster_version_and_pending_requests() -> TestResult {
    let repository = repository()?;
    let alice = owner("alice@example.com")?;
    let carol = owner("carol@example.com")?;
    let bob = jid("bob@example.com")?;
    for owner in [&alice, &carol] {
        block_on(repository.upsert(
            owner,
            RosterItemUpdate {
                jid: bob.clone(),
                name: None,
                groups: Vec::new(),
            },
        ))?;
        block_on(repository.put_pending(
            owner,
            PendingSubscription {
                sender: bob.clone(),
                stanza: b"<presence/>".as_slice().into(),
            },
        ))?;
    }

    block_on(repository.delete_all(&alice))?;
    assert_eq!(block_on(repository.snapshot(&alice))?.version.get(), 0);
    assert!(block_on(repository.pending(&alice))?.is_empty());
    assert_eq!(block_on(repository.snapshot(&carol))?.items.len(), 1);
    assert_eq!(block_on(repository.pending(&carol))?.len(), 1);
    Ok(())
}

#[test]
fn roster_and_pending_requests_survive_reopening() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("roster.redb");
    let owner = owner("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    {
        let repository = RedbRosterRepository::open(&path)?;
        block_on(repository.upsert(
            &owner,
            RosterItemUpdate {
                jid: contact.clone(),
                name: Some("Bob".into()),
                groups: vec!["Friends".into()],
            },
        ))?;
        block_on(repository.put_pending(
            &owner,
            PendingSubscription {
                sender: contact.clone(),
                stanza: b"<presence/>".as_slice().into(),
            },
        ))?;
    }

    let repository = RedbRosterRepository::open(path)?;
    let snapshot = block_on(repository.snapshot(&owner))?;
    assert_eq!(snapshot.version.get(), 1);
    assert_eq!(snapshot.items[0].name.as_deref(), Some("Bob"));
    assert_eq!(block_on(repository.pending(&owner))?[0].sender, contact);
    Ok(())
}

#[test]
fn roster_jids_are_owned_normalized_addresses() -> TestResult {
    let normalized = jid("É@BÜCHER.EXAMPLE")?;
    assert_eq!(normalized, jid("E\u{301}@xn--bcher-kva.example")?);
    assert_eq!(normalized.as_str(), "é@bücher.example");
    assert_eq!(format!("{normalized:?}"), "RosterJid { .. }");

    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let full = Jid::parse_in("alice@example.com/desktop", &mut arena)?;
    assert_eq!(
        RosterJid::from(full.resolve(&arena)?).as_str(),
        "alice@example.com/desktop"
    );
    assert_eq!(jid("example.com")?.as_str(), "example.com");
    Ok(())
}

#[test]
fn snapshots_are_isolated_by_owner_and_sorted_by_contact() -> TestResult {
    let repository = repository()?;
    let alice = owner("alice@example.com")?;
    let carol = owner("carol@example.com")?;
    for contact in ["zara@example.com", "bob@example.com"] {
        block_on(repository.upsert(
            &alice,
            RosterItemUpdate {
                jid: jid(contact)?,
                name: None,
                groups: Vec::new(),
            },
        ))?;
    }
    block_on(repository.upsert(
        &carol,
        RosterItemUpdate {
            jid: jid("dave@example.com")?,
            name: None,
            groups: Vec::new(),
        },
    ))?;

    let snapshot = block_on(repository.snapshot(&alice))?;
    assert_eq!(snapshot.version.get(), 2);
    assert_eq!(snapshot.items[0].jid.as_str(), "bob@example.com");
    assert_eq!(snapshot.items[1].jid.as_str(), "zara@example.com");
    assert_eq!(block_on(repository.snapshot(&carol))?.items.len(), 1);
    Ok(())
}

#[test]
fn subscription_update_reads_and_changes_state_in_one_write() -> TestResult {
    let repository = repository()?;
    let owner = owner("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    assert!(block_on(repository.update_subscription(&owner, &contact, |_| None))?.is_none());
    assert!(block_on(repository.get(&owner, &contact))?.is_none());
    let first = block_on(repository.update_subscription(&owner, &contact, |current| {
        assert_eq!(current, RosterSubscription::default());
        Some(RosterSubscription {
            state: SubscriptionState::To,
            pending_out: true,
            approved: false,
        })
    }))?
    .ok_or("subscription was not changed")?;
    assert_eq!(first.version.get(), 1);

    let second = block_on(
        repository.update_subscription(&owner, &contact, |mut current| {
            assert_eq!(current.state, SubscriptionState::To);
            current.pending_out = false;
            Some(current)
        }),
    )?
    .ok_or("subscription was not changed")?;
    assert_eq!(second.version.get(), 2);
    assert_eq!(second.value.subscription.state, SubscriptionState::To);
    assert!(!second.value.subscription.pending_out);
    assert!(block_on(repository.update_subscription(&owner, &contact, |_| None))?.is_none());
    assert_eq!(block_on(repository.snapshot(&owner))?.version.get(), 2);
    Ok(())
}
