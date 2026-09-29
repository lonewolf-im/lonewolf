// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use crate::support::{C2sSuite, Client, TestResult};
use compio::runtime::Runtime;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::redb::RedbRosterRepository;
use lonewolf_storage::roster::{
    PendingSubscription, RosterItemUpdate, RosterJid, RosterRepository, RosterSubscription,
    SubscriptionState,
};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;

const ROSTER_NAMESPACE: &str = "jabber:iq:roster";

fn request_roster(client: &mut Client, id: &str, expected: &str) -> TestResult {
    client.send(&format!(
        "<iq type='get' id='{id}'><query xmlns='{ROSTER_NAMESPACE}'/></iq>"
    ))?;
    client.expect_xml(expected)
}

fn expect_roster_push(client: &mut Client, to: &str, item: &str) -> TestResult<String> {
    let push = client.receive()?;
    push.assert_name("jabber:client", "iq");
    assert_eq!(push.attribute("type"), Some("set"), "{push:?}");
    assert_eq!(push.attribute("to"), Some(to), "{push:?}");
    let id = push.attribute("id").ok_or("roster push has no ID")?.into();
    let query = push.child(ROSTER_NAMESPACE, "query")?;
    assert_eq!(query.children.len(), 1, "{push:?}");
    query.children[0].assert_xml(item)?;
    Ok(id)
}

fn seed_roster(directory: &Path) -> TestResult {
    fs::create_dir(directory.join("data"))?;
    let repository = RedbRosterRepository::open(directory.join("data/lonewolf.dat"))?;
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let owner = Jid::parse_in("alice@localhost", &mut arena)?;
    let contact = Jid::parse_in("bob@localhost", &mut arena)?;
    let owner = AccountKey::try_from(owner.resolve(&arena)?)?;
    let contact = RosterJid::from(contact.resolve(&arena)?);
    Runtime::new()?.block_on(async {
        repository
            .upsert(
                &owner,
                RosterItemUpdate {
                    jid: contact.clone(),
                    name: Some("Bob Smith".into()),
                    groups: vec!["Friends".into(), "Work".into()],
                },
            )
            .await?;
        repository
            .update_subscription(&owner, &contact, |_| {
                Some(RosterSubscription {
                    state: SubscriptionState::Both,
                    pending_out: true,
                    approved: true,
                })
            })
            .await?;
        Ok::<_, lonewolf_storage::roster::RosterError>(())
    })?;
    Ok(())
}

fn seed_pending_subscriptions(directory: &Path) -> TestResult {
    fs::create_dir(directory.join("data"))?;
    let repository = RedbRosterRepository::open(directory.join("data/lonewolf.dat"))?;
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let owner = Jid::parse_in("bob@localhost", &mut arena)?;
    let owner = AccountKey::try_from(owner.resolve(&arena)?)?;
    let mut subscriptions = Vec::new();
    for index in 0..65 {
        let sender = format!("sender{index:03}@localhost");
        let jid = Jid::parse_in(&sender, &mut arena)?;
        subscriptions.push(PendingSubscription {
            sender: RosterJid::from(jid.resolve(&arena)?),
            stanza: format!(
                "<presence xmlns='jabber:client' type='subscribe' id='pending-{index:03}' from='{sender}' to='bob@localhost'/>"
            )
            .into_bytes()
            .into_boxed_slice(),
        });
    }
    Runtime::new()?.block_on(async {
        for subscription in subscriptions {
            repository.put_pending(&owner, subscription).await?;
        }
        Ok::<_, lonewolf_storage::roster::RosterError>(())
    })?;
    Ok(())
}

fn seed_interrupted_subscription_approval(directory: &Path) -> TestResult {
    fs::create_dir(directory.join("data"))?;
    let repository = RedbRosterRepository::open(directory.join("data/lonewolf.dat"))?;
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let alice = Jid::parse_in("alice@localhost", &mut arena)?;
    let bob = Jid::parse_in("bob@localhost", &mut arena)?;
    let alice_account = AccountKey::try_from(alice.resolve(&arena)?)?;
    let bob_account = AccountKey::try_from(bob.resolve(&arena)?)?;
    let alice_contact = RosterJid::from(alice.resolve(&arena)?);
    let bob_contact = RosterJid::from(bob.resolve(&arena)?);
    Runtime::new()?.block_on(async {
        repository
            .update_subscription(&alice_account, &bob_contact, |_| {
                Some(RosterSubscription {
                    state: SubscriptionState::To,
                    pending_out: false,
                    approved: false,
                })
            })
            .await?;
        repository
            .put_pending(
                &bob_account,
                PendingSubscription {
                    sender: alice_contact,
                    stanza: b"<presence xmlns='jabber:client' type='subscribe' from='alice@localhost' to='bob@localhost'/>"
                        .to_vec()
                        .into_boxed_slice(),
                },
            )
            .await?;
        Ok::<_, lonewolf_storage::roster::RosterError>(())
    })?;
    Ok(())
}

fn seed_pending_request_with_existing_permission(directory: &Path) -> TestResult {
    fs::create_dir(directory.join("data"))?;
    let repository = RedbRosterRepository::open(directory.join("data/lonewolf.dat"))?;
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let alice = Jid::parse_in("alice@localhost", &mut arena)?;
    let bob = Jid::parse_in("bob@localhost", &mut arena)?;
    let alice_account = AccountKey::try_from(alice.resolve(&arena)?)?;
    let bob_account = AccountKey::try_from(bob.resolve(&arena)?)?;
    let alice_contact = RosterJid::from(alice.resolve(&arena)?);
    let bob_contact = RosterJid::from(bob.resolve(&arena)?);
    Runtime::new()?.block_on(async {
        repository
            .update_subscription(&alice_account, &bob_contact, |_| {
                Some(RosterSubscription {
                    state: SubscriptionState::None,
                    pending_out: true,
                    approved: false,
                })
            })
            .await?;
        repository
            .update_subscription(&bob_account, &alice_contact, |_| {
                Some(RosterSubscription {
                    state: SubscriptionState::From,
                    pending_out: false,
                    approved: false,
                })
            })
            .await?;
        Ok::<_, lonewolf_storage::roster::RosterError>(())
    })?;
    Ok(())
}

#[test]
fn subscription_request_reaches_an_available_contact_and_updates_the_roster() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    let mut bob_tablet = suite.connect("bob", "password", "tablet")?;

    request_roster(
        &mut alice,
        "initial-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    bob_tablet.send("<presence/>")?;
    bob_tablet.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/tablet' to='bob@localhost'/>",
    )?;
    bob_tablet.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/tablet' to='bob@localhost'/>",
    )?;

    alice.send("<presence type='subscribe' id='request' from='mallory@localhost/spy' to='bob@localhost/ignored'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' id='request' from='alice@localhost' to='bob@localhost'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>")?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' type='subscribe' id='request' from='alice@localhost' to='bob@localhost'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>")?;
    let push = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{push}'/>"))?;
    alice.send("<presence type='subscribe' id='repeat' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' id='repeat' from='alice@localhost' to='bob@localhost'/>")?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' type='subscribe' id='repeat' from='alice@localhost' to='bob@localhost'/>")?;
    request_roster(
        &mut alice,
        "pending-roster",
        "<iq xmlns='jabber:client' type='result' id='pending-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='none' ask='subscribe'/></query></iq>",
    )?;

    alice.close()?;
    bob.close()?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost' type='unavailable'/>")?;
    bob_tablet.close()
}

#[test]
fn subscription_approval_updates_both_rosters_and_delivers_current_presence() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut alice_tablet = suite.connect("alice", "password", "tablet")?;
    let mut bob = suite.connect("bob", "password", "phone")?;

    request_roster(
        &mut alice,
        "alice-roster",
        "<iq xmlns='jabber:client' type='result' id='alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob,
        "bob-roster",
        "<iq xmlns='jabber:client' type='result' id='bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice_tablet.send("<presence/>")?;
    alice_tablet.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/tablet' to='alice@localhost'/>",
    )?;
    bob.send("<presence><show>away</show></presence>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'><show>away</show></presence>")?;

    alice.send("<presence type='subscribe' id='request' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' id='request' from='alice@localhost' to='bob@localhost'/>")?;
    bob.send("<presence type='subscribed' id='approval' from='mallory@localhost/spy' to='alice@localhost/ignored'/>")?;
    let alice_pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{alice_pending}'/>"))?;

    alice.expect_xml("<presence xmlns='jabber:client' type='subscribed' id='approval' from='bob@localhost' to='alice@localhost'/>")?;
    let alice_approved = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='to'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{alice_approved}'/>"))?;
    alice_tablet.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost'><show>away</show></presence>")?;
    let bob_approved = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='from'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{bob_approved}'/>"))?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;

    request_roster(
        &mut alice,
        "approved-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='approved-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='to'/></query></iq>",
    )?;
    request_roster(
        &mut bob,
        "approved-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='approved-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='from'/></query></iq>",
    )?;
    request_roster(
        &mut alice_tablet,
        "approved-tablet-roster",
        "<iq xmlns='jabber:client' type='result' id='approved-tablet-roster' to='alice@localhost/tablet'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='to'/></query></iq>",
    )?;

    alice.close()?;
    alice_tablet.close()?;
    bob.close()
}

#[test]
fn repeated_subscription_request_is_automatically_approved_without_roster_changes() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;

    request_roster(
        &mut alice,
        "initial-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob,
        "initial-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;

    alice.send("<presence type='subscribe' id='initial-request' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' id='initial-request' from='alice@localhost' to='bob@localhost'/>")?;
    let alice_pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{alice_pending}'/>"))?;
    bob.send("<presence type='subscribed' id='approval' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribed' id='approval' from='bob@localhost' to='alice@localhost'/>")?;
    let alice_approved = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='to'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{alice_approved}'/>"))?;
    let bob_approved = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='from'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{bob_approved}'/>"))?;

    alice.send("<presence type='subscribe' id='repeat-request' to='bob@localhost'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>")?;
    request_roster(
        &mut alice,
        "unchanged-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='to'/></query></iq>",
    )?;
    request_roster(
        &mut bob,
        "unchanged-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='from'/></query></iq>",
    )?;

    alice.close()?;
    bob.close()
}

#[test]
fn automatic_approval_completes_an_outstanding_request() -> TestResult {
    let suite = C2sSuite::with_extensions_and_setup(
        "'roster'",
        seed_pending_request_with_existing_permission,
    )?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;

    request_roster(
        &mut alice,
        "pending-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='pending-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='none' ask='subscribe'/></query></iq>",
    )?;
    request_roster(
        &mut bob,
        "permitted-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='permitted-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='from'/></query></iq>",
    )?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;

    alice.send("<presence type='subscribe' id='repeat' to='bob@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribed' id='repeat' from='bob@localhost' to='alice@localhost'/>")?;
    let push = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='to'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{push}'/>"))?;
    request_roster(
        &mut bob,
        "unchanged-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='from'/></query></iq>",
    )?;

    alice.close()?;
    bob.close()
}

#[test]
fn denied_subscription_clears_the_request_and_does_not_replay_it() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;

    request_roster(
        &mut alice,
        "alice-roster",
        "<iq xmlns='jabber:client' type='result' id='alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob,
        "bob-roster",
        "<iq xmlns='jabber:client' type='result' id='bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;

    alice.send("<presence type='subscribe' id='request' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' id='request' from='alice@localhost' to='bob@localhost'/>")?;
    let pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{pending}'/>"))?;

    bob.send("<presence type='unsubscribed' id='denied' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='unsubscribed' id='denied' from='bob@localhost' to='alice@localhost'/>")?;
    let cleared = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{cleared}'/>"))?;
    request_roster(
        &mut bob,
        "unchanged-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    bob.send("<presence type='unavailable'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost' type='unavailable'/>")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    request_roster(
        &mut bob,
        "still-empty-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='still-empty-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    alice.close()?;
    bob.close()
}

#[test]
fn revoking_a_grant_sends_unavailable_before_unsubscribed_and_updates_both_rosters() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    let mut bob_tablet = suite.connect("bob", "password", "tablet")?;
    request_roster(
        &mut alice,
        "alice-roster",
        "<iq xmlns='jabber:client' type='result' id='alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob,
        "bob-roster",
        "<iq xmlns='jabber:client' type='result' id='bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    bob.send("<presence><show>away</show></presence>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'><show>away</show></presence>")?;
    bob_tablet.send("<presence/>")?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'><show>away</show></presence>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/tablet' to='bob@localhost'/>",
    )?;
    bob_tablet.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/tablet' to='bob@localhost'/>",
    )?;

    alice.send("<presence type='subscribe' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' from='alice@localhost' to='bob@localhost'/>")?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' type='subscribe' from='alice@localhost' to='bob@localhost'/>")?;
    let pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{pending}'/>"))?;
    bob.send("<presence type='subscribed' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribed' from='bob@localhost' to='alice@localhost'/>")?;
    let approved = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='to'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{approved}'/>"))?;
    let first = alice.receive()?;
    let second = alice.receive()?;
    let (phone, tablet) = if first.attribute("from") == Some("bob@localhost/phone") {
        (&first, &second)
    } else {
        (&second, &first)
    };
    phone.assert_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost'><show>away</show></presence>")?;
    tablet.assert_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/tablet' to='alice@localhost'/>",
    )?;
    let granted = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='from'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{granted}'/>"))?;

    bob.send("<presence type='unsubscribed' id='revoked' to='alice@localhost'/>")?;
    let first = alice.receive()?;
    let second = alice.receive()?;
    let (phone, tablet) = if first.attribute("from") == Some("bob@localhost/phone") {
        (&first, &second)
    } else {
        (&second, &first)
    };
    phone.assert_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost' type='unavailable'/>")?;
    tablet.assert_xml("<presence xmlns='jabber:client' from='bob@localhost/tablet' to='alice@localhost' type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='unsubscribed' id='revoked' from='bob@localhost' to='alice@localhost'/>")?;
    let alice_revoked = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{alice_revoked}'/>"))?;
    let bob_revoked = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='none'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{bob_revoked}'/>"))?;
    request_roster(
        &mut alice,
        "revoked-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='revoked-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='none'/></query></iq>",
    )?;
    request_roster(
        &mut bob,
        "revoked-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='revoked-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='none'/></query></iq>",
    )?;

    bob.send("<presence type='unsubscribed' id='repeat' to='alice@localhost'/>")?;
    request_roster(
        &mut alice,
        "unchanged-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='none'/></query></iq>",
    )?;
    request_roster(
        &mut bob,
        "unchanged-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='none'/></query></iq>",
    )?;
    alice.close()?;
    bob.close()?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost' type='unavailable'/>")?;
    bob_tablet.close()
}

#[test]
fn unsubscribe_notifies_the_contact_before_roster_push_and_unavailable_presence() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    let mut bob_tablet = suite.connect("bob", "password", "tablet")?;
    request_roster(
        &mut alice,
        "alice-roster",
        "<iq xmlns='jabber:client' type='result' id='alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob,
        "bob-roster",
        "<iq xmlns='jabber:client' type='result' id='bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob_tablet,
        "bob-tablet-roster",
        "<iq xmlns='jabber:client' type='result' id='bob-tablet-roster' to='bob@localhost/tablet'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    bob_tablet.send("<presence/>")?;
    bob_tablet.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/tablet' to='bob@localhost'/>",
    )?;
    bob_tablet.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/tablet' to='bob@localhost'/>",
    )?;
    alice.send("<presence type='subscribe' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' from='alice@localhost' to='bob@localhost'/>")?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' type='subscribe' from='alice@localhost' to='bob@localhost'/>")?;
    let pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{pending}'/>"))?;
    bob.send("<presence type='subscribed' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribed' from='bob@localhost' to='alice@localhost'/>")?;
    let approved = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='to'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{approved}'/>"))?;
    let first = alice.receive()?;
    let second = alice.receive()?;
    let (phone, tablet) = if first.attribute("from") == Some("bob@localhost/phone") {
        (&first, &second)
    } else {
        (&second, &first)
    };
    phone.assert_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost'/>",
    )?;
    tablet.assert_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/tablet' to='alice@localhost'/>",
    )?;
    let granted = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='from'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{granted}'/>"))?;
    let tablet_granted = expect_roster_push(
        &mut bob_tablet,
        "bob@localhost/tablet",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='from'/>",
    )?;
    bob_tablet.send(&format!("<iq type='result' id='{tablet_granted}'/>"))?;

    alice.send("<presence type='unsubscribe' id='stop' to='bob@localhost/ignored'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='unsubscribe' id='stop' from='alice@localhost' to='bob@localhost'/>")?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' type='unsubscribe' id='stop' from='alice@localhost' to='bob@localhost'/>")?;
    let bob_push = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='none'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{bob_push}'/>"))?;
    let tablet_push = expect_roster_push(
        &mut bob_tablet,
        "bob@localhost/tablet",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='none'/>",
    )?;
    bob_tablet.send(&format!("<iq type='result' id='{tablet_push}'/>"))?;
    let alice_push = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{alice_push}'/>"))?;
    let first = alice.receive()?;
    let second = alice.receive()?;
    let (phone, tablet) = if first.attribute("from") == Some("bob@localhost/phone") {
        (&first, &second)
    } else {
        (&second, &first)
    };
    phone.assert_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost' type='unavailable'/>")?;
    tablet.assert_xml("<presence xmlns='jabber:client' from='bob@localhost/tablet' to='alice@localhost' type='unavailable'/>")?;
    alice.send("<presence type='unsubscribe' id='repeat' to='bob@localhost'/>")?;
    request_roster(
        &mut alice,
        "unchanged-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='none'/></query></iq>",
    )?;
    request_roster(
        &mut bob,
        "unchanged-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='none'/></query></iq>",
    )?;
    alice.close()?;
    bob.close()?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost' type='unavailable'/>")?;
    bob_tablet.close()
}

#[test]
fn unsubscribe_removes_a_pending_request_before_the_contact_comes_online() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    request_roster(
        &mut alice,
        "initial-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    alice.send("<presence type='subscribe' id='request' to='bob@localhost'/>")?;
    let pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{pending}'/>"))?;
    alice.send("<presence type='unsubscribe' id='withdraw' to='bob@localhost'/>")?;
    let cleared = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{cleared}'/>"))?;

    let mut bob = suite.connect("bob", "password", "phone")?;
    request_roster(
        &mut bob,
        "bob-roster",
        "<iq xmlns='jabber:client' type='result' id='bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    request_roster(
        &mut bob,
        "still-empty",
        "<iq xmlns='jabber:client' type='result' id='still-empty' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.close()?;
    bob.close()
}

#[test]
fn unsubscribe_from_a_mutual_subscription_keeps_the_reverse_grant() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    request_roster(
        &mut alice,
        "alice-roster",
        "<iq xmlns='jabber:client' type='result' id='alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob,
        "bob-roster",
        "<iq xmlns='jabber:client' type='result' id='bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;

    alice.send("<presence type='subscribe' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' from='alice@localhost' to='bob@localhost'/>")?;
    let pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{pending}'/>"))?;
    bob.send("<presence type='subscribed' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribed' from='bob@localhost' to='alice@localhost'/>")?;
    let approved = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='to'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{approved}'/>"))?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost'/>",
    )?;
    let granted = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='from'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{granted}'/>"))?;

    bob.send("<presence type='subscribe' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribe' from='bob@localhost' to='alice@localhost'/>")?;
    let pending = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='from' ask='subscribe'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{pending}'/>"))?;
    alice.send("<presence type='subscribed' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribed' from='alice@localhost' to='bob@localhost'/>")?;
    let approved = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='both'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{approved}'/>"))?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost'/>",
    )?;
    let granted = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='both'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{granted}'/>"))?;

    alice.send("<presence type='unsubscribe' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='unsubscribe' from='alice@localhost' to='bob@localhost'/>")?;
    let bob_push = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='to'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{bob_push}'/>"))?;
    let alice_push = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='from'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{alice_push}'/>"))?;
    alice.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost' type='unavailable'/>")?;
    request_roster(
        &mut alice,
        "final-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='final-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='from'/></query></iq>",
    )?;
    request_roster(
        &mut bob,
        "final-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='final-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='to'/></query></iq>",
    )?;
    alice.close()?;
    bob.close()
}

#[test]
fn unsubscribe_from_self_sends_one_final_roster_push() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    request_roster(
        &mut alice,
        "initial-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    alice.send("<presence type='subscribe' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribe' from='alice@localhost' to='alice@localhost'/>")?;
    let pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{pending}'/>"))?;
    alice.send("<presence type='subscribed' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribed' from='alice@localhost' to='alice@localhost'/>")?;
    let approved = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='to'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{approved}'/>"))?;
    let granted = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='both'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{granted}'/>"))?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;

    alice.send("<presence type='unsubscribe' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='unsubscribe' from='alice@localhost' to='alice@localhost'/>")?;
    let withdrawn = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='none'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{withdrawn}'/>"))?;
    alice.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost' type='unavailable'/>")?;
    request_roster(
        &mut alice,
        "final-roster",
        "<iq xmlns='jabber:client' type='result' id='final-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='none'/></query></iq>",
    )?;
    alice.close()
}

#[test]
fn unsubscribe_updates_the_contact_roster_while_the_contact_is_offline() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    request_roster(
        &mut alice,
        "alice-roster",
        "<iq xmlns='jabber:client' type='result' id='alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob,
        "bob-roster",
        "<iq xmlns='jabber:client' type='result' id='bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    alice.send("<presence type='subscribe' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' from='alice@localhost' to='bob@localhost'/>")?;
    let pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{pending}'/>"))?;
    bob.send("<presence type='subscribed' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribed' from='bob@localhost' to='alice@localhost'/>")?;
    let approved = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='to'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{approved}'/>"))?;
    let granted = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='from'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{granted}'/>"))?;
    bob.close()?;

    alice.send("<presence type='unsubscribe' to='bob@localhost'/>")?;
    let withdrawn = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{withdrawn}'/>"))?;
    let mut bob = suite.connect("bob", "password", "tablet")?;
    request_roster(
        &mut bob,
        "final-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='final-bob-roster' to='bob@localhost/tablet'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='none'/></query></iq>",
    )?;
    alice.close()?;
    bob.close()
}

#[test]
fn revocation_clears_the_grant_after_the_subscriber_account_is_deleted() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    request_roster(
        &mut alice,
        "alice-roster",
        "<iq xmlns='jabber:client' type='result' id='alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob,
        "bob-roster",
        "<iq xmlns='jabber:client' type='result' id='bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    alice.send("<presence type='subscribe' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' from='alice@localhost' to='bob@localhost'/>")?;
    let pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{pending}'/>"))?;
    bob.send("<presence type='subscribed' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribed' from='bob@localhost' to='alice@localhost'/>")?;
    let approved = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='to'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{approved}'/>"))?;
    let granted = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='from'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{granted}'/>"))?;

    alice.close()?;
    suite.delete_account("alice")?;
    bob.send("<presence type='unsubscribed' to='alice@localhost'/>")?;
    let revoked = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='none'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{revoked}'/>"))?;
    request_roster(
        &mut bob,
        "revoked-roster",
        "<iq xmlns='jabber:client' type='result' id='revoked-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='none'/></query></iq>",
    )?;
    bob.close()
}

#[test]
fn self_subscription_revocation_sends_one_final_roster_push() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    request_roster(
        &mut alice,
        "initial-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;

    alice.send("<presence type='subscribe' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribe' from='alice@localhost' to='alice@localhost'/>")?;
    let pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{pending}'/>"))?;
    alice.send("<presence type='subscribed' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribed' from='alice@localhost' to='alice@localhost'/>")?;
    let approved = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='to'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{approved}'/>"))?;
    let granted = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='both'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{granted}'/>"))?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;

    alice.send("<presence type='unsubscribed' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost' type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='unsubscribed' from='alice@localhost' to='alice@localhost'/>")?;
    let revoked = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='none'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{revoked}'/>"))?;
    request_roster(
        &mut alice,
        "final-roster",
        "<iq xmlns='jabber:client' type='result' id='final-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='none'/></query></iq>",
    )?;
    alice.close()
}

#[test]
fn unsolicited_subscription_approval_is_silently_ignored() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;

    request_roster(
        &mut alice,
        "initial-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob,
        "initial-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    bob.send("<presence type='subscribed' id='unsolicited' to='alice@localhost'/>")?;
    request_roster(
        &mut alice,
        "unchanged-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob,
        "unchanged-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    alice.close()?;
    bob.close()
}

#[test]
fn subscription_approval_retry_completes_an_interrupted_transition() -> TestResult {
    let suite =
        C2sSuite::with_extensions_and_setup("'roster'", seed_interrupted_subscription_approval)?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;

    request_roster(
        &mut alice,
        "partial-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='partial-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='to'/></query></iq>",
    )?;
    request_roster(
        &mut bob,
        "partial-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='partial-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    bob.send("<presence type='subscribed' id='retry' to='alice@localhost'/>")?;
    let bob_approved = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='from'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{bob_approved}'/>"))?;

    request_roster(
        &mut alice,
        "unchanged-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='to'/></query></iq>",
    )?;
    request_roster(
        &mut bob,
        "completed-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='completed-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='from'/></query></iq>",
    )?;

    alice.close()?;
    bob.close()
}

#[test]
fn crossed_subscription_approvals_create_a_mutual_subscription() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;

    request_roster(
        &mut alice,
        "initial-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut bob,
        "initial-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    alice.send("<presence type='subscribe' id='alice-request' to='bob@localhost'/>")?;
    let alice_pending = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{alice_pending}'/>"))?;
    bob.send("<presence type='subscribe' id='bob-request' to='alice@localhost'/>")?;
    let bob_pending = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='none' ask='subscribe'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{bob_pending}'/>"))?;

    bob.send("<presence type='subscribed' id='alice-approved' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='subscribed' id='alice-approved' from='bob@localhost' to='alice@localhost'/>")?;
    let alice_to = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='to'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{alice_to}'/>"))?;
    let bob_from = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='from' ask='subscribe'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{bob_from}'/>"))?;

    alice.send("<presence type='subscribed' id='bob-approved' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribed' id='bob-approved' from='alice@localhost' to='bob@localhost'/>")?;
    let bob_both = expect_roster_push(
        &mut bob,
        "bob@localhost/phone",
        "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='both'/>",
    )?;
    bob.send(&format!("<iq type='result' id='{bob_both}'/>"))?;
    let alice_both = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='both'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{alice_both}'/>"))?;

    request_roster(
        &mut alice,
        "mutual-alice-roster",
        "<iq xmlns='jabber:client' type='result' id='mutual-alice-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='both'/></query></iq>",
    )?;
    request_roster(
        &mut bob,
        "mutual-bob-roster",
        "<iq xmlns='jabber:client' type='result' id='mutual-bob-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'><item jid='alice@localhost' subscription='both'/></query></iq>",
    )?;

    alice.close()?;
    bob.close()
}

#[test]
fn subscription_request_is_delivered_when_an_offline_contact_becomes_available() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    request_roster(
        &mut alice,
        "initial-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.send("<presence type='subscribe' id='offline' to='bob@localhost'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>")?;
    let push = expect_roster_push(
        &mut alice,
        "alice@localhost/desk",
        "<item xmlns='jabber:iq:roster' jid='bob@localhost' subscription='none' ask='subscribe'/>",
    )?;
    alice.send(&format!("<iq type='result' id='{push}'/>"))?;

    let mut bob = suite.connect("bob", "password", "phone")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' id='offline' from='alice@localhost' to='bob@localhost'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>")?;

    bob.send("<presence><show>away</show></presence>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'><show>away</show></presence>")?;
    let mut bob_tablet = suite.connect("bob", "password", "tablet")?;
    bob_tablet.send("<presence/>")?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'><show>away</show></presence>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/tablet' to='bob@localhost'/>",
    )?;
    bob_tablet.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/tablet' to='bob@localhost'/>",
    )?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' type='subscribe' id='offline' from='alice@localhost' to='bob@localhost'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>")?;

    alice.close()?;
    bob.close()?;
    bob_tablet.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost' type='unavailable'/>")?;
    bob_tablet.close()
}

#[test]
fn all_stored_subscription_requests_are_replayed_beyond_the_resource_mailbox_capacity() -> TestResult
{
    let suite = C2sSuite::with_extensions_and_setup("'roster'", seed_pending_subscriptions)?;
    suite.create_account("bob", "password")?;
    let mut bob = suite.connect("bob", "password", "phone")?;

    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    for index in 0..65 {
        bob.expect_xml(&format!(
            "<presence xmlns='jabber:client' type='subscribe' id='pending-{index:03}' from='sender{index:03}@localhost' to='bob@localhost'/>",
        ))?;
    }

    bob.close()
}

#[test]
fn subscription_request_to_a_missing_account_returns_an_error_without_mutating_the_roster()
-> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<presence type='subscribe' id='missing' to='bob@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='error' id='missing' from='bob@localhost' to='alice@localhost/desk'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")?;
    request_roster(
        &mut alice,
        "unchanged-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    alice.close()
}

#[test]
fn subscription_request_rejected_by_the_recipient_host_does_not_mutate_the_roster() -> TestResult {
    let suite = C2sSuite::with_hosts(
        r#"
[hosts.localhost]
extensions = ["roster"]
[hosts."other.localhost"]
[hosts."other.localhost".tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
"#,
    )?;
    suite.create_account("alice", "password")?;
    suite.create_account_jid("bob@other.localhost", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<presence type='subscribe' id='disabled' to='bob@other.localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='error' id='disabled' from='bob@other.localhost' to='alice@localhost/desk'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")?;
    request_roster(
        &mut alice,
        "unchanged-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    alice.close()
}

#[test]
fn enabled_roster_returns_an_empty_roster() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>")?;

    alice.close()
}

#[test]
fn roster_get_with_an_item_returns_bad_request() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<iq type='get' id='invalid-roster'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'/></query></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='invalid-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'/></query><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;

    alice.close()
}

#[test]
fn roster_get_returns_stored_items() -> TestResult {
    let suite = C2sSuite::with_extensions_and_setup("'roster'", seed_roster)?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<iq type='get' id='stored-roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='stored-roster' to='alice@localhost/desk'>
            <query xmlns='jabber:iq:roster'>
                <item jid='bob@localhost' name='Bob Smith' subscription='both' ask='subscribe' approved='true'>
                    <group>Friends</group>
                    <group>Work</group>
                </item>
            </query>
        </iq>",
    )?;

    alice.close()
}

#[test]
fn roster_get_for_another_account_returns_forbidden() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send(
        "<iq type='get' id='other-roster' to='bob@localhost'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='other-roster' from='bob@localhost' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/><error type='auth'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;

    alice.close()
}

#[test]
fn roster_set_adds_an_item_and_pushes_it_to_interested_resources() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut desk = suite.connect("alice", "password", "desk")?;
    let mut phone = suite.connect("alice", "password", "phone")?;
    let mut tablet = suite.connect("alice", "password", "tablet")?;

    request_roster(
        &mut desk,
        "desk-roster",
        "<iq xmlns='jabber:client' type='result' id='desk-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    request_roster(
        &mut phone,
        "phone-roster",
        "<iq xmlns='jabber:client' type='result' id='phone-roster' to='alice@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    desk.send("<iq type='set' id='add-bob'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' name='Bob Smith'><group>Friends</group><group>Work</group></item></query></iq>")?;
    desk.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='add-bob' to='alice@localhost/desk'/>",
    )?;
    let item = "<item xmlns='jabber:iq:roster' jid='bob@localhost' name='Bob Smith' subscription='none'><group>Friends</group><group>Work</group></item>";
    let desk_push = expect_roster_push(&mut desk, "alice@localhost/desk", item)?;
    let phone_push = expect_roster_push(&mut phone, "alice@localhost/phone", item)?;
    desk.send(&format!("<iq type='result' id='{desk_push}'/>"))?;
    phone.send(&format!("<iq type='result' id='{phone_push}'/>"))?;

    request_roster(
        &mut tablet,
        "tablet-roster",
        "<iq xmlns='jabber:client' type='result' id='tablet-roster' to='alice@localhost/tablet'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' name='Bob Smith' subscription='none'><group>Friends</group><group>Work</group></item></query></iq>",
    )?;

    desk.close()?;
    phone.close()?;
    tablet.close()
}

#[test]
fn roster_set_updates_editable_fields_and_preserves_subscription_state() -> TestResult {
    let suite = C2sSuite::with_extensions_and_setup("'roster'", seed_roster)?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    request_roster(
        &mut alice,
        "initial-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' name='Bob Smith' subscription='both' ask='subscribe' approved='true'><group>Friends</group><group>Work</group></item></query></iq>",
    )?;
    alice.send("<iq type='set' id='update-bob'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' name='Robert' subscription='from'><group>Family</group></item></query></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='update-bob' to='alice@localhost/desk'/>",
    )?;
    let item = "<item xmlns='jabber:iq:roster' jid='bob@localhost' name='Robert' subscription='both' ask='subscribe' approved='true'><group>Family</group></item>";
    let push = expect_roster_push(&mut alice, "alice@localhost/desk", item)?;
    alice.send(&format!("<iq type='result' id='{push}'/>"))?;
    request_roster(
        &mut alice,
        "updated-roster",
        "<iq xmlns='jabber:client' type='result' id='updated-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' name='Robert' subscription='both' ask='subscribe' approved='true'><group>Family</group></item></query></iq>",
    )?;

    alice.close()
}

#[test]
fn roster_set_with_multiple_items_returns_bad_request_without_mutating() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    request_roster(
        &mut alice,
        "initial-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.send("<iq type='set' id='multiple-items'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'/><item jid='carol@localhost'/></query></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='multiple-items' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'/><item jid='carol@localhost'/></query><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    request_roster(
        &mut alice,
        "unchanged-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    alice.close()
}

#[test]
fn roster_set_with_duplicate_groups_returns_bad_request_without_mutating() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    request_roster(
        &mut alice,
        "initial-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.send("<iq type='set' id='duplicate-groups'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'><group>Friends</group><group>Friends</group></item></query></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='duplicate-groups' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'><group>Friends</group><group>Friends</group></item></query><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    request_roster(
        &mut alice,
        "unchanged-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    alice.close()
}

#[test]
fn roster_set_with_an_empty_group_returns_not_acceptable_without_mutating() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    request_roster(
        &mut alice,
        "initial-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.send("<iq type='set' id='empty-group'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'><group/></item></query></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='empty-group' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'><group/></item></query><error type='modify'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    request_roster(
        &mut alice,
        "unchanged-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    alice.close()
}

#[test]
fn roster_set_for_another_account_returns_forbidden_without_mutating() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;

    request_roster(
        &mut bob,
        "initial-roster",
        "<iq xmlns='jabber:client' type='result' id='initial-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.send("<iq type='set' id='other-roster' to='bob@localhost'><query xmlns='jabber:iq:roster'><item jid='carol@localhost'/></query></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='other-roster' from='bob@localhost' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='carol@localhost'/></query><error type='auth'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    request_roster(
        &mut bob,
        "unchanged-roster",
        "<iq xmlns='jabber:client' type='result' id='unchanged-roster' to='bob@localhost/phone'><query xmlns='jabber:iq:roster'/></iq>",
    )?;

    alice.close()?;
    bob.close()
}

#[test]
fn roster_set_without_an_item_returns_bad_request() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<iq type='set' id='missing-item'><query xmlns='jabber:iq:roster'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='missing-item' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;

    alice.close()
}

#[test]
fn roster_set_without_an_item_jid_returns_bad_request() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<iq type='set' id='missing-jid'><query xmlns='jabber:iq:roster'><item name='Bob'/></query></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='missing-jid' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item name='Bob'/></query><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;

    alice.close()
}

#[test]
fn roster_set_with_a_full_jid_returns_bad_request() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<iq type='set' id='full-jid'><query xmlns='jabber:iq:roster'><item jid='bob@localhost/phone'/></query></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='full-jid' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost/phone'/></query><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;

    alice.close()
}

#[test]
fn roster_set_does_not_push_to_an_uninterested_initiating_resource() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<iq type='set' id='add-bob'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'/></query></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='add-bob' to='alice@localhost/desk'/>",
    )?;
    request_roster(
        &mut alice,
        "stored-roster",
        "<iq xmlns='jabber:client' type='result' id='stored-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='none'/></query></iq>",
    )?;

    alice.close()
}
