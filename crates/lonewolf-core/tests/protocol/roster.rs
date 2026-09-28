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
