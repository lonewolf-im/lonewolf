// SPDX-License-Identifier: Apache-2.0

use quick_xml::escape::escape;

use super::change_rule;
use super::mutations::{fetch, push_id};
use super::presence::subscribe;
use crate::roster::seed_mutual_subscription;
use crate::support::xml::Element;
use crate::support::{C2sSuite, Client, PASSWORD, TestResult, barrier, mutually_subscribe};

const ALICE: &str = "alice@localhost";
const DESK: &str = "alice@localhost/desk";
const PHONE: &str = "alice@localhost/phone";
const BOB: &str = "bob@localhost";
const TABLET: &str = "bob@localhost/tablet";
const WATCH: &str = "bob@localhost/watch";
const BOTH_VISIBLE: &[(&str, Option<&str>)] =
    &[(DESK, Some("at the desk")), (PHONE, Some("outdoors"))];
const BOTH_HIDDEN: &[(&str, Option<&str>)] = &[(DESK, None), (PHONE, None)];

fn suite(users: &[&str]) -> TestResult<C2sSuite> {
    let suite = C2sSuite::with_extensions("'blocking', 'roster', 'ping'")?;
    for user in users {
        suite.create_account(user, PASSWORD)?;
    }
    Ok(suite)
}

fn presence_before_ping(client: &mut Client) -> TestResult<Vec<Element>> {
    client.send("<iq type='get' id='presence-check'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    let mut presence = Vec::new();
    loop {
        let stanza = client.receive()?;
        if stanza.name == "iq" {
            assert_eq!(stanza.attribute("id"), Some("presence-check"), "{stanza:?}");
            assert_eq!(stanza.attribute("type"), Some("result"), "{stanza:?}");
            return Ok(presence);
        }
        stanza.assert_name("jabber:client", "presence");
        presence.push(stanza);
    }
}

fn publish(client: &mut Client, status: &str) -> TestResult {
    client.send(&format!("<presence><status>{status}</status></presence>"))?;
    let presence = presence_before_ping(client)?;
    assert!(
        presence.iter().any(|stanza| stanza
            .child("jabber:client", "status")
            .is_ok_and(|child| child.text == status)),
        "missing presence echo for {status}: {presence:?}"
    );
    Ok(())
}

pub(super) fn expect_presence(
    client: &mut Client,
    recipient: &str,
    expected: &[(&str, Option<&str>)],
) -> TestResult {
    let arrived = presence_before_ping(client)?;
    let mut missing = expected.to_vec();
    for stanza in &arrived {
        let to = stanza.attribute("to").ok_or("missing recipient")?;
        assert!(
            to == recipient || Some(to) == recipient.split_once('/').map(|p| p.0),
            "{stanza:?}"
        );
        let from = stanza.attribute("from").ok_or("missing presence source")?;
        let status = match stanza.attribute("type") {
            Some("unavailable") => {
                assert!(
                    stanza.child("jabber:client", "status").is_err(),
                    "{stanza:?}"
                );
                None
            }
            None => Some(stanza.child("jabber:client", "status")?.text.as_str()),
            other => return Err(format!("unexpected presence type {other:?}: {stanza:?}").into()),
        };
        let index = missing
            .iter()
            .position(|pair| *pair == (from, status))
            .ok_or_else(|| {
                format!("unexpected presence for {recipient}: {stanza:?}, expected {expected:?}")
            })?;
        missing.swap_remove(index);
    }
    assert!(
        missing.is_empty(),
        "{recipient} missing {missing:?}, received {arrived:?}"
    );
    Ok(())
}

#[test]
fn block_and_unblock_send_presence_only_on_effective_transitions() -> TestResult {
    let suite = suite(&["alice", "bob", "carol", "dave", "erin"])?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut idle_source = suite.connect("alice", PASSWORD, "idle")?;
    fetch(&mut idle_source, "")?;
    let mut tablet = suite.connect("bob", PASSWORD, "tablet")?;
    let mut watch = suite.connect("bob", PASSWORD, "watch")?;
    let mut offline = suite.connect("bob", PASSWORD, "idle")?;
    let mut carol = suite.connect("carol", PASSWORD, "desk")?;
    let mut dave = suite.connect("dave", PASSWORD, "desk")?;
    let mut erin = suite.connect("erin", PASSWORD, "desk")?;
    subscribe(&mut tablet, BOB, &mut desk, ALICE)?;
    mutually_subscribe(&mut desk, "alice", &mut carol, "carol")?;
    subscribe(&mut desk, ALICE, &mut dave, "dave@localhost")?;
    desk.send("<iq type='set' id='entry'><query xmlns='jabber:iq:roster'><item jid='erin@localhost'/></query></iq>")?;
    let entry = desk.receive()?;
    assert_eq!(entry.attribute("id"), Some("entry"));
    assert_eq!(entry.attribute("type"), Some("result"));
    for client in [&mut tablet, &mut watch, &mut carol, &mut dave, &mut erin] {
        publish(client, "online")?;
    }
    expect_presence(&mut tablet, TABLET, &[(WATCH, Some("online"))])?;
    publish(&mut desk, "at the desk")?;
    publish(&mut phone, "outdoors")?;
    expect_presence(&mut desk, DESK, &[(PHONE, Some("outdoors"))])?;
    expect_presence(&mut tablet, TABLET, BOTH_VISIBLE)?;
    expect_presence(&mut watch, WATCH, BOTH_VISIBLE)?;
    expect_presence(&mut carol, "carol@localhost/desk", BOTH_VISIBLE)?;
    let same = &[][..];
    for (command, item, tablet_updates, watch_updates, carol_updates) in [
        ("block", "localhost/watch", same, same, same),
        ("unblock", "localhost/watch", same, same, same),
        ("block", TABLET, BOTH_HIDDEN, same, same),
        ("block", TABLET, same, same, same),
        ("block", BOB, same, BOTH_HIDDEN, same),
        ("block", "localhost", same, same, BOTH_HIDDEN),
        ("unblock", "localhost", same, same, BOTH_VISIBLE),
        ("unblock", BOB, same, BOTH_VISIBLE, same),
        ("unblock", TABLET, BOTH_VISIBLE, same, same),
        ("unblock", TABLET, same, same, same),
        ("block", "localhost", BOTH_HIDDEN, BOTH_HIDDEN, BOTH_HIDDEN),
        ("block", BOB, same, same, same),
        ("block", TABLET, same, same, same),
        ("unblock", TABLET, same, same, same),
        ("unblock", BOB, same, same, same),
        ("unblock", "", BOTH_VISIBLE, BOTH_VISIBLE, BOTH_VISIBLE),
        ("unblock", "", same, same, same),
    ] {
        change_rule(&mut desk, command, item)?;
        let push = idle_source.receive()?;
        let items = if item.is_empty() {
            &[]
        } else {
            std::slice::from_ref(&item)
        };
        let id = push_id(&push, "alice@localhost/idle", command, items)?;
        idle_source.send(&format!("<iq type='result' id='{}'/>", escape(id)))?;
        expect_presence(&mut tablet, TABLET, tablet_updates)?;
        expect_presence(&mut watch, WATCH, watch_updates)?;
        expect_presence(&mut carol, "carol@localhost/desk", carol_updates)?;
        expect_presence(&mut offline, "bob@localhost/idle", same)?;
        expect_presence(&mut dave, "dave@localhost/desk", same)?;
        expect_presence(&mut erin, "erin@localhost/desk", same)?;
    }
    desk.send("<message to='bob@localhost/tablet' id='resumed'/>")?;
    tablet.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/tablet' id='resumed'/>")
}

fn probe(client: &mut Client, recipient: &str, source: &str, kind: Option<&str>) -> TestResult {
    client.send("<presence type='probe' to='alice@localhost/phone' id='scope'/>")?;
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "presence");
    assert_eq!(reply.attribute("from"), Some(source), "{reply:?}");
    assert_eq!(reply.attribute("to"), Some(recipient), "{reply:?}");
    assert_eq!(reply.attribute("type"), kind, "{reply:?}");
    Ok(())
}

#[test]
fn directed_only_withdrawal_is_scoped_to_the_original_source() -> TestResult {
    let suite = suite(&["alice", "bob"])?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut tablet = suite.connect("bob", PASSWORD, "tablet")?;
    let mut watch = suite.connect("bob", PASSWORD, "watch")?;
    publish(&mut desk, "at the desk")?;
    publish(&mut phone, "outdoors")?;
    expect_presence(&mut desk, DESK, &[(PHONE, Some("outdoors"))])?;
    publish(&mut tablet, "tablet online")?;
    publish(&mut watch, "watch online")?;
    expect_presence(&mut tablet, TABLET, &[(WATCH, Some("watch online"))])?;

    phone
        .send("<presence to='bob@localhost/tablet'><status>directed update</status></presence>")?;
    barrier(&mut phone)?;
    expect_presence(&mut tablet, TABLET, &[(PHONE, Some("directed update"))])?;
    change_rule(&mut desk, "block", BOB)?;
    expect_presence(&mut tablet, TABLET, &[(PHONE, None)])?;
    expect_presence(&mut watch, WATCH, &[])?;
    change_rule(&mut desk, "unblock", BOB)?;
    expect_presence(&mut tablet, TABLET, &[])?;
    expect_presence(&mut watch, WATCH, &[])?;
    probe(&mut tablet, TABLET, PHONE, None)?;
    probe(&mut watch, WATCH, ALICE, Some("unsubscribed"))?;
    phone.send("<presence to='bob@localhost/tablet'><status>second grant</status></presence>")?;
    barrier(&mut phone)?;
    expect_presence(&mut tablet, TABLET, &[(PHONE, Some("second grant"))])?;
    phone.send("<presence type='unavailable' to='bob@localhost/tablet'/>")?;
    barrier(&mut phone)?;
    expect_presence(&mut tablet, TABLET, &[(PHONE, None)])?;
    change_rule(&mut desk, "block", BOB)?;
    expect_presence(&mut tablet, TABLET, &[])?;
    change_rule(&mut desk, "unblock", "")?;
    expect_presence(&mut tablet, TABLET, &[])?;
    expect_presence(&mut watch, WATCH, &[])?;
    probe(&mut tablet, TABLET, ALICE, Some("unsubscribed"))
}

#[test]
fn mutual_block_prevents_reappearance() -> TestResult {
    let suite = suite(&["alice", "bob"])?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "tablet")?;
    subscribe(&mut bob, BOB, &mut alice, ALICE)?;
    publish(&mut bob, "online")?;
    publish(&mut alice, "at the desk")?;
    expect_presence(&mut bob, TABLET, &[(DESK, Some("at the desk"))])?;
    change_rule(&mut bob, "block", ALICE)?;
    change_rule(&mut alice, "block", BOB)?;
    expect_presence(&mut bob, TABLET, &[])?;
    change_rule(&mut alice, "unblock", BOB)?;
    expect_presence(&mut bob, TABLET, &[])?;
    change_rule(&mut bob, "unblock", ALICE)?;
    change_rule(&mut alice, "block", BOB)?;
    expect_presence(&mut bob, TABLET, &[(DESK, None)])?;
    change_rule(&mut alice, "unblock", BOB)?;
    expect_presence(&mut bob, TABLET, &[(DESK, Some("at the desk"))])
}

fn roster(client: &mut Client, peer: &str, subscription: &str) -> TestResult<Element> {
    client.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("id"), Some("roster"));
    assert_eq!(reply.attribute("type"), Some("result"));
    let query = reply.child("jabber:iq:roster", "query")?;
    assert_eq!(query.children.len(), 1);
    let item = query.child("jabber:iq:roster", "item")?;
    assert_eq!(item.attribute("jid"), Some(peer));
    assert_eq!(item.attribute("subscription"), Some(subscription));
    Ok(reply)
}

#[test]
fn block_preserves_subscription_and_sends_no_notice() -> TestResult {
    let suite = suite(&["alice", "bob"])?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "tablet")?;
    subscribe(&mut bob, BOB, &mut alice, ALICE)?;
    let owner_roster = roster(&mut alice, BOB, "from")?;
    let peer_roster = roster(&mut bob, ALICE, "to")?;
    publish(&mut bob, "online")?;
    publish(&mut alice, "at the desk")?;
    expect_presence(&mut bob, TABLET, &[(DESK, Some("at the desk"))])?;
    change_rule(&mut alice, "block", BOB)?;
    assert_eq!(roster(&mut alice, BOB, "from")?, owner_roster);
    expect_presence(&mut bob, TABLET, &[(DESK, None)])?;
    assert_eq!(roster(&mut bob, ALICE, "to")?, peer_roster);
    change_rule(&mut alice, "unblock", BOB)?;
    expect_presence(&mut bob, TABLET, &[(DESK, Some("at the desk"))])?;
    assert_eq!(roster(&mut alice, BOB, "from")?, owner_roster);
    assert_eq!(roster(&mut bob, ALICE, "to")?, peer_roster);
    alice.send("<message to='bob@localhost/tablet' id='resumed'/>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/tablet' id='resumed'/>")
}

#[test]
fn disabled_roster_uses_only_live_directed_grants_for_transitions() -> TestResult {
    let suite =
        C2sSuite::with_extensions_and_setup("'blocking', 'ping'", seed_mutual_subscription)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "tablet")?;
    publish(&mut bob, "online")?;
    publish(&mut alice, "at the desk")?;
    change_rule(&mut alice, "block", BOB)?;
    expect_presence(&mut bob, TABLET, &[])?;
    change_rule(&mut alice, "unblock", "")?;
    expect_presence(&mut bob, TABLET, &[])?;
    alice.send("<presence to='bob@localhost/tablet'><status>directed</status></presence>")?;
    barrier(&mut alice)?;
    expect_presence(&mut bob, TABLET, &[(DESK, Some("directed"))])?;
    change_rule(&mut alice, "block", BOB)?;
    expect_presence(&mut bob, TABLET, &[(DESK, None)])?;
    change_rule(&mut alice, "unblock", "")?;
    expect_presence(&mut bob, TABLET, &[])
}

#[test]
fn unblock_restores_only_still_available_resources_with_their_latest_presence() -> TestResult {
    let suite = suite(&["alice", "bob"])?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "tablet")?;
    subscribe(&mut bob, BOB, &mut desk, ALICE)?;
    change_rule(&mut desk, "block", BOB)?;
    publish(&mut bob, "online")?;
    publish(&mut desk, "original")?;
    publish(&mut phone, "outdoors")?;
    expect_presence(&mut desk, DESK, &[(PHONE, Some("outdoors"))])?;
    publish(&mut desk, "updated")?;
    expect_presence(&mut phone, PHONE, &[(DESK, Some("updated"))])?;
    phone.close()?;
    suite.wait_for_closed("stream_end", 1)?;
    expect_presence(&mut desk, DESK, &[(PHONE, None)])?;
    expect_presence(&mut bob, TABLET, &[])?;
    change_rule(&mut desk, "unblock", BOB)?;
    expect_presence(&mut bob, TABLET, &[(DESK, Some("updated"))])
}
