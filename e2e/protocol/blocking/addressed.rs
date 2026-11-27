// SPDX-License-Identifier: Apache-2.0

use compio::runtime::Runtime;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::OfflineReads;
use lonewolf_storage::{RedbStorage, Storage};
use lonewolf_util::arena::Arena;
use lonewolf_xmpp::jid::Jid;

use super::mutations::{assert_result, send_change};
use crate::support::xml::Element;
use crate::support::{C2sSuite, Client, PASSWORD, TestResult, barrier, mutually_subscribe};

const ALICE: &str = "alice@localhost/desk";
const BOB: &str = "bob@localhost/desk";
const BLOCK_ALICE: &str = "<item jid='alice@localhost'/>";
const BLOCK_BOB: &str = "<item jid='bob@localhost'/>";
const STANZA_ERROR: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";
const BLOCKED: &str = "urn:xmpp:blocking:errors";

fn change(client: &mut Client, command: &str, items: &str) -> TestResult {
    send_change(client, command, items)?;
    assert_result(&client.receive()?);
    Ok(())
}

pub(super) fn checked_error(
    client: &mut Client,
    name: &str,
    owner_block: bool,
) -> TestResult<Element> {
    let reply = client
        .receive()
        .map_err(|error| format!("waiting for the {name} error for 'attempt': {error}"))?;
    reply.assert_name("jabber:client", name);
    assert_eq!(reply.attribute("id"), Some("attempt"), "{reply:?}");
    assert_eq!(reply.attribute("type"), Some("error"), "{reply:?}");
    let error = reply.child("jabber:client", "error")?;
    assert_eq!(error.attribute("type"), Some("cancel"), "{reply:?}");
    let condition = if owner_block {
        "not-acceptable"
    } else {
        "service-unavailable"
    };
    error.child(STANZA_ERROR, condition)?;
    assert_eq!(
        error.child(BLOCKED, "blocked").is_ok(),
        owner_block,
        "{reply:?}"
    );
    Ok(reply)
}

#[test]
fn local_mutual_block_reports_only_own_rule() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let chat =
        "<message type='chat' to='bob@localhost/desk' id='attempt'><body>Hello</body></message>";
    alice.send(chat)?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='attempt'><body>Hello</body></message>")?;
    let mut tablet = suite.connect("bob", PASSWORD, "tablet")?;
    change(&mut alice, "block", "<item jid='BOB@LOCALHOST/desk'/>")?;
    tablet.send("<message type='chat' to='alice@localhost/desk' id='other-resource'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' type='chat' from='bob@localhost/tablet' to='alice@localhost/desk' id='other-resource'/>")?;
    alice.send(chat)?;
    checked_error(&mut alice, "message", true)?;
    change(&mut alice, "unblock", "<item jid='bob@localhost/desk'/>")?;
    tablet.close()?;
    change(&mut alice, "block", BLOCK_BOB)?;
    alice.send(chat)?;
    let blocked = checked_error(&mut alice, "message", true)?;
    assert_eq!(blocked.attribute("from"), Some(BOB));
    assert_eq!(blocked.attribute("to"), Some(ALICE));
    assert_eq!(blocked.child("jabber:client", "body")?.text, "Hello");
    for target in [ALICE, "alice@localhost/missing"] {
        for kind in ["get", "set"] {
            let request = format!(
                "<iq type='{kind}' to='{target}' id='attempt'><query xmlns='urn:test:peer'/></iq>"
            );
            bob.send(&request)?;
            checked_error(&mut bob, "iq", false)?;
        }
    }
    change(&mut alice, "unblock", BLOCK_BOB)?;
    alice.send(chat)?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='attempt'><body>Hello</body></message>")?;
    change(&mut alice, "block", BLOCK_BOB)?;
    change(&mut bob, "block", BLOCK_ALICE)?;
    for target in [ALICE, "alice@localhost/missing"] {
        bob.send(&format!("<message to='{target}' id='attempt'/>"))?;
        checked_error(&mut bob, "message", true)?;
    }
    change(&mut alice, "unblock", BLOCK_BOB)?;
    alice.send(chat)?;
    checked_error(&mut alice, "message", false)?;
    change(&mut bob, "unblock", "")?;
    alice.send(chat)?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='attempt'><body>Hello</body></message>")?;
    alice.close()?;
    bob.close()?;
    suite.stop()
}

#[test]
fn addressed_block_precedes_server_service_and_remote_routing() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'blocking', 'test-service'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    change(
        &mut alice,
        "block",
        "<item jid='localhost/resource'/><item jid='echo.localhost'/><item jid='remote.test'/>",
    )?;
    for target in [
        "localhost/resource",
        "echo.localhost",
        "user@remote.test/desk",
    ] {
        alice.send(&format!(
            "<iq type='get' to='{target}' id='attempt'><query xmlns='urn:test:peer'/></iq>"
        ))?;
        checked_error(&mut alice, "iq", true)?;
        alice.send(&format!(
            "<message to='{target}' id='attempt'><body>hello</body></message>"
        ))?;
        checked_error(&mut alice, "message", true)?;
    }
    alice.close()?;
    suite.stop()
}

#[test]
fn self_block_does_not_isolate_sibling_sessions() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let items =
        "<item jid='alice@localhost'/><item jid='alice@localhost/phone'/><item jid='localhost'/>";
    change(&mut desk, "block", items)?;
    desk.send("<message to='alice@localhost/phone' type='chat' id='sibling'/>")?;
    phone.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/phone' type='chat' id='sibling'/>")?;
    phone.send(
        "<iq type='get' id='self' to='alice@localhost'><blocklist xmlns='urn:xmpp:blocking'/></iq>",
    )?;
    super::expect_list(
        &mut phone,
        "self",
        &format!("<blocklist xmlns='urn:xmpp:blocking'>{items}</blocklist>"),
    )?;
    desk.send("<message to='bob@localhost/desk' id='attempt'/>")?;
    checked_error(&mut desk, "message", true)?;
    barrier(&mut bob)?;
    change(&mut desk, "unblock", "")?;
    let push = phone.receive()?;
    push.assert_name("jabber:client", "iq");
    assert_eq!(push.attribute("type"), Some("set"));
    push.child("urn:xmpp:blocking", "unblock")?;
    phone.close()?;
    desk.close()?;
    bob.close()?;
    suite.stop()
}

#[test]
fn directed_presence_rejects_outbound_and_suppresses_inbound() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'roster', 'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    change(&mut alice, "block", BLOCK_BOB)?;
    alice.send("<presence to='bob@localhost/desk' id='attempt'/>")?;
    checked_error(&mut alice, "presence", true)?;
    change(&mut alice, "unblock", BLOCK_BOB)?;
    bob.send("<presence type='probe' to='alice@localhost/desk' id='no-grant'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='unsubscribed' from='alice@localhost' to='bob@localhost/desk' id='no-grant'/>")?;
    change(&mut alice, "block", BLOCK_BOB)?;
    for (kind, to) in [
        (" type='unavailable'", BOB),
        (" type='probe'", BOB),
        (" type='subscribe'", "bob@localhost"),
        (" type='subscribed'", "bob@localhost"),
        (" type='unsubscribe'", "bob@localhost"),
        (" type='unsubscribed'", "bob@localhost"),
    ] {
        alice.send(&format!("<presence{kind} to='{to}' id='attempt'/>"))?;
        checked_error(&mut alice, "presence", true)?;
        barrier(&mut bob)?;
    }
    for kind in [
        "",
        " type='unavailable'",
        " type='probe'",
        " type='subscribe'",
        " type='subscribed'",
        " type='unsubscribe'",
        " type='unsubscribed'",
    ] {
        bob.send(&format!(
            "<presence{kind} to='alice@localhost' id='incoming'/>"
        ))?;
    }
    barrier(&mut bob)?;
    barrier(&mut alice)?;
    for client in [&mut alice, &mut bob] {
        client.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
        let result = client.receive()?;
        assert_eq!(result.attribute("type"), Some("result"), "{result:?}");
        assert!(
            result
                .child("jabber:iq:roster", "query")?
                .children
                .is_empty()
        );
    }
    alice.close()?;
    bob.close()?;
    suite.stop()
}

#[test]
fn blocked_terminal_stanzas_are_silent_in_both_directions() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    change(&mut alice, "block", BLOCK_BOB)?;
    send_terminal_stanzas(&mut alice, BOB)?;
    barrier(&mut alice)?;
    barrier(&mut bob)?;
    send_terminal_stanzas(&mut bob, ALICE)?;
    barrier(&mut bob)?;
    barrier(&mut alice)?;
    alice.close()?;
    bob.close()?;
    suite.stop()
}

pub(super) fn send_terminal_stanzas(source: &mut Client, destination: &str) -> TestResult {
    source.send(&format!(
        "<iq type='result' to='{destination}' id='result'/>"
    ))?;
    for name in ["message", "iq", "presence"] {
        source.send(&format!("<{name} type='error' to='{destination}' id='terminal'><error type='cancel'><service-unavailable xmlns='{STANZA_ERROR}'/></error></{name}>"))?;
    }
    Ok(())
}

#[test]
fn blocked_traffic_precedes_account_and_message_side_effects() -> TestResult {
    let mut suite = C2sSuite::with_extensions(
        "'blocking', 'offline', 'test-archive', 'test-message-observer', 'carbons'",
    )?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut sibling = suite.connect("alice", PASSWORD, "phone")?;
    sibling.send("<iq type='set' id='carbon'><enable xmlns='urn:xmpp:carbons:2'/></iq>")?;
    assert_eq!(sibling.receive()?.attribute("type"), Some("result"));
    change(&mut alice, "block", BLOCK_BOB)?;
    alice.send(
        "<message type='chat' to='bob@localhost' id='attempt'><body>offline</body></message>",
    )?;
    checked_error(&mut alice, "message", true)?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    alice.send(
        "<message type='chat' to='bob@localhost/desk' id='attempt'><body>online</body></message>",
    )?;
    checked_error(&mut alice, "message", true)?;
    for (name, namespace) in [
        ("entries", "urn:lonewolf:test:archive"),
        ("messages", "urn:lonewolf:test:observer"),
    ] {
        alice.send(&format!(
            "<iq type='get' to='localhost' id='audit'><{name} xmlns='{namespace}'/></iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' from='localhost' to='{ALICE}' type='result' id='audit'><{name} xmlns='{namespace}'/></iq>"))?;
    }
    barrier(&mut sibling)?;
    barrier(&mut bob)?;
    bob.close()?;
    alice.close()?;
    sibling.close()?;
    suite.stop()?;
    let store = RedbStorage::open(suite.fixture_path().join("data/lonewolf.dat"))?;
    let mut arena = Arena::try_new(Default::default())?;
    let account =
        AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;
    Runtime::new()?.block_on(async {
        assert_eq!(store.begin_read().await?.offline_count(&account).await?, 0);
        Ok(())
    })
}

fn expect_bob_items(bob: &mut Client, items: &str) -> TestResult {
    bob.send("<iq type='get' to='alice@localhost' id='items'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    bob.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='items' from='alice@localhost' to='bob@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'>{items}</query></iq>"))
}

#[test]
fn blocked_contact_gets_service_unavailable_from_bare_jid_services() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'roster', 'disco', 'vcard', 'ping', 'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
    alice.send("<iq type='set' id='card'><vCard xmlns='vcard-temp'><FN>Alice</FN></vCard></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='card' to='alice@localhost/desk'/>",
    )?;
    alice.send("<presence id='online'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost' id='online'/>")?;
    barrier(&mut alice)?;
    let requests = [
        "<query xmlns='http://jabber.org/protocol/disco#items'/>",
        "<query xmlns='http://jabber.org/protocol/disco#info'/>",
        "<ping xmlns='urn:xmpp:ping'/>",
        "<vCard xmlns='vcard-temp'/>",
    ];
    for payload in requests {
        bob.send(&format!(
            "<iq type='get' to='alice@localhost' id='allowed'>{payload}</iq>"
        ))?;
        let reply = bob.receive()?;
        reply.assert_name("jabber:client", "iq");
        assert_eq!(reply.attribute("type"), Some("result"), "{reply:?}");
        assert_eq!(reply.attribute("id"), Some("allowed"), "{reply:?}");
    }
    expect_bob_items(&mut bob, "<item jid='alice@localhost/desk'/>")?;

    change(&mut alice, "block", BLOCK_BOB)?;
    for payload in requests {
        bob.send(&format!(
            "<iq type='get' to='alice@localhost' id='attempt'>{payload}</iq>"
        ))?;
        let reply = checked_error(&mut bob, "iq", false)?;
        assert_eq!(
            reply.attribute("from"),
            Some("alice@localhost"),
            "{reply:?}"
        );
    }
    alice
        .send("<iq type='get' to='bob@localhost' id='attempt'><vCard xmlns='vcard-temp'/></iq>")?;
    let reply = checked_error(&mut alice, "iq", true)?;
    assert_eq!(reply.attribute("from"), Some("bob@localhost"), "{reply:?}");
    barrier(&mut bob)?;

    change(&mut alice, "unblock", BLOCK_BOB)?;
    expect_bob_items(&mut bob, "<item jid='alice@localhost/desk'/>")?;
    alice.close()?;
    bob.close()?;
    suite.stop()
}
