// SPDX-License-Identifier: Apache-2.0

use crate::blocking::{change_rule, external};
use crate::support::component::ComponentClient;
use crate::support::federation::peer::RawS2sPeer;
use crate::support::federation::single::{SingleServer, authenticated};
use crate::support::federation::workflow::{
    available, iq_reply, presence, push, roster, traffic, workflow_options,
};
use crate::support::federation::{FederatedPair, subscribe_mutually};
use crate::support::{PASSWORD, TestResult, barrier};

const ALICE: &str = "alice@a.test";
const DESK: &str = "alice@a.test/desk";
const BOB: &str = "bob@b.test";
const PHONE: &str = "bob@b.test/phone";
const SERVER: &str = "jabber:server";

fn peer_barrier(peer: &mut RawS2sPeer) -> TestResult {
    peer.send(
        "<iq from='b.test' to='a.test' type='get' id='boundary'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    peer.receive()?.assert_xml(
        "<iq xmlns='jabber:server' from='a.test' to='b.test' type='result' id='boundary'/>",
    )
}

fn snapshot(peer: &mut RawS2sPeer, kind: Option<&str>, status: Option<&str>) -> TestResult {
    let stanza = peer.receive()?;
    external::envelope(&stanza, SERVER, "presence", DESK, BOB, kind);
    assert_eq!(
        stanza.children.len(),
        usize::from(status.is_some()),
        "{stanza:?}"
    );
    if let Some(status) = status {
        assert_eq!(stanza.child(SERVER, "status")?.text, status);
    }
    Ok(())
}

#[test]
fn matrix_and_presence_transition() -> TestResult {
    let mut fixture =
        SingleServer::start_bidirectional_with_extensions("", "'blocking','roster','ping'")?;
    let mut peer = authenticated(&fixture)?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    change_rule(&mut alice, "block", "private.example")?;
    external::foreign_commands(&mut peer, PHONE, ALICE, "missing@a.test")?;

    roster(&mut alice)?;
    alice.send("<presence type='subscribed' to='bob@b.test'/>")?;
    push(&mut alice, BOB, "none", None)?;
    peer.send("<presence type='subscribe' from='bob@b.test' to='alice@a.test'/>")?;
    external::envelope(
        &peer.receive()?,
        SERVER,
        "presence",
        ALICE,
        BOB,
        Some("subscribed"),
    );
    push(&mut alice, BOB, "from", None)?;
    alice.send("<presence><status>ready</status></presence>")?;
    presence(&mut alice, DESK, ALICE, None)?;
    snapshot(&mut peer, None, Some("ready"))?;
    external::chats(&mut alice, &mut peer, DESK, PHONE, true)?;

    change_rule(&mut alice, "block", BOB)?;
    snapshot(&mut peer, Some("unavailable"), None)?;
    external::blocked_matrix(&mut alice, &mut peer, DESK, PHONE)?;
    external::chats(&mut alice, &mut peer, DESK, "carol@b.test/phone", true)?;
    peer_barrier(&mut peer)?;
    barrier(&mut alice)?;

    change_rule(&mut alice, "unblock", BOB)?;
    snapshot(&mut peer, None, Some("ready"))?;
    external::restored_traffic(&mut alice, &mut peer, DESK, PHONE)?;

    alice.send("<presence type='subscribe' to='bob@b.test'/>")?;
    external::envelope(
        &peer.receive()?,
        SERVER,
        "presence",
        ALICE,
        BOB,
        Some("subscribe"),
    );
    push(&mut alice, BOB, "from", Some("subscribe"))?;
    peer.send("<presence type='subscribed' from='bob@b.test' to='alice@a.test'/>")?;
    presence(&mut alice, BOB, ALICE, Some("subscribed"))?;
    push(&mut alice, BOB, "both", None)?;
    external::verify_owner_list(&mut alice)?;
    peer_barrier(&mut peer)?;
    peer.close()?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn federated_bare_address_keeps_exact_wire_semantics() -> TestResult {
    let components = "[[components.listeners]]\naddress='127.0.0.1:0'\n[components.domains.'rooms.a.test']\nsecret='component-test-secret-0001'";
    let mut fixture =
        SingleServer::start_bidirectional_with_extensions(components, "'blocking','ping'")?;
    let mut peer = authenticated(&fixture)?;
    let mut component = ComponentClient::authenticated(
        &fixture.suite,
        "rooms.a.test",
        "component-test-secret-0001",
    )?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;

    change_rule(&mut alice, "block", PHONE)?;
    external::chats(&mut alice, &mut peer, DESK, BOB, true)?;
    external::chats(&mut alice, &mut peer, DESK, "bob@b.test/tablet", true)?;
    external::chats(&mut alice, &mut peer, DESK, PHONE, false)?;
    change_rule(&mut alice, "unblock", PHONE)?;
    change_rule(&mut alice, "block", "b.test/phone")?;
    external::chats(&mut alice, &mut peer, DESK, "b.test/phone", false)?;
    external::chats(&mut alice, &mut peer, DESK, PHONE, true)?;
    external::chats(&mut alice, &mut peer, DESK, "b.test", true)?;

    change_rule(&mut alice, "block", "b.test")?;
    for address in ["b.test", BOB, PHONE, "bob@b.test/tablet"] {
        external::chats(&mut alice, &mut peer, DESK, address, false)?;
    }
    let room = "room@rooms.a.test/desk";
    external::chats(&mut alice, &mut component, DESK, room, true)?;
    change_rule(&mut alice, "block", room)?;
    external::chats(&mut alice, &mut component, DESK, room, false)?;
    change_rule(&mut alice, "unblock", "")?;
    external::chats(&mut alice, &mut component, DESK, room, true)?;
    external::chats(&mut alice, &mut peer, DESK, BOB, true)?;
    peer_barrier(&mut peer)?;
    component.close()?;
    peer.close()?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn resource_rule_for_remote_account_preserves_bare_federated_address() -> TestResult {
    let mut options = workflow_options();
    options.a_extensions.push_str(", 'blocking'");
    let mut pair = FederatedPair::start("a.test", "b.test", options)?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    available(&mut bob, "bob@b.test", "phone")?;
    alice.send("<iq type='set' id='set'><block xmlns='urn:xmpp:blocking'><item jid='bob@b.test/tablet'/></block></iq>")?;
    let set = alice.receive()?;
    set.assert_name("jabber:client", "iq");
    assert_eq!(set.attribute("id"), Some("set"));
    assert_eq!(set.attribute("type"), Some("result"));
    alice.send("<message type='chat' to='bob@b.test' id='bare'/>")?;
    let message = bob.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(message.attribute("to"), Some("bob@b.test"));
    assert_eq!(message.attribute("id"), Some("bare"));
    assert_eq!(message.attribute("type"), Some("chat"));
    traffic(
        &pair,
        "resource_rule_for_remote_account_preserves_bare_federated_address",
        [1, 0, 0],
        [0, 0, 0],
    )?;
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn generated_federated_presence_retains_its_full_source_and_bare_wire_recipient() -> TestResult {
    let mut options = workflow_options();
    options.a_extensions.push_str(", 'blocking'");
    let mut pair = FederatedPair::start("a.test", "b.test", options)?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send("<iq type='set' id='rule'><block xmlns='urn:xmpp:blocking'><item jid='bob@b.test/tablet'/></block></iq>")?;
    let reply = alice.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("id"), Some("rule"));
    assert_eq!(reply.attribute("type"), Some("result"));
    subscribe_mutually(&mut alice, "alice@a.test", &mut bob, "bob@b.test")?;

    alice.send("<presence id='update'><show>away</show></presence>")?;
    presence(&mut alice, "alice@a.test/desk", "alice@a.test", None)?;
    let update = presence(&mut bob, "alice@a.test/desk", "bob@b.test", None)?;
    assert_eq!(update.attribute("id"), Some("update"));
    assert_eq!(update.child("jabber:client", "show")?.text, "away");
    alice.close()?;
    presence(
        &mut bob,
        "alice@a.test/desk",
        "bob@b.test",
        Some("unavailable"),
    )?;
    bob.close()?;
    pair.stop()
}

#[test]
fn federated_subscriber_receives_committed_block_presence_transitions() -> TestResult {
    let mut options = workflow_options();
    options.a_extensions.push_str(", 'blocking'");
    let mut pair = FederatedPair::start("a.test", "b.test", options)?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    subscribe_mutually(&mut alice, "alice@a.test", &mut bob, "bob@b.test")?;
    alice.send("<presence><status>current</status></presence>")?;
    presence(&mut alice, "alice@a.test/desk", "alice@a.test", None)?;
    presence(&mut bob, "alice@a.test/desk", "bob@b.test", None)?;

    for (command, recipient, kind) in [
        ("block", "bob@b.test/phone", Some("unavailable")),
        ("unblock", "bob@b.test/phone", None),
        ("block", "bob@b.test", Some("unavailable")),
        ("unblock", "bob@b.test", None),
    ] {
        crate::blocking::change_rule(&mut alice, command, recipient)?;
        alice.send("<iq type='get' id='remote' to='b.test'><ping xmlns='urn:xmpp:ping'/></iq>")?;
        iq_reply(
            &mut alice,
            "remote",
            "result",
            "b.test",
            "alice@a.test/desk",
        )?;
        bob.send("<iq type='get' id='local' to='b.test'><ping xmlns='urn:xmpp:ping'/></iq>")?;
        let update = presence(&mut bob, "alice@a.test/desk", recipient, kind)?;
        if kind.is_none() {
            assert_eq!(update.child("jabber:client", "status")?.text, "current");
        } else {
            assert!(update.child("jabber:client", "status").is_err());
        }
        iq_reply(&mut bob, "local", "result", "b.test", "bob@b.test/phone")?;
    }
    alice.close()?;
    presence(
        &mut bob,
        "alice@a.test/desk",
        "bob@b.test",
        Some("unavailable"),
    )?;
    bob.close()?;
    pair.stop()
}
