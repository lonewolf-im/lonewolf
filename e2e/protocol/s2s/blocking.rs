// SPDX-License-Identifier: Apache-2.0

use super::bidi::authenticated;
use super::negotiation::SingleServer;
use crate::blocking::{change_rule, external};
use crate::support::component::ComponentClient;
use crate::support::federation::peer::RawS2sPeer;
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

    super::roster(&mut alice)?;
    alice.send("<presence type='subscribed' to='bob@b.test'/>")?;
    super::push(&mut alice, BOB, "none", None)?;
    peer.send("<presence type='subscribe' from='bob@b.test' to='alice@a.test'/>")?;
    external::envelope(
        &peer.receive()?,
        SERVER,
        "presence",
        ALICE,
        BOB,
        Some("subscribed"),
    );
    super::push(&mut alice, BOB, "from", None)?;
    alice.send("<presence><status>ready</status></presence>")?;
    super::presence(&mut alice, DESK, ALICE, None)?;
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
    super::push(&mut alice, BOB, "from", Some("subscribe"))?;
    peer.send("<presence type='subscribed' from='bob@b.test' to='alice@a.test'/>")?;
    super::presence(&mut alice, BOB, ALICE, Some("subscribed"))?;
    super::push(&mut alice, BOB, "both", None)?;
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
