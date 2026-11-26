// SPDX-License-Identifier: Apache-2.0

use super::addressed::{checked_error, send_terminal_stanzas};
use super::change_rule;
use crate::carbons::{copy, enable};
use crate::offline::{await_empty, receive_stored};
use crate::support::{C2sSuite, Client, PASSWORD, TestResult, barrier};

fn expect_backlog(client: &mut Client, count: &str) -> TestResult {
    client.send("<iq type='get' id='backlog'><query xmlns='urn:lonewolf:test:offline'/></iq>")?;
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("result"));
    assert_eq!(reply.attribute("id"), Some("backlog"));
    assert_eq!(
        reply
            .child("urn:lonewolf:test:offline", "query")?
            .attribute("count"),
        Some(count)
    );
    Ok(())
}

#[test]
fn stanza_matrix() -> TestResult {
    let mut suite = C2sSuite::with_extensions(
        "'blocking', 'carbons', 'offline', 'roster', 'test-offline-inspect'",
    )?;
    for name in ["alice", "bob", "carol"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let mut carol = suite.connect("carol", PASSWORD, "desk")?;
    bob.send("<message to='alice@localhost' type='chat' id='discard'><body>old</body></message>")?;
    barrier(&mut bob)?;
    carol.send(
        "<message to='alice@localhost' type='chat' id='keep'><body>stored</body></message>",
    )?;
    barrier(&mut carol)?;

    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    expect_backlog(&mut alice, "2")?;
    change_rule(&mut alice, "block", "bob@localhost")?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    receive_stored(
        &mut alice,
        "<message xmlns='jabber:client' type='chat' from='carol@localhost/desk' to='alice@localhost' id='keep'><body>stored</body></message>",
    )?;
    await_empty(&mut alice, "alice@localhost/desk")?;

    let mut copy_target = suite.connect("alice", PASSWORD, "phone")?;
    enable(&mut copy_target, "alice@localhost/phone")?;
    bob.send("<message type='chat' id='attempt' to='alice@localhost/desk'><body>blocked</body></message>")?;
    checked_error(&mut bob, "message", false)?;
    for kind in ["get", "set"] {
        bob.send(&format!("<iq type='{kind}' to='alice@localhost/desk' id='attempt'><query xmlns='urn:test:matrix'/></iq>"))?;
        checked_error(&mut bob, "iq", false)?;
    }
    alice.send("<message type='headline' to='bob@localhost/desk' id='attempt'/>")?;
    checked_error(&mut alice, "message", true)?;
    alice.send("<presence to='bob@localhost/desk' id='attempt'/>")?;
    checked_error(&mut alice, "presence", true)?;
    bob.send("<presence type='probe' to='alice@localhost/desk'/><presence type='subscribe' to='alice@localhost'/>")?;
    send_terminal_stanzas(&mut bob, "alice@localhost/desk")?;
    barrier(&mut bob)?;
    send_terminal_stanzas(&mut alice, "bob@localhost/desk")?;
    barrier(&mut alice)?;
    barrier(&mut bob)?;
    barrier(&mut copy_target)?;

    change_rule(&mut bob, "block", "alice@localhost")?;
    bob.send("<message to='alice@localhost/desk' id='attempt'/>")?;
    checked_error(&mut bob, "message", true)?;
    change_rule(&mut bob, "unblock", "")?;
    change_rule(&mut alice, "unblock", "")?;
    expect_backlog(&mut alice, "0")?;
    let fresh = "<message xmlns='jabber:client' type='chat' from='bob@localhost/desk' to='alice@localhost/desk' id='fresh'><body>new</body></message>";
    bob.send(
        "<message type='chat' to='alice@localhost/desk' id='fresh'><body>new</body></message>",
    )?;
    alice.expect_xml(fresh)?;
    copy(
        &mut copy_target,
        "alice@localhost/phone",
        "received",
        " type='chat'",
        fresh,
    )?;
    barrier(&mut alice)?;
    barrier(&mut copy_target)?;

    change_rule(&mut alice, "block", "bob@localhost/desk")?;
    bob.send("<message to='alice@localhost/desk' id='attempt'/>")?;
    checked_error(&mut bob, "message", false)?;
    let mut other = suite.connect("bob", PASSWORD, "phone")?;
    other.send("<message to='alice@localhost/desk' id='sibling'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk' id='sibling'/>")?;
    change_rule(&mut alice, "block", "localhost/phone")?;
    alice.send(
        "<iq type='get' to='localhost/phone' id='attempt'><query xmlns='urn:test:matrix'/></iq>",
    )?;
    checked_error(&mut alice, "iq", true)?;
    other.send("<message to='alice@localhost/desk' id='distinct-entity'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk' id='distinct-entity'/>")?;
    change_rule(&mut alice, "block", "localhost")?;
    other.send("<message to='alice@localhost/desk' id='attempt'/>")?;
    checked_error(&mut other, "message", false)?;
    alice.send("<message to='alice@localhost/phone' id='own-resource'/>")?;
    copy_target.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/phone' id='own-resource'/>")?;
    other.send("<message to='carol@localhost/desk' id='allowed'/>")?;
    carol.expect_xml("<message xmlns='jabber:client' from='bob@localhost/phone' to='carol@localhost/desk' id='allowed'/>")?;
    for mut client in [copy_target, alice, other, carol, bob] {
        client.close()?;
    }
    suite.stop()
}
