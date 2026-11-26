// SPDX-License-Identifier: Apache-2.0

use crate::support::PASSWORD;

use super::support::{C2sSuite, Client, TestResult};

fn accounts(suite: &C2sSuite) -> TestResult {
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)
}

fn events(client: &mut Client, resource: &str, expected: &str) -> TestResult {
    client.send("<iq type='get' to='localhost' id='events'><messages xmlns='urn:lonewolf:test:observer'/></iq>")?;
    client.expect_xml(&format!("<iq xmlns='jabber:client' from='localhost' to='alice@localhost/{resource}' type='result' id='events'><messages xmlns='urn:lonewolf:test:observer'>{expected}</messages></iq>"))
}

fn available(bob: &mut Client) -> TestResult {
    bob.send("<presence/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/desk' to='bob@localhost'/>")
}

#[test]
fn local_messages_produce_sent_and_received_events() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-message-observer'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    available(&mut bob)?;
    alice.send("<message type='chat' to='bob@localhost'><body>Hello</body></message>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat'><body>Hello</body></message>")?;
    events(
        &mut alice,
        "desk",
        "<event account='alice@localhost' role='sent' outcome='routed'/><event account='bob@localhost' role='received' outcome='routed'/>",
    )?;
    alice.close()?;
    bob.close()
}

#[test]
fn stored_messages_report_stored() -> TestResult {
    let suite = C2sSuite::with_extensions("'offline', 'test-message-observer'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message type='chat' to='bob@localhost'><body>Hello</body></message>")?;
    events(
        &mut alice,
        "desk",
        "<event account='alice@localhost' role='sent' outcome='stored'/><event account='bob@localhost' role='received' outcome='stored'/>",
    )?;
    alice.close()
}

#[test]
fn rejected_messages_produce_only_a_sent_event() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-message-observer'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    alice.send("<message type='normal' to='bob@localhost/absent' id='reject'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost/absent' to='alice@localhost/desk' type='error' id='reject'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></message>")?;
    events(
        &mut alice,
        "desk",
        "<event account='alice@localhost' role='sent' outcome='rejected'/>",
    )?;
    alice.close()?;
    bob.close()
}

#[test]
fn messages_stopped_by_policy_produce_no_events() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-policy', 'test-message-observer'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message type='chat' to='blocked@localhost' id='blocked'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='blocked@localhost' to='alice@localhost/desk' type='error' id='blocked'><error type='modify'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>A request value exceeds an allowed limit or has an unsupported format.</text><blocked xmlns='urn:lonewolf:test:policy'/></error></message>")?;
    events(&mut alice, "desk", "")?;
    alice.close()
}

#[test]
fn archive_ids_reach_observers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-archive', 'test-message-observer'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    available(&mut bob)?;
    alice.send("<message type='chat' to='bob@localhost'><body>Hello</body></message>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat'><body>Hello</body><stanza-id xmlns='urn:xmpp:sid:0' id='2' by='bob@localhost'/></message>")?;
    events(
        &mut alice,
        "desk",
        "<event account='alice@localhost' role='sent' outcome='routed' archived='1'/><event account='bob@localhost' role='received' outcome='routed' archived='2'/>",
    )?;
    alice.close()?;
    bob.close()
}

#[test]
fn observer_deliveries_are_not_observed() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-message-observer'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "a")?;
    let mut sibling = suite.connect("alice", PASSWORD, "b")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    sibling.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    sibling.expect_xml("<iq xmlns='jabber:client' to='alice@localhost/b' type='result' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    available(&mut bob)?;
    alice.send("<message type='chat' to='bob@localhost'><body>copy</body></message>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/a' to='bob@localhost' type='chat'><body>copy</body></message>")?;
    sibling.expect_xml("<message xmlns='jabber:client' from='localhost' to='alice@localhost/b' type='headline'><copied xmlns='urn:lonewolf:test:observer'/></message>")?;
    events(
        &mut alice,
        "a",
        "<event account='alice@localhost' role='sent' outcome='routed'/><event account='bob@localhost' role='received' outcome='routed'/>",
    )?;
    alice.close()?;
    sibling.close()?;
    bob.close()
}

#[test]
fn service_messages_are_observed_on_both_sides() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-service', 'test-message-observer'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message type='chat' to='room@echo.localhost'><body>Hello</body></message>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='room@echo.localhost' to='alice@localhost/desk' type='chat'><body>Hello</body></message>")?;
    events(
        &mut alice,
        "desk",
        "<event account='alice@localhost' role='received' outcome='routed'/><event account='alice@localhost' role='sent' outcome='forwarded'/>",
    )?;
    alice.close()
}
