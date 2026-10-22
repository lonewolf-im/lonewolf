// SPDX-License-Identifier: Apache-2.0

use crate::support::PASSWORD;

use super::support::{C2sSuite, Client, TestResult};

fn accounts(suite: &C2sSuite) -> TestResult {
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)
}

fn entries(client: &mut Client, full: &str, expected: &str) -> TestResult {
    client.send("<iq type='get' to='localhost' id='entries'><entries xmlns='urn:lonewolf:test:archive'/></iq>")?;
    client.expect_xml(&format!("<iq xmlns='jabber:client' from='localhost' to='{full}' type='result' id='entries'><entries xmlns='urn:lonewolf:test:archive'>{expected}</entries></iq>"))
}

#[test]
fn messages_get_the_recipients_stanza_id() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-archive'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "res")?;
    let mut bob = suite.connect("bob", PASSWORD, "res")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/res' to='bob@localhost'/>",
    )?;
    alice.send(
        "<message type='chat' to='bob@localhost' id='archived'><body>Hello</body></message>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost' type='chat' id='archived'><body>Hello</body><stanza-id xmlns='urn:xmpp:sid:0' id='2' by='bob@localhost'/></message>")?;
    entries(
        &mut alice,
        "alice@localhost/res",
        "<entry owner='alice@localhost' direction='sent' id='1'/><entry owner='bob@localhost' direction='received' id='2'/>",
    )?;
    alice.close()?;
    bob.close()
}

#[test]
fn spoofed_stanza_ids_are_removed() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-archive'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "res")?;
    let mut bob = suite.connect("bob", PASSWORD, "res")?;
    alice.send("<message type='chat' to='bob@localhost/res' id='spoof'><stanza-id xmlns='urn:xmpp:sid:0' by='bob@localhost' id='x'/><stanza-id xmlns='urn:xmpp:sid:0' by='other.example' id='y'/></message>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost/res' type='chat' id='spoof'><stanza-id xmlns='urn:xmpp:sid:0' by='other.example' id='y'/><stanza-id xmlns='urn:xmpp:sid:0' id='2' by='bob@localhost'/></message>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn archive_rejection_stops_the_message() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-archive'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "res")?;
    let mut bob = suite.connect("bob", PASSWORD, "res")?;
    alice.send(
        "<message type='chat' to='bob@localhost/res' id='reject'><body>reject</body></message>",
    )?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost/res' to='alice@localhost/res' type='error' id='reject'><body>reject</body><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot complete this request within its resource limits.</text></error></message>")?;
    entries(&mut alice, "alice@localhost/res", "")?;
    alice.send("<message type='chat' to='bob@localhost/res' id='first'/>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost/res' type='chat' id='first'><stanza-id xmlns='urn:xmpp:sid:0' id='2' by='bob@localhost'/></message>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn messages_within_one_account_are_archived_once() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-archive'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut sender = suite.connect("alice", PASSWORD, "a")?;
    let mut recipient = suite.connect("alice", PASSWORD, "b")?;
    sender.send("<message type='chat' to='alice@localhost/b' id='self'/>")?;
    recipient.expect_xml("<message xmlns='jabber:client' from='alice@localhost/a' to='alice@localhost/b' type='chat' id='self'/>")?;
    entries(
        &mut sender,
        "alice@localhost/a",
        "<entry owner='alice@localhost' direction='sent' id='1'/>",
    )?;
    sender.close()?;
    recipient.close()
}

#[test]
fn offline_messages_keep_their_stanza_id() -> TestResult {
    let suite = C2sSuite::with_extensions("'offline', 'test-archive'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "res")?;
    alice
        .send("<message type='chat' to='bob@localhost' id='stored'><body>Hello</body></message>")?;
    entries(
        &mut alice,
        "alice@localhost/res",
        "<entry owner='alice@localhost' direction='sent' id='1'/><entry owner='bob@localhost' direction='received' id='2'/>",
    )?;
    let mut bob = suite.connect("bob", PASSWORD, "res")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/res' to='bob@localhost'/>",
    )?;
    let mut message = bob.receive()?;
    let delay = message.child("urn:xmpp:delay", "delay")?;
    assert_eq!(delay.attribute("from"), Some("localhost"));
    assert!(delay.attribute("stamp").is_some());
    message
        .children
        .retain(|child| child.namespace != "urn:xmpp:delay" || child.name != "delay");
    message.assert_xml("<message xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost' type='chat' id='stored'><body>Hello</body><stanza-id xmlns='urn:xmpp:sid:0' id='2' by='bob@localhost'/></message>")?;
    entries(
        &mut alice,
        "alice@localhost/res",
        "<entry owner='alice@localhost' direction='sent' id='1'/><entry owner='bob@localhost' direction='received' id='2'/>",
    )?;
    alice.close()?;
    bob.close()
}

#[test]
fn two_archive_handlers_prevent_startup() -> TestResult {
    let error = C2sSuite::with_extensions("'test-archive', 'test-second-archive'")
        .err()
        .ok_or("server started with conflicting archives")?;
    assert!(
        error.to_string().contains("conflicting archive handlers"),
        "{error}"
    );
    Ok(())
}

#[test]
fn without_an_archive_messages_are_unchanged() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", PASSWORD, "res")?;
    let mut bob = suite.connect("bob", PASSWORD, "res")?;
    alice.send("<message type='chat' to='bob@localhost/res' id='spoof'><stanza-id xmlns='urn:xmpp:sid:0' by='bob@localhost' id='x'/><stanza-id xmlns='urn:xmpp:sid:0' by='other.example' id='y'/></message>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost/res' type='chat' id='spoof'><stanza-id xmlns='urn:xmpp:sid:0' by='bob@localhost' id='x'/><stanza-id xmlns='urn:xmpp:sid:0' by='other.example' id='y'/></message>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn messages_to_and_from_services_are_archived() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-archive', 'test-service'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "res")?;
    alice
        .send("<message type='chat' to='echo.localhost' id='echo'><body>Hello</body></message>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='echo.localhost' to='alice@localhost/res' type='chat' id='echo'><body>Hello</body><stanza-id xmlns='urn:xmpp:sid:0' id='2' by='alice@localhost'/></message>")?;
    entries(
        &mut alice,
        "alice@localhost/res",
        "<entry owner='alice@localhost' direction='sent' id='1'/><entry owner='alice@localhost' direction='received' id='2'/>",
    )?;
    alice.close()
}
