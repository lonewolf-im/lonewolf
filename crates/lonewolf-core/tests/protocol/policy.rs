// SPDX-License-Identifier: Apache-2.0

use super::support::{C2sSuite, TestResult};

#[test]
fn outbound_rejection_carries_the_application_condition() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-policy'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("blocked", "password")?;
    let mut alice = suite.connect("alice", "password", "res")?;
    let mut blocked = suite.connect("blocked", "password", "res")?;
    let mut second = suite.connect("blocked", "password", "second")?;
    blocked.send("<presence/>")?;
    blocked.expect_xml(
        "<presence xmlns='jabber:client' from='blocked@localhost/res' to='blocked@localhost'/>",
    )?;

    alice.send(
        "<message type='chat' to='blocked@localhost' id='blocked'><body>Blocked</body></message>",
    )?;
    alice.expect_xml("<message xmlns='jabber:client' from='blocked@localhost' to='alice@localhost/res' type='error' id='blocked'><body>Blocked</body><error type='modify'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><blocked xmlns='urn:lonewolf:test:policy'/></error></message>")?;
    second.send("<message type='chat' to='blocked@localhost/res' id='first'/>")?;
    blocked.expect_xml("<message xmlns='jabber:client' from='blocked@localhost/second' to='blocked@localhost/res' type='chat' id='first'/>")?;
    alice.close()?;
    blocked.close()?;
    second.close()
}

#[test]
fn inbound_drop_discards_without_a_reply() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-policy'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("spammer", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "res")?;
    let mut spammer = suite.connect("spammer", "password", "res")?;
    let mut bob = suite.connect("bob", "password", "res")?;

    spammer.send("<message type='chat' to='alice@localhost/res' id='drop'/><iq type='get' id='barrier'><query xmlns='urn:test:barrier'/></iq>")?;
    spammer.expect_xml("<iq xmlns='jabber:client' type='error' id='barrier'><query xmlns='urn:test:barrier'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    bob.send("<message type='chat' to='alice@localhost/res' id='first'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost/res' to='alice@localhost/res' type='chat' id='first'/>")?;
    alice.close()?;
    spammer.close()?;
    bob.close()
}

#[test]
fn inbound_rejection_answers_the_sender() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-policy'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("rejecter", "password")?;
    let mut alice = suite.connect("alice", "password", "res")?;
    let mut rejecter = suite.connect("rejecter", "password", "res")?;

    rejecter.send("<message type='chat' to='alice@localhost/res' id='reject'/>")?;
    rejecter.expect_xml("<message xmlns='jabber:client' from='alice@localhost/res' to='rejecter@localhost/res' type='error' id='reject'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
    alice.send("<message type='chat' to='alice@localhost/res' id='first'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='alice@localhost/res' to='alice@localhost/res' type='chat' id='first'/>")?;
    alice.close()?;
    rejecter.close()
}

#[test]
fn policy_does_not_apply_within_one_account() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-policy'")?;
    suite.create_account("blocked", "password")?;
    let mut sender = suite.connect("blocked", "password", "a")?;
    let mut recipient = suite.connect("blocked", "password", "b")?;

    sender.send("<message type='chat' to='blocked@localhost/b' id='self'/>")?;
    recipient.expect_xml("<message xmlns='jabber:client' from='blocked@localhost/a' to='blocked@localhost/b' type='chat' id='self'/>")?;
    sender.close()?;
    recipient.close()
}

#[test]
fn failing_policy_rejects_with_its_condition() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-policy'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "res")?;

    alice.send("<message type='chat' to='broken@localhost' id='failure'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='broken@localhost' to='alice@localhost/res' type='error' id='failure'><error type='wait'><internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
    alice.close()
}

#[test]
fn iq_requests_follow_policy_and_rejected_responses_are_dropped() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-policy'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("blocked", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "res")?;
    let mut blocked = suite.connect("blocked", "password", "res")?;
    let mut bob = suite.connect("bob", "password", "res")?;
    let mut second = suite.connect("blocked", "password", "second")?;

    alice.send(
        "<iq type='get' to='blocked@localhost/res' id='reject'><query xmlns='urn:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' from='blocked@localhost/res' type='error' id='reject'><query xmlns='urn:test:iq'/><error type='modify'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><blocked xmlns='urn:lonewolf:test:policy'/></error></iq>")?;
    alice.send("<presence to='blocked@localhost/res'/>")?;
    blocked.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='blocked@localhost/res'/>",
    )?;
    blocked.send(
        "<iq type='get' to='alice@localhost/res' id='answer'><query xmlns='urn:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' from='blocked@localhost/res' to='alice@localhost/res' type='get' id='answer'><query xmlns='urn:test:iq'/></iq>")?;
    alice.send("<iq type='result' to='blocked@localhost/res' id='answer'/><message type='chat' to='bob@localhost/res' id='ready'/>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost/res' type='chat' id='ready'/>")?;
    second.send("<message type='chat' to='blocked@localhost/res' id='first'/>")?;
    blocked.expect_xml("<message xmlns='jabber:client' from='blocked@localhost/second' to='blocked@localhost/res' type='chat' id='first'/>")?;
    alice.send("<presence to='blocked@localhost/res' type='unavailable'/>")?;
    blocked.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/res' to='blocked@localhost/res' type='unavailable'/>")?;
    alice.close()?;
    blocked.close()?;
    second.close()?;
    bob.close()
}

#[test]
fn stanzas_from_services_follow_inbound_policy() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-policy', 'test-service'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "res")?;
    let mut bob = suite.connect("bob", "password", "res")?;

    alice.send("<message type='chat' to='spammer@echo.localhost' id='drop'/><message type='chat' to='bob@localhost/res' id='ready'/>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost/res' type='chat' id='ready'/>")?;
    bob.send("<message type='chat' to='alice@localhost/res' id='first'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost/res' to='alice@localhost/res' type='chat' id='first'/>")?;
    alice.close()?;
    bob.close()
}
