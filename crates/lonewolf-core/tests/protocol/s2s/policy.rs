// SPDX-License-Identifier: Apache-2.0

use super::{iq_reply, stanza_error};
use crate::support::federation::{FederatedPair, PairOptions};
use crate::support::{PASSWORD, TestResult};

#[test]
fn messages_follow_inbound_policy_over_federation() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            a_extensions: "'roster'".into(),
            b_extensions: "'roster', 'test-policy'".into(),
            ..PairOptions::default()
        },
    )?;
    for user in ["spammer", "rejecter", "alice"] {
        pair.a.create_account(user, PASSWORD)?;
    }
    pair.b.create_account("bob", PASSWORD)?;
    let mut spammer = pair.a.connect("spammer", PASSWORD, "desk")?;
    let mut rejecter = pair.a.connect("rejecter", PASSWORD, "desk")?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;

    spammer.send("<message type='chat' id='dropped' to='bob@b.test/phone'><body>Drop this</body></message><iq type='get' id='drop-fence' to='b.test'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    stanza_error(
        &iq_reply(
            &mut spammer,
            "drop-fence",
            "error",
            "b.test",
            "spammer@a.test/desk",
        )?,
        "service-unavailable",
    )?;

    rejecter.send("<message type='chat' id='rejected' to='bob@b.test/phone'><body>Reject this</body></message>")?;
    let rejected = rejecter.receive()?;
    rejected.assert_name("jabber:client", "message");
    assert_eq!(rejected.attribute("id"), Some("rejected"));
    assert_eq!(rejected.attribute("type"), Some("error"));
    assert_eq!(rejected.attribute("from"), Some("bob@b.test/phone"));
    assert_eq!(rejected.attribute("to"), Some("rejecter@a.test/desk"));
    stanza_error(&rejected, "service-unavailable")?;

    alice.send("<message type='chat' id='allowed' to='bob@b.test/phone'><body>Deliver this</body></message>")?;
    let delivered = bob.receive()?;
    delivered.assert_name("jabber:client", "message");
    assert_eq!(delivered.attribute("id"), Some("allowed"));
    assert_eq!(delivered.attribute("type"), Some("chat"));
    assert_eq!(delivered.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(delivered.attribute("to"), Some("bob@b.test/phone"));
    assert_eq!(
        delivered.child("jabber:client", "body")?.text,
        "Deliver this"
    );

    spammer.close()?;
    rejecter.close()?;
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn iq_requests_follow_inbound_policy_over_federation() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            a_extensions: "'roster'".into(),
            b_extensions: "'roster', 'test-policy', 'ping'".into(),
            ..PairOptions::default()
        },
    )?;
    for user in ["spammer", "rejecter", "alice"] {
        pair.a.create_account(user, PASSWORD)?;
    }
    pair.b.create_account("bob", PASSWORD)?;
    let mut spammer = pair.a.connect("spammer", PASSWORD, "desk")?;
    let mut rejecter = pair.a.connect("rejecter", PASSWORD, "desk")?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    for (client, from, id) in [
        (&mut spammer, "spammer@a.test/desk", "dropped"),
        (&mut rejecter, "rejecter@a.test/desk", "rejected"),
    ] {
        client.send(&format!(
            "<iq type='get' id='{id}' to='bob@b.test'><ping xmlns='urn:xmpp:ping'/></iq>"
        ))?;
        stanza_error(
            &iq_reply(client, id, "error", "bob@b.test", from)?,
            "service-unavailable",
        )?;
    }
    crate::support::federation::subscribe_mutually(
        &mut alice,
        "alice@a.test",
        &mut bob,
        "bob@b.test",
    )?;
    alice.send("<iq type='get' id='allowed' to='bob@b.test'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    assert!(
        iq_reply(
            &mut alice,
            "allowed",
            "result",
            "bob@b.test",
            "alice@a.test/desk"
        )?
        .children
        .is_empty()
    );
    alice.send("<presence type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='alice@a.test/desk' to='alice@a.test' type='unavailable'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='alice@a.test/desk' to='bob@b.test' type='unavailable' xml:lang='en'/>")?;
    spammer.close()?;
    rejecter.close()?;
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn probes_from_dropped_peers_are_unanswered_over_federation() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            a_extensions: "'roster'".into(),
            b_extensions: "'roster', 'test-policy', 'ping'".into(),
            ..PairOptions::default()
        },
    )?;
    pair.a.create_account("spammer", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut spammer = pair.a.connect("spammer", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    bob.send("<iq type='set' to='b.test' id='policy-off'><toggle xmlns='urn:lonewolf:test:policy' enabled='false'/></iq>")?;
    assert!(
        iq_reply(
            &mut bob,
            "policy-off",
            "result",
            "b.test",
            "bob@b.test/phone"
        )?
        .children
        .is_empty()
    );
    crate::support::federation::subscribe_mutually(
        &mut spammer,
        "spammer@a.test",
        &mut bob,
        "bob@b.test",
    )?;
    spammer.send("<presence type='probe' to='bob@b.test/phone'/>")?;
    super::presence(
        &mut spammer,
        "bob@b.test/phone",
        "spammer@a.test/desk",
        None,
    )?;
    bob.send("<iq type='set' to='b.test' id='policy-on'><toggle xmlns='urn:lonewolf:test:policy' enabled='true'/></iq>")?;
    assert!(
        iq_reply(
            &mut bob,
            "policy-on",
            "result",
            "b.test",
            "bob@b.test/phone"
        )?
        .children
        .is_empty()
    );

    spammer.send("<presence type='probe' to='bob@b.test/phone'/><iq type='get' id='probe-fence' to='b.test'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    assert!(
        iq_reply(
            &mut spammer,
            "probe-fence",
            "result",
            "b.test",
            "spammer@a.test/desk"
        )?
        .children
        .is_empty()
    );

    bob.send("<iq type='set' to='b.test' id='policy-cleanup'><toggle xmlns='urn:lonewolf:test:policy' enabled='false'/></iq>")?;
    assert!(
        iq_reply(
            &mut bob,
            "policy-cleanup",
            "result",
            "b.test",
            "bob@b.test/phone"
        )?
        .children
        .is_empty()
    );
    spammer.send("<presence type='unavailable'/>")?;
    spammer.expect_xml("<presence xmlns='jabber:client' from='spammer@a.test/desk' to='spammer@a.test' type='unavailable'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='spammer@a.test/desk' to='bob@b.test' type='unavailable' xml:lang='en'/>")?;
    spammer.close()?;
    bob.close()?;
    pair.stop()
}
