// SPDX-License-Identifier: Apache-2.0

use crate::support::{C2sSuite, Client, TestResult};

fn barrier(client: &mut Client, full: &str) -> TestResult {
    client.send(&format!(
        "<message to='{full}' type='chat' id='PRIVATE-BARRIER'/>"
    ))?;
    client.expect_xml(&format!("<message xmlns='jabber:client' from='{full}' to='{full}' type='chat' id='PRIVATE-BARRIER'/>"))
}

fn assert_private_metadata(logs: &str) {
    for line in logs.lines().filter(|line| {
        line.contains("roster operation committed")
            || line.contains("roster response prepared")
            || line.contains("initial presence prepared")
            || line.contains("offline ")
            || line.contains("pending subscriptions flushed")
    }) {
        for private in [
            "alice@",
            "bob@",
            "ghost@",
            "PRIVATE-",
            "pencil",
            "secret",
            "version=",
            "sequence=",
            "through=",
            "<message",
            "<presence",
            "<iq",
        ] {
            assert!(!line.contains(private), "private metadata in {line}");
        }
        assert!(line.contains("INFO"), "unexpected level in {line}");
    }
}

#[test]
fn roster_main_operations_emit_finite_private_info_summaries() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "secret")?;
    let mut alice = suite.connect("alice", "pencil", "PRIVATE-DESK")?;
    let mut bob = suite.connect("bob", "secret", "PRIVATE-PHONE")?;

    alice.send("<iq type='set' id='PRIVATE-UPSERT'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' name='PRIVATE-NAME'><group>PRIVATE-GROUP</group></item></query></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='PRIVATE-UPSERT' to='alice@localhost/PRIVATE-DESK'/>")?;
    for _ in 0..2 {
        bob.send("<presence type='subscribed' to='alice@localhost' id='PRIVATE-PRE-APPROVAL'/>")?;
        barrier(&mut bob, "bob@localhost/PRIVATE-PHONE")?;
    }
    for _ in 0..2 {
        alice.send("<presence type='subscribe' to='bob@localhost' id='PRIVATE-REQUEST'/>")?;
        barrier(&mut alice, "alice@localhost/PRIVATE-DESK")?;
    }
    for _ in 0..2 {
        alice.send("<presence type='unsubscribe' to='bob@localhost' id='PRIVATE-WITHDRAWAL'/>")?;
        barrier(&mut alice, "alice@localhost/PRIVATE-DESK")?;
    }
    alice.send("<presence type='subscribe' to='bob@localhost' id='PRIVATE-PENDING'/>")?;
    barrier(&mut alice, "alice@localhost/PRIVATE-DESK")?;
    bob.send("<presence type='subscribed' to='alice@localhost' id='PRIVATE-APPROVAL'/>")?;
    barrier(&mut bob, "bob@localhost/PRIVATE-PHONE")?;
    for _ in 0..2 {
        bob.send("<presence type='unsubscribed' to='alice@localhost' id='PRIVATE-CANCELLATION'/>")?;
        barrier(&mut bob, "bob@localhost/PRIVATE-PHONE")?;
    }
    bob.send("<presence type='subscribed' to='ghost@localhost' id='PRIVATE-MISSING'/>")?;
    barrier(&mut bob, "bob@localhost/PRIVATE-PHONE")?;

    alice.send("<iq type='get' id='PRIVATE-GET'><query xmlns='jabber:iq:roster' ver=''/></iq>")?;
    let reply = alice.receive()?;
    assert_eq!(reply.attribute("type"), Some("result"));
    let query = reply.child("jabber:iq:roster", "query")?;
    assert_eq!(query.children.len(), 1);
    assert_eq!(query.children[0].attribute("subscription"), Some("none"));
    assert_eq!(query.children[0].attribute("name"), Some("PRIVATE-NAME"));
    let version = query.attribute("ver").ok_or("missing roster version")?;
    alice.send(&format!(
        "<iq type='get' id='PRIVATE-CACHED'><query xmlns='jabber:iq:roster' ver='{version}'/></iq>"
    ))?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='PRIVATE-CACHED' to='alice@localhost/PRIVATE-DESK'/>")?;
    for _ in 0..2 {
        alice.send("<presence><status>PRIVATE-PRESENCE</status></presence>")?;
        alice.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/PRIVATE-DESK' to='alice@localhost'><status>PRIVATE-PRESENCE</status></presence>")?;
    }
    alice.send("<iq type='set' id='PRIVATE-REMOVE'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' subscription='remove'/></query></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='PRIVATE-REMOVE' to='alice@localhost/PRIVATE-DESK'/>")?;
    let removal = alice.receive()?;
    assert_eq!(
        removal.child("jabber:iq:roster", "query")?.children[0].attribute("subscription"),
        Some("remove")
    );
    suite.delete_account("bob")?;
    bob.expect_stream_error("not-authorized")?;

    let logs = suite.wait_for_log("operation=\"cleanup\" outcome=\"committed\"")?;
    for pair in [
        "operation=\"upsert\" outcome=\"upserted\"",
        "operation=\"remove\" outcome=\"removed\"",
        "operation=\"subscribe\" outcome=\"pending\"",
        "operation=\"subscribe\" outcome=\"pre_approved\"",
        "operation=\"subscribe\" outcome=\"no_change\"",
        "operation=\"approve\" outcome=\"approved\"",
        "operation=\"approve\" outcome=\"pre_approved\"",
        "operation=\"approve\" outcome=\"no_change\"",
        "operation=\"cancel\" outcome=\"cancelled\"",
        "operation=\"cancel\" outcome=\"no_change\"",
        "operation=\"unsubscribe\" outcome=\"withdrawn\"",
        "operation=\"unsubscribe\" outcome=\"no_change\"",
        "operation=\"get\" outcome=\"full\" item_count=1",
        "operation=\"get\" outcome=\"unchanged\" item_count=0",
    ] {
        assert!(logs.contains(pair), "missing {pair}: {logs}");
    }
    assert_eq!(logs.matches("initial presence prepared").count(), 1);
    assert_eq!(
        logs.matches("roster operation committed operation=\"cleanup\"")
            .count(),
        1
    );
    assert_private_metadata(&logs);
    alice.close()
}

#[test]
fn offline_policy_commit_replay_and_cleanup_emit_private_info_summaries() -> TestResult {
    let suite = C2sSuite::with_hosts(
        "[hosts.localhost]\nextensions = ['offline']\n[hosts.localhost.offline]\nmax_messages_per_account = 1",
    )?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "secret")?;
    let mut alice = suite.connect("alice", "pencil", "PRIVATE-DESK")?;
    alice.send("<message to='bob@localhost' type='chat' id='PRIVATE-STATE'><active xmlns='http://jabber.org/protocol/chatstates'/></message>")?;
    barrier(&mut alice, "alice@localhost/PRIVATE-DESK")?;
    alice.send("<message to='bob@localhost' type='chat' id='PRIVATE-STORED'><body>PRIVATE-BODY</body></message>")?;
    barrier(&mut alice, "alice@localhost/PRIVATE-DESK")?;
    alice.send("<message to='bob@localhost' type='chat' id='PRIVATE-QUOTA'/>")?;
    let quota = alice.receive()?;
    assert_eq!(quota.attribute("type"), Some("error"));
    quota
        .child("jabber:client", "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", "resource-constraint")?;
    alice.send("<message to='ghost@localhost' type='chat' id='PRIVATE-GHOST'/>")?;
    let missing = alice.receive()?;
    missing
        .child("jabber:client", "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;

    let mut bob = suite.connect("bob", "secret", "PRIVATE-PHONE")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/PRIVATE-PHONE' to='bob@localhost'/>",
    )?;
    let stored = bob.receive()?;
    assert_eq!(stored.attribute("id"), Some("PRIVATE-STORED"));
    assert_eq!(stored.child("jabber:client", "body")?.text, "PRIVATE-BODY");
    stored.child("urn:xmpp:delay", "delay")?;
    barrier(&mut bob, "bob@localhost/PRIVATE-PHONE")?;
    suite.wait_for_log("operation=\"acknowledge_replay\" outcome=\"committed\"")?;
    bob.close()?;
    let mut bob = suite.connect("bob", "secret", "PRIVATE-TABLET")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/PRIVATE-TABLET' to='bob@localhost'/>",
    )?;
    barrier(&mut bob, "bob@localhost/PRIVATE-TABLET")?;
    suite.delete_account("bob")?;
    bob.expect_stream_error("not-authorized")?;
    let logs = suite.wait_for_log("offline account state cleared")?;
    for fields in [
        "operation=\"store\" outcome=\"discarded\" reason=\"chat_state_only\"",
        "operation=\"store\" outcome=\"rejected\" reason=\"quota_exceeded\" message_count=1 limit=1",
        "operation=\"store\" outcome=\"rejected\" reason=\"no_account\"",
        "operation=\"store\" outcome=\"stored\" bytes=",
        "operation=\"reroute\" outcome=\"retained\" reason=\"offline\"",
        "operation=\"backlog\" outcome=\"available\" message_count=1",
        "operation=\"backlog\" outcome=\"empty\" message_count=0",
        "operation=\"replay\" outcome=\"flushed\" messages_written=1 messages_skipped=0",
        "operation=\"acknowledge_replay\" outcome=\"committed\"",
        "operation=\"cleanup\" outcome=\"committed\"",
    ] {
        assert!(logs.contains(fields), "missing {fields}: {logs}");
    }
    assert_eq!(logs.matches("offline replay flushed").count(), 1);
    assert_eq!(logs.matches("offline message policy decided").count(), 3);
    assert_private_metadata(&logs);
    alice.close()
}

#[test]
fn deleting_an_account_reports_offline_cleanup_with_the_extension_disabled() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("bob", "secret")?;
    let mut bob = suite.connect("bob", "secret", "PRIVATE-PHONE")?;
    suite.delete_account("bob")?;
    bob.expect_stream_error("not-authorized")?;
    let logs = suite.wait_for_log("offline account state cleared")?;
    assert_eq!(logs.matches("offline account state cleared").count(), 1);
    assert!(logs.contains("operation=\"cleanup\" outcome=\"committed\""));
    assert_private_metadata(&logs);
    Ok(())
}
