// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use super::{available, iq_reply, presence, push, roster, stanza_error};
use crate::support::federation::{FederatedPair, PairOptions, refused_endpoint};
use crate::support::{PASSWORD, TestResult};

fn options() -> PairOptions {
    PairOptions {
        a_bidirectional: None,
        b_bidirectional: None,
        a_extensions: "'roster', 'ping'".into(),
        b_extensions: "'roster', 'ping'".into(),
        ..PairOptions::default()
    }
}

#[test]
fn two_servers_share_one_connection_for_chat_in_both_directions() -> TestResult {
    let mut pair = FederatedPair::start("a.test", "b.test", options())?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat'><body>one shared connection</body></message>",
    )?;
    let message = bob.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(message.attribute("to"), Some("bob@b.test/phone"));
    assert_eq!(
        message.child("jabber:client", "body")?.text,
        "one shared connection"
    );
    bob.send("<message to='alice@a.test/desk' type='chat'><body>shared reply</body></message>")?;
    let message = alice.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("bob@b.test/phone"));
    assert_eq!(message.attribute("to"), Some("alice@a.test/desk"));
    assert_eq!(message.child("jabber:client", "body")?.text, "shared reply");
    for sample in [
        "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"success\"} 1",
        "lonewolf_s2s_bidi_negotiations_total{direction=\"outbound\",outcome=\"enabled\"} 1",
        "lonewolf_s2s_bidi_streams{direction=\"outbound\"} 1",
        "lonewolf_s2s_bidi_stanzas_received_total{kind=\"message\"} 1",
    ] {
        pair.a.wait_for_metric(sample)?;
    }
    for sample in [
        "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"success\"} 1",
        "lonewolf_s2s_bidi_negotiations_total{direction=\"inbound\",outcome=\"enabled\"} 1",
        "lonewolf_s2s_bidi_handoffs_total{target=\"inbound_stream\"} 1",
        "lonewolf_s2s_bidi_stanzas_sent_total{kind=\"message\"} 1",
        "lonewolf_s2s_connections{direction=\"outbound\"} 0",
    ] {
        pair.b.wait_for_metric(sample)?;
    }
    let body = pair.b.scrape_metrics()?;
    assert!(
        !body
            .lines()
            .any(|line| line
                .starts_with("lonewolf_s2s_authentications_total{direction=\"outbound\""))
    );
    assert!(
        !body
            .lines()
            .any(|line| line.starts_with("lonewolf_s2s_dns_resolutions_total{"))
    );
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn subscriptions_presence_and_iqs_use_the_shared_connection() -> TestResult {
    let mut pair = FederatedPair::start("a.test", "b.test", options())?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat'><body>Alice dials first</body></message>",
    )?;
    let message = bob.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(message.attribute("to"), Some("bob@b.test/phone"));
    assert_eq!(
        message.child("jabber:client", "body")?.text,
        "Alice dials first"
    );
    for client in [&mut alice, &mut bob] {
        assert!(
            roster(client)?
                .child("jabber:iq:roster", "query")?
                .children
                .is_empty()
        );
    }
    available(&mut alice, "alice@a.test", "desk")?;
    available(&mut bob, "bob@b.test", "phone")?;
    bob.send("<iq type='set' id='add-alice'><query xmlns='jabber:iq:roster'><item jid='alice@a.test'/></query></iq>")?;
    bob.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='add-alice' to='bob@b.test/phone'/>",
    )?;
    push(&mut bob, "alice@a.test", "none", None)?;
    bob.send("<presence type='subscribe' to='alice@a.test'/>")?;
    push(&mut bob, "alice@a.test", "none", Some("subscribe"))?;
    presence(&mut alice, "bob@b.test", "alice@a.test", Some("subscribe"))?;
    alice.send("<presence type='subscribed' to='bob@b.test'/>")?;
    push(&mut alice, "bob@b.test", "from", None)?;
    presence(&mut bob, "alice@a.test", "bob@b.test", Some("subscribed"))?;
    push(&mut bob, "alice@a.test", "to", None)?;
    presence(&mut bob, "alice@a.test/desk", "bob@b.test", None)?;
    alice.send("<presence type='subscribe' to='bob@b.test'/>")?;
    push(&mut alice, "bob@b.test", "from", Some("subscribe"))?;
    presence(&mut bob, "alice@a.test", "bob@b.test", Some("subscribe"))?;
    bob.send("<presence type='subscribed' to='alice@a.test'/>")?;
    push(&mut bob, "alice@a.test", "both", None)?;
    presence(&mut alice, "bob@b.test", "alice@a.test", Some("subscribed"))?;
    push(&mut alice, "bob@b.test", "both", None)?;
    presence(&mut alice, "bob@b.test/phone", "alice@a.test", None)?;
    for (client, jid) in [(&mut alice, "bob@b.test"), (&mut bob, "alice@a.test")] {
        let reply = roster(client)?;
        let item = reply
            .child("jabber:iq:roster", "query")?
            .child("jabber:iq:roster", "item")?;
        assert_eq!(item.attribute("jid"), Some(jid));
        assert_eq!(item.attribute("subscription"), Some("both"));
        assert_eq!(item.attribute("ask"), None);
    }
    alice.send(
        "<iq type='get' id='ping-bob' to='bob@b.test/phone'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    let request = iq_reply(
        &mut bob,
        "ping-bob",
        "get",
        "alice@a.test/desk",
        "bob@b.test/phone",
    )?;
    request.child("urn:xmpp:ping", "ping")?;
    bob.send("<iq type='result' id='ping-bob' to='alice@a.test/desk'/>")?;
    iq_reply(
        &mut alice,
        "ping-bob",
        "result",
        "bob@b.test/phone",
        "alice@a.test/desk",
    )?;
    bob.send("<iq type='get' id='ping-a' to='a.test'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    iq_reply(&mut bob, "ping-a", "result", "a.test", "bob@b.test/phone")?;
    pair.a
        .wait_for_metric("lonewolf_s2s_connections{direction=\"outbound\"} 1")?;
    pair.b
        .wait_for_metric("lonewolf_s2s_connections{direction=\"outbound\"} 0")?;
    pair.a
        .wait_for_metric("lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 1")?;
    pair.b
        .wait_for_metric("lonewolf_s2s_stanzas_received_total{kind=\"message\"} 1")?;
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
fn either_server_can_keep_one_connection_per_direction() -> TestResult {
    for (a_bidirectional, b_bidirectional, direction, outcome) in [
        (Some(false), None, "inbound", "not_requested"),
        (None, Some(false), "outbound", "not_offered"),
    ] {
        let mut pair = FederatedPair::start(
            "a.test",
            "b.test",
            PairOptions {
                a_bidirectional,
                b_bidirectional,
                ..options()
            },
        )?;
        pair.a.create_account("alice", PASSWORD)?;
        pair.b.create_account("bob", PASSWORD)?;
        let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
        let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
        alice.send(
            "<message to='bob@b.test/phone' type='chat'><body>one direction</body></message>",
        )?;
        let message = bob.receive()?;
        message.assert_name("jabber:client", "message");
        assert_eq!(message.attribute("from"), Some("alice@a.test/desk"));
        assert_eq!(message.attribute("to"), Some("bob@b.test/phone"));
        assert_eq!(
            message.child("jabber:client", "body")?.text,
            "one direction"
        );
        bob.send(
            "<message to='alice@a.test/desk' type='chat'><body>another connection</body></message>",
        )?;
        let message = alice.receive()?;
        message.assert_name("jabber:client", "message");
        assert_eq!(message.attribute("from"), Some("bob@b.test/phone"));
        assert_eq!(message.attribute("to"), Some("alice@a.test/desk"));
        assert_eq!(
            message.child("jabber:client", "body")?.text,
            "another connection"
        );
        let suite = if direction == "inbound" {
            &pair.b
        } else {
            &pair.a
        };
        suite.wait_for_metric(&format!("lonewolf_s2s_bidi_negotiations_total{{direction=\"{direction}\",outcome=\"{outcome}\"}} 1"))?;
        pair.b.wait_for_metric(
            "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"success\"} 1",
        )?;
        for suite in [&pair.a, &pair.b] {
            suite.wait_for_metric("lonewolf_s2s_connections{direction=\"outbound\"} 1")?;
            suite.wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 1")?;
        }
        alice.close()?;
        bob.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn closed_shared_connection_falls_back_to_dialing() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            limits: "idle_timeout_secs = 2".into(),
            ..options()
        },
    )?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat'><body>shared before idle</body></message>",
    )?;
    let message = bob.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(message.attribute("to"), Some("bob@b.test/phone"));
    assert_eq!(
        message.child("jabber:client", "body")?.text,
        "shared before idle"
    );
    bob.send(
        "<message to='alice@a.test/desk' type='chat'><body>reply before idle</body></message>",
    )?;
    let message = alice.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("bob@b.test/phone"));
    assert_eq!(message.attribute("to"), Some("alice@a.test/desk"));
    assert_eq!(
        message.child("jabber:client", "body")?.text,
        "reply before idle"
    );
    pair.a
        .wait_for_metric("lonewolf_s2s_bidi_streams{direction=\"outbound\"} 0")?;
    pair.b
        .wait_for_metric("lonewolf_s2s_bidi_streams{direction=\"inbound\"} 0")?;
    bob.send("<message to='alice@a.test/desk' type='chat'><body>new dial</body></message>")?;
    let message = alice.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("bob@b.test/phone"));
    assert_eq!(message.attribute("to"), Some("alice@a.test/desk"));
    assert_eq!(message.child("jabber:client", "body")?.text, "new dial");
    pair.b.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"success\"} 1",
    )?;
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn stopping_the_dialing_server_releases_the_shared_connection() -> TestResult {
    let mut pair = FederatedPair::start("a.test", "b.test", options())?;
    let refused = refused_endpoint()?;
    pair.dns.srv(
        "a.test",
        &[(0, 0, refused.address().port(), "unavailable.a.test")],
    );
    pair.dns.a("unavailable.a.test", Ipv4Addr::LOCALHOST);
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>before stop</body></message>")?;
    let message = bob.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(message.attribute("to"), Some("bob@b.test/phone"));
    assert_eq!(message.child("jabber:client", "body")?.text, "before stop");
    bob.send("<message to='alice@a.test/desk' type='chat'><body>shared reply</body></message>")?;
    let message = alice.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("bob@b.test/phone"));
    assert_eq!(message.attribute("to"), Some("alice@a.test/desk"));
    assert_eq!(message.child("jabber:client", "body")?.text, "shared reply");
    alice.close()?;
    pair.a.stop()?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_streams_closed_total{direction=\"inbound\",outcome=\"stream_end\"} 1",
    )?;
    pair.b
        .wait_for_metric("lonewolf_s2s_bidi_streams{direction=\"inbound\"} 0")?;
    bob.send("<message to='alice@a.test/desk' type='chat' id='after-stop'><body>fresh dial fails</body></message>")?;
    let error = bob.receive()?;
    error.assert_name("jabber:client", "message");
    assert_eq!(error.attribute("id"), Some("after-stop"));
    assert_eq!(error.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(error.attribute("to"), Some("bob@b.test/phone"));
    stanza_error(&error, "remote-server-timeout")?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"unreachable\"} 1",
    )?;
    bob.close()?;
    pair.b.stop()?;
    drop(refused);
    pair.dns.stop()
}
