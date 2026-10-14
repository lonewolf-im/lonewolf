// SPDX-License-Identifier: Apache-2.0

use super::support::{C2sSuite, Client, TestResult};

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
fn inbound_drop_replies_to_iq_and_discards_messages() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-policy'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("spammer", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "res")?;
    let mut spammer = suite.connect("spammer", "password", "res")?;
    let mut bob = suite.connect("bob", "password", "res")?;

    spammer.send("<message type='chat' to='alice@localhost/res' id='drop'/><iq type='get' to='alice@localhost/res' id='drop-iq'><query xmlns='urn:test:iq'/></iq><iq type='get' id='barrier'><query xmlns='urn:test:barrier'/></iq>")?;
    spammer.expect_xml("<iq xmlns='jabber:client' from='alice@localhost/res' type='error' id='drop-iq'><query xmlns='urn:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    spammer.expect_xml("<iq xmlns='jabber:client' type='error' id='barrier'><query xmlns='urn:test:barrier'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.expect_no_tls_input()?;
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
    alice.expect_xml("<message xmlns='jabber:client' from='broken@localhost' to='alice@localhost/res' type='error' id='failure'><error type='cancel'><internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
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
    toggle(&mut alice, false)?;
    alice.send("<presence to='blocked@localhost/res'/>")?;
    blocked.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='blocked@localhost/res'/>",
    )?;
    toggle(&mut alice, true)?;
    blocked.send(
        "<iq type='get' to='alice@localhost/res' id='answer'><query xmlns='urn:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' from='blocked@localhost/res' to='alice@localhost/res' type='get' id='answer'><query xmlns='urn:test:iq'/></iq>")?;
    alice.send("<iq type='result' to='blocked@localhost/res' id='answer'/><message type='chat' to='bob@localhost/res' id='ready'/>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost/res' type='chat' id='ready'/>")?;
    second.send("<message type='chat' to='blocked@localhost/res' id='first'/>")?;
    blocked.expect_xml("<message xmlns='jabber:client' from='blocked@localhost/second' to='blocked@localhost/res' type='chat' id='first'/>")?;
    toggle(&mut alice, false)?;
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

fn toggle(client: &mut Client, enabled: bool) -> TestResult {
    client.send(&format!("<iq type='set' to='localhost' id='toggle'><toggle xmlns='urn:lonewolf:test:policy' enabled='{enabled}'/></iq>"))?;
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("result"), "{reply:?}");
    assert_eq!(reply.attribute("id"), Some("toggle"), "{reply:?}");
    assert_eq!(reply.attribute("from"), Some("localhost"), "{reply:?}");
    assert!(reply.children.is_empty(), "{reply:?}");
    Ok(())
}

fn barrier(client: &mut Client) -> TestResult {
    client.send("<iq type='get' id='barrier'><query xmlns='urn:test:barrier'/></iq>")?;
    client.expect_xml("<iq xmlns='jabber:client' type='error' id='barrier'><query xmlns='urn:test:barrier'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")
}

fn mutually_subscribe(
    left: &mut Client,
    left_name: &str,
    right: &mut Client,
    right_name: &str,
) -> TestResult {
    left.send(&format!(
        "<presence type='subscribed' to='{right_name}@localhost'/>"
    ))?;
    barrier(left)?;
    right.send(&format!("<presence type='subscribe' to='{left_name}@localhost'/><presence type='subscribed' to='{left_name}@localhost'/>"))?;
    barrier(right)?;
    left.send(&format!(
        "<presence type='subscribe' to='{right_name}@localhost'/>"
    ))?;
    barrier(left)
}

#[test]
fn directed_presence_follows_policy() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-policy'")?;
    for user in ["alice", "blocked", "bob"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "res")?;
    let mut blocked = suite.connect("blocked", "password", "x")?;
    let mut bob = suite.connect("bob", "password", "res")?;

    alice.send("<presence to='blocked@localhost/x'/>")?;
    barrier(&mut alice)?;
    alice.close()?;
    suite.wait_for_log("stream disconnected")?;
    toggle(&mut bob, false)?;
    bob.send("<message type='chat' to='blocked@localhost/x' id='first'/>")?;
    blocked.expect_xml("<message xmlns='jabber:client' from='bob@localhost/res' to='blocked@localhost/x' type='chat' id='first'/>")?;
    blocked.close()?;
    bob.close()
}

#[test]
fn probes_from_dropped_peers_are_unanswered() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-policy'")?;
    for user in ["alice", "spammer", "bob"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "res")?;
    let mut spammer = suite.connect("spammer", "password", "res")?;
    let mut bob = suite.connect("bob", "password", "res")?;
    toggle(&mut alice, false)?;
    mutually_subscribe(&mut alice, "alice", &mut spammer, "spammer")?;
    spammer.send("<presence/>")?;
    spammer.expect_xml(
        "<presence xmlns='jabber:client' from='spammer@localhost/res' to='spammer@localhost'/>",
    )?;
    toggle(&mut alice, true)?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='alice@localhost'/>",
    )?;
    spammer.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='spammer@localhost'/>",
    )?;

    spammer.send("<presence type='probe' to='alice@localhost'/>")?;
    barrier(&mut spammer)?;
    bob.send("<message type='chat' to='spammer@localhost/res' id='first'/>")?;
    spammer.expect_xml("<message xmlns='jabber:client' from='bob@localhost/res' to='spammer@localhost/res' type='chat' id='first'/>")?;
    alice.close()?;
    spammer.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/res' to='spammer@localhost' type='unavailable'/>")?;
    spammer.close()?;
    bob.close()
}

#[test]
fn subscription_requests_from_dropped_peers_are_discarded() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-policy'")?;
    for user in ["alice", "spammer", "bob"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "res")?;
    let mut spammer = suite.connect("spammer", "password", "res")?;
    let mut bob = suite.connect("bob", "password", "res")?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='alice@localhost'/>",
    )?;

    spammer.send("<presence type='subscribe' to='alice@localhost'/>")?;
    barrier(&mut spammer)?;
    bob.send("<message type='chat' to='alice@localhost/res' id='first'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost/res' to='alice@localhost/res' type='chat' id='first'/>")?;
    alice.close()?;
    spammer.close()?;
    bob.close()
}

#[test]
fn broadcasts_skip_members_rejected_by_policy() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-policy'")?;
    for user in ["alice", "bob", "blocked", "spammer"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "res")?;
    let mut bob = suite.connect("bob", "password", "res")?;
    let mut blocked = suite.connect("blocked", "password", "res")?;
    let mut spammer = suite.connect("spammer", "password", "res")?;
    toggle(&mut alice, false)?;
    mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
    mutually_subscribe(&mut alice, "alice", &mut blocked, "blocked")?;
    mutually_subscribe(&mut alice, "alice", &mut spammer, "spammer")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/res' to='bob@localhost'/>",
    )?;
    blocked.send("<presence/>")?;
    blocked.expect_xml(
        "<presence xmlns='jabber:client' from='blocked@localhost/res' to='blocked@localhost'/>",
    )?;
    spammer.send("<presence/>")?;
    spammer.expect_xml(
        "<presence xmlns='jabber:client' from='spammer@localhost/res' to='spammer@localhost'/>",
    )?;
    barrier(&mut spammer)?;
    toggle(&mut alice, true)?;

    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='alice@localhost'/>",
    )?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='blocked@localhost/res' to='alice@localhost'/>",
    )?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/res' to='alice@localhost'/>",
    )?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost'/>",
    )?;
    spammer.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='spammer@localhost'/>",
    )?;
    barrier(&mut alice)?;
    toggle(&mut bob, false)?;
    bob.send("<message type='chat' to='alice@localhost/res' id='first'/><message type='chat' to='blocked@localhost/res' id='first'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost/res' to='alice@localhost/res' type='chat' id='first'/>")?;
    blocked.expect_xml("<message xmlns='jabber:client' from='bob@localhost/res' to='blocked@localhost/res' type='chat' id='first'/>")?;
    toggle(&mut alice, true)?;
    alice.close()?;
    bob.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost' type='unavailable'/>")?;
    spammer.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/res' to='spammer@localhost' type='unavailable'/>")?;
    bob.close()?;
    blocked.close()?;
    spammer.close()
}

#[test]
fn session_end_broadcast_skips_members_rejected_by_policy() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-policy'")?;
    for user in ["alice", "bob", "blocked", "spammer"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "res")?;
    let mut bob = suite.connect("bob", "password", "res")?;
    let mut blocked = suite.connect("blocked", "password", "res")?;
    let mut spammer = suite.connect("spammer", "password", "res")?;
    toggle(&mut alice, false)?;
    mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
    mutually_subscribe(&mut alice, "alice", &mut blocked, "blocked")?;
    mutually_subscribe(&mut alice, "alice", &mut spammer, "spammer")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/res' to='bob@localhost'/>",
    )?;
    blocked.send("<presence/>")?;
    blocked.expect_xml(
        "<presence xmlns='jabber:client' from='blocked@localhost/res' to='blocked@localhost'/>",
    )?;
    spammer.send("<presence/>")?;
    spammer.expect_xml(
        "<presence xmlns='jabber:client' from='spammer@localhost/res' to='spammer@localhost'/>",
    )?;
    barrier(&mut spammer)?;
    toggle(&mut alice, true)?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='alice@localhost'/>",
    )?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='blocked@localhost/res' to='alice@localhost'/>",
    )?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/res' to='alice@localhost'/>",
    )?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost'/>",
    )?;
    spammer.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='spammer@localhost'/>",
    )?;
    barrier(&mut alice)?;

    alice.close()?;
    bob.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/res' to='bob@localhost' type='unavailable'/>")?;
    spammer.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/res' to='spammer@localhost' type='unavailable'/>")?;
    toggle(&mut bob, false)?;
    bob.send("<message type='chat' to='blocked@localhost/res' id='first'/>")?;
    blocked.expect_xml("<message xmlns='jabber:client' from='bob@localhost/res' to='blocked@localhost/res' type='chat' id='first'/>")?;
    bob.close()?;
    blocked.close()?;
    spammer.close()
}

#[test]
fn pending_requests_from_dropped_peers_are_not_replayed() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-policy'")?;
    for user in ["alice", "spammer", "bob"] {
        suite.create_account(user, "password")?;
    }
    let mut spammer = suite.connect("spammer", "password", "res")?;
    let mut bob = suite.connect("bob", "password", "res")?;
    toggle(&mut bob, false)?;
    spammer.send("<presence type='subscribe' to='alice@localhost'/>")?;
    barrier(&mut spammer)?;
    toggle(&mut bob, true)?;
    let mut alice = suite.connect("alice", "password", "res")?;

    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/res' to='alice@localhost'/>",
    )?;
    barrier(&mut alice)?;
    bob.send("<message type='chat' to='alice@localhost/res' id='first'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost/res' to='alice@localhost/res' type='chat' id='first'/>")?;
    alice.close()?;
    spammer.close()?;
    bob.close()
}

#[test]
fn sender_preapproval_uses_outbound_policy_and_skips_prospective_recipient_policy() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-policy'")?;
    for user in ["alice", "spammer", "rejecter"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "res")?;
    for sender in ["spammer", "rejecter"] {
        let mut client = suite.connect(sender, "password", "res")?;
        for target in ["blocked@localhost", "blocked@remote.invalid"] {
            for kind in ["subscribed", "unsubscribed"] {
                client.send(&format!("<presence type='{kind}' to='{target}'/>"))?;
            }
        }
        client.send("<iq type='get' id='denied'><query xmlns='jabber:iq:roster' ver=''/></iq>")?;
        client.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='denied' to='{sender}@localhost/res'><query xmlns='jabber:iq:roster' ver='0'/></iq>"))?;
        client.send("<presence type='subscribed' to='alice@localhost'/>")?;
        let push = client.receive()?;
        push.assert_name("jabber:client", "iq");
        assert_eq!(push.attribute("type"), Some("set"));
        assert_eq!(push.attribute("id"), Some("roster-1"));
        push.child("jabber:iq:roster", "query")?.children[0].assert_xml("<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='none' approved='true'/>")?;
        client.send("<iq type='result' id='roster-1'/><presence type='subscribed' to='alice@localhost'/><iq type='get' id='approved'><query xmlns='jabber:iq:roster' ver='1'/></iq>")?;
        client.expect_xml(&format!(
            "<iq xmlns='jabber:client' type='result' id='approved' to='{sender}@localhost/res'/>"
        ))?;
        client.send("<presence type='subscribe' to='alice@localhost'/>")?;
        barrier(&mut client)?;
        client.send("<presence type='unsubscribed' to='alice@localhost'/>")?;
        let push = client.receive()?;
        assert_eq!(push.attribute("id"), Some("roster-2"));
        push.child("jabber:iq:roster", "query")?.children[0].assert_xml(
            "<item xmlns='jabber:iq:roster' jid='alice@localhost' subscription='none'/>",
        )?;
        client.send("<iq type='result' id='roster-2'/><iq type='get' id='cancelled'><query xmlns='jabber:iq:roster' ver='2'/></iq>")?;
        client.expect_xml(&format!(
            "<iq xmlns='jabber:client' type='result' id='cancelled' to='{sender}@localhost/res'/>"
        ))?;
        client.close()?;
    }
    alice.send("<iq type='get' id='unchanged'><query xmlns='jabber:iq:roster' ver=''/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='unchanged' to='alice@localhost/res'><query xmlns='jabber:iq:roster' ver='0'/></iq>")?;
    alice.close()
}

#[test]
fn pending_approvals_and_denials_still_require_recipient_inbound_policy() -> TestResult {
    for sender in ["spammer", "rejecter"] {
        let suite = C2sSuite::with_extensions("'roster', 'test-policy'")?;
        suite.create_account("alice", "password")?;
        suite.create_account(sender, "password")?;
        let mut alice = suite.connect("alice", "password", "res")?;
        let mut client = suite.connect(sender, "password", "res")?;
        alice.send(&format!("<presence type='subscribe' to='{sender}@localhost'/><iq type='get' id='pending'><query xmlns='jabber:iq:roster' ver=''/></iq>"))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='pending' to='alice@localhost/res'><query xmlns='jabber:iq:roster' ver='1'><item jid='{sender}@localhost' subscription='none' ask='subscribe'/></query></iq>"))?;
        for kind in ["subscribed", "unsubscribed"] {
            client.send(&format!("<presence type='{kind}' to='alice@localhost'/><iq type='get' id='unchanged'><query xmlns='jabber:iq:roster' ver=''/></iq>"))?;
            client.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='unchanged' to='{sender}@localhost/res'><query xmlns='jabber:iq:roster' ver='0'/></iq>"))?;
            alice.send(
                "<iq type='get' id='still-pending'><query xmlns='jabber:iq:roster' ver='1'/></iq>",
            )?;
            alice.expect_xml("<iq xmlns='jabber:client' type='result' id='still-pending' to='alice@localhost/res'/>")?;
        }
        alice.close()?;
        client.close()?;
    }
    Ok(())
}
