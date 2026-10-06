// SPDX-License-Identifier: Apache-2.0

use super::support::{C2sSuite, Client, TestResult};

fn sentinel(from: &mut Client, to: &mut Client, target: &str) -> TestResult {
    from.send(&format!("<message to='{target}' id='sentinel'/>"))?;
    let message = to.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("id"), Some("sentinel"), "{message:?}");
    Ok(())
}

#[test]
fn presence_errors_reach_exact_and_available_resources_without_replies() -> TestResult {
    let suite = C2sSuite::start()?;
    for user in ["alice", "bob", "offline"] {
        suite.create_account(user, "password")?;
    }
    let mut desk = suite.connect("alice", "password", "desk")?;
    let mut phone = suite.connect("alice", "password", "phone")?;
    let mut tablet = suite.connect("alice", "password", "tablet")?;
    let mut bob = suite.connect("bob", "password", "desk")?;

    bob.send("<presence type='error' from='mallory@localhost/forged' to='alice@localhost/desk' id='full' xml:lang='fr'><status>bonjour</status><x xmlns='urn:test'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='fr'>indisponible</text></error></presence>")?;
    desk.expect_xml("<presence xmlns='jabber:client' type='error' from='bob@localhost/desk' to='alice@localhost/desk' id='full' xml:lang='fr'><status>bonjour</status><x xmlns='urn:test'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='fr'>indisponible</text></error></presence>")?;
    sentinel(&mut bob, &mut phone, "alice@localhost/phone")?;
    phone.send("<presence id='phone'><priority>-1</priority></presence>")?;
    assert_eq!(phone.receive()?.attribute("id"), Some("phone"));
    tablet.send("<presence id='tablet'/>")?;
    assert_eq!(tablet.receive()?.attribute("id"), Some("phone"));
    assert_eq!(tablet.receive()?.attribute("id"), Some("tablet"));
    assert_eq!(phone.receive()?.attribute("id"), Some("tablet"));

    bob.send("<presence type='error' to='alice@localhost' id='bare'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")?;
    for resource in [&mut phone, &mut tablet] {
        resource.expect_xml("<presence xmlns='jabber:client' type='error' from='bob@localhost/desk' to='alice@localhost' id='bare'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")?;
    }
    sentinel(&mut bob, &mut desk, "alice@localhost/desk")?;
    for target in [
        "offline@localhost",
        "offline@localhost/desk",
        "unknown@localhost",
        "alice@localhost/missing",
        "alice@remote.example/desk",
        "bob@localhost",
        "localhost",
    ] {
        bob.send(&format!("<presence type='error' to='{target}'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>"))?;
    }
    bob.send("<presence type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")?;
    sentinel(&mut bob, &mut desk, "alice@localhost/desk")?;
    sentinel(&mut desk, &mut bob, "bob@localhost/desk")?;
    desk.close()?;
    phone.close()?;
    assert_eq!(tablet.receive()?.attribute("type"), Some("unavailable"));
    tablet.close()?;
    bob.close()
}

#[test]
fn presence_errors_keep_roster_state_cached_presence_and_later_broadcasts() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    let mut carol = suite.connect("carol", "password", "desk")?;
    bob.send("<presence id='bob'/>")?;
    assert_eq!(bob.receive()?.attribute("id"), Some("bob"));
    alice.send("<presence id='original'><show>away</show><priority>5</priority></presence>")?;
    assert_eq!(alice.receive()?.attribute("id"), Some("original"));
    bob.send("<presence to='alice@localhost' type='subscribe'/>")?;
    assert_eq!(alice.receive()?.attribute("type"), Some("subscribe"));
    alice.send("<presence to='bob@localhost' type='subscribed'/>")?;
    assert_eq!(bob.receive()?.attribute("id"), Some("original"));
    alice.send("<presence to='carol@localhost' type='subscribed'/>")?;
    alice.send("<presence to='carol@localhost' type='subscribe'/>")?;
    alice.send("<presence to='carol@localhost/desk' id='directed'/>")?;
    assert_eq!(carol.receive()?.attribute("id"), Some("directed"));
    alice.send("<iq type='get' id='before'><query xmlns='jabber:iq:roster' ver=''/></iq>")?;
    let before = alice.receive()?;
    let before = before.child("jabber:iq:roster", "query")?;
    assert!(
        before
            .children
            .iter()
            .any(|item| item.attribute("subscription") == Some("from"))
    );
    assert!(
        before
            .children
            .iter()
            .any(|item| item.attribute("approved") == Some("true")
                && item.attribute("ask") == Some("subscribe"))
    );
    let version = before.attribute("ver").ok_or("missing version")?.to_owned();

    bob.send("<presence type='error' to='alice@localhost/desk' id='full'><priority>-128</priority><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")?;
    assert_eq!(alice.receive()?.attribute("id"), Some("full"));
    carol.send("<presence type='error' to='alice@localhost' id='bare'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")?;
    assert_eq!(alice.receive()?.attribute("id"), Some("bare"));
    bob.send("<presence type='probe' to='alice@localhost' id='cached'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' id='original'><show>away</show><priority>5</priority></presence>")?;
    carol.send("<presence type='probe' to='alice@localhost/desk' id='grant'/>")?;
    carol.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='carol@localhost/desk' id='grant'/>")?;
    alice.send("<iq type='get' id='after'><query xmlns='jabber:iq:roster' ver=''/></iq>")?;
    let after = alice.receive()?;
    let after = after.child("jabber:iq:roster", "query")?;
    assert_eq!(after.attribute("ver"), Some(version.as_str()));
    assert_eq!(after.children, before.children);
    alice.send("<presence id='updated'><show>chat</show></presence>")?;
    assert_eq!(alice.receive()?.attribute("id"), Some("updated"));
    bob.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' id='updated'><show>chat</show></presence>")?;
    sentinel(&mut alice, &mut carol, "carol@localhost/desk")?;
    alice.close()?;
    assert_eq!(bob.receive()?.attribute("type"), Some("unavailable"));
    assert_eq!(carol.receive()?.attribute("type"), Some("unavailable"));
    bob.close()?;
    carol.close()
}

#[test]
fn directed_presence_reaches_a_full_and_a_bare_jid_and_broadcasts_skip_them() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    let mut carol = suite.connect("carol", "password", "desk")?;
    carol.send("<presence/>")?;
    carol.expect_xml(
        "<presence xmlns='jabber:client' from='carol@localhost/desk' to='carol@localhost'/>",
    )?;

    alice.send("<presence to='bob@localhost/desk' id='to-bob'><show>chat</show></presence>")?;
    bob.expect_xml("<presence xmlns='jabber:client' id='to-bob' from='alice@localhost/desk' to='bob@localhost/desk'><show>chat</show></presence>")?;
    alice.send("<presence to='carol@localhost' id='to-carol'/>")?;
    carol.expect_xml("<presence xmlns='jabber:client' id='to-carol' from='alice@localhost/desk' to='carol@localhost'/>")?;

    alice.send("<presence id='broadcast'><show>away</show></presence>")?;
    alice.expect_xml("<presence xmlns='jabber:client' id='broadcast' from='alice@localhost/desk' to='alice@localhost'><show>away</show></presence>")?;
    sentinel(&mut alice, &mut bob, "bob@localhost/desk")?;
    sentinel(&mut alice, &mut carol, "carol@localhost/desk")?;

    alice.send("<presence type='unavailable' id='gone'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='unavailable' id='gone' from='alice@localhost/desk' to='alice@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='unavailable' id='gone' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;
    carol.expect_xml("<presence xmlns='jabber:client' type='unavailable' id='gone' from='alice@localhost/desk' to='carol@localhost'/>")?;

    alice.close()?;
    sentinel(&mut carol, &mut bob, "bob@localhost/desk")?;
    bob.close()?;
    carol.close()
}

#[test]
fn directed_unavailable_presence_forgets_the_recipient() -> TestResult {
    let suite = C2sSuite::start()?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    let mut carol = suite.connect("carol", "password", "desk")?;

    alice.send("<presence to='bob@localhost/desk'/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk'/>",
    )?;
    alice.send("<presence to='bob@localhost/desk' type='unavailable'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;

    alice.close()?;
    sentinel(&mut carol, &mut bob, "bob@localhost/desk")?;
    bob.close()?;
    carol.close()
}

#[test]
fn closing_the_stream_sends_unavailable_to_directed_recipients() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;

    alice.send("<presence to='bob@localhost/desk'/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk'/>",
    )?;
    alice.close()?;

    bob.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;
    bob.close()
}

#[test]
fn directed_presence_to_an_absent_recipient_is_dropped_silently() -> TestResult {
    let suite = C2sSuite::start()?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    let mut carol = suite.connect("carol", "password", "desk")?;

    for target in [
        "nobody@localhost",
        "bob@localhost/tablet",
        "bob@remote.example",
        "localhost",
    ] {
        alice.send(&format!("<presence to='{target}'/>"))?;
    }
    sentinel(&mut alice, &mut bob, "bob@localhost/desk")?;

    alice.close()?;
    sentinel(&mut carol, &mut bob, "bob@localhost/desk")?;
    bob.close()?;
    carol.close()
}

#[test]
fn repeated_directed_presence_and_the_own_account_are_told_once() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut phone = suite.connect("alice", "password", "phone")?;
    let mut bob = suite.connect("bob", "password", "desk")?;

    alice.send("<presence to='bob@localhost/desk' id='first'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' id='first' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;
    alice.send("<presence to='bob@localhost/desk' id='again'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' id='again' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;
    alice.send("<presence to='alice@localhost/phone' id='self'/>")?;
    phone.expect_xml("<presence xmlns='jabber:client' id='self' from='alice@localhost/desk' to='alice@localhost/phone'/>")?;

    alice.close()?;
    bob.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;
    sentinel(&mut phone, &mut bob, "bob@localhost/desk")?;
    bob.send("<message to='alice@localhost/phone' id='sentinel'/>")?;
    let message = phone.receive()?;
    assert_eq!(message.attribute("id"), Some("sentinel"), "{message:?}");
    phone.close()?;
    bob.close()
}

#[test]
fn incoming_directed_unavailable_removes_only_its_full_recipient_grant() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    let mut phone = suite.connect("bob", "password", "phone")?;
    let mut carol = suite.connect("carol", "password", "desk")?;
    alice.send("<presence to='bob@localhost/desk'/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk'/>",
    )?;
    alice.send("<presence to='bob@localhost/phone'/>")?;
    phone.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/phone'/>",
    )?;
    bob.send("<presence to='alice@localhost/desk' type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='bob@localhost/desk' to='alice@localhost/desk'/>")?;
    alice.close()?;
    phone.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='alice@localhost/desk' to='bob@localhost/phone'/>")?;
    sentinel(&mut carol, &mut bob, "bob@localhost/desk")?;
    phone.close()?;
    bob.close()?;
    carol.close()
}

#[test]
fn bare_directed_probes_reply_only_from_granting_resources_without_payload() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut desk = suite.connect("alice", "password", "desk")?;
    let mut phone = suite.connect("alice", "password", "phone")?;
    let mut ungranting = suite.connect("alice", "password", "tablet")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    let mut sibling = suite.connect("bob", "password", "phone")?;
    for (source, id) in [(&mut desk, "desk"), (&mut phone, "phone")] {
        source.send(&format!("<presence to='bob@localhost/desk' id='{id}'><status>private</status><x xmlns='urn:test'/></presence>"))?;
        assert_eq!(bob.receive()?.attribute("id"), Some(id));
    }
    bob.send("<presence type='probe' from='mallory@localhost/forged' to='alice@localhost' id='probe'><x xmlns='urn:test'/></presence>")?;
    let mut sources = Vec::new();
    for _ in 0..2 {
        let reply = bob.receive()?;
        reply.assert_name("jabber:client", "presence");
        assert_eq!(reply.attribute("id"), Some("probe"));
        assert_eq!(reply.attribute("to"), Some("bob@localhost/desk"));
        assert!(reply.attribute("type").is_none());
        assert!(reply.children.is_empty());
        sources.push(reply.attribute("from").ok_or("missing from")?.to_owned());
    }
    sources.sort();
    assert_eq!(sources, ["alice@localhost/desk", "alice@localhost/phone"]);
    for (target, from, kind) in [
        ("alice@localhost/desk", "alice@localhost/desk", None),
        (
            "alice@localhost/tablet",
            "alice@localhost",
            Some("unsubscribed"),
        ),
        (
            "alice@localhost/missing",
            "alice@localhost",
            Some("unsubscribed"),
        ),
    ] {
        bob.send(&format!("<presence type='probe' to='{target}' id='full'/>"))?;
        let reply = bob.receive()?;
        assert_eq!(reply.attribute("from"), Some(from));
        assert_eq!(reply.attribute("id"), Some("full"));
        assert_eq!(reply.attribute("type"), kind);
        assert!(reply.children.is_empty());
    }
    desk.send("<presence type='unavailable' to='bob@localhost/desk'/>")?;
    assert_eq!(bob.receive()?.attribute("type"), Some("unavailable"));
    bob.send("<presence type='probe' to='alice@localhost/desk' id='revoked'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='unsubscribed' from='alice@localhost' to='bob@localhost/desk' id='revoked'/>")?;
    sentinel(&mut bob, &mut sibling, "bob@localhost/phone")?;
    desk.close()?;
    phone.close()?;
    assert_eq!(bob.receive()?.attribute("type"), Some("unavailable"));
    ungranting.close()?;
    sibling.close()?;
    bob.close()
}

#[test]
fn subscribed_bare_probes_preserve_current_presence_and_full_probes_are_minimal() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut sibling = suite.connect("alice", "password", "phone")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    let mut phone = suite.connect("bob", "password", "phone")?;
    bob.send("<presence id='original' xml:lang='fr'><show>away</show><status>bonjour</status><x xmlns='urn:test'/></presence>")?;
    assert_eq!(bob.receive()?.attribute("id"), Some("original"));
    phone.send("<presence id='second'><priority>-1</priority></presence>")?;
    assert_eq!(phone.receive()?.attribute("id"), Some("original"));
    assert_eq!(phone.receive()?.attribute("id"), Some("second"));
    assert_eq!(bob.receive()?.attribute("id"), Some("second"));
    alice.send("<presence to='bob@localhost' type='subscribe'/>")?;
    assert_eq!(bob.receive()?.attribute("type"), Some("subscribe"));
    assert_eq!(phone.receive()?.attribute("type"), Some("subscribe"));
    bob.send("<presence to='alice@localhost' type='subscribed'/>")?;
    sentinel(&mut bob, &mut alice, "alice@localhost/desk")?;
    alice.send("<presence type='probe' to='bob@localhost' id='bare'/>")?;
    let mut replies = [alice.receive()?, alice.receive()?];
    replies.sort_by_key(|reply| reply.attribute("id").map(str::to_owned));
    replies[0].assert_xml("<presence xmlns='jabber:client' id='original' xml:lang='fr' from='bob@localhost/desk' to='alice@localhost/desk'><show>away</show><status>bonjour</status><x xmlns='urn:test'/></presence>")?;
    replies[1].assert_xml("<presence xmlns='jabber:client' id='second' from='bob@localhost/phone' to='alice@localhost/desk'><priority>-1</priority></presence>")?;
    for (target, kind) in [
        ("bob@localhost/desk", None),
        ("bob@localhost/missing", Some("unavailable")),
    ] {
        alice.send(&format!("<presence type='probe' to='{target}' id='full'/>"))?;
        let reply = alice.receive()?;
        assert_eq!(reply.attribute("from"), Some(target));
        assert_eq!(reply.attribute("id"), Some("full"));
        assert_eq!(reply.attribute("type"), kind);
        assert!(reply.children.is_empty());
    }
    sentinel(&mut alice, &mut sibling, "alice@localhost/phone")?;
    bob.send("<presence type='unavailable' id='desk-gone'/>")?;
    assert_eq!(bob.receive()?.attribute("id"), Some("desk-gone"));
    assert_eq!(phone.receive()?.attribute("id"), Some("desk-gone"));
    phone.send("<presence type='unavailable' id='phone-gone'/>")?;
    assert_eq!(phone.receive()?.attribute("id"), Some("phone-gone"));
    alice.send("<presence type='probe' to='bob@localhost' id='offline'/>")?;
    let offline = alice.receive()?;
    assert_eq!(offline.attribute("from"), Some("bob@localhost"));
    assert_eq!(offline.attribute("id"), Some("offline"));
    assert_eq!(offline.attribute("type"), Some("unavailable"));
    assert_eq!(offline.children.len(), 1);
    assert!(
        offline
            .child("urn:xmpp:delay", "delay")?
            .attribute("stamp")
            .is_some()
    );
    alice.close()?;
    sibling.close()?;
    bob.close()?;
    phone.close()
}

#[test]
fn probe_denials_preserve_preapproval_and_roster_version() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    alice.send("<presence type='subscribed' to='bob@localhost'/>")?;
    alice.send("<iq type='get' id='before'><query xmlns='jabber:iq:roster' ver=''/></iq>")?;
    let before = alice.receive()?;
    let before = before.child("jabber:iq:roster", "query")?;
    assert_eq!(before.children[0].attribute("approved"), Some("true"));
    let version = before.attribute("ver").ok_or("missing version")?.to_owned();
    for target in [
        "alice@localhost",
        "alice@localhost/desk",
        "missing@localhost/secret",
    ] {
        bob.send(&format!(
            "<presence type='probe' to='{target}' id='denied'/>"
        ))?;
        let reply = bob.receive()?;
        assert_eq!(reply.attribute("type"), Some("unsubscribed"));
        assert_eq!(
            reply.attribute("from"),
            Some(target.split('/').next().ok_or("missing bare")?)
        );
        assert_eq!(reply.attribute("id"), Some("denied"));
        assert!(reply.children.is_empty());
    }
    bob.send("<message to='alice@localhost/desk' id='done'/>")?;
    assert_eq!(alice.receive()?.attribute("id"), Some("done"));
    alice.send("<iq type='get' id='after'><query xmlns='jabber:iq:roster' ver=''/></iq>")?;
    let after = alice.receive()?;
    let after = after.child("jabber:iq:roster", "query")?;
    assert_eq!(after.attribute("ver"), Some(version.as_str()));
    assert_eq!(after.children, before.children);
    alice.close()?;
    bob.close()
}

#[test]
fn a_probe_waiting_for_account_order_keeps_draining_a_healthy_reader() -> TestResult {
    let suite = C2sSuite::with_extensions_limits_and_setup(
        "'roster', 'test-iq'",
        "incoming_stanzas_per_connection = { per_second = 100_000, burst = 100_000 }",
        |_| Ok(()),
    )?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut source = suite.connect("alice", "password", "desk")?;
    let mut slow = suite.connect("alice", "password", "slow")?;
    let mut requester = suite.connect("alice", "password", "phone")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    source.send("<presence id='source'><status>private</status></presence>")?;
    assert_eq!(source.receive()?.attribute("id"), Some("source"));
    requester.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    assert_eq!(requester.receive()?.attribute("id"), Some("roster"));
    slow.send("<iq type='set' id='slow'><slow xmlns='urn:lonewolf:test:iq' millis='4000'/></iq>")?;
    assert_eq!(requester.receive()?.attribute("id"), Some("slow"));
    requester.send("<presence type='probe' to='alice@localhost/desk' id='probe'/>")?;
    for batch in 0..75 {
        for index in batch * 16..(batch + 1) * 16 {
            bob.send(&format!(
                "<message to='alice@localhost/phone' id='live-{index}'/>"
            ))?;
        }
        for index in batch * 16..(batch + 1) * 16 {
            let message = requester.receive()?;
            message.assert_name("jabber:client", "message");
            assert_eq!(
                message.attribute("id"),
                Some(format!("live-{index}").as_str())
            );
        }
    }
    requester.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/phone' id='probe'/>")?;
    assert_eq!(slow.receive()?.attribute("id"), Some("slow"));
    requester.send("<message to='bob@localhost/desk' id='after'/>")?;
    assert_eq!(bob.receive()?.attribute("id"), Some("after"));
    source.close()?;
    slow.close()?;
    requester.close()?;
    bob.close()
}

#[test]
fn cancelling_a_waiting_probe_releases_its_work_and_account_order() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut source = suite.connect("alice", "password", "desk")?;
    let mut slow = suite.connect("alice", "password", "slow")?;
    let mut requester = suite.connect("alice", "password", "phone")?;
    source.send("<presence/>")?;
    source.receive()?;
    requester.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    requester.receive()?;
    slow.send("<iq type='set' id='slow'><slow xmlns='urn:lonewolf:test:iq' millis='1000'/></iq>")?;
    assert_eq!(requester.receive()?.attribute("id"), Some("slow"));
    requester.send("<presence type='probe' to='alice@localhost/desk' id='cancelled'/>")?;
    requester.reset()?;
    source.send("<presence type='probe' to='alice@localhost/desk' id='next'/>")?;
    source.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='next'/>")?;
    assert_eq!(slow.receive()?.attribute("id"), Some("slow"));
    source.close()?;
    slow.close()
}

#[test]
fn a_probe_behind_a_committed_revocation_reads_the_new_authorization() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-iq'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut source = suite.connect("alice", "password", "desk")?;
    let mut slow = suite.connect("alice", "password", "slow")?;
    let mut requester = suite.connect("bob", "password", "desk")?;
    source.send("<presence id='source'><status>private</status></presence>")?;
    source.receive()?;
    requester.send("<presence type='subscribe' to='alice@localhost'/>")?;
    assert_eq!(source.receive()?.attribute("type"), Some("subscribe"));
    source.send("<presence type='subscribed' to='bob@localhost'/>")?;
    sentinel(&mut source, &mut requester, "bob@localhost/desk")?;
    source.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    source.receive()?;
    requester.send("<presence type='probe' to='alice@localhost' id='authorized'/>")?;
    assert_eq!(requester.receive()?.attribute("id"), Some("source"));
    slow.send("<iq type='set' id='revoke'><slow xmlns='urn:lonewolf:test:iq' millis='1000' revoke='bob@localhost'/></iq>")?;
    assert_eq!(source.receive()?.attribute("id"), Some("slow"));
    requester.send("<presence type='probe' to='alice@localhost' id='denied'/>")?;
    requester.expect_xml("<presence xmlns='jabber:client' type='unsubscribed' from='alice@localhost' to='bob@localhost/desk' id='denied'/>")?;
    assert_eq!(slow.receive()?.attribute("id"), Some("revoke"));
    source.close()?;
    slow.close()?;
    requester.close()
}
