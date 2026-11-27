// SPDX-License-Identifier: Apache-2.0

use super::{ACCOUNTS, available, iq_reply, stanza_error, traffic, workflow_options};
use crate::support::federation::FederatedPair;
use crate::support::{PASSWORD, TestResult};

#[test]
fn resource_rule_for_remote_account_preserves_bare_federated_address() -> TestResult {
    let mut options = workflow_options();
    options.a_extensions.push_str(", 'blocking'");
    let mut pair = FederatedPair::start("a.test", "b.test", options)?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    available(&mut bob, "bob@b.test", "phone")?;
    alice.send("<iq type='set' id='set'><block xmlns='urn:xmpp:blocking'><item jid='bob@b.test/tablet'/></block></iq>")?;
    let set = alice.receive()?;
    set.assert_name("jabber:client", "iq");
    assert_eq!(set.attribute("id"), Some("set"));
    assert_eq!(set.attribute("type"), Some("result"));
    alice.send("<message type='chat' to='bob@b.test' id='bare'/>")?;
    let message = bob.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(message.attribute("to"), Some("bob@b.test"));
    assert_eq!(message.attribute("id"), Some("bare"));
    assert_eq!(message.attribute("type"), Some("chat"));
    traffic(
        &pair,
        "resource_rule_for_remote_account_preserves_bare_federated_address",
        [1, 0, 0],
        [0, 0, 0],
    )?;
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn chat_to_bare_jid_reaches_available_resource() -> TestResult {
    for (ad, an, bd, bn) in [ACCOUNTS, ("b.test", "bob", "a.test", "alice")] {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        available(&mut b, &bj, "phone")?;
        a.send(&format!(
            "<message type='chat' id='chat' to='{bj}'><body>Hello across domains</body></message>"
        ))?;
        let reply = b.receive()?;
        reply.assert_name("jabber:client", "message");
        assert_eq!(reply.attribute("type"), Some("chat"));
        assert_eq!(reply.attribute("id"), Some("chat"));
        assert_eq!(reply.attribute("from"), Some(format!("{aj}/desk").as_str()));
        assert_eq!(reply.attribute("to"), Some(bj.as_str()));
        assert_eq!(
            reply.child("jabber:client", "body")?.text,
            "Hello across domains"
        );
        traffic(
            &pair,
            "chat_to_bare_jid_reaches_available_resource",
            [1, 0, 0],
            [0, 0, 0],
        )?;
        a.close()?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn chat_to_full_jid_reaches_that_resource() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    let mut other = pair.b.connect(bn, PASSWORD, "tablet")?;
    available(&mut other, &bj, "tablet")?;
    a.send(&format!(
        "<message type='chat' id='chat' to='{bj}/phone'><body>Hello across domains</body></message>"
    ))?;
    let reply = b.receive()?;
    reply.assert_name("jabber:client", "message");
    assert_eq!(reply.attribute("type"), Some("chat"));
    assert_eq!(reply.attribute("id"), Some("chat"));
    assert_eq!(reply.attribute("from"), Some(format!("{aj}/desk").as_str()));
    assert_eq!(reply.attribute("to"), Some(format!("{bj}/phone").as_str()));
    assert_eq!(
        reply.child("jabber:client", "body")?.text,
        "Hello across domains"
    );
    crate::support::barrier(&mut other)?;
    traffic(
        &pair,
        "chat_to_full_jid_reaches_that_resource",
        [1, 0, 0],
        [0, 0, 0],
    )?;
    a.close()?;
    b.close()?;
    other.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn message_to_offline_recipient_is_stored_and_replayed() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    a.send(&format!(
        "<message type='chat' id='stored' to='{bj}'><body>Stored across domains</body></message>"
    ))?;
    a.send(&format!(
        "<iq type='get' id='stored-fence' to='{bj}'><ping xmlns='urn:xmpp:ping'/></iq>"
    ))?;
    stanza_error(
        &iq_reply(&mut a, "stored-fence", "error", &bj, &format!("{aj}/desk"))?,
        "service-unavailable",
    )?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    available(&mut b, &bj, "phone")?;
    let reply = b.receive()?;
    reply.assert_name("jabber:client", "message");
    assert_eq!(reply.attribute("type"), Some("chat"));
    assert_eq!(reply.attribute("id"), Some("stored"));
    assert_eq!(reply.attribute("from"), Some(format!("{aj}/desk").as_str()));
    assert_eq!(reply.attribute("to"), Some(bj.as_str()));
    assert_eq!(
        reply.child("jabber:client", "body")?.text,
        "Stored across domains"
    );
    let delay = reply.child("urn:xmpp:delay", "delay")?;
    assert_eq!(delay.attribute("from"), Some(bd));
    let stamp = delay.attribute("stamp").ok_or("missing replay timestamp")?;
    assert_eq!(stamp.len(), 20);
    assert!(stamp.ends_with('Z') && stamp.as_bytes()[10] == b'T');
    crate::support::barrier(&mut b)?;
    traffic(
        &pair,
        "message_to_offline_recipient_is_stored_and_replayed",
        [1, 1, 0],
        [0, 1, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn message_to_missing_account_is_discarded() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    a.send(&format!(
        "<message type='chat' id='discarded' to='{bj}'><body>Missing account</body></message>"
    ))?;
    // Sequential inbound dispatch and the FIFO return link fence the earlier discard.
    a.send(&format!(
        "<iq type='get' id='discard-fence' to='{bj}'><ping xmlns='urn:xmpp:ping'/></iq>"
    ))?;
    stanza_error(
        &iq_reply(&mut a, "discard-fence", "error", &bj, &format!("{aj}/desk"))?,
        "service-unavailable",
    )?;
    crate::support::barrier(&mut a)?;
    traffic(
        &pair,
        "message_to_missing_account_is_discarded",
        [1, 1, 0],
        [0, 1, 0],
    )?;
    a.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn groupchat_to_bare_jid_returns_service_unavailable() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    available(&mut b, &bj, "phone")?;
    a.send(&format!(
        "<message type='groupchat' id='groupchat' to='{bj}'><body>Wrong target</body></message>"
    ))?;
    let reply = a.receive()?;
    reply.assert_name("jabber:client", "message");
    assert_eq!(reply.attribute("id"), Some("groupchat"));
    assert_eq!(reply.attribute("from"), Some(bj.as_str()));
    assert_eq!(reply.attribute("to"), Some(format!("{aj}/desk").as_str()));
    stanza_error(&reply, "service-unavailable")?;
    crate::support::barrier(&mut b)?;
    traffic(
        &pair,
        "groupchat_to_bare_jid_returns_service_unavailable",
        [1, 0, 0],
        [1, 0, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn messages_keep_order() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    available(&mut b, &bj, "phone")?;
    for batch in 0..20 {
        for index in batch * 10..(batch + 1) * 10 {
            a.send(&format!("<message type='chat' to='{bj}' id='sequence-{index}'><body>{index}</body></message>"))?;
        }
        for index in batch * 10..(batch + 1) * 10 {
            let reply = b.receive()?;
            reply.assert_name("jabber:client", "message");
            assert_eq!(reply.attribute("from"), Some(format!("{aj}/desk").as_str()));
            assert_eq!(
                reply.attribute("id"),
                Some(format!("sequence-{index}").as_str())
            );
            assert_eq!(
                reply.child("jabber:client", "body")?.text,
                index.to_string()
            );
        }
    }
    traffic(&pair, "messages_keep_order", [200, 0, 0], [0, 0, 0])?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn extension_payloads_keep_their_namespaces() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    available(&mut b, &bj, "phone")?;
    let extension = "<forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='original@example.test' to='target@example.test' type='chat'><body>Nested client body</body><x xmlns='urn:test:extension'><message xmlns='jabber:server'><body>Server namespace below an extension</body></message></x></message></forwarded>";
    // RFC 6121 §§5.2.3 and 5.2.4 allow each alternative to inherit or specify its language.
    let translations = "<subject>Demain</subject><subject xml:lang='es'>Mañana</subject><body>À midi</body><body xml:lang='es'>Al mediodía</body>";
    a.send(&format!("<message type='chat' id='namespaces' to='{bj}' xml:lang='fr'>{translations}{extension}</message>"))?;
    b.expect_xml(&format!("<message xmlns='jabber:client' type='chat' id='namespaces' from='{aj}/desk' to='{bj}' xml:lang='fr'>{translations}{extension}</message>"))?;
    traffic(
        &pair,
        "extension_payloads_keep_their_namespaces",
        [1, 0, 0],
        [0, 0, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn carbons_copy_federated_messages() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    let mut a2 = pair.a.connect(an, PASSWORD, "tablet")?;
    let mut b2 = pair.b.connect(bn, PASSWORD, "tablet")?;
    for (client, full) in [
        (&mut a, format!("{aj}/desk")),
        (&mut a2, format!("{aj}/tablet")),
        (&mut b, format!("{bj}/phone")),
        (&mut b2, format!("{bj}/tablet")),
    ] {
        client.send("<iq type='set' id='enable'><enable xmlns='urn:xmpp:carbons:2'/></iq>")?;
        client.expect_xml(&format!(
            "<iq xmlns='jabber:client' type='result' id='enable' to='{full}'/>"
        ))?;
    }
    a.send(&format!("<message type='chat' id='carbon' to='{bj}/phone'><body>Carbon across domains</body></message>"))?;
    let inner = format!(
        "<message xmlns='jabber:client' type='chat' id='carbon' from='{aj}/desk' to='{bj}/phone'><body>Carbon across domains</body></message>"
    );
    let received_inner = inner.replace("type='chat'", "type='chat' xml:lang='en'");
    b.receive()?.assert_xml(&received_inner)?;
    for (client, bare, full, direction) in [
        (&mut a2, &aj, format!("{aj}/tablet"), "sent"),
        (&mut b2, &bj, format!("{bj}/tablet"), "received"),
    ] {
        let copy = client.receive()?;
        copy.assert_name("jabber:client", "message");
        assert_eq!(copy.attribute("from"), Some(bare.as_str()));
        assert_eq!(copy.attribute("to"), Some(full.as_str()));
        copy.child("urn:xmpp:carbons:2", direction)?
            .child("urn:xmpp:forward:0", "forwarded")?
            .child("jabber:client", "message")?
            .assert_xml(if direction == "sent" {
                &inner
            } else {
                &received_inner
            })?;
    }
    a2.close()?;
    b2.close()?;
    traffic(
        &pair,
        "carbons_copy_federated_messages",
        [1, 0, 0],
        [0, 0, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}
