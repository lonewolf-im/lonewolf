// SPDX-License-Identifier: Apache-2.0

use crate::support::federation::FederatedPair;
use crate::support::federation::workflow::{
    ACCOUNTS, available, iq_reply, stanza_error, traffic, workflow_options,
};
use crate::support::{PASSWORD, TestResult};

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
    a.send(&format!("<message type='chat' id='namespaces' to='{bj}'><body>Outer client body</body>{extension}</message>"))?;
    let reply = b.receive()?;
    reply.assert_name("jabber:client", "message");
    assert_eq!(reply.attribute("from"), Some(format!("{aj}/desk").as_str()));
    assert_eq!(
        reply.child("jabber:client", "body")?.text,
        "Outer client body"
    );
    reply
        .child("urn:xmpp:forward:0", "forwarded")?
        .assert_xml(extension)?;
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
fn language_alternatives_keep_their_inherited_and_explicit_languages() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    available(&mut b, &bj, "phone")?;
    let translations = "<subject>Demain</subject><subject xml:lang='es'>Mañana</subject><body>À midi</body><body xml:lang='es'>Al mediodía</body>";
    a.send(&format!(
        "<message type='chat' id='languages' to='{bj}' xml:lang='fr'>{translations}</message>"
    ))?;
    b.expect_xml(&format!("<message xmlns='jabber:client' type='chat' id='languages' from='{aj}/desk' to='{bj}' xml:lang='fr'>{translations}</message>"))?;
    traffic(
        &pair,
        "language_alternatives_keep_their_inherited_and_explicit_languages",
        [1, 0, 0],
        [0, 0, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn federated_delays_claiming_the_receiving_server_are_discarded() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    available(&mut b, &bj, "phone")?;
    let kept = "<delay xmlns='urn:xmpp:delay' from='muc.example' stamp='2001-01-01T00:00:00Z'/><delay xmlns='urn:xmpp:delay' stamp='2002-01-01T00:00:00Z'/>";
    a.send(&format!(
        "<message type='chat' id='delayed' to='{bj}'><body>Hello</body><delay xmlns='urn:xmpp:delay' from='{bd}' stamp='2000-01-01T00:00:00Z'/>{kept}</message>"
    ))?;
    b.expect_xml(&format!("<message xmlns='jabber:client' type='chat' id='delayed' from='{aj}/desk' to='{bj}' xml:lang='en'><body>Hello</body>{kept}</message>"))?;
    traffic(
        &pair,
        "federated_delays_claiming_the_receiving_server_are_discarded",
        [1, 0, 0],
        [0, 0, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()
}
