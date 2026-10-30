// SPDX-License-Identifier: Apache-2.0

use super::{DIRECTIONS, available, iq_reply, stanza_error, traffic, workflow_options};
use crate::support::federation::FederatedPair;
use crate::support::{PASSWORD, TestResult};

#[test]
fn chat_to_bare_jid_reaches_available_resource() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
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
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        let mut other = pair.b.connect(bn, PASSWORD, "tablet")?;
        available(&mut other, &bj, "tablet")?;
        a.send(&format!("<message type='chat' id='chat' to='{bj}/phone'><body>Hello across domains</body></message>"))?;
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
    }
    Ok(())
}

#[test]
fn message_to_offline_recipient_is_stored_and_replayed() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        a.send(&format!("<message type='chat' id='stored' to='{bj}'><body>Stored across domains</body></message>"))?;
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
    }
    Ok(())
}

#[test]
fn message_to_missing_account_is_discarded() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
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
    }
    Ok(())
}

#[test]
fn groupchat_to_bare_jid_returns_service_unavailable() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
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
    }
    Ok(())
}

#[test]
fn messages_keep_order() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
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
    }
    Ok(())
}

#[test]
fn extension_payloads_keep_their_namespaces() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
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
    }
    Ok(())
}

#[test]
fn carbons_copy_federated_messages() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
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
    }
    Ok(())
}
