// SPDX-License-Identifier: Apache-2.0

use super::support::{Client, Server, TestResult};

fn message(client: &mut Client, id: &str, from: &str, to: &str) -> TestResult {
    let received = client.receive()?;
    received.assert_name("jabber:client", "message");
    assert_eq!(received.attribute("id"), Some(id), "{received:?}");
    assert_eq!(received.attribute("from"), Some(from));
    assert_eq!(received.attribute("to"), Some(to));
    assert_ne!(received.attribute("type"), Some("error"), "{received:?}");
    Ok(())
}

fn presence(client: &mut Client, from: &str, unavailable: bool) -> TestResult {
    let received = client.receive()?;
    received.assert_name("jabber:client", "presence");
    assert_eq!(received.attribute("from"), Some(from), "{received:?}");
    assert_eq!(received.attribute("to"), Some("alice@localhost"));
    assert_eq!(
        received.attribute("type"),
        unavailable.then_some("unavailable")
    );
    Ok(())
}

fn available_pair(server: &Server, second_priority: i8) -> TestResult<(Client, Client)> {
    let mut desk = Client::connect(server, "alice", "pencil", "desk")?;
    let mut phone = Client::connect(server, "alice", "pencil", "phone")?;
    desk.send("<presence/>")?;
    presence(&mut desk, "alice@localhost/desk", false)?;
    phone.send(&format!(
        "<presence><priority>{second_priority}</priority></presence>"
    ))?;
    presence(&mut phone, "alice@localhost/desk", false)?;
    presence(&mut phone, "alice@localhost/phone", false)?;
    presence(&mut desk, "alice@localhost/phone", false)?;
    Ok((desk, phone))
}

#[test]
fn bare_chat_and_normal_follow_priority_while_full_jids_ignore_availability() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    server.create_account("bob", "secret")?;
    let mut sender = Client::connect(&server, "bob", "secret", "desk")?;
    let (mut desk, mut phone) = available_pair(&server, 5)?;
    for kind in ["chat", "normal"] {
        sender.send(&format!(
            "<message to='alice@localhost' type='{kind}' id='{kind}'/>"
        ))?;
        message(&mut phone, kind, "bob@localhost/desk", "alice@localhost")?;
    }
    phone.send("<presence type='unavailable'/>")?;
    presence(&mut desk, "alice@localhost/phone", true)?;
    presence(&mut phone, "alice@localhost/phone", true)?;
    sender.send("<message to='alice@localhost' id='normal'/>")?;
    message(&mut desk, "normal", "bob@localhost/desk", "alice@localhost")?;
    sender.send("<message to='alice@localhost/phone' type='chat' id='full'/>")?;
    message(
        &mut phone,
        "full",
        "bob@localhost/desk",
        "alice@localhost/phone",
    )?;
    desk.send("<presence><priority>-1</priority></presence>")?;
    presence(&mut desk, "alice@localhost/desk", false)?;
    sender.send("<message to='alice@localhost' type='chat' id='negative'/>")?;
    sender.receive()?.assert_stanza_error(
        "message",
        "negative",
        "cancel",
        "service-unavailable",
    )?;
    sender.send("<message to='alice@localhost/desk' type='chat' id='full-negative'/>")?;
    message(
        &mut desk,
        "full-negative",
        "bob@localhost/desk",
        "alice@localhost/desk",
    )?;
    desk.barrier()?;
    phone.barrier()?;
    sender.barrier()
}

#[test]
fn headline_broadcasts_to_eligible_resources_and_chat_ties_choose_the_oldest() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let (mut desk, mut phone) = available_pair(&server, 0)?;
    desk.send("<message to='alice@localhost' type='chat' id='tie'/><message to='alice@localhost' type='headline' id='news'/>")?;
    message(&mut desk, "tie", "alice@localhost/desk", "alice@localhost")?;
    message(&mut desk, "news", "alice@localhost/desk", "alice@localhost")?;
    message(
        &mut phone,
        "news",
        "alice@localhost/desk",
        "alice@localhost",
    )?;
    phone.send("<presence><priority>-1</priority></presence>")?;
    presence(&mut desk, "alice@localhost/phone", false)?;
    presence(&mut phone, "alice@localhost/phone", false)?;
    desk.send("<message to='alice@localhost' type='headline' id='eligible'/><message to='alice@localhost/phone' id='sentinel'/>")?;
    message(
        &mut desk,
        "eligible",
        "alice@localhost/desk",
        "alice@localhost",
    )?;
    message(
        &mut phone,
        "sentinel",
        "alice@localhost/desk",
        "alice@localhost/phone",
    )?;
    desk.barrier()?;
    phone.barrier()
}

#[test]
fn missing_full_chat_falls_back_but_other_types_return_errors() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut client = Client::connect(&server, "alice", "pencil", "desk")?;
    client.send("<presence/>")?;
    presence(&mut client, "alice@localhost/desk", false)?;
    client.send("<message to='alice@localhost/missing' type='chat' id='fallback'/>")?;
    message(
        &mut client,
        "fallback",
        "alice@localhost/desk",
        "alice@localhost/missing",
    )?;
    for kind in ["normal", "headline", "groupchat"] {
        client.send(&format!(
            "<message to='alice@localhost/missing' type='{kind}' id='{kind}'/>"
        ))?;
        client
            .receive()?
            .assert_stanza_error("message", kind, "cancel", "service-unavailable")?;
    }
    client.barrier()
}

#[test]
fn unroutable_messages_return_addressed_errors_with_the_original_payload() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    server.create_account("offline", "secret")?;
    let mut client = Client::connect(&server, "alice", "pencil", "desk")?;
    for (to, kind, condition) in [
        ("alice@localhost", "chat", "service-unavailable"),
        ("offline@localhost", "normal", "service-unavailable"),
        ("missing@localhost", "chat", "service-unavailable"),
        ("alice@localhost/missing", "chat", "service-unavailable"),
        ("alice@remote.example", "chat", "service-unavailable"),
        ("localhost", "chat", "service-unavailable"),
        ("alice@localhost", "groupchat", "service-unavailable"),
    ] {
        client.send(&format!("<message to='{to}' from='mallory@localhost' type='{kind}' id='failed'><body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra></message>"))?;
        let error = client.receive()?;
        error.assert_stanza_error(
            "message",
            "failed",
            if condition == "bad-request" {
                "modify"
            } else {
                "cancel"
            },
            condition,
        )?;
        assert_eq!(error.attribute("from"), Some(to));
        assert_eq!(error.attribute("to"), Some("alice@localhost/desk"));
        assert_eq!(error.child("jabber:client", "body")?.text, "Keep & escape");
        assert_eq!(error.child("urn:test:payload", "extra")?.text, "value");
    }
    client.barrier()
}

#[test]
fn bare_error_and_undeliverable_error_or_headline_messages_are_silent() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut client = Client::connect(&server, "alice", "pencil", "desk")?;
    for (to, kind) in [
        ("alice@localhost", "error"),
        ("missing@localhost", "error"),
        ("alice@localhost/missing", "error"),
        ("alice@remote.example", "error"),
        ("alice@localhost", "headline"),
        ("missing@localhost", "headline"),
    ] {
        let error = if kind == "error" {
            "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
        } else {
            ""
        };
        client.send(&format!(
            "<message to='{to}' type='{kind}' id='silent'>{error}</message>"
        ))?;
    }
    client.barrier()?;
    client.send("<presence/>")?;
    presence(&mut client, "alice@localhost/desk", false)?;
    client.send("<message to='alice@localhost' type='error' id='bare-error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message><message to='alice@localhost/desk' type='error' id='full-error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
    let delivered = client.receive()?;
    delivered.assert_name("jabber:client", "message");
    assert_eq!(delivered.attribute("id"), Some("full-error"));
    assert_eq!(delivered.attribute("type"), Some("error"));
    client.barrier()
}

#[test]
fn omitted_destination_routes_to_own_bare_jid_and_preserves_payload_namespaces() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut client = Client::connect(&server, "alice", "pencil", "desk")?;
    client.send("<presence from='mallory@localhost/spy'><priority>7</priority></presence>")?;
    let available = client.receive()?;
    assert_eq!(available.attribute("from"), Some("alice@localhost/desk"));
    assert_eq!(available.child("jabber:client", "priority")?.text, "7");
    client.send("<message id='self' xml:lang='es'><body>Hola &amp; adiós</body><x xmlns='urn:test:outer'><value xmlns='urn:test:inner'>✓</value></x></message>")?;
    let received = client.receive()?;
    received.assert_name("jabber:client", "message");
    assert_eq!(received.attribute("id"), Some("self"));
    assert_eq!(received.attribute("from"), Some("alice@localhost/desk"));
    assert_eq!(received.attribute("to"), Some("alice@localhost"));
    assert_eq!(received.attribute("xml:lang"), Some("es"));
    assert_eq!(
        received.child("jabber:client", "body")?.text,
        "Hola & adiós"
    );
    assert_eq!(
        received
            .child("urn:test:outer", "x")?
            .child("urn:test:inner", "value")?
            .text,
        "✓"
    );
    client.barrier()
}

#[test]
fn pipelined_self_messages_drain_the_outbound_mailbox_in_order() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut client = Client::connect(&server, "alice", "pencil", "desk")?;
    let mut batch = String::new();
    for index in 0..64 {
        use std::fmt::Write;
        write!(
            batch,
            "<message to='alice@localhost/desk' type='chat' id='{index}'/>"
        )?;
    }
    client.send(&batch)?;
    for index in 0..64 {
        message(
            &mut client,
            &index.to_string(),
            "alice@localhost/desk",
            "alice@localhost/desk",
        )?;
    }
    client.barrier()
}

#[test]
fn invalid_presence_priority_returns_an_error_without_making_the_resource_available() -> TestResult
{
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut client = Client::connect(&server, "alice", "pencil", "desk")?;
    for priority in [
        "<priority>128</priority>",
        "<priority>-129</priority>",
        "<priority>many</priority>",
        "<priority/>",
        "<priority extra='1'>1</priority>",
        "<priority>1</priority><priority>2</priority>",
    ] {
        client.send(&format!("<presence id='priority'>{priority}</presence>"))?;
        client
            .receive()?
            .assert_stanza_error("presence", "priority", "modify", "bad-request")?;
        client.send("<message to='alice@localhost' type='chat' id='unavailable'/>")?;
        client.receive()?.assert_stanza_error(
            "message",
            "unavailable",
            "cancel",
            "service-unavailable",
        )?;
    }
    client.barrier()
}

#[test]
fn directed_and_subscription_presence_do_not_change_local_availability() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut client = Client::connect(&server, "alice", "pencil", "desk")?;
    client.send("<presence to='alice@localhost'/>")?;
    for kind in [
        "subscribe",
        "subscribed",
        "unsubscribe",
        "unsubscribed",
        "probe",
        "error",
    ] {
        let error = if kind == "error" {
            "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
        } else {
            ""
        };
        client.send(&format!("<presence type='{kind}'>{error}</presence>"))?;
    }
    client.send("<message to='alice@localhost' type='chat' id='unavailable'/>")?;
    client.receive()?.assert_stanza_error(
        "message",
        "unavailable",
        "cancel",
        "service-unavailable",
    )?;
    client.barrier()
}

#[test]
fn disconnect_broadcasts_unavailable_and_releases_the_resource() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    for graceful in [true, false] {
        let (mut desk, mut phone) = available_pair(&server, 5)?;
        if graceful {
            phone.close()?;
        }
        drop(phone);
        presence(&mut desk, "alice@localhost/phone", true)?;
        desk.send("<message to='alice@localhost' type='chat' id='remaining'/>")?;
        message(
            &mut desk,
            "remaining",
            "alice@localhost/desk",
            "alice@localhost",
        )?;
        let mut rebound = Client::connect(&server, "alice", "pencil", "phone")?;
        rebound.barrier()?;
        rebound.close()?;
        desk.close()?;
    }
    Ok(())
}

#[test]
fn unsupported_iqs_return_errors_and_unsolicited_replies_are_ignored() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut client = Client::connect(&server, "alice", "pencil", "desk")?;
    for kind in ["get", "set"] {
        for to in [
            None,
            Some("localhost"),
            Some("remote.example"),
            Some("alice@localhost"),
            Some("alice@localhost/desk"),
        ] {
            let destination = to.map(|to| format!("to='{to}'")).unwrap_or_default();
            client.send(&format!("<iq {destination} from='mallory@localhost/spy' type='{kind}' id='unsupported'><query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query></iq>"))?;
            let reply = client.receive()?;
            reply.assert_stanza_error("iq", "unsupported", "cancel", "service-unavailable")?;
            assert_eq!(reply.attribute("from"), to);
            assert_eq!(reply.attribute("to"), None);
            reply
                .child("urn:test:outer", "query")?
                .child("urn:test:inner", "child")?;
        }
    }
    client.send("<iq type='result' id='orphan'/><iq type='error' id='orphan'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    client.barrier()
}

#[test]
fn full_jid_message_reaches_an_authenticated_resource_without_presence() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    server.create_account("bob", "secret")?;
    let mut alice = Client::connect(&server, "alice", "pencil", "desktop")?;
    let mut bob = Client::connect(&server, "bob", "secret", "phone")?;
    alice.send("<message to='bob@localhost/phone' from='mallory@localhost' type='chat' id='hello'><body>Hello</body></message>")?;
    let message = bob.receive()?;
    assert_eq!(message.name, "message");
    assert_eq!(message.namespace, "jabber:client");
    assert_eq!(message.attribute("id"), Some("hello"));
    assert_eq!(message.attribute("type"), Some("chat"));
    assert_eq!(message.attribute("from"), Some("alice@localhost/desktop"));
    assert_eq!(message.attribute("to"), Some("bob@localhost/phone"));
    assert_eq!(message.child("jabber:client", "body")?.text, "Hello");
    Ok(())
}
