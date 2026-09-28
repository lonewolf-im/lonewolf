// SPDX-License-Identifier: Apache-2.0

use super::support::{BIND_NAMESPACE, Client, OPEN, Server, TestResult};

fn invalid_bind(client: &mut Client, payload: &str) -> TestResult {
    client.send(&format!(
        "<iq type='set' id='bad'><bind xmlns='{BIND_NAMESPACE}'>{payload}</bind></iq>"
    ))?;
    client
        .receive()?
        .assert_stanza_error("iq", "bad", "modify", "bad-request")
}

#[test]
fn requested_resource_is_prepared_and_xml_escaped_in_the_returned_jid() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut client = Client::authenticated(&server, "alice", "pencil")?;
    assert_eq!(
        client.bind(Some("Desk & <Phone>"))?,
        "alice@localhost/Desk & <Phone>"
    );
    client.barrier()
}

#[test]
fn missing_and_conflicting_resources_get_distinct_random_names() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut first = Client::connect(&server, "alice", "pencil", "desk")?;
    let mut second = Client::authenticated(&server, "alice", "pencil")?;
    let mut third = Client::authenticated(&server, "alice", "pencil")?;
    let generated = second.bind(None)?;
    let conflict = third.bind(Some("desk"))?;
    for jid in [&generated, &conflict] {
        let random = jid
            .strip_prefix("alice@localhost/lw-")
            .ok_or("missing random resource")?;
        assert_eq!(random.len(), 32);
        assert!(random.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    assert_ne!(generated, conflict);
    first.barrier()?;
    second.barrier()?;
    third.barrier()
}

#[test]
fn malformed_bind_requests_allow_retry_and_the_sixth_failure_closes_the_stream() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    for recover in [true, false] {
        let mut client = Client::authenticated(&server, "alice", "pencil")?;
        for payload in [
            "<resource/>",
            "<resource attr='1'>desk</resource>",
            "<resource>desk</resource><resource>phone</resource>",
            "<other/>",
            "text",
        ] {
            invalid_bind(&mut client, payload)?;
        }
        if recover {
            assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
            client.close()?;
        } else {
            invalid_bind(&mut client, "<resource/>")?;
            client.expect_stream_error("policy-violation")?;
        }
    }
    Ok(())
}

#[test]
fn invalid_binding_addresses_and_namespaces_close_without_registering() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    for (attributes, condition) in [
        ("from='bob@localhost'", "invalid-from"),
        ("from='alice@localhost/desk'", "invalid-from"),
        ("to='bob@localhost'", "not-authorized"),
        (
            "xmlns='jabber:server' from='alice@localhost' to='localhost'",
            "invalid-namespace",
        ),
    ] {
        let mut client = Client::authenticated(&server, "alice", "pencil")?;
        client.send(&format!("<iq {attributes} type='set' id='bad'><bind xmlns='{BIND_NAMESPACE}'><resource>desk</resource></bind></iq>"))?;
        client.expect_stream_error(condition)?;
        Client::connect(&server, "alice", "pencil", "desk")?.close()?;
    }
    Ok(())
}

#[test]
fn resource_limit_returns_a_retryable_error_and_disconnect_releases_capacity() -> TestResult {
    let server = Server::resource_limit(1)?;
    server.create_account("alice", "pencil")?;
    let mut occupied = Client::connect(&server, "alice", "pencil", "desk")?;
    let mut retry = Client::authenticated(&server, "alice", "pencil")?;
    retry.send(&format!("<iq type='set' id='full'><bind xmlns='{BIND_NAMESPACE}'><resource>phone</resource></bind></iq>"))?;
    retry
        .receive()?
        .assert_stanza_error("iq", "full", "wait", "resource-constraint")?;
    occupied.close()?;
    assert_eq!(retry.bind(Some("phone"))?, "alice@localhost/phone");
    retry.barrier()
}

#[test]
fn prefix_free_streams_still_return_client_namespace_iqs() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut client = Client::secure(&server)?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();
    client.open_with(&OPEN.replace(" xmlns='jabber:client'", ""))?;
    client.features()?;
    for (id, resource, kind) in [("bad", "", "error"), ("good", "desk", "result")] {
        client.send(&format!("<iq xmlns='jabber:client' type='set' id='{id}'><bind xmlns='{BIND_NAMESPACE}'><resource>{resource}</resource></bind></iq>"))?;
        let reply = client.receive()?;
        reply.assert_name("jabber:client", "iq");
        assert_eq!(reply.attribute("id"), Some(id));
        assert_eq!(reply.attribute("type"), Some(kind));
        if kind == "error" {
            reply.assert_stanza_error("iq", id, "modify", "bad-request")?;
        } else {
            assert_eq!(
                reply
                    .child(BIND_NAMESPACE, "bind")?
                    .child(BIND_NAMESPACE, "jid")?
                    .text,
                "alice@localhost/desk"
            );
        }
    }
    client.send("<iq xmlns='jabber:client' type='get' id='unsupported'><query xmlns='urn:test:unknown'/></iq>")?;
    client
        .receive()?
        .assert_stanza_error("iq", "unsupported", "cancel", "service-unavailable")?;
    client.close()
}
