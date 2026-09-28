// SPDX-License-Identifier: Apache-2.0

use super::support::{
    Client, OPEN, PlainClient, SASL_NAMESPACE, Server, TLS_NAMESPACE, TestResult,
};

#[test]
fn valid_openings_select_the_host_and_negotiate_version_and_namespace() -> TestResult {
    let server = Server::start()?;
    for opening in [
        OPEN.to_owned(),
        OPEN.replace(" to='localhost'", ""),
        OPEN.replace("version='1.0'", "version='01.000'"),
        OPEN.replace("version='1.0'", "version='1.13'"),
        OPEN.replace("version='1.0'", "version='12.3'"),
        OPEN.replace("version='1.0'", "version='999999999999999999999.0'"),
        OPEN.replace(
            "version='1.0'",
            "from='Alice@LOCALHOST/Phone' xml:lang='es' version='1.0'",
        ),
        OPEN.replace(" xmlns='jabber:client'", ""),
        format!("\u{feff}<?xml version='1.0' encoding='UTF-8'?>{OPEN}"),
    ] {
        let mut client = PlainClient::tcp(&server)?;
        let header = client.open_with(&opening)?;
        assert_eq!(header.attribute("from"), Some("localhost"), "{opening}");
        assert_eq!(header.attribute("version"), Some("1.0"), "{opening}");
        assert_eq!(header.attribute("xml:lang"), Some("en"));
        assert_eq!(
            header.attribute("to"),
            opening.contains("from=").then_some("alice@localhost")
        );
        assert_eq!(
            header.attribute("xmlns"),
            opening
                .contains("xmlns='jabber:client'")
                .then_some("jabber:client")
        );
        let id = header.attribute("id").ok_or("missing stream id")?;
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let features = client.features()?;
        assert_eq!(features.children.len(), 1);
        features
            .child(TLS_NAMESPACE, "starttls")?
            .child(TLS_NAMESPACE, "required")?;
        client.close()?;
    }
    Ok(())
}

fn invalid_openings() -> Vec<(String, &'static str)> {
    [
        ("to='localhost'", "to='unknown.example'", "host-unknown"),
        ("to='localhost'", "to='alice@localhost'", "bad-format"),
        ("to='localhost'", "to='localhost/phone'", "bad-format"),
        ("to='localhost'", "to='bad domain'", "bad-format"),
        ("version='1.0'", "version='0.9'", "unsupported-version"),
        ("version='1.0'", "", "unsupported-version"),
        ("version='1.0'", "version='+1.0'", "unsupported-version"),
        ("version='1.0'", "version='1.x'", "unsupported-version"),
        (
            "version='1.0'",
            "version='1.0' xml:lang='en_US'",
            "bad-format",
        ),
        ("version='1.0'", "version='1.0' xml:lang=''", "bad-format"),
        (
            "version='1.0'",
            "version='1.0' from='bad domain'",
            "invalid-from",
        ),
        (
            "version='1.0'",
            "version='1.0' to='localhost'",
            "bad-format",
        ),
        (
            "xmlns='jabber:client'",
            "xmlns='jabber:server'",
            "invalid-namespace",
        ),
        (
            "http://etherx.jabber.org/streams",
            "urn:invalid:stream",
            "invalid-namespace",
        ),
    ]
    .into_iter()
    .map(|(from, to, error)| (OPEN.replace(from, to), error))
    .chain([
        (
            format!("<?xml version='1.1'?>{OPEN}"),
            "unsupported-version",
        ),
        (
            format!("<?xml version='1.0' encoding='ISO-8859-1'?>{OPEN}"),
            "unsupported-encoding",
        ),
        ("invalid".into(), "bad-format"),
    ])
    .collect()
}

#[test]
fn invalid_initial_openings_receive_a_server_header_error_and_footer() -> TestResult {
    let server = Server::start()?;
    for (opening, condition) in invalid_openings() {
        let mut client = PlainClient::tcp(&server)?;
        let header = client.open_with(&opening)?;
        if condition == "unsupported-version" {
            assert_eq!(header.attribute("version"), None, "{opening}");
        }
        client
            .expect_stream_error(condition)
            .map_err(|error| format!("{opening}: {error}"))?;
    }
    Ok(())
}

#[test]
fn invalid_openings_are_checked_again_after_tls() -> TestResult {
    let server = Server::start()?;
    for (opening, condition) in invalid_openings() {
        let mut client = Client::encrypted(&server)?;
        client.open_with(&opening)?;
        client
            .expect_stream_error(condition)
            .map_err(|error| format!("{opening}: {error}"))?;
    }
    Ok(())
}

#[test]
fn invalid_openings_are_checked_again_after_authentication() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    for (opening, condition) in invalid_openings().into_iter().chain([(
        OPEN.replace("to='localhost'", "from='bob@localhost' to='localhost'"),
        "invalid-from",
    )]) {
        let mut client = Client::secure(&server)?;
        client.authenticate("alice", "pencil")?;
        let mut client = client.restart();
        client.open_with(&opening)?;
        client
            .expect_stream_error(condition)
            .map_err(|error| format!("{opening}: {error}"))?;
    }
    Ok(())
}

#[test]
fn starttls_rejects_attributes_children_and_text() -> TestResult {
    let server = Server::start()?;
    for request in [
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls' extra='1'/>",
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><child/></starttls>",
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>text</starttls>",
    ] {
        let mut client = PlainClient::tcp(&server)?;
        client.open()?;
        client.send(request)?;
        client.receive()?.assert_name(TLS_NAMESPACE, "failure");
        client.expect_end()?;
    }
    Ok(())
}

#[test]
fn tls_restart_changes_stream_id_and_offers_only_sasl_features() -> TestResult {
    let server = Server::start()?;
    let mut plain = PlainClient::tcp(&server)?;
    let first = plain.open_with(OPEN)?;
    plain.features()?;
    let mut client = plain.start_tls(&server)?;
    let second = client.open_with(OPEN)?;
    assert_ne!(first.attribute("id"), second.attribute("id"));
    let features = client.features()?;
    let mechanisms = features.child(SASL_NAMESPACE, "mechanisms")?;
    assert_eq!(
        mechanisms
            .children
            .iter()
            .map(|child| child.text.as_str())
            .collect::<Vec<_>>(),
        [
            "SCRAM-SHA-256-PLUS",
            "SCRAM-SHA-256",
            "SCRAM-SHA-1-PLUS",
            "SCRAM-SHA-1"
        ]
    );
    assert!(
        features
            .children
            .iter()
            .all(|child| child.name != "starttls" && child.name != "bind")
    );
    let binding = features.child("urn:xmpp:sasl-cb:0", "sasl-channel-binding")?;
    assert_eq!(
        binding
            .children
            .iter()
            .map(|child| child.attribute("type"))
            .collect::<Vec<_>>(),
        [Some("tls-server-end-point"), Some("tls-exporter")]
    );
    client.close()
}

#[test]
fn premature_stanzas_are_not_authorized_in_each_negotiation_phase() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    for payload in ["<message/>", "<presence/>", "<other/>"] {
        let mut plain = PlainClient::tcp(&server)?;
        plain.open()?;
        plain.send(payload)?;
        plain.expect_stream_error("not-authorized")?;
        let mut secure = Client::secure(&server)?;
        secure.send(payload)?;
        if payload == "<other/>" {
            let failure = secure.receive()?;
            failure.assert_name(SASL_NAMESPACE, "failure");
            failure.child(SASL_NAMESPACE, "malformed-request")?;
            secure.close()?;
        } else {
            secure.expect_stream_error("not-authorized")?;
        }
        let mut authenticated = Client::authenticated(&server, "alice", "pencil")?;
        authenticated.send(payload)?;
        authenticated.expect_stream_error("not-authorized")?;
    }
    Ok(())
}

#[test]
fn malformed_stanzas_report_specific_stream_conditions_in_each_phase() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    for (payload, condition) in [
        (
            b"<message xmlns='jabber:server' from='alice@localhost' to='localhost'/>".as_slice(),
            "invalid-namespace",
        ),
        (b"<other xmlns='jabber:server'/>", "invalid-namespace"),
        (b"<iq type='subscribe'/>", "invalid-xml"),
        (b"<x:message/>", "not-well-formed"),
        (b"<message><body></message>", "bad-format"),
        (b"<message id='a' id='b'/>", "bad-format"),
        (b"<message><!--forbidden--></message>", "restricted-xml"),
        (
            b"<message><?instruction value?></message>",
            "restricted-xml",
        ),
        (b"<!DOCTYPE message><message/>", "restricted-xml"),
        (
            b"<message><body>&unknown;</body></message>",
            "restricted-xml",
        ),
        (b"<message>\xff</message>", "unsupported-encoding"),
    ] {
        let mut plain = PlainClient::tcp(&server)?;
        plain.open()?;
        plain.send_bytes(payload)?;
        plain.expect_stream_error(condition)?;
        for mut client in [
            Client::secure(&server)?,
            Client::authenticated(&server, "alice", "pencil")?,
            Client::connect(&server, "alice", "pencil", "desktop")?,
        ] {
            client.send_bytes(payload)?;
            client.expect_stream_error(condition)?;
        }
    }
    Ok(())
}

#[test]
fn unknown_elements_after_binding_report_unsupported_stanza_type() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    for payload in ["<other/>", "<other xmlns='urn:test:unknown'/>"] {
        let mut client = Client::connect(&server, "alice", "pencil", "desktop")?;
        client.send(payload)?;
        client.expect_stream_error("unsupported-stanza-type")?;
    }
    Ok(())
}

#[test]
fn stanza_size_limit_is_enforced_before_and_after_tls() -> TestResult {
    let server = Server::configured("", "max_stanza_bytes = 10000")?;
    server.create_account("alice", "pencil")?;
    let payload = format!("<message><body>{}", "x".repeat(10000));
    let mut plain = PlainClient::tcp(&server)?;
    plain.open()?;
    plain.send(&payload)?;
    plain.expect_stream_error("policy-violation")?;
    let mut bound = Client::connect(&server, "alice", "pencil", "desktop")?;
    bound.send(&payload)?;
    bound.expect_stream_error("policy-violation")
}

#[test]
fn stream_footer_closes_each_phase_without_waiting_for_tcp_eof() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut plain = PlainClient::tcp(&server)?;
    plain.open()?;
    plain.close()?;
    Client::secure(&server)?.close()?;
    Client::authenticated(&server, "alice", "pencil")?.close()?;
    Client::connect(&server, "alice", "pencil", "desktop")?.close()
}

#[test]
fn idle_connections_close_at_establishment_authentication_and_binding_deadlines() -> TestResult {
    use std::time::{Duration, Instant};

    let server = Server::configured(
        "",
        "connection_establishment_timeout_secs = 1\nauthentication_timeout_secs = 1\nresource_binding_timeout_secs = 1",
    )?;
    server.create_account("alice", "pencil")?;
    for phase in ["establishment", "authentication", "binding"] {
        let started = Instant::now();
        match phase {
            "establishment" => PlainClient::tcp(&server)?.expect_eof()?,
            "authentication" => Client::secure(&server)?.expect_eof()?,
            _ => Client::authenticated(&server, "alice", "pencil")?.expect_eof()?,
        }
        let elapsed = started.elapsed();
        assert!(
            (Duration::from_secs(1)..Duration::from_secs(4)).contains(&elapsed),
            "{phase} closed after {elapsed:?}, expected a one-second idle deadline"
        );
    }
    Ok(())
}

#[test]
fn tcp_eof_releases_connection_capacity_before_and_after_the_opening() -> TestResult {
    let server = Server::configured("", "max_connections_per_ip = 1")?;
    for opened in [false, true] {
        let mut client = PlainClient::tcp(&server)?;
        if opened {
            client.open()?;
        }
        client.transport().shutdown(std::net::Shutdown::Write)?;
        client.expect_eof()?;
        let mut replacement = PlainClient::tcp(&server)?;
        replacement.open()?;
        replacement.close()?;
    }
    Ok(())
}

#[test]
fn plaintext_after_starttls_proceed_is_rejected_as_a_tls_failure() -> TestResult {
    use std::io::Read;
    let server = Server::start()?;
    let mut client = PlainClient::tcp(&server)?;
    client.open()?;
    client.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")?;
    client.receive()?.assert_name(TLS_NAMESPACE, "proceed");
    client.send(OPEN)?;
    let mut received = Vec::new();
    match client.into_inner().take(1024).read_to_end(&mut received) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(error) => return Err(error.into()),
    }
    assert!(!received.windows(7).any(|bytes| bytes == b"<stream"));
    assert!(
        server
            .wait_for_log("outcome=\"tls_failure\"")?
            .contains("stream disconnected")
    );
    Ok(())
}
