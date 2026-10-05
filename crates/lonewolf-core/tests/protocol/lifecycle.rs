// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use rustls::version;

use super::support::{C2sSuite, Client, SASL_NAMESPACE, TestResult};

#[test]
fn requested_resource_logs_ordered_transitions_without_exposing_jids() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;
    client.bind(Some("desk"))?;
    client.close()?;
    let logs = suite.wait_for_log("stream disconnected")?;
    let events = [
        "connection established",
        "connection authenticated",
        "resource bound",
        "stream disconnected",
    ];
    let lines: Vec<_> = logs
        .lines()
        .filter(|line| events.iter().any(|event| line.contains(event)))
        .collect();
    assert_eq!(lines.len(), events.len(), "{logs}");
    for (line, event) in lines.iter().zip(events) {
        assert!(line.contains(event), "{logs}");
        assert!(line.contains("connection_type=\"c2s\""), "{logs}");
        assert!(line.contains("listener_id=0"), "{logs}");
        assert!(line.contains("worker_id="), "{logs}");
    }
    let connection_id = lines[0]
        .split("connection_id=")
        .nth(1)
        .and_then(|field| field.split_whitespace().next())
        .ok_or("missing connection ID")?;
    for line in &lines[1..] {
        assert!(
            line.contains(&format!("connection_id={connection_id}")),
            "{logs}"
        );
    }
    assert!(lines[0].contains("host=\"localhost\""), "{logs}");
    assert!(lines[1].contains("SCRAM-SHA-256"), "{logs}");
    assert!(lines[2].contains("resource_requested=true"), "{logs}");
    assert!(lines[3].contains("stream_phase=\"bound\""), "{logs}");
    assert!(lines[3].contains("outcome=\"stream_end\""), "{logs}");
    assert!(!logs.contains("alice@localhost"), "{logs}");
    Ok(())
}

#[test]
fn generated_resource_logs_ordered_transitions_without_exposing_jids() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;
    client.bind(None)?;
    client.close()?;
    let logs = suite.wait_for_log("stream disconnected")?;
    let events = [
        "connection established",
        "connection authenticated",
        "resource bound",
        "stream disconnected",
    ];
    let lines: Vec<_> = logs
        .lines()
        .filter(|line| events.iter().any(|event| line.contains(event)))
        .collect();
    assert_eq!(lines.len(), events.len(), "{logs}");
    for (line, event) in lines.iter().zip(events) {
        assert!(line.contains(event), "{logs}");
        assert!(line.contains("connection_type=\"c2s\""), "{logs}");
        assert!(line.contains("listener_id=0"), "{logs}");
        assert!(line.contains("worker_id="), "{logs}");
    }
    let connection_id = lines[0]
        .split("connection_id=")
        .nth(1)
        .and_then(|field| field.split_whitespace().next())
        .ok_or("missing connection ID")?;
    for line in &lines[1..] {
        assert!(
            line.contains(&format!("connection_id={connection_id}")),
            "{logs}"
        );
    }
    assert!(lines[0].contains("host=\"localhost\""), "{logs}");
    assert!(lines[1].contains("SCRAM-SHA-256"), "{logs}");
    assert!(lines[2].contains("resource_requested=false"), "{logs}");
    assert!(lines[3].contains("stream_phase=\"bound\""), "{logs}");
    assert!(lines[3].contains("outcome=\"stream_end\""), "{logs}");
    assert!(!logs.contains("alice@localhost"), "{logs}");
    Ok(())
}

#[test]
fn authentication_deadline_ends_at_sasl_success() -> TestResult {
    let suite = C2sSuite::with_limits(
        "authentication_timeout_secs = 2\nresource_binding_timeout_secs = 5",
    )?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    let started = Instant::now();
    client
        .scram(
            "alice",
            "pencil",
            "SCRAM-SHA-256-PLUS",
            Some("tls-exporter"),
        )?
        .assert_name(SASL_NAMESPACE, "success");
    std::thread::sleep(Duration::from_millis(2100).saturating_sub(started.elapsed()));
    let mut client = client.restart();
    client.open()?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn failed_exporter_proof_requires_a_fresh_tls_connection() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    for version in [&version::TLS12, &version::TLS13] {
        for mechanism in ["SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS"] {
            let mut client = Client::secure_with_versions(&suite, &[version])?;
            client
                .scram("alice", "wrong", mechanism, Some("tls-exporter"))?
                .assert_xml(
                    "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
                )?;
            client.expect_end()?;

            let mut fresh = Client::secure_with_versions(&suite, &[version])?;
            fresh
                .scram("alice", "pencil", mechanism, Some("tls-exporter"))?
                .assert_name(SASL_NAMESPACE, "success");
            let mut fresh = fresh.restart();
            fresh.open()?;
            assert_eq!(fresh.bind(Some("desk"))?, "alice@localhost/desk");
            fresh.close()?;
        }
    }
    Ok(())
}

#[test]
fn rejected_exporter_identity_closes_after_the_sasl_failure() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    for (username, authzid, condition) in [
        ("missing", None, "not-authorized"),
        ("alice", Some("bob@localhost"), "invalid-authzid"),
    ] {
        let mut client = suite.unauthenticated_client()?;
        let exchange = client.begin_scram(
            username,
            "pencil",
            "SCRAM-SHA-256-PLUS",
            Some("tls-exporter"),
            authzid,
        )?;
        client.finish_scram(exchange)?.assert_xml(&format!(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><{condition}/></failure>"
        ))?;
        client.expect_end()?;
    }
    Ok(())
}

#[test]
fn exporter_abort_and_malformed_final_close_after_the_sasl_failure() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    for (response, condition) in [
        (
            "<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>",
            "aborted",
        ),
        (
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>!</response>",
            "incorrect-encoding",
        ),
        (
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>=</response>",
            "malformed-request",
        ),
    ] {
        for initial_response in [true, false] {
            let mut client = suite.unauthenticated_client()?;
            if initial_response {
                client.send_sasl_auth("SCRAM-SHA-256-PLUS", "p=tls-exporter,,n=alice,r=nonce")?;
            } else {
                client.send_sasl_auth("SCRAM-SHA-256-PLUS", "")?;
                assert!(client.receive_sasl_challenge()?.is_empty());
                client.send_sasl_response("p=tls-exporter,,n=alice,r=nonce")?;
            }
            assert!(client.receive_sasl_challenge()?.starts_with("r=nonce"));
            client.send(response)?;
            client.expect_xml(&format!(
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><{condition}/></failure>"
            ))?;
            client.expect_end()?;
        }
    }
    Ok(())
}

#[test]
fn replacing_an_exporter_attempt_closes_without_starting_another_mechanism() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    for version in [&version::TLS12, &version::TLS13] {
        for (mechanism, first) in [
            ("SCRAM-SHA-1-PLUS", "p=tls-exporter,,n=alice,r=next"),
            (
                "SCRAM-SHA-256-PLUS",
                "p=tls-server-end-point,,n=alice,r=next",
            ),
            ("SCRAM-SHA-256", "n,,n=alice,r=next"),
        ] {
            let mut client = Client::secure_with_versions(&suite, &[version])?;
            client.send_sasl_auth("SCRAM-SHA-256-PLUS", "p=tls-exporter,,n=alice,r=nonce")?;
            assert!(client.receive_sasl_challenge()?.starts_with("r=nonce"));
            client.send_sasl_auth(mechanism, first)?;
            client.expect_end()?;
        }
    }
    Ok(())
}

#[test]
fn exporter_is_not_reserved_before_a_valid_client_first() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.send_sasl_auth("SCRAM-SHA-256-PLUS", "p=tls-exporter,,n=alice")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><malformed-request/></failure>",
    )?;
    client.send_sasl_auth("SCRAM-SHA-256-PLUS", "")?;
    assert!(client.receive_sasl_challenge()?.is_empty());
    client.send("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
    client
        .scram(
            "alice",
            "pencil",
            "SCRAM-SHA-256-PLUS",
            Some("tls-exporter"),
        )?
        .assert_name(SASL_NAMESPACE, "success");
    let mut client = client.restart();
    client.open()?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn endpoint_and_non_plus_attempts_keep_their_retry_budget() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    for (mechanism, binding, first) in [
        ("SCRAM-SHA-256", None, "n,,n=alice,r=nonce"),
        (
            "SCRAM-SHA-256-PLUS",
            Some("tls-server-end-point"),
            "p=tls-server-end-point,,n=alice,r=nonce",
        ),
    ] {
        let mut client = suite.unauthenticated_client()?;
        client
            .scram("alice", "wrong", mechanism, binding)?
            .assert_xml(
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
            )?;
        client.send_sasl_auth(mechanism, first)?;
        client.receive_sasl_challenge()?;
        client.send("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
        client
            .expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
        client
            .scram("alice", "pencil", mechanism, binding)?
            .assert_name(SASL_NAMESPACE, "success");
        let mut client = client.restart();
        client.open()?;
        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.close()?;
    }
    Ok(())
}

#[test]
fn local_error_waits_for_delayed_xml_and_tls_closure() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desk")?;
    client.send("<unsupported/>")?;
    client.receive()?.assert_xml("<stream:error xmlns:stream='http://etherx.jabber.org/streams'><unsupported-stanza-type xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>")?;
    client.expect_footer()?;
    client.expect_no_tls_input()?;
    client.send("<message to='alice@localhost/desk' id='discarded'/></stream:stream>")?;
    client.expect_tls_close()?;
    client.expect_tcp_open()?;
    client.send_tls_close()?;
    client.expect_tcp_eof()
}

#[test]
fn peer_footer_waits_for_delayed_tls_close_notify() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desk")?;
    client.send("</stream:stream>")?;
    client.expect_footer()?;
    client.expect_tls_close()?;
    client.expect_tcp_open()?;
    client.send_tls_close()?;
    client.expect_tcp_eof()
}

#[test]
fn silent_peer_close_uses_one_five_second_budget() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desk")?;
    let started = Instant::now();
    client.send("<unsupported/>")?;
    client.receive()?;
    client.expect_footer()?;
    std::thread::sleep(Duration::from_secs(4));
    client.send("</stream:stream>")?;
    client.expect_tls_close()?;
    client.expect_tcp_eof()?;
    assert!(started.elapsed() >= Duration::from_millis(4800));
    assert!(started.elapsed() < Duration::from_secs(7));
    Ok(())
}

#[test]
fn authentication_deadline_caps_a_local_close_wait() -> TestResult {
    let suite = C2sSuite::with_limits("authentication_timeout_secs = 1")?;
    let mut client = suite.unauthenticated_client()?;
    let started = Instant::now();
    client.send("<message/>")?;
    client.receive()?;
    client.expect_footer()?;
    client.expect_eof()?;
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[test]
fn account_retirement_preserves_a_partial_read_while_recreation_proceeds() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut retiring = suite.connect("alice", "pencil", "desk")?;
    retiring.send("<message to='alice@localhost/desk' id='discarded'")?;
    std::thread::sleep(Duration::from_millis(50));
    suite.delete_account("alice")?;
    retiring
        .receive()?
        .child("urn:ietf:params:xml:ns:xmpp-streams", "not-authorized")?;
    retiring.expect_footer()?;
    retiring.expect_no_tls_input()?;
    suite.create_account("alice", "pencil")?;
    let mut recreated = suite.connect("alice", "pencil", "desk")?;
    retiring.send("/></stream:stream>")?;
    retiring.expect_tls_close()?;
    retiring.send_tls_close()?;
    retiring.expect_tcp_eof()?;
    recreated.send("<message to='alice@localhost/desk' id='sentinel'/>")?;
    recreated.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel'/>")?;
    recreated.close()
}

#[test]
fn unavailable_presence_and_resource_retirement_precede_a_silent_peer_wait() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut observer = suite.connect("alice", "pencil", "observer")?;
    observer.send("<presence/>")?;
    observer.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/observer' to='alice@localhost'/>",
    )?;
    let mut retiring = suite.connect("alice", "pencil", "desk")?;
    retiring.send("<presence/>")?;
    retiring.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/observer' to='alice@localhost'/>",
    )?;
    retiring.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    observer.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    retiring.send("<unsupported/>")?;
    retiring.receive()?;
    retiring.expect_footer()?;
    observer.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost' type='unavailable'/>")?;
    let mut replacement = suite.connect("alice", "pencil", "desk")?;
    retiring.expect_no_tls_input()?;
    retiring.send("</stream:stream>")?;
    retiring.expect_tls_close()?;
    retiring.send_tls_close()?;
    retiring.expect_tcp_eof()?;
    observer.send("<message to='alice@localhost/observer' id='sentinel'/>")?;
    observer.expect_xml("<message xmlns='jabber:client' from='alice@localhost/observer' to='alice@localhost/observer' id='sentinel'/>")?;
    replacement.close()?;
    observer.close()
}
