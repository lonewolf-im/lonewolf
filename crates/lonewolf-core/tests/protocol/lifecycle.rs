// SPDX-License-Identifier: Apache-2.0

use crate::support::{ALTERNATE_PASSWORD, NEW_PASSWORD, PASSWORD};

use std::time::{Duration, Instant};

use rustls::version;

use super::support::{C2sSuite, Client, SASL_NAMESPACE, TestResult};

#[test]
fn resource_assignment_logs_ordered_transitions_without_exposing_jids() -> TestResult {
    for (resource, requested) in [(Some("desk"), true), (None, false)] {
        let mut suite = C2sSuite::start()?;
        suite.create_account("alice", ALTERNATE_PASSWORD)?;
        let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
        client.bind(resource)?;
        client.close()?;
        let logs = suite.stop_with_logs()?;
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
        let assignment = format!("resource_requested={requested}");
        assert!(
            lines[2].contains(&assignment),
            "missing {assignment}: {logs}"
        );
        assert!(lines[3].contains("stream_phase=\"bound\""), "{logs}");
        assert!(lines[3].contains("outcome=\"stream_end\""), "{logs}");
        assert!(!logs.contains("alice@localhost"), "{logs}");
    }
    Ok(())
}

#[test]
fn authentication_deadline_ends_at_sasl_success() -> TestResult {
    let suite = C2sSuite::with_limits(
        "authentication_timeout_secs = 2\nresource_binding_timeout_secs = 5",
    )?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.unauthenticated_client()?;
    let started = Instant::now();
    client
        .scram(
            "alice",
            ALTERNATE_PASSWORD,
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
fn failed_exporter_proof_allows_non_exporter_retries_on_the_same_connection() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    for version in [&version::TLS12, &version::TLS13] {
        for mechanism in ["SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS"] {
            for (retry_mechanism, binding) in [
                ("SCRAM-SHA-256", None),
                ("SCRAM-SHA-256-PLUS", Some("tls-server-end-point")),
            ] {
                let mut client = Client::secure_with_versions(&suite, &[version])?;
                client
                .scram("alice", "wrong", mechanism, Some("tls-exporter"))?
                .assert_xml(
                    "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
                )?;
                client
                    .scram("alice", ALTERNATE_PASSWORD, retry_mechanism, binding)?
                    .assert_name(SASL_NAMESPACE, "success");
                let mut client = client.restart();
                client.open()?;
                assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
                client.close()?;
            }
        }
    }
    Ok(())
}

#[test]
fn rejected_exporter_identity_allows_a_non_exporter_retry() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    for (username, authzid, condition) in [
        ("missing", None, "not-authorized"),
        ("alice", Some("bob@localhost"), "invalid-authzid"),
    ] {
        let mut client = suite.unauthenticated_client()?;
        let exchange = client.begin_scram(
            username,
            ALTERNATE_PASSWORD,
            "SCRAM-SHA-256-PLUS",
            Some("tls-exporter"),
            authzid,
        )?;
        client.finish_scram(exchange)?.assert_xml(&format!(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><{condition}/></failure>"
        ))?;
        client
            .scram("alice", ALTERNATE_PASSWORD, "SCRAM-SHA-256", None)?
            .assert_name(SASL_NAMESPACE, "success");
        let mut client = client.restart();
        client.open()?;
        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.close()?;
    }
    Ok(())
}

#[test]
fn exporter_abort_and_malformed_final_allow_a_non_exporter_retry() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
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
            client
                .scram("alice", ALTERNATE_PASSWORD, "SCRAM-SHA-256", None)?
                .assert_name(SASL_NAMESPACE, "success");
            let mut client = client.restart();
            client.open()?;
            assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
            client.close()?;
        }
    }
    Ok(())
}

#[test]
fn replacing_an_exporter_attempt_authenticates_without_the_exporter() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    for version in [&version::TLS12, &version::TLS13] {
        for (mechanism, binding) in [
            ("SCRAM-SHA-256-PLUS", Some("tls-server-end-point")),
            ("SCRAM-SHA-256", None),
        ] {
            let mut client = Client::secure_with_versions(&suite, &[version])?;
            client.send_sasl_auth("SCRAM-SHA-256-PLUS", "p=tls-exporter,,n=alice,r=nonce")?;
            assert!(client.receive_sasl_challenge()?.starts_with("r=nonce"));
            client
                .scram("alice", ALTERNATE_PASSWORD, mechanism, binding)?
                .assert_name(SASL_NAMESPACE, "success");
            let mut client = client.restart();
            client.open()?;
            assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
            client.close()?;
        }
    }
    Ok(())
}

#[test]
fn failed_exporter_proof_refuses_exporter_reuse_and_allows_a_fresh_connection() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    for version in [&version::TLS12, &version::TLS13] {
        for mechanism in ["SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS"] {
            let mut client = Client::secure_with_versions(&suite, &[version])?;
            client
                .scram("alice", "wrong", mechanism, Some("tls-exporter"))?
                .assert_xml(
                    "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
                )?;
            client.send_sasl_auth(mechanism, "p=tls-exporter,,n=alice,r=next")?;
            client.expect_stream_error("policy-violation")?;

            let mut fresh = Client::secure_with_versions(&suite, &[version])?;
            fresh
                .scram("alice", ALTERNATE_PASSWORD, mechanism, Some("tls-exporter"))?
                .assert_name(SASL_NAMESPACE, "success");
            let mut fresh = fresh.restart();
            fresh.open()?;
            assert_eq!(fresh.bind(Some("desk"))?, "alice@localhost/desk");
            fresh.close()?;
        }
    }
    suite.wait_for_closed("channel_binding_reused", 4)?;
    Ok(())
}

#[test]
fn reusing_exporter_after_failure_abort_or_replacement_is_a_policy_violation() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    for version in [&version::TLS12, &version::TLS13] {
        for username in ["alice", "missing"] {
            for ending in ["proof", "abort", NEW_PASSWORD] {
                let mut client = Client::secure_with_versions(&suite, &[version])?;
                if ending == "proof" {
                    client
                        .scram(username, "wrong", "SCRAM-SHA-256-PLUS", Some("tls-exporter"))?
                        .assert_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>")?;
                } else {
                    client.send_sasl_auth(
                        "SCRAM-SHA-256-PLUS",
                        &format!("p=tls-exporter,,n={username},r=nonce"),
                    )?;
                    assert!(client.receive_sasl_challenge()?.starts_with("r=nonce"));
                    if ending == "abort" {
                        client.send("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
                        client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
                    }
                }
                client
                    .scram(username, "wrong", "SCRAM-SHA-256", None)?
                    .assert_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>")?;
                client.send_sasl_auth(
                    "SCRAM-SHA-1-PLUS",
                    &format!("p=tls-exporter,,n={username},r=next"),
                )?;
                client.expect_stream_error("policy-violation")?;
            }
        }
    }
    suite.wait_for_closed("channel_binding_reused", 12)?;
    Ok(())
}

#[test]
fn replacing_an_exporter_attempt_with_exporter_is_a_policy_violation() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    for initial_response in [true, false] {
        let mut client = suite.unauthenticated_client()?;
        client.send_sasl_auth("SCRAM-SHA-256-PLUS", "p=tls-exporter,,n=alice,r=nonce")?;
        assert!(client.receive_sasl_challenge()?.starts_with("r=nonce"));
        if initial_response {
            client.send_sasl_auth("SCRAM-SHA-1-PLUS", "p=tls-exporter,,n=alice,r=next")?;
        } else {
            client.send_sasl_auth("SCRAM-SHA-1-PLUS", "")?;
            assert!(client.receive_sasl_challenge()?.is_empty());
            client.send_sasl_response("p=tls-exporter,,n=alice,r=next")?;
        }
        client.expect_stream_error("policy-violation")?;
    }
    suite.wait_for_closed("channel_binding_reused", 2)?;
    Ok(())
}

#[test]
fn mixed_exporter_and_non_exporter_failures_share_the_retry_budget() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    for username in ["alice", "missing"] {
        let mut client = suite.unauthenticated_client()?;
        for (mechanism, binding) in [
            ("SCRAM-SHA-256-PLUS", Some("tls-exporter")),
            ("SCRAM-SHA-256", None),
            ("SCRAM-SHA-256-PLUS", Some("tls-server-end-point")),
        ] {
            client
                .scram(username, "wrong", mechanism, binding)?
                .assert_xml(
                    "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
                )?;
        }
        client.expect_stream_error("policy-violation")?;
    }
    suite.wait_for_closed("authentication_attempts_exceeded", 2)?;
    Ok(())
}

#[test]
fn replacing_exporter_and_non_exporter_attempts_shares_the_retry_budget() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.unauthenticated_client()?;
    client.send_sasl_auth("SCRAM-SHA-256-PLUS", "p=tls-exporter,,n=alice,r=first")?;
    assert!(client.receive_sasl_challenge()?.starts_with("r=first"));
    client.send_sasl_auth("SCRAM-SHA-256", "n,,n=alice,r=second")?;
    assert!(client.receive_sasl_challenge()?.starts_with("r=second"));
    client
        .scram(
            "alice",
            "wrong",
            "SCRAM-SHA-256-PLUS",
            Some("tls-server-end-point"),
        )?
        .assert_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
        )?;
    client.expect_stream_error("policy-violation")?;
    suite.wait_for_closed("authentication_attempts_exceeded", 1)?;
    Ok(())
}

#[test]
fn exporter_is_not_reserved_before_a_valid_client_first() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
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
            ALTERNATE_PASSWORD,
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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
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
            .scram("alice", ALTERNATE_PASSWORD, mechanism, binding)?
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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut retiring = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let idle = suite.wait_for_metrics("all stanza chunks available", |body| {
        matches!(
            (
                pool_chunks(body, "lonewolf_stanza_pool_available_chunks"),
                pool_chunks(body, "lonewolf_stanza_pool_chunks")
            ),
            (Ok(available), Ok(total)) if available == total
        )
    })?;
    let available = pool_chunks(&idle, "lonewolf_stanza_pool_available_chunks")?;
    retiring.send("<message to='alice@localhost/desk' id='discarded'><body>partial")?;
    let reading = suite.wait_for_metrics("partial stanza owns an arena", |body| {
        pool_chunks(body, "lonewolf_stanza_pool_available_chunks")
            .is_ok_and(|current| current < available)
    })?;
    assert!(pool_chunks(&reading, "lonewolf_stanza_pool_available_chunks")? < available);
    suite.delete_account("alice")?;
    retiring
        .receive()?
        .child("urn:ietf:params:xml:ns:xmpp-streams", "not-authorized")?;
    retiring.expect_footer()?;
    retiring.expect_no_tls_input()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut recreated = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    retiring.send("</body></message></stream:stream>")?;
    retiring.expect_tls_close()?;
    retiring.send_tls_close()?;
    retiring.expect_tcp_eof()?;
    recreated.send("<message to='alice@localhost/desk' id='sentinel'/>")?;
    recreated.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel'/>")?;
    recreated.close()
}

fn pool_chunks(body: &str, series: &str) -> TestResult<u64> {
    let mut samples = body
        .lines()
        .filter_map(|line| line.strip_prefix(series)?.strip_prefix('{'));
    let first = samples.next().ok_or("missing stanza pool samples")?;
    let count = |sample: &str| -> TestResult<u64> {
        Ok(sample
            .rsplit_once(' ')
            .ok_or("missing pool chunk count")?
            .1
            .parse()?)
    };
    samples.try_fold(count(first)?, |total, sample| Ok(total + count(sample)?))
}

#[test]
fn unavailable_presence_and_resource_retirement_precede_a_silent_peer_wait() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut observer = suite.connect("alice", ALTERNATE_PASSWORD, "observer")?;
    observer.send("<presence/>")?;
    observer.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/observer' to='alice@localhost'/>",
    )?;
    let mut retiring = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
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
    let mut replacement = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
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

#[test]
fn account_iq_dispatch_observes_completed_deletion_and_recreation() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<iq type='get' id='before' to='bob@localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='before' from='bob@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='bob@localhost'/></iq>")?;
    alice.send("<iq type='set' id='before-set' to='bob@localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='before-set' from='bob@localhost' to='alice@localhost/desk'/>")?;
    suite.delete_account("bob")?;
    for kind in ["get", "set"] {
        alice.send(&format!("<iq type='{kind}' id='deleted-{kind}' to='bob@localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>"))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='deleted-{kind}' from='bob@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
    }
    suite.create_account("bob", PASSWORD)?;
    alice.send(
        "<iq type='get' id='after' to='bob@localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='after' from='bob@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='bob@localhost'/></iq>")?;
    alice.send("<iq type='set' id='after-set' to='bob@localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='after-set' from='bob@localhost' to='alice@localhost/desk'/>")?;
    alice.send(
        "<iq type='get' id='calls'><query xmlns='urn:lonewolf:test:iq' calls='true'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='calls' to='alice@localhost/desk'><calls xmlns='urn:lonewolf:test:iq' gets='2' sets='2'/></iq>")?;
    alice.close()
}
