// SPDX-License-Identifier: Apache-2.0

use crate::support::{ALTERNATE_PASSWORD, OTHER_PASSWORD};

use crate::support::{C2sSuite, TestResult};

fn sample_value(body: &str, series: &str) -> Option<f64> {
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
}

#[test]
fn metrics_endpoint_reports_build_information() -> TestResult {
    let mut suite = C2sSuite::with_metrics()?;
    let body = suite.wait_for_metric("lonewolf_log_dropped_lines_total 0")?;
    assert_eq!(
        sample_value(
            &body,
            "lonewolf_build_info{version=\"integration-test\",branch=\"test\",commit=\"test\"}"
        ),
        Some(1.0),
        "{body}"
    );
    assert_eq!(
        sample_value(&body, "lonewolf_log_dropped_lines_total"),
        Some(0.0)
    );
    assert!(
        body.lines()
            .any(|line| line == "lonewolf_stanza_pool_chunks{chunk_bytes=\"524288\"} 2"),
        "{body}"
    );
    assert!(body.ends_with("# EOF\n"), "{body}");
    suite.stop()
}

#[test]
fn storage_commits_are_reported_per_store() -> TestResult {
    let mut suite = C2sSuite::with_metrics()?;
    let series = "lonewolf_storage_commit_duration_seconds_count{store=\"primary\"}";
    let before = suite.scrape_metrics()?;
    let before = sample_value(&before, series).ok_or("missing storage commit count")?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let body = suite.scrape_metrics()?;
    let after = sample_value(&body, series).ok_or("missing storage commit count")?;
    assert!(after >= before + 1.0, "{body}");
    assert!(!body.contains("alice"), "{body}");
    suite.stop()
}

#[test]
fn router_sessions_and_message_outcomes_are_reported() -> TestResult {
    let mut suite = C2sSuite::with_metrics()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    suite.create_account("bob", OTHER_PASSWORD)?;
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", OTHER_PASSWORD, "desk")?;
    suite.wait_for_metric("lonewolf_router_sessions 2")?;
    alice.send(
        "<message to='bob@localhost/desk' type='chat' id='routed'><body>Hello</body></message>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='routed'><body>Hello</body></message>")?;
    suite.wait_for_metric("lonewolf_router_messages_total{outcome=\"routed\"} 1")?;
    bob.close()?;
    suite.wait_for_metric("lonewolf_router_sessions 1")?;
    alice
        .send("<message to='bob@localhost' type='chat' id='stored'><body>Hello</body></message>")?;
    let body = suite.wait_for_metric("lonewolf_router_messages_total{outcome=\"stored\"} 1")?;
    assert!(!body.contains("alice"), "{body}");
    assert!(!body.contains("bob"), "{body}");
    alice.close()?;
    suite.stop()
}

#[test]
fn client_connection_lifecycle_is_reported() -> TestResult {
    let mut suite = C2sSuite::with_metrics()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
    client.bind(Some("desk"))?;
    let body = suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 1")?;
    for sample in [
        "lonewolf_c2s_connections_accepted_total{listener=\"0\"} 1",
        "lonewolf_c2s_unauthenticated_connections 0",
        "lonewolf_c2s_phase_duration_seconds_count{phase=\"establishing\"} 1",
        "lonewolf_c2s_phase_duration_seconds_count{phase=\"authenticating\"} 1",
        "lonewolf_c2s_phase_duration_seconds_count{phase=\"binding\"} 1",
    ] {
        assert!(body.lines().any(|line| line == sample), "{body}");
    }
    client.close()?;
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"bound\",outcome=\"stream_end\"} 1")?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    let body = suite.wait_for_metric("lonewolf_c2s_session_duration_seconds_count 1")?;
    assert!(!body.contains("alice"), "{body}");
    suite.stop()
}

#[test]
fn admission_rejections_are_reported_by_limit() -> TestResult {
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    let mut suite = C2sSuite::with_metrics_settings(
        "connection_attempts_per_ip = { per_second = 1, burst = 1 }",
        10,
    )?;
    let connections: Vec<_> = (0..5)
        .map(|_| TcpStream::connect(suite.address))
        .collect::<Result<_, _>>()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let body = suite.scrape_metrics()?;
        if sample_value(&body, "lonewolf_c2s_connections_rejected_total{listener=\"0\",reason=\"connection_attempts_per_ip\"}").is_some_and(|value| value >= 1.0) {
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!("missing admission rejection metric: {body}").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(connections);
    suite.stop()
}

#[test]
fn authentication_and_binding_outcomes_are_reported() -> TestResult {
    let mut suite = C2sSuite::with_metrics_settings("", 1)?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.unauthenticated_client()?;
    client.send("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'/>")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
    )?;
    let failure = client.scram("alice", "wrong", "SCRAM-SHA-256", None)?;
    failure.assert_name("urn:ietf:params:xml:ns:xmpp-sasl", "failure");
    client.authenticate("alice", ALTERNATE_PASSWORD)?;
    let mut client = client.restart();
    client
        .open()?
        .child("urn:ietf:params:xml:ns:xmpp-bind", "bind")?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    suite.wait_for_metric("lonewolf_c2s_stanzas_received_total{listener=\"0\",kind=\"iq\"} 1")?;
    suite.wait_for_metric("lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"iq\"} 1")?;
    let mut second = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
    second.send("<iq type='set' id='full'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>phone</resource></bind></iq>")?;
    second.expect_xml("<iq xmlns='jabber:client' type='error' id='full'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    suite.wait_for_metric("lonewolf_c2s_stanzas_received_total{listener=\"0\",kind=\"iq\"} 2")?;
    suite.wait_for_metric("lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"iq\"} 2")?;
    for sample in [
        "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"none\",outcome=\"invalid_mechanism\"} 1",
        "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256\",outcome=\"not_authorized\"} 1",
        "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256\",outcome=\"success\"} 2",
        "lonewolf_c2s_resource_bindings_total{listener=\"0\",outcome=\"success\"} 1",
        "lonewolf_c2s_resource_bindings_total{listener=\"0\",outcome=\"resource_constraint\"} 1",
    ] {
        let body = suite.wait_for_metric(sample)?;
        assert!(!body.contains("alice"), "{body}");
    }
    second.close()?;
    client.close()?;
    suite.stop()
}

#[test]
fn stanza_byte_and_rate_limit_counters_are_reported() -> TestResult {
    use std::time::{Duration, Instant};

    let mut suite = C2sSuite::with_metrics_settings(
        "new_recipients_per_connection = { per_second = 1, burst = 1 }",
        10,
    )?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    alice.send("<message to='bob@localhost' type='chat'/><message to='carol@localhost' type='chat'/><message to='dave@localhost' type='chat'/>")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let (body, rejected) = loop {
        let body = suite.scrape_metrics()?;
        let rejected = sample_value(&body, "lonewolf_c2s_rate_limited_total{listener=\"0\",limit=\"new_recipients_per_connection\"}").unwrap_or(0.0);
        if rejected >= 1.0
            && sample_value(
                &body,
                "lonewolf_c2s_stanzas_received_total{listener=\"0\",kind=\"message\"}",
            ) == Some(3.0)
            && sample_value(
                &body,
                "lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"message\"}",
            ) == Some(rejected)
        {
            break (body, rejected);
        }
        if Instant::now() >= deadline {
            return Err(format!("missing stanza traffic metrics: {body}").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        sample_value(
            &body,
            "lonewolf_c2s_stanzas_received_total{listener=\"0\",kind=\"message\"}"
        ),
        Some(3.0),
        "{body}"
    );
    assert_eq!(
        sample_value(
            &body,
            "lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"message\"}"
        ),
        Some(rejected),
        "{body}"
    );
    for direction in ["received", "sent"] {
        assert!(
            sample_value(
                &body,
                &format!("lonewolf_c2s_{direction}_bytes_total{{listener=\"0\"}}")
            )
            .is_some_and(|value| value > 0.0),
            "{body}"
        );
    }
    assert!(body.lines().any(|line| line.starts_with("lonewolf_c2s_rate_limited_total{listener=\"0\",limit=\"incoming_stanzas_per_connection\"} ")), "{body}");
    for account in ["alice", "bob", "carol", "dave"] {
        assert!(!body.contains(account), "{body}");
    }
    let mut replies = 0.0;
    while replies < rejected {
        let reply = alice.receive()?;
        reply.assert_name("jabber:client", "message");
        reply.child("jabber:client", "error")?;
        replies += 1.0;
    }
    alice.close()?;
    suite.stop()
}
