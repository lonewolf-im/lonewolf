// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use super::support::{C2sSuite, TestResult};

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
    client.authenticate("alice", "pencil")?;
    std::thread::sleep(Duration::from_millis(2100).saturating_sub(started.elapsed()));
    let mut client = client.restart();
    client.open()?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}
