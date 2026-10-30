// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use super::super::support::federation::{
    FederatedPair, PairOptions,
    peer::{self, RawS2sListener},
    thread_result,
};
use super::super::support::{PASSWORD, TestResult};
use super::negotiation::{SingleServer, authentication, closed};

#[test]
fn idle_outbound_stream_closes_and_reconnects() -> TestResult {
    let mut fixture = SingleServer::start("[limits.s2s]\nidle_timeout_secs=1")?;
    let listener = RawS2sListener::bind()?;
    fixture.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "server.b.test")],
    );
    fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
    let config = peer::server_config(
        &fixture.ca,
        fixture
            .ca
            .server(fixture.directory.path(), "peer", &["b.test"])?,
        "a.test",
    )?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    for (index, body) in ["first connection", "second connection"]
        .into_iter()
        .enumerate()
    {
        alice.send(&format!(
            "<message to='bob@b.test/phone' type='chat'><body>{body}</body></message>"
        ))?;
        let mut peer = listener.accept("b.test", "a.test", Arc::clone(&config), true)?;
        peer.receive()?.assert_xml(&format!("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat'><body>{body}</body></message>"))?;
        authentication(&fixture.suite, "outbound", "success", index as u64 + 1)?;
        peer.answer_close()?;
        closed(&fixture.suite, "outbound", "idle", index as u64 + 1)?;
    }
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 2")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_links{state=\"ready\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn peer_certificate_expiry_resets_stream() -> TestResult {
    {
        let mut fixture = SingleServer::start("")?;
        let listener = RawS2sListener::bind()?;
        fixture.dns.srv(
            "b.test",
            &[(0, 0, listener.address()?.port(), "server.b.test")],
        );
        fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
        let key = fixture
            .ca
            .short_lived(fixture.directory.path(), "b.test", 4)?;
        let config = peer::server_config(&fixture.ca, key, "a.test")?;
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send(
            "<message to='bob@b.test/phone' type='chat'><body>before expiry</body></message>",
        )?;
        let mut peer = listener.accept("b.test", "a.test", config, true)?;
        peer.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat'><body>before expiry</body></message>")?;
        authentication(&fixture.suite, "outbound", "success", 1)?;
        peer.expect_stream_error("reset")?;
        closed(&fixture.suite, "outbound", "certificate_expired", 1)?;
        alice.close()?;
        fixture.stop()?;
    }
    let mut pair = FederatedPair::start("a.test", "b.test", PairOptions::default())?;
    pair.ca.server_until(
        pair.b.fixture_path(),
        "host",
        &["b.test"],
        time::OffsetDateTime::now_utc() + time::Duration::seconds(4),
    )?;
    pair.b.restart()?;
    pair.dns.srv(
        "b.test",
        &[(0, 0, pair.b.s2s_addresses()?[0].port(), "b.b.test")],
    );
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat'><body>short certificate</body></message>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' xml:lang='en' from='alice@a.test/desk' to='bob@b.test/phone' type='chat'><body>short certificate</body></message>")?;
    authentication(&pair.a, "outbound", "success", 1)?;
    authentication(&pair.b, "inbound", "success", 1)?;
    closed(&pair.a, "outbound", "certificate_expired", 1)?;
    closed(&pair.b, "inbound", "peer_error", 1)?;
    bob.close()?;
    let previous = pair
        .b
        .stop_with_s2s_state()?
        .ok_or("missing pre-restart state")?;
    assert_eq!(previous.queued_stanzas, 0);
    pair.ca.server(pair.b.fixture_path(), "host", &["b.test"])?;
    pair.b.restart()?;
    assert!(!pair.b.fixture_path().join("s2s-shutdown.json").exists());
    pair.dns.srv(
        "b.test",
        &[(0, 0, pair.b.s2s_addresses()?[0].port(), "b.b.test")],
    );
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat'><body>fresh certificate</body></message>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' xml:lang='en' from='alice@a.test/desk' to='bob@b.test/phone' type='chat'><body>fresh certificate</body></message>")?;
    authentication(&pair.a, "outbound", "success", 2)?;
    authentication(&pair.b, "inbound", "success", 1)?;
    pair.a
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 2")?;
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn shutdown_during_negotiation_completes_within_deadline() -> TestResult {
    let mut fixture = SingleServer::start("[limits.s2s]\nnegotiation_timeout_secs=60")?;
    let listener = RawS2sListener::bind()?;
    fixture.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "server.b.test")],
    );
    fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat'><body>cancel negotiation</body></message>",
    )?;
    let peer = listener.accept_until_proceed("b.test", "a.test")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_links{state=\"connecting\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 1")?;
    alice.close()?;
    let started = Instant::now();
    let state = fixture
        .suite
        .stop_with_s2s_state()?
        .ok_or("missing active shutdown state")?;
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(state.dropped_shutdown, 1);
    assert_eq!(state.dropped_connection_lost, 0);
    assert_eq!(state.queued_stanzas, 0);
    assert_eq!(state.queued_bytes, 0);
    drop(peer);
    let receipt = fixture.suite.fixture_path().join("s2s-shutdown.json");
    let old = std::fs::read(&receipt)?;
    std::fs::remove_file(&receipt)?;
    assert!(fixture.suite.stop_with_s2s_state().is_err());
    std::fs::write(&receipt, b"malformed")?;
    assert!(fixture.suite.stop_with_s2s_state().is_err());
    let mut invalid: serde_json::Value = serde_json::from_slice(&old)?;
    let state = invalid
        .as_object_mut()
        .ok_or("receipt is not an object")?
        .remove("state")
        .ok_or("receipt has no state")?;
    std::fs::write(&receipt, serde_json::to_vec(&invalid)?)?;
    assert!(fixture.suite.stop_with_s2s_state().is_err());
    invalid["state"] = serde_json::Value::Null;
    std::fs::write(&receipt, serde_json::to_vec(&invalid)?)?;
    assert_eq!(fixture.suite.stop_with_s2s_state()?, None);
    invalid["state"] = state;
    invalid["pid"] = serde_json::json!(0);
    std::fs::write(&receipt, serde_json::to_vec(&invalid)?)?;
    assert!(fixture.suite.stop_with_s2s_state().is_err());
    std::fs::write(&receipt, &old)?;
    fixture.suite.restart()?;
    assert!(!receipt.exists());
    let state = fixture
        .suite
        .stop_with_s2s_state()?
        .ok_or("missing restarted shutdown state")?;
    assert_eq!(state.dropped_shutdown, 0);
    assert_eq!(state.dropped_connection_lost, 0);
    assert_eq!(state.queued_stanzas, 0);
    assert_eq!(state.queued_bytes, 0);
    let fresh: serde_json::Value = serde_json::from_slice(&std::fs::read(receipt)?)?;
    let old: serde_json::Value = serde_json::from_slice(&old)?;
    assert_ne!(old["pid"], fresh["pid"]);
    fixture.dns.stop()
}

#[test]
fn shutdown_with_queued_stanzas_drops_and_counts_them() -> TestResult {
    let mut fixture = SingleServer::start(
        "[limits.s2s]\nmax_queued_stanzas_per_link=2\nnegotiation_timeout_secs=60",
    )?;
    let listener = RawS2sListener::bind()?;
    fixture.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "server.b.test")],
    );
    fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>queued first</body></message>")?;
    let peer = listener.accept_until_proceed("b.test", "a.test")?;
    alice
        .send("<message to='bob@b.test/phone' type='chat'><body>queued second</body></message>")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_links{state=\"connecting\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 2")?;
    fixture
        .suite
        .wait_for_metrics("queued bytes without a written stanza", |body| {
            super::sample(body, "lonewolf_s2s_outbound_queued_bytes").is_ok_and(|count| count > 0)
                && !body
                    .lines()
                    .any(|line| line.starts_with("lonewolf_s2s_stanzas_sent_total"))
        })?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
    alice.close()?;
    let state = fixture
        .suite
        .stop_with_s2s_state()?
        .ok_or("missing active shutdown state")?;
    assert_eq!(state.dropped_shutdown, 2);
    assert_eq!(state.dropped_connection_lost, 0);
    assert_eq!(state.queued_stanzas, 0);
    assert_eq!(state.queued_bytes, 0);
    drop(peer);
    fixture.dns.stop()
}

#[test]
fn shutdown_sends_system_shutdown_to_inbound_peers() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_offered()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    authentication(&fixture.suite, "inbound", "success", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 1")?;
    let (reply, stopped) = std::thread::scope(|scope| {
        let suite = &mut fixture.suite;
        let worker = scope.spawn(move || thread_result(suite.stop_with_s2s_state()));
        let reply = peer.expect_stream_error("system-shutdown");
        let stopped = worker.join();
        (reply, stopped)
    });
    reply?;
    let state = stopped
        .map_err(|_| "shutdown worker panicked")??
        .ok_or("missing active shutdown state")?;
    assert_eq!(state.dropped_shutdown, 0);
    assert_eq!(state.dropped_connection_lost, 0);
    assert_eq!(state.queued_stanzas, 0);
    assert_eq!(state.queued_bytes, 0);
    fixture.dns.stop()
}
