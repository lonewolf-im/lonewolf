// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::bidi::outbound_listener;
use super::negotiation::SingleServer;
use super::{C2sSuite, PASSWORD, TestResult};
use crate::support::clock::{Clock, with_clock};

const CONNECTIONS: &str = "/v1/s2s/connections";

fn wait_for_connection_count(suite: &C2sSuite, count: usize) -> TestResult<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (status, page) = suite.admin_get(CONNECTIONS)?;
        assert_eq!(status, 200, "{page}");
        let connections = page["connections"]
            .as_array()
            .ok_or("missing connections array")?;
        if connections.len() == count {
            return Ok(page);
        }
        assert!(
            Instant::now() < deadline,
            "expected {count} connections: {page}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn inbound_peer_is_listed_while_authenticated() -> TestResult {
    let mut server = SingleServer::start("")?;
    let mut peer = server.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(server.client_config()?)?;
    peer.expect_external_offered()?;
    let (status, page) = server.suite.admin_get(CONNECTIONS)?;
    assert_eq!(status, 200, "{page}");
    assert_eq!(page, json!({"connections": [], "next_cursor": null}));

    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    let page = wait_for_connection_count(&server.suite, 1)?;
    let connection = &page["connections"][0];
    assert_eq!(connection["direction"], "inbound");
    assert_eq!(connection["bidirectional"], false);
    assert_eq!(connection["local_domain"], "a.test");
    assert_eq!(connection["remote_domain"], "b.test");
    assert_eq!(connection["tls_mode"], "starttls");
    assert_eq!(connection["tls_version"], "TLSv1.3");
    connection["remote_address"]
        .as_str()
        .ok_or("missing peer address")?
        .parse::<SocketAddr>()?;
    for field in ["bytes_received", "bytes_sent"] {
        assert!(
            connection[field].as_u64().is_some_and(|bytes| bytes > 0),
            "{connection}"
        );
    }

    peer.close()?;
    wait_for_connection_count(&server.suite, 0)?;
    server.stop()
}

#[test]
fn federation_inactive_server_answers_s2s_inactive() -> TestResult {
    let mut server = C2sSuite::start()?;
    let (status, body) = server.admin_get(CONNECTIONS)?;
    assert_eq!(status, 404);
    assert_eq!(body, json!({"error": {"code": "s2s_inactive"}}));
    server.stop()
}

#[test]
fn outbound_link_is_listed_while_connected() -> TestResult {
    let mut server = with_clock(|| SingleServer::start(""))?;
    let (listener, config) = outbound_listener(&server)?;
    server.suite.create_account("alice", PASSWORD)?;
    let mut alice = server.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>open link</body></message>")?;
    let mut peer = listener.accept("b.test", "a.test", config, true)?;
    peer.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat'><body>open link</body></message>")?;

    let (status, page) = server.suite.admin_get(CONNECTIONS)?;
    assert_eq!(status, 200, "{page}");
    let connections = page["connections"]
        .as_array()
        .ok_or("missing connections array")?;
    assert_eq!(connections.len(), 1, "{page}");
    let connection = &connections[0];
    assert_eq!(connection["direction"], "outbound");
    assert_eq!(connection["bidirectional"], false);
    assert_eq!(connection["local_domain"], "a.test");
    assert_eq!(connection["remote_domain"], "b.test");
    assert_eq!(
        connection["remote_address"],
        listener.address()?.to_string()
    );
    assert_eq!(connection["tls_mode"], "starttls");
    assert_eq!(connection["tls_version"], "TLSv1.3");
    for field in ["bytes_received", "bytes_sent"] {
        assert!(
            connection[field].as_u64().is_some_and(|bytes| bytes > 0),
            "{connection}"
        );
    }

    Clock::at(server.suite.fixture_path()).expire_ms(600_000)?;
    peer.answer_close()?;
    wait_for_connection_count(&server.suite, 0)?;
    alice.close()?;
    server.stop()
}

#[test]
fn bidirectional_outbound_link_reports_bidi() -> TestResult {
    let mut server = SingleServer::start_bidirectional("")?;
    let (listener, config) = outbound_listener(&server)?;
    server.suite.create_account("alice", PASSWORD)?;
    let mut alice = server.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>open link</body></message>")?;
    let (mut peer, requested) = listener.accept_offering_bidi("b.test", "a.test", config)?;
    assert!(requested);
    peer.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat'><body>open link</body></message>")?;

    let (status, page) = server.suite.admin_get(CONNECTIONS)?;
    assert_eq!(status, 200, "{page}");
    let connections = page["connections"]
        .as_array()
        .ok_or("missing connections array")?;
    assert_eq!(connections.len(), 1, "{page}");
    assert_eq!(connections[0]["direction"], "outbound");
    assert_eq!(connections[0]["bidirectional"], true);

    peer.close()?;
    alice.close()?;
    server.stop()
}
