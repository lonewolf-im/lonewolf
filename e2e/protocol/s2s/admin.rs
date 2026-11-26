// SPDX-License-Identifier: Apache-2.0

use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::bidi::outbound_listener;
use super::negotiation::SingleServer;
use super::{C2sSuite, PASSWORD, TestResult, stanza_error};
use crate::support::Client;
use crate::support::clock::{Clock, with_clock};
use crate::support::federation::{FederatedPair, PairOptions, refused_endpoint};

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

const ALICE_CHAT: &str =
    "<message to='bob@b.test/phone' type='chat'><body>hello Bob</body></message>";
const BOB_CHAT: &str =
    "<message to='alice@a.test/desk' type='chat'><body>hello Alice</body></message>";
const ALICE_DELIVERY: &str = "<message xmlns='jabber:client' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' xml:lang='en'><body>hello Bob</body></message>";
const BOB_DELIVERY: &str = "<message xmlns='jabber:client' from='bob@b.test/phone' to='alice@a.test/desk' type='chat' xml:lang='en'><body>hello Alice</body></message>";

fn pair_options(bidirectional: Option<bool>) -> PairOptions {
    PairOptions {
        a_bidirectional: bidirectional,
        b_bidirectional: bidirectional,
        a_extensions: "'roster', 'ping'".into(),
        b_extensions: "'roster', 'ping'".into(),
        ..PairOptions::default()
    }
}

fn connect_pair(pair: &FederatedPair) -> TestResult<(Client, Client)> {
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    Ok((
        pair.a.connect("alice", PASSWORD, "desk")?,
        pair.b.connect("bob", PASSWORD, "phone")?,
    ))
}

fn connection_page(suite: &C2sSuite, target: &str) -> TestResult<Value> {
    let (status, page) = suite.admin_get(target)?;
    assert_eq!(status, 200, "{target}: {page}");
    Ok(page)
}

fn connections(page: &Value) -> TestResult<&[Value]> {
    page["connections"]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("missing connections array: {page}").into())
}

#[test]
fn shared_connection_is_listed_once_on_each_server() -> TestResult {
    let mut pair = FederatedPair::start("a.test", "b.test", pair_options(None))?;
    let (mut alice, mut bob) = connect_pair(&pair)?;
    alice.send(ALICE_CHAT)?;
    bob.expect_xml(ALICE_DELIVERY)?;
    bob.send(BOB_CHAT)?;
    alice.expect_xml(BOB_DELIVERY)?;
    pair.a.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"success\"} 1",
    )?;

    let a_page = connection_page(&pair.a, CONNECTIONS)?;
    let a_connections = connections(&a_page)?;
    assert_eq!(a_connections.len(), 1, "{a_page}");
    let outbound = &a_connections[0];
    assert_eq!(outbound["direction"], "outbound");
    assert_eq!(outbound["bidirectional"], true);
    assert_eq!(outbound["local_domain"], "a.test");
    assert_eq!(outbound["remote_domain"], "b.test");
    let remote_address = outbound["remote_address"]
        .as_str()
        .ok_or("missing peer address")?
        .parse::<SocketAddr>()?;
    assert!(pair.b.s2s_addresses()?.contains(&remote_address));
    for field in ["bytes_received", "bytes_sent"] {
        assert!(
            outbound[field].as_u64().is_some_and(|bytes| bytes > 0),
            "{outbound}"
        );
    }

    let b_page = connection_page(&pair.b, CONNECTIONS)?;
    let b_connections = connections(&b_page)?;
    assert_eq!(b_connections.len(), 1, "{b_page}");
    let inbound = &b_connections[0];
    assert_eq!(inbound["direction"], "inbound");
    assert_eq!(inbound["bidirectional"], true);
    assert_eq!(inbound["local_domain"], "b.test");
    assert_eq!(inbound["remote_domain"], "a.test");

    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn separate_connections_are_listed_per_direction() -> TestResult {
    let mut pair = FederatedPair::start("a.test", "b.test", pair_options(Some(false)))?;
    let (mut alice, mut bob) = connect_pair(&pair)?;
    alice.send(ALICE_CHAT)?;
    bob.expect_xml(ALICE_DELIVERY)?;
    bob.send(BOB_CHAT)?;
    alice.expect_xml(BOB_DELIVERY)?;

    for (suite, local, remote) in [(&pair.a, "a.test", "b.test"), (&pair.b, "b.test", "a.test")] {
        let page = connection_page(suite, CONNECTIONS)?;
        let entries = connections(&page)?;
        assert_eq!(entries.len(), 2, "{page}");
        for direction in ["inbound", "outbound"] {
            let connection = entries
                .iter()
                .find(|entry| entry["direction"] == direction)
                .ok_or_else(|| format!("missing {direction} connection: {page}"))?;
            assert_eq!(connection["bidirectional"], false);
            assert_eq!(connection["local_domain"], local);
            assert_eq!(connection["remote_domain"], remote);
            assert_eq!(connection["tls_mode"], "starttls");
            assert_eq!(connection["tls_version"], "TLSv1.3");
        }
    }

    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn listing_pages_and_filters_live_connections() -> TestResult {
    let mut pair = FederatedPair::start("a.test", "b.test", pair_options(Some(false)))?;
    let (mut alice, mut bob) = connect_pair(&pair)?;
    alice.send(ALICE_CHAT)?;
    bob.expect_xml(ALICE_DELIVERY)?;
    bob.send(BOB_CHAT)?;
    alice.expect_xml(BOB_DELIVERY)?;

    let first_page = connection_page(&pair.a, "/v1/s2s/connections?limit=1")?;
    let first_entries = connections(&first_page)?;
    assert_eq!(first_entries.len(), 1, "{first_page}");
    let cursor = first_page["next_cursor"].as_u64().ok_or("missing cursor")?;
    assert_eq!(first_entries[0]["connection_id"], cursor);

    let second_page = connection_page(&pair.a, &format!("{CONNECTIONS}?limit=1&after={cursor}"))?;
    let second_entries = connections(&second_page)?;
    assert_eq!(second_entries.len(), 1, "{second_page}");
    let second_id = second_entries[0]["connection_id"]
        .as_u64()
        .ok_or("missing second connection ID")?;
    assert!(second_id > cursor, "{second_page}");
    assert_eq!(second_page.get("next_cursor"), Some(&Value::Null));

    let matching_page = connection_page(&pair.a, "/v1/s2s/connections?remote_domain=B.TEST")?;
    let matching_entries = connections(&matching_page)?;
    assert_eq!(matching_entries.len(), 2, "{matching_page}");
    assert_eq!(matching_entries[0]["connection_id"], cursor);
    assert_eq!(matching_entries[1]["connection_id"], second_id);
    assert_eq!(matching_page.get("next_cursor"), Some(&Value::Null));
    let missing_page = connection_page(&pair.a, "/v1/s2s/connections?remote_domain=c.test")?;
    assert_eq!(
        missing_page,
        json!({"connections": [], "next_cursor": null})
    );
    let (status, error) = pair
        .a
        .admin_get("/v1/s2s/connections?remote_domain=user%40b.test")?;
    assert_eq!(status, 400, "{error}");
    assert_eq!(error, json!({"error": {"code": "invalid_domain"}}));

    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn entries_leave_the_listing_when_the_dialing_server_stops() -> TestResult {
    let mut pair = FederatedPair::start("a.test", "b.test", pair_options(None))?;
    let refused = refused_endpoint()?;
    pair.dns.srv(
        "a.test",
        &[(0, 0, refused.address().port(), "unavailable.a.test")],
    );
    pair.dns.a("unavailable.a.test", Ipv4Addr::LOCALHOST);
    let (mut alice, mut bob) = connect_pair(&pair)?;
    alice.send(ALICE_CHAT)?;
    bob.expect_xml(ALICE_DELIVERY)?;
    bob.send(BOB_CHAT)?;
    alice.expect_xml(BOB_DELIVERY)?;

    let page = connection_page(&pair.b, CONNECTIONS)?;
    let entries = connections(&page)?;
    assert_eq!(entries.len(), 1, "{page}");
    assert_eq!(entries[0]["direction"], "inbound");
    assert_eq!(entries[0]["bidirectional"], true);
    alice.close()?;
    pair.a.stop()?;
    wait_for_connection_count(&pair.b, 0)?;

    bob.send("<message to='alice@a.test/desk' type='chat' id='after-stop'><body>fresh dial fails</body></message>")?;
    let error = bob.receive()?;
    error.assert_name("jabber:client", "message");
    assert_eq!(error.attribute("id"), Some("after-stop"));
    assert_eq!(error.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(error.attribute("to"), Some("bob@b.test/phone"));
    stanza_error(&error, "remote-server-timeout")?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"unreachable\"} 1",
    )?;
    let empty_page = connection_page(&pair.b, CONNECTIONS)?;
    assert_eq!(empty_page, json!({"connections": [], "next_cursor": null}));

    bob.close()?;
    pair.b.stop()?;
    drop(refused);
    pair.dns.stop()
}
