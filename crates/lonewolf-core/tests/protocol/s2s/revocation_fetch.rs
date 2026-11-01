// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;
use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use super::super::support::federation::{
    crl_server::{CrlResponse, CrlServer},
    peer::{self, RawS2sListener},
};
use super::super::support::{PASSWORD, TestResult};
use super::negotiation::{SingleServer, authentication, expect_bounce};

#[test]
fn revoked_peer_is_rejected_with_a_fetched_crl_in_both_directions() -> TestResult {
    let mut http = CrlServer::start()?;
    let mut server = SingleServer::start("")?;
    let listener = RawS2sListener::bind()?;
    server.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "peer.b.test")],
    );
    server.dns.a("peer.b.test", Ipv4Addr::LOCALHOST);
    let key = server.ca.server_with_crl_urls(
        server.directory.path(),
        "revoked-peer",
        &["b.test"],
        &[http.url("revoked.crl")],
    )?;
    let now = OffsetDateTime::now_utc();
    let der = server.ca.crl(
        &[(key.cert[0].clone(), None)],
        now - Duration::minutes(1),
        now + Duration::days(1),
        1,
    )?;
    http.serve("revoked.crl", CrlResponse::Body(der));
    let client = peer::client_config(&server.ca, Arc::clone(&key))?;
    let serving = peer::server_config(&server.ca, key, "a.test")?;
    server.suite.create_account("alice", PASSWORD)?;
    let mut alice = server.suite.connect("alice", PASSWORD, "desk")?;

    let mut inbound = server.connect()?;
    inbound.expect_starttls_features()?;
    let mut inbound = inbound.start_tls_with_header(
        client,
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='b.test' to='a.test'>",
        None,
    )?;
    inbound.expect_stream_error("not-authorized")?;
    authentication(&server.suite, "inbound", "certificate_revoked", 1)?;
    server.suite.wait_for_metric("lonewolf_s2s_revocation_checks_total{direction=\"inbound\",source=\"fetched\",phase=\"handshake\",status=\"revoked\",reason=\"none\"} 1")?;

    alice.send("<message type='chat' id='revoked-peer' to='bob@b.test/phone'><body>must bounce</body></message>")?;
    let mut outbound = listener.accept("b.test", "a.test", serving, true)?;
    outbound.answer_close()?;
    expect_bounce(&mut alice, "revoked-peer", "remote-server-timeout")?;
    authentication(&server.suite, "outbound", "certificate_revoked", 1)?;
    server.suite.wait_for_metric("lonewolf_s2s_revocation_checks_total{direction=\"outbound\",source=\"fetched\",phase=\"handshake\",status=\"revoked\",reason=\"none\"} 1")?;
    assert_eq!(http.requests("revoked.crl"), 1);

    alice.close()?;
    server.stop()?;
    http.stop()?;
    Ok(())
}

#[test]
fn peers_without_a_usable_crl_federate_with_an_unknown_status() -> TestResult {
    let mut http = CrlServer::start()?;
    let mut server = SingleServer::start("")?;
    let listener = RawS2sListener::bind()?;
    server.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "peer.b.test")],
    );
    server.dns.a("peer.b.test", Ipv4Addr::LOCALHOST);
    let key = server.ca.server_with_crl_urls(
        server.directory.path(),
        "unknown-peer",
        &["b.test"],
        &[http.url("missing.crl")],
    )?;
    http.serve("missing.crl", CrlResponse::Status(404));
    let client = peer::client_config(&server.ca, Arc::clone(&key))?;
    let serving = peer::server_config(&server.ca, key, "a.test")?;
    server.suite.create_account("alice", PASSWORD)?;
    let mut alice = server.suite.connect("alice", PASSWORD, "desk")?;

    let mut inbound = server.connect()?;
    inbound.expect_starttls_features()?;
    let mut inbound = inbound.start_tls(client)?;
    inbound.expect_external_offered()?;
    inbound.auth_external(Some("b.test"))?;
    inbound.expect_sasl_success()?;
    let mut inbound = inbound.restart("b.test", "a.test")?;
    inbound.send("<message type='chat' from='bob@b.test/phone' to='alice@a.test/desk'><body>unknown inbound</body></message>")?;
    let received = alice.receive()?;
    received.assert_name("jabber:client", "message");
    assert_eq!(received.attribute("from"), Some("bob@b.test/phone"));
    assert_eq!(
        received.child("jabber:client", "body")?.text,
        "unknown inbound"
    );
    authentication(&server.suite, "inbound", "success", 1)?;
    server.suite.wait_for_metric("lonewolf_s2s_revocation_checks_total{direction=\"inbound\",source=\"fetched\",phase=\"handshake\",status=\"unknown\",reason=\"fetch_failed\"} 1")?;

    alice.send(
        "<message type='chat' to='bob@b.test/phone'><body>unknown outbound</body></message>",
    )?;
    let mut outbound = listener.accept("b.test", "a.test", serving, true)?;
    let received = outbound.receive()?;
    received.assert_name("jabber:server", "message");
    assert_eq!(received.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(
        received.child("jabber:server", "body")?.text,
        "unknown outbound"
    );
    authentication(&server.suite, "outbound", "success", 1)?;
    server.suite.wait_for_metric("lonewolf_s2s_revocation_checks_total{direction=\"outbound\",source=\"fetched\",phase=\"handshake\",status=\"unknown\",reason=\"fetch_failed\"} 1")?;
    assert_eq!(http.requests("missing.crl"), 1);

    inbound.close()?;
    outbound.close()?;
    alice.close()?;
    server.stop()?;
    http.stop()?;
    Ok(())
}
