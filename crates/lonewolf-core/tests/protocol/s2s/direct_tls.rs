// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;

use super::super::support::federation::{
    FederationCa,
    peer::{self, RawS2sListener},
};
use super::super::support::{PASSWORD, TestResult};
use super::negotiation::{SingleServer, authentication, closed, expect_bounce};

fn route(listener: &RawS2sListener) -> TestResult<String> {
    Ok(format!(
        "[s2s.routes]\n'b.test'=[{{address='{}',tls_mode='direct'}}]",
        listener.address()?
    ))
}

fn config(fixture: &SingleServer, alpn: &[u8]) -> TestResult<Arc<rustls::ServerConfig>> {
    let mut config = peer::server_config(
        &fixture.ca,
        fixture
            .ca
            .server(fixture.directory.path(), "peer", &["b.test"])?,
        "a.test",
    )?;
    if !alpn.is_empty() {
        Arc::get_mut(&mut config)
            .ok_or("shared config")?
            .alpn_protocols
            .push(alpn.to_vec());
    }
    Ok(config)
}

fn assert_no_xml_until_close(mut socket: TcpStream) -> TestResult {
    let mut remaining = Vec::new();
    match socket.read_to_end(&mut remaining) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
        Err(error) => return Err(error.into()),
    }
    assert!(
        remaining.is_empty(),
        "unexpected bytes after ClientHello: {remaining:?}"
    );
    Ok(())
}

#[test]
fn direct_tls_static_route_sends_client_hello_then_external_and_protected_restart() -> TestResult {
    for alpn in [b"xmpp-server".as_slice(), b"".as_slice()] {
        let listener = RawS2sListener::bind()?.direct_tls();
        let mut fixture = SingleServer::start(&route(&listener)?)?;
        let config = config(&fixture, alpn)?;
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='direct'><body>protected</body></message>")?;
        let mut peer = listener.accept("b.test", "a.test", config, true)?;
        peer.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='direct'><body>protected</body></message>")?;
        authentication(&fixture.suite, "outbound", "success", 1)?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"static\"} 1")?;
        for service in ["_xmpp-server._tcp.b.test", "_xmpps-server._tcp.b.test"] {
            assert_eq!(fixture.dns.query_count(service, RecordType::SRV), 0);
        }
        peer.close()?;
        closed(&fixture.suite, "outbound", "stream_end", 1)?;
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn direct_tls_rejects_wrong_role_alpn() -> TestResult {
    let listener = RawS2sListener::bind()?.direct_tls();
    let mut fixture = SingleServer::start(&route(&listener)?)?;
    let config = config(&fixture, b"xmpp-client")?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat' id='alpn'><body>wrong role</body></message>",
    )?;
    assert!(listener.accept("b.test", "a.test", config, true).is_err());
    expect_bounce(&mut alice, "alpn", "remote-server-timeout")?;
    authentication(&fixture.suite, "outbound", "tls_failure", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"outbound\"} 0")?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn direct_tls_rejects_wrong_name_untrusted_and_numeric_target_only_certificates() -> TestResult {
    for kind in ["wrong_name", "untrusted", "target_only"] {
        let listener = RawS2sListener::bind()?.direct_tls();
        let mut fixture = SingleServer::start(&route(&listener)?)?;
        let other = tempfile::tempdir()?;
        let untrusted = FederationCa::new(other.path())?;
        let key = match kind {
            "wrong_name" => fixture.ca.wrong_name(fixture.directory.path(), "b.test")?,
            "untrusted" => untrusted.server(other.path(), "peer", &["b.test"])?,
            _ => fixture
                .ca
                .server(fixture.directory.path(), "target", &["127.0.0.1"])?,
        };
        let config = peer::server_config(&fixture.ca, key, "a.test")?;
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='certificate'><body>identity required</body></message>")?;
        assert!(listener.accept("b.test", "a.test", config, true).is_err());
        expect_bounce(&mut alice, "certificate", "remote-server-timeout")?;
        authentication(
            &fixture.suite,
            "outbound",
            if kind == "untrusted" {
                "certificate_untrusted"
            } else {
                "certificate_name"
            },
            1,
        )?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_connections{direction=\"outbound\"} 0")?;
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn direct_tls_failure_falls_back_to_separately_configured_starttls() -> TestResult {
    let direct = RawS2sListener::bind()?.direct_tls();
    let starttls = RawS2sListener::bind()?;
    let extra = format!(
        "[s2s.routes]\n'b.test'=[{{address='{}',tls_mode='direct'}}, '{}']",
        direct.address()?,
        starttls.address()?
    );
    let mut fixture = SingleServer::start(&extra)?;
    let wrong = peer::server_config(
        &fixture.ca,
        fixture.ca.wrong_name(fixture.directory.path(), "b.test")?,
        "a.test",
    )?;
    let valid = config(&fixture, b"")?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>failover</body></message>")?;
    assert!(direct.accept("b.test", "a.test", wrong, true).is_err());
    let mut peer = starttls.accept("b.test", "a.test", valid, true)?;
    assert_eq!(
        peer.receive()?.child("jabber:server", "body")?.text,
        "failover"
    );
    authentication(&fixture.suite, "outbound", "success", 1)?;
    let metrics = fixture.suite.scrape_metrics()?;
    assert!(!metrics.contains(
        "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"certificate_name\"}"
    ));
    peer.close()?;
    closed(&fixture.suite, "outbound", "stream_end", 1)?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn direct_tls_handshake_timeout_sends_no_xml_and_releases_connection() -> TestResult {
    let listener = RawS2sListener::bind()?.direct_tls();
    let mut fixture = SingleServer::start(&format!(
        "{}\n[limits.s2s]\nnegotiation_timeout_secs=1",
        route(&listener)?
    ))?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat' id='timeout'><body>silent TLS</body></message>",
    )?;
    let (socket, _) = listener.accept_client_hello("b.test")?;
    assert_no_xml_until_close(socket)?;
    expect_bounce(&mut alice, "timeout", "remote-server-timeout")?;
    authentication(&fixture.suite, "outbound", "timeout", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"outbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn direct_tls_shutdown_cancels_handshake_without_xml_and_releases_queued_work() -> TestResult {
    let listener = RawS2sListener::bind()?.direct_tls();
    let mut fixture = SingleServer::start(&format!(
        "{}\n[limits.s2s]\nnegotiation_timeout_secs=60",
        route(&listener)?
    ))?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>cancel TLS</body></message>")?;
    let (socket, _) = listener.accept_client_hello("b.test")?;
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
        .ok_or("missing shutdown state")?;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(state.dropped_shutdown, 1);
    assert_eq!(state.dropped_connection_lost, 0);
    assert_eq!(state.queued_stanzas, 0);
    assert_eq!(state.queued_bytes, 0);
    assert_no_xml_until_close(socket)?;
    fixture.dns.stop()
}
