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

mod discovery;
mod identities;
mod pairs;
mod protected;

const TIMEOUT: Duration = Duration::from_secs(10);

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
        transport_attempts(&fixture.suite, "outbound", &[("direct", "success", 1)])?;
        transport_connections(&fixture.suite, "outbound", 0, 1)?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"static\"} 1")?;
        for service in ["_xmpp-server._tcp.b.test", "_xmpps-server._tcp.b.test"] {
            assert_eq!(fixture.dns.query_count(service, RecordType::SRV), 0);
        }
        peer.close()?;
        closed(&fixture.suite, "outbound", "stream_end", 1)?;
        transport_connections(&fixture.suite, "outbound", 0, 0)?;
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
    transport_attempts(&fixture.suite, "outbound", &[("direct", "tls_failure", 1)])?;
    transport_connections(&fixture.suite, "outbound", 0, 0)?;
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
    transport_attempts(
        &fixture.suite,
        "outbound",
        &[
            ("direct", "certificate_name", 1),
            ("starttls", "success", 1),
        ],
    )?;
    transport_connections(&fixture.suite, "outbound", 1, 0)?;
    let metrics = fixture.suite.scrape_metrics()?;
    assert!(!metrics.contains(
        "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"certificate_name\"}"
    ));
    peer.close()?;
    closed(&fixture.suite, "outbound", "stream_end", 1)?;
    transport_connections(&fixture.suite, "outbound", 0, 0)?;
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
    transport_attempts(&fixture.suite, "outbound", &[("direct", "timeout", 1)])?;
    transport_connections(&fixture.suite, "outbound", 0, 0)?;
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
    transport_connections(&fixture.suite, "outbound", 0, 1)?;
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
    assert_eq!(state.transport_cancelled, [[0, 0], [0, 1]]);
    assert_eq!(state.transport_connections, [[0; 2]; 2]);
    assert_eq!(state.connections, [0; 2]);
    assert_eq!(state.authentication_protocol, [0, 1]);
    assert_no_xml_until_close(socket)?;
    fixture.dns.stop()
}

pub(super) fn inbound_fixture(extra: &str, bidi: bool) -> TestResult<SingleServer> {
    let mut fixture = if bidi {
        SingleServer::start_bidirectional(extra)?
    } else {
        SingleServer::start(extra)?
    };
    let path = fixture.suite.fixture_path().join("lonewolf.toml");
    let config = std::fs::read_to_string(&path)?;
    let original = "listeners = [{ address = \"127.0.0.1:0\" }]";
    assert!(config.contains(original));
    std::fs::write(
        path,
        config.replacen(
            original,
            "listeners=[{address='127.0.0.1:0'}, {address='127.0.0.1:0',tls_mode='direct'}]",
            1,
        ),
    )?;
    fixture.suite.restart()?;
    assert_eq!(fixture.suite.s2s_addresses()?.len(), 2);
    Ok(fixture)
}

fn inbound_header(from: Option<&str>, to: &str) -> String {
    let from = from
        .map(|from| format!(" from='{from}'"))
        .unwrap_or_default();
    format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server'{from} to='{to}' version='1.0'>"
    )
}

#[test]
fn inbound_direct_tls_external_bidi_limits_and_optional_alpn_share_starttls_flow() -> TestResult {
    use super::super::support::federation::peer::RawS2sPeer;
    for alpn in [false, true] {
        let mut fixture = inbound_fixture("", true)?;
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        let mut config = (*fixture.client_config()?).clone();
        if alpn {
            config.alpn_protocols = vec![b"xmpp-server".to_vec()];
        }
        let mut inbound = RawS2sPeer::tls_first(
            fixture.suite.s2s_addresses()?[1],
            "b.test",
            "a.test",
            Arc::new(config),
        )?;
        assert_eq!(
            inbound.alpn_protocol(),
            alpn.then_some(b"xmpp-server".as_slice())
        );
        inbound.open_protected(&inbound_header(Some("b.test"), "a.test"), Some("b.test"))?;
        inbound.expect_external_and_bidi_offered()?;
        inbound.request_bidi()?;
        inbound.auth_external(None)?;
        inbound
            .receive()?
            .assert_xml("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
        inbound.send("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>=</response>")?;
        inbound.expect_sasl_success()?;
        let mut inbound = inbound.restart("b.test", "a.test")?;
        authentication(&fixture.suite, "inbound", "success", 1)?;
        transport_attempts(&fixture.suite, "inbound", &[("direct", "success", 1)])?;
        transport_connections(&fixture.suite, "inbound", 0, 1)?;
        inbound.send("<message from='bob@b.test/phone' to='alice@a.test/desk' type='chat' id='direct-in'><body>Inbound</body></message>")?;
        alice.expect_xml("<message xmlns='jabber:client' from='bob@b.test/phone' to='alice@a.test/desk' type='chat' id='direct-in'><body>Inbound</body></message>")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='bidi-direct'><body>Reply</body></message>")?;
        inbound.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='bidi-direct'><body>Reply</body></message>")?;
        inbound.close()?;
        closed(&fixture.suite, "inbound", "stream_end", 1)?;
        let mut legacy = fixture.connect()?;
        legacy.expect_starttls_features()?;
        let mut legacy = legacy.start_tls(fixture.client_config()?)?;
        legacy.expect_external_and_bidi_offered()?;
        legacy.auth_external(Some("b.test"))?;
        legacy.expect_sasl_success()?;
        let mut legacy = legacy.restart("b.test", "a.test")?;
        authentication(&fixture.suite, "inbound", "success", 2)?;
        transport_attempts(
            &fixture.suite,
            "inbound",
            &[("direct", "success", 1), ("starttls", "success", 1)],
        )?;
        transport_connections(&fixture.suite, "inbound", 1, 0)?;
        legacy.close()?;
        closed(&fixture.suite, "inbound", "stream_end", 2)?;
        transport_connections(&fixture.suite, "inbound", 0, 0)?;
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn inbound_direct_tls_requires_bound_to_from_and_remote_certificate_identity() -> TestResult {
    use super::super::support::{federation::peer::RawS2sPeer, tls};
    for (kind, condition, outcome) in [
        ("to_mismatch", "host-unknown", "host_unknown"),
        ("missing_from", "not-authorized", "missing_from"),
        ("no_certificate", "not-authorized", "no_certificate"),
        ("wrong_domain", "not-authorized", "certificate_name"),
        ("local_spoof", "invalid-from", "invalid_from"),
    ] {
        let mut fixture = inbound_fixture("", false)?;
        let config = match kind {
            "no_certificate" => Arc::new(tls::client_config(
                fixture.ca.roots()?,
                rustls::DEFAULT_VERSIONS,
            )?),
            "wrong_domain" => peer::client_config(
                &fixture.ca,
                fixture.ca.wrong_name(fixture.directory.path(), "b.test")?,
            )?,
            _ => fixture.client_config()?,
        };
        let mut inbound = RawS2sPeer::tls_first(
            fixture.suite.s2s_addresses()?[1],
            "b.test",
            "a.test",
            config,
        )?;
        let from = match kind {
            "missing_from" => None,
            "local_spoof" => Some("a.test"),
            _ => Some("b.test"),
        };
        let to = if kind == "to_mismatch" {
            "other.test"
        } else {
            "a.test"
        };
        inbound.open_protected(&inbound_header(from, to), None)?;
        inbound.expect_stream_error(condition)?;
        authentication(&fixture.suite, "inbound", outcome, 1)?;
        transport_attempts(&fixture.suite, "inbound", &[("direct", outcome, 1)])?;
        transport_connections(&fixture.suite, "inbound", 0, 0)?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn inbound_direct_tls_external_authzid_mismatch_rejects_and_cleans_up() -> TestResult {
    use super::super::support::federation::peer::RawS2sPeer;
    let mut fixture = inbound_fixture("", false)?;
    let mut inbound = RawS2sPeer::tls_first(
        fixture.suite.s2s_addresses()?[1],
        "b.test",
        "a.test",
        fixture.client_config()?,
    )?;
    inbound.open_protected(&inbound_header(Some("b.test"), "a.test"), Some("b.test"))?;
    inbound.expect_external_offered()?;
    for _ in 0..2 {
        inbound.auth_external(Some("other.test"))?;
        inbound.receive()?.assert_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-authzid/></failure>",
        )?;
    }
    inbound.answer_close()?;
    authentication(&fixture.suite, "inbound", "invalid_authzid", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    fixture.stop()
}

#[test]
fn inbound_direct_tls_rejects_untrusted_and_client_auth_only_certificates() -> TestResult {
    use super::super::support::federation::peer::RawS2sPeer;
    for kind in ["untrusted", "client_auth_only"] {
        let mut fixture = inbound_fixture("", false)?;
        let other = tempfile::tempdir()?;
        let other_ca = FederationCa::new(other.path())?;
        let key = if kind == "untrusted" {
            other_ca.server(other.path(), "peer", &["b.test"])?
        } else {
            fixture
                .ca
                .client_auth_only(fixture.directory.path(), "b.test")?
        };
        let config = peer::client_config(&fixture.ca, key)?;
        if let Ok(mut inbound) = RawS2sPeer::tls_first(
            fixture.suite.s2s_addresses()?[1],
            "b.test",
            "a.test",
            config,
        ) {
            assert!(
                inbound
                    .open_protected(&inbound_header(Some("b.test"), "a.test"), None)
                    .is_err()
            );
        }
        authentication(&fixture.suite, "inbound", "tls_failure", 1)?;
        transport_attempts(&fixture.suite, "inbound", &[("direct", "tls_failure", 1)])?;
        transport_connections(&fixture.suite, "inbound", 0, 0)?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn inbound_direct_tls_requires_sni_and_server_alpn_without_plaintext_xml() -> TestResult {
    use rustls::pki_types::ServerName;
    use std::io::Write;
    struct Wire {
        socket: TcpStream,
        first: Option<u8>,
    }
    impl Read for Wire {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let count = self.socket.read(bytes)?;
            if count > 0 && self.first.is_none() {
                self.first = Some(bytes[0]);
            }
            Ok(count)
        }
    }
    impl Write for Wire {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.socket.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.socket.flush()
        }
    }
    let mut fixture = inbound_fixture("", false)?;
    for (name, wrong_role) in [
        (Some("a.test"), true),
        (None, false),
        (Some("unknown.test"), false),
    ] {
        let mut config = (*fixture.client_config()?).clone();
        config.enable_sni = name.is_some();
        if wrong_role {
            config.alpn_protocols = vec![b"xmpp-client".to_vec()];
        }
        let socket = TcpStream::connect_timeout(&fixture.suite.s2s_addresses()?[1], TIMEOUT)?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        socket.set_write_timeout(Some(TIMEOUT))?;
        let mut wire = Wire {
            socket,
            first: None,
        };
        let mut connection = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from(name.unwrap_or("a.test"))?,
        )?;
        let mut result = Ok(());
        while connection.is_handshaking() && result.is_ok() {
            result = connection.complete_io(&mut wire).map(|_| ());
        }
        assert!(result.is_err(), "{name:?}, wrong_role={wrong_role}");
        assert!(
            wire.first.is_none_or(|byte| (20..=23).contains(&byte)),
            "{:?}",
            wire.first
        );
    }
    for sample in [
        "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"tls_failure\"} 1",
        "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"host_unknown\"} 2",
        "lonewolf_s2s_negotiation_duration_seconds_count{direction=\"inbound\"} 3",
        "lonewolf_s2s_connections{direction=\"inbound\"} 0",
    ] {
        fixture.suite.wait_for_metric(sample)?;
    }
    transport_attempts(
        &fixture.suite,
        "inbound",
        &[("direct", "tls_failure", 1), ("direct", "host_unknown", 2)],
    )?;
    transport_connections(&fixture.suite, "inbound", 0, 0)?;
    fixture.stop()
}

#[test]
fn inbound_direct_tls_timeout_malformed_hello_and_shutdown_close_without_xml() -> TestResult {
    use std::io::Write;
    for kind in ["timeout", "malformed", "shutdown"] {
        let mut fixture = inbound_fixture("[limits.s2s]\nnegotiation_timeout_secs=1", false)?;
        let mut socket = TcpStream::connect_timeout(&fixture.suite.s2s_addresses()?[1], TIMEOUT)?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        socket.set_write_timeout(Some(TIMEOUT))?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 1")?;
        if kind == "shutdown" {
            let state = fixture
                .suite
                .stop_with_s2s_state()?
                .ok_or("missing shutdown state")?;
            assert_eq!(state.transport_cancelled, [[0, 1], [0, 0]]);
            assert_eq!(state.transport_connections, [[0; 2]; 2]);
            assert_eq!(state.connections, [0; 2]);
        } else if kind == "malformed" {
            socket.write_all(b"<stream:stream xmlns='jabber:server'>")?;
        }
        assert_no_xml_until_close(socket)?;
        if kind != "shutdown" {
            authentication(
                &fixture.suite,
                "inbound",
                if kind == "timeout" {
                    "timeout"
                } else {
                    "tls_failure"
                },
                1,
            )?;
            fixture
                .suite
                .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
        }
        if kind != "shutdown" {
            transport_attempts(
                &fixture.suite,
                "inbound",
                &[(
                    "direct",
                    if kind == "timeout" {
                        "timeout"
                    } else {
                        "tls_failure"
                    },
                    1,
                )],
            )?;
            transport_connections(&fixture.suite, "inbound", 0, 0)?;
        }
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn inbound_direct_tls_service_requires_registration_covering_certificate_and_federation()
-> TestResult {
    use super::super::support::federation::peer::RawS2sPeer;
    let mut fixture = inbound_fixture("", true)?;
    fixture.ca.server(
        fixture.suite.fixture_path(),
        "host",
        &["a.test", "*.a.test", "uncovered.test"],
    )?;
    let path = fixture.suite.fixture_path().join("lonewolf.toml");
    let config = std::fs::read_to_string(&path)?;
    assert!(config.contains("extensions = []"));
    std::fs::write(
        &path,
        format!(
            "{}\n[hosts.'uncovered.test']\nextensions=['test-service']\n[hosts.'uncovered.test'.tls]\ncertificate_chain_path='certificate-host.pem'\nprivate_key_path='private-key-host.pem'",
            config.replacen("extensions = []", "extensions = ['test-service']", 1)
        ),
    )?;
    fixture.suite.restart()?;
    let mut inbound = RawS2sPeer::tls_first(
        fixture.suite.s2s_addresses()?[1],
        "b.test",
        "echo.a.test",
        fixture.client_config()?,
    )?;
    inbound.open_protected(
        &inbound_header(Some("b.test"), "echo.a.test"),
        Some("b.test"),
    )?;
    inbound.expect_external_and_bidi_offered()?;
    inbound.request_bidi()?;
    inbound.auth_external(Some("b.test"))?;
    inbound.expect_sasl_success()?;
    let mut inbound = inbound.restart("b.test", "echo.a.test")?;
    authentication(&fixture.suite, "inbound", "success", 1)?;
    inbound.send("<message from='bob@b.test/phone' to='room@echo.a.test' type='chat' id='service'><body>Service</body></message>")?;
    inbound.receive()?.assert_xml("<message xmlns='jabber:server' from='room@echo.a.test' to='bob@b.test/phone' type='chat' id='service'><body>Service</body></message>")?;
    inbound.send("<iq from='bob@b.test/phone' to='echo.a.test' type='get' id='direct-service-iq'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    inbound.receive()?.assert_xml("<iq xmlns='jabber:server' from='echo.a.test' to='bob@b.test/phone' type='result' id='direct-service-iq'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='component' type='generic' name='Echo'/><feature var='http://jabber.org/protocol/disco#info'/></query></iq>")?;
    inbound.close()?;
    closed(&fixture.suite, "inbound", "stream_end", 1)?;
    for name in ["unregistered.a.test", "echo.uncovered.test"] {
        assert!(
            RawS2sPeer::tls_first(
                fixture.suite.s2s_addresses()?[1],
                "b.test",
                name,
                fixture.client_config()?
            )
            .is_err(),
            "{name}"
        );
    }
    fixture.suite.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"host_unknown\"} 2",
    )?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    let config = std::fs::read_to_string(&path)?;
    assert!(config.contains("[hosts.\"a.test\"]"));
    std::fs::write(
        &path,
        config.replacen(
            "[hosts.\"a.test\"]",
            "[hosts.\"a.test\"]\nfederation=false",
            1,
        ),
    )?;
    fixture.suite.restart()?;
    assert!(
        RawS2sPeer::tls_first(
            fixture.suite.s2s_addresses()?[1],
            "b.test",
            "a.test",
            fixture.client_config()?
        )
        .is_err()
    );
    authentication(&fixture.suite, "inbound", "host_unknown", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    fixture.stop()
}

#[test]
fn inbound_direct_tls_listener_does_not_override_global_or_host_federation_opt_out() -> TestResult {
    use super::super::support::{
        C2sSuite,
        federation::{FakeDns, FederatedHost},
    };
    for (global, host) in [(false, true), (true, false)] {
        let directory = tempfile::tempdir()?;
        let ca = Arc::new(FederationCa::new(directory.path())?);
        let mut dns = FakeDns::start()?;
        let mut suite = C2sSuite::federated(FederatedHost {
            domain: "a.test".into(),
            revocation: Default::default(),
            enabled: Some(global),
            bidirectional: Some(false),
            federation: Some(host),
            extensions: String::new(),
            extra_toml: String::new(),
            ca,
            dns: dns.address(),
            completion: None,
        })?;
        let path = suite.fixture_path().join("lonewolf.toml");
        let config = std::fs::read_to_string(&path)?;
        let original = "listeners = [{ address = \"127.0.0.1:0\" }]";
        assert!(config.contains(original));
        std::fs::write(
            path,
            config.replacen(
                original,
                "listeners=[{address='127.0.0.1:0',tls_mode='direct'}]",
                1,
            ),
        )?;
        suite.restart()?;
        assert!(suite.s2s.is_none());
        assert!(!suite.scrape_metrics()?.contains("lonewolf_s2s_"));
        suite.create_account("alice", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='disabled-direct'><body>Disabled</body></message>")?;
        expect_bounce(&mut alice, "disabled-direct", "remote-server-not-found")?;
        for service in ["_xmpp-server._tcp.b.test", "_xmpps-server._tcp.b.test"] {
            assert_eq!(dns.query_count(service, RecordType::SRV), 0);
        }
        alice.close()?;
        suite.stop()?;
        dns.stop()?;
    }
    Ok(())
}

pub(super) fn transport_attempts(
    suite: &super::super::support::C2sSuite,
    direction: &str,
    expected: &[(&str, &str, u64)],
) -> TestResult {
    let prefix = format!("lonewolf_s2s_transport_attempts_total{{direction=\"{direction}\",");
    let samples: Vec<_> = expected
        .iter()
        .map(|(mode, outcome, count)| {
            format!("{prefix}tls_mode=\"{mode}\",outcome=\"{outcome}\"}} {count}")
        })
        .collect();
    let body = suite.wait_for_metrics("exact transport outcomes", |body| {
        samples
            .iter()
            .all(|sample| body.lines().any(|line| line == sample))
    })?;
    let actual: Vec<_> = body
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .collect();
    assert_eq!(actual.len(), samples.len(), "{body}");
    Ok(())
}

pub(super) fn transport_connections(
    suite: &super::super::support::C2sSuite,
    direction: &str,
    starttls: u64,
    direct: u64,
) -> TestResult {
    let samples = [
        format!(
            "lonewolf_s2s_connections{{direction=\"{direction}\"}} {}",
            starttls + direct
        ),
        format!(
            "lonewolf_s2s_transport_connections{{direction=\"{direction}\",tls_mode=\"starttls\"}} {starttls}"
        ),
        format!(
            "lonewolf_s2s_transport_connections{{direction=\"{direction}\",tls_mode=\"direct\"}} {direct}"
        ),
    ];
    suite.wait_for_metrics("matching aggregate and mode connection gauges", |body| {
        samples
            .iter()
            .all(|sample| body.lines().any(|line| line == sample))
    })?;
    Ok(())
}
