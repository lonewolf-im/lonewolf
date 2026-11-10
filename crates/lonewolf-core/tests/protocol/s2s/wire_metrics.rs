// SPDX-License-Identifier: Apache-2.0

use lonewolf_core::config::TlsMode;

use super::negotiation::{SingleServer, closed};
use crate::support::federation::peer::RawS2sListener;
use crate::support::federation::peer::{self, RawS2sPeer};
use crate::support::{PASSWORD, TestResult};

#[test]
fn inbound_starttls_tls13_counts_exact_tls_socket_bytes() -> TestResult {
    inbound(TlsMode::StartTls, &rustls::version::TLS13)
}

fn inbound(mode: TlsMode, version: &'static rustls::SupportedProtocolVersion) -> TestResult {
    let mut fixture = SingleServer::start("")?;
    fixture.set_transport(mode)?;
    let config = peer::client_config_with_versions(
        &fixture.ca,
        fixture
            .ca
            .server(fixture.directory.path(), "peer", &["b.test"])?,
        &[version],
    )?;
    let mut peer = RawS2sPeer::protected(
        mode,
        fixture.suite.s2s_addresses()?[0],
        "b.test",
        "a.test",
        config,
        Some("b.test"),
    )?;
    peer.expect_external_offered()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    assert_eq!(peer.protocol_version(), Some(version.version));
    peer.close()?;
    closed(&fixture.suite, "inbound", "stream_end", 1)?;
    let totals = peer.tls_totals()?;
    finish(&mut fixture, totals, 0)
}

fn finish(
    fixture: &mut SingleServer,
    totals: crate::support::wire::WireSnapshot,
    direction: usize,
) -> TestResult {
    let state = fixture
        .suite
        .stop_with_s2s_state()?
        .ok_or("missing shutdown receipt")?;
    let mut ends = [0; 2];
    ends[direction] = 1;
    assert_eq!(state.transport_ends, ends);
    crate::support::federation::assert_shutdown_empty(Some(state));
    assert_eq!(state.received_bytes[direction], totals.written);
    assert_eq!(state.sent_bytes[direction], totals.read);
    fixture.dns.stop()
}

#[test]
fn inbound_starttls_tls12_counts_exact_tls_socket_bytes() -> TestResult {
    inbound(TlsMode::StartTls, &rustls::version::TLS12)
}

#[test]
fn inbound_direct_tls12_counts_exact_tls_socket_bytes() -> TestResult {
    inbound(TlsMode::Direct, &rustls::version::TLS12)
}

#[test]
fn inbound_direct_tls13_counts_exact_tls_socket_bytes() -> TestResult {
    inbound(TlsMode::Direct, &rustls::version::TLS13)
}

#[test]
fn outbound_starttls_tls12_counts_exact_tls_socket_bytes() -> TestResult {
    outbound(TlsMode::StartTls, &rustls::version::TLS12)
}

#[test]
fn outbound_starttls_tls13_counts_exact_tls_socket_bytes() -> TestResult {
    outbound(TlsMode::StartTls, &rustls::version::TLS13)
}

#[test]
fn outbound_direct_tls12_counts_exact_tls_socket_bytes() -> TestResult {
    outbound(TlsMode::Direct, &rustls::version::TLS12)
}

#[test]
fn outbound_direct_tls13_counts_exact_tls_socket_bytes() -> TestResult {
    outbound(TlsMode::Direct, &rustls::version::TLS13)
}

fn outbound(mode: TlsMode, version: &'static rustls::SupportedProtocolVersion) -> TestResult {
    let listener = RawS2sListener::bind()?.with_transport(mode);
    let mut fixture = SingleServer::start(&format!(
        "[s2s.routes]\n'b.test'=[{{address='{}',tls_mode='{}'}}]",
        listener.address()?,
        if mode == TlsMode::Direct {
            "direct"
        } else {
            "starttls"
        }
    ))?;
    let config = peer::server_config_with_versions(
        &fixture.ca,
        fixture
            .ca
            .server(fixture.directory.path(), "peer", &["b.test"])?,
        "a.test",
        &[version],
    )?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='wire'><body>Socket accounting</body></message>")?;
    let mut remote = listener.accept("b.test", "a.test", config, true)?;
    assert_eq!(remote.protocol_version(), Some(version.version));
    remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='wire'><body>Socket accounting</body></message>")?;
    remote.close()?;
    closed(&fixture.suite, "outbound", "stream_end", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_links{state=\"ready\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_links{state=\"connecting\"} 0")?;
    let totals = remote.tls_totals()?;
    alice.close()?;
    finish(&mut fixture, totals, 1)
}

#[test]
fn failed_tls_records_keep_exact_socket_bytes_in_both_modes_and_directions() -> TestResult {
    use std::io::{Read, Write};
    for mode in [TlsMode::StartTls, TlsMode::Direct] {
        for outbound in [false, true] {
            let listener = RawS2sListener::bind()?.with_transport(mode);
            let mut fixture = if outbound {
                SingleServer::start(&format!(
                    "[s2s.routes]\n'b.test'=[{{address='{}',tls_mode='{}'}}]",
                    listener.address()?,
                    if mode == TlsMode::Direct {
                        "direct"
                    } else {
                        "starttls"
                    }
                ))?
            } else {
                SingleServer::start("")?
            };
            let mut alice = if outbound {
                fixture.suite.create_account("alice", PASSWORD)?;
                let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
                alice.send("<message to='bob@b.test/phone' type='chat' id='failed-wire'><body>Must fail</body></message>")?;
                Some(alice)
            } else {
                fixture.set_transport(mode)?;
                None
            };
            let socket = handshake_socket(&fixture, &listener, mode, outbound)?;
            let mut socket = crate::support::wire::WireIo::new(socket);
            if outbound {
                consume_client_hello(&mut socket)?;
            }
            socket.write_all(b"\x16\x03\x03\x00\x04\xff\x00\x00\x00")?;
            socket.flush()?;
            let mut remaining = Vec::new();
            match socket.read_to_end(&mut remaining) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(error) => return Err(error.into()),
            }
            let direction = if outbound { "outbound" } else { "inbound" };
            if let Some(alice) = &mut alice {
                super::negotiation::expect_bounce(alice, "failed-wire", "remote-server-timeout")?;
                alice.close()?;
            }
            super::negotiation::authentication(&fixture.suite, direction, "tls_failure", 1)?;
            fixture.suite.wait_for_metric(&format!(
                "lonewolf_s2s_connections{{direction=\"{direction}\"}} 0"
            ))?;
            let totals = socket.counters().snapshot();
            let state = fixture
                .suite
                .stop_with_s2s_state()?
                .ok_or("missing shutdown receipt")?;
            crate::support::federation::assert_shutdown_empty(Some(state));
            assert_eq!(state.transport_ends, [0; 2]);
            let index = usize::from(outbound);
            assert_eq!(state.received_bytes[index], totals.written);
            assert_eq!(state.sent_bytes[index], totals.read);
            fixture.dns.stop()?;
        }
    }
    Ok(())
}

fn handshake_socket(
    fixture: &SingleServer,
    listener: &RawS2sListener,
    mode: TlsMode,
    outbound: bool,
) -> TestResult<std::net::TcpStream> {
    let socket = if outbound {
        if mode == TlsMode::Direct {
            listener.accept_socket()?
        } else {
            listener
                .accept_until_proceed("b.test", "a.test")?
                .into_plain_socket()?
        }
    } else if mode == TlsMode::Direct {
        std::net::TcpStream::connect_timeout(
            &fixture.suite.s2s_addresses()?[0],
            std::time::Duration::from_secs(10),
        )?
    } else {
        let mut peer = fixture.connect()?;
        peer.expect_starttls_features()?;
        peer.start_tls_socket()?
    };
    socket.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    Ok(socket)
}

fn consume_client_hello(socket: &mut impl std::io::Read) -> TestResult {
    let mut acceptor = rustls::server::Acceptor::default();
    loop {
        if acceptor.read_tls(socket)? == 0 {
            return Err("missing ClientHello".into());
        }
        if let Some(accepted) = acceptor.accept().map_err(|(error, _)| error)? {
            assert_eq!(accepted.client_hello().server_name(), Some("b.test"));
            return Ok(());
        }
    }
}

#[test]
fn cancelled_outbound_handshakes_preserve_reported_byte_bounds_in_both_modes() -> TestResult {
    use std::io::Read;
    for mode in [TlsMode::StartTls, TlsMode::Direct] {
        let listener = RawS2sListener::bind()?.with_transport(mode);
        let mut fixture = SingleServer::start(&format!(
            "[limits.s2s]\nnegotiation_timeout_secs=60\n[s2s.routes]\n'b.test'=[{{address='{}',tls_mode='{}'}}]",
            listener.address()?,
            if mode == TlsMode::Direct {
                "direct"
            } else {
                "starttls"
            }
        ))?;
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='cancel-wire'><body>Never delivered</body></message>")?;
        let mut socket =
            crate::support::wire::WireIo::new(handshake_socket(&fixture, &listener, mode, true)?);
        consume_client_hello(&mut socket)?;
        alice.close()?;
        let state = fixture
            .suite
            .stop_with_s2s_state()?
            .ok_or("missing shutdown receipt")?;
        let mut remaining = Vec::new();
        match socket.read_to_end(&mut remaining) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(error) => return Err(error.into()),
        }
        assert!(remaining.is_empty());
        let totals = socket.counters().snapshot();
        let mut cancelled = [[0; 2]; 2];
        cancelled[1][usize::from(mode == TlsMode::Direct)] = 1;
        assert_eq!(state.transport_cancelled, cancelled);
        assert_eq!(state.transport_ends, [0; 2]);
        crate::support::federation::assert_shutdown_empty(Some(state));
        assert_eq!(totals.written, 0);
        assert_eq!(state.received_bytes, [0; 2]);
        assert_eq!(state.sent_bytes[0], 0);
        assert!(totals.read > 0);
        assert!(state.sent_bytes[1] <= totals.read);
        fixture.dns.stop()?;
    }
    Ok(())
}
