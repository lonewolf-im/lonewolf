// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use super::super::support::{
    PASSWORD, TestResult,
    federation::{peer::RawS2sListener, refused_endpoint},
};
use super::direct_tls::{inbound_fixture, transport_attempts, transport_connections};
use super::negotiation::{SingleServer, authentication, expect_bounce};

const TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn transport_metrics_outbound_refusal_counts_each_explicit_mode_without_open_connections()
-> TestResult {
    for mode in ["starttls", "direct"] {
        let refused = refused_endpoint()?;
        let mut fixture = SingleServer::start(&format!(
            "[s2s.routes]\n'b.test'=[{{address='{}',tls_mode='{mode}'}}]",
            refused.address()
        ))?;
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='refused'><body>Refused</body></message>")?;
        expect_bounce(&mut alice, "refused", "remote-server-timeout")?;
        authentication(&fixture.suite, "outbound", "unreachable", 1)?;
        transport_attempts(&fixture.suite, "outbound", &[(mode, "unreachable", 1)])?;
        transport_connections(&fixture.suite, "outbound", 0, 0)?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"static\"} 1")?;
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn transport_metrics_starttls_tls_timeout_preserves_one_aggregate_authentication() -> TestResult {
    let listener = RawS2sListener::bind()?;
    let mut fixture = SingleServer::start(&format!(
        "[limits.s2s]\nnegotiation_timeout_secs=1\n[s2s.routes]\n'b.test'=['{}']",
        listener.address()?
    ))?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='timeout-mode'><body>Timeout</body></message>")?;
    let pending = listener.accept_until_proceed("b.test", "a.test")?;
    transport_connections(&fixture.suite, "outbound", 1, 0)?;
    expect_bounce(&mut alice, "timeout-mode", "remote-server-timeout")?;
    authentication(&fixture.suite, "outbound", "timeout", 1)?;
    transport_attempts(&fixture.suite, "outbound", &[("starttls", "timeout", 1)])?;
    transport_connections(&fixture.suite, "outbound", 0, 0)?;
    drop(pending);
    alice.close()?;
    fixture.stop()
}

#[test]
fn transport_metrics_admission_rejection_does_not_create_an_attempt_for_either_mode() -> TestResult
{
    let mut fixture = inbound_fixture(
        "[limits.s2s]\nmax_inbound_connections=1\nnegotiation_timeout_secs=60",
        false,
    )?;
    for (slot, mode) in [(0, "starttls"), (1, "direct")] {
        let socket = TcpStream::connect_timeout(&fixture.suite.s2s_addresses()?[slot], TIMEOUT)?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        transport_connections(
            &fixture.suite,
            "inbound",
            u64::from(slot == 0),
            u64::from(slot == 1),
        )?;
        let rejected_slot = 1 - slot;
        let mut rejected =
            TcpStream::connect_timeout(&fixture.suite.s2s_addresses()?[rejected_slot], TIMEOUT)?;
        rejected.set_read_timeout(Some(TIMEOUT))?;
        assert_eq!(rejected.read(&mut [0; 1])?, 0);
        fixture.suite.wait_for_metric(&format!("lonewolf_s2s_connections_rejected_total{{listener=\"{rejected_slot}\",reason=\"max_inbound_connections\"}} 1"))?;
        if slot == 0 {
            transport_attempts(&fixture.suite, "inbound", &[])?;
        } else {
            transport_attempts(&fixture.suite, "inbound", &[("starttls", "protocol", 1)])?;
        }
        drop(socket);
        fixture.suite.wait_for_metric(&format!(
            "lonewolf_s2s_authentications_total{{direction=\"inbound\",outcome=\"{}\"}} 1",
            if mode == "direct" {
                "tls_failure"
            } else {
                "protocol"
            }
        ))?;
        transport_connections(&fixture.suite, "inbound", 0, 0)?;
    }
    transport_attempts(
        &fixture.suite,
        "inbound",
        &[("starttls", "protocol", 1), ("direct", "tls_failure", 1)],
    )?;
    fixture.suite.wait_for_metric(
        "lonewolf_s2s_negotiation_duration_seconds_count{direction=\"inbound\"} 2",
    )?;
    fixture.stop()
}

fn client_hello(mut socket: TcpStream, config: Arc<rustls::ClientConfig>) -> TestResult<TcpStream> {
    let mut connection = rustls::ClientConnection::new(config, "a.test".try_into()?)?;
    while connection.wants_write() {
        connection.write_tls(&mut socket)?;
    }
    socket.flush()?;
    let mut record = [0; 5];
    socket.read_exact(&mut record)?;
    assert_eq!(record[0], 22);
    assert_eq!(record[1], 3);
    let size = u16::from_be_bytes([record[3], record[4]]) as usize;
    assert!(size <= 18_432);
    socket.read_exact(&mut vec![0; size])?;
    Ok(socket)
}

#[test]
fn transport_metrics_inbound_cancellation_before_and_during_each_tls_mode_releases_all_guards()
-> TestResult {
    use super::super::support::federation::peer::RawS2sPeer;
    for slot in 0..2 {
        for during in [false, true] {
            let mut fixture = inbound_fixture("[limits.s2s]\nnegotiation_timeout_secs=60", false)?;
            let address = fixture.suite.s2s_addresses()?[slot];
            let socket = if slot == 0 && during {
                let mut peer = RawS2sPeer::connect(address, "b.test", "a.test")?;
                peer.expect_starttls_features()?;
                peer.start_tls_socket()?
            } else {
                TcpStream::connect_timeout(&address, TIMEOUT)?
            };
            socket.set_read_timeout(Some(TIMEOUT))?;
            socket.set_write_timeout(Some(TIMEOUT))?;
            let mut socket = if during {
                client_hello(socket, fixture.client_config()?)?
            } else {
                socket
            };
            transport_connections(
                &fixture.suite,
                "inbound",
                u64::from(slot == 0),
                u64::from(slot == 1),
            )?;
            let body = fixture.suite.scrape_metrics()?;
            for sample in [
                "lonewolf_c2s_listener_info{listener=\"0\",tls_mode=\"starttls\"} 1",
                "lonewolf_s2s_listener_info{listener=\"0\",tls_mode=\"starttls\"} 1",
                "lonewolf_s2s_listener_info{listener=\"1\",tls_mode=\"direct\"} 1",
            ] {
                assert!(body.lines().any(|line| line == sample), "{body}");
            }
            assert_eq!(
                body.lines()
                    .filter(|line| line.starts_with("lonewolf_s2s_listener_info{"))
                    .count(),
                2
            );
            let reader = std::thread::spawn(move || -> io::Result<()> {
                if slot == 0 && !during {
                    let mut response = Vec::new();
                    while !response.ends_with(b"</stream:stream>") {
                        let mut byte = [0];
                        if socket.read(&mut byte)? == 0 {
                            return Err(io::Error::other("missing shutdown footer"));
                        }
                        response.push(byte[0]);
                    }
                    assert!(
                        String::from_utf8(response)
                            .map_err(io::Error::other)?
                            .contains("system-shutdown")
                    );
                    socket.write_all(b"</stream:stream>")?;
                }
                let mut remaining = Vec::new();
                match socket.read_to_end(&mut remaining) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
                    Err(error) => return Err(error),
                }
                if during {
                    assert!(
                        remaining
                            .first()
                            .is_none_or(|byte| (20..=23).contains(byte))
                    );
                } else {
                    assert!(remaining.is_empty());
                }
                Ok(())
            });
            let state = fixture
                .suite
                .stop_with_s2s_state()?
                .ok_or("missing shutdown receipt")?;
            reader.join().map_err(|_| "peer reader panicked")??;
            let mut cancelled = [[0; 2]; 2];
            cancelled[0][slot] = 1;
            assert_eq!(state.transport_cancelled, cancelled);
            assert_eq!(state.transport_connections, [[0; 2]; 2]);
            assert_eq!(state.connections, [0; 2]);
            if during {
                assert_eq!(state.authentication_protocol, [1, 0]);
            }
            fixture.dns.stop()?;
        }
    }
    Ok(())
}
