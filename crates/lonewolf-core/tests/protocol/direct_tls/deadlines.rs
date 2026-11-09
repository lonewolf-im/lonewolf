// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::support::{OPEN, crl_gate::CrlReadGate, tls};
use rustls::pki_types::ServerName;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::Duration;
const TIMEOUT: Duration = Duration::from_secs(10);

fn socket(address: std::net::SocketAddr) -> TestResult<TcpStream> {
    let socket = TcpStream::connect_timeout(&address, TIMEOUT)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    Ok(socket)
}

#[test]
fn direct_tls_admission_holds_silent_sockets_before_client_hello_and_recovers_capacity()
-> TestResult {
    for global in [false, true] {
        let hosts = "[[c2s.listeners]]\naddress='127.0.0.1:0'\ntls_mode='direct'\n[hosts.localhost]\nextensions=[]";
        let mut suite = C2sSuite::with_listener_setup(
            "tls_mode='direct'",
            "max_connections_per_ip=1",
            hosts,
            |directory| {
                let path = directory.join("lonewolf.toml");
                let config = std::fs::read_to_string(&path)?;
                std::fs::write(
                    path,
                    config.replacen(
                        "[limits.c2s]",
                        &format!(
                            "[limits.c2s]\nmax_unauthenticated_connections={}",
                            if global { 1 } else { 4 }
                        ),
                        1,
                    ),
                )?;
                Ok(())
            },
        )?;
        suite.create_account("alice", PASSWORD)?;
        let held = socket(suite.address)?;
        suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 1")?;
        let rejected_slot = usize::from(global);
        let mut rejected = socket(suite.listener_address(rejected_slot)?)?;
        assert_eq!(rejected.read(&mut [0; 1])?, 0);
        let reason = if global {
            "max_unauthenticated_connections"
        } else {
            "max_connections_per_ip"
        };
        suite.wait_for_metric(&format!("lonewolf_c2s_connections_rejected_total{{listener=\"{rejected_slot}\",reason=\"{reason}\"}} 1"))?;
        let second = if global {
            None
        } else {
            let socket = socket(suite.listener_address(1)?)?;
            suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 2")?;
            Some(socket)
        };
        held.shutdown(Shutdown::Both)?;
        drop(held);
        if let Some(second) = second {
            second.shutdown(Shutdown::Both)?;
            drop(second);
        }
        suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
        let mut client = Client::direct_tls(&suite)?;
        client.open()?.assert_xml(DEFAULT_FEATURES)?;
        client.authenticate("alice", PASSWORD)?;
        let mut client = client.restart();
        client.open()?.assert_xml(BIND_FEATURES)?;
        assert_eq!(client.bind(Some("recovered"))?, "alice@localhost/recovered");
        client.close()?;
        suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
        suite.wait_for_metric("lonewolf_c2s_connections{listener=\"1\"} 0")?;
        suite.wait_for_metric("lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256\",outcome=\"success\"} 1")?;
        suite.wait_for_metric("lonewolf_router_sessions 0")?;
        suite.stop()?;
    }
    Ok(())
}

#[test]
fn direct_tls_silent_partial_and_stalled_handshakes_timeout_without_xml_then_recover() -> TestResult
{
    let mut suite = C2sSuite::with_listener_setup(
        "tls_mode='direct'",
        "connection_establishment_timeout_secs=1",
        "[hosts.localhost]\nextensions=[]",
        |_| Ok(()),
    )?;
    suite.create_account("alice", PASSWORD)?;
    for phase in 0..3 {
        let mut socket = socket(suite.address)?;
        let mut connection = rustls::ClientConnection::new(
            Arc::clone(&suite.tls),
            ServerName::try_from("localhost")?,
        )?;
        let mut hello = Vec::new();
        connection.write_tls(&mut hello)?;
        if phase == 1 {
            socket.write_all(&hello[..10])?;
        }
        if phase == 2 {
            socket.write_all(&hello)?;
            assert!(connection.read_tls(&mut socket)? > 0);
            connection.process_new_packets()?;
        }
        let mut response = Vec::new();
        socket.read_to_end(&mut response)?;
        if phase < 2 {
            assert!(response.is_empty());
        } else {
            assert!(response.first().is_none_or(|b| (20..=23).contains(b)));
            assert!(!response.windows(7).any(|b| b == b"<stream"));
        }
        suite.wait_for_metric(&format!("lonewolf_c2s_connections_closed_total{{listener=\"0\",phase=\"establishing\",outcome=\"establishment_timeout\"}} {}",phase+1))?;
        suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    }
    let mut client = Client::direct_tls(&suite)?;
    client.open()?.assert_xml(DEFAULT_FEATURES)?;
    client.authenticate("alice", PASSWORD)?;
    let mut client = client.restart();
    client.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(
        client.bind(Some("after-timeouts"))?,
        "alice@localhost/after-timeouts"
    );
    client.close()?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}

#[test]
fn direct_tls_selected_policy_refresh_uses_establishment_deadline_and_unblocks_after_cancel()
-> TestResult {
    let mut suite = C2sSuite::with_listener_setup(
        "tls_mode='direct'",
        "connection_establishment_timeout_secs=1",
        "[hosts.localhost]\nextensions=[]",
        |directory| {
            tls::ClientCertificates::configure(directory)?;
            Ok(())
        },
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut gate = CrlReadGate::new(&suite.fixture_path().join("client-crls.pem"))?;
    let mut socket = socket(suite.address)?;
    let mut connection =
        rustls::ClientConnection::new(Arc::clone(&suite.tls), ServerName::try_from("localhost")?)?;
    connection.write_tls(&mut socket)?;
    gate.captured()?;
    assert_eq!(socket.read(&mut [0; 1])?, 0);
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"establishing\",outcome=\"establishment_timeout\"} 1")?;
    suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    gate.release()?;
    drop(gate);
    let mut client = Client::direct_tls(&suite)?;
    client.open()?.assert_xml(DEFAULT_FEATURES)?;
    client.authenticate("alice", PASSWORD)?;
    let mut client = client.restart();
    client.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(
        client.bind(Some("policy-recovered"))?,
        "alice@localhost/policy-recovered"
    );
    client.close()?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}

#[test]
fn direct_tls_fragmented_records_and_tls13_coalesced_finished_header_complete_without_losing_bytes()
-> TestResult {
    let mut suite = C2sSuite::with_listener_setup(
        "tls_mode='direct'",
        "",
        "[hosts.localhost]\nextensions=[]",
        |_| Ok(()),
    )?;
    suite.create_account("alice", PASSWORD)?;
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let body = suite.scrape_metrics()?;
        let baseline = body
            .lines()
            .find_map(|line| {
                line.strip_prefix("lonewolf_c2s_received_bytes_total{listener=\"0\"} ")
            })
            .map(str::parse::<usize>)
            .transpose()?
            .unwrap_or(0);
        let mut connection = rustls::ClientConnection::new(
            suite.tls_with_versions(&[version])?,
            ServerName::try_from("localhost")?,
        )?;
        let mut socket = socket(suite.address)?;
        let mut hello = Vec::new();
        connection.write_tls(&mut hello)?;
        let mut wire_bytes = hello.len();
        for part in hello.chunks(3) {
            socket.write_all(part)?;
        }
        while connection.is_handshaking() {
            if connection.wants_write() {
                wire_bytes += connection.write_tls(&mut socket)?;
            }
            connection.read_tls(&mut socket)?;
            connection.process_new_packets()?;
        }
        if version.version == rustls::ProtocolVersion::TLSv1_3 {
            assert!(connection.wants_write());
        }
        connection.writer().write_all(OPEN.as_bytes())?;
        let mut coalesced = Vec::new();
        while connection.wants_write() {
            connection.write_tls(&mut coalesced)?;
        }
        wire_bytes += coalesced.len();
        socket.write_all(&coalesced)?;
        let mut client = Client::new(rustls::StreamOwned::new(connection, socket));
        client.open_with("")?;
        client.features()?.assert_xml(DEFAULT_FEATURES)?;
        suite.wait_for_metric(&format!(
            "lonewolf_c2s_received_bytes_total{{listener=\"0\"}} {}",
            baseline + wire_bytes
        ))?;
        client.authenticate("alice", PASSWORD)?;
        let mut client = client.restart();
        client.open()?.assert_xml(BIND_FEATURES)?;
        assert_eq!(
            client.bind(Some("fragmented"))?,
            "alice@localhost/fragmented"
        );
        client.close()?;
    }
    suite.wait_for_metric("lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256\",outcome=\"success\"} 2")?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}

#[test]
fn direct_tls_shutdown_completes_pending_hello_sasl_and_bound_c2s_tasks() -> TestResult {
    for phase in 0..3 {
        let mut suite = C2sSuite::with_federation_and_setup(
            "[hosts.localhost]\nextensions=[]\nfederation=true\n[logging]\nlevel='off'",
            "[s2s]\nenabled=true\nlisteners=[{address='127.0.0.1:0',tls_mode='direct'}]",
            |directory| {
                tls::configure_host(directory, "-eligible", &["eligible.test"])?;
                let path = directory.join("lonewolf.toml");
                let config = std::fs::read_to_string(&path)?;
                let config = config.replacen(
                    "[[c2s.listeners]]",
                    "[[c2s.listeners]]\ntls_mode='direct'",
                    1,
                );
                std::fs::write(
                    path,
                    format!(
                        "{config}\n[hosts.'eligible.test']\nfederation=true\n[hosts.'eligible.test'.tls]\ncertificate_chain_path='certificate-eligible.pem'\nprivate_key_path='private-key-eligible.pem'\n"
                    ),
                )?;
                Ok(())
            },
        )?;
        suite.create_account("alice", PASSWORD)?;
        let state;
        if phase == 0 {
            let mut peer = socket(suite.address)?;
            suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 1")?;
            state = suite.stop_with_s2s_state()?;
            assert_eq!(peer.read(&mut [0; 1])?, 0);
        } else {
            let mut client = Client::direct_tls(&suite)?;
            client.open()?.assert_xml(DEFAULT_FEATURES)?;
            if phase == 1 {
                client.send_sasl_auth("SCRAM-SHA-256", "n,,n=alice,r=nonce")?;
                assert!(client.receive_sasl_challenge()?.starts_with("r=nonce"));
            } else {
                client.authenticate("alice", PASSWORD)?;
                client = client.restart();
                client.open()?.assert_xml(BIND_FEATURES)?;
                assert_eq!(client.bind(Some("shutdown"))?, "alice@localhost/shutdown");
            }
            let reader = std::thread::spawn(move || {
                client
                    .expect_stream_error("system-shutdown")
                    .map_err(|e| e.to_string())
            });
            state = suite.stop_with_s2s_state()?;
            reader
                .join()
                .map_err(|_| "C2S shutdown reader panicked")??;
        }
        let state = state.ok_or("missing completed shutdown receipt")?;
        assert_eq!(state.c2s_connections, 0);
        assert_eq!(state.c2s_unauthenticated, 0);
        assert_eq!(state.router_sessions, 0);
        crate::support::federation::assert_shutdown_empty(Some(state));
    }
    Ok(())
}

#[test]
fn direct_tls_old_versions_and_missing_tls12_ems_fail_without_plaintext_then_recover() -> TestResult
{
    let mut suite = C2sSuite::with_listener_setup(
        "tls_mode='direct'",
        "",
        "[hosts.localhost]\nextensions=[]",
        |_| Ok(()),
    )?;
    suite.create_account("alice", PASSWORD)?;
    for legacy_version in [Some(1), Some(2), None] {
        let old = legacy_version.is_some();
        let mut connection = rustls::ClientConnection::new(
            suite.tls_with_versions(&[&rustls::version::TLS12])?,
            ServerName::try_from("localhost")?,
        )?;
        let mut hello = Vec::new();
        connection.write_tls(&mut hello)?;
        let mut at = 44 + usize::from(hello[43]);
        at += 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        at += 1 + usize::from(hello[at]);
        let extensions_at = at;
        at += 2;
        let mut removed = false;
        while at < hello.len() {
            let kind = u16::from_be_bytes([hello[at], hello[at + 1]]);
            let length = 4 + usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
            if kind == if old { 43 } else { 23 } {
                hello.drain(at..at + length);
                removed = true;
            } else {
                at += length;
            }
        }
        if !old {
            assert!(removed, "TLS1.2 client omitted EMS before mutation");
        }
        if let Some(version) = legacy_version {
            hello[9..11].copy_from_slice(&[3, version]);
        }
        let extensions: u16 = (hello.len() - extensions_at - 2).try_into()?;
        hello[extensions_at..extensions_at + 2].copy_from_slice(&extensions.to_be_bytes());
        let record: u16 = (hello.len() - 5).try_into()?;
        hello[3..5].copy_from_slice(&record.to_be_bytes());
        let handshake: u32 = (hello.len() - 9).try_into()?;
        hello[6..9].copy_from_slice(&handshake.to_be_bytes()[1..]);
        let mut peer = socket(suite.address)?;
        peer.write_all(&hello)?;
        let mut response = Vec::new();
        assert_eq!(peer.read_to_end(&mut response)?, 0);
        assert!(response.is_empty());
    }
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"establishing\",outcome=\"tls_failure\"} 3")?;
    let mut client = Client::direct_tls(&suite)?;
    client.open()?.assert_xml(DEFAULT_FEATURES)?;
    client.authenticate("alice", PASSWORD)?;
    let mut client = client.restart();
    client.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(client.bind(Some("modern"))?, "alice@localhost/modern");
    client.close()?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}
