// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::support::OPEN;
use rustls::pki_types::ServerName;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn direct_tls_alpn_absent_correct_and_mixed_roles_complete_authenticated_sessions() -> TestResult {
    let mut suite = C2sSuite::with_listener_setup(
        "tls_mode='direct'",
        "",
        "[hosts.localhost]\nextensions=[]",
        |_| Ok(()),
    )?;
    suite.create_account("alice", PASSWORD)?;
    for protocols in [
        vec![],
        vec![b"xmpp-client".to_vec()],
        vec![
            b"xmpp-server".to_vec(),
            b"other".to_vec(),
            b"xmpp-client".to_vec(),
        ],
    ] {
        let offered = !protocols.is_empty();
        let mut config = (*suite.tls).clone();
        config.alpn_protocols = protocols;
        let mut client = Client::direct_tls_with_config(
            suite.address,
            Arc::new(config),
            ServerName::try_from("localhost")?,
        )?;
        client.complete_tls()?;
        assert_eq!(
            client.transport().conn.alpn_protocol(),
            offered.then_some(b"xmpp-client".as_slice())
        );
        client.open()?.assert_xml(DEFAULT_FEATURES)?;
        client.authenticate("alice", PASSWORD)?;
        let mut client = client.restart();
        client.open()?.assert_xml(BIND_FEATURES)?;
        assert_eq!(client.bind(Some("alpn"))?, "alice@localhost/alpn");
        client.send("<message to='alice@localhost/alpn' type='chat' id='alpn'><body>Selected</body></message>")?;
        client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/alpn' to='alice@localhost/alpn' type='chat' id='alpn'><body>Selected</body></message>")?;
        client.close()?;
    }
    suite.wait_for_metric("lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256\",outcome=\"success\"} 3")?;
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"bound\",outcome=\"stream_end\"} 3")?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}

#[test]
fn direct_tls_wrong_role_alpn_fails_the_handshake_without_xml_or_authentication() -> TestResult {
    let mut suite = C2sSuite::direct_tls()?;
    for role in [b"xmpp-server".as_slice(), b"unrelated".as_slice()] {
        let mut config = (*suite.tls).clone();
        config.alpn_protocols = vec![role.to_vec()];
        let mut client = Client::direct_tls_with_config(
            suite.address,
            Arc::new(config),
            ServerName::try_from("localhost")?,
        )?;
        let Err(error) = client.complete_tls() else {
            return Err("wrong ALPN succeeded".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{error:?}");
    }
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"establishing\",outcome=\"tls_failure\"} 2")?;
    let body = suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    assert!(
        !body.contains("lonewolf_c2s_authentications_total"),
        "{body}"
    );
    suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    suite.stop()
}

#[test]
fn direct_tls_missing_unknown_sni_and_plaintext_input_close_before_xml() -> TestResult {
    let mut suite = C2sSuite::direct_tls()?;
    for (index, identity) in [None, Some("unknown.example"), Some("plaintext")]
        .into_iter()
        .enumerate()
    {
        let mut socket = TcpStream::connect_timeout(&suite.address, Duration::from_secs(10))?;
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        socket.set_write_timeout(Some(Duration::from_secs(10)))?;
        if identity == Some("plaintext") {
            socket.write_all(OPEN.as_bytes())?;
        } else {
            let mut config = (*suite.tls).clone();
            config.enable_sni = identity.is_some();
            let mut connection = rustls::ClientConnection::new(
                Arc::new(config),
                ServerName::try_from(identity.unwrap_or("localhost"))?,
            )?;
            while connection.wants_write() {
                connection.write_tls(&mut socket)?;
            }
        }
        socket.flush()?;
        let mut response = Vec::new();
        match socket.read_to_end(&mut response) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => return Err(error.into()),
        }
        assert!(response.is_empty(), "pre-TLS response must contain no XML");
        suite.wait_for_metric(&format!("lonewolf_c2s_connections_closed_total{{listener=\"0\",phase=\"establishing\",outcome=\"tls_failure\"}} {}", index + 1))?;
        suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
        suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    }
    assert!(
        !suite
            .scrape_metrics()?
            .contains("lonewolf_c2s_authentications_total")
    );
    suite.stop()
}

#[test]
fn direct_tls_encrypted_starttls_and_malformed_header_have_exact_bounded_closure() -> TestResult {
    let mut suite = C2sSuite::direct_tls()?;
    let mut client = Client::direct_tls(&suite)?;
    client.open()?.assert_xml(DEFAULT_FEATURES)?;
    client.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")?;
    client.expect_end()?;
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"authenticating\",outcome=\"starttls_rejected\"} 1")?;
    let mut client = Client::direct_tls(&suite)?;
    client.open_with("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version=1.0>")?;
    client.expect_stream_error("not-well-formed")?;
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"establishing\",outcome=\"not_well_formed\"} 1")?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}

#[test]
fn direct_tls_failed_authentication_closes_at_the_existing_retry_limit() -> TestResult {
    let mut suite = C2sSuite::direct_tls()?;
    suite.create_account("alice", PASSWORD)?;
    let mut client = Client::direct_tls(&suite)?;
    client.open()?.assert_xml(DEFAULT_FEATURES)?;
    for _ in 0..3 {
        client
            .scram("alice", "incorrect password", "SCRAM-SHA-256", None)?
            .assert_xml(
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
            )?;
    }
    client.expect_stream_error("policy-violation")?;
    suite.wait_for_metric("lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256\",outcome=\"not_authorized\"} 3")?;
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"authenticating\",outcome=\"authentication_attempts_exceeded\"} 1")?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}
