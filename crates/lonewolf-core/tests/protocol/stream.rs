// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use super::support::{C2sSuite, OPEN, TLS_NAMESPACE, TestResult};

#[test]
fn starttls_rejects_attributes() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls' extra='1'/>")?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")?;
    client.expect_end()
}

#[test]
fn starttls_rejects_children() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><child/></starttls>")?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")?;
    client.expect_end()
}

#[test]
fn starttls_rejects_text() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>text</starttls>")?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")?;
    client.expect_end()
}

#[test]
fn tls_restart_changes_the_stream_id_and_offers_sasl() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let before_tls = client.open_with(OPEN)?;
    client.features()?;
    let mut client = client.start_tls(&suite)?;

    let after_tls = client.open_with(OPEN)?;
    assert_ne!(before_tls.attribute("id"), after_tls.attribute("id"));
    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'>
            <channel-binding type='tls-server-end-point'/>
            <channel-binding type='tls-exporter'/>
        </sasl-channel-binding>
        <mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
            <mechanism>SCRAM-SHA-256-PLUS</mechanism>
            <mechanism>SCRAM-SHA-256</mechanism>
            <mechanism>SCRAM-SHA-1-PLUS</mechanism>
            <mechanism>SCRAM-SHA-1</mechanism>
        </mechanisms>
    </stream:features>",
    )?;
    client.close()
}

#[test]
fn stanza_size_limit_closes_the_stream_before_tls() -> TestResult {
    let suite = C2sSuite::with_limits("max_stanza_bytes = 10000")?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(&format!("<message><body>{}", "x".repeat(10000)))?;
    client.expect_stream_error("policy-violation")
}

#[test]
fn stanza_size_limit_closes_the_stream_after_binding() -> TestResult {
    let suite = C2sSuite::with_limits("max_stanza_bytes = 10000")?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(&format!("<message><body>{}", "x".repeat(10000)))?;
    client.expect_stream_error("policy-violation")
}

#[test]
fn stream_footer_closes_the_connection_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send("</stream:stream>")?;
    client.expect_end()
}

#[test]
fn stream_footer_closes_the_connection_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send("</stream:stream>")?;
    client.expect_end()
}

#[test]
fn stream_footer_closes_the_connection_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("</stream:stream>")?;
    client.expect_end()
}

#[test]
fn stream_footer_closes_the_connection_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send("</stream:stream>")?;
    client.expect_end()
}

#[test]
fn idle_connection_establishment_closes_at_the_configured_deadline() -> TestResult {
    let suite = C2sSuite::with_limits("connection_establishment_timeout_secs = 1")?;
    let started = Instant::now();
    let mut client = suite.tcp_client()?;

    client.expect_eof()?;
    assert!((Duration::from_secs(1)..Duration::from_secs(4)).contains(&started.elapsed()));
    Ok(())
}

#[test]
fn idle_authentication_closes_at_the_configured_deadline() -> TestResult {
    let suite = C2sSuite::with_limits("authentication_timeout_secs = 1")?;
    let started = Instant::now();
    let mut client = suite.unauthenticated_client()?;

    client.expect_eof()?;
    assert!((Duration::from_secs(1)..Duration::from_secs(4)).contains(&started.elapsed()));
    Ok(())
}

#[test]
fn idle_resource_binding_closes_at_the_configured_deadline() -> TestResult {
    let suite = C2sSuite::with_limits("resource_binding_timeout_secs = 1")?;
    suite.create_account("alice", "pencil")?;
    let started = Instant::now();
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.expect_eof()?;
    assert!((Duration::from_secs(1)..Duration::from_secs(4)).contains(&started.elapsed()));
    Ok(())
}

#[test]
fn tcp_eof_after_opening_releases_connection_capacity() -> TestResult {
    let suite = C2sSuite::with_limits("max_connections_per_ip = 1")?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.transport().shutdown(std::net::Shutdown::Write)?;
    client.expect_eof()?;
    suite.wait_for_log("stream disconnected")?;

    let mut replacement = suite.tcp_client()?;
    replacement.open()?;
    replacement.close()
}

#[test]
fn tcp_eof_before_opening_releases_connection_capacity() -> TestResult {
    let suite = C2sSuite::with_limits("max_connections_per_ip = 1")?;
    let mut client = suite.tcp_client()?;

    client.transport().shutdown(std::net::Shutdown::Write)?;
    client.expect_eof()?;
    suite.wait_for_log("stream disconnected")?;

    let mut replacement = suite.tcp_client()?;
    replacement.open()?;
    replacement.close()
}

#[test]
fn plaintext_after_starttls_proceed_is_rejected_as_a_tls_failure() -> TestResult {
    use std::io::Read;
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;
    client.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")?;
    client.receive()?.assert_name(TLS_NAMESPACE, "proceed");
    client.send(OPEN)?;
    let mut received = Vec::new();
    match client.into_inner().take(1024).read_to_end(&mut received) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(error) => return Err(error.into()),
    }
    assert!(!received.windows(7).any(|bytes| bytes == b"<stream"));
    assert!(
        suite
            .wait_for_log("outcome=\"tls_failure\"")?
            .contains("stream disconnected")
    );
    Ok(())
}
