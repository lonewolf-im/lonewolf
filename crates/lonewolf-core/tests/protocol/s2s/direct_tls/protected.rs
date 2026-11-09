// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::support::federation::peer::RawS2sPeer;

#[test]
fn direct_tls_first_protected_features_and_bidi_advice_enforce_limits_on_the_same_connection()
-> TestResult {
    let mut fixture = inbound_fixture(
        "[limits.s2s]\nmax_stanza_bytes=10000\nidle_timeout_secs=7",
        true,
    )?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    let mut remote = RawS2sPeer::tls_first(
        fixture.suite.s2s_addresses()?[1],
        "b.test",
        "a.test",
        fixture.client_config()?,
    )?
    .expecting_limits(10000, 7);
    remote.open_protected(&inbound_header(Some("b.test"), "a.test"), Some("b.test"))?;
    remote.expect_external_and_bidi_offered()?;
    remote.send(&format!(
        "<bidi xmlns='urn:xmpp:bidi'>{}</bidi>",
        peer::limits_xml(300, 0)
    ))?;
    remote.auth_external(Some("b.test"))?;
    remote.expect_sasl_success()?;
    let mut remote = remote.restart("b.test", "a.test")?;
    authentication(&fixture.suite, "inbound", "success", 1)?;
    let large = "x".repeat(600);
    alice.send(&format!(
        "<message to='bob@b.test/phone' type='chat' id='too-large'><body>{large}</body></message>"
    ))?;
    expect_bounce(&mut alice, "too-large", "policy-violation")?;
    alice
        .send("<message to='bob@b.test/phone' type='chat' id='fits'><body>Fits</body></message>")?;
    remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='fits'><body>Fits</body></message>")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_peer_size_rejections_total 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bounces_total{condition=\"policy_violation\"} 1")?;
    transport_attempts(&fixture.suite, "inbound", &[("direct", "success", 1)])?;
    transport_attempts(&fixture.suite, "outbound", &[])?;
    transport_connections(&fixture.suite, "inbound", 0, 1)?;
    remote.close()?;
    closed(&fixture.suite, "inbound", "stream_end", 1)?;
    transport_connections(&fixture.suite, "inbound", 0, 0)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn direct_tls_unusable_bidi_limit_is_rejected_before_authentication_success() -> TestResult {
    let mut fixture = inbound_fixture("", true)?;
    let mut remote = RawS2sPeer::tls_first(
        fixture.suite.s2s_addresses()?[1],
        "b.test",
        "a.test",
        fixture.client_config()?,
    )?;
    remote.open_protected(&inbound_header(Some("b.test"), "a.test"), Some("b.test"))?;
    remote.expect_external_and_bidi_offered()?;
    remote.send(&format!(
        "<bidi xmlns='urn:xmpp:bidi'>{}</bidi>",
        peer::limits_xml(0, 0)
    ))?;
    remote.auth_external(Some("b.test"))?;
    remote.expect_stream_error("policy-violation")?;
    authentication(&fixture.suite, "inbound", "protocol", 1)?;
    transport_attempts(&fixture.suite, "inbound", &[("direct", "protocol", 1)])?;
    transport_connections(&fixture.suite, "inbound", 0, 0)?;
    fixture.stop()
}

#[test]
fn direct_tls_encrypted_starttls_and_forged_sender_never_start_another_tls_session() -> TestResult {
    for spoof in [false, true] {
        let mut fixture = inbound_fixture("", true)?;
        let mut remote = RawS2sPeer::tls_first(
            fixture.suite.s2s_addresses()?[1],
            "b.test",
            "a.test",
            fixture.client_config()?,
        )?;
        remote.open_protected(&inbound_header(Some("b.test"), "a.test"), Some("b.test"))?;
        remote.expect_external_and_bidi_offered()?;
        if spoof {
            remote.request_bidi()?;
            remote.auth_external(Some("b.test"))?;
            remote.expect_sasl_success()?;
            remote = remote.restart("b.test", "a.test")?;
            remote.send("<message from='bob@forged.test/phone' to='alice@a.test/desk' type='chat' id='spoof'><body>Forged</body></message>")?;
            remote.expect_stream_error("invalid-from")?;
            authentication(&fixture.suite, "inbound", "success", 1)?;
            transport_attempts(&fixture.suite, "inbound", &[("direct", "success", 1)])?;
            closed(&fixture.suite, "inbound", "invalid_from", 1)?;
        } else {
            remote.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")?;
            remote.expect_stream_error("not-authorized")?;
            authentication(&fixture.suite, "inbound", "protocol", 1)?;
            transport_attempts(&fixture.suite, "inbound", &[("direct", "protocol", 1)])?;
        }
        transport_connections(&fixture.suite, "inbound", 0, 0)?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn direct_tls_first_encrypted_auth_stanza_obeys_the_configured_input_limit() -> TestResult {
    let mut fixture = inbound_fixture("[limits.s2s]\nmax_stanza_bytes=10000", false)?;
    let mut remote = RawS2sPeer::tls_first(
        fixture.suite.s2s_addresses()?[1],
        "b.test",
        "a.test",
        fixture.client_config()?,
    )?
    .expecting_limits(10000, 600);
    remote.open_protected(&inbound_header(Some("b.test"), "a.test"), Some("b.test"))?;
    remote.expect_external_offered()?;
    remote.send(&format!(
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>{}</auth>",
        "A".repeat(12000)
    ))?;
    remote.expect_terminal_stream_error("policy-violation")?;
    authentication(&fixture.suite, "inbound", "protocol", 1)?;
    transport_attempts(&fixture.suite, "inbound", &[("direct", "protocol", 1)])?;
    transport_connections(&fixture.suite, "inbound", 0, 0)?;
    fixture.stop()
}

#[test]
fn direct_tls_malformed_first_encrypted_header_closes_with_exact_stream_error() -> TestResult {
    let mut fixture = inbound_fixture("", false)?;
    let mut remote = RawS2sPeer::tls_first(
        fixture.suite.s2s_addresses()?[1],
        "b.test",
        "a.test",
        fixture.client_config()?,
    )?;
    let malformed =
        inbound_header(Some("b.test"), "a.test").replace("version='1.0'", "version=1.0");
    remote.open_protected(&malformed, None)?;
    remote.expect_terminal_stream_error("not-well-formed")?;
    authentication(&fixture.suite, "inbound", "protocol", 1)?;
    transport_attempts(&fixture.suite, "inbound", &[("direct", "protocol", 1)])?;
    transport_connections(&fixture.suite, "inbound", 0, 0)?;
    fixture.stop()
}
