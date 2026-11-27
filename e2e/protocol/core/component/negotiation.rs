// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;
use std::time::Instant;

use sha1::{Digest as _, Sha1};

use crate::support::component::{ComponentClient, NAMESPACE};
use crate::support::{C2sSuite, TestResult};

const DOMAIN: &str = "muc.localhost";
const SECRET: &str = "component-test-secret-0001";
const CONFIG: &str = "[components.domains.'muc.localhost']\nsecret='component-test-secret-0001'";

fn authentication(suite: &C2sSuite, outcome: &str, count: u64) -> TestResult {
    suite.wait_for_metric(&format!(
        "lonewolf_component_authentications_total{{outcome=\"{outcome}\"}} {count}"
    ))?;
    Ok(())
}
fn closed(suite: &C2sSuite, outcome: &str, count: u64) -> TestResult {
    suite.wait_for_metric(&format!(
        "lonewolf_component_streams_closed_total{{outcome=\"{outcome}\"}} {count}"
    ))?;
    Ok(())
}
fn rejected(client: &mut ComponentClient, condition: &str) -> TestResult {
    client.expect_stream_error(condition)?;
    client.expect_footer()?;
    client.send("</stream:stream>")?;
    client.expect_eof()
}

#[test]
fn handshake_ignores_version_and_accepts_uppercase_digest_without_features() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut previous_id = None;
    for (index, version) in [None, Some("1.0")].into_iter().enumerate() {
        let mut client = ComponentClient::connect(suite.component_address(0)?)?;
        let header = if version.is_some() {
            client.open_with(&format!("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='{NAMESPACE}' to='{DOMAIN}' from='ignored.example' version='1.0' xml:lang='fr'>"))?
        } else {
            client.open(DOMAIN, version)?
        };
        assert_eq!(header.namespace, NAMESPACE);
        assert_eq!(header.from.as_deref(), Some(DOMAIN));
        assert!(header.version.is_none());
        assert_eq!(header.id.len(), 32);
        assert!(
            header
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_ne!(previous_id.as_deref(), Some(header.id.as_str()));
        previous_id = Some(header.id.clone());
        if version.is_some() {
            let digest = Sha1::digest(format!("{}{SECRET}", header.id));
            let mut xml = String::from("<handshake ignored='yes'> \t\r\n");
            for byte in digest {
                write!(xml, "{byte:02X}")?;
            }
            xml.push_str("\t\r\n </handshake>");
            client.send(&xml)?;
        } else {
            client.send_handshake_for(SECRET, &header.id)?;
        }
        client.expect_handshake()?;
        suite.wait_for_metric("lonewolf_component_streams 1")?;
        suite.wait_for_metric(
            "lonewolf_component_listener_info{listener=\"0\",tls_mode=\"none\"} 1",
        )?;
        authentication(&suite, "success", index as u64 + 1)?;
        client.close()?;
        suite.wait_for_metric("lonewolf_component_streams 0")?;
        suite.wait_for_metric("lonewolf_component_connections 0")?;
        closed(&suite, "stream_end", index as u64 + 1)?;
    }
    suite.stop()
}

#[test]
fn invalid_handshakes_reject_secret_children_and_early_stanzas() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    for (index, value) in [
        "<handshake>wrong</handshake>",
        "<handshake><child/></handshake>",
        "<message to='localhost' from='muc.localhost'/>",
        "<other/>",
        "<handshake xmlns='jabber:client'/>",
    ]
    .into_iter()
    .enumerate()
    {
        let mut client = ComponentClient::connect(suite.component_address(0)?)?;
        client.open(DOMAIN, None)?;
        client.send(value)?;
        rejected(&mut client, "not-authorized")?;
        authentication(&suite, "not_authorized", index as u64 + 1)?;
        suite.wait_for_metric("lonewolf_component_streams 0")?;
    }
    suite.stop()
}

#[test]
fn invalid_handshake_closes_the_tcp_connection_without_the_component_footer() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut client = ComponentClient::connect(suite.component_address(0)?)?;
    let header = client.open(DOMAIN, None)?;
    client.send_handshake_for("different-component-test-secret", &header.id)?;
    client.expect_stream_error("not-authorized")?;
    client.expect_footer()?;
    client.expect_eof()?;
    authentication(&suite, "not_authorized", 1)?;
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    suite.stop()
}

#[test]
fn unknown_missing_and_non_domain_addresses_omit_response_from() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    for (index, to) in [
        Some("unknown.localhost"),
        Some("localhost"),
        Some("a@muc.localhost"),
        Some("muc.localhost/resource"),
        None,
    ]
    .into_iter()
    .enumerate()
    {
        let mut client = ComponentClient::connect(suite.component_address(0)?)?;
        let address = to.map_or_else(String::new, |domain| format!(" to='{domain}'"));
        let response = client.open_with(&format!("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='{NAMESPACE}'{address}>"))?;
        assert!(response.from.is_none());
        rejected(&mut client, "host-unknown")?;
        authentication(&suite, "host_unknown", index as u64 + 1)?;
    }
    suite.stop()
}

#[test]
fn unsupported_content_namespaces_return_invalid_namespace() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    for (index, namespace) in ["jabber:component:connect", "jabber:client", "jabber:server"]
        .into_iter()
        .enumerate()
    {
        let mut client = ComponentClient::connect(suite.component_address(0)?)?;
        client.open_with(&format!("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='{namespace}' to='{DOMAIN}'>"))?;
        rejected(&mut client, "invalid-namespace")?;
        authentication(&suite, "invalid_namespace", index as u64 + 1)?;
    }
    suite.stop()
}

#[test]
fn default_domain_cap_rejects_second_handshake_and_releases_after_close() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut first = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let mut mismatched = ComponentClient::connect(suite.component_address(0)?)?;
    let header = mismatched.open(DOMAIN, None)?;
    mismatched.send_handshake_for("different-component-test-secret", &header.id)?;
    rejected(&mut mismatched, "not-authorized")?;
    authentication(&suite, "not_authorized", 1)?;
    let mut second = ComponentClient::connect(suite.component_address(0)?)?;
    let header = second.open(DOMAIN, None)?;
    second.send_handshake_for(SECRET, &header.id)?;
    rejected(&mut second, "conflict")?;
    authentication(&suite, "conflict", 1)?;
    suite.wait_for_metric("lonewolf_component_streams 1")?;
    first.close()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    let mut replacement = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    authentication(&suite, "success", 2)?;
    replacement.close()?;
    suite.stop()
}

#[test]
fn two_domain_connections_have_independent_ids_lifetimes_and_capacity() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!("{CONFIG}\nmax_connections=2"))?;
    let mut first = ComponentClient::connect(suite.component_address(0)?)?;
    let first_header = first.open(DOMAIN, None)?;
    first.send_handshake_for(SECRET, &first_header.id)?;
    first.expect_handshake()?;
    let mut second = ComponentClient::connect(suite.component_address(0)?)?;
    let second_header = second.open(DOMAIN, None)?;
    assert_ne!(first_header.id, second_header.id);
    second.send_handshake_for(SECRET, &second_header.id)?;
    second.expect_handshake()?;
    suite.wait_for_metric("lonewolf_component_streams 2")?;
    let mut third = ComponentClient::connect(suite.component_address(0)?)?;
    let third_header = third.open(DOMAIN, None)?;
    third.send_handshake_for(SECRET, &third_header.id)?;
    rejected(&mut third, "conflict")?;
    authentication(&suite, "conflict", 1)?;
    first.close()?;
    suite.wait_for_metric("lonewolf_component_streams 1")?;
    let mut replacement = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    suite.wait_for_metric("lonewolf_component_streams 2")?;
    second.close()?;
    replacement.close()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    suite.stop()
}

#[test]
fn silent_negotiation_expires_with_header_error_and_footer() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\n[limits.components]\nnegotiation_timeout_secs=1"
    ))?;
    let mut client = ComponentClient::connect(suite.component_address(0)?)?;
    let header = client.open_with("")?;
    assert!(header.from.is_none());
    rejected(&mut client, "connection-timeout")?;
    authentication(&suite, "timeout", 1)?;
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    suite.stop()
}

#[test]
fn attempt_and_global_connection_limits_refuse_without_xml() -> TestResult {
    for (limits, reason) in [
        (
            "connection_attempts_per_ip={per_second=1,burst=1}",
            "connection_attempts_per_ip",
        ),
        ("max_inbound_connections=1", "max_inbound_connections"),
    ] {
        let mut suite =
            C2sSuite::with_components(&format!("{CONFIG}\n[limits.components]\n{limits}"))?;
        let mut first = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
        let mut refused = ComponentClient::connect(suite.component_address(0)?)?;
        refused.expect_eof()?;
        suite.wait_for_metric(&format!(
            "lonewolf_component_connections_rejected_total{{listener=\"0\",reason=\"{reason}\"}} 1"
        ))?;
        suite.wait_for_metric("lonewolf_component_connections 1")?;
        first.close()?;
        suite.stop()?;
    }
    Ok(())
}

#[test]
fn repeated_handshake_closes_stream_as_unsupported_type() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut client = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    client.send("<handshake/>")?;
    rejected(&mut client, "unsupported-stanza-type")?;
    closed(&suite, "unsupported_stanza_type", 1)?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    suite.stop()
}

#[test]
fn negotiation_footer_peer_error_eof_and_parser_failure_are_accounted() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut footer = ComponentClient::connect(suite.component_address(0)?)?;
    footer.open(DOMAIN, None)?;
    footer.close()?;
    authentication(&suite, "peer_closed", 1)?;
    let mut error = ComponentClient::connect(suite.component_address(0)?)?;
    error.open(DOMAIN, None)?;
    error.send("<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>")?;
    error.expect_eof()?;
    authentication(&suite, "transport_error", 1)?;
    let mut eof = ComponentClient::connect(suite.component_address(0)?)?;
    suite.wait_for_metric("lonewolf_component_connections 1")?;
    eof.shutdown_write()?;
    eof.expect_eof()?;
    authentication(&suite, "transport_error", 2)?;
    let mut malformed = ComponentClient::connect(suite.component_address(0)?)?;
    malformed.open(DOMAIN, None)?;
    malformed.send("<handshake></wrong>")?;
    rejected(&mut malformed, "not-well-formed")?;
    authentication(&suite, "protocol_error", 1)?;
    suite.stop()
}

#[test]
fn authenticated_peer_error_and_transport_loss_skip_xml_and_release_guards() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut peer = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    peer.send("<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>")?;
    peer.expect_eof()?;
    closed(&suite, "peer_error", 1)?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    let mut transport = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    transport.shutdown_write()?;
    transport.expect_eof()?;
    closed(&suite, "transport_error", 1)?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    suite.stop()
}

#[test]
fn socket_byte_metrics_equal_independent_wire_counts() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut client = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    client.close()?;
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    let bytes = client.counters.snapshot();
    suite.wait_for_metric(&format!(
        "lonewolf_component_received_bytes_total {}",
        bytes.written
    ))?;
    suite.wait_for_metric(&format!(
        "lonewolf_component_sent_bytes_total {}",
        bytes.read
    ))?;
    suite.stop()
}

#[test]
fn shutdown_closes_negotiating_and_authenticated_components_within_bound() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut authenticated = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let mut negotiating = ComponentClient::connect(suite.component_address(0)?)?;
    negotiating.open(DOMAIN, None)?;
    suite.wait_for_metric("lonewolf_component_connections 2")?;
    let started = Instant::now();
    let state = std::thread::scope(|scope| -> TestResult<_> {
        let peers = scope.spawn(move || -> Result<(), String> {
            rejected(&mut negotiating, "system-shutdown").map_err(|e| e.to_string())?;
            rejected(&mut authenticated, "system-shutdown").map_err(|e| e.to_string())
        });
        let state = suite
            .stop_with_component_state()?
            .ok_or("missing component shutdown state")?;
        peers
            .join()
            .map_err(|_| "component shutdown reader panicked")?
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        Ok(state)
    })?;
    assert_eq!(
        state,
        lonewolf_core::test_support::ComponentShutdownState {
            connections: 0,
            streams: 0,
            authentication_success: 1,
            authentication_shutdown: 1,
            authentication_total: 2,
            streams_closed_shutdown: 1,
            streams_closed_total: 1,
        }
    );
    assert!(suite.stop_with_s2s_state()?.is_none());
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    Ok(())
}

#[test]
fn absent_component_domains_omit_component_readiness_addresses() -> TestResult {
    let mut suite = C2sSuite::start()?;
    assert!(suite.component.is_none());
    assert!(suite.component_address(0).is_err());
    assert!(!suite.scrape_metrics()?.contains("lonewolf_component_"));
    assert!(suite.stop_with_component_state()?.is_none());
    Ok(())
}

#[test]
fn oversized_handshake_uses_policy_violation_and_releases_connection() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\n[limits.components]\nmax_stanza_bytes=10000"
    ))?;
    let mut client = ComponentClient::connect(suite.component_address(0)?)?;
    client.open(DOMAIN, None)?;
    client.send(&format!("<handshake>{}</handshake>", "a".repeat(10001)))?;
    rejected(&mut client, "policy-violation")?;
    authentication(&suite, "protocol_error", 1)?;
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    suite.stop()
}
