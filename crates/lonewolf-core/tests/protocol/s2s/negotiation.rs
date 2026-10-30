// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use super::super::support::federation::{
    FakeDns, FederatedHost, FederatedPair, FederationCa, PairOptions,
    peer::{self, RawS2sPeer},
};
use super::super::support::{C2sSuite, PASSWORD, TestResult, tls};

pub(super) struct SingleServer {
    pub suite: C2sSuite,
    pub dns: FakeDns,
    pub ca: Arc<FederationCa>,
    pub directory: tempfile::TempDir,
}

impl SingleServer {
    pub fn start(extra: &str) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let ca = Arc::new(FederationCa::new(directory.path())?);
        let dns = FakeDns::start()?;
        let suite = C2sSuite::federated(FederatedHost {
            domain: "a.test".into(),
            enabled: None,
            federation: None,
            extensions: String::new(),
            extra_toml: extra.into(),
            ca: Arc::clone(&ca),
            dns: dns.address(),
            completion: None,
        })?;
        Ok(Self {
            suite,
            dns,
            ca,
            directory,
        })
    }

    pub fn connect(&self) -> TestResult<RawS2sPeer> {
        RawS2sPeer::connect(self.suite.s2s_addresses()?[0], "b.test", "a.test")
    }

    pub fn client_config(&self) -> TestResult<Arc<rustls::ClientConfig>> {
        peer::client_config(
            &self.ca,
            self.ca.server(self.directory.path(), "peer", &["b.test"])?,
        )
    }

    pub fn stop(&mut self) -> TestResult {
        self.suite.stop()?;
        self.dns.stop()
    }
}

pub(super) fn authentication(
    suite: &C2sSuite,
    direction: &str,
    outcome: &str,
    count: u64,
) -> TestResult {
    suite.wait_for_metric(&format!("lonewolf_s2s_authentications_total{{direction=\"{direction}\",outcome=\"{outcome}\"}} {count}"))?;
    suite.wait_for_metric(&format!(
        "lonewolf_s2s_negotiation_duration_seconds_count{{direction=\"{direction}\"}} {count}"
    ))?;
    Ok(())
}

pub(super) fn closed(suite: &C2sSuite, direction: &str, outcome: &str, count: u64) -> TestResult {
    suite.wait_for_metric(&format!("lonewolf_s2s_streams_closed_total{{direction=\"{direction}\",outcome=\"{outcome}\"}} {count}"))?;
    suite.wait_for_metric(&format!(
        "lonewolf_s2s_connections{{direction=\"{direction}\"}} 0"
    ))?;
    suite.wait_for_metric(&format!(
        "lonewolf_s2s_streams{{direction=\"{direction}\"}} 0"
    ))?;
    Ok(())
}

pub(super) fn expect_bounce(
    client: &mut super::super::support::Client,
    id: &str,
    condition: &str,
) -> TestResult {
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "message");
    assert_eq!(reply.attribute("type"), Some("error"));
    assert_eq!(reply.attribute("id"), Some(id));
    assert_eq!(reply.attribute("to"), Some("alice@a.test/desk"));
    assert_eq!(reply.attribute("from"), Some("bob@b.test/phone"));
    reply
        .child("jabber:client", "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", condition)?;
    Ok(())
}

#[test]
fn localhost_only_configuration_keeps_federation_inactive() -> TestResult {
    let mut suite = C2sSuite::start()?;
    let path = suite.fixture_path().join("lonewolf.toml");
    let config = std::fs::read_to_string(&path)?.replace("[s2s]\nenabled = false", "[s2s]");
    std::fs::write(path, config)?;
    suite.restart()?;
    assert!(suite.s2s.is_none());
    assert!(!suite.scrape_metrics()?.contains("lonewolf_s2s_"));
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<message type='chat' to='bob@remote.test' id='inactive'><body>inactive</body></message>",
    )?;
    let reply = alice.receive()?;
    reply.assert_name("jabber:client", "message");
    assert_eq!(reply.attribute("type"), Some("error"));
    assert_eq!(reply.attribute("id"), Some("inactive"));
    reply.child("jabber:client", "error")?.child(
        "urn:ietf:params:xml:ns:xmpp-stanzas",
        "remote-server-not-found",
    )?;
    alice.close()?;
    assert_eq!(suite.stop_with_s2s_state()?, None);
    Ok(())
}

#[test]
fn certificate_host_federates_by_default() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            a_enabled: None,
            b_enabled: None,
            ..PairOptions::default()
        },
    )?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send(
        "<message type='chat' to='bob@b.test/phone'><body>enabled by certificate</body></message>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' xml:lang='en'><body>enabled by certificate</body></message>")?;
    authentication(&pair.a, "outbound", "success", 1)?;
    authentication(&pair.b, "inbound", "success", 1)?;
    pair.a
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn disabled_federation_opens_no_listener() -> TestResult {
    let directory = tempfile::tempdir()?;
    let ca = Arc::new(FederationCa::new(directory.path())?);
    let mut dns = FakeDns::start()?;
    let mut suite = C2sSuite::federated(FederatedHost {
        domain: "a.test".into(),
        enabled: Some(false),
        federation: None,
        extensions: String::new(),
        extra_toml: String::new(),
        ca,
        dns: dns.address(),
        completion: None,
    })?;
    assert!(suite.s2s.is_none());
    assert!(!suite.scrape_metrics()?.contains("lonewolf_s2s_"));
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat' id='disabled'><body>disabled</body></message>",
    )?;
    expect_bounce(&mut alice, "disabled", "remote-server-not-found")?;
    assert_eq!(
        dns.query_count(
            "_xmpp-server._tcp.b.test",
            hickory_proto::rr::RecordType::SRV
        ),
        0
    );
    alice.close()?;
    assert_eq!(suite.stop_with_s2s_state()?, None);
    dns.stop()
}

#[test]
fn host_opt_out_keeps_one_domain_local() -> TestResult {
    let mut pair = FederatedPair::start("a.test", "b.test", PairOptions::default())?;
    pair.ca
        .server(pair.a.fixture_path(), "host", &["a.test", "local.test"])?;
    let path = pair.a.fixture_path().join("lonewolf.toml");
    let mut config = std::fs::read_to_string(&path)?;
    config.push_str("\n[hosts.'local.test']\nfederation=false\n[hosts.'local.test'.tls]\ncertificate_chain_path='certificate-host.pem'\nprivate_key_path='private-key-host.pem'\n");
    std::fs::write(path, config)?;
    pair.a.restart()?;
    pair.dns.srv(
        "a.test",
        &[(0, 0, pair.a.s2s_addresses()?[0].port(), "a.a.test")],
    );
    pair.a.create_account("alice", PASSWORD)?;
    pair.a.create_account_jid("local@local.test", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>public host</body></message>")?;
    let reply = bob.receive()?;
    assert_eq!(reply.child("jabber:client", "body")?.text, "public host");
    authentication(&pair.a, "outbound", "success", 1)?;
    authentication(&pair.b, "inbound", "success", 1)?;
    pair.a.domain = "local.test".into();
    let mut local = pair.a.connect("local", PASSWORD, "desk")?;
    local.send(
        "<message to='bob@b.test/phone' type='chat' id='local'><body>local host</body></message>",
    )?;
    let reply = local.receive()?;
    assert_eq!(reply.attribute("type"), Some("error"));
    assert_eq!(reply.attribute("id"), Some("local"));
    reply.child("jabber:client", "error")?.child(
        "urn:ietf:params:xml:ns:xmpp-stanzas",
        "remote-server-not-found",
    )?;
    assert_eq!(
        pair.dns.query_count(
            "_xmpp-server._tcp.b.test",
            hickory_proto::rr::RecordType::SRV
        ),
        1
    );
    let mut peer = RawS2sPeer::connect_with_response_from(
        pair.a.s2s_addresses()?[0],
        "b.test",
        "local.test",
        "a.test",
    )?;
    peer.expect_stream_error("host-unknown")?;
    authentication(&pair.a, "inbound", "host_unknown", 1)?;
    local.close()?;
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn peer_with_valid_certificate_authenticates() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_offered()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    authentication(&fixture.suite, "inbound", "success", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 1")?;
    peer.close()?;
    closed(&fixture.suite, "inbound", "stream_end", 1)?;
    fixture.stop()
}

#[test]
fn peer_without_client_certificate_is_not_authorized() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let config = Arc::new(tls::client_config(
        fixture.ca.roots()?,
        rustls::DEFAULT_VERSIONS,
    )?);
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls_with_header(config, "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='b.test' to='a.test' version='1.0'>", None)?;
    peer.expect_stream_error("not-authorized")?;
    authentication(&fixture.suite, "inbound", "no_certificate", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
    fixture.stop()
}

#[test]
fn peer_certificate_for_another_domain_is_not_authorized() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let config = peer::client_config(
        &fixture.ca,
        fixture.ca.wrong_name(fixture.directory.path(), "b.test")?,
    )?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls_with_header(config, "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='b.test' to='a.test' version='1.0'>", None)?;
    peer.expect_stream_error("not-authorized")?;
    authentication(&fixture.suite, "inbound", "certificate_name", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
    fixture.stop()
}

#[test]
fn peer_certificate_with_only_client_auth_fails_tls() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let config = peer::client_config(
        &fixture.ca,
        fixture
            .ca
            .client_auth_only(fixture.directory.path(), "b.test")?,
    )?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    assert_tls_rejection(peer.start_tls(config))?;
    authentication(&fixture.suite, "inbound", "tls_failure", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
    fixture.stop()
}

#[test]
fn peer_certificate_from_untrusted_ca_fails_tls() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let other = tempfile::tempdir()?;
    let untrusted = FederationCa::new(other.path())?;
    let config = peer::client_config(
        &fixture.ca,
        untrusted.server(other.path(), "peer", &["b.test"])?,
    )?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    assert_tls_rejection(peer.start_tls(config))?;
    authentication(&fixture.suite, "inbound", "tls_failure", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
    fixture.stop()
}

#[test]
fn peer_with_expired_certificate_fails_tls() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let config = peer::client_config(
        &fixture.ca,
        fixture.ca.expired(fixture.directory.path(), "b.test")?,
    )?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    assert_tls_rejection(peer.start_tls(config))?;
    authentication(&fixture.suite, "inbound", "tls_failure", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
    fixture.stop()
}

fn assert_tls_rejection(result: TestResult<RawS2sPeer>) -> TestResult {
    let error = result.err().ok_or("invalid certificate completed TLS")?;
    let error = match error.downcast_ref::<quick_xml::Error>() {
        Some(quick_xml::Error::Io(error)) => error.as_ref(),
        _ => return Err(format!("TLS failure did not return an XML I/O error: {error:?}").into()),
    };
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof, "{error}");
    Ok(())
}

#[test]
fn srv_id_and_xmpp_addr_certificates_authenticate() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let keys = [
        fixture.ca.srv_id(fixture.directory.path(), "b.test")?,
        fixture.ca.xmpp_addr(fixture.directory.path(), "b.test")?,
    ];
    for (index, key) in keys.into_iter().enumerate() {
        let mut peer = fixture.connect()?;
        peer.expect_starttls_features()?;
        let mut peer = peer.start_tls(peer::client_config(&fixture.ca, key)?)?;
        peer.expect_external_offered()?;
        peer.auth_external(Some("b.test"))?;
        peer.expect_sasl_success()?;
        let mut peer = peer.restart("b.test", "a.test")?;
        authentication(&fixture.suite, "inbound", "success", index as u64 + 1)?;
        peer.close()?;
        closed(&fixture.suite, "inbound", "stream_end", index as u64 + 1)?;
    }
    fixture.stop()
}

#[test]
fn header_without_from_after_tls_is_not_authorized() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls_with_header(fixture.client_config()?, "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' to='a.test' version='1.0'>", None)?;
    peer.expect_stream_error("not-authorized")?;
    authentication(&fixture.suite, "inbound", "missing_from", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
    fixture.stop()
}

#[test]
fn unknown_to_gets_host_unknown() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let mut peer = RawS2sPeer::connect_with_response_from(
        fixture.suite.s2s_addresses()?[0],
        "b.test",
        "unknown.test",
        "a.test",
    )?;
    peer.expect_stream_error("host-unknown")?;
    authentication(&fixture.suite, "inbound", "host_unknown", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
    fixture.stop()
}

#[test]
fn stanza_before_authentication_gets_not_authorized() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_offered()?;
    peer.send("<message from='bob@b.test' to='alice@a.test'><body>before SASL</body></message>")?;
    peer.expect_stream_error("not-authorized")?;
    authentication(&fixture.suite, "inbound", "protocol", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
    fixture.stop()
}

#[test]
fn mismatched_authzid_gets_invalid_authzid() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_offered()?;
    for _ in 0..2 {
        peer.auth_external(Some("other.test"))?;
        peer.receive()?.assert_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-authzid/></failure>",
        )?;
    }
    peer.answer_close()?;
    authentication(&fixture.suite, "inbound", "invalid_authzid", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
    fixture.stop()
}

#[test]
fn spoofed_stanza_from_gets_invalid_from() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_offered()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    authentication(&fixture.suite, "inbound", "success", 1)?;
    peer.send("<message from='bob@other.test' to='alice@a.test'><body>spoof</body></message>")?;
    peer.expect_stream_error("invalid-from")?;
    closed(&fixture.suite, "inbound", "invalid_from", 1)?;
    fixture.stop()
}

#[test]
fn stanza_to_another_local_host_gets_host_unknown() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    fixture.ca.server(
        fixture.suite.fixture_path(),
        "host",
        &["a.test", "other.test"],
    )?;
    let path = fixture.suite.fixture_path().join("lonewolf.toml");
    let mut config = std::fs::read_to_string(&path)?;
    config.push_str("\n[hosts.'other.test'.tls]\ncertificate_chain_path='certificate-host.pem'\nprivate_key_path='private-key-host.pem'\n");
    std::fs::write(path, config)?;
    fixture.suite.restart()?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_offered()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    authentication(&fixture.suite, "inbound", "success", 1)?;
    peer.send("<message from='bob@b.test' to='alice@other.test'><body>different local host</body></message>")?;
    peer.expect_stream_error("host-unknown")?;
    closed(&fixture.suite, "inbound", "host_unknown", 1)?;
    fixture.stop()
}

#[test]
fn stanza_without_to_gets_improper_addressing() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_offered()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    authentication(&fixture.suite, "inbound", "success", 1)?;
    peer.send("<message from='bob@b.test'><body>missing destination</body></message>")?;
    peer.expect_stream_error("improper-addressing")?;
    closed(&fixture.suite, "inbound", "improper_addressing", 1)?;
    fixture.stop()
}

#[test]
fn dialback_element_gets_unsupported_stanza_type() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_offered()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    authentication(&fixture.suite, "inbound", "success", 1)?;
    peer.send(
        "<db:result xmlns:db='jabber:server:dialback' from='b.test' to='a.test'>key</db:result>",
    )?;
    peer.expect_stream_error("unsupported-stanza-type")?;
    closed(&fixture.suite, "inbound", "unsupported_stanza_type", 1)?;
    fixture.stop()
}

#[test]
fn second_stream_beyond_limit_gets_conflict() -> TestResult {
    let mut fixture = SingleServer::start("[limits.s2s]\nmax_inbound_streams_per_domain=1")?;
    let mut first = fixture.connect()?;
    first.expect_starttls_features()?;
    let mut first = first.start_tls(fixture.client_config()?)?;
    first.expect_external_offered()?;
    first.auth_external(Some("b.test"))?;
    first.expect_sasl_success()?;
    let mut first = first.restart("b.test", "a.test")?;
    authentication(&fixture.suite, "inbound", "success", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 1")?;
    let mut second = fixture.connect()?;
    second.expect_starttls_features()?;
    let mut second = second.start_tls(fixture.client_config()?)?;
    second.expect_external_offered()?;
    second.auth_external(Some("b.test"))?;
    second.expect_sasl_success()?;
    let mut second = second.restart("b.test", "a.test")?;
    second.expect_stream_error("conflict")?;
    authentication(&fixture.suite, "inbound", "success", 2)?;
    fixture.suite.wait_for_metric(
        "lonewolf_s2s_streams_closed_total{direction=\"inbound\",outcome=\"conflict\"} 1",
    )?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 1")?;
    first.close()?;
    closed(&fixture.suite, "inbound", "stream_end", 1)?;
    fixture.stop()
}
