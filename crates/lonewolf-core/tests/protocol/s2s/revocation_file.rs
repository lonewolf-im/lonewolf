// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;
use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use super::super::support::federation::{
    FakeDns, FederatedHost, FederationCa, HostRevocation,
    crl_server::{CrlResponse, CrlServer},
    peer::{self, RawS2sListener},
};
use super::super::support::{C2sSuite, PASSWORD, TestResult};
use super::negotiation::{SingleServer, authentication, expect_bounce};

#[test]
fn revoked_peers_are_rejected_with_a_crl_file_in_both_directions() -> TestResult {
    let mut http = CrlServer::start()?;
    let directory = tempfile::tempdir()?;
    let ca = Arc::new(FederationCa::new(directory.path())?);
    let dns = FakeDns::start()?;
    let key = ca.server_with_crl_urls(
        directory.path(),
        "revoked-peer",
        &["b.test"],
        &[http.url("b.crl")],
    )?;
    let path = directory.path().join("crls.pem");
    let now = OffsetDateTime::now_utc();
    let next_update = now + Duration::days(1);
    ca.write_crl(
        &path,
        &[(key.cert[0].clone(), None)],
        now - Duration::minutes(1),
        next_update,
        1,
    )?;
    http.serve(
        "b.crl",
        CrlResponse::Body(ca.crl(&[], now - Duration::minutes(1), next_update, 1)?),
    );
    let suite = C2sSuite::federated(FederatedHost {
        domain: "a.test".into(),
        revocation: HostRevocation {
            crls_path: Some(path),
            fetch_crls: Some(true),
            ..Default::default()
        },
        enabled: None,
        federation: None,
        extensions: String::new(),
        extra_toml: String::new(),
        ca: Arc::clone(&ca),
        dns: dns.address(),
        completion: None,
    })?;
    let mut server = SingleServer {
        suite,
        dns,
        ca,
        directory,
    };
    let listener = RawS2sListener::bind()?;
    server.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "peer.b.test")],
    );
    server.dns.a("peer.b.test", Ipv4Addr::LOCALHOST);
    let client = peer::client_config(&server.ca, Arc::clone(&key))?;
    let serving = peer::server_config(&server.ca, key, "a.test")?;
    server.suite.create_account("alice", PASSWORD)?;
    let mut alice = server.suite.connect("alice", PASSWORD, "desk")?;
    let mut inbound = server.connect()?;
    inbound.expect_starttls_features()?;
    let mut inbound = inbound.start_tls_with_header(client, "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='b.test' to='a.test'>", None)?;
    inbound.expect_stream_error("not-authorized")?;
    authentication(&server.suite, "inbound", "certificate_revoked", 1)?;
    server.suite.wait_for_metric("lonewolf_s2s_revocation_checks_total{direction=\"inbound\",source=\"file\",phase=\"handshake\",status=\"revoked\",reason=\"none\"} 1")?;
    alice.send("<message type='chat' id='revoked-file' to='bob@b.test/phone'><body>must bounce</body></message>")?;
    let mut outbound = listener.accept("b.test", "a.test", serving, true)?;
    outbound.answer_close()?;
    expect_bounce(&mut alice, "revoked-file", "remote-server-timeout")?;
    authentication(&server.suite, "outbound", "certificate_revoked", 1)?;
    server.suite.wait_for_metric("lonewolf_s2s_revocation_checks_total{direction=\"outbound\",source=\"file\",phase=\"handshake\",status=\"revoked\",reason=\"none\"} 1")?;
    let metrics = server.suite.wait_for_metric(&format!(
        "lonewolf_s2s_crl_file_next_update_seconds {}",
        next_update.unix_timestamp()
    ))?;
    assert!(!metrics.contains("lonewolf_s2s_crl_fetches_total"));
    assert_eq!(http.requests("b.crl"), 0);
    alice.close()?;
    server.stop()?;
    http.stop()?;
    Ok(())
}

#[test]
fn crl_file_state_at_startup() -> TestResult {
    let directory = tempfile::tempdir()?;
    let ca = Arc::new(FederationCa::new(directory.path())?);
    let mut dns = FakeDns::start()?;
    let path = directory.path().join("crls.pem");
    let host = || FederatedHost {
        domain: "a.test".into(),
        revocation: HostRevocation {
            crls_path: Some(path.clone()),
            ..Default::default()
        },
        enabled: None,
        federation: None,
        extensions: String::new(),
        extra_toml: String::new(),
        ca: Arc::clone(&ca),
        dns: dns.address(),
        completion: None,
    };
    std::fs::write(&path, b"invalid CRL file")?;
    assert!(C2sSuite::federated(host()).is_err());
    let now = OffsetDateTime::now_utc();
    ca.write_crl(
        &path,
        &[],
        now - Duration::minutes(2),
        now - Duration::minutes(1),
        1,
    )?;
    let mut suite = C2sSuite::federated(host())?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let key = ca.server(directory.path(), "peer", &["b.test"])?;
    let mut inbound = peer::RawS2sPeer::connect(suite.s2s_addresses()?[0], "b.test", "a.test")?;
    inbound.expect_starttls_features()?;
    let mut inbound = inbound.start_tls_with_header(peer::client_config(&ca, key)?, "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='b.test' to='a.test'>", None)?;
    inbound.expect_stream_error("not-authorized")?;
    authentication(&suite, "inbound", "revocation_stale", 1)?;
    let metrics =
        suite.wait_for_metric("lonewolf_s2s_crl_file_load_failures_total{reason=\"stale\"} 2")?;
    assert!(!metrics.contains("lonewolf_s2s_crl_file_next_update_seconds"));
    suite.wait_for_metric("lonewolf_s2s_revocation_checks_total{direction=\"inbound\",source=\"file\",phase=\"handshake\",status=\"unknown\",reason=\"stale\"} 1")?;
    alice.close()?;
    suite.stop()?;
    dns.stop()?;
    Ok(())
}
