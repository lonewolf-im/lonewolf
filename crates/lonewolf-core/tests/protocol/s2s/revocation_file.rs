// SPDX-License-Identifier: Apache-2.0

use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration as Wait, Instant};

use time::{Duration, OffsetDateTime};

use super::super::support::federation::{
    FakeDns, FederatedHost, FederatedPair, FederationCa, HostRevocation, PairOptions,
    crl_server::{CrlResponse, CrlServer},
    peer::{self, RawS2sListener},
    pki::certificate,
    thread_result,
};
use super::super::support::{
    C2sSuite, PASSWORD, TestResult,
    tls::{block_crl_reads, wait_for_crl_reader},
};
use super::negotiation::{SingleServer, authentication, closed, expect_bounce};

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
        bidirectional: Some(false),
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
        bidirectional: Some(false),
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

fn checked(
    suite: &C2sSuite,
    direction: &str,
    phase: &str,
    status: &str,
    reason: &str,
    count: u64,
) -> TestResult {
    suite.wait_for_metric(&format!("lonewolf_s2s_revocation_checks_total{{direction=\"{direction}\",source=\"file\",phase=\"{phase}\",status=\"{status}\",reason=\"{reason}\"}} {count}"))?;
    Ok(())
}

#[test]
fn unrevoked_peers_federate_with_crl_files() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            crl_files: true,
            ..Default::default()
        },
    )?;
    assert!(pair.a_crls.as_ref().is_some_and(|path| path.is_file()));
    assert!(pair.b_crls.as_ref().is_some_and(|path| path.is_file()));
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send("<message type='chat' to='bob@b.test/phone'><body>file a to b</body></message>")?;
    assert_eq!(
        bob.receive()?.child("jabber:client", "body")?.text,
        "file a to b"
    );
    bob.send("<message type='chat' to='alice@a.test/desk'><body>file b to a</body></message>")?;
    assert_eq!(
        alice.receive()?.child("jabber:client", "body")?.text,
        "file b to a"
    );
    for suite in [&pair.a, &pair.b] {
        for direction in ["inbound", "outbound"] {
            authentication(suite, direction, "success", 1)?;
            checked(suite, direction, "handshake", "good", "none", 1)?;
        }
        suite.wait_for_metrics("file nextUpdate", |body| {
            super::sample(body, "lonewolf_s2s_crl_file_next_update_seconds")
                .is_ok_and(|value| value > 0)
        })?;
        assert!(
            !suite
                .fixture_path()
                .join("s2s-revalidation-interval-ms")
                .exists()
        );
    }
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn crl_file_update_revoking_a_live_peer_closes_its_links() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            crl_files: true,
            b_revocation: HostRevocation {
                revalidation_interval: Some(Wait::from_millis(500)),
                ..Default::default()
            },
            limits: "failure_backoff_initial_secs = 1".into(),
            ..Default::default()
        },
    )?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send("<message type='chat' to='bob@b.test/phone'><body>before revocation a to b</body></message>")?;
    assert_eq!(
        bob.receive()?.child("jabber:client", "body")?.text,
        "before revocation a to b"
    );
    bob.send("<message type='chat' to='alice@a.test/desk'><body>before revocation b to a</body></message>")?;
    assert_eq!(
        alice.receive()?.child("jabber:client", "body")?.text,
        "before revocation b to a"
    );
    let actual = certificate(&pair.a.fixture_path().join("certificate-host.pem"))?;
    let now = OffsetDateTime::now_utc();
    pair.ca.write_crl(
        pair.b_crls.as_deref().ok_or("missing b CRL file")?,
        &[(actual, None)],
        now - Duration::minutes(1),
        now + Duration::days(1),
        2,
    )?;
    for direction in ["inbound", "outbound"] {
        closed(&pair.b, direction, "certificate_revoked", 1)?;
        checked(&pair.b, direction, "recheck", "revoked", "none", 1)?;
        closed(&pair.a, direction, "peer_error", 1)?;
    }
    pair.a
        .wait_for_metrics("old outbound link released", |body| {
            super::sample(body, "lonewolf_s2s_outbound_links{state=\"ready\"}")
                .is_ok_and(|value| value == 0)
                && super::sample(body, "lonewolf_s2s_outbound_links{state=\"connecting\"}")
                    .is_ok_and(|value| value == 0)
        })?;
    alice.send("<message type='chat' id='file-revoked' to='bob@b.test/phone'><body>must bounce</body></message>")?;
    expect_bounce(&mut alice, "file-revoked", "remote-server-timeout")?;
    pair.b.wait_for_metric("lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"certificate_revoked\"} 1")?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_negotiation_duration_seconds_count{direction=\"inbound\"} 2",
    )?;
    checked(&pair.b, "inbound", "handshake", "revoked", "none", 1)?;
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn stale_or_unusable_crl_files_stop_federation_until_refreshed() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            crl_files: true,
            b_revocation: HostRevocation {
                revalidation_interval: Some(Wait::from_millis(500)),
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send(
        "<message type='chat' to='bob@b.test/phone'><body>before stale a to b</body></message>",
    )?;
    assert_eq!(
        bob.receive()?.child("jabber:client", "body")?.text,
        "before stale a to b"
    );
    bob.send(
        "<message type='chat' to='alice@a.test/desk'><body>before stale b to a</body></message>",
    )?;
    assert_eq!(
        alice.receive()?.child("jabber:client", "body")?.text,
        "before stale b to a"
    );
    pair.a
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
    let actual = certificate(&pair.a.fixture_path().join("certificate-host.pem"))?;
    let key = PrivateKeyDer::from_pem_file(pair.a.fixture_path().join("private-key-host.pem"))?;
    let key = Arc::new(rustls::sign::CertifiedKey::from_der(
        vec![actual],
        key,
        &rustls_graviola::default_provider(),
    )?);
    let client = peer::client_config(&pair.ca, key)?;
    let path = pair.b_crls.as_deref().ok_or("missing b CRL file")?;
    let now = OffsetDateTime::now_utc();
    pair.ca.write_crl(
        path,
        &[],
        now - Duration::hours(1),
        now + Duration::seconds(3),
        2,
    )?;
    for direction in ["inbound", "outbound"] {
        closed(&pair.b, direction, "revocation_stale", 1)?;
        closed(&pair.a, direction, "peer_error", 1)?;
    }
    let mut stale = peer::RawS2sPeer::connect(pair.b.s2s_addresses()?[0], "a.test", "b.test")?;
    stale.expect_starttls_features()?;
    let mut stale = stale.start_tls_with_header(Arc::clone(&client), "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='a.test' to='b.test'>", None)?;
    stale.expect_stream_error("not-authorized")?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"revocation_stale\"} 1",
    )?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_negotiation_duration_seconds_count{direction=\"inbound\"} 2",
    )?;
    checked(&pair.b, "inbound", "handshake", "unknown", "stale", 1)?;
    pair.b.wait_for_metrics("stale file load", |body| {
        super::sample(
            body,
            "lonewolf_s2s_crl_file_load_failures_total{reason=\"stale\"}",
        )
        .is_ok_and(|value| value > 0)
    })?;
    let mut invalid =
        tempfile::NamedTempFile::new_in(path.parent().ok_or("missing CRL directory")?)?;
    invalid.write_all(b"invalid CRL file")?;
    invalid.persist(path).map_err(|error| error.error)?;
    let mut invalid = peer::RawS2sPeer::connect(pair.b.s2s_addresses()?[0], "a.test", "b.test")?;
    invalid.expect_starttls_features()?;
    let mut invalid = invalid.start_tls_with_header(client, "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='a.test' to='b.test'>", None)?;
    invalid.expect_stream_error("not-authorized")?;
    pair.b.wait_for_metric("lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"revocation_unavailable\"} 1")?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_negotiation_duration_seconds_count{direction=\"inbound\"} 3",
    )?;
    checked(&pair.b, "inbound", "handshake", "unknown", "invalid", 1)?;
    pair.b
        .wait_for_metric("lonewolf_s2s_crl_file_load_failures_total{reason=\"invalid\"} 1")?;
    let now = OffsetDateTime::now_utc();
    pair.ca.write_crl(
        path,
        &[],
        now - Duration::minutes(1),
        now + Duration::days(1),
        3,
    )?;
    let released = pair.a.wait_for_metrics("released outbound links", |body| {
        super::sample(body, "lonewolf_s2s_outbound_links{state=\"ready\"}")
            .is_ok_and(|value| value == 0)
            && super::sample(body, "lonewolf_s2s_outbound_links{state=\"connecting\"}")
                .is_ok_and(|value| value == 0)
    })?;
    assert_eq!(
        super::sample(&released, "lonewolf_s2s_outbound_links{state=\"backoff\"}")?,
        0
    );
    alice.send(
        "<message type='chat' to='bob@b.test/phone'><body>one recovery message</body></message>",
    )?;
    assert_eq!(
        bob.receive()?.child("jabber:client", "body")?.text,
        "one recovery message"
    );
    pair.b.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"success\"} 2",
    )?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_negotiation_duration_seconds_count{direction=\"inbound\"} 4",
    )?;
    checked(&pair.b, "inbound", "handshake", "good", "none", 2)?;
    alice.close()?;
    bob.close()?;
    let state = pair
        .b
        .stop_with_s2s_state()?
        .ok_or("missing b shutdown state")?;
    assert_eq!(state.dropped_shutdown, 0);
    assert_eq!(state.dropped_connection_lost, 0);
    assert_eq!(state.queued_stanzas, 0);
    assert_eq!(state.queued_bytes, 0);
    pair.a.stop()?;
    pair.dns.stop()
}

#[test]
fn shutdown_with_crl_file_checks_is_clean() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            crl_files: true,
            ..Default::default()
        },
    )?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send(
        "<message type='chat' to='bob@b.test/phone'><body>shutdown a to b</body></message>",
    )?;
    assert_eq!(
        bob.receive()?.child("jabber:client", "body")?.text,
        "shutdown a to b"
    );
    bob.send("<message type='chat' to='alice@a.test/desk'><body>shutdown b to a</body></message>")?;
    assert_eq!(
        alice.receive()?.child("jabber:client", "body")?.text,
        "shutdown b to a"
    );
    for suite in [&pair.a, &pair.b] {
        suite.wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
    }
    alice.close()?;
    bob.close()?;
    let (a, b) = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            let started = Instant::now();
            (
                thread_result(pair.a.stop_with_s2s_state()),
                started.elapsed(),
            )
        });
        let b = scope.spawn(|| {
            let started = Instant::now();
            (
                thread_result(pair.b.stop_with_s2s_state()),
                started.elapsed(),
            )
        });
        (a.join(), b.join())
    });
    for result in [a, b] {
        let (state, elapsed) = result.map_err(|_| "server shutdown worker panicked")?;
        assert!(elapsed < Wait::from_secs(10));
        let state = state?.ok_or("missing paired shutdown state")?;
        assert_eq!(state.dropped_shutdown, 0);
        assert_eq!(state.dropped_connection_lost, 0);
        assert_eq!(state.queued_stanzas, 0);
        assert_eq!(state.queued_bytes, 0);
    }
    pair.dns.stop()?;
    let directory = tempfile::tempdir()?;
    let ca = Arc::new(FederationCa::new(directory.path())?);
    let mut dns = FakeDns::start()?;
    let path = directory.path().join("crls.pem");
    let now = OffsetDateTime::now_utc();
    ca.write_crl(
        &path,
        &[],
        now - Duration::minutes(1),
        now + Duration::days(1),
        1,
    )?;
    let mut suite = C2sSuite::federated(FederatedHost {
        domain: "a.test".into(),
        revocation: HostRevocation {
            crls_path: Some(path.clone()),
            ..Default::default()
        },
        enabled: None,
        bidirectional: Some(false),
        federation: None,
        extensions: String::new(),
        extra_toml: "[limits.s2s]\nnegotiation_timeout_secs=60".into(),
        ca: Arc::clone(&ca),
        dns: dns.address(),
        completion: None,
    })?;
    let key = ca.server(directory.path(), "blocked-peer", &["b.test"])?;
    let client = peer::client_config(&ca, key)?;
    block_crl_reads(&path)?;
    let mut raw = peer::RawS2sPeer::connect(suite.s2s_addresses()?[0], "b.test", "a.test")?;
    raw.expect_starttls_features()?;
    std::thread::scope(|scope| -> TestResult {
        let worker = scope.spawn(move || thread_result((|| -> TestResult {
            let mut raw = raw.start_tls_with_header(client, "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='b.test' to='a.test'>", None)?;
            raw.expect_stream_error("system-shutdown")
        })()));
        let writer = wait_for_crl_reader(&path)?;
        let started = Instant::now();
        let state = suite
            .stop_with_s2s_state()?
            .ok_or("missing blocked-load shutdown state")?;
        assert!(started.elapsed() < Wait::from_secs(10));
        assert_eq!(state.dropped_shutdown, 0);
        assert_eq!(state.dropped_connection_lost, 0);
        assert_eq!(state.queued_stanzas, 0);
        assert_eq!(state.queued_bytes, 0);
        drop(writer);
        worker
            .join()
            .map_err(|_| "blocked peer worker panicked")??;
        Ok(())
    })?;
    dns.stop()
}
