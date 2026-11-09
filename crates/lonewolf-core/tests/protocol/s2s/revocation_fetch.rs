// SPDX-License-Identifier: Apache-2.0

use lonewolf_core::config::TlsMode;

use rustls::pki_types::pem::PemObject;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration as Wait, Instant};

use time::{Duration, OffsetDateTime};

use super::super::support::federation::{
    FederatedPair, HostRevocation, PairOptions,
    crl_server::{CrlResponse, CrlServer},
    peer::{self, RawS2sListener, RawS2sPeer},
    pki::certificate,
};
use super::super::support::{C2sSuite, PASSWORD, TestResult};
use super::negotiation::{SingleServer, authentication, closed, expect_bounce};

fn crl_url(http: &CrlServer, mode: TlsMode, path: &str) -> String {
    if mode == TlsMode::Direct {
        format!("http://crl.test:{}/{path}", http.port())
    } else {
        http.url(path)
    }
}

fn assert_crl_host_dns(
    dns: &super::super::support::federation::FakeDns,
    mode: TlsMode,
) -> TestResult {
    use hickory_proto::rr::RecordType;
    if mode == TlsMode::Direct {
        assert!(dns.query_count("crl.test", RecordType::A) > 0);
        for service in ["_xmpp-server._tcp.crl.test", "_xmpps-server._tcp.crl.test"] {
            assert_eq!(dns.query_count(service, RecordType::SRV), 0);
        }
    }
    Ok(())
}

#[test]
fn revoked_peer_is_rejected_with_a_fetched_crl_in_both_directions() -> TestResult {
    revoked_peer_is_rejected_with_a_fetched_crl_in_both_directions_transport(TlsMode::StartTls)
}

#[test]
fn direct_tls_revoked_peer_is_rejected_with_a_fetched_crl_in_both_directions() -> TestResult {
    revoked_peer_is_rejected_with_a_fetched_crl_in_both_directions_transport(TlsMode::Direct)
}

fn revoked_peer_is_rejected_with_a_fetched_crl_in_both_directions_transport(
    mode: TlsMode,
) -> TestResult {
    let mut http = CrlServer::start()?;
    let mut server = SingleServer::start("")?;
    server.set_transport(mode)?;
    server.dns.a("crl.test", Ipv4Addr::LOCALHOST);
    let listener = RawS2sListener::bind()?.with_transport(mode);
    server.dns.srv_with_mode(
        mode,
        "b.test",
        &[(0, 0, listener.address()?.port(), "peer.b.test")],
    );
    server.dns.a("peer.b.test", Ipv4Addr::LOCALHOST);
    let key = server.ca.server_with_crl_urls(
        server.directory.path(),
        "revoked-peer",
        &["b.test"],
        &[crl_url(&http, mode, "revoked.crl")],
    )?;
    let now = OffsetDateTime::now_utc();
    let der = server.ca.crl(
        &[(key.cert[0].clone(), None)],
        now - Duration::minutes(1),
        now + Duration::days(1),
        1,
    )?;
    http.serve("revoked.crl", CrlResponse::Body(der));
    let client = peer::client_config(&server.ca, Arc::clone(&key))?;
    let serving = peer::server_config(&server.ca, key, "a.test")?;
    server.suite.create_account("alice", PASSWORD)?;
    let mut alice = server.suite.connect("alice", PASSWORD, "desk")?;

    let mut inbound = peer::RawS2sPeer::protected(
        mode,
        server.suite.s2s_addresses()?[0],
        "b.test",
        "a.test",
        client,
        None,
    )?;
    inbound.expect_stream_error("not-authorized")?;
    authentication(&server.suite, "inbound", "certificate_revoked", 1)?;
    server.suite.wait_for_metric("lonewolf_s2s_revocation_checks_total{direction=\"inbound\",source=\"fetched\",phase=\"handshake\",status=\"revoked\",reason=\"none\"} 1")?;

    alice.send("<message type='chat' id='revoked-peer' to='bob@b.test/phone'><body>must bounce</body></message>")?;
    let mut outbound = listener.accept("b.test", "a.test", serving, true)?;
    outbound.answer_close()?;
    expect_bounce(&mut alice, "revoked-peer", "remote-server-timeout")?;
    authentication(&server.suite, "outbound", "certificate_revoked", 1)?;
    server.suite.wait_for_metric("lonewolf_s2s_revocation_checks_total{direction=\"outbound\",source=\"fetched\",phase=\"handshake\",status=\"revoked\",reason=\"none\"} 1")?;
    assert_eq!(http.requests("revoked.crl"), 1);

    alice.close()?;
    assert_crl_host_dns(&server.dns, mode)?;
    server.stop()?;
    http.stop()?;
    Ok(())
}

#[test]
fn peers_without_a_usable_crl_federate_with_an_unknown_status() -> TestResult {
    peers_without_a_usable_crl_federate_with_an_unknown_status_transport(TlsMode::StartTls)
}

#[test]
fn direct_tls_peers_without_a_usable_crl_federate_with_an_unknown_status() -> TestResult {
    peers_without_a_usable_crl_federate_with_an_unknown_status_transport(TlsMode::Direct)
}

fn peers_without_a_usable_crl_federate_with_an_unknown_status_transport(
    mode: TlsMode,
) -> TestResult {
    let mut http = CrlServer::start()?;
    let mut server = SingleServer::start("")?;
    server.set_transport(mode)?;
    server.dns.a("crl.test", Ipv4Addr::LOCALHOST);
    let listener = RawS2sListener::bind()?.with_transport(mode);
    server.dns.srv_with_mode(
        mode,
        "b.test",
        &[(0, 0, listener.address()?.port(), "peer.b.test")],
    );
    server.dns.a("peer.b.test", Ipv4Addr::LOCALHOST);
    let key = server.ca.server_with_crl_urls(
        server.directory.path(),
        "unknown-peer",
        &["b.test"],
        &[crl_url(&http, mode, "missing.crl")],
    )?;
    http.serve("missing.crl", CrlResponse::Status(404));
    let client = peer::client_config(&server.ca, Arc::clone(&key))?;
    let serving = peer::server_config(&server.ca, key, "a.test")?;
    server.suite.create_account("alice", PASSWORD)?;
    let mut alice = server.suite.connect("alice", PASSWORD, "desk")?;

    let mut inbound = peer::RawS2sPeer::protected(
        mode,
        server.suite.s2s_addresses()?[0],
        "b.test",
        "a.test",
        client,
        Some("b.test"),
    )?;
    inbound.expect_external_offered()?;
    inbound.auth_external(Some("b.test"))?;
    inbound.expect_sasl_success()?;
    let mut inbound = inbound.restart("b.test", "a.test")?;
    inbound.send("<message type='chat' from='bob@b.test/phone' to='alice@a.test/desk'><body>unknown inbound</body></message>")?;
    let received = alice.receive()?;
    received.assert_name("jabber:client", "message");
    assert_eq!(received.attribute("from"), Some("bob@b.test/phone"));
    assert_eq!(
        received.child("jabber:client", "body")?.text,
        "unknown inbound"
    );
    authentication(&server.suite, "inbound", "success", 1)?;
    server.suite.wait_for_metric("lonewolf_s2s_revocation_checks_total{direction=\"inbound\",source=\"fetched\",phase=\"handshake\",status=\"unknown\",reason=\"fetch_failed\"} 1")?;

    alice.send(
        "<message type='chat' to='bob@b.test/phone'><body>unknown outbound</body></message>",
    )?;
    let mut outbound = listener.accept("b.test", "a.test", serving, true)?;
    let received = outbound.receive()?;
    received.assert_name("jabber:server", "message");
    assert_eq!(received.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(
        received.child("jabber:server", "body")?.text,
        "unknown outbound"
    );
    authentication(&server.suite, "outbound", "success", 1)?;
    server.suite.wait_for_metric("lonewolf_s2s_revocation_checks_total{direction=\"outbound\",source=\"fetched\",phase=\"handshake\",status=\"unknown\",reason=\"fetch_failed\"} 1")?;
    assert_eq!(http.requests("missing.crl"), 1);

    inbound.close()?;
    outbound.close()?;
    alice.close()?;
    let now = OffsetDateTime::now_utc();
    let wrong_directory = tempfile::tempdir()?;
    let wrong_ca = super::super::support::federation::FederationCa::new(wrong_directory.path())?;
    http.serve("invalid.crl", CrlResponse::Body(b"invalid CRL".to_vec()));
    http.serve(
        "wrong-key.crl",
        CrlResponse::Body(wrong_ca.crl(
            &[],
            now - Duration::minutes(1),
            now + Duration::days(1),
            1,
        )?),
    );
    http.serve(
        "expired.crl",
        CrlResponse::Body(server.ca.crl(
            &[],
            now - Duration::minutes(2),
            now - Duration::minutes(1),
            1,
        )?),
    );
    http.serve("large.crl", CrlResponse::Body(vec![0; 4 * 1024 * 1024 + 1]));
    for (index, (reason, urls)) in [
        ("no_distribution_point", Vec::new()),
        (
            "unsupported_scheme",
            vec!["https://crl.test/list.crl".to_owned()],
        ),
        ("invalid", vec![crl_url(&http, mode, "invalid.crl")]),
        ("bad_signature", vec![crl_url(&http, mode, "wrong-key.crl")]),
        ("stale", vec![crl_url(&http, mode, "expired.crl")]),
        ("too_large", vec![crl_url(&http, mode, "large.crl")]),
    ]
    .into_iter()
    .enumerate()
    {
        let key =
            server
                .ca
                .server_with_crl_urls(server.directory.path(), reason, &["b.test"], &urls)?;
        let mut inbound = peer::RawS2sPeer::protected(
            mode,
            server.suite.s2s_addresses()?[0],
            "b.test",
            "a.test",
            peer::client_config(&server.ca, key)?,
            Some("b.test"),
        )?;
        inbound.expect_external_offered()?;
        inbound.auth_external(Some("b.test"))?;
        inbound.expect_sasl_success()?;
        let mut inbound = inbound.restart("b.test", "a.test")?;
        authentication(&server.suite, "inbound", "success", index as u64 + 2)?;
        checked(&server.suite, "inbound", "handshake", "unknown", reason, 1)?;
        inbound.close()?;
    }
    for path in [
        "missing.crl",
        "invalid.crl",
        "wrong-key.crl",
        "expired.crl",
        "large.crl",
    ] {
        assert_eq!(http.requests(path), 1);
    }
    assert_crl_host_dns(&server.dns, mode)?;
    server.stop()?;
    http.stop()?;
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
    suite.wait_for_metric(&format!("lonewolf_s2s_revocation_checks_total{{direction=\"{direction}\",source=\"fetched\",phase=\"{phase}\",status=\"{status}\",reason=\"{reason}\"}} {count}"))?;
    Ok(())
}

#[test]
fn unrevoked_peers_federate_with_fetched_crls() -> TestResult {
    unrevoked_peers_federate_with_fetched_crls_transport(TlsMode::StartTls)
}

#[test]
fn direct_tls_unrevoked_peers_federate_with_fetched_crls() -> TestResult {
    unrevoked_peers_federate_with_fetched_crls_transport(TlsMode::Direct)
}

fn unrevoked_peers_federate_with_fetched_crls_transport(mode: TlsMode) -> TestResult {
    let mut http = CrlServer::start()?;
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            a_revocation: HostRevocation {
                crl_url: Some(crl_url(&http, mode, "a.crl")),
                ..Default::default()
            },
            b_revocation: HostRevocation {
                crl_url: Some(crl_url(&http, mode, "b.crl")),
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    if mode == TlsMode::Direct {
        pair.direct_tls()?;
    }
    pair.dns.a("crl.test", Ipv4Addr::LOCALHOST);
    let now = OffsetDateTime::now_utc();
    for path in ["a.crl", "b.crl"] {
        http.serve(
            path,
            CrlResponse::Body(pair.ca.crl(
                &[],
                now - Duration::minutes(1),
                now + Duration::days(1),
                1,
            )?),
        );
    }
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send("<message type='chat' to='bob@b.test/phone'><body>fresh a to b</body></message>")?;
    assert_eq!(
        bob.receive()?.child("jabber:client", "body")?.text,
        "fresh a to b"
    );
    bob.send("<message type='chat' to='alice@a.test/desk'><body>fresh b to a</body></message>")?;
    assert_eq!(
        alice.receive()?.child("jabber:client", "body")?.text,
        "fresh b to a"
    );
    for suite in [&pair.a, &pair.b] {
        for direction in ["inbound", "outbound"] {
            authentication(suite, direction, "success", 1)?;
            checked(suite, direction, "handshake", "good", "none", 1)?;
        }
        suite.wait_for_metric("lonewolf_s2s_crl_fetches_total{outcome=\"success\"} 1")?;
        suite.wait_for_metric("lonewolf_s2s_crl_cache_entries 1")?;
        assert!(
            !suite
                .fixture_path()
                .join("s2s-revalidation-interval-ms")
                .exists()
        );
    }
    assert_eq!(http.requests("a.crl"), 1);
    assert_eq!(http.requests("b.crl"), 1);
    alice.close()?;
    bob.close()?;
    assert_crl_host_dns(&pair.dns, mode)?;
    pair.stop()?;
    http.stop()?;
    Ok(())
}

#[test]
fn public_trust_policy_refuses_private_crl_destinations() -> TestResult {
    public_trust_policy_refuses_private_crl_destinations_transport(TlsMode::StartTls)
}

#[test]
fn direct_tls_public_trust_policy_refuses_private_crl_destinations() -> TestResult {
    public_trust_policy_refuses_private_crl_destinations_transport(TlsMode::Direct)
}

fn public_trust_policy_refuses_private_crl_destinations_transport(mode: TlsMode) -> TestResult {
    let mut http = CrlServer::start()?;
    let mut server = SingleServer::start_with_revocation(
        "",
        HostRevocation {
            public_destinations_only: true,
            ..Default::default()
        },
    )?;
    server.set_transport(mode)?;
    server.dns.a("crl.test", Ipv4Addr::LOCALHOST);
    server.dns.a("crl.test", Ipv4Addr::LOCALHOST);
    for (index, url) in [
        format!("http://crl.test:{}/b.crl", http.port()),
        http.url("c.crl"),
    ]
    .into_iter()
    .enumerate()
    {
        let key = server.ca.server_with_crl_urls(
            server.directory.path(),
            &format!("blocked-{index}"),
            &["b.test"],
            &[url],
        )?;
        let mut inbound = peer::RawS2sPeer::protected(
            mode,
            server.suite.s2s_addresses()?[0],
            "b.test",
            "a.test",
            peer::client_config(&server.ca, key)?,
            Some("b.test"),
        )?;
        inbound.expect_external_offered()?;
        inbound.auth_external(Some("b.test"))?;
        inbound.expect_sasl_success()?;
        let mut inbound = inbound.restart("b.test", "a.test")?;
        authentication(&server.suite, "inbound", "success", index as u64 + 1)?;
        checked(
            &server.suite,
            "inbound",
            "handshake",
            "unknown",
            "blocked_address",
            index as u64 + 1,
        )?;
        server.suite.wait_for_metric(&format!(
            "lonewolf_s2s_crl_fetches_total{{outcome=\"blocked_address\"}} {}",
            index + 1
        ))?;
        inbound.close()?;
    }
    assert_eq!(http.requests("b.crl"), 0);
    assert_eq!(http.requests("c.crl"), 0);
    assert_crl_host_dns(&server.dns, mode)?;
    server.stop()?;
    http.stop()?;
    Ok(())
}

#[test]
fn crl_arriving_after_the_handshake_wait_closes_the_revoked_link() -> TestResult {
    crl_arriving_after_the_handshake_wait_closes_the_revoked_link_transport(TlsMode::StartTls)
}

#[test]
fn direct_tls_crl_arriving_after_the_handshake_wait_closes_the_revoked_link() -> TestResult {
    crl_arriving_after_the_handshake_wait_closes_the_revoked_link_transport(TlsMode::Direct)
}

fn crl_arriving_after_the_handshake_wait_closes_the_revoked_link_transport(
    mode: TlsMode,
) -> TestResult {
    let mut http = CrlServer::start()?;
    let mut server = SingleServer::start("")?;
    server.set_transport(mode)?;
    server.dns.a("crl.test", Ipv4Addr::LOCALHOST);
    let key = server.ca.server_with_crl_urls(
        server.directory.path(),
        "late-peer",
        &["b.test"],
        &[crl_url(&http, mode, "late.crl")],
    )?;
    let now = OffsetDateTime::now_utc();
    http.serve(
        "late.crl",
        CrlResponse::Delayed(
            Wait::from_secs(4),
            Box::new(CrlResponse::Body(server.ca.crl(
                &[(key.cert[0].clone(), None)],
                now - Duration::minutes(1),
                now + Duration::days(1),
                1,
            )?)),
        ),
    );
    let client = peer::client_config(&server.ca, key)?;
    let started = Instant::now();
    let mut inbound = peer::RawS2sPeer::protected(
        mode,
        server.suite.s2s_addresses()?[0],
        "b.test",
        "a.test",
        Arc::clone(&client),
        Some("b.test"),
    )?;
    inbound.expect_external_offered()?;
    inbound.auth_external(Some("b.test"))?;
    inbound.expect_sasl_success()?;
    let mut inbound = inbound.restart("b.test", "a.test")?;
    assert!(started.elapsed() >= Wait::from_secs(1));
    authentication(&server.suite, "inbound", "success", 1)?;
    checked(
        &server.suite,
        "inbound",
        "handshake",
        "unknown",
        "pending",
        1,
    )?;
    assert!(
        !server
            .suite
            .fixture_path()
            .join("s2s-revalidation-interval-ms")
            .exists()
    );
    let waiting = Instant::now();
    inbound.expect_stream_error("reset")?;
    assert!(waiting.elapsed() < Wait::from_secs(5));
    closed(&server.suite, "inbound", "certificate_revoked", 1)?;
    checked(&server.suite, "inbound", "recheck", "revoked", "none", 1)?;
    let mut retry = peer::RawS2sPeer::protected(
        mode,
        server.suite.s2s_addresses()?[0],
        "b.test",
        "a.test",
        client,
        None,
    )?;
    retry.expect_stream_error("not-authorized")?;
    server.suite.wait_for_metric("lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"certificate_revoked\"} 1")?;
    server.suite.wait_for_metric(
        "lonewolf_s2s_negotiation_duration_seconds_count{direction=\"inbound\"} 2",
    )?;
    checked(&server.suite, "inbound", "handshake", "revoked", "none", 1)?;
    assert_eq!(http.requests("late.crl"), 1);
    assert_crl_host_dns(&server.dns, mode)?;
    server.stop()?;
    http.stop()?;
    Ok(())
}

#[test]
fn crl_refresh_revoking_a_live_peer_closes_its_links() -> TestResult {
    crl_refresh_revoking_a_live_peer_closes_its_links_transport(TlsMode::StartTls)
}

#[test]
fn direct_tls_crl_refresh_revoking_a_live_peer_closes_its_links() -> TestResult {
    crl_refresh_revoking_a_live_peer_closes_its_links_transport(TlsMode::Direct)
}

fn crl_refresh_revoking_a_live_peer_closes_its_links_transport(mode: TlsMode) -> TestResult {
    let mut http = CrlServer::start()?;
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            a_revocation: HostRevocation {
                crl_url: Some(crl_url(&http, mode, "a.crl")),
                ..Default::default()
            },
            b_revocation: HostRevocation {
                crl_url: Some(crl_url(&http, mode, "b.crl")),
                revalidation_interval: Some(Wait::from_millis(500)),
                ..Default::default()
            },
            limits: "failure_backoff_initial_secs = 1".into(),
            ..Default::default()
        },
    )?;
    if mode == TlsMode::Direct {
        pair.direct_tls()?;
    }
    pair.dns.a("crl.test", Ipv4Addr::LOCALHOST);
    assert!(
        !pair
            .a
            .fixture_path()
            .join("s2s-revalidation-interval-ms")
            .exists()
    );
    assert_eq!(
        std::fs::read_to_string(pair.b.fixture_path().join("s2s-revalidation-interval-ms"))?,
        "500"
    );
    let now = OffsetDateTime::now_utc();
    for path in ["a.crl", "b.crl"] {
        http.serve(
            path,
            CrlResponse::Body(pair.ca.crl(
                &[],
                now - Duration::minutes(2),
                now + Duration::days(1),
                1,
            )?),
        );
    }
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice
        .send("<message type='chat' to='bob@b.test/phone'><body>before a to b</body></message>")?;
    assert_eq!(
        bob.receive()?.child("jabber:client", "body")?.text,
        "before a to b"
    );
    bob.send("<message type='chat' to='alice@a.test/desk'><body>before b to a</body></message>")?;
    assert_eq!(
        alice.receive()?.child("jabber:client", "body")?.text,
        "before b to a"
    );
    let control_directory = tempfile::tempdir()?;
    let control_key = pair.ca.server_with_crl_urls(
        control_directory.path(),
        "control",
        &["control.test"],
        &[crl_url(&http, mode, "a.crl")],
    )?;
    let mut control = peer::RawS2sPeer::protected(
        mode,
        pair.b.s2s_addresses()?[0],
        "control.test",
        "b.test",
        peer::client_config(&pair.ca, control_key)?,
        Some("control.test"),
    )?;
    control.expect_external_offered()?;
    control.auth_external(Some("control.test"))?;
    control.expect_sasl_success()?;
    let mut control = control.restart("control.test", "b.test")?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"success\"} 2",
    )?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_negotiation_duration_seconds_count{direction=\"inbound\"} 2",
    )?;
    let actual = certificate(&pair.a.fixture_path().join("certificate-host.pem"))?;
    http.serve(
        "a.crl",
        CrlResponse::Body(pair.ca.crl(
            &[(actual.clone(), None)],
            now - Duration::minutes(1),
            now + Duration::days(1),
            2,
        )?),
    );
    for direction in ["inbound", "outbound"] {
        pair.b.wait_for_metric(&format!("lonewolf_s2s_streams_closed_total{{direction=\"{direction}\",outcome=\"certificate_revoked\"}} 1"))?;
        checked(&pair.b, direction, "recheck", "revoked", "none", 1)?;
        closed(&pair.a, direction, "peer_error", 1)?;
    }
    control.send("<message type='chat' from='control.test' to='bob@b.test/phone'><body>control survives revocation</body></message>")?;
    assert_eq!(
        bob.receive()?.child("jabber:client", "body")?.text,
        "control survives revocation"
    );
    http.serve(
        "a.crl",
        CrlResponse::Body(pair.ca.crl(&[], now, now + Duration::days(1), 1)?),
    );
    pair.b
        .wait_for_metric("lonewolf_s2s_crl_fetches_total{outcome=\"rollback\"} 1")?;
    control.send("<message type='chat' from='control.test' to='bob@b.test/phone'><body>control survives rollback</body></message>")?;
    assert_eq!(
        bob.receive()?.child("jabber:client", "body")?.text,
        "control survives rollback"
    );
    control.close()?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(
        pair.a.fixture_path().join("private-key-host.pem"),
    )?;
    let key = Arc::new(rustls::sign::CertifiedKey::from_der(
        vec![actual],
        key,
        &rustls_graviola::default_provider(),
    )?);
    let client = peer::client_config(&pair.ca, key)?;
    let requests = http.requests("a.crl");
    let mut rejected = peer::RawS2sPeer::protected(
        mode,
        pair.b.s2s_addresses()?[0],
        "a.test",
        "b.test",
        client,
        None,
    )?;
    rejected.expect_stream_error("not-authorized")?;
    pair.b.wait_for_metric("lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"certificate_revoked\"} 1")?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_negotiation_duration_seconds_count{direction=\"inbound\"} 3",
    )?;
    checked(&pair.b, "inbound", "handshake", "revoked", "none", 1)?;
    assert_eq!(http.requests("a.crl"), requests);
    alice.close()?;
    bob.close()?;
    assert_crl_host_dns(&pair.dns, mode)?;
    pair.stop()?;
    http.stop()?;
    Ok(())
}

#[test]
fn stale_crls_still_reject_listed_peers() -> TestResult {
    stale_crls_still_reject_listed_peers_transport(TlsMode::StartTls)
}

#[test]
fn direct_tls_stale_crls_still_reject_listed_peers() -> TestResult {
    stale_crls_still_reject_listed_peers_transport(TlsMode::Direct)
}

fn stale_crls_still_reject_listed_peers_transport(mode: TlsMode) -> TestResult {
    let mut http = CrlServer::start()?;
    let mut server = SingleServer::start("")?;
    server.set_transport(mode)?;
    server.dns.a("crl.test", Ipv4Addr::LOCALHOST);
    server.suite.create_account("alice", PASSWORD)?;
    let mut alice = server.suite.connect("alice", PASSWORD, "desk")?;
    let mut clients = Vec::new();
    let mut certificates = Vec::new();
    for domain in ["x.test", "y.test", "z.test"] {
        let key = server.ca.server_with_crl_urls(
            server.directory.path(),
            domain,
            &[domain],
            &[crl_url(&http, mode, "stale.crl")],
        )?;
        certificates.push(key.cert[0].clone());
        clients.push(peer::client_config(&server.ca, key)?);
    }
    let now = OffsetDateTime::now_utc();
    http.serve(
        "stale.crl",
        CrlResponse::Body(server.ca.crl(
            &[
                (
                    certificates[0].clone(),
                    Some(rcgen::RevocationReason::KeyCompromise),
                ),
                (
                    certificates[1].clone(),
                    Some(rcgen::RevocationReason::CertificateHold),
                ),
            ],
            now - Duration::minutes(1),
            now + Duration::seconds(3),
            1,
        )?),
    );
    let mut z = peer::RawS2sPeer::protected(
        mode,
        server.suite.s2s_addresses()?[0],
        "z.test",
        "a.test",
        Arc::clone(&clients[2]),
        Some("z.test"),
    )?;
    z.expect_external_offered()?;
    z.auth_external(Some("z.test"))?;
    z.expect_sasl_success()?;
    let mut z = z.restart("z.test", "a.test")?;
    authentication(&server.suite, "inbound", "success", 1)?;
    checked(&server.suite, "inbound", "handshake", "good", "none", 1)?;
    for (index, domain) in ["x.test", "y.test"].into_iter().enumerate() {
        let mut rejected = peer::RawS2sPeer::protected(
            mode,
            server.suite.s2s_addresses()?[0],
            domain,
            "a.test",
            Arc::clone(&clients[index]),
            None,
        )?;
        rejected.expect_stream_error("not-authorized")?;
    }
    server.suite.wait_for_metric("lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"certificate_revoked\"} 2")?;
    checked(&server.suite, "inbound", "handshake", "revoked", "none", 2)?;
    http.serve("stale.crl", CrlResponse::Status(503));
    server
        .suite
        .wait_for_metric("lonewolf_s2s_crl_fetches_total{outcome=\"http_status\"} 1")?;
    let mut x = peer::RawS2sPeer::protected(
        mode,
        server.suite.s2s_addresses()?[0],
        "x.test",
        "a.test",
        Arc::clone(&clients[0]),
        None,
    )?;
    x.expect_stream_error("not-authorized")?;
    server.suite.wait_for_metric("lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"certificate_revoked\"} 3")?;
    checked(&server.suite, "inbound", "handshake", "revoked", "none", 3)?;
    let mut y = peer::RawS2sPeer::protected(
        mode,
        server.suite.s2s_addresses()?[0],
        "y.test",
        "a.test",
        Arc::clone(&clients[1]),
        Some("y.test"),
    )?;
    y.expect_external_offered()?;
    y.auth_external(Some("y.test"))?;
    y.expect_sasl_success()?;
    let mut y = y.restart("y.test", "a.test")?;
    checked(&server.suite, "inbound", "handshake", "unknown", "stale", 1)?;
    server.suite.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"success\"} 2",
    )?;
    server.suite.wait_for_metric(
        "lonewolf_s2s_negotiation_duration_seconds_count{direction=\"inbound\"} 5",
    )?;
    z.send("<message type='chat' from='z.test' to='alice@a.test/desk'><body>unlisted peer stays open</body></message>")?;
    assert_eq!(
        alice.receive()?.child("jabber:client", "body")?.text,
        "unlisted peer stays open"
    );
    assert_eq!(http.requests("stale.crl"), 2);
    assert!(
        !server
            .suite
            .fixture_path()
            .join("s2s-revalidation-interval-ms")
            .exists()
    );
    y.close()?;
    z.close()?;
    alice.close()?;
    assert_crl_host_dns(&server.dns, mode)?;
    server.stop()?;
    http.stop()?;
    Ok(())
}

#[test]
fn failing_crl_urls_back_off_and_share_one_fetch() -> TestResult {
    failing_crl_urls_back_off_and_share_one_fetch_transport(TlsMode::StartTls)
}

#[test]
fn direct_tls_failing_crl_urls_back_off_and_share_one_fetch() -> TestResult {
    failing_crl_urls_back_off_and_share_one_fetch_transport(TlsMode::Direct)
}

fn failing_crl_urls_back_off_and_share_one_fetch_transport(mode: TlsMode) -> TestResult {
    let mut http = CrlServer::start()?;
    let mut server = SingleServer::start("")?;
    server.set_transport(mode)?;
    server.dns.a("crl.test", Ipv4Addr::LOCALHOST);
    http.serve(
        "failure.crl",
        CrlResponse::Delayed(Wait::from_secs(1), Box::new(CrlResponse::Status(500))),
    );
    let address = server.suite.s2s_addresses()?[0];
    let mut configs = Vec::new();
    for domain in ["one.test", "two.test", "three.test", "four.test"] {
        let key = server.ca.server_with_crl_urls(
            server.directory.path(),
            domain,
            &[domain],
            &[crl_url(&http, mode, "failure.crl")],
        )?;
        configs.push(peer::client_config(&server.ca, key)?);
    }
    let mut peers = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (index, domain) in ["one.test", "two.test", "three.test"]
            .into_iter()
            .enumerate()
        {
            let client = Arc::clone(&configs[index]);
            handles.push(scope.spawn(move || -> Result<RawS2sPeer, String> {
                let run = || -> TestResult<RawS2sPeer> {
                    let mut inbound = peer::RawS2sPeer::protected(
                        mode,
                        address,
                        domain,
                        "a.test",
                        client,
                        Some(domain),
                    )?;
                    inbound.expect_external_offered()?;
                    inbound.auth_external(Some(domain))?;
                    inbound.expect_sasl_success()?;
                    inbound.restart(domain, "a.test")
                };
                run().map_err(|error| error.to_string())
            }));
        }
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| "raw peer worker panicked".to_string())
                    .and_then(|result| result)
            })
            .collect::<Result<Vec<_>, _>>()
    })?;
    authentication(&server.suite, "inbound", "success", 3)?;
    checked(
        &server.suite,
        "inbound",
        "handshake",
        "unknown",
        "fetch_failed",
        3,
    )?;
    assert_eq!(http.requests("failure.crl"), 1);
    let mut fourth = peer::RawS2sPeer::protected(
        mode,
        address,
        "four.test",
        "a.test",
        Arc::clone(&configs[3]),
        Some("four.test"),
    )?;
    fourth.expect_external_offered()?;
    fourth.auth_external(Some("four.test"))?;
    fourth.expect_sasl_success()?;
    let mut fourth = fourth.restart("four.test", "a.test")?;
    authentication(&server.suite, "inbound", "success", 4)?;
    checked(
        &server.suite,
        "inbound",
        "handshake",
        "unknown",
        "fetch_failed",
        4,
    )?;
    server
        .suite
        .wait_for_metric("lonewolf_s2s_crl_fetches_total{outcome=\"http_status\"} 1")?;
    assert_eq!(http.requests("failure.crl"), 1);
    for peer in &mut peers {
        peer.close()?;
    }
    fourth.close()?;
    assert_crl_host_dns(&server.dns, mode)?;
    server.stop()?;
    http.stop()?;
    Ok(())
}

#[test]
fn disabled_fetching_skips_revocation_checks() -> TestResult {
    let mut http = CrlServer::start()?;
    let mut server = SingleServer::start_with_revocation(
        "",
        HostRevocation {
            fetch_crls: Some(false),
            ..Default::default()
        },
    )?;
    let key = server.ca.server_with_crl_urls(
        server.directory.path(),
        "disabled-peer",
        &["b.test"],
        &[http.url("disabled.crl")],
    )?;
    let now = OffsetDateTime::now_utc();
    http.serve(
        "disabled.crl",
        CrlResponse::Body(server.ca.crl(
            &[(key.cert[0].clone(), None)],
            now - Duration::minutes(1),
            now + Duration::days(1),
            1,
        )?),
    );
    let mut inbound = server.connect()?;
    inbound.expect_starttls_features()?;
    let mut inbound = inbound.start_tls(peer::client_config(&server.ca, key)?)?;
    inbound.expect_external_offered()?;
    inbound.auth_external(Some("b.test"))?;
    inbound.expect_sasl_success()?;
    let mut inbound = inbound.restart("b.test", "a.test")?;
    authentication(&server.suite, "inbound", "success", 1)?;
    assert_eq!(http.requests("disabled.crl"), 0);
    assert!(
        !server
            .suite
            .scrape_metrics()?
            .contains("lonewolf_s2s_revocation_checks_total")
    );
    inbound.close()?;
    server.stop()?;
    http.stop()?;
    Ok(())
}

#[test]
fn restart_starts_with_an_empty_crl_cache() -> TestResult {
    let mut http = CrlServer::start()?;
    let mut server = SingleServer::start("")?;
    let key = server.ca.server_with_crl_urls(
        server.directory.path(),
        "restart-peer",
        &["b.test"],
        &[http.url("restart.crl")],
    )?;
    let client = peer::client_config(&server.ca, key)?;
    let now = OffsetDateTime::now_utc();
    http.serve(
        "restart.crl",
        CrlResponse::Body(server.ca.crl(
            &[],
            now - Duration::minutes(1),
            now + Duration::days(1),
            1,
        )?),
    );
    for generation in 1..=2 {
        let mut inbound = server.connect()?;
        inbound.expect_starttls_features()?;
        let mut inbound = inbound.start_tls(Arc::clone(&client))?;
        inbound.expect_external_offered()?;
        inbound.auth_external(Some("b.test"))?;
        inbound.expect_sasl_success()?;
        let mut inbound = inbound.restart("b.test", "a.test")?;
        authentication(&server.suite, "inbound", "success", 1)?;
        checked(&server.suite, "inbound", "handshake", "good", "none", 1)?;
        server
            .suite
            .wait_for_metric("lonewolf_s2s_crl_fetches_total{outcome=\"success\"} 1")?;
        assert_eq!(http.requests("restart.crl"), generation);
        assert!(
            !server
                .suite
                .fixture_path()
                .join("s2s-revalidation-interval-ms")
                .exists()
        );
        inbound.close()?;
        if generation == 1 {
            server.suite.restart()?;
        }
    }
    server.stop()?;
    http.stop()?;
    Ok(())
}

#[test]
fn shutdown_during_a_crl_fetch_is_clean() -> TestResult {
    let mut http = CrlServer::start()?;
    let mut server = SingleServer::start("")?;
    http.serve("hanging.crl", CrlResponse::Hang);
    let key = server.ca.server_with_crl_urls(
        server.directory.path(),
        "hanging-peer",
        &["b.test"],
        &[http.url("hanging.crl")],
    )?;
    let mut inbound = server.connect()?;
    inbound.expect_starttls_features()?;
    let mut inbound = inbound.start_tls(peer::client_config(&server.ca, key)?)?;
    inbound.expect_external_offered()?;
    inbound.auth_external(Some("b.test"))?;
    inbound.expect_sasl_success()?;
    let mut inbound = inbound.restart("b.test", "a.test")?;
    authentication(&server.suite, "inbound", "success", 1)?;
    checked(
        &server.suite,
        "inbound",
        "handshake",
        "unknown",
        "pending",
        1,
    )?;
    assert_eq!(http.requests("hanging.crl"), 1);
    let started = Instant::now();
    let state = std::thread::scope(|scope| -> TestResult<_> {
        let stop = scope.spawn(|| {
            server
                .suite
                .stop_with_s2s_state()
                .map_err(|error| error.to_string())
        });
        let closed = inbound.expect_stream_error("system-shutdown");
        let state = stop
            .join()
            .map_err(|_| "server shutdown worker panicked")??;
        closed?;
        state.ok_or_else(|| "missing federation shutdown state".into())
    })?;
    assert!(started.elapsed() < Wait::from_secs(10));
    assert_eq!(state.dropped_shutdown, 0);
    assert_eq!(state.dropped_connection_lost, 0);
    assert_eq!(state.queued_stanzas, 0);
    assert_eq!(state.queued_bytes, 0);
    server.dns.stop()?;
    http.stop()?;
    Ok(())
}
