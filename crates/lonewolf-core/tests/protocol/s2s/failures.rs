// SPDX-License-Identifier: Apache-2.0

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;

use super::super::support::federation::{
    FederatedPair, FederationCa, PairOptions,
    peer::{self, RawS2sListener},
};
use super::super::support::{PASSWORD, TestResult};
use super::negotiation::{SingleServer, authentication, closed, expect_bounce};

pub(super) fn refused_endpoint() -> TestResult<(socket2::Socket, SocketAddr)> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
    let address = socket
        .local_addr()?
        .as_socket()
        .ok_or("refused endpoint has no IP address")?;
    Ok((socket, address))
}

#[test]
fn srv_records_are_followed_in_priority_order() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let (_refused, refused) = refused_endpoint()?;
    let listener = RawS2sListener::bind()?;
    fixture.dns.srv(
        "b.test",
        &[
            (0, 0, refused.port(), "first.b.test"),
            (10, 0, listener.address()?.port(), "second.b.test"),
        ],
    );
    fixture.dns.a("first.b.test", Ipv4Addr::LOCALHOST);
    fixture.dns.a("second.b.test", Ipv4Addr::LOCALHOST);
    let config = peer::server_config(
        &fixture.ca,
        fixture
            .ca
            .server(fixture.directory.path(), "peer", &["b.test"])?,
        "a.test",
    )?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='priority'><body>second endpoint</body></message>")?;
    let mut peer = listener.accept("b.test", "a.test", config, true)?;
    peer.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='priority'><body>second endpoint</body></message>")?;
    authentication(&fixture.suite, "outbound", "success", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
    assert_eq!(
        fixture
            .dns
            .query_count("_xmpp-server._tcp.b.test", RecordType::SRV),
        1
    );
    assert!(fixture.dns.query_count("first.b.test", RecordType::A) > 0);
    assert!(fixture.dns.query_count("second.b.test", RecordType::A) > 0);
    peer.close()?;
    closed(&fixture.suite, "outbound", "stream_end", 1)?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn static_route_replaces_dns() -> TestResult {
    let mut pair = FederatedPair::start("a.test", "b.test", PairOptions::default())?;
    let address = pair.b.s2s_addresses()?[0];
    let path = pair.a.fixture_path().join("lonewolf.toml");
    let mut config = std::fs::read_to_string(&path)?;
    config.push_str(&format!(
        "\n[s2s.routes]\n'b.test'=[{:?}]\n",
        address.to_string()
    ));
    std::fs::write(path, config)?;
    pair.a.restart()?;
    pair.dns.nxdomain("_xmpp-server._tcp.b.test");
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat'><body>static endpoint</body></message>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' xml:lang='en'><body>static endpoint</body></message>")?;
    authentication(&pair.a, "outbound", "success", 1)?;
    authentication(&pair.b, "inbound", "success", 1)?;
    pair.a
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"static\"} 1")?;
    assert_eq!(
        pair.dns
            .query_count("_xmpp-server._tcp.b.test", RecordType::SRV),
        0
    );
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn srv_target_dot_bounces_remote_server_not_found() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    fixture.dns.no_service("b.test");
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='no-service'><body>no service</body></message>")?;
    expect_bounce(&mut alice, "no-service", "remote-server-not-found")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"no_service\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bounces_total{condition=\"remote_server_not_found\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_links{state=\"backoff\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_bytes 0")?;
    assert_eq!(
        fixture
            .dns
            .query_count("_xmpp-server._tcp.b.test", RecordType::SRV),
        1
    );
    alice.close()?;
    fixture.stop()
}

#[test]
fn unreachable_endpoint_bounces_remote_server_timeout() -> TestResult {
    let (_refused, address) = refused_endpoint()?;
    let mut fixture =
        SingleServer::start("[limits.s2s]\nconnect_timeout_secs=1\nnegotiation_timeout_secs=2")?;
    fixture
        .dns
        .srv("b.test", &[(0, 0, address.port(), "server.b.test")]);
    fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='unreachable'><body>unreachable</body></message>")?;
    expect_bounce(&mut alice, "unreachable", "remote-server-timeout")?;
    authentication(&fixture.suite, "outbound", "unreachable", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bounces_total{condition=\"remote_server_timeout\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"outbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_bytes 0")?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn receiving_peer_without_external_bounces_remote_server_timeout() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let listener = RawS2sListener::bind()?;
    fixture.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "server.b.test")],
    );
    fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
    let config = peer::server_config(
        &fixture.ca,
        fixture
            .ca
            .server(fixture.directory.path(), "peer", &["b.test"])?,
        "a.test",
    )?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='no-external'><body>external required</body></message>")?;
    let mut peer = listener.accept("b.test", "a.test", config, false)?;
    peer.answer_close()?;
    expect_bounce(&mut alice, "no-external", "remote-server-timeout")?;
    authentication(&fixture.suite, "outbound", "external_not_offered", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bounces_total{condition=\"remote_server_timeout\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"outbound\"} 0")?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn receiving_peer_with_wrong_certificate_bounces_remote_server_timeout() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let listener = RawS2sListener::bind()?;
    fixture.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "server.b.test")],
    );
    fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
    let config = peer::server_config(
        &fixture.ca,
        fixture.ca.wrong_name(fixture.directory.path(), "b.test")?,
        "a.test",
    )?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='wrong-certificate'><body>identity required</body></message>")?;
    let error = listener
        .accept("b.test", "a.test", config, true)
        .err()
        .ok_or("wrong certificate completed TLS")?;
    let error = error
        .downcast_ref::<std::io::Error>()
        .ok_or("TLS failure did not return an I/O error")?;
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof, "{error}");
    expect_bounce(&mut alice, "wrong-certificate", "remote-server-timeout")?;
    authentication(&fixture.suite, "outbound", "certificate_name", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bounces_total{condition=\"remote_server_timeout\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"outbound\"} 0")?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn receiving_peer_with_self_signed_ca_leaf_bounces_remote_server_timeout() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let listener = RawS2sListener::bind()?;
    fixture.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "server.b.test")],
    );
    fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
    let config = peer::server_config(
        &fixture.ca,
        FederationCa::self_signed_ca("b.test")?,
        "a.test",
    )?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='ca-leaf'><body>trusted leaf required</body></message>")?;
    let error = listener
        .accept("b.test", "a.test", config, true)
        .err()
        .ok_or("CA certificate completed TLS and authenticated the peer")?;
    let error = error
        .downcast_ref::<std::io::Error>()
        .ok_or("TLS failure did not return an I/O error")?;
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof, "{error}");
    expect_bounce(&mut alice, "ca-leaf", "remote-server-timeout")?;
    authentication(&fixture.suite, "outbound", "certificate_untrusted", 1)?;
    let metrics = fixture.suite.scrape_metrics()?;
    for outcome in ["tls_failure", "success"] {
        assert!(
            !metrics.contains(&format!(
                "lonewolf_s2s_authentications_total{{direction=\"outbound\",outcome=\"{outcome}\"}}"
            )),
            "{metrics}"
        );
    }
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_connections{direction=\"outbound\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_bytes 0")?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn backoff_answers_without_new_attempts() -> TestResult {
    let (_refused, address) = refused_endpoint()?;
    let mut fixture = SingleServer::start(
        "[limits.s2s]\nfailure_backoff_initial_secs=1\nfailure_backoff_max_secs=1\nconnect_timeout_secs=1",
    )?;
    fixture
        .dns
        .srv("b.test", &[(0, 0, address.port(), "server.b.test")]);
    fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='first'><body>first attempt</body></message>")?;
    expect_bounce(&mut alice, "first", "remote-server-timeout")?;
    let failed_at = Instant::now();
    alice.send("<message to='bob@b.test/phone' type='chat' id='cached'><body>cached failure</body></message>")?;
    expect_bounce(&mut alice, "cached", "remote-server-timeout")?;
    assert!(failed_at.elapsed() < Duration::from_secs(1));
    authentication(&fixture.suite, "outbound", "unreachable", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_admission_rejections_total{reason=\"backoff\"} 1")?;
    assert_eq!(
        fixture
            .dns
            .query_count("_xmpp-server._tcp.b.test", RecordType::SRV),
        1
    );
    if let Some(remaining) = Duration::from_secs(1).checked_sub(failed_at.elapsed()) {
        std::thread::sleep(remaining);
    }
    alice.send("<message to='bob@b.test/phone' type='chat' id='after-backoff'><body>new attempt</body></message>")?;
    expect_bounce(&mut alice, "after-backoff", "remote-server-timeout")?;
    authentication(&fixture.suite, "outbound", "unreachable", 2)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 2")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bounces_total{condition=\"remote_server_timeout\"} 2")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
    assert_eq!(
        fixture
            .dns
            .query_count("_xmpp-server._tcp.b.test", RecordType::SRV),
        2
    );
    alice.close()?;
    fixture.stop()
}

fn set_client_deadline(
    client: &mut super::super::support::Client,
    deadline: Instant,
) -> TestResult {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("queue scenario deadline elapsed")?;
    client.transport().sock.set_read_timeout(Some(remaining))?;
    client.transport().sock.set_write_timeout(Some(remaining))?;
    Ok(())
}

#[test]
fn full_link_queue_answers_resource_constraint() -> TestResult {
    let mut fixture = SingleServer::start(
        "[limits.s2s]\nmax_queued_stanzas_per_link=2\nstalled_write_timeout_secs=60\n[limits.c2s.profiles.default]\nincoming_stanzas_per_connection={per_second=10000,burst=10000}\nincoming_xml_per_connection={bytes_per_second=67108864,burst_bytes=67108864}",
    )?;
    let listener = RawS2sListener::bind()?;
    listener.set_receive_buffer_size(1024)?;
    fixture.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "server.b.test")],
    );
    fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
    let config = peer::server_config(
        &fixture.ca,
        fixture
            .ca
            .server(fixture.directory.path(), "peer", &["b.test"])?,
        "a.test",
    )?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>establish</body></message>")?;
    let mut peer = listener.accept("b.test", "a.test", config, true)?;
    peer.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat'><body>establish</body></message>")?;
    authentication(&fixture.suite, "outbound", "success", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_links{state=\"ready\"} 1")?;
    let body = "x".repeat(131072);
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut rejected = false;
    for index in 0..256 {
        if Instant::now() >= deadline {
            break;
        }
        let id = format!("fill-{index}");
        set_client_deadline(&mut alice, deadline)?;
        alice.send(&format!(
            "<message to='bob@b.test/phone' type='chat' id='{id}'><body>{body}</body></message>"
        ))?;
        set_client_deadline(&mut alice, deadline)?;
        alice.send("<iq type='get' id='processed'><query xmlns='urn:test:queue-barrier'/></iq>")?;
        loop {
            set_client_deadline(&mut alice, deadline)?;
            let reply = alice.receive()?;
            if reply.name == "iq" {
                assert_eq!(reply.attribute("id"), Some("processed"));
                assert_eq!(reply.attribute("type"), Some("error"));
                reply
                    .child("jabber:client", "error")?
                    .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
                break;
            }
            reply.assert_name("jabber:client", "message");
            assert_eq!(reply.attribute("id"), Some(id.as_str()));
            assert_eq!(reply.attribute("type"), Some("error"));
            reply
                .child("jabber:client", "error")?
                .child("urn:ietf:params:xml:ns:xmpp-stanzas", "resource-constraint")?;
            rejected = true;
        }
        if rejected {
            break;
        }
    }
    assert!(
        rejected,
        "queue did not fill within the message budget and deadline"
    );
    fixture
        .suite
        .wait_for_metrics("queue-full admission", |body| {
            super::sample(
                body,
                "lonewolf_s2s_admission_rejections_total{reason=\"queue_full\"}",
            )
            .is_ok_and(|count| count > 0)
        })?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_links{state=\"ready\"} 1")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 2")?;
    fixture.suite.wait_for_metrics("queued XML bytes", |body| {
        super::sample(body, "lonewolf_s2s_outbound_queued_bytes").is_ok_and(|count| count > 0)
    })?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
    alice.close()?;
    let state = fixture
        .suite
        .stop_with_s2s_state()?
        .ok_or("missing active shutdown state")?;
    assert_eq!(state.dropped_shutdown, 2);
    assert!(state.dropped_connection_lost <= 1, "{state:?}");
    assert_eq!(state.queued_stanzas, 0);
    assert_eq!(state.queued_bytes, 0);
    drop(peer);
    fixture.dns.stop()
}

#[test]
fn stanza_received_on_outbound_stream_gets_not_authorized() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let listener = RawS2sListener::bind()?;
    fixture.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "server.b.test")],
    );
    fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
    let config = peer::server_config(
        &fixture.ca,
        fixture
            .ca
            .server(fixture.directory.path(), "peer", &["b.test"])?,
        "a.test",
    )?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice
        .send("<message to='bob@b.test/phone' type='chat'><body>one direction</body></message>")?;
    let mut peer = listener.accept("b.test", "a.test", config, true)?;
    peer.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat'><body>one direction</body></message>")?;
    authentication(&fixture.suite, "outbound", "success", 1)?;
    peer.send("<message from='bob@b.test/phone' to='alice@a.test/desk'><body>wrong direction</body></message>")?;
    peer.expect_stream_error("not-authorized")?;
    closed(&fixture.suite, "outbound", "not_authorized", 1)?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
    alice.close()?;
    fixture.stop()
}
