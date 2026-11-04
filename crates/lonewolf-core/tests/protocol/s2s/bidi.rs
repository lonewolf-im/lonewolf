// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use super::super::support::federation::{
    peer::{self, RawS2sListener, RawS2sPeer},
    thread_result,
};
use super::super::support::{PASSWORD, TestResult};
use super::negotiation::{SingleServer, authentication, expect_bounce};

fn encrypted(fixture: &SingleServer) -> TestResult<RawS2sPeer> {
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_and_bidi_offered()?;
    Ok(peer)
}

fn authenticated(fixture: &SingleServer) -> TestResult<RawS2sPeer> {
    let mut peer = encrypted(fixture)?;
    peer.request_bidi()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let peer = peer.restart("b.test", "a.test")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bidi_streams{direction=\"inbound\"} 1")?;
    Ok(peer)
}

#[test]
fn connecting_peer_is_offered_bidi_after_tls() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_and_bidi_offered()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    peer.restart("b.test", "a.test")?.close()?;
    fixture.stop()
}

#[test]
fn local_stanzas_reach_a_bidi_peer_over_its_own_connection() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let mut peer = encrypted(&fixture)?;
    peer.request_bidi()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bidi_streams{direction=\"inbound\"} 1")?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message type='chat' to='bob@b.test/phone'><body>out</body></message>")?;
    peer.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat'><body>out</body></message>")?;
    peer.send("<message from='bob@b.test/phone' to='alice@a.test/desk' type='chat'><body>in</body></message>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@b.test/phone' to='alice@a.test/desk' type='chat'><body>in</body></message>")?;
    for sample in [
        "lonewolf_s2s_bidi_negotiations_total{direction=\"inbound\",outcome=\"enabled\"} 1",
        "lonewolf_s2s_bidi_streams{direction=\"inbound\"} 1",
        "lonewolf_s2s_bidi_handoffs_total{target=\"inbound_stream\"} 1",
        "lonewolf_s2s_bidi_stanzas_sent_total{kind=\"message\"} 1",
        "lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 1",
        "lonewolf_s2s_stanzas_received_total{kind=\"message\"} 1",
        "lonewolf_s2s_outbound_links{state=\"ready\"} 1",
    ] {
        fixture.suite.wait_for_metric(sample)?;
    }
    assert!(
        !fixture
            .suite
            .scrape_metrics()?
            .lines()
            .any(|line| line.starts_with("lonewolf_s2s_dns_resolutions_total{"))
    );
    alice.close()?;
    peer.close()?;
    fixture.stop()
}

#[test]
fn peer_without_bidi_request_keeps_one_direction() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let mut peer = encrypted(&fixture)?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    fixture.suite.wait_for_metric(
        "lonewolf_s2s_bidi_negotiations_total{direction=\"inbound\",outcome=\"not_requested\"} 1",
    )?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat' id='one-way'><body>out</body></message>",
    )?;
    expect_bounce(&mut alice, "one-way", "remote-server-not-found")?;
    peer.close()?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn bidi_request_errors_get_not_authorized() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    peer.request_bidi()?;
    peer.expect_stream_error("not-authorized")?;
    authentication(&fixture.suite, "inbound", "protocol", 1)?;
    for (index, request) in [
        "<bidi xmlns='urn:xmpp:bidi'/><bidi xmlns='urn:xmpp:bidi'/>",
        "<bidi xmlns='urn:xmpp:bidi'><x/></bidi>",
        "<bidi xmlns='urn:xmpp:bidi' extra='value'/>",
        "<bidi xmlns='urn:xmpp:bidi'>text</bidi>",
    ]
    .into_iter()
    .enumerate()
    {
        let mut peer = encrypted(&fixture)?;
        peer.send(request)?;
        peer.expect_stream_error("not-authorized")?;
        authentication(&fixture.suite, "inbound", "protocol", index as u64 + 2)?;
    }
    fixture.stop()
}

#[test]
fn first_bidi_request_before_second_sasl_attempt_is_accepted() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let mut peer = encrypted(&fixture)?;
    peer.auth_external(Some("other.test"))?;
    peer.receive()?.assert_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-authzid/></failure>",
    )?;
    peer.request_bidi()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bidi_streams{direction=\"inbound\"} 1")?;
    fixture.suite.wait_for_metric(
        "lonewolf_s2s_bidi_negotiations_total{direction=\"inbound\",outcome=\"enabled\"} 1",
    )?;
    peer.close()?;
    fixture.stop()
}

#[test]
fn second_bidi_request_after_failed_sasl_is_rejected() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let mut peer = encrypted(&fixture)?;
    peer.request_bidi()?;
    peer.auth_external(Some("other.test"))?;
    peer.receive()?.assert_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-authzid/></failure>",
    )?;
    peer.request_bidi()?;
    peer.expect_stream_error("not-authorized")?;
    authentication(&fixture.suite, "inbound", "protocol", 1)?;
    fixture.stop()
}

#[test]
fn bidi_in_sasl_challenge_gets_not_authorized() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let mut peer = encrypted(&fixture)?;
    peer.auth_external(None)?;
    peer.receive()?
        .assert_xml("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    peer.request_bidi()?;
    peer.expect_stream_error("not-authorized")?;
    authentication(&fixture.suite, "inbound", "protocol", 1)?;
    fixture.stop()
}

#[test]
fn bidi_after_authentication_gets_unsupported_stanza_type() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let mut peer = authenticated(&fixture)?;
    peer.request_bidi()?;
    peer.expect_stream_error("unsupported-stanza-type")?;
    fixture.stop()
}

#[test]
fn disabled_bidirectional_offers_only_external() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_offered()?;
    peer.request_bidi()?;
    peer.expect_stream_error("not-authorized")?;
    authentication(&fixture.suite, "inbound", "protocol", 1)?;
    fixture.stop()
}

#[test]
fn closed_bidi_stream_returns_the_pair_to_dialing() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let mut peer = authenticated(&fixture)?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>first</body></message>")?;
    assert_eq!(
        peer.receive()?.child("jabber:server", "body")?.text,
        "first"
    );
    peer.close()?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bidi_streams{direction=\"inbound\"} 0")?;
    let listener = RawS2sListener::bind()?;
    fixture
        .dns
        .srv("b.test", &[(0, 0, listener.address()?.port(), "b.test")]);
    fixture.dns.a("b.test", Ipv4Addr::LOCALHOST);
    let config = peer::server_config(
        &fixture.ca,
        fixture
            .ca
            .server(fixture.directory.path(), "listener", &["b.test"])?,
        "a.test",
    )?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>second</body></message>")?;
    let mut outbound = listener.accept("b.test", "a.test", config, true)?;
    assert_eq!(
        outbound.receive()?.child("jabber:server", "body")?.text,
        "second"
    );
    authentication(&fixture.suite, "outbound", "success", 1)?;
    outbound.close()?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn shutdown_closes_a_bidi_stream_with_system_shutdown() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let mut peer = authenticated(&fixture)?;
    let (reply, stopped) = std::thread::scope(|scope| {
        let suite = &mut fixture.suite;
        let worker = scope.spawn(move || thread_result(suite.stop_with_s2s_state()));
        let reply = peer.expect_stream_error("system-shutdown");
        (reply, worker.join())
    });
    reply?;
    let state = stopped
        .map_err(|_| "shutdown worker panicked")??
        .ok_or("missing shutdown state")?;
    assert_eq!(state.queued_stanzas, 0);
    assert_eq!(state.queued_bytes, 0);
    fixture.dns.stop()
}

fn outbound_listener(
    fixture: &SingleServer,
) -> TestResult<(RawS2sListener, std::sync::Arc<rustls::ServerConfig>)> {
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
    Ok((listener, config))
}

#[test]
fn outbound_link_requests_bidi_and_receives_over_it() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let (listener, config) = outbound_listener(&fixture)?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message type='chat' to='bob@b.test/phone'><body>open link</body></message>")?;
    let (mut peer, requested) = listener.accept_offering_bidi("b.test", "a.test", config)?;
    assert!(requested);
    peer.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat'><body>open link</body></message>")?;
    peer.send("<message from='bob@b.test/phone' to='alice@a.test/desk' type='chat'><body>same link</body></message>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@b.test/phone' to='alice@a.test/desk' type='chat'><body>same link</body></message>")?;
    alice.send(
        "<message type='chat' to='bob@b.test/phone'><body>same link reply</body></message>",
    )?;
    peer.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat'><body>same link reply</body></message>")?;
    for sample in [
        "lonewolf_s2s_bidi_negotiations_total{direction=\"outbound\",outcome=\"enabled\"} 1",
        "lonewolf_s2s_bidi_streams{direction=\"outbound\"} 1",
        "lonewolf_s2s_bidi_stanzas_received_total{kind=\"message\"} 1",
        "lonewolf_s2s_stanzas_received_total{kind=\"message\"} 1",
    ] {
        fixture.suite.wait_for_metric(sample)?;
    }
    assert!(!fixture.suite.scrape_metrics()?.contains(
        "lonewolf_s2s_streams_closed_total{direction=\"outbound\",outcome=\"not_authorized\"}"
    ));
    peer.close()?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bidi_streams{direction=\"outbound\"} 0")?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn reverse_iq_is_answered_over_the_same_link() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let (listener, config) = outbound_listener(&fixture)?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>open link</body></message>")?;
    let (mut peer, requested) = listener.accept_offering_bidi("b.test", "a.test", config)?;
    assert!(requested);
    peer.receive()?.assert_name("jabber:server", "message");
    peer.send("<iq type='get' id='p1' from='bob@b.test/phone' to='a.test'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    let reply = peer.receive()?;
    reply.assert_name("jabber:server", "iq");
    assert_eq!(reply.attribute("id"), Some("p1"));
    assert_eq!(reply.attribute("from"), Some("a.test"));
    assert_eq!(reply.attribute("to"), Some("bob@b.test/phone"));
    assert_eq!(reply.attribute("type"), Some("error"));
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bidi_stanzas_received_total{kind=\"iq\"} 1")?;
    peer.close()?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn outbound_link_without_offer_does_not_request_bidi() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let (listener, config) = outbound_listener(&fixture)?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice
        .send("<message to='bob@b.test/phone' type='chat'><body>one direction</body></message>")?;
    let mut peer = listener.accept("b.test", "a.test", config, true)?;
    peer.receive()?.assert_name("jabber:server", "message");
    fixture.suite.wait_for_metric(
        "lonewolf_s2s_bidi_negotiations_total{direction=\"outbound\",outcome=\"not_offered\"} 1",
    )?;
    peer.send("<message from='bob@b.test/phone' to='alice@a.test/desk'><body>wrong direction</body></message>")?;
    peer.expect_stream_error("not-authorized")?;
    super::negotiation::closed(&fixture.suite, "outbound", "not_authorized", 1)?;
    alice.close()?;
    fixture.stop()
}

#[test]
fn disabled_bidirectional_ignores_the_offer() -> TestResult {
    let mut fixture = SingleServer::start("")?;
    let (listener, config) = outbound_listener(&fixture)?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>disabled</body></message>")?;
    let (mut peer, requested) = listener.accept_offering_bidi("b.test", "a.test", config)?;
    assert!(!requested);
    peer.receive()?.assert_name("jabber:server", "message");
    peer.send("<message from='bob@b.test/phone' to='alice@a.test/desk'><body>wrong direction</body></message>")?;
    peer.expect_stream_error("not-authorized")?;
    super::negotiation::closed(&fixture.suite, "outbound", "not_authorized", 1)?;
    assert!(
        !fixture
            .suite
            .scrape_metrics()?
            .contains("lonewolf_s2s_bidi_negotiations_total{direction=\"outbound\"")
    );
    alice.close()?;
    fixture.stop()
}

#[test]
fn reverse_stanza_from_another_domain_closes_the_link_with_invalid_from() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("")?;
    let (listener, config) = outbound_listener(&fixture)?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>open link</body></message>")?;
    let (mut peer, requested) = listener.accept_offering_bidi("b.test", "a.test", config)?;
    assert!(requested);
    peer.receive()?.assert_name("jabber:server", "message");
    peer.send("<message from='mallory@c.test/x' to='alice@a.test/desk' type='chat'><body>wrong domain</body></message>")?;
    peer.expect_stream_error("invalid-from")?;
    super::negotiation::closed(&fixture.suite, "outbound", "invalid_from", 1)?;
    alice.send(
        "<iq to='a.test' type='get' id='rejected-fence'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    let reply = alice.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("id"), Some("rejected-fence"));
    assert_eq!(reply.attribute("type"), Some("error"));
    alice.close()?;
    fixture.stop()
}

#[test]
fn bidi_link_stays_open_while_the_peer_sends() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional("[limits.s2s]\nidle_timeout_secs = 2")?;
    let (listener, config) = outbound_listener(&fixture)?;
    let listener = listener.expecting_limits(524288, 2);
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat'><body>open link</body></message>")?;
    let (mut peer, requested) = listener.accept_offering_bidi("b.test", "a.test", config)?;
    assert!(requested);
    peer.receive()?.assert_name("jabber:server", "message");
    let started = std::time::Instant::now();
    for second in 1..=4 {
        std::thread::sleep(
            (started + std::time::Duration::from_secs(second))
                .saturating_duration_since(std::time::Instant::now()),
        );
        peer.send("<message from='bob@b.test/phone' to='alice@a.test/desk' type='chat'><body>active peer</body></message>")?;
        alice.expect_xml("<message xmlns='jabber:client' from='bob@b.test/phone' to='alice@a.test/desk' type='chat'><body>active peer</body></message>")?;
    }
    let silent = std::time::Instant::now();
    peer.answer_close()?;
    assert!(silent.elapsed() <= std::time::Duration::from_secs(3));
    super::negotiation::closed(&fixture.suite, "outbound", "idle", 1)?;
    alice.close()?;
    fixture.stop()
}
