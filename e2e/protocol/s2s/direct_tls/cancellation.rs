// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::support::xml::XmlStream;
use std::io::Read;

#[test]
fn direct_tls_shutdown_during_each_srv_and_target_address_query_reaps_without_attempt_or_replay()
-> TestResult {
    for phase in [
        "_xmpp-server._tcp.b.test",
        "_xmpps-server._tcp.b.test",
        "edge.b.test",
    ] {
        let mut fixture = SingleServer::start("[limits.s2s]\nnegotiation_timeout_secs=60")?;
        let kind = if phase == "edge.b.test" {
            RecordType::A
        } else {
            RecordType::SRV
        };
        fixture.dns.drop_queries(phase);
        let listener = RawS2sListener::bind()?.direct_tls();
        if phase == "edge.b.test" {
            fixture.dns.direct_srv(
                "b.test",
                &[(0, 0, listener.address()?.port(), "edge.b.test")],
            );
        }
        let observed = fixture.dns.observe_query(phase, kind);
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='cancel-dns'><body>Must not replay</body></message>")?;
        observed.recv_timeout(TIMEOUT)?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_outbound_links{state=\"connecting\"} 1")?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 1")?;
        let body = fixture.suite.scrape_metrics()?;
        assert!(
            !body.contains("lonewolf_s2s_transport_attempts_total{"),
            "{body}"
        );
        alice.close()?;
        let state = fixture
            .suite
            .stop_with_s2s_state()?
            .ok_or("missing completed shutdown receipt")?;
        assert_eq!(state.dropped_shutdown, 1);
        assert_eq!(state.dropped_connection_lost, 0);
        assert_eq!(state.transport_cancelled, [[0; 2]; 2]);
        assert_eq!(state.authentication_protocol, [0; 2]);
        assert_eq!(state.c2s_connections, 0);
        assert_eq!(state.c2s_unauthenticated, 0);
        assert_eq!(state.router_sessions, 0);
        crate::support::federation::assert_shutdown_empty(Some(state));
        listener.assert_not_contacted()?;
        fixture.dns.stop()?;
    }
    Ok(())
}

#[test]
fn direct_tls_shutdown_during_external_completion_cancels_once_and_never_publishes_or_replays()
-> TestResult {
    let listener = RawS2sListener::bind()?.direct_tls();
    let mut fixture = SingleServer::start(&format!(
        "{}\n[limits.s2s]\nnegotiation_timeout_secs=60",
        route(&listener)?
    ))?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='cancel-sasl'><body>Never delivered</body></message>")?;
    let (socket, accepted) = listener.accept_client_hello("b.test")?;
    let connection = accepted
        .into_connection(config(&fixture, b"xmpp-server")?)
        .map_err(|(error, _)| error)?;
    let mut stream = XmlStream::new(rustls::StreamOwned::new(connection, socket));
    let header=stream.open_with("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='b.test' to='a.test' version='1.0' id='pending-external'>")?;
    assert_eq!(header.attribute("from"), Some("a.test"));
    assert_eq!(header.attribute("to"), Some("b.test"));
    stream.send("<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>")?;
    let auth = stream.receive()?;
    auth.assert_name("urn:ietf:params:xml:ns:xmpp-sasl", "auth");
    assert_eq!(auth.attribute("mechanism"), Some("EXTERNAL"));
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 1")?;
    transport_connections(&fixture.suite, "outbound", 0, 1)?;
    alice.close()?;
    let state = fixture
        .suite
        .stop_with_s2s_state()?
        .ok_or("missing completed shutdown receipt")?;
    assert_eq!(state.transport_cancelled, [[0, 0], [0, 1]]);
    assert_eq!(state.authentication_protocol, [0, 1]);
    assert_eq!(state.dropped_shutdown, 1);
    assert_eq!(state.dropped_connection_lost, 0);
    let mut response = Vec::new();
    let error = stream
        .transport()
        .read_to_end(&mut response)
        .expect_err("pending SASL transport did not abort");
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert!(response.is_empty());
    assert_eq!(state.c2s_connections, 0);
    assert_eq!(state.router_sessions, 0);
    crate::support::federation::assert_shutdown_empty(Some(state));
    listener.assert_not_contacted()?;
    fixture.dns.stop()
}

#[test]
fn direct_tls_shutdown_of_established_outbound_bidi_drains_authenticated_ownership() -> TestResult {
    for bidi in [false, true] {
        let listener = RawS2sListener::bind()?.direct_tls();
        let mut fixture = if bidi {
            SingleServer::start_bidirectional(&route(&listener)?)?
        } else {
            SingleServer::start(&route(&listener)?)?
        };
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='before-stop'><body>Delivered once</body></message>")?;
        let (mut remote, requested) =
            listener.accept_offering_bidi("b.test", "a.test", config(&fixture, b"xmpp-server")?)?;
        assert_eq!(requested, bidi);
        remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='before-stop'><body>Delivered once</body></message>")?;
        authentication(&fixture.suite, "outbound", "success", 1)?;
        transport_attempts(&fixture.suite, "outbound", &[("direct", "success", 1)])?;
        transport_connections(&fixture.suite, "outbound", 0, 1)?;
        alice.close()?;
        let reader =
            std::thread::spawn(move || remote.answer_close().map_err(|error| error.to_string()));
        let state = fixture
            .suite
            .stop_with_s2s_state()?
            .ok_or("missing completed shutdown receipt")?;
        reader
            .join()
            .map_err(|_| "outgoing shutdown reader panicked")??;
        assert_eq!(state.transport_cancelled, [[0; 2]; 2]);
        assert_eq!(state.queued_stanzas, 0);
        assert_eq!(state.dropped_shutdown, 0);
        assert_eq!(state.c2s_connections, 0);
        assert_eq!(state.router_sessions, 0);
        crate::support::federation::assert_shutdown_empty(Some(state));
        fixture.dns.stop()?;
    }
    Ok(())
}

#[test]
fn direct_tls_shared_s2s_admission_precedes_hello_and_recovers_both_listener_modes() -> TestResult {
    use crate::support::federation::peer::RawS2sPeer;
    let mut fixture = inbound_fixture(
        "[limits.s2s]\nmax_inbound_connections=2\nnegotiation_timeout_secs=60",
        false,
    )?;
    let addresses = fixture.suite.s2s_addresses()?;
    let mut held = Vec::new();
    for (slot, address) in addresses.iter().enumerate() {
        let socket = TcpStream::connect_timeout(address, TIMEOUT)?;
        held.push(socket);
        transport_connections(&fixture.suite, "inbound", 1, u64::from(slot == 1))?;
    }
    for (slot, address) in addresses.iter().enumerate() {
        let mut rejected = TcpStream::connect_timeout(address, TIMEOUT)?;
        rejected.set_read_timeout(Some(TIMEOUT))?;
        assert_eq!(rejected.read(&mut [0; 1])?, 0);
        fixture.suite.wait_for_metric(&format!("lonewolf_s2s_connections_rejected_total{{listener=\"{slot}\",reason=\"max_inbound_connections\"}} 1"))?;
    }
    for socket in held {
        socket.shutdown(std::net::Shutdown::Both)?;
    }
    transport_connections(&fixture.suite, "inbound", 0, 0)?;
    let mut peer =
        RawS2sPeer::tls_first(addresses[1], "b.test", "a.test", fixture.client_config()?)?;
    peer.open_protected(&inbound_header(Some("b.test"), "a.test"), Some("b.test"))?;
    peer.expect_external_offered()?;
    peer.auth_external(Some(""))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    fixture.suite.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"success\"} 1",
    )?;
    fixture.suite.wait_for_metric(
        "lonewolf_s2s_negotiation_duration_seconds_count{direction=\"inbound\"} 3",
    )?;
    transport_attempts(
        &fixture.suite,
        "inbound",
        &[
            ("starttls", "protocol", 1),
            ("direct", "tls_failure", 1),
            ("direct", "success", 1),
        ],
    )?;
    peer.close()?;
    transport_connections(&fixture.suite, "inbound", 0, 0)?;
    fixture.stop()
}

#[test]
fn direct_tls_inbound_bidi_shutdown_retires_live_stream_and_all_mode_gauges() -> TestResult {
    use crate::support::federation::peer::RawS2sPeer;
    let mut fixture = inbound_fixture("", true)?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    let mut peer = RawS2sPeer::tls_first(
        fixture.suite.s2s_addresses()?[1],
        "b.test",
        "a.test",
        fixture.client_config()?,
    )?;
    peer.open_protected(&inbound_header(Some("b.test"), "a.test"), Some("b.test"))?;
    peer.expect_external_and_bidi_offered()?;
    peer.request_bidi()?;
    peer.auth_external(Some(""))?;
    peer.expect_sasl_success()?;
    let mut peer = peer.restart("b.test", "a.test")?;
    peer.send("<message from='bob@b.test/phone' to='alice@a.test/desk' type='chat' id='before-stop'><body>Live incoming bidi</body></message>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@b.test/phone' to='alice@a.test/desk' type='chat' id='before-stop'><body>Live incoming bidi</body></message>")?;
    authentication(&fixture.suite, "inbound", "success", 1)?;
    transport_attempts(&fixture.suite, "inbound", &[("direct", "success", 1)])?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bidi_streams{direction=\"inbound\"} 1")?;
    alice.close()?;
    let reader = std::thread::spawn(move || {
        peer.expect_stream_error("system-shutdown")
            .map_err(|e| e.to_string())
    });
    let state = fixture
        .suite
        .stop_with_s2s_state()?
        .ok_or("missing completed shutdown receipt")?;
    reader
        .join()
        .map_err(|_| "inbound shutdown reader panicked")??;
    assert_eq!(state.transport_cancelled, [[0; 2]; 2]);
    assert_eq!(state.c2s_connections, 0);
    assert_eq!(state.router_sessions, 0);
    crate::support::federation::assert_shutdown_empty(Some(state));
    fixture.dns.stop()
}
