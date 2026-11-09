// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::support::federation::refused_endpoint;
use std::io::Write;
use std::net::Ipv4Addr;

fn publish(fixture: &SingleServer, direct: bool, priority: u16, port: u16, target: &str) {
    if direct {
        fixture
            .dns
            .direct_srv("b.test", &[(priority, 0, port, target)]);
    } else {
        fixture.dns.srv("b.test", &[(priority, 0, port, target)]);
    }
    fixture.dns.a(target, Ipv4Addr::LOCALHOST);
}

fn assert_discovery(fixture: &SingleServer) -> TestResult {
    for service in ["_xmpp-server._tcp.b.test", "_xmpps-server._tcp.b.test"] {
        assert_eq!(fixture.dns.query_count(service, RecordType::SRV), 1);
    }
    for family in [RecordType::A, RecordType::AAAA] {
        assert_eq!(fixture.dns.query_count("b.test", family), 0);
    }
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
    Ok(())
}

#[test]
fn direct_only_srv_authenticates_xmpp_domain_and_carries_correlated_iq_over_bidi() -> TestResult {
    let listener = RawS2sListener::bind()?.direct_tls();
    let mut fixture = SingleServer::start_bidirectional_with_extensions("", "'ping'")?;
    publish(&fixture, true, 0, listener.address()?.port(), "edge.b.test");
    let config = config(&fixture, b"xmpp-server")?;
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='discovered'><body>SRV direct</body></message>")?;
    let (mut remote, requested) = listener.accept_offering_bidi("b.test", "a.test", config)?;
    assert!(requested);
    assert_eq!(remote.alpn_protocol(), Some(b"xmpp-server".as_slice()));
    remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='discovered'><body>SRV direct</body></message>")?;
    remote.send("<iq from='bob@b.test/phone' to='a.test' type='get' id='correlated'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    remote.receive()?.assert_xml("<iq xmlns='jabber:server' from='a.test' to='bob@b.test/phone' type='result' id='correlated'/>")?;
    assert_discovery(&fixture)?;
    authentication(&fixture.suite, "outbound", "success", 1)?;
    transport_attempts(&fixture.suite, "outbound", &[("direct", "success", 1)])?;
    transport_connections(&fixture.suite, "outbound", 0, 1)?;
    remote.close()?;
    closed(&fixture.suite, "outbound", "stream_end", 1)?;
    transport_connections(&fixture.suite, "outbound", 0, 0)?;
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
fn mixed_srv_lower_priority_wins_in_both_transport_orderings() -> TestResult {
    for direct_first in [false, true] {
        let chosen = if direct_first {
            RawS2sListener::bind()?.direct_tls()
        } else {
            RawS2sListener::bind()?
        };
        let decoy = RawS2sListener::bind()?;
        let mut fixture = SingleServer::start("")?;
        publish(
            &fixture,
            direct_first,
            1,
            chosen.address()?.port(),
            "preferred.b.test",
        );
        publish(
            &fixture,
            !direct_first,
            20,
            decoy.address()?.port(),
            "later.b.test",
        );
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='priority'><body>Priority wins</body></message>")?;
        let mut remote =
            chosen.accept("b.test", "a.test", config(&fixture, b"xmpp-server")?, true)?;
        remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='priority'><body>Priority wins</body></message>")?;
        let mode = if direct_first { "direct" } else { "starttls" };
        transport_attempts(&fixture.suite, "outbound", &[(mode, "success", 1)])?;
        authentication(&fixture.suite, "outbound", "success", 1)?;
        assert_discovery(&fixture)?;
        decoy.assert_not_contacted()?;
        remote.close()?;
        closed(&fixture.suite, "outbound", "stream_end", 1)?;
        transport_connections(&fixture.suite, "outbound", 0, 0)?;
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn mixed_srv_failover_keeps_modes_and_one_aggregate_authentication() -> TestResult {
    for failure in [
        "direct_refused",
        "direct_bad_handshake",
        "direct_bad_certificate",
        "starttls_bad_certificate",
    ] {
        let direct_first = failure != "starttls_bad_certificate";
        let first = if direct_first {
            RawS2sListener::bind()?.direct_tls()
        } else {
            RawS2sListener::bind()?
        };
        let second = if direct_first {
            RawS2sListener::bind()?
        } else {
            RawS2sListener::bind()?.direct_tls()
        };
        let refused = refused_endpoint()?;
        let mut fixture = SingleServer::start("")?;
        let port = if failure == "direct_refused" {
            refused.address().port()
        } else {
            first.address()?.port()
        };
        publish(&fixture, direct_first, 0, port, "first.b.test");
        publish(
            &fixture,
            !direct_first,
            10,
            second.address()?.port(),
            "second.b.test",
        );
        let wrong = peer::server_config(
            &fixture.ca,
            fixture.ca.wrong_name(fixture.directory.path(), "b.test")?,
            "a.test",
        )?;
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='failover-srv'><body>Retained once</body></message>")?;
        let outcome = match failure {
            "direct_refused" => "unreachable",
            "direct_bad_handshake" => {
                let (mut socket, _) = first.accept_client_hello("b.test")?;
                socket.write_all(b"not a TLS record")?;
                socket.shutdown(std::net::Shutdown::Both)?;
                "tls_failure"
            }
            _ => {
                assert!(first.accept("b.test", "a.test", wrong, true).is_err());
                "certificate_name"
            }
        };
        let mut remote =
            second.accept("b.test", "a.test", config(&fixture, b"xmpp-server")?, true)?;
        remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='failover-srv'><body>Retained once</body></message>")?;
        let (failed, succeeded) = if direct_first {
            ("direct", "starttls")
        } else {
            ("starttls", "direct")
        };
        transport_attempts(
            &fixture.suite,
            "outbound",
            &[(failed, outcome, 1), (succeeded, "success", 1)],
        )?;
        authentication(&fixture.suite, "outbound", "success", 1)?;
        let metrics = fixture.suite.scrape_metrics()?;
        assert_eq!(
            metrics
                .lines()
                .filter(|line| line
                    .starts_with("lonewolf_s2s_authentications_total{direction=\"outbound\""))
                .count(),
            1
        );
        assert_discovery(&fixture)?;
        remote.close()?;
        closed(&fixture.suite, "outbound", "stream_end", 1)?;
        transport_connections(&fixture.suite, "outbound", 0, 0)?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn dot_disables_only_its_own_srv_transport() -> TestResult {
    for direct in [false, true] {
        let listener = if direct {
            RawS2sListener::bind()?.direct_tls()
        } else {
            RawS2sListener::bind()?
        };
        let mut fixture = SingleServer::start("")?;
        publish(
            &fixture,
            direct,
            0,
            listener.address()?.port(),
            "available.b.test",
        );
        if direct {
            fixture.dns.no_service("b.test");
        } else {
            fixture.dns.direct_srv("b.test", &[(0, 0, 0, ".")]);
        }
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='dot-other'><body>Other transport</body></message>")?;
        let mut remote =
            listener.accept("b.test", "a.test", config(&fixture, b"xmpp-server")?, true)?;
        remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='dot-other'><body>Other transport</body></message>")?;
        transport_attempts(
            &fixture.suite,
            "outbound",
            &[(if direct { "direct" } else { "starttls" }, "success", 1)],
        )?;
        assert_discovery(&fixture)?;
        remote.close()?;
        closed(&fixture.suite, "outbound", "stream_end", 1)?;
        transport_connections(&fixture.suite, "outbound", 0, 0)?;
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn unusable_advertisements_bounce_without_origin_queries_or_decoy_connections() -> TestResult {
    for case in [
        "direct_dot_missing_starttls",
        "both_dot",
        "no_addresses",
        "all_refused",
    ] {
        let mut fixture = SingleServer::start("")?;
        let decoy = RawS2sListener::bind()?;
        let first = refused_endpoint()?;
        let second = refused_endpoint()?;
        fixture.dns.a("b.test", Ipv4Addr::LOCALHOST);
        match case {
            "direct_dot_missing_starttls" => fixture.dns.direct_srv("b.test", &[(0, 0, 0, ".")]),
            "both_dot" => {
                fixture.dns.no_service("b.test");
                fixture.dns.direct_srv("b.test", &[(0, 0, 0, ".")]);
            }
            "no_addresses" => fixture.dns.direct_srv(
                "b.test",
                &[(0, 0, decoy.address()?.port(), "no-address.b.test")],
            ),
            _ => {
                publish(&fixture, true, 0, first.address().port(), "first.b.test");
                publish(&fixture, false, 1, second.address().port(), "second.b.test");
            }
        }
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='unusable'><body>Do not bypass DNS</body></message>")?;
        let refused = case == "all_refused";
        expect_bounce(
            &mut alice,
            "unusable",
            if refused {
                "remote-server-timeout"
            } else {
                "remote-server-not-found"
            },
        )?;
        if refused {
            transport_attempts(
                &fixture.suite,
                "outbound",
                &[("direct", "unreachable", 1), ("starttls", "unreachable", 1)],
            )?;
            authentication(&fixture.suite, "outbound", "unreachable", 1)?;
        } else {
            transport_attempts(&fixture.suite, "outbound", &[])?;
        }
        for service in ["_xmpp-server._tcp.b.test", "_xmpps-server._tcp.b.test"] {
            assert_eq!(fixture.dns.query_count(service, RecordType::SRV), 1);
        }
        for family in [RecordType::A, RecordType::AAAA] {
            assert_eq!(fixture.dns.query_count("b.test", family), 0);
        }
        for sample in [
            "lonewolf_s2s_outbound_queued_stanzas 0",
            "lonewolf_s2s_outbound_queued_bytes 0",
        ] {
            fixture.suite.wait_for_metric(sample)?;
        }
        transport_connections(&fixture.suite, "outbound", 0, 0)?;
        decoy.assert_not_contacted()?;
        alice.close()?;
        let state = fixture
            .suite
            .stop_with_s2s_state()?
            .ok_or("missing shutdown receipt")?;
        assert_eq!(state.queued_stanzas, 0);
        assert_eq!(state.queued_bytes, 0);
        assert_eq!(state.transport_connections, [[0; 2]; 2]);
        assert_eq!(state.connections, [0; 2]);
        fixture.dns.stop()?;
    }
    Ok(())
}
