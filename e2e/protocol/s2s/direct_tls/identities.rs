// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::net::Ipv4Addr;

#[test]
fn direct_srv_accepts_server_auth_dns_srv_id_and_xmpp_addr_reference_identities() -> TestResult {
    for identity in ["dns", "srv_id", "xmpp_addr"] {
        let listener = RawS2sListener::bind()?.direct_tls();
        let mut fixture = SingleServer::start("")?;
        fixture.dns.direct_srv(
            "b.test",
            &[(0, 0, listener.address()?.port(), "edge.b.test")],
        );
        fixture.dns.a("edge.b.test", Ipv4Addr::LOCALHOST);
        let key = match identity {
            "srv_id" => fixture.ca.srv_id(fixture.directory.path(), "b.test")?,
            "xmpp_addr" => fixture.ca.xmpp_addr(fixture.directory.path(), "b.test")?,
            _ => fixture
                .ca
                .server(fixture.directory.path(), "dns", &["b.test"])?,
        };
        let config = peer::server_config(&fixture.ca, key, "a.test")?;
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='identity'><body>XMPP reference identity</body></message>")?;
        let mut remote = listener.accept("b.test", "a.test", config, true)?;
        remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='identity'><body>XMPP reference identity</body></message>")?;
        authentication(&fixture.suite, "outbound", "success", 1)?;
        transport_attempts(&fixture.suite, "outbound", &[("direct", "success", 1)])?;
        remote.close()?;
        closed(&fixture.suite, "outbound", "stream_end", 1)?;
        transport_connections(&fixture.suite, "outbound", 0, 0)?;
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn direct_srv_rejects_target_only_expired_client_auth_and_invented_service_identity() -> TestResult
{
    for (identity, outcome) in [
        ("target_only", "certificate_name"),
        ("expired", "certificate_expired"),
        ("client_auth", "certificate_purpose"),
        ("invented_srv", "certificate_name"),
    ] {
        let listener = RawS2sListener::bind()?.direct_tls();
        let mut fixture = SingleServer::start("")?;
        fixture.dns.direct_srv(
            "b.test",
            &[(0, 0, listener.address()?.port(), "edge.b.test")],
        );
        fixture.dns.a("edge.b.test", Ipv4Addr::LOCALHOST);
        let key = match identity {
            "target_only" => {
                fixture
                    .ca
                    .server(fixture.directory.path(), "target", &["edge.b.test"])?
            }
            "expired" => fixture.ca.expired(fixture.directory.path(), "b.test")?,
            "client_auth" => fixture
                .ca
                .client_auth_only(fixture.directory.path(), "b.test")?,
            _ => fixture
                .ca
                .service_id(fixture.directory.path(), "_xmpps-server", "b.test")?,
        };
        let config = peer::server_config(&fixture.ca, key, "a.test")?;
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='rejected-identity'><body>Identity required</body></message>")?;
        assert!(listener.accept("b.test", "a.test", config, true).is_err());
        expect_bounce(&mut alice, "rejected-identity", "remote-server-timeout")?;
        authentication(&fixture.suite, "outbound", outcome, 1)?;
        transport_attempts(&fixture.suite, "outbound", &[("direct", outcome, 1)])?;
        transport_connections(&fixture.suite, "outbound", 0, 0)?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_outbound_queued_bytes 0")?;
        for family in [RecordType::A, RecordType::AAAA] {
            assert_eq!(fixture.dns.query_count("b.test", family), 0);
        }
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn static_legacy_and_mixed_mode_routes_keep_configured_order_and_bypass_both_services() -> TestResult
{
    for mode in ["legacy", "direct_first", "starttls_first"] {
        let direct = mode == "direct_first";
        let listener = if direct {
            RawS2sListener::bind()?.direct_tls()
        } else {
            RawS2sListener::bind()?
        };
        let decoy = RawS2sListener::bind()?;
        let first = if direct {
            format!("{{address='{}',tls_mode='direct'}}", listener.address()?)
        } else {
            format!("'{}'", listener.address()?)
        };
        let second = if direct {
            format!("'{}'", decoy.address()?)
        } else {
            format!("{{address='{}',tls_mode='direct'}}", decoy.address()?)
        };
        let endpoints = if mode == "legacy" {
            first
        } else {
            format!("{first},{second}")
        };
        let mut fixture = SingleServer::start(&format!("[s2s.routes]\n'b.test'=[{endpoints}]"))?;
        fixture.dns.servfail("_xmpp-server._tcp.b.test");
        fixture.dns.servfail("_xmpps-server._tcp.b.test");
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='static-order'><body>Configured route</body></message>")?;
        let mut remote = listener.accept("b.test", "a.test", config(&fixture, b"")?, true)?;
        remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='static-order'><body>Configured route</body></message>")?;
        transport_attempts(
            &fixture.suite,
            "outbound",
            &[(if direct { "direct" } else { "starttls" }, "success", 1)],
        )?;
        authentication(&fixture.suite, "outbound", "success", 1)?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"static\"} 1")?;
        for service in ["_xmpp-server._tcp.b.test", "_xmpps-server._tcp.b.test"] {
            assert_eq!(fixture.dns.query_count(service, RecordType::SRV), 0);
        }
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
fn inbound_direct_tls_preserves_srv_id_and_xmpp_addr_but_rejects_invented_identity() -> TestResult {
    use crate::support::federation::peer::RawS2sPeer;
    for kind in ["srv_id", "xmpp_addr", "invented"] {
        let mut fixture = inbound_fixture("", true)?;
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        let key = match kind {
            "srv_id" => fixture.ca.srv_id(fixture.directory.path(), "b.test")?,
            "xmpp_addr" => fixture.ca.xmpp_addr(fixture.directory.path(), "b.test")?,
            _ => fixture
                .ca
                .service_id(fixture.directory.path(), "_xmpps-server", "b.test")?,
        };
        let mut remote = RawS2sPeer::tls_first(
            fixture.suite.s2s_addresses()?[1],
            "b.test",
            "a.test",
            peer::client_config(&fixture.ca, key)?,
        )?;
        remote.open_protected(
            &inbound_header(Some("b.test"), "a.test"),
            if kind == "invented" {
                None
            } else {
                Some("b.test")
            },
        )?;
        if kind == "invented" {
            remote.expect_stream_error("not-authorized")?;
            authentication(&fixture.suite, "inbound", "certificate_name", 1)?;
            transport_attempts(
                &fixture.suite,
                "inbound",
                &[("direct", "certificate_name", 1)],
            )?;
        } else {
            remote.expect_external_and_bidi_offered()?;
            remote.request_bidi()?;
            remote.auth_external(Some("b.test"))?;
            remote.expect_sasl_success()?;
            let mut remote = remote.restart("b.test", "a.test")?;
            remote.send("<message from='bob@b.test/phone' to='alice@a.test/desk' type='chat' id='remote-identity'><body>Remote identity</body></message>")?;
            alice.expect_xml("<message xmlns='jabber:client' from='bob@b.test/phone' to='alice@a.test/desk' type='chat' id='remote-identity'><body>Remote identity</body></message>")?;
            alice.send("<message to='bob@b.test/phone' type='chat' id='identity-reply'><body>Verified</body></message>")?;
            remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='identity-reply'><body>Verified</body></message>")?;
            authentication(&fixture.suite, "inbound", "success", 1)?;
            transport_attempts(&fixture.suite, "inbound", &[("direct", "success", 1)])?;
            remote.close()?;
            closed(&fixture.suite, "inbound", "stream_end", 1)?;
        }
        transport_connections(&fixture.suite, "inbound", 0, 0)?;
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}
