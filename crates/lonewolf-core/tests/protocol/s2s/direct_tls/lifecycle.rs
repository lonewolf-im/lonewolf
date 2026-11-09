// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::support::federation::peer::RawS2sPeer;
use lonewolf_core::config::TlsMode;
use std::net::Ipv4Addr;

#[test]
fn direct_tls_leaf_expiry_resets_inbound_and_outbound_bidi_and_releases_routing_ownership()
-> TestResult {
    expiry(false)
}

#[test]
fn direct_tls_intermediate_expiry_resets_inbound_and_outbound_bidi_and_releases_routing_ownership()
-> TestResult {
    expiry(true)
}

fn expiry(intermediate: bool) -> TestResult {
    for inbound in [true, false] {
        let mut fixture = SingleServer::start_bidirectional("")?;
        fixture.set_transport(TlsMode::Direct)?;
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        let key = if intermediate {
            fixture.ca.intermediate_until(
                "b.test",
                time::OffsetDateTime::now_utc() + time::Duration::seconds(6),
            )?
        } else {
            fixture
                .ca
                .short_lived(fixture.directory.path(), "b.test", 6)?
        };
        let listener = RawS2sListener::bind()?.direct_tls();
        fixture.dns.direct_srv(
            "b.test",
            &[(0, 0, listener.address()?.port(), "expiry.b.test")],
        );
        fixture.dns.a("expiry.b.test", Ipv4Addr::LOCALHOST);
        let mut remote = if inbound {
            let mut remote = RawS2sPeer::protected(
                TlsMode::Direct,
                fixture.suite.s2s_addresses()?[0],
                "b.test",
                "a.test",
                peer::client_config(&fixture.ca, key)?,
                Some("b.test"),
            )?;
            remote.expect_external_and_bidi_offered()?;
            remote.request_bidi()?;
            remote.auth_external(Some("b.test"))?;
            remote.expect_sasl_success()?;
            remote.restart("b.test", "a.test")?
        } else {
            alice.send("<message to='bob@b.test/phone' type='chat' id='before-expiry'><body>Before expiry</body></message>")?;
            let (mut remote, requested) = listener.accept_offering_bidi(
                "b.test",
                "a.test",
                peer::server_config(&fixture.ca, key, "a.test")?,
            )?;
            assert!(requested);
            remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='before-expiry'><body>Before expiry</body></message>")?;
            remote
        };
        let local_certificate = crate::support::federation::pki::certificate(
            &fixture.suite.fixture_path().join("certificate-host.pem"),
        )?;
        assert_eq!(
            remote
                .peer_certificates()
                .ok_or("missing local certificate")?[0],
            local_certificate
        );
        let direction = if inbound { "inbound" } else { "outbound" };
        authentication(&fixture.suite, direction, "success", 1)?;
        transport_attempts(&fixture.suite, direction, &[("direct", "success", 1)])?;
        transport_connections(&fixture.suite, direction, 0, 1)?;
        remote.send("<message from='bob@b.test/phone' to='alice@a.test/desk' type='chat' id='bidi-live'><body>Bidi is live</body></message>")?;
        alice.expect_xml("<message xmlns='jabber:client' from='bob@b.test/phone' to='alice@a.test/desk' type='chat' id='bidi-live'><body>Bidi is live</body></message>")?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='bidi-reply'><body>Reverse link</body></message>")?;
        remote.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='bidi-reply'><body>Reverse link</body></message>")?;
        remote.expect_stream_error("reset")?;
        closed(&fixture.suite, direction, "certificate_expired", 1)?;
        transport_connections(&fixture.suite, direction, 0, 0)?;
        fixture.suite.wait_for_metric(&format!(
            "lonewolf_s2s_bidi_streams{{direction=\"{direction}\"}} 0"
        ))?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_outbound_links{state=\"ready\"} 0")?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
        fixture
            .suite
            .wait_for_metric("lonewolf_s2s_outbound_queued_bytes 0")?;
        let fresh_key = fixture
            .ca
            .server(fixture.directory.path(), "fresh", &["b.test"])?;
        let mut fresh = if inbound {
            let mut fresh = RawS2sPeer::protected(
                TlsMode::Direct,
                fixture.suite.s2s_addresses()?[0],
                "b.test",
                "a.test",
                peer::client_config(&fixture.ca, fresh_key)?,
                Some("b.test"),
            )?;
            fresh.expect_external_and_bidi_offered()?;
            fresh.request_bidi()?;
            fresh.auth_external(Some("b.test"))?;
            fresh.expect_sasl_success()?;
            fresh.restart("b.test", "a.test")?
        } else {
            alice.send("<message to='bob@b.test/phone' type='chat' id='fresh-owner'><body>Fresh ownership</body></message>")?;
            let (mut fresh, requested) = listener.accept_offering_bidi(
                "b.test",
                "a.test",
                peer::server_config(&fixture.ca, fresh_key, "a.test")?,
            )?;
            assert!(requested);
            fresh.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='fresh-owner'><body>Fresh ownership</body></message>")?;
            fresh
        };
        fresh.send("<message from='bob@b.test/phone' to='alice@a.test/desk' type='chat' id='fresh-live'><body>Fresh authenticated stream</body></message>")?;
        alice.expect_xml("<message xmlns='jabber:client' from='bob@b.test/phone' to='alice@a.test/desk' type='chat' id='fresh-live'><body>Fresh authenticated stream</body></message>")?;
        authentication(&fixture.suite, direction, "success", 2)?;
        transport_attempts(&fixture.suite, direction, &[("direct", "success", 2)])?;
        fresh.close()?;
        closed(&fixture.suite, direction, "stream_end", 1)?;
        transport_connections(&fixture.suite, direction, 0, 0)?;
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}
