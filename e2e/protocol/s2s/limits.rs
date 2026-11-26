// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use super::super::support::federation::peer::{self, RawS2sListener};
use super::super::support::{PASSWORD, TestResult};
use super::negotiation::SingleServer;

#[test]
fn oversized_heads_bounce_then_smaller_stanzas_use_the_same_physical_connection() -> TestResult {
    for mode in ["inbound_bidi", "outbound_bidi", "outbound_unidirectional"] {
        let mut fixture = if mode == "outbound_unidirectional" {
            SingleServer::start("")?
        } else {
            SingleServer::start_bidirectional("")?
        };
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        let listener = RawS2sListener::bind()?.advertising("", &peer::limits_xml(500, 0), "");
        let mut stream = if mode == "inbound_bidi" {
            let mut stream = fixture.connect()?;
            stream.expect_starttls_features()?;
            let mut stream = stream.start_tls(fixture.client_config()?)?;
            stream.expect_external_and_bidi_offered()?;
            stream.send(&format!(
                "<bidi xmlns='urn:xmpp:bidi'>{}</bidi>",
                peer::limits_xml(500, 0)
            ))?;
            stream.auth_external(Some("b.test"))?;
            stream.expect_sasl_success()?;
            stream.restart("b.test", "a.test")?
        } else {
            fixture.dns.srv(
                "b.test",
                &[(0, 0, listener.address()?.port(), "server.b.test")],
            );
            fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
            alice.send("<message to='bob@b.test/phone' type='chat' id='establish'><body>ready</body></message>")?;
            let config = peer::server_config(
                &fixture.ca,
                fixture
                    .ca
                    .server(fixture.directory.path(), "peer", &["b.test"])?,
                "a.test",
            )?;
            let mut stream = if mode == "outbound_bidi" {
                let (stream, requested) =
                    listener.accept_offering_bidi("b.test", "a.test", config)?;
                assert!(requested);
                stream
            } else {
                listener.accept("b.test", "a.test", config, true)?
            };
            assert_eq!(stream.receive()?.attribute("id"), Some("establish"));
            stream
        };
        let direction = if mode == "inbound_bidi" {
            "inbound"
        } else {
            "outbound"
        };
        fixture.suite.wait_for_metric(&format!(
            "lonewolf_s2s_authentications_total{{direction=\"{direction}\",outcome=\"success\"}} 1"
        ))?;
        let body = "é<&🙂".repeat(200);
        let escaped = body.replace('&', "&amp;").replace('<', "&lt;");
        alice.send(&format!("<message to='bob@b.test/phone' type='chat' id='oversize'><body>{escaped}</body><p:extra xmlns:p='urn:payload' p:a='&amp;'/></message>"))?;
        alice.send("<message to='bob@b.test/phone' type='chat' id='following'><body>small</body></message>")?;
        let bounced = alice.receive()?;
        bounced.assert_name("jabber:client", "message");
        assert_eq!(bounced.attribute("id"), Some("oversize"));
        assert_eq!(bounced.attribute("type"), Some("error"));
        assert_eq!(bounced.attribute("from"), Some("bob@b.test/phone"));
        assert_eq!(bounced.attribute("to"), Some("alice@a.test/desk"));
        assert_eq!(bounced.child("jabber:client", "body")?.text, body);
        assert_eq!(
            bounced.child("urn:payload", "extra")?.attribute("p:a"),
            Some("&")
        );
        let error = bounced.child("jabber:client", "error")?;
        assert_eq!(error.attribute("by"), None);
        error.child("urn:ietf:params:xml:ns:xmpp-stanzas", "policy-violation")?;
        assert_eq!(stream.receive()?.attribute("id"), Some("following"));
        let sent = if mode == "inbound_bidi" { 1 } else { 2 };
        for sample in [
            "lonewolf_s2s_peer_size_rejections_total 1".to_owned(),
            "lonewolf_s2s_bounces_total{condition=\"policy_violation\"} 1".to_owned(),
            format!("lonewolf_s2s_stanzas_sent_total{{kind=\"message\"}} {sent}"),
            format!("lonewolf_s2s_connections{{direction=\"{direction}\"}} 1"),
            "lonewolf_s2s_outbound_links{state=\"ready\"} 1".to_owned(),
            "lonewolf_s2s_outbound_queued_stanzas 0".to_owned(),
            "lonewolf_s2s_outbound_queued_bytes 0".to_owned(),
        ] {
            fixture.suite.wait_for_metric(&sample)?;
        }
        let metrics = fixture.suite.scrape_metrics()?;
        assert!(
            !metrics.contains("lonewolf_s2s_dropped_stanzas_total"),
            "{metrics}"
        );
        if mode == "inbound_bidi" {
            fixture
                .suite
                .wait_for_metric("lonewolf_s2s_bidi_stanzas_sent_total{kind=\"message\"} 1")?;
            assert!(!metrics.contains("lonewolf_s2s_dns_resolutions_total"));
        } else {
            fixture
                .suite
                .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
            assert!(!metrics.contains("lonewolf_s2s_bidi_stanzas_sent_total"));
        }
        alice.close()?;
        stream.close()?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn tls_clears_plaintext_advice_and_final_features_replace_or_retain_tls_advice() -> TestResult {
    for (post_tls, final_features, rejected) in [
        ("", "", false),
        (
            "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>300</max-bytes></limits>",
            "",
            true,
        ),
        (
            "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>300</max-bytes></limits>",
            "<limits xmlns='urn:xmpp:stream-limits:0'/>",
            false,
        ),
        (
            "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>300</max-bytes></limits>",
            "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>2000</max-bytes></limits>",
            false,
        ),
        (
            "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>2000</max-bytes></limits>",
            "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>300</max-bytes></limits>",
            true,
        ),
        (
            "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>300</max-bytes></limits>",
            "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>-1</max-bytes></limits>",
            true,
        ),
    ] {
        let mut fixture = SingleServer::start("")?;
        let listener = RawS2sListener::bind()?.advertising(
            "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>64</max-bytes></limits>",
            post_tls,
            final_features,
        );
        fixture.dns.srv(
            "b.test",
            &[(0, 0, listener.address()?.port(), "server.b.test")],
        );
        fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
        fixture.suite.create_account("alice", PASSWORD)?;
        let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
        alice.send(&format!(
            "<message to='bob@b.test/phone' type='chat' id='phase-size'><body>{}</body></message>",
            "x".repeat(600)
        ))?;
        let config = peer::server_config(
            &fixture.ca,
            fixture
                .ca
                .server(fixture.directory.path(), "peer", &["b.test"])?,
            "a.test",
        )?;
        let mut stream = listener.accept("b.test", "a.test", config, true)?;
        if rejected {
            super::negotiation::expect_bounce(&mut alice, "phase-size", "policy-violation")?;
        } else {
            assert_eq!(stream.receive()?.attribute("id"), Some("phase-size"));
        }
        alice.send(
            "<message to='bob@b.test/phone' type='chat' id='phase-tail'><body>ok</body></message>",
        )?;
        assert_eq!(stream.receive()?.attribute("id"), Some("phase-tail"));
        fixture.suite.wait_for_metric(
            "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"success\"} 1",
        )?;
        let metrics = fixture.suite.scrape_metrics()?;
        assert_eq!(
            metrics.contains("lonewolf_s2s_peer_size_rejections_total 1"),
            rejected
        );
        stream.close()?;
        alice.close()?;
        fixture.stop()?;
    }
    Ok(())
}

#[test]
fn unusably_small_bidi_advice_closes_with_policy_violation_without_routed_rejection() -> TestResult
{
    let mut fixture = SingleServer::start_bidirectional("")?;
    let mut stream = fixture.connect()?;
    stream.expect_starttls_features()?;
    let mut stream = stream.start_tls(fixture.client_config()?)?;
    stream.expect_external_and_bidi_offered()?;
    stream.send(&format!(
        "<bidi xmlns='urn:xmpp:bidi'>{}</bidi>",
        peer::limits_xml(0, 0)
    ))?;
    stream.auth_external(Some("b.test"))?;
    stream.expect_stream_error("policy-violation")?;
    super::negotiation::authentication(&fixture.suite, "inbound", "protocol", 1)?;
    let metrics = fixture.suite.scrape_metrics()?;
    assert!(!metrics.contains("lonewolf_s2s_peer_size_rejections_total"));
    assert!(!metrics.contains("lonewolf_s2s_stanzas_sent_total"));
    fixture.stop()
}

#[test]
fn oversized_errors_iq_results_and_ordinary_presence_do_not_create_error_loops() -> TestResult {
    let mut fixture = SingleServer::start_bidirectional_with_extensions("", "'ping'")?;
    let listener = RawS2sListener::bind()?.advertising("", &peer::limits_xml(300, 0), "");
    fixture.dns.srv(
        "b.test",
        &[(0, 0, listener.address()?.port(), "server.b.test")],
    );
    fixture.dns.a("server.b.test", Ipv4Addr::LOCALHOST);
    fixture.suite.create_account("alice", PASSWORD)?;
    let mut alice = fixture.suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<message to='bob@b.test/phone' type='chat' id='establish'><body>ready</body></message>",
    )?;
    let config = peer::server_config(
        &fixture.ca,
        fixture
            .ca
            .server(fixture.directory.path(), "peer", &["b.test"])?,
        "a.test",
    )?;
    let (mut stream, requested) = listener.accept_offering_bidi("b.test", "a.test", config)?;
    assert!(requested);
    assert_eq!(stream.receive()?.attribute("id"), Some("establish"));
    let body = "x".repeat(1024);
    for xml in [
        format!(
            "<message type='error' to='bob@b.test/phone' id='error'><body>{body}</body><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>"
        ),
        format!(
            "<iq type='result' to='bob@b.test/phone' id='result'><query xmlns='urn:test'>{body}</query></iq>"
        ),
        format!(
            "<presence to='bob@b.test/phone' id='ordinary'><x xmlns='urn:test'>{body}</x></presence>"
        ),
    ] {
        alice.send(&xml)?;
    }
    alice.send("<message to='bob@b.test/phone' type='chat' id='tail'><body>ok</body></message>")?;
    assert_eq!(stream.receive()?.attribute("id"), Some("tail"));
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_peer_size_rejections_total 3")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_dropped_stanzas_total{reason=\"not_bounceable\"} 3")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 2")?;
    alice.send(
        "<iq to='a.test' type='get' id='no-loop-barrier'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    let reply = alice.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("result"));
    assert_eq!(reply.attribute("id"), Some("no-loop-barrier"));
    assert!(
        !fixture
            .suite
            .scrape_metrics()?
            .contains("lonewolf_s2s_bounces_total")
    );
    stream.close()?;
    alice.close()?;
    fixture.stop()
}
