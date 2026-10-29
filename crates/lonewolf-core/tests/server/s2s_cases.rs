// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;

use super::{outbound as out, support::*};

fn authenticated(fixture: &Fixture, address: SocketAddr) -> Result<Peer> {
    let (mut peer, _) = start_tls(address, fixture.client(Some("peer.test"), false)?)?;
    external(&mut peer, HEADER)?;
    success(&mut peer, AUTH)?;
    Ok(peer)
}

fn finish_error(peer: &mut Peer, condition: &str) -> Result {
    stream_error(peer, condition)?;
    peer.write_all(FOOTER.as_bytes())?;
    peer.conn.send_close_notify();
    peer.flush()?;
    Ok(())
}

#[test]
fn authenticated_ingress_enforces_namespaces_addresses_and_rejected_envelopes() -> Result {
    let fixture = Fixture::new()?;
    let (mut server, address) = fixture.server("[hosts.localhost]\nfederation=false\n")?;
    let cases = [
        ("<message from='a@peer.test'/>", "improper-addressing"),
        ("<message to='b@local.test'/>", "improper-addressing"),
        (
            "<message to='b@localhost' from='a@peer.test'/>",
            "host-unknown",
        ),
        (
            "<message to='b@third.test' from='a@peer.test'/>",
            "host-unknown",
        ),
        (
            "<message to='b@local.test' from='a@third.test'/>",
            "invalid-from",
        ),
        (
            "<message xmlns='jabber:client' to='b@local.test' from='a@peer.test'/>",
            "invalid-namespace",
        ),
        (
            "<message xmlns='urn:foreign' to='b@local.test' from='a@peer.test'/>",
            "invalid-namespace",
        ),
        (
            "<db:result xmlns:db='jabber:server:dialback' from='peer.test' to='local.test'/>",
            "unsupported-stanza-type",
        ),
        (
            "<message to='bad@@local.test' from='a@peer.test'/>",
            "improper-addressing",
        ),
        (
            "<message to='b@local.test' from='bad@@peer.test'/>",
            "improper-addressing",
        ),
        (
            "<message to='b@local.test' from='a@third.test'>text</message>",
            "invalid-from",
        ),
        (
            "<message to='b@third.test' from='a@peer.test'>text</message>",
            "host-unknown",
        ),
        (
            "<message xmlns='jabber:client' to='b@local.test' from='a@peer.test'>text</message>",
            "invalid-namespace",
        ),
        (
            "<message from='a@peer.test'>text</message>",
            "improper-addressing",
        ),
    ];
    let mut counts = std::collections::BTreeMap::new();
    for (xml, condition) in cases {
        let mut peer = authenticated(&fixture, address)?;
        peer.write_all(xml.as_bytes())?;
        finish_error(&mut peer, condition)?;
        let outcome = condition.replace('-', "_");
        let count = counts.entry(outcome.clone()).or_insert(0);
        *count += 1;
        wait_sample(
            &server,
            &format!(
                "lonewolf_s2s_streams_closed_total{{direction=\"inbound\",outcome=\"{outcome}\"}}"
            ),
            *count,
        )?;
    }
    wait_sample(
        &server,
        "lonewolf_s2s_connections{direction=\"inbound\"}",
        0,
    )?;
    assert_eq!(
        out::counter(
            &metrics(&server)?,
            "lonewolf_s2s_stanzas_received_total{kind=\"message\"}"
        )?,
        0
    );
    assert_eq!(
        out::counter(
            &metrics(&server)?,
            "lonewolf_s2s_dns_resolutions_total{outcome=\"static\"}"
        )?,
        0
    );
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn shared_inbound_pair_limit_survives_conflict_and_releases_after_close() -> Result {
    let fixture = Fixture::new()?;
    let mut server = super::process::Server::start(
        &format!(
            "{}[[s2s.listeners]]\naddress='127.0.0.1:0'\n[limits.s2s]\nmax_inbound_streams_per_domain=1\n",
            fixture.config
        ),
        2,
    )?;
    let addresses = server
        .ready_with(|readiness| readiness.s2s)?
        .ok_or("S2S readiness")?;
    assert_eq!(addresses.len(), 2);
    let mut first = authenticated(&fixture, addresses[0])?;
    let mut refused = authenticated(&fixture, addresses[1])?;
    finish_error(&mut refused, "conflict")?;
    wait_sample(
        &server,
        "lonewolf_s2s_streams_closed_total{direction=\"inbound\",outcome=\"conflict\"}",
        1,
    )?;
    wait_sample(&server, "lonewolf_s2s_streams{direction=\"inbound\"}", 1)?;
    close(&mut first)?;
    wait_sample(&server, "lonewolf_s2s_streams{direction=\"inbound\"}", 0)?;
    let mut again = authenticated(&fixture, addresses[1])?;
    close(&mut again)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn inbound_idle_and_actual_certificate_deadlines_close_with_lifetime_outcomes() -> Result {
    let fixture = Fixture::new()?;
    let (mut server, address) = fixture.server("[limits.s2s]\nidle_timeout_secs=1\n")?;
    let mut idle = authenticated(&fixture, address)?;
    assert_eq!(until(&mut idle, FOOTER)?, FOOTER);
    idle.write_all(FOOTER.as_bytes())?;
    idle.conn.send_close_notify();
    idle.flush()?;
    wait_sample(
        &server,
        "lonewolf_s2s_streams_closed_total{direction=\"inbound\",outcome=\"idle\"}",
        1,
    )?;
    server.stop(Signal::SIGTERM)?;

    let (mut server, address) = fixture.server("")?;
    let expiry = time::OffsetDateTime::now_utc() + time::Duration::seconds(4);
    let config = fixture.client_until(expiry)?;
    let (mut peer, _) = start_tls(address, config)?;
    external(&mut peer, HEADER)?;
    success(&mut peer, AUTH)?;
    finish_error(&mut peer, "reset")?;
    assert!(time::OffsetDateTime::now_utc().unix_timestamp() >= expiry.unix_timestamp());
    wait_sample(
        &server,
        "lonewolf_s2s_streams_closed_total{direction=\"inbound\",outcome=\"certificate_expired\"}",
        1,
    )?;
    wait_sample(&server, "lonewolf_s2s_streams{direction=\"inbound\"}", 0)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn genuine_ingress_replies_establish_ordered_outbound_stream_reuse_and_never_answer_errors()
-> Result {
    let fixture = Fixture::new()?;
    let listener = out::listener()?;
    let config = out::config(&fixture, "peer.test", false, false)?;
    let (mut server, mut initiator) = out::start(&fixture, &[listener.local_addr()?], "")?;
    out::trigger(&mut initiator, "one")?;
    let mut receiving = out::establish(&listener, config, &fixture)?;
    out::reply(&mut receiving, "one")?;
    initiator.write_all(b"<message type='error' from='a@peer.test/remote' to='b@local.test/local' id='never'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
    out::trigger(&mut initiator, "two")?;
    out::trigger(&mut initiator, "three")?;
    out::reply(&mut receiving, "two")?;
    out::reply(&mut receiving, "three")?;
    initiator.write_all(b"<iq type='get' from='a@peer.test/remote' to='b@local.test/local' id='iq'><query xmlns='urn:test'/></iq>")?;
    initiator.flush()?;
    let iq = until(&mut receiving, "</iq>")?;
    assert!(
        iq.contains("xmlns=\"jabber:server\"")
            && iq.contains("id=\"iq\"")
            && iq.contains("service-unavailable")
            && iq.contains("to=\"a@peer.test/remote\"")
            && iq.contains("from=\"b@local.test/local\""),
        "{iq}"
    );
    initiator.write_all(
        b"<message from='a@peer.test/remote' to='b@local.test/local' id='bad'>text</message>",
    )?;
    initiator.flush()?;
    let rejected_reply = until(&mut receiving, "</message>")?;
    assert!(
        rejected_reply.contains("bad-request") && rejected_reply.contains("id=\"bad\""),
        "{rejected_reply}"
    );
    listener.set_nonblocking(true)?;
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    wait_sample(&server, &out::outbound_auth("success"), 1)?;
    assert_eq!(out::authentication_total(&metrics(&server)?)?, 1);
    wait_sample(
        &server,
        "lonewolf_s2s_dns_resolutions_total{outcome=\"static\"}",
        1,
    )?;
    wait_sample(
        &server,
        "lonewolf_s2s_stanzas_received_total{kind=\"message\"}",
        5,
    )?;
    wait_sample(
        &server,
        "lonewolf_s2s_connections{direction=\"outbound\"}",
        1,
    )?;
    wait_sample(&server, "lonewolf_s2s_streams{direction=\"outbound\"}", 1)?;
    out::close(&mut receiving)?;
    out::wait_zero(&server)?;
    close(&mut initiator)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn outgoing_idle_footer_forbidden_stanza_and_peer_error_remove_links_and_reestablish() -> Result {
    for mode in ["idle", "footer", "stanza", "error"] {
        let fixture = Fixture::new()?;
        let listener = out::listener()?;
        let config = out::config(&fixture, "peer.test", false, false)?;
        let extra = if mode == "idle" {
            "[limits.s2s]\nidle_timeout_secs=1\n"
        } else {
            ""
        };
        let (mut server, mut initiator) = out::start(&fixture, &[listener.local_addr()?], extra)?;
        out::trigger(&mut initiator, "one")?;
        let mut receiving = out::establish(&listener, Arc::clone(&config), &fixture)?;
        out::reply(&mut receiving, "one")?;
        let inbound_address = initiator.sock.peer_addr()?;
        let expected = match mode {
            "idle" => {
                assert_eq!(until(&mut receiving, FOOTER)?, FOOTER);
                receiving.write_all(FOOTER.as_bytes())?;
                receiving.conn.send_close_notify();
                receiving.flush()?;
                "idle"
            }
            "footer" => {
                out::close(&mut receiving)?;
                "stream_end"
            }
            "stanza" => {
                receiving.write_all(b"<message from='peer.test' to='local.test'/>")?;
                finish_receiving_error(&mut receiving, "not-authorized")?;
                "not_authorized"
            }
            _ => {
                receiving.write_all(b"<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>")?;
                receiving.flush()?;
                out::abort_seen(&mut receiving)?;
                "peer_error"
            }
        };
        wait_sample(
            &server,
            &format!(
                "lonewolf_s2s_streams_closed_total{{direction=\"outbound\",outcome=\"{expected}\"}}"
            ),
            1,
        )?;
        out::wait_zero(&server)?;
        wait_sample(&server, "lonewolf_s2s_outbound_links{state=\"ready\"}", 0)?;
        if mode == "idle" {
            drop(initiator);
            initiator = authenticated(&fixture, inbound_address)?;
        }
        out::trigger(&mut initiator, "next")?;
        let mut next = out::establish(&listener, config, &fixture)?;
        out::reply(&mut next, "next")?;
        wait_sample(&server, &out::outbound_auth("success"), 2)?;
        out::close(&mut next)?;
        close(&mut initiator)?;
        server.stop(Signal::SIGTERM)?;
    }
    Ok(())
}

fn finish_receiving_error(peer: &mut out::ReceivingPeer, condition: &str) -> Result {
    stream_error(peer, condition)?;
    peer.write_all(FOOTER.as_bytes())?;
    peer.conn.send_close_notify();
    peer.flush()?;
    Ok(())
}

fn fail_plain(listener: &std::net::TcpListener, mode: &str) -> Result {
    let mut peer = out::accept(listener)?;
    out::header(&mut peer)?;
    if mode == "identity" {
        peer.write_all(
            format!(
                "{}<stream:features/>",
                out::RESPONSE.replace("from='peer.test'", "from='third.test'")
            )
            .as_bytes(),
        )?;
    } else if mode == "no_tls" {
        peer.write_all(format!("{}<stream:features/>", out::RESPONSE).as_bytes())?;
    } else {
        peer.write_all(format!("{}{}", out::RESPONSE, out::FEATURES).as_bytes())?;
        assert_eq!(until(&mut peer, "/>")?, STARTTLS);
        peer.write_all(b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")?;
    }
    let footer = until(&mut peer, FOOTER)?;
    if mode == "no_tls" {
        assert!(footer.contains("policy-violation"), "{footer}");
    }
    if mode == "identity" {
        assert!(footer.contains("host-unknown"), "{footer}");
    }
    peer.write_all(FOOTER.as_bytes())?;
    assert_eq!(peer.read(&mut [0; 1])?, 0);
    Ok(())
}

fn fail_tls(listener: &std::net::TcpListener, fixture: &Fixture, mode: &str) -> Result {
    let name = if mode == "certificate_name" {
        "third.test"
    } else {
        "peer.test"
    };
    let config = out::config(
        fixture,
        name,
        mode == "certificate_purpose",
        mode == "certificate_untrusted",
    )?;
    let mut stream = out::accept(listener)?;
    out::starttls(&mut stream)?;
    let mut peer = rustls::StreamOwned::new(rustls::ServerConnection::new(config)?, stream);
    assert!(peer.conn.complete_io(&mut peer.sock).is_err());
    out::abort_seen(&mut peer.sock)?;
    Ok(())
}

fn fail_sasl(listener: &std::net::TcpListener, fixture: &Fixture, mode: &str) -> Result {
    let mut stream = out::accept(listener)?;
    out::starttls(&mut stream)?;
    let mut peer = out::tls(
        stream,
        out::config(fixture, "peer.test", false, false)?,
        fixture,
    )?;
    if mode == "external_not_offered" {
        out::header(&mut peer)?;
        peer.write_all(format!("{}<stream:features/>", out::RESPONSE).as_bytes())?;
    } else {
        out::auth(&mut peer)?;
        if mode == "sasl_failure" {
            peer.write_all(
                b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
            )?;
        } else if mode == "nonempty" {
            peer.write_all(
                b"<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>eA==</challenge>",
            )?;
        } else {
            peer.write_all(b"<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
            assert_eq!(
                until(&mut peer, "</response>")?,
                "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>=</response>"
            );
            peer.write_all(b"<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
        }
    }
    assert_eq!(until(&mut peer, FOOTER)?, FOOTER);
    peer.write_all(FOOTER.as_bytes())?;
    peer.conn.send_close_notify();
    peer.flush()?;
    assert_eq!(peer.read(&mut [0; 1])?, 0);
    Ok(())
}

#[test]
fn outbound_establishment_failures_have_one_dns_and_one_final_authentication_outcome() -> Result {
    for mode in [
        "no_tls",
        "tls_refused",
        "identity",
        "certificate_name",
        "certificate_purpose",
        "certificate_untrusted",
        "external_not_offered",
        "sasl_failure",
        "repeated",
        "nonempty",
    ] {
        let fixture = Fixture::new()?;
        let listener = out::listener()?;
        let (mut server, mut initiator) = out::start(&fixture, &[listener.local_addr()?], "")?;
        out::trigger(&mut initiator, "failure")?;
        match mode {
            "no_tls" | "tls_refused" | "identity" => fail_plain(&listener, mode)?,
            "certificate_name" | "certificate_purpose" | "certificate_untrusted" => {
                fail_tls(&listener, &fixture, mode)?
            }
            _ => fail_sasl(&listener, &fixture, mode)?,
        }
        let outcome = if matches!(mode, "identity" | "repeated" | "nonempty") {
            "protocol"
        } else {
            mode
        };
        out::failure(&server, outcome)?;
        close(&mut initiator)?;
        server.stop(Signal::SIGTERM)?;
    }
    Ok(())
}

#[test]
fn outbound_single_empty_challenge_is_answered_and_the_reply_is_delivered() -> Result {
    let fixture = Fixture::new()?;
    let listener = out::listener()?;
    let (mut server, mut initiator) = out::start(&fixture, &[listener.local_addr()?], "")?;
    out::trigger(&mut initiator, "challenge")?;
    let mut stream = out::accept(&listener)?;
    out::starttls(&mut stream)?;
    let mut peer = out::tls(
        stream,
        out::config(&fixture, "peer.test", false, false)?,
        &fixture,
    )?;
    out::auth(&mut peer)?;
    peer.write_all(b"<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    assert_eq!(
        until(&mut peer, "</response>")?,
        "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>=</response>"
    );
    out::ready(&mut peer)?;
    out::reply(&mut peer, "challenge")?;
    wait_sample(&server, &out::outbound_auth("success"), 1)?;
    assert_eq!(out::authentication_total(&metrics(&server)?)?, 1);
    out::close(&mut peer)?;
    out::wait_zero(&server)?;
    close(&mut initiator)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn endpoint_attempts_are_ordered_and_only_the_final_establishment_records_authentication() -> Result
{
    for mode in ["refused", "tls", "sasl", "protocol"] {
        let fixture = Fixture::new()?;
        let first = out::listener()?;
        let second = out::listener()?;
        let refused = out::refused()?;
        let first_address = if mode == "refused" {
            out::address(&refused)?
        } else {
            first.local_addr()?
        };
        let (mut server, mut initiator) =
            out::start(&fixture, &[first_address, second.local_addr()?], "")?;
        out::trigger(&mut initiator, "retry")?;
        match mode {
            "tls" => fail_tls(&first, &fixture, "certificate_name")?,
            "sasl" => fail_sasl(&first, &fixture, "sasl_failure")?,
            "protocol" => fail_plain(&first, "identity")?,
            _ => {}
        }
        let mut peer = out::establish(
            &second,
            out::config(&fixture, "peer.test", false, false)?,
            &fixture,
        )?;
        out::reply(&mut peer, "retry")?;
        wait_sample(&server, &out::outbound_auth("success"), 1)?;
        assert_eq!(out::authentication_total(&metrics(&server)?)?, 1);
        wait_sample(
            &server,
            "lonewolf_s2s_dns_resolutions_total{outcome=\"static\"}",
            1,
        )?;
        let body = metrics(&server)?;
        for failure in [
            "certificate_name",
            "sasl_failure",
            "protocol",
            "unreachable",
        ] {
            assert_eq!(
                out::counter(&body, &out::outbound_auth(failure))?,
                0,
                "{body}"
            );
        }
        out::close(&mut peer)?;
        out::wait_zero(&server)?;
        close(&mut initiator)?;
        server.stop(Signal::SIGTERM)?;
        drop(refused);
    }
    Ok(())
}

#[test]
fn all_refusals_and_mixed_connected_failures_preserve_terminal_error_precedence() -> Result {
    for connected in [false, true] {
        let fixture = Fixture::new()?;
        let refused_first = out::refused()?;
        let refused_last = out::refused()?;
        let first = out::listener()?;
        let last = out::listener()?;
        let mut endpoints = vec![out::address(&refused_first)?];
        if connected {
            endpoints.extend([first.local_addr()?, last.local_addr()?]);
        }
        endpoints.push(out::address(&refused_last)?);
        let (mut server, mut initiator) = out::start(&fixture, &endpoints, "")?;
        out::trigger(&mut initiator, "failure")?;
        if connected {
            fail_plain(&first, "identity")?;
            fail_sasl(&last, &fixture, "external_not_offered")?;
        }
        out::failure(
            &server,
            if connected {
                "external_not_offered"
            } else {
                "unreachable"
            },
        )?;
        close(&mut initiator)?;
        server.stop(Signal::SIGTERM)?;
        drop((refused_first, refused_last));
    }
    Ok(())
}

fn decimal_sample(body: &str, name: &str) -> Result<f64> {
    body.lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|value| value.strip_prefix(' '))
        })
        .ok_or_else(|| "missing histogram sample".into())
        .and_then(|value| Ok(value.parse()?))
}

#[test]
fn silent_endpoints_have_separate_deadlines_and_cleanup_is_bounded_and_excluded_from_auth_elapsed()
-> Result {
    let fixture = Fixture::new()?;
    let first = out::listener()?;
    let second = out::listener()?;
    let (mut server, mut initiator) = out::start(
        &fixture,
        &[first.local_addr()?, second.local_addr()?],
        "[limits.s2s]\nnegotiation_timeout_secs=1\n",
    )?;
    out::trigger(&mut initiator, "silent")?;
    let started = Instant::now();
    let mut first_peer = out::accept(&first)?;
    out::header(&mut first_peer)?;
    stream_error(&mut first_peer, "connection-timeout")?;
    let first_deadline = started.elapsed();
    assert!(first_deadline >= Duration::from_secs(1) && first_deadline < Duration::from_secs(3));
    assert_eq!(first_peer.read(&mut [0; 1])?, 0);
    assert!(started.elapsed() >= first_deadline + Duration::from_secs(4));
    assert!(started.elapsed() < first_deadline + Duration::from_secs(7));
    let mut second_peer = out::accept(&second)?;
    out::header(&mut second_peer)?;
    let second_started = Instant::now();
    stream_error(&mut second_peer, "connection-timeout")?;
    assert!(second_started.elapsed() >= Duration::from_millis(900));
    second_peer.write_all(FOOTER.as_bytes())?;
    assert_eq!(second_peer.read(&mut [0; 1])?, 0);
    out::failure(&server, "timeout")?;
    let body = metrics(&server)?;
    let measured = decimal_sample(
        &body,
        "lonewolf_s2s_negotiation_duration_seconds_sum{direction=\"outbound\"}",
    )?;
    assert!((2.0..4.0).contains(&measured), "{measured}: {body}");
    close(&mut initiator)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn genuine_network_shutdown_interrupts_tls_cleanup_backoff_and_established_output() -> Result {
    for phase in ["tls", "cleanup", "backoff", "output"] {
        let fixture = Fixture::new()?;
        let listener = out::listener()?;
        let (mut server, mut initiator) = out::start(&fixture, &[listener.local_addr()?], "")?;
        out::trigger(&mut initiator, "shutdown")?;
        if phase == "backoff" {
            fail_plain(&listener, "no_tls")?;
            out::failure(&server, "no_tls")?;
            drop(initiator);
            out::shutdown(&mut server)?;
            continue;
        }
        let mut stream = out::accept(&listener)?;
        if phase == "cleanup" {
            out::header(&mut stream)?;
            stream.write_all(format!("{}<stream:features/>", out::RESPONSE).as_bytes())?;
            stream_error(&mut stream, "policy-violation")?;
            drop(initiator);
            out::shutdown(&mut server)?;
            assert_eq!(stream.read(&mut [0; 1])?, 0);
        } else if phase == "tls" {
            out::starttls(&mut stream)?;
            let mut byte = [0; 1];
            stream.read_exact(&mut byte)?;
            assert_eq!(byte[0], 0x16);
            drop(initiator);
            out::shutdown(&mut server)?;
            out::abort_seen(&mut stream)?;
        } else {
            out::starttls(&mut stream)?;
            let mut peer = out::tls(
                stream,
                out::config(&fixture, "peer.test", false, false)?,
                &fixture,
            )?;
            out::auth(&mut peer)?;
            out::ready(&mut peer)?;
            out::reply(&mut peer, "shutdown")?;
            let payload = "x".repeat(32_000);
            for index in 0..16 {
                initiator.write_all(format!("<message from='a@peer.test' to='local.test' id='bulk{index}'><body>{payload}</body></message>").as_bytes())?;
            }
            initiator.flush()?;
            wait_sample(
                &server,
                "lonewolf_s2s_stanzas_received_total{kind=\"message\"}",
                17,
            )?;
            let mut first_byte = [0; 1];
            peer.read_exact(&mut first_byte)?;
            assert_eq!(first_byte[0], b'<');
            drop(initiator);
            std::thread::scope(|scope| -> Result {
                let receiver = scope.spawn(move || -> std::result::Result<(), String> {
                    let mut received = vec![first_byte[0]];
                    let mut byte = [0; 1];
                    loop {
                        match peer.read(&mut byte) {
                            Ok(0) => break,
                            Ok(_) => received.push(byte[0]),
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::UnexpectedEof
                                        | std::io::ErrorKind::ConnectionReset
                                ) =>
                            {
                                break;
                            }
                            Err(error) => return Err(error.to_string()),
                        }
                        if received.ends_with(FOOTER.as_bytes()) {
                            peer.write_all(FOOTER.as_bytes())
                                .map_err(|error| error.to_string())?;
                            peer.conn.send_close_notify();
                            peer.flush().map_err(|error| error.to_string())?;
                            assert_eq!(peer.read(&mut byte).map_err(|error| error.to_string())?, 0);
                            break;
                        }
                        assert!(received.len() <= 1_048_576);
                    }
                    assert!(!received.is_empty());
                    Ok(())
                });
                out::shutdown(&mut server)?;
                receiver
                    .join()
                    .map_err(|_| "receiver panicked")?
                    .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
                Ok(())
            })?;
        }
    }
    Ok(())
}

#[test]
fn outgoing_certificate_expiry_resets_the_stream_and_new_input_reestablishes() -> Result {
    let fixture = Fixture::new()?;
    let listener = out::listener()?;
    let (mut server, mut initiator) = out::start(&fixture, &[listener.local_addr()?], "")?;
    let expiry = time::OffsetDateTime::now_utc() + time::Duration::seconds(4);
    let config = out::expiring_config(&fixture, expiry)?;
    out::trigger(&mut initiator, "before")?;
    let mut first = out::establish(&listener, config, &fixture)?;
    out::reply(&mut first, "before")?;
    finish_receiving_error(&mut first, "reset")?;
    assert!(time::OffsetDateTime::now_utc().unix_timestamp() >= expiry.unix_timestamp());
    wait_sample(
        &server,
        "lonewolf_s2s_streams_closed_total{direction=\"outbound\",outcome=\"certificate_expired\"}",
        1,
    )?;
    out::wait_zero(&server)?;
    out::trigger(&mut initiator, "after")?;
    let mut second = out::establish(
        &listener,
        out::config(&fixture, "peer.test", false, false)?,
        &fixture,
    )?;
    out::reply(&mut second, "after")?;
    wait_sample(&server, &out::outbound_auth("success"), 2)?;
    out::close(&mut second)?;
    out::wait_zero(&server)?;
    close(&mut initiator)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn authenticated_oversize_and_malformed_xml_keep_the_exact_wire_error_and_one_protocol_close()
-> Result {
    for (xml, condition) in [
        (
            format!(
                "<message from='a@peer.test' to='b@local.test'><body>{}</body></message>",
                "x".repeat(10_100)
            ),
            "policy-violation",
        ),
        (
            "<message from='a@peer.test' to='b@local.test'><body></message>".to_owned(),
            "not-well-formed",
        ),
    ] {
        let fixture = Fixture::new()?;
        let (mut server, address) = fixture.server("[limits.s2s]\nmax_stanza_bytes=10000\n")?;
        let mut peer = authenticated(&fixture, address)?;
        peer.write_all(xml.as_bytes())?;
        peer.flush()?;
        let response = until(&mut peer, FOOTER)?;
        assert_eq!(
            response,
            format!(
                "<stream:error><{condition} xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>{FOOTER}"
            )
        );
        assert_eq!(peer.read(&mut [0; 1])?, 0);
        wait_sample(
            &server,
            "lonewolf_s2s_streams_closed_total{direction=\"inbound\",outcome=\"protocol_error\"}",
            1,
        )?;
        wait_sample(
            &server,
            "lonewolf_s2s_connections{direction=\"inbound\"}",
            0,
        )?;
        wait_sample(&server, "lonewolf_s2s_streams{direction=\"inbound\"}", 0)?;
        let body = metrics(&server)?;
        let closes = body
            .lines()
            .filter(|line| {
                line.starts_with("lonewolf_s2s_streams_closed_total{direction=\"inbound\"")
            })
            .try_fold(0usize, |total, line| -> Result<usize> {
                Ok(total
                    + line
                        .rsplit_once(' ')
                        .ok_or("close sample")?
                        .1
                        .parse::<usize>()?)
            })?;
        assert_eq!(closes, 1);
        server.stop(Signal::SIGTERM)?;
    }
    Ok(())
}
