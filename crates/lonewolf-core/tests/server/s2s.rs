// SPDX-License-Identifier: Apache-2.0

#[path = "support/c2s_outbound.rs"]
mod c2s_outbound;
#[path = "support/s2s_outbound.rs"]
mod outbound;
#[path = "support/process.rs"]
mod process;
mod s2s_c2s;
mod s2s_cases;
#[path = "support/s2s.rs"]
mod support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use nix::sys::signal::Signal;
use process::{Server, TIMEOUT};
use support::*;

#[test]
fn inbound_external_success_orders_elements_and_rotates_stream_ids() -> Result {
    let fixture = Fixture::new()?;
    let (mut server, address) = fixture.server("")?;
    let mut received = 0;
    let mut sent = 0;
    for auth in [
        AUTH.to_owned(),
        format!(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>{}</auth>",
            STANDARD.encode("PEER.TEST")
        ),
    ] {
        let (mut peer, first) = start_tls(address, fixture.client(Some("peer.test"), false)?)?;
        let second = external(&mut peer, HEADER)?;
        let third = success(&mut peer, &auth)?;
        received += 2 * HEADER.len() + auth.len() + FOOTER.len();
        sent += second.len() + third.len() + FOOTER.len()
            + "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>".len()
            + "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>".len()
            + "<stream:features/>".len();
        assert_ne!(id(&first)?, id(&second)?);
        assert_ne!(id(&second)?, id(&third)?);
        assert_ne!(id(&first)?, id(&third)?);
        close(&mut peer)?;
    }
    wait_sample(&server, &auth_sample("success"), 2)?;
    wait_sample(
        &server,
        "lonewolf_s2s_received_bytes_total{direction=\"inbound\"}",
        received,
    )?;
    wait_sample(
        &server,
        "lonewolf_s2s_sent_bytes_total{direction=\"inbound\"}",
        sent,
    )?;
    wait_sample(
        &server,
        "lonewolf_s2s_connections{direction=\"inbound\"}",
        0,
    )?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn unknown_host_and_plaintext_stanzas_are_rejected_before_tls() -> Result {
    let fixture = Fixture::new()?;
    let (mut server, address) = fixture.server("")?;
    let mut peer = connect(address)?;
    peer.write_all(HEADER.replace("local.test", "unknown.test").as_bytes())?;
    let header = until(&mut peer, "<stream:stream")? + &until(&mut peer, ">")?;
    assert!(header.contains(" from='local.test'"));
    stream_error(&mut peer, "host-unknown")?;
    peer.write_all(FOOTER.as_bytes())?;
    assert_eq!(peer.read(&mut [0])?, 0);
    wait_sample(&server, &auth_sample("host_unknown"), 1)?;
    let mut peer = connect(address)?;
    peer.write_all(HEADER.as_bytes())?;
    response_header(&mut peer)?;
    until(&mut peer, "</stream:features>")?;
    peer.write_all(b"<message/>")?;
    stream_error(&mut peer, "not-authorized")?;
    peer.write_all(FOOTER.as_bytes())?;
    assert_eq!(peer.read(&mut [0])?, 0);
    wait_sample(&server, &auth_sample("protocol"), 1)?;
    let body = metrics(&server)?;
    assert!(
        !body.contains("lonewolf_s2s_received_bytes_total{"),
        "{body}"
    );
    assert!(!body.contains("lonewolf_s2s_sent_bytes_total{"), "{body}");
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn post_tls_headers_and_certificates_gate_external_advertisement() -> Result {
    let fixture = Fixture::new()?;
    let (mut server, address) = fixture.server("")?;
    for (identity, header, condition, outcome) in [
        (
            Some("peer.test"),
            HEADER.replace(" from='peer.test'", ""),
            "not-authorized",
            "missing_from",
        ),
        (
            Some("peer.test"),
            HEADER.replace("peer.test", "local.test"),
            "invalid-from",
            "invalid_from",
        ),
        (None, HEADER.to_owned(), "not-authorized", "no_certificate"),
        (
            Some("another.test"),
            HEADER.to_owned(),
            "not-authorized",
            "certificate_name",
        ),
        (
            Some("peer.test"),
            HEADER.replace("local.test", "unknown.test"),
            "host-unknown",
            "host_unknown",
        ),
    ] {
        let (mut peer, _) = start_tls(address, fixture.client(identity, false)?)?;
        peer.write_all(header.as_bytes())?;
        let error = until(&mut peer, FOOTER)?;
        assert!(error.contains(&format!("<{condition}")), "{error}");
        assert!(!error.contains("EXTERNAL"));
        peer.write_all(FOOTER.as_bytes())?;
        peer.conn.send_close_notify();
        peer.flush()?;
        assert_eq!(peer.read(&mut [0])?, 0);
        wait_sample(&server, &auth_sample(outcome), 1)?;
    }
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn client_auth_only_certificate_fails_the_tls_handshake() -> Result {
    let fixture = Fixture::new()?;
    let (mut server, address) = fixture.server("")?;
    match start_tls(address, fixture.client(Some("peer.test"), true)?) {
        Err(_) => {}
        Ok((mut peer, _)) => {
            let _ = peer.write_all(HEADER.as_bytes());
            assert!(peer.read(&mut [0]).is_err());
        }
    }
    wait_sample(&server, &auth_sample("tls_failure"), 1)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn external_empty_challenge_abort_and_two_attempt_limit() -> Result {
    let fixture = Fixture::new()?;
    let (mut server, address) = fixture.server("")?;
    let (mut peer, _) = start_tls(address, fixture.client(Some("peer.test"), false)?)?;
    external(&mut peer, HEADER)?;
    peer.write_all(b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'/>")?;
    assert_eq!(
        until(&mut peer, "/>")?,
        "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"
    );
    let _ = success(
        &mut peer,
        "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>=</response>",
    )?;
    close(&mut peer)?;
    for (first, second, outcome) in [
        (
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>b3RoZXIudGVzdA==</auth>",
            "invalid-authzid",
            "invalid_authzid",
        ),
        (
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>=</auth>",
            "invalid-mechanism",
            "invalid_mechanism",
        ),
    ] {
        let (mut peer, _) = start_tls(address, fixture.client(Some("peer.test"), false)?)?;
        external(&mut peer, HEADER)?;
        peer.write_all(first.as_bytes())?;
        assert!(until(&mut peer, "</failure>")?.contains(second));
        peer.write_all(first.as_bytes())?;
        assert!(until(&mut peer, "</failure>")?.contains(second));
        assert_eq!(until(&mut peer, FOOTER)?, FOOTER);
        peer.write_all(FOOTER.as_bytes())?;
        assert_eq!(peer.read(&mut [0])?, 0);
        wait_sample(&server, &auth_sample(outcome), 1)?;
    }
    let (mut peer, _) = start_tls(address, fixture.client(Some("peer.test"), false)?)?;
    external(&mut peer, HEADER)?;
    peer.write_all(b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'/>")?;
    until(&mut peer, "/>")?;
    peer.write_all(b"<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    assert!(until(&mut peer, "</failure>")?.contains("<aborted/>"));
    success(&mut peer, AUTH)?;
    close(&mut peer)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn final_restart_cannot_change_the_authenticated_domain_pair() -> Result {
    let fixture = Fixture::new()?;
    let (mut server, address) = fixture.server("")?;
    for (header, condition) in [
        (HEADER.replace("peer.test", "other.test"), "invalid-from"),
        (HEADER.replace("local.test", "other.test"), "host-unknown"),
    ] {
        let (mut peer, _) = start_tls(address, fixture.client(Some("peer.test"), false)?)?;
        external(&mut peer, HEADER)?;
        peer.write_all(AUTH.as_bytes())?;
        until(&mut peer, "/>")?;
        peer.write_all(header.as_bytes())?;
        stream_error(&mut peer, condition)?;
        peer.write_all(FOOTER.as_bytes())?;
        assert_eq!(peer.read(&mut [0])?, 0);
    }
    wait_sample(&server, &auth_sample("invalid_from"), 2)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn negotiation_deadline_closes_with_timeout_and_records_once() -> Result {
    let fixture = Fixture::new()?;
    let (mut server, address) = fixture.server("[limits.s2s]\nnegotiation_timeout_secs=1\n")?;
    let mut peer = connect(address)?;
    peer.write_all(HEADER.as_bytes())?;
    response_header(&mut peer)?;
    until(&mut peer, "</stream:features>")?;
    stream_error(&mut peer, "connection-timeout")?;
    peer.write_all(FOOTER.as_bytes())?;
    assert_eq!(peer.read(&mut [0])?, 0);
    wait_sample(&server, &auth_sample("timeout"), 1)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn admission_rejects_without_xml_and_keeps_lifetime_gauges() -> Result {
    let fixture = Fixture::new()?;
    let (mut server, address) = fixture.server("[limits.s2s]\nmax_inbound_connections=1\n")?;
    let (mut peer, _) = start_tls(address, fixture.client(Some("peer.test"), false)?)?;
    external(&mut peer, HEADER)?;
    success(&mut peer, AUTH)?;
    wait_sample(
        &server,
        "lonewolf_s2s_connections{direction=\"inbound\"}",
        1,
    )?;
    let mut refused = connect(address)?;
    assert_eq!(refused.read(&mut [0])?, 0);
    wait_sample(
        &server,
        "lonewolf_s2s_connections_rejected_total{listener=\"0\",reason=\"max_inbound_connections\"}",
        1,
    )?;
    close(&mut peer)?;
    wait_sample(
        &server,
        "lonewolf_s2s_connections{direction=\"inbound\"}",
        0,
    )?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn inactive_federation_omits_listeners_and_metrics_and_keeps_c2s() -> Result {
    let mut server = Server::start(
        "[[c2s.listeners]]\naddress='127.0.0.1:0'\n[metrics]\nenabled=true\naddress='127.0.0.1:0'\n",
        1,
    )?;
    let c2s = server.ready()?;
    assert!(!metrics(&server)?.contains("lonewolf_s2s_"));
    let mut peer = connect(c2s[0])?;
    peer.write_all(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0'>")?;
    assert!(until(&mut peer, "</stream:features>")?.contains("<required/>"));
    drop(peer);
    server.stop(Signal::SIGTERM)?;
    let fixture = Fixture::new()?;
    let mut server = Server::start(&format!("{}[s2s]\nenabled=false\n", fixture.config), 1)?;
    server.ready()?;
    assert!(!metrics(&server)?.contains("lonewolf_s2s_"));
    server.stop(Signal::SIGTERM)?;
    let mut server = Server::start(
        &format!("{}[hosts.'local.test']\nfederation=false\n", fixture.config),
        1,
    )?;
    server.ready()?;
    assert!(!metrics(&server)?.contains("lonewolf_s2s_"));
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn shutdown_interrupts_plaintext_tls_and_authenticated_streams() -> Result {
    let fixture = Fixture::new()?;
    for phase in 0..3 {
        let (mut server, address) = fixture.server("")?;
        let (mut peer, _) = start_tls(address, fixture.client(Some("peer.test"), false)?)?;
        external(&mut peer, HEADER)?;
        if phase == 1 {
            peer.write_all(
                b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'/>",
            )?;
            assert_eq!(
                until(&mut peer, "/>")?,
                "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"
            );
        }
        if phase == 2 {
            success(&mut peer, AUTH)?;
        }
        let peer_task = std::thread::spawn(move || -> std::result::Result<(), String> {
            stream_error(&mut peer, "system-shutdown").map_err(|error| error.to_string())?;
            peer.write_all(FOOTER.as_bytes())
                .map_err(|error| error.to_string())?;
            peer.conn.send_close_notify();
            peer.flush().map_err(|error| error.to_string())?;
            if peer.read(&mut [0]).map_err(|error| error.to_string())? != 0 {
                return Err("missing TLS close".into());
            }
            Ok(())
        });
        let started = Instant::now();
        server.stop(Signal::SIGTERM)?;
        peer_task.join().map_err(|_| "peer task panicked")??;
        assert!(started.elapsed() < TIMEOUT);
    }
    let (mut server, address) = fixture.server("")?;
    let mut peer = connect(address)?;
    peer.write_all(HEADER.as_bytes())?;
    response_header(&mut peer)?;
    until(&mut peer, "</stream:features>")?;
    peer.write_all(STARTTLS.as_bytes())?;
    assert_eq!(
        until(&mut peer, "/>")?,
        "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    );
    server.stop(Signal::SIGTERM)?;
    assert_eq!(peer.read(&mut [0])?, 0);
    let (mut server, address) = fixture.server("")?;
    let mut peer = connect(address)?;
    peer.write_all(HEADER.as_bytes())?;
    response_header(&mut peer)?;
    until(&mut peer, "</stream:features>")?;
    let peer_task = std::thread::spawn(move || -> std::result::Result<(), String> {
        stream_error(&mut peer, "system-shutdown").map_err(|error| error.to_string())?;
        peer.write_all(FOOTER.as_bytes())
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    server.stop(Signal::SIGTERM)?;
    peer_task.join().map_err(|_| "peer task panicked")??;
    Ok(())
}

#[test]
fn occupied_s2s_listener_fails_startup_and_releases_c2s() -> Result {
    let fixture = Fixture::new()?;
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut server = Server::start(
        &fixture.config.replace(
            "[[s2s.listeners]]\naddress='127.0.0.1:0'",
            &format!("[[s2s.listeners]]\naddress='{}'", occupied.local_addr()?),
        ),
        2,
    )?;
    assert_eq!(server.wait()?.code(), Some(1));
    Ok(())
}

#[test]
fn closing_wait_is_bounded_and_sends_tls_close_notify_without_peer_footer() -> Result {
    let fixture = Fixture::new()?;
    let (mut server, address) = fixture.server("")?;
    let (mut peer, _) = start_tls(address, fixture.client(Some("wrong.test"), false)?)?;
    peer.write_all(HEADER.as_bytes())?;
    stream_error(&mut peer, "not-authorized")?;
    let started = Instant::now();
    assert_eq!(peer.read(&mut [0])?, 0);
    assert!(started.elapsed() < TIMEOUT);
    wait_sample(&server, &auth_sample("certificate_name"), 1)?;
    wait_sample(
        &server,
        "lonewolf_s2s_connections{direction=\"inbound\"}",
        0,
    )?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}
