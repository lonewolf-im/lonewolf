// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::net::UdpSocket;

use nix::sys::signal::Signal;

use super::{c2s_outbound as client, outbound as out, process::TIMEOUT, support::*};

fn sent(kind: &str, target: &str, id: &str) -> String {
    match kind {
        "get" | "set" | "result" | "iq-error" => {
            let error = if kind == "iq-error" {
                "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
            } else {
                ""
            };
            let kind = if kind == "iq-error" { "error" } else { kind };
            format!(
                "<iq type='{kind}' to='{target}' from='mallory@third.test/spy' id='{id}'><query xmlns='urn:test'/>{error}</iq>"
            )
        }
        _ => {
            let error = if kind == "error" {
                "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
            } else {
                ""
            };
            format!(
                "<message type='{kind}' to='{target}' from='mallory@third.test/spy' id='{id}'><body>payload</body>{error}</message>"
            )
        }
    }
}

fn bounce(peer: &mut Peer, name: &str, id: &str, condition: &str) -> Result {
    let stanza = client::stanza(peer, name)?;
    assert_eq!(
        (stanza.namespace.as_str(), stanza.name.as_str()),
        ("jabber:client", name)
    );
    for (key, value) in [
        ("type", "error"),
        ("from", "bob@peer.test/phone"),
        ("to", "alice@local.test/desk"),
        ("id", id),
    ] {
        assert_eq!(
            stanza.attributes.get(key).map(String::as_str),
            Some(value),
            "{stanza:?}"
        );
    }
    let error = stanza.child("jabber:client", "error")?;
    error.child("urn:ietf:params:xml:ns:xmpp-stanzas", condition)?;
    assert!(
        !error
            .child("urn:ietf:params:xml:ns:xmpp-stanzas", "text")?
            .text
            .is_empty()
    );
    Ok(())
}

#[test]
fn c2s_messages_and_all_iq_types_reach_authenticated_remote_peer() -> Result {
    let fixture = Fixture::new()?;
    let listener = out::listener()?;
    let extra = format!("[s2s.routes]\n'peer.test'=['{}']\n", listener.local_addr()?);
    let config = out::config(&fixture, "peer.test", false, false)?;
    let (mut server, mut sender) = client::start(&fixture, &extra)?;
    sender.write_all(sent("chat", "bob@peer.test/phone", "first").as_bytes())?;
    sender.flush()?;
    let mut receiving = out::establish(&listener, config, &fixture)?;
    let first = client::element(&until(&mut receiving, "</message>")?)?;
    assert_eq!(
        first.attributes.get("id").map(String::as_str),
        Some("first")
    );
    for kind in [
        "chat", "headline", "error", "get", "set", "result", "iq-error",
    ] {
        for target in ["bob@peer.test", "bob@peer.test/phone"] {
            let name = if matches!(kind, "get" | "set" | "result" | "iq-error") {
                "iq"
            } else {
                "message"
            };
            let id = format!(
                "{kind}-{}",
                if target.ends_with("phone") {
                    "full"
                } else {
                    "bare"
                }
            );
            sender.write_all(sent(kind, target, &id).as_bytes())?;
            sender.flush()?;
            let stanza = client::element(&until(&mut receiving, &format!("</{name}>"))?)?;
            assert_eq!(
                (stanza.namespace.as_str(), stanza.name.as_str()),
                ("jabber:server", name)
            );
            for (key, value) in [
                ("id", id.as_str()),
                ("to", target),
                ("from", "alice@local.test/desk"),
                ("type", if kind == "iq-error" { "error" } else { kind }),
            ] {
                assert_eq!(
                    stanza.attributes.get(key).map(String::as_str),
                    Some(value),
                    "{stanza:?}"
                );
            }
        }
    }
    client::barrier(&mut sender)?;
    wait_sample(&server, &out::outbound_auth("success"), 1)?;
    wait_sample(
        &server,
        "lonewolf_s2s_stanzas_sent_total{kind=\"message\"}",
        7,
    )?;
    wait_sample(&server, "lonewolf_s2s_stanzas_sent_total{kind=\"iq\"}", 8)?;
    wait_sample(&server, "lonewolf_s2s_outbound_queued_stanzas", 0)?;
    client::close(&mut sender)?;
    out::close(&mut receiving)?;
    out::wait_zero(&server)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

fn inbound_peer(fixture: &Fixture, address: std::net::SocketAddr) -> Result<Peer> {
    let (mut peer, _) = start_tls(address, fixture.client(Some("peer.test"), false)?)?;
    external(&mut peer, HEADER)?;
    success(&mut peer, AUTH)?;
    Ok(peer)
}

fn inbound_message(stanza: &client::Element, namespace: &str, target: &str, id: &str) -> Result {
    assert_eq!(
        (stanza.namespace.as_str(), stanza.name.as_str()),
        (namespace, "message")
    );
    for (key, value) in [
        ("from", "bob@peer.test/phone"),
        ("to", target),
        ("id", id),
        ("type", "chat"),
    ] {
        assert_eq!(
            stanza.attributes.get(key).map(String::as_str),
            Some(value),
            "{stanza:?}"
        );
    }
    assert_eq!(stanza.child(namespace, "body")?.text, "inbound payload");
    Ok(())
}

#[test]
fn inbound_chat_reaches_available_bare_and_full_clients_and_errors_use_outbound_stream() -> Result {
    let fixture = Fixture::new()?;
    let listener = out::listener()?;
    let extra = format!("[s2s.routes]\n'peer.test'=['{}']\n", listener.local_addr()?);
    let (mut server, mut receiver, _, s2s) = client::start_inbound(&fixture, &extra)?;
    receiver.write_all(b"<presence><status>Ready</status></presence>")?;
    receiver.flush()?;
    let presence = client::stanza(&mut receiver, "presence")?;
    assert_eq!(
        presence.attributes.get("from").map(String::as_str),
        Some("alice@local.test/desk")
    );
    client::barrier(&mut receiver)?;
    let mut incoming = inbound_peer(&fixture, s2s)?;
    for (target, id) in [
        ("alice@local.test", "bare"),
        ("alice@local.test/desk", "full"),
    ] {
        write!(
            incoming,
            "<message type='chat' from='bob@peer.test/phone' to='{target}' id='{id}'><body>inbound payload</body></message>"
        )?;
        incoming.flush()?;
        inbound_message(
            &client::stanza(&mut receiver, "message")?,
            "jabber:client",
            target,
            id,
        )?;
    }
    incoming.write_all(b"<message type='groupchat' from='bob@peer.test/phone' to='alice@local.test' id='groupchat'><body>inbound payload</body></message>")?;
    incoming.flush()?;
    let mut outgoing = out::establish(
        &listener,
        out::config(&fixture, "peer.test", false, false)?,
        &fixture,
    )?;
    let reply = client::element(&until(&mut outgoing, "</message>")?)?;
    assert_eq!(
        (reply.namespace.as_str(), reply.name.as_str()),
        ("jabber:server", "message")
    );
    for (key, value) in [
        ("from", "alice@local.test"),
        ("to", "bob@peer.test/phone"),
        ("id", "groupchat"),
        ("type", "error"),
    ] {
        assert_eq!(
            reply.attributes.get(key).map(String::as_str),
            Some(value),
            "{reply:?}"
        );
    }
    assert_eq!(
        reply.child("jabber:server", "body")?.text,
        "inbound payload"
    );
    reply
        .child("jabber:server", "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
    close(&mut incoming)?;
    client::close(&mut receiver)?;
    out::close(&mut outgoing)?;
    out::wait_zero(&server)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn inbound_offline_message_replays_after_same_stream_dispatch_barrier_and_availability() -> Result {
    eprintln!("offline.fixture.enter");
    let fixture = Fixture::new()?;
    eprintln!("offline.fixture.complete");
    eprintln!("offline.listener.enter");
    let listener = out::listener()?;
    eprintln!("offline.listener.complete");
    let extra = format!(
        "[s2s.routes]\n'peer.test'=['{}']\n[hosts.'local.test']\nextensions=['offline']\n",
        listener.local_addr()?
    );
    eprintln!("offline.initial_client.enter");
    let (mut server, mut initial, c2s, s2s) = client::start_inbound(&fixture, &extra)?;
    eprintln!("offline.initial_client.complete");
    eprintln!("offline.initial_close.enter");
    client::close(&mut initial)?;
    eprintln!("offline.initial_close.complete");
    eprintln!("offline.inbound_auth.enter");
    let mut incoming = inbound_peer(&fixture, s2s)?;
    eprintln!("offline.inbound_auth.complete");
    eprintln!("offline.store_barrier_send.enter");
    incoming.write_all(b"<message type='chat' from='bob@peer.test/phone' to='alice@local.test' id='offline'><body>inbound payload</body></message><message type='groupchat' from='bob@peer.test/phone' to='alice@local.test' id='stored-barrier'><body>barrier</body></message>")?;
    incoming.flush()?;
    eprintln!("offline.store_barrier_send.complete");
    eprintln!("offline.outbound_establish.enter");
    let mut outgoing = out::establish(
        &listener,
        out::config(&fixture, "peer.test", false, false)?,
        &fixture,
    )?;
    eprintln!("offline.outbound_establish.complete");
    eprintln!("offline.barrier_read.enter");
    let barrier = client::element(&until(&mut outgoing, "</message>")?)?;
    eprintln!("offline.barrier_read.complete");
    assert_eq!(barrier.namespace, "jabber:server");
    for (key, value) in [
        ("from", "alice@local.test"),
        ("to", "bob@peer.test/phone"),
        ("id", "stored-barrier"),
        ("type", "error"),
    ] {
        assert_eq!(
            barrier.attributes.get(key).map(String::as_str),
            Some(value),
            "{barrier:?}"
        );
    }
    barrier
        .child("jabber:server", "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
    eprintln!("offline.reconnect.enter");
    let mut receiver = client::client(&fixture, c2s)?;
    eprintln!("offline.reconnect.complete");
    eprintln!("offline.availability_send.enter");
    receiver.write_all(b"<presence><status>Ready</status></presence>")?;
    receiver.flush()?;
    eprintln!("offline.availability_send.complete");
    eprintln!("offline.presence_read.enter");
    let presence = client::stanza(&mut receiver, "presence")?;
    eprintln!("offline.presence_read.complete");
    assert_eq!(
        presence.attributes.get("from").map(String::as_str),
        Some("alice@local.test/desk")
    );
    eprintln!("offline.replay_read.enter");
    let replay = client::stanza(&mut receiver, "message")?;
    eprintln!("offline.replay_read.complete");
    inbound_message(&replay, "jabber:client", "alice@local.test", "offline")?;
    replay.child("urn:xmpp:delay", "delay")?;
    eprintln!("offline.client_barrier.enter");
    client::barrier(&mut receiver)?;
    eprintln!("offline.client_barrier.complete");
    eprintln!("offline.inbound_close.enter");
    close(&mut incoming)?;
    eprintln!("offline.inbound_close.complete");
    eprintln!("offline.client_close.enter");
    client::close(&mut receiver)?;
    eprintln!("offline.client_close.complete");
    eprintln!("offline.outbound_close.enter");
    out::close(&mut outgoing)?;
    eprintln!("offline.outbound_close.complete");
    eprintln!("offline.outbound_zero.enter");
    out::wait_zero(&server)?;
    eprintln!("offline.outbound_zero.complete");
    eprintln!("offline.server_stop.enter");
    server.stop(Signal::SIGTERM)?;
    eprintln!("offline.server_stop.complete");
    Ok(())
}

fn dns_not_found(socket: &UdpSocket) -> std::io::Result<()> {
    for _ in 0..3 {
        let mut packet = [0; 4096];
        let (length, peer) = socket.recv_from(&mut packet)?;
        if length < 17 {
            return Err(std::io::Error::other("truncated DNS query"));
        }
        let mut end = 12;
        while packet[end] != 0 {
            end += usize::from(packet[end]) + 1;
            if end + 5 > length {
                return Err(std::io::Error::other("invalid DNS question"));
            }
        }
        end += 5;
        packet[2..4].copy_from_slice(&0x8183_u16.to_be_bytes());
        packet[6..12].fill(0);
        socket.send_to(&packet[..end], peer)?;
    }
    Ok(())
}

#[test]
fn c2s_chat_iq_and_headline_establishment_failures_bounce_to_sending_resource() -> Result {
    for mode in ["dns", "connection", "tls", "sasl", "timeout"] {
        for kind in ["chat", "get", "headline"] {
            let fixture = Fixture::new()?;
            let listener = out::listener()?;
            let refused = if mode == "connection" {
                Some(out::refused()?)
            } else {
                None
            };
            let dns = UdpSocket::bind("127.0.0.1:0")?;
            dns.set_read_timeout(Some(TIMEOUT))?;
            let endpoint = match &refused {
                Some(endpoint) => out::address(endpoint)?,
                None => listener.local_addr()?,
            };
            let extra = if mode == "dns" {
                format!("[s2s.dns]\nnameservers=['{}']\n", dns.local_addr()?)
            } else {
                format!(
                    "[s2s.routes]\n'peer.test'=['{endpoint}']\n[limits.s2s]\nnegotiation_timeout_secs=1\n"
                )
            };
            let (mut server, mut sender) = client::start(&fixture, &extra)?;
            let id = format!("{mode}-{kind}");
            sender.write_all(sent(kind, "bob@peer.test/phone", &id).as_bytes())?;
            sender.flush()?;
            let (condition, authentication) = match mode {
                "dns" => {
                    std::thread::scope(|scope| {
                        scope
                            .spawn(|| dns_not_found(&dns))
                            .join()
                            .map_err(|_| std::io::Error::other("DNS fixture panicked"))?
                    })?;
                    ("remote-server-not-found", None)
                }
                "connection" => ("remote-server-timeout", Some("unreachable")),
                "tls" => {
                    let mut stream = out::accept(&listener)?;
                    out::starttls(&mut stream)?;
                    let mut peer = rustls::StreamOwned::new(
                        rustls::ServerConnection::new(out::config(
                            &fixture,
                            "third.test",
                            false,
                            false,
                        )?)?,
                        stream,
                    );
                    assert!(peer.conn.complete_io(&mut peer.sock).is_err());
                    out::abort_seen(&mut peer.sock)?;
                    ("remote-server-timeout", Some("certificate_name"))
                }
                "sasl" => {
                    let mut stream = out::accept(&listener)?;
                    out::starttls(&mut stream)?;
                    let mut peer = out::tls(
                        stream,
                        out::config(&fixture, "peer.test", false, false)?,
                        &fixture,
                    )?;
                    out::auth(&mut peer)?;
                    peer.write_all(b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>")?;
                    peer.flush()?;
                    assert_eq!(until(&mut peer, FOOTER)?, FOOTER);
                    peer.write_all(FOOTER.as_bytes())?;
                    peer.conn.send_close_notify();
                    peer.flush()?;
                    assert_eq!(peer.read(&mut [0; 1])?, 0);
                    ("remote-server-timeout", Some("sasl_failure"))
                }
                _ => {
                    let mut stream = out::accept(&listener)?;
                    out::header(&mut stream)?;
                    let error = until(&mut stream, FOOTER)?;
                    assert!(error.contains("connection-timeout"), "{error}");
                    stream.write_all(FOOTER.as_bytes())?;
                    assert_eq!(stream.read(&mut [0; 1])?, 0);
                    ("remote-server-timeout", Some("timeout"))
                }
            };
            bounce(
                &mut sender,
                if kind == "get" { "iq" } else { "message" },
                &id,
                condition,
            )?;
            wait_sample(
                &server,
                &format!(
                    "lonewolf_s2s_bounces_total{{condition=\"{}\"}}",
                    condition.replace('-', "_")
                ),
                1,
            )?;
            wait_sample(&server, "lonewolf_s2s_outbound_queued_stanzas", 0)?;
            wait_sample(&server, "lonewolf_s2s_outbound_queued_bytes", 0)?;
            if let Some(authentication) = authentication {
                out::failure(&server, authentication)?;
            } else {
                wait_sample(
                    &server,
                    "lonewolf_s2s_dns_resolutions_total{outcome=\"not_found\"}",
                    1,
                )?;
                assert_eq!(out::authentication_total(&metrics(&server)?)?, 0);
                out::wait_zero(&server)?;
            }
            let body = metrics(&server)?;
            let bounces = body
                .lines()
                .filter(|line| line.starts_with("lonewolf_s2s_bounces_total{"))
                .try_fold(0_u64, |total, line| -> Result<u64> {
                    Ok(total
                        + line
                            .rsplit_once(' ')
                            .ok_or("bounce sample")?
                            .1
                            .parse::<u64>()?)
                })?;
            assert_eq!(bounces, 1, "{mode} {kind}");
            assert_eq!(
                sample(&body, "lonewolf_s2s_outbound_links{state=\"backoff\"}")?,
                1
            );
            client::barrier(&mut sender)?;
            client::close(&mut sender)?;
            server.stop(Signal::SIGTERM)?;
            drop(refused);
        }
    }
    Ok(())
}

#[test]
fn c2s_queued_error_messages_and_iq_responses_never_bounce() -> Result {
    let fixture = Fixture::new()?;
    let listener = out::listener()?;
    let extra = format!("[s2s.routes]\n'peer.test'=['{}']\n", listener.local_addr()?);
    let (mut server, mut sender) = client::start(&fixture, &extra)?;
    for kind in ["error", "result", "iq-error", "headline"] {
        sender.write_all(sent(kind, "bob@peer.test/phone", kind).as_bytes())?;
    }
    sender.flush()?;
    let mut stream = out::accept(&listener)?;
    out::starttls(&mut stream)?;
    let mut receiving = out::tls(
        stream,
        out::config(&fixture, "peer.test", false, false)?,
        &fixture,
    )?;
    out::auth(&mut receiving)?;
    client::barrier(&mut sender)?;
    wait_sample(&server, "lonewolf_s2s_outbound_queued_stanzas", 4)?;
    receiving.write_all(
        b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
    )?;
    receiving.flush()?;
    assert_eq!(until(&mut receiving, FOOTER)?, FOOTER);
    receiving.write_all(FOOTER.as_bytes())?;
    receiving.conn.send_close_notify();
    receiving.flush()?;
    assert_eq!(receiving.read(&mut [0; 1])?, 0);
    bounce(&mut sender, "message", "headline", "remote-server-timeout")?;
    wait_sample(
        &server,
        "lonewolf_s2s_dropped_stanzas_total{reason=\"not_bounceable\"}",
        3,
    )?;
    wait_sample(
        &server,
        "lonewolf_s2s_bounces_total{condition=\"remote_server_timeout\"}",
        1,
    )?;
    wait_sample(&server, "lonewolf_s2s_outbound_queued_stanzas", 0)?;
    wait_sample(&server, "lonewolf_s2s_outbound_queued_bytes", 0)?;
    out::failure(&server, "sasl_failure")?;
    client::barrier(&mut sender)?;
    client::close(&mut sender)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

fn remote_presence(peer: &mut impl Read, kind: Option<&str>, id: Option<&str>) -> Result {
    let mut xml = until(peer, ">")?;
    if !xml.ends_with("/>") {
        xml.push_str(&until(peer, "</presence>")?);
    }
    let stanza = client::element(&xml)?;
    assert_eq!(
        (stanza.namespace.as_str(), stanza.name.as_str()),
        ("jabber:server", "presence")
    );
    assert_eq!(
        stanza.attributes.get("from").map(String::as_str),
        Some("alice@local.test/desk")
    );
    assert_eq!(
        stanza.attributes.get("to").map(String::as_str),
        Some("bob@peer.test/phone")
    );
    assert_eq!(stanza.attributes.get("type").map(String::as_str), kind);
    assert_eq!(stanza.attributes.get("id").map(String::as_str), id);
    if kind == Some("error") {
        stanza
            .child("jabber:server", "error")?
            .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
    }
    Ok(())
}

#[test]
fn c2s_directed_presence_probes_errors_and_withdrawals_reach_authenticated_peer() -> Result {
    let fixture = Fixture::new()?;
    let listener = out::listener()?;
    let extra = format!("[s2s.routes]\n'peer.test'=['{}']\n", listener.local_addr()?);
    let config = out::config(&fixture, "peer.test", false, false)?;
    let (mut server, mut sender) = client::start(&fixture, &extra)?;
    sender.write_all(b"<presence to='bob@peer.test/phone' from='mallory@third.test/spy' id='available'><status>Ready</status></presence>")?;
    sender.flush()?;
    let mut receiving = out::establish(&listener, config, &fixture)?;
    remote_presence(&mut receiving, None, Some("available"))?;
    for (kind, id, payload) in [
        ("probe", "probe", ""),
        (
            "error",
            "error",
            "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>",
        ),
        ("unavailable", "explicit", ""),
    ] {
        write!(
            sender,
            "<presence type='{kind}' to='bob@peer.test/phone' from='mallory@third.test/spy' id='{id}'>{payload}</presence>"
        )?;
        sender.flush()?;
        remote_presence(&mut receiving, Some(kind), Some(id))?;
    }
    sender.write_all(b"<presence to='bob@peer.test/phone' id='again'/>")?;
    sender.flush()?;
    remote_presence(&mut receiving, None, Some("again"))?;
    client::barrier(&mut sender)?;
    client::close(&mut sender)?;
    remote_presence(&mut receiving, Some("unavailable"), None)?;
    wait_sample(&server, &out::outbound_auth("success"), 1)?;
    wait_sample(
        &server,
        "lonewolf_s2s_stanzas_sent_total{kind=\"presence\"}",
        6,
    )?;
    out::close(&mut receiving)?;
    out::wait_zero(&server)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}
