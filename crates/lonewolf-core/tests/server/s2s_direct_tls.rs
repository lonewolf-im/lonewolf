// SPDX-License-Identifier: Apache-2.0

use super::*;
use rustls::pki_types::ServerName;
use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

#[path = "../support/ports.rs"]
#[allow(dead_code)]
mod ports;

fn direct_config(fixture: &Fixture) -> String {
    let config = fixture
        .config
        .replace(
            "[[c2s.listeners]]\naddress='127.0.0.1:0'",
            "[[c2s.listeners]]\naddress='127.0.0.1:0'\ntls_mode='direct'",
        )
        .replace(
            "[[s2s.listeners]]\naddress='127.0.0.1:0'",
            "[[s2s.listeners]]\naddress='127.0.0.1:0'\ntls_mode='direct'",
        );
    format!("{config}[logging]\nlevel='off'\n")
}

fn direct(fixture: &Fixture, address: SocketAddr, role: &[u8], certificate: bool) -> Result<Peer> {
    let mut config = (*fixture.client(certificate.then_some("peer.test"), false)?).clone();
    config.alpn_protocols = vec![role.to_vec()];
    let connection =
        rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("local.test")?)?;
    let mut peer = rustls::StreamOwned::new(connection, connect(address)?);
    while peer.conn.is_handshaking() {
        peer.conn.complete_io(&mut peer.sock)?;
    }
    assert_eq!(peer.conn.alpn_protocol(), Some(role));
    Ok(peer)
}

#[test]
fn direct_tls_mixed_listeners_keep_indices_and_port_zero_addresses_across_workers() -> Result {
    let fixture = Fixture::new()?;
    for ip in ["127.0.0.1".to_owned(), Ipv6Addr::LOCALHOST.to_string()] {
        let endpoint = if ip.contains(':') {
            format!("[{ip}]:0")
        } else {
            format!("{ip}:0")
        };
        let config = format!("{}[logging]\nlevel='off'\n",fixture.config.replace("[[c2s.listeners]]\naddress='127.0.0.1:0'", &format!("[[c2s.listeners]]\naddress='{endpoint}'\n[[c2s.listeners]]\naddress='{endpoint}'\ntls_mode='direct'")).replace("[[s2s.listeners]]\naddress='127.0.0.1:0'", &format!("[[s2s.listeners]]\naddress='{endpoint}'\ntls_mode='direct'\n[[s2s.listeners]]\naddress='{endpoint}'")));
        let mut server = Server::start(&config, 2)?;
        let (c2s, s2s) = server.ready_with(|ready| (ready.c2s, ready.s2s))?;
        let s2s = s2s.ok_or("missing S2S")?;
        assert_eq!(c2s.len(), 2);
        assert_eq!(s2s.len(), 2);
        assert_ne!(c2s[0], c2s[1]);
        assert_ne!(s2s[0], s2s[1]);
        for addresses in [&c2s, &s2s] {
            for address in addresses {
                assert_ne!(address.port(), 0);
                assert_eq!(address.is_ipv6(), ip.contains(':'));
            }
        }
        for _ in 0..4 {
            let mut plain = connect(c2s[0])?;
            plain.write_all(c2s_outbound::HEADER.as_bytes())?;
            assert!(until(&mut plain, "</stream:features>")?.contains("<starttls"));
            let mut secure = direct(&fixture, c2s[1], b"xmpp-client", false)?;
            secure.write_all(c2s_outbound::HEADER.as_bytes())?;
            let features = until(&mut secure, "</stream:features>")?;
            assert!(features.contains("SCRAM-SHA-256"));
            assert!(!features.contains("<starttls"));
            close(&mut secure)?;
            let mut secure = direct(&fixture, s2s[0], b"xmpp-server", true)?;
            external(&mut secure, HEADER)?;
            success(&mut secure, AUTH)?;
            close(&mut secure)?;
            let mut plain = connect(s2s[1])?;
            plain.write_all(HEADER.as_bytes())?;
            assert!(until(&mut plain, "</stream:features>")?.contains("<starttls"));
        }
        let body = metrics(&server)?;
        for (family, modes) in [
            ("c2s", ["starttls", "direct"]),
            ("s2s", ["direct", "starttls"]),
        ] {
            assert_eq!(
                body.lines()
                    .filter(|line| line.starts_with(&format!("lonewolf_{family}_listener_info{{")))
                    .count(),
                2
            );
            for (slot, mode) in modes.into_iter().enumerate() {
                assert!(body.lines().any(|line|line==format!("lonewolf_{family}_listener_info{{listener=\"{slot}\",tls_mode=\"{mode}\"}} 1")),"{body}");
            }
        }
        wait_sample(
            &server,
            "lonewolf_s2s_connections{direction=\"inbound\"}",
            0,
        )?;
        wait_sample(&server, "lonewolf_c2s_connections{listener=\"1\"}", 0)?;
        server.stop(Signal::SIGTERM)?;
        assert!(
            !server
                .directory
                .path()
                .join("run/lonewolf/admin.sock")
                .exists()
        );
    }
    Ok(())
}

#[test]
fn direct_tls_startup_validation_and_late_bind_failure_complete_rollback() -> Result {
    let fixture = Fixture::new()?;
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let (_reservation, c2s) = ports::reserve_listener_address()?;
    let base = direct_config(&fixture).replace(
        "[[c2s.listeners]]\naddress='127.0.0.1:0'",
        &format!("[[c2s.listeners]]\naddress='{c2s}'"),
    );
    let cases = [
        base.replace("tls_mode='direct'", "tls_mode='invalid'"),
        base.replace(
            "[[s2s.listeners]]\naddress='127.0.0.1:0'",
            &format!("[[s2s.listeners]]\naddress='{c2s}'"),
        ),
        base.replace(
            "[[s2s.listeners]]\naddress='127.0.0.1:0'",
            &format!("[[s2s.listeners]]\naddress='{}'", occupied.local_addr()?),
        ),
        base.lines()
            .filter(|line| !line.starts_with("certificate_chain_path="))
            .collect::<Vec<_>>()
            .join("\n"),
        format!(
            "{base}[hosts.'managed.test'.tls]\nprovider='letsencrypt'\n[letsencrypt]\nlisten=['{c2s}']\n"
        ),
        base.replace(
            "[metrics]\nenabled=true\naddress='127.0.0.1:0'",
            &format!("[metrics]\nenabled=true\naddress='{c2s}'"),
        ),
    ];
    for config in cases {
        let mut server = Server::start(&config, 2)?;
        assert_eq!(server.wait()?.code(), Some(1));
        assert!(!server.has_readiness()?);
        assert!(
            !server
                .directory
                .path()
                .join("run/lonewolf/admin.sock")
                .exists()
        );
        ports::wait_until_released(c2s, Instant::now() + TIMEOUT)?;
    }
    for _ in 0..2 {
        let mut server = Server::start(&base, 2)?;
        let addresses = server.ready_with(|r| r.c2s)?;
        assert_eq!(addresses, [c2s]);
        let mut peer = direct(&fixture, c2s, b"xmpp-client", false)?;
        peer.write_all(c2s_outbound::HEADER.as_bytes())?;
        until(&mut peer, "</stream:features>")?;
        close(&mut peer)?;
        server.stop(Signal::SIGTERM)?;
    }
    Ok(())
}

#[test]
fn direct_tls_disabled_federation_keeps_c2s_and_omits_all_s2s_registration() -> Result {
    let fixture = Fixture::new()?;
    for extra in [
        "[s2s]\nenabled=false\n",
        "[hosts.'local.test']\nfederation=false\n",
    ] {
        let mut server = Server::start(&format!("{}{extra}", direct_config(&fixture)), 2)?;
        let addresses = server.ready()?;
        assert_eq!(addresses.len(), 1);
        let body = metrics(&server)?;
        assert!(!body.contains("lonewolf_s2s_"), "{body}");
        let mut peer = direct(&fixture, addresses[0], b"xmpp-client", false)?;
        peer.write_all(c2s_outbound::HEADER.as_bytes())?;
        assert!(until(&mut peer, "</stream:features>")?.contains("SCRAM-SHA-256"));
        close(&mut peer)?;
        wait_sample(&server, "lonewolf_c2s_connections{listener=\"0\"}", 0)?;
        server.stop(Signal::SIGTERM)?;
    }
    Ok(())
}

#[test]
fn direct_tls_fragmented_hello_and_protected_header_share_the_original_deadline_upper_bound()
-> Result {
    let fixture = Fixture::new()?;
    let config = format!(
        "{}[limits.c2s.profiles.default]\nconnection_establishment_timeout_secs=5\n[limits.s2s]\nnegotiation_timeout_secs=5\n",
        direct_config(&fixture)
    );
    let mut server = Server::start(&config, 2)?;
    let (c2s, s2s) = server.ready_with(|r| (r.c2s, r.s2s))?;
    for (address, role, certificate) in [
        (c2s[0], b"xmpp-client".as_slice(), false),
        (
            s2s.ok_or("missing S2S")?[0],
            b"xmpp-server".as_slice(),
            true,
        ),
    ] {
        let mut client_config =
            (*fixture.client(certificate.then_some("peer.test"), false)?).clone();
        client_config.alpn_protocols = vec![role.to_vec()];
        let mut connection = rustls::ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("local.test")?,
        )?;
        let mut hello = Vec::new();
        connection.write_tls(&mut hello)?;
        assert!(hello.len() > 10);
        let mut socket = connect(address)?;
        socket.write_all(&hello[..10])?;
        wait_sample(
            &server,
            if certificate {
                "lonewolf_s2s_transport_connections{direction=\"inbound\",tls_mode=\"direct\"}"
            } else {
                "lonewolf_c2s_connections{listener=\"0\"}"
            },
            1,
        )?;
        let original_deadline_upper_bound = Instant::now() + Duration::from_secs(5);
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        let error = socket
            .read(&mut [0; 1])
            .expect_err("partial ClientHello produced server bytes");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{error}"
        );
        assert!(
            Instant::now() < original_deadline_upper_bound,
            "partial handshake outlived its staging budget"
        );
        socket.set_read_timeout(Some(TIMEOUT))?;
        socket.write_all(&hello[10..])?;
        let mut peer = rustls::StreamOwned::new(connection, socket);
        while peer.conn.is_handshaking() {
            peer.conn.complete_io(&mut peer.sock)?;
        }
        assert!(
            Instant::now() < original_deadline_upper_bound,
            "TLS did not progress before the original deadline"
        );
        if certificate {
            let response = until(&mut peer, FOOTER)?;
            assert!(response.contains("connection-timeout"), "{response}");
            assert!(
                Instant::now() < original_deadline_upper_bound + Duration::from_secs(1),
                "first-header phase received a fresh timeout"
            );
            peer.write_all(FOOTER.as_bytes())?;
            peer.conn.send_close_notify();
            peer.flush()?;
            assert_eq!(peer.read(&mut [0; 1])?, 0);
        } else {
            let mut response = Vec::new();
            assert_eq!(peer.read_to_end(&mut response)?, 0);
            assert!(response.is_empty());
            assert!(
                Instant::now() < original_deadline_upper_bound + Duration::from_secs(1),
                "first-header phase received a fresh timeout"
            );
        }
    }
    wait_sample(
        &server,
        "lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"establishing\",outcome=\"establishment_timeout\"}",
        1,
    )?;
    wait_sample(&server, &auth_sample("timeout"), 1)?;
    wait_sample(
        &server,
        "lonewolf_s2s_transport_attempts_total{direction=\"inbound\",tls_mode=\"direct\",outcome=\"timeout\"}",
        1,
    )?;
    wait_sample(&server, "lonewolf_c2s_unauthenticated_connections", 0)?;
    let mut valid = direct(&fixture, c2s[0], b"xmpp-client", false)?;
    valid.write_all(c2s_outbound::HEADER.as_bytes())?;
    until(&mut valid, "</stream:features>")?;
    close(&mut valid)?;
    server.stop(Signal::SIGTERM)?;
    Ok(())
}

#[test]
fn direct_tls_sigterm_completes_pending_hello_sasl_authenticated_and_bidi_workers() -> Result {
    let fixture = Fixture::new()?;
    for phase in 0..4 {
        let mut server = Server::start(&direct_config(&fixture), 2)?;
        let addresses = server.ready_with(|r| r.s2s)?.ok_or("missing S2S")?;
        if phase == 0 {
            let mut socket = connect(addresses[0])?;
            wait_sample(
                &server,
                "lonewolf_s2s_transport_connections{direction=\"inbound\",tls_mode=\"direct\"}",
                1,
            )?;
            server.stop(Signal::SIGTERM)?;
            assert_eq!(socket.read(&mut [0; 1])?, 0);
        } else {
            let mut peer = direct(&fixture, addresses[0], b"xmpp-server", true)?;
            external(&mut peer, HEADER)?;
            if phase == 1 {
                peer.write_all(
                    b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'/>",
                )?;
                assert_eq!(
                    until(&mut peer, "/>")?,
                    "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"
                );
            } else {
                if phase == 3 {
                    peer.write_all(b"<bidi xmlns='urn:xmpp:bidi'/>")?;
                }
                success(&mut peer, AUTH)?;
                wait_sample(&server, &auth_sample("success"), 1)?;
            }
            let reader = std::thread::spawn(move || -> std::result::Result<(), String> {
                stream_error(&mut peer, "system-shutdown").map_err(|e| e.to_string())?;
                peer.write_all(FOOTER.as_bytes())
                    .map_err(|e| e.to_string())?;
                peer.conn.send_close_notify();
                peer.flush().map_err(|e| e.to_string())?;
                assert_eq!(peer.read(&mut [0; 1]).map_err(|e| e.to_string())?, 0);
                Ok(())
            });
            server.stop(Signal::SIGTERM)?;
            reader.join().map_err(|_| "peer panicked")??;
        }
        assert!(
            !server
                .directory
                .path()
                .join("run/lonewolf/admin.sock")
                .exists()
        );
    }
    Ok(())
}
