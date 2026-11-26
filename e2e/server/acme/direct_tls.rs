// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::Arc;
use support::{crl_gate::CrlReadGate, tls::ClientCertificates};

const DOMAIN: &str = "xmpp.example.test";
const FEATURES: &str = "<stream:features xmlns:stream='http://etherx.jabber.org/streams'><sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/><channel-binding type='tls-exporter'/></sasl-channel-binding><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-256-PLUS</mechanism><mechanism>SCRAM-SHA-256</mechanism><mechanism>SCRAM-SHA-1-PLUS</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms></stream:features>";

fn configure(ca: &FakeAcmeCa) -> TestResult<C2sSuite> {
    let server = C2sSuite::configure(
        ca,
        "[hosts.\"xmpp.example.test\".tls]\nprovider='letsencrypt'",
        "[logging]\nlevel='off'\n[metrics]\nenabled=true\naddress='127.0.0.1:0'",
    )?;
    server.replace_config(&server.config()?.replacen(
        "[[c2s.listeners]]",
        "[[c2s.listeners]]\ntls_mode='direct'",
        1,
    ))?;
    Ok(server)
}

#[test]
fn direct_tls_managed_rotation_holds_selected_a_through_b_publication_and_keeps_bound_sessions()
-> TestResult {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let mut ca = FakeAcmeCa::start()?;
        let mut server = configure(&ca)?;
        let _credentials = ClientCertificates::configure(server.path())?;
        server.replace_config(&server.config()?.replace(
            "[hosts.localhost.tls.client_auth]",
            "[hosts.\"xmpp.example.test\".tls.client_auth]",
        ))?;
        server.enable_clock();
        server.start_once(&ca)?;
        let parked = server.parked_clock(0)?;
        assert_eq!(server.launch_count, 1);
        assert_eq!(server.setup_retries, 0);
        server.account(DOMAIN)?;
        let config = server.tls_with_versions(&[version])?;
        let mut bound = server.tls_first(DOMAIN, Arc::clone(&config))?;
        let a = peer(&mut bound)?;
        assert_eq!(
            bound.transport().conn.protocol_version(),
            Some(version.version)
        );
        bound.open()?.assert_xml(FEATURES)?;
        bound
            .scram(
                "alice",
                PASSWORD,
                "SCRAM-SHA-256-PLUS",
                Some("tls-server-end-point"),
            )?
            .assert_name(SASL_NAMESPACE, "success");
        let mut bound = bound.restart();
        bound.open()?.child(support::BIND_NAMESPACE, "bind")?;
        assert_eq!(
            bound.bind(Some("before"))?,
            "alice@xmpp.example.test/before"
        );
        let mut gate = CrlReadGate::new(&server.path().join("client-crls.pem"))?;
        let mut paused_config = (*config).clone();
        paused_config.alpn_protocols = vec![b"xmpp-client".to_vec()];
        let address = server.address;
        std::thread::scope(|scope| -> TestResult {
            let pending = scope.spawn(move || -> Result<Client, String> {
                let run = || -> TestResult<Client> {
                    let mut client = Client::direct_tls_with_config(
                        address,
                        Arc::new(paused_config),
                        rustls::pki_types::ServerName::try_from(DOMAIN)?,
                    )?;
                    client.complete_tls()?;
                    Ok(client)
                };
                run().map_err(|error| error.to_string())
            });
            let held = (|| -> TestResult {
                gate.captured()?;
                gate.replace_path()?;
                ca.renew();
                let generation =
                    server.advance_clock(parked.now + std::time::Duration::from_secs(3601))?;
                server.parked_clock(generation)?;
                let mut fresh = server.tls_first(DOMAIN, Arc::clone(&config))?;
                let b = peer(&mut fresh)?;
                assert_ne!(a, b);
                fresh.open()?.assert_xml(FEATURES)?;
                fresh
                    .scram(
                        "alice",
                        PASSWORD,
                        "SCRAM-SHA-256-PLUS",
                        Some("tls-server-end-point"),
                    )?
                    .assert_name(SASL_NAMESPACE, "success");
                let mut fresh = fresh.restart();
                fresh.open()?.child(support::BIND_NAMESPACE, "bind")?;
                assert_eq!(fresh.bind(Some("after"))?, "alice@xmpp.example.test/after");
                bound.send("<message to='alice@xmpp.example.test/after' type='chat' id='old-live'><body>Old session remains</body></message>")?;
                fresh.expect_xml("<message xmlns='jabber:client' from='alice@xmpp.example.test/before' to='alice@xmpp.example.test/after' type='chat' id='old-live'><body>Old session remains</body></message>")?;
                assert_eq!(peer(&mut bound)?, a);
                fresh.close()?;
                Ok(())
            })();
            let released = gate.release();
            drop(gate);
            let connected = pending
                .join()
                .map_err(|_| "captured handshake worker panicked")?;
            held?;
            released?;
            let mut paused = connected?;
            assert_eq!(peer(&mut paused)?, a);
            paused.open()?.assert_xml(FEATURES)?;
            paused
                .scram(
                    "alice",
                    PASSWORD,
                    "SCRAM-SHA-256-PLUS",
                    Some("tls-server-end-point"),
                )?
                .assert_name(SASL_NAMESPACE, "success");
            let mut paused = paused.restart();
            paused.open()?.child(support::BIND_NAMESPACE, "bind")?;
            assert_eq!(
                paused.bind(Some("captured"))?,
                "alice@xmpp.example.test/captured"
            );
            paused.send("<message to='alice@xmpp.example.test/before' type='chat' id='captured-live'><body>Captured generation</body></message>")?;
            bound.expect_xml("<message xmlns='jabber:client' from='alice@xmpp.example.test/captured' to='alice@xmpp.example.test/before' type='chat' id='captured-live'><body>Captured generation</body></message>")?;
            paused.close()
        })?;
        bound.close()?;
        server.wait_for_metric("lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256-PLUS\",outcome=\"success\"} 3")?;
        server.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
        server.wait_for_metric("lonewolf_router_sessions 0")?;
        assert_eq!(ca.counts().at(AcmeStage::NewOrder), 2);
        assert_eq!(server.launch_count, 1);
        assert!(ca.counts().errors.is_empty(), "{:?}", ca.counts());
        assert!(server.stop_once()?.success());
        let certificate = server
            .records()?
            .1
            .ok_or("missing host")?
            .certificate
            .ok_or("missing certificate")?
            .material
            .chain[0]
            .clone();
        let counts = ca.counts();
        ca.offline();
        server.start_once(&ca)?;
        let mut cached = server.tls_first(DOMAIN, config)?;
        assert_eq!(peer(&mut cached)?, certificate);
        assert_eq!(server.launch_count, 2);
        assert_eq!(server.setup_retries, 0);
        cached.open()?.assert_xml(FEATURES)?;
        cached
            .scram(
                "alice",
                PASSWORD,
                "SCRAM-SHA-256-PLUS",
                Some("tls-exporter"),
            )?
            .assert_name(SASL_NAMESPACE, "success");
        let mut cached = cached.restart();
        cached.open()?.child(support::BIND_NAMESPACE, "bind")?;
        assert_eq!(
            cached.bind(Some("cached"))?,
            "alice@xmpp.example.test/cached"
        );
        cached.close()?;
        assert!(server.stop_once()?.success());
        assert_eq!(
            ca.counts().at(AcmeStage::NewOrder),
            counts.at(AcmeStage::NewOrder)
        );
    }
    Ok(())
}

#[test]
fn direct_tls_s2s_rotation_updates_local_server_and_client_chains_without_reconnecting_old_links()
-> TestResult {
    use support::federation::{
        FederationCa,
        peer::{self as s2s, RawS2sListener, RawS2sPeer},
    };
    let mut ca = FakeAcmeCa::start()?;
    let directory = tempfile::tempdir()?;
    let remote_ca = FederationCa::new(directory.path())?;
    let remote_key = remote_ca.server(directory.path(), "remote", &["b.test", "c.test"])?;
    let listener = RawS2sListener::bind()?.direct_tls();
    let mut server = configure(&ca)?;
    let config = server.config()?.replace("[s2s]\nenabled = false", &format!("[s2s]\nenabled=true\nbidirectional=false\nlisteners=[{{address='127.0.0.1:0',tls_mode='direct'}}]\n[s2s.tls]\ntrust_anchors_path={:?}\n[s2s.routes]\n'b.test'=[{{address='{}',tls_mode='direct'}}]", remote_ca.trust_anchors_path(), listener.address()?));
    assert_ne!(config, server.config()?);
    server.replace_config(&config)?;
    server.enable_clock();
    server.start_once(&ca)?;
    let parked = server.parked_clock(0)?;
    server.account(DOMAIN)?;
    let mut alice = server.tls_first(DOMAIN, Arc::clone(&server.tls))?;
    let a = peer(&mut alice)?;
    alice.open()?.assert_xml(FEATURES)?;
    alice
        .scram(
            "alice",
            PASSWORD,
            "SCRAM-SHA-256-PLUS",
            Some("tls-server-end-point"),
        )?
        .assert_name(SASL_NAMESPACE, "success");
    let mut alice = alice.restart();
    alice.open()?.child(support::BIND_NAMESPACE, "bind")?;
    assert_eq!(
        alice.bind(Some("rotation"))?,
        "alice@xmpp.example.test/rotation"
    );
    let mut client =
        (*support::tls::with_client_certificate(&server.tls, Arc::clone(&remote_key))).clone();
    client.alpn_protocols = vec![b"xmpp-server".to_vec()];
    let client = Arc::new(client);
    let address = *server
        .s2s
        .as_ref()
        .and_then(|addresses| addresses.first())
        .ok_or("missing S2S listener")?;
    let mut old_inbound = RawS2sPeer::tls_first(address, "b.test", DOMAIN, Arc::clone(&client))?;
    assert_eq!(
        old_inbound
            .peer_certificates()
            .ok_or("missing local server chain")?[0]
            .as_ref(),
        a
    );
    let header_b = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='b.test' to='{DOMAIN}' version='1.0'>"
    );
    old_inbound.open_protected(&header_b, Some("b.test"))?;
    old_inbound.expect_external_offered()?;
    old_inbound.auth_external(Some("b.test"))?;
    old_inbound.expect_sasl_success()?;
    let mut old_inbound = old_inbound.restart("b.test", DOMAIN)?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='local-a'><body>Client chain A</body></message>")?;
    let remote_server = s2s::server_config_with_roots(
        server.roots.clone(),
        remote_key,
        DOMAIN,
        rustls::DEFAULT_VERSIONS,
    )?;
    let mut old_outbound = listener.accept("b.test", DOMAIN, Arc::clone(&remote_server), true)?;
    assert_eq!(
        old_outbound
            .peer_certificates()
            .ok_or("missing local client chain")?[0]
            .as_ref(),
        a
    );
    old_outbound.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@xmpp.example.test/rotation' to='bob@b.test/phone' type='chat' id='local-a'><body>Client chain A</body></message>")?;
    ca.renew();
    let generation = server.advance_clock(parked.now + std::time::Duration::from_secs(3601))?;
    server.parked_clock(generation)?;
    let mut new_inbound = RawS2sPeer::tls_first(address, "c.test", DOMAIN, client)?;
    let b = new_inbound
        .peer_certificates()
        .ok_or("missing rotated server chain")?[0]
        .as_ref()
        .to_vec();
    assert_ne!(a, b);
    let header_c = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='c.test' to='{DOMAIN}' version='1.0'>"
    );
    new_inbound.open_protected(&header_c, Some("c.test"))?;
    new_inbound.expect_external_offered()?;
    new_inbound.auth_external(Some("c.test"))?;
    new_inbound.expect_sasl_success()?;
    let mut new_inbound = new_inbound.restart("c.test", DOMAIN)?;
    old_inbound.send("<message from='bob@b.test/phone' to='alice@xmpp.example.test/rotation' type='chat' id='server-a-live'><body>Old inbound survives</body></message>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@b.test/phone' to='alice@xmpp.example.test/rotation' type='chat' id='server-a-live'><body>Old inbound survives</body></message>")?;
    assert_eq!(
        old_inbound
            .peer_certificates()
            .ok_or("missing old server chain")?[0]
            .as_ref(),
        a
    );
    alice.send("<message to='bob@b.test/phone' type='chat' id='client-a-live'><body>Old outbound survives</body></message>")?;
    old_outbound.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@xmpp.example.test/rotation' to='bob@b.test/phone' type='chat' id='client-a-live'><body>Old outbound survives</body></message>")?;
    server.wait_for_metric("lonewolf_s2s_transport_attempts_total{direction=\"outbound\",tls_mode=\"direct\",outcome=\"success\"} 1")?;
    old_outbound.close()?;
    server.wait_for_metric(
        "lonewolf_s2s_streams_closed_total{direction=\"outbound\",outcome=\"stream_end\"} 1",
    )?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='local-b'><body>Client chain B</body></message>")?;
    let mut new_outbound = listener.accept("b.test", DOMAIN, remote_server, true)?;
    assert_eq!(
        new_outbound
            .peer_certificates()
            .ok_or("missing rotated client chain")?[0]
            .as_ref(),
        b
    );
    new_outbound.receive()?.assert_xml("<message xmlns='jabber:server' from='alice@xmpp.example.test/rotation' to='bob@b.test/phone' type='chat' id='local-b'><body>Client chain B</body></message>")?;
    new_inbound.send("<message from='carol@c.test/phone' to='alice@xmpp.example.test/rotation' type='chat' id='server-b-live'><body>New inbound uses B</body></message>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='carol@c.test/phone' to='alice@xmpp.example.test/rotation' type='chat' id='server-b-live'><body>New inbound uses B</body></message>")?;
    for direction in ["inbound", "outbound"] {
        server.wait_for_metric(&format!("lonewolf_s2s_transport_attempts_total{{direction=\"{direction}\",tls_mode=\"direct\",outcome=\"success\"}} 2"))?;
        server.wait_for_metric(&format!(
            "lonewolf_s2s_authentications_total{{direction=\"{direction}\",outcome=\"success\"}} 2"
        ))?;
    }
    old_inbound.close()?;
    new_inbound.close()?;
    new_outbound.close()?;
    for direction in ["inbound", "outbound"] {
        server.wait_for_metric(&format!(
            "lonewolf_s2s_transport_connections{{direction=\"{direction}\",tls_mode=\"direct\"}} 0"
        ))?;
        server.wait_for_metric(&format!(
            "lonewolf_s2s_connections{{direction=\"{direction}\"}} 0"
        ))?;
    }
    server.wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
    server.wait_for_metric("lonewolf_s2s_outbound_queued_bytes 0")?;
    alice.close()?;
    server.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    assert_eq!(ca.counts().at(AcmeStage::NewOrder), 2);
    assert_eq!(server.launch_count, 1);
    assert_eq!(server.setup_retries, 0);
    assert!(ca.counts().errors.is_empty(), "{:?}", ca.counts());
    assert!(server.stop_once()?.success());
    ca.offline();
    Ok(())
}
