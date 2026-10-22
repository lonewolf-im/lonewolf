// SPDX-License-Identifier: Apache-2.0

#[path = "../support/ports.rs"]
mod ports;

#[path = "../support/acme/mod.rs"]
mod support;

use support::process::peer;
use support::{
    AcmeFault, AcmeStage, C2sSuite, Client, FakeAcmeCa, PASSWORD, SASL_NAMESPACE, TestResult,
};

fn authenticate(mut client: Client, binding: &str, resource: &str) -> TestResult<Client> {
    client
        .scram("alice", PASSWORD, "SCRAM-SHA-256-PLUS", Some(binding))?
        .assert_name(SASL_NAMESPACE, "success");
    let mut client = client.restart();
    client.open()?;
    assert_eq!(
        client.bind(Some(resource))?,
        format!("alice@xmpp.example.test/{resource}")
    );
    Ok(client)
}

#[test]
fn provider_bootstrap_verifies_https_jws_csr_http01_and_both_plus_bindings() -> TestResult {
    let ca = FakeAcmeCa::start()?;
    let mut server = C2sSuite::managed(&ca)?;
    server.start(&ca)?;
    ca.wait_for(AcmeStage::Certificate)?;
    let certificate = server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    for (i, binding) in ["tls-server-end-point", "tls-exporter"].iter().enumerate() {
        let client = server.secure("xmpp.example.test")?;
        let mut client = authenticate(client, binding, &format!("bootstrap-{i}"))?;
        assert_eq!(peer(&mut client)?, certificate);
        client.close()?;
    }
    assert_eq!(ca.counts().at(AcmeStage::NewOrder), 1);
    assert_eq!(ca.counts().callbacks.len(), 1);
    assert_eq!(ca.counts().csrs.len(), 1);
    assert!(ca.counts().errors.is_empty(), "{:?}", ca.counts());
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    Ok(())
}

#[test]
fn cached_restart_is_offline_and_directory_namespaces_are_isolated() -> TestResult {
    let mut ca = FakeAcmeCa::start()?;
    let mut server = C2sSuite::managed(&ca)?;
    server.start(&ca)?;
    let certificate = server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    let (account, host) = server.records()?;
    assert_eq!(
        host.ok_or("host")?
            .certificate
            .ok_or("certificate")?
            .material
            .chain[0],
        certificate
    );
    let counts = ca.counts();
    ca.offline();
    server.start(&ca)?;
    let mut client = authenticate(
        server.secure("xmpp.example.test")?,
        "tls-exporter",
        "offline",
    )?;
    assert_eq!(peer(&mut client)?, certificate);
    client.close()?;
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    assert_eq!(server.records()?.0.key_pkcs8, account.key_pkcs8);
    assert_eq!(
        ca.counts().at(AcmeStage::NewOrder),
        counts.at(AcmeStage::NewOrder)
    );
    let other = FakeAcmeCa::start()?;
    other.set_fault(AcmeStage::Account, AcmeFault::Hold);
    other.callback(server.challenge);
    let config = server
        .config()?
        .replace(&server.directory_url, &other.alternate_directory_url())
        .replace(
            ca.trust_bundle_path().to_str().ok_or("trust path")?,
            other.trust_bundle_path().to_str().ok_or("trust path")?,
        );
    server.replace_config(&config)?;
    server.directory_url = other.alternate_directory_url();
    server.roots = other.roots.clone();
    server.tls = server.tls_with_versions(rustls::DEFAULT_VERSIONS)?;
    server.start(&other)?;
    other.wait_for(AcmeStage::Account)?;
    assert_pending(&server, "xmpp.example.test")?;
    server.kill()?;
    assert_ne!(server.records()?.0.key_pkcs8, account.key_pkcs8);
    assert!(server.records()?.1.is_none());
    Ok(())
}

fn assert_pending(server: &C2sSuite, domain: &str) -> TestResult {
    let mut plain = server.plain(domain)?;
    plain.send(&format!("<starttls xmlns='{}'/>", support::TLS_NAMESPACE))?;
    plain
        .receive()?
        .assert_name(support::TLS_NAMESPACE, "failure");
    Ok(())
}

#[test]
fn pending_host_coexists_with_file_and_cached_hosts_then_activates() -> TestResult {
    let ca = FakeAcmeCa::start()?;
    let mut server = C2sSuite::managed(&ca)?;
    server.start(&ca)?;
    server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    let roots = support::tls::configure_host(server.path(), "-file", &["file.example.test"])?;
    for certificate in roots.roots {
        server.roots.roots.push(certificate);
    }
    server.tls = server.tls_with_versions(rustls::DEFAULT_VERSIONS)?;
    server.replace_config(&format!("{}\n[hosts.\"pending.example.test\".tls]\nprovider='letsencrypt'\n[hosts.\"file.example.test\".tls]\ncertificate_chain_path='certificate-file.pem'\nprivate_key_path='private-key-file.pem'\n",server.config()?))?;
    ca.set_fault(AcmeStage::Challenge, AcmeFault::Hold);
    let before = ca.counts().at(AcmeStage::Challenge);
    server.start(&ca)?;
    ca.wait_count(AcmeStage::Challenge, before + 1)?;
    assert_pending(&server, "pending.example.test")?;
    let mut cached = authenticate(
        server.secure("xmpp.example.test")?,
        "tls-exporter",
        "healthy",
    )?;
    cached.close()?;
    server.account("file.example.test")?;
    let mut file = server.secure("file.example.test")?;
    file.authenticate("alice", PASSWORD)?;
    ca.release(AcmeStage::Challenge);
    wait_until(
        || server.secure("pending.example.test").is_ok(),
        "pending host activation",
    )?;
    server.account("pending.example.test")?;
    let mut pending = server.secure("pending.example.test")?;
    pending.authenticate("alice", PASSWORD)?;
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    Ok(())
}

fn wait_until(mut condition: impl FnMut() -> bool, description: &str) -> TestResult {
    let deadline = std::time::Instant::now() + support::TIMEOUT;
    loop {
        if condition() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("timeout: {description}").into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn rotation(versions: &[&'static rustls::SupportedProtocolVersion], binding: &str) -> TestResult {
    let ca = FakeAcmeCa::start()?;
    ca.renew();
    ca.set_fault(AcmeStage::Ari, AcmeFault::Hold);
    let mut server = C2sSuite::managed(&ca)?;
    server.start(&ca)?;
    let a = server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    ca.wait_for(AcmeStage::Ari)?;
    let config = server.tls_with_versions(versions)?;
    let mut paused = server.encrypted("xmpp.example.test", config.clone())?;
    assert_eq!(peer(&mut paused)?, a);
    let mut bound = server.encrypted("xmpp.example.test", config.clone())?;
    bound.open()?;
    let mut bound = authenticate(bound, binding, "bound-before")?;
    ca.release(AcmeStage::Ari);
    let b = server.wait_certificate(Some(&a))?;
    assert_ne!(a, b);
    paused.open()?;
    let mut paused = authenticate(paused, binding, "paused-after")?;
    assert_eq!(peer(&mut paused)?, a);
    paused.close()?;
    bound.send("<iq type='get' id='still-bound'><query xmlns='jabber:iq:roster'/></iq>")?;
    assert_eq!(bound.receive()?.attribute("type"), Some("result"));
    bound.close()?;
    for i in 0..2 {
        let mut fresh = server.encrypted("xmpp.example.test", config.clone())?;
        assert_eq!(peer(&mut fresh)?, b);
        if i == 0 {
            assert_eq!(
                fresh.transport().conn.handshake_kind(),
                Some(rustls::HandshakeKind::Full)
            );
        }
        fresh.open()?;
        let mut fresh = authenticate(fresh, binding, &format!("fresh-{i}"))?;
        fresh.close()?;
    }
    assert_eq!(ca.counts().at(AcmeStage::NewOrder), 2);
    assert!(ca.counts().errors.is_empty(), "{:?}", ca.counts());
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    Ok(())
}
#[test]
fn ari_rotation_tls12_endpoint_keeps_paused_and_bound_sessions_and_rejects_old_resumption()
-> TestResult {
    rotation(&[&rustls::version::TLS12], "tls-server-end-point")
}
#[test]
fn ari_rotation_tls13_exporter_keeps_paused_and_bound_sessions_and_rejects_old_resumption()
-> TestResult {
    rotation(&[&rustls::version::TLS13], "tls-exporter")
}

#[test]
fn proxy_preserves_alabel_host_and_path_and_rejects_wrong_host_and_token() -> TestResult {
    let ca = FakeAcmeCa::start()?;
    ca.set_fault(AcmeStage::Challenge, AcmeFault::Hold);
    let mut server = C2sSuite::managed(&ca)?;
    server.replace_config(
        &server
            .config()?
            .replace("xmpp.example.test", "bücher.example"),
    )?;
    let proxy = support::ChallengeProxy::start(server.challenge)?;
    ca.callback(proxy.address);
    server.start_with_route(&ca, |address| proxy.set_target(address))?;
    ca.wait_for(AcmeStage::Challenge)?;
    let callback = ca.counts().callbacks[0].clone();
    assert_eq!(callback.0, "xn--bcher-kva.example");
    assert!(
        support::http_get(proxy.address, "wrong.example", &callback.1)?
            .starts_with("HTTP/1.1 404 ")
    );
    assert!(
        support::http_get(
            proxy.address,
            &callback.0,
            "/.well-known/acme-challenge/wrong_token_long_enough_to_be_valid"
        )?
        .starts_with("HTTP/1.1 404 ")
    );
    assert!(
        proxy
            .requests
            .lock()
            .contains(&(callback.0.clone(), callback.1.clone()))
    );
    ca.release(AcmeStage::Challenge);
    wait_until(|| server.secure("bücher.example").is_ok(), "IDN issuance")?;
    server.account("bücher.example")?;
    let mut client = server.secure("bücher.example")?;
    client.authenticate("alice", PASSWORD)?;
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    Ok(())
}

#[test]
fn ipv6_listener_works_when_available_and_bind_collision_rolls_back_all_endpoints() -> TestResult {
    let ca = FakeAcmeCa::start()?;
    let mut server = C2sSuite::managed(&ca)?;
    match std::net::TcpListener::bind("[::1]:0") {
        Ok(listener) => {
            let address = listener.local_addr()?;
            server.reserve_listener(listener)?;
            server.start(&ca)?;
            server.wait_certificate(None)?;
            server.account("xmpp.example.test")?;
            let mut client =
                authenticate(server.secure("xmpp.example.test")?, "tls-exporter", "ipv6")?;
            client.close()?;
            assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
            eprintln!("IPv6 branch: passed actual HTTP01 on {address}");
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
            ) =>
        {
            eprintln!("IPv6 branch unavailable: {error}")
        }
        Err(error) => return Err(error.into()),
    }
    let collision = std::net::TcpListener::bind("127.0.0.1:0")?;
    let occupied = collision.local_addr()?;
    let (_reservation, free) = ports::reserve_listener_address()?;
    let config = server.config()?;
    let old = config
        .lines()
        .find(|line| line.starts_with("listen ="))
        .ok_or("listen")?;
    server
        .replace_config(&config.replace(old, &format!("listen = [\"{free}\",\"{occupied}\"]")))?;
    server.spawn()?;
    assert!(!server.wait_exit()?.success());
    assert!(server.logs()?.contains("HTTP bind"));
    let _released = ports::bind_released_listener(
        free,
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    )?;
    assert_eq!(
        ca.counts().at(AcmeStage::NewOrder),
        usize::from(ca.counts().at(AcmeStage::Challenge) > 0)
    );
    Ok(())
}

#[test]
fn client_auth_and_crl_policy_remain_enforced_after_managed_rotation() -> TestResult {
    let ca = FakeAcmeCa::start()?;
    ca.renew();
    ca.set_fault(AcmeStage::Ari, AcmeFault::Hold);
    let mut server = C2sSuite::managed(&ca)?;
    let credentials = support::tls::ClientCertificates::configure(server.path())?;
    server.replace_config(&server.config()?.replace(
        "[hosts.localhost.tls.client_auth]",
        "[hosts.\"xmpp.example.test\".tls.client_auth]",
    ))?;
    let identity = credentials.identity_key(
        &["alice@xmpp.example.test"],
        time::OffsetDateTime::now_utc() + time::Duration::days(1),
    )?;
    server.start(&ca)?;
    let a = server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    for round in 0..2 {
        let mut external = server.encrypted(
            "xmpp.example.test",
            support::tls::with_client_certificate(&server.tls, identity.clone()),
        )?;
        external.open()?;
        external.send_external_auth(Some(""))?;
        external.receive()?.assert_name(SASL_NAMESPACE, "success");
        let mut external = external.restart();
        external.open()?;
        assert_eq!(
            external.bind(Some("external"))?,
            "alice@xmpp.example.test/external"
        );
        external.close()?;
        let mut no_certificate = authenticate(
            server.secure("xmpp.example.test")?,
            "tls-server-end-point",
            &format!("no-cert-{round}"),
        )?;
        no_certificate.close()?;
        for (_, key) in &credentials.rejected {
            assert!(
                server
                    .encrypted(
                        "xmpp.example.test",
                        support::tls::with_client_certificate(&server.tls, key.clone())
                    )
                    .and_then(|mut client| client.open())
                    .is_err()
            );
        }
        if round == 0 {
            ca.release(AcmeStage::Ari);
            server.wait_certificate(Some(&a))?;
        }
    }
    credentials.replace_crl(
        true,
        time::OffsetDateTime::now_utc() + time::Duration::days(1),
    )?;
    assert!(
        server
            .encrypted(
                "xmpp.example.test",
                support::tls::with_client_certificate(&server.tls, identity)
            )
            .and_then(|mut client| client.open())
            .is_err()
    );
    let mut client = authenticate(
        server.secure("xmpp.example.test")?,
        "tls-exporter",
        "after-revocation",
    )?;
    client.close()?;
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    Ok(())
}

fn failure_preserves(stage: AcmeStage, fault: AcmeFault, expected: &str) -> TestResult {
    let ca = FakeAcmeCa::start()?;
    ca.renew();
    ca.set_fault(AcmeStage::Ari, AcmeFault::Hold);
    let mut server = C2sSuite::configure(
        &ca,
        "[hosts.\"xmpp.example.test\".tls]\nprovider='letsencrypt'",
        "[metrics]\nenabled=true\naddress='127.0.0.1:0'",
    )?;
    server.start(&ca)?;
    let a = server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    let mut bound = authenticate(
        server.secure("xmpp.example.test")?,
        "tls-exporter",
        "failure-survivor",
    )?;
    let before = ca.counts().at(stage);
    let minimum_retry = match &fault {
        AcmeFault::Status(_, delay) => {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
                + delay
        }
        _ => 0,
    };
    ca.set_fault(stage, fault);
    ca.release(AcmeStage::Ari);
    ca.wait_count(stage, before + 1)?;
    server.wait_log("ACME certificate will retry")?;
    assert_eq!(peer(&mut server.secure("xmpp.example.test")?)?, a);
    bound.send("<iq type='get' id='survived'><query xmlns='jabber:iq:roster'/></iq>")?;
    assert_eq!(bound.receive()?.attribute("type"), Some("result"));
    bound.close()?;
    wait_until(
        || {
            server.metrics().is_ok_and(|metrics| {
                metrics.lines().any(|line| {
                    line.contains("acme_attempts_total{")
                        && line.contains("host=\"xmpp.example.test\"")
                        && line.contains(&format!("outcome=\"{expected}\""))
                        && line.ends_with(" 1")
                })
            })
        },
        "failure metric",
    )?;
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    let (_, record) = server.records()?;
    let record = record.ok_or("record")?;
    assert_eq!(
        record.certificate.ok_or("certificate")?.material.chain[0],
        a
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    assert!(record.retry.not_before_unix > now);
    assert!(record.retry.not_before_unix >= minimum_retry);
    let failed_counts = ca.counts();
    assert!(failed_counts.at(AcmeStage::NewOrder) <= 2);
    assert!(failed_counts.at(stage) <= before + 1);
    let logs = server.logs()?;
    for secret in [
        "PRIVATE-CA-DETAIL",
        "PRIVATE-INVALID-CERTIFICATE",
        "challenge_token_",
        "BEGIN PRIVATE KEY",
        "nonce-",
    ] {
        assert!(!logs.contains(secret), "leaked {secret}");
    }
    server.start(&ca)?;
    assert_eq!(peer(&mut server.secure("xmpp.example.test")?)?, a);
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    assert_eq!(
        ca.counts().at(AcmeStage::NewOrder),
        failed_counts.at(AcmeStage::NewOrder)
    );
    assert_eq!(
        server.records()?.1.ok_or("record")?.retry.not_before_unix,
        record.retry.not_before_unix
    );
    Ok(())
}
#[test]
fn rate_limit_429_preserves_certificate_and_durable_retry_after() -> TestResult {
    failure_preserves(
        AcmeStage::NewOrder,
        AcmeFault::Status(429, 3600),
        "rate_limited",
    )
}
#[test]
fn unavailable_503_preserves_certificate_and_durable_retry_after() -> TestResult {
    failure_preserves(AcmeStage::NewOrder, AcmeFault::Status(503, 3600), "network")
}
#[test]
fn authorization_denial_preserves_certificate_and_attempt_bounds() -> TestResult {
    failure_preserves(AcmeStage::Authorization, AcmeFault::Denied, "authorization")
}
#[test]
fn oversized_certificate_preserves_old_material_and_bounded_attempts() -> TestResult {
    failure_preserves(AcmeStage::Certificate, AcmeFault::Oversized, "network")
}
#[test]
fn invalid_certificate_preserves_old_material_and_bounded_attempts() -> TestResult {
    failure_preserves(AcmeStage::Certificate, AcmeFault::Invalid, "material")
}
#[test]
fn wrong_key_certificate_preserves_old_material_and_bounded_attempts() -> TestResult {
    failure_preserves(AcmeStage::Certificate, AcmeFault::WrongKey, "material")
}

#[test]
fn slow_https_ca_times_out_preserving_old_material_and_shutdown_deadline() -> TestResult {
    let ca = FakeAcmeCa::start()?;
    ca.renew();
    ca.set_fault(AcmeStage::Ari, AcmeFault::Hold);
    let mut server = C2sSuite::managed(&ca)?;
    server.start(&ca)?;
    let a = server.wait_certificate(None)?;
    ca.set_fault(AcmeStage::Certificate, AcmeFault::Hold);
    ca.release(AcmeStage::Ari);
    ca.wait_count(AcmeStage::Certificate, 2)?;
    server.wait_log("ACME certificate will retry")?;
    assert_eq!(peer(&mut server.secure("xmpp.example.test")?)?, a);
    let start = std::time::Instant::now();
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    assert!(start.elapsed() < std::time::Duration::from_secs(30));
    ca.release(AcmeStage::Certificate);
    assert_eq!(
        server
            .records()?
            .1
            .ok_or("record")?
            .certificate
            .ok_or("certificate")?
            .material
            .chain[0],
        a
    );
    Ok(())
}

#[test]
fn expired_material_rejects_new_starttls_while_bound_session_survives_and_renewal_recovers()
-> TestResult {
    use x509_cert::der::Decode;
    let ca = FakeAcmeCa::start()?;
    ca.lifetime(12);
    ca.renew();
    ca.set_fault(AcmeStage::Ari, AcmeFault::Hold);
    let mut server = C2sSuite::managed(&ca)?;
    server.start(&ca)?;
    let a = server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    let certificate = x509_cert::Certificate::from_der(&a)?;
    let expiry = certificate
        .tbs_certificate()
        .validity()
        .not_after
        .to_unix_duration()
        .as_secs();
    let mut bound = authenticate(
        server.secure("xmpp.example.test")?,
        "tls-exporter",
        "expiry-survivor",
    )?;
    ca.lifetime(86_400);
    ca.set_fault(AcmeStage::Certificate, AcmeFault::Hold);
    ca.release(AcmeStage::Ari);
    ca.wait_count(AcmeStage::Certificate, 2)?;
    wait_until(
        || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .is_ok_and(|now| now.as_secs() >= expiry)
        },
        "real certificate expiry",
    )?;
    assert_pending(&server, "xmpp.example.test")?;
    bound.send("<iq type='get' id='after-expiry'><query xmlns='jabber:iq:roster'/></iq>")?;
    assert_eq!(bound.receive()?.attribute("type"), Some("result"));
    ca.release(AcmeStage::Certificate);
    let b = server.wait_certificate(Some(&a))?;
    assert_ne!(a, b);
    let mut recovered = authenticate(
        server.secure("xmpp.example.test")?,
        "tls-exporter",
        "recovered",
    )?;
    recovered.close()?;
    bound.close()?;
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    Ok(())
}

fn interrupted(stage: AcmeStage) -> TestResult {
    let ca = FakeAcmeCa::start()?;
    ca.set_fault(stage, AcmeFault::Hold);
    let mut server = C2sSuite::managed(&ca)?;
    server.enable_clock();
    server.start(&ca)?;
    ca.wait_for(stage)?;
    let frozen = server.freeze_clock()?;
    server.kill()?;
    let (account, host) = server.records()?;
    let before = ca.counts();
    let pending = host.as_ref().and_then(|host| host.order.clone());
    if matches!(
        stage,
        AcmeStage::Authorization
            | AcmeStage::Challenge
            | AcmeStage::Finalize
            | AcmeStage::Certificate
    ) {
        assert!(account.credentials_json.is_some());
        assert!(pending.as_ref().is_some_and(|order| order.url.is_some()));
    }
    if stage == AcmeStage::Account {
        assert!(account.credentials_json.is_none());
    }
    if stage == AcmeStage::NewOrder {
        assert!(pending.as_ref().is_some_and(|order| order.url.is_none()));
    }
    let floor = host.as_ref().map_or(account.retry.not_before_unix, |host| {
        host.retry
            .not_before_unix
            .max(account.retry.not_before_unix)
    });
    let until = std::time::UNIX_EPOCH + std::time::Duration::from_secs(floor);
    assert!(until > frozen.now);
    ca.release(stage);
    server.start(&ca)?;
    let parked = server.parked_clock(0)?;
    assert_eq!(parked.now, frozen.now);
    assert_pending(&server, "xmpp.example.test")?;
    assert_eq!(ca.counts().stages, before.stages);
    let just_before = until - std::time::Duration::from_secs(1);
    let generation = server.advance_clock(just_before)?;
    let parked = server.parked_clock(generation)?;
    assert_eq!(parked.now, just_before);
    assert_pending(&server, "xmpp.example.test")?;
    assert_eq!(ca.counts().stages, before.stages);
    server.advance_clock(until)?;
    server.resume_clock()?;
    let certificate = server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    let mut client = authenticate(
        server.secure("xmpp.example.test")?,
        "tls-exporter",
        "resumed",
    )?;
    client.close()?;
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    let (restored, record) = server.records()?;
    assert_eq!(restored.key_pkcs8, account.key_pkcs8);
    let issued = record
        .ok_or("restored host")?
        .certificate
        .ok_or("restored certificate")?;
    assert_eq!(issued.material.chain[0], certificate);
    if let Some(pending) = pending {
        assert_eq!(issued.material.private_key_pkcs8, pending.key_pkcs8);
        assert!(ca.counts().csrs.iter().all(|csr| csr == &pending.csr_der));
    }
    assert_eq!(ca.counts().accounts.len(), 1);
    assert_eq!(ca.counts().at(AcmeStage::Finalize), 1);
    if stage == AcmeStage::Account {
        assert_eq!(ca.counts().at(AcmeStage::NewOrder), 1);
    } else {
        assert_eq!(
            ca.counts().at(AcmeStage::NewOrder),
            before.at(AcmeStage::NewOrder) + usize::from(stage == AcmeStage::NewOrder)
        );
    }
    Ok(())
}
#[test]
fn kill_at_account_response_reuses_durable_jwk_and_cooldown() -> TestResult {
    interrupted(AcmeStage::Account)
}
#[test]
fn lost_new_order_response_allows_only_one_orphan_and_reuses_key_csr_cooldown() -> TestResult {
    interrupted(AcmeStage::NewOrder)
}
#[test]
fn kill_after_order_url_commit_resumes_same_url_key_csr_account_and_cooldown() -> TestResult {
    interrupted(AcmeStage::Authorization)
}
#[test]
fn kill_at_real_challenge_callback_resumes_durable_order_and_cooldown() -> TestResult {
    interrupted(AcmeStage::Challenge)
}
#[test]
fn kill_at_finalize_resumes_same_csr_order_and_cooldown() -> TestResult {
    interrupted(AcmeStage::Finalize)
}
#[test]
fn kill_before_certificate_download_resumes_committed_order_and_cooldown() -> TestResult {
    interrupted(AcmeStage::Certificate)
}

#[test]
fn kill_after_published_b_restarts_offline_with_the_same_committed_b() -> TestResult {
    let mut ca = FakeAcmeCa::start()?;
    ca.renew();
    ca.set_fault(AcmeStage::Ari, AcmeFault::Hold);
    let mut server = C2sSuite::managed(&ca)?;
    server.start(&ca)?;
    let a = server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    ca.release(AcmeStage::Ari);
    let b = server.wait_certificate(Some(&a))?;
    server.kill()?;
    assert_eq!(
        server
            .records()?
            .1
            .ok_or("host")?
            .certificate
            .ok_or("certificate")?
            .material
            .chain[0],
        b
    );
    ca.offline();
    server.start(&ca)?;
    let mut client = authenticate(
        server.secure("xmpp.example.test")?,
        "tls-server-end-point",
        "published-b",
    )?;
    assert_eq!(peer(&mut client)?, b);
    client.close()?;
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    Ok(())
}

fn sigterm(stage: AcmeStage) -> TestResult {
    let ca = FakeAcmeCa::start()?;
    ca.set_fault(stage, AcmeFault::Hold);
    let mut server = C2sSuite::managed(&ca)?;
    server.start(&ca)?;
    ca.wait_for(stage)?;
    let start = std::time::Instant::now();
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    assert!(start.elapsed() < std::time::Duration::from_secs(30));
    let old = server.records()?;
    let addresses = [server.address, server.challenge];
    for address in addresses {
        let _listener = ports::bind_released_listener(
            address,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )?;
    }
    ca.release(stage);
    server.start(&ca)?;
    assert_pending(&server, "xmpp.example.test")?;
    server.kill()?;
    let restarted = server.records()?;
    assert_eq!(restarted.0.key_pkcs8, old.0.key_pkcs8);
    assert_eq!(
        restarted.0.retry.not_before_unix,
        old.0.retry.not_before_unix
    );
    assert!(
        restarted
            .1
            .as_ref()
            .is_none_or(|host| host.certificate.is_none())
    );
    if let Some(old) = old.1 {
        let new = restarted.1.ok_or("host")?;
        assert_eq!(new.retry.not_before_unix, old.retry.not_before_unix);
        assert_eq!(
            new.order.as_ref().map(|order| &order.key_pkcs8),
            old.order.as_ref().map(|order| &order.key_pkcs8)
        );
    }
    Ok(())
}
#[test]
fn sigterm_during_https_releases_listeners_state_and_prevents_late_activation() -> TestResult {
    sigterm(AcmeStage::Account)
}
#[test]
fn sigterm_during_challenge_releases_listeners_state_and_prevents_late_activation() -> TestResult {
    sigterm(AcmeStage::Challenge)
}
#[test]
fn sigterm_during_finalize_releases_listeners_state_and_prevents_late_activation() -> TestResult {
    sigterm(AcmeStage::Finalize)
}
#[test]
fn sigterm_before_cache_publication_releases_state_and_prevents_late_activation() -> TestResult {
    sigterm(AcmeStage::Certificate)
}

#[test]
fn corrupt_locked_and_insecure_cache_fail_without_reset_or_secret_logs() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let ca = FakeAcmeCa::start()?;
    for mode in ["corrupt", "locked", "insecure"] {
        let mut server = C2sSuite::managed(&ca)?;
        std::fs::create_dir_all(server.path().join("acme"))?;
        let path = server.path().join("acme/state.redb");
        let held = if mode == "locked" {
            Some(server.state()?)
        } else {
            std::fs::write(&path, b"PRIVATE-CORRUPT-CACHE")?;
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(if mode == "insecure" { 0o644 } else { 0o600 }),
            )?;
            None
        };
        let contents = std::fs::read(&path)?;
        server.spawn()?;
        assert!(!server.wait_exit()?.success());
        assert_eq!(std::fs::read(&path)?, contents);
        let logs = server.logs()?;
        assert!(!logs.contains("PRIVATE-CORRUPT-CACHE"));
        assert!(logs.contains("ACME"));
        drop(held);
    }
    assert_eq!(ca.counts().at(AcmeStage::NewOrder), 0);
    Ok(())
}

#[test]
fn ari_rotation_tls12_exporter_keeps_connection_binding_and_generation() -> TestResult {
    rotation(&[&rustls::version::TLS12], "tls-exporter")
}
#[test]
fn ari_rotation_tls13_endpoint_keeps_connection_binding_and_generation() -> TestResult {
    rotation(&[&rustls::version::TLS13], "tls-server-end-point")
}

#[test]
fn two_concurrent_issuance_jobs_leave_a_cached_host_usable_and_activate_all_pending_hosts()
-> TestResult {
    let ca = FakeAcmeCa::start()?;
    let mut server = C2sSuite::managed(&ca)?;
    server.start(&ca)?;
    server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    let mut config = server.config()?;
    for name in ["one.example.test", "two.example.test", "three.example.test"] {
        config.push_str(&format!(
            "\n[hosts.\"{name}\".tls]\nprovider='letsencrypt'\n"
        ));
    }
    server.replace_config(&config)?;
    ca.set_fault(AcmeStage::Challenge, AcmeFault::Hold);
    server.start(&ca)?;
    ca.wait_count(AcmeStage::Challenge, 3).map_err(|error| {
        format!(
            "{error}; {}",
            server
                .logs()
                .unwrap_or_default()
                .lines()
                .filter(|line| line.contains("ACME"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    })?;
    assert_eq!(ca.counts().at(AcmeStage::NewOrder), 3);
    assert_eq!(ca.counts().callbacks.len(), 3);
    let mut healthy = authenticate(
        server.secure("xmpp.example.test")?,
        "tls-exporter",
        "two-jobs",
    )?;
    healthy.close()?;
    assert_eq!(ca.counts().at(AcmeStage::NewOrder), 3);
    ca.release(AcmeStage::Challenge);
    for name in ["one.example.test", "two.example.test", "three.example.test"] {
        wait_until(
            || server.secure(name).is_ok(),
            "concurrent pending host activation",
        )?;
        server.account(name)?;
        let mut client = server.secure(name)?;
        client.authenticate("alice", PASSWORD)?;
    }
    assert_eq!(ca.counts().at(AcmeStage::NewOrder), 4);
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    Ok(())
}

#[test]
fn occupied_automatic_endpoint_retries_once_without_ca_or_cache_effects_then_authenticates()
-> TestResult {
    let ca = FakeAcmeCa::start()?;
    let mut server = C2sSuite::managed(&ca)?;
    let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = occupied.local_addr()?;
    server.replace_config(&server.config()?.replace(
        &format!("listen = [\"{}\"]", server.challenge),
        &format!("listen = [\"{address}\"]"),
    ))?;
    server.challenge = address;
    server.start(&ca)?;
    assert_eq!(server.setup_retries, 1);
    assert_eq!(server.launch_count, 2);
    assert_eq!(server.setup_failures.len(), 1);
    let failed = &server.setup_failures[0];
    assert!(failed.ca_unchanged && failed.state_unchanged);
    assert_eq!(
        failed.logs.lines().last(),
        Some("ACME HTTP bind failed: ACME listener operation failed")
    );
    assert_eq!(
        std::fs::read_to_string(server.path().join("startup-failure-1.log"))?,
        failed.logs
    );
    assert_ne!(server.challenge, address);
    server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    let mut client = authenticate(
        server.secure("xmpp.example.test")?,
        "tls-exporter",
        "after-setup-retry",
    )?;
    client.close()?;
    assert_eq!(ca.counts().at(AcmeStage::Account), 1);
    assert_eq!(ca.counts().at(AcmeStage::NewOrder), 1);
    assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
    Ok(())
}

#[test]
fn automatic_setup_does_not_retry_port_zero_or_corrupt_locked_insecure_cache() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let ca = FakeAcmeCa::start()?;
    for mode in ["port-zero", "corrupt", "locked", "insecure"] {
        let mut server = C2sSuite::managed(&ca)?;
        let path = server.path().join("acme/state.redb");
        let held = if mode == "locked" {
            Some(server.state()?)
        } else {
            None
        };
        if mode == "port-zero" {
            server.replace_config(&server.config()?.replace(
                &format!("listen = [\"{}\"]", server.challenge),
                "listen = [\"127.0.0.1:0\"]",
            ))?;
        } else if mode != "locked" {
            std::fs::create_dir_all(server.path().join("acme"))?;
            std::fs::write(&path, b"PRIVATE-CORRUPT-CACHE")?;
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(if mode == "insecure" { 0o644 } else { 0o600 }),
            )?;
        }
        assert!(server.start(&ca).is_err(), "{mode}");
        assert_eq!(server.launch_count, 1);
        assert_eq!(server.setup_retries, 0);
        assert_eq!(server.setup_failures.len(), 1);
        assert!(server.setup_failures[0].ca_unchanged);
        assert!(server.setup_failures[0].state_unchanged);
        assert!(!server.path().join("startup-failure-2.log").exists());
        drop(held);
    }
    assert_eq!(ca.counts().at(AcmeStage::NewOrder), 0);
    Ok(())
}

#[test]
fn automatic_setup_never_restarts_a_child_after_readiness() -> TestResult {
    let ca = FakeAcmeCa::start()?;
    let mut server = C2sSuite::managed(&ca)?;
    server.start(&ca)?;
    server.wait_certificate(None)?;
    server.account("xmpp.example.test")?;
    let mut client = authenticate(
        server.secure("xmpp.example.test")?,
        "tls-exporter",
        "before-crash",
    )?;
    client.close()?;
    let launches = server.launch_count;
    let retries = server.setup_retries;
    server.kill()?;
    assert_eq!(server.launch_count, launches);
    assert_eq!(server.setup_retries, retries);
    assert!(server.records()?.1.ok_or("host")?.certificate.is_some());
    Ok(())
}

#[test]
fn twenty_bootstraps_under_concurrent_tcp_activity_cover_proxy_ipv6_and_cached_restart()
-> TestResult {
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|worker| {
                scope.spawn(move || -> Result<(usize, usize), String> {
                    (|| -> TestResult<(usize, usize)> {
                        let mut retries = 0;
                        let mut ipv6 = 0;
                        for round in 0..5 {
                            let number = worker * 5 + round;
                            let mut ca = FakeAcmeCa::start()?;
                            let mut server = C2sSuite::managed(&ca)?;
                            if number % 5 == 1 {
                                match std::net::TcpListener::bind("[::1]:0") {
                                    Ok(listener) => {
                                        server.reserve_listener(listener)?;
                                        ipv6 += 1;
                                    }
                                    Err(error)
                                        if matches!(
                                            error.kind(),
                                            std::io::ErrorKind::AddrNotAvailable
                                                | std::io::ErrorKind::Unsupported
                                        ) =>
                                    {
                                        eprintln!("IPv6 stress branch unavailable: {error}")
                                    }
                                    Err(error) => return Err(error.into()),
                                }
                            }
                            let proxy = if number % 5 == 0 {
                                Some(support::ChallengeProxy::start(server.challenge)?)
                            } else {
                                None
                            };
                            if let Some(proxy) = &proxy {
                                ca.callback(proxy.address);
                                server
                                    .start_with_route(&ca, |address| proxy.set_target(address))?;
                            } else {
                                server.start(&ca)?;
                            }
                            let certificate = server.wait_certificate(None)?;
                            server.account("xmpp.example.test")?;
                            let mut client = authenticate(
                                server.secure("xmpp.example.test")?,
                                "tls-exporter",
                                "stress",
                            )?;
                            client.close()?;
                            assert_eq!(ca.counts().callbacks.len(), 1);
                            if let Some(proxy) = &proxy {
                                assert_eq!(proxy.requests.lock().len(), 1);
                            }
                            assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
                            if number % 5 == 2 {
                                let account = server.records()?.0.key_pkcs8;
                                ca.offline();
                                server.start(&ca)?;
                                let mut client = authenticate(
                                    server.secure("xmpp.example.test")?,
                                    "tls-server-end-point",
                                    "stress-restart",
                                )?;
                                assert_eq!(peer(&mut client)?, certificate);
                                client.close()?;
                                assert!(server.stop(nix::sys::signal::Signal::SIGTERM)?.success());
                                assert_eq!(server.records()?.0.key_pkcs8, account);
                            }
                            retries += server.setup_retries;
                        }
                        Ok((retries, ipv6))
                    })()
                    .map_err(|error| error.to_string())
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join())
            .collect::<Vec<_>>()
    });
    let mut retries = 0;
    let mut ipv6 = 0;
    for result in results {
        let (worker_retries, worker_ipv6) =
            result.map_err(|_| "startup stress worker panicked")??;
        retries += worker_retries;
        ipv6 += worker_ipv6;
    }
    eprintln!(
        "ACME startup stress passed: bootstrap_launches=20 cached_restarts=4 proxy_routes=4 ipv6_routes={ipv6} setup_retries={retries}"
    );
    Ok(())
}
