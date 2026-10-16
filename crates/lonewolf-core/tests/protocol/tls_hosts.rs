// SPDX-License-Identifier: Apache-2.0

use crate::support::ALTERNATE_PASSWORD;

use std::io::Write;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;

use super::support::{BIND_NAMESPACE, C2sSuite, SASL_NAMESPACE, TLS_NAMESPACE, TestResult, tls};

fn host_suite(domain: &str, certificate_identity: &str) -> TestResult<(C2sSuite, ClientConfig)> {
    let hosts = format!(
        "[hosts.{domain:?}.tls]\ncertificate_chain_path = 'certificate-host.pem'\nprivate_key_path = 'private-key-host.pem'\n[hosts.'other.localhost'.tls]\ncertificate_chain_path = 'certificate.pem'\nprivate_key_path = 'private-key.pem'"
    );
    let mut roots = None;
    let suite = C2sSuite::with_hosts_and_setup(&hosts, |directory| {
        roots = Some(tls::configure_host(
            directory,
            "-host",
            &[certificate_identity, "unrelated.example"],
        )?);
        Ok(())
    })?;
    let config = tls::client_config(
        roots.ok_or("missing host trust root")?,
        rustls::DEFAULT_VERSIONS,
    )?;
    Ok((suite, config))
}

fn opening(domain: &str) -> String {
    format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='{domain}' version='1.0'>"
    )
}

#[test]
fn idn_alabel_sni_retains_unicode_stream_and_bound_jid() -> TestResult {
    let domain = "bücher.example";
    let (mut suite, config) = host_suite(domain, "xn--bcher-kva.example")?;
    suite.create_account_jid("alice@bücher.example", ALTERNATE_PASSWORD)?;
    for (identity, sni) in [
        ("xn--bcher-kva.example", true),
        ("XN--BCHER-KVA.EXAMPLE", true),
        ("xn--bcher-kva.example", false),
    ] {
        let mut config = config.clone();
        config.enable_sni = sni;
        let mut plain = suite.tcp_client()?;
        assert_eq!(
            plain.open_with(&opening(domain))?.attribute("from"),
            Some(domain)
        );
        plain.features()?.child(TLS_NAMESPACE, "starttls")?;
        let mut client =
            plain.start_tls_with_identity(Arc::new(config), ServerName::try_from(identity)?)?;
        assert_eq!(
            client.open_with(&opening(domain))?.attribute("from"),
            Some(domain)
        );
        client.features()?.child(SASL_NAMESPACE, "mechanisms")?;
        client.authenticate("alice", ALTERNATE_PASSWORD)?;
        let mut client = client.restart();
        assert_eq!(
            client.open_with(&opening(domain))?.attribute("from"),
            Some(domain)
        );
        client.features()?.child(BIND_NAMESPACE, "bind")?;
        assert_eq!(client.bind(Some("desk"))?, "alice@bücher.example/desk");
        client.close()?;
    }
    suite.stop()
}

#[test]
fn ipv4_reference_identity_without_sni_authenticates_and_binds() -> TestResult {
    let domain = "192.0.2.1";
    let (mut suite, config) = host_suite(domain, domain)?;
    suite.create_account_jid("alice@192.0.2.1", ALTERNATE_PASSWORD)?;
    let mut plain = suite.tcp_client()?;
    assert_eq!(
        plain.open_with(&opening(domain))?.attribute("from"),
        Some(domain)
    );
    plain.features()?.child(TLS_NAMESPACE, "starttls")?;
    let mut client =
        plain.start_tls_with_identity(Arc::new(config), ServerName::try_from(domain)?)?;
    client.open_with(&opening(domain))?;
    client.features()?.child(SASL_NAMESPACE, "mechanisms")?;
    client.authenticate("alice", ALTERNATE_PASSWORD)?;
    let mut client = client.restart();
    client.open_with(&opening(domain))?;
    client.features()?.child(BIND_NAMESPACE, "bind")?;
    assert_eq!(client.bind(Some("desk"))?, "alice@192.0.2.1/desk");
    client.close()?;
    suite.stop()
}

#[test]
fn ipv6_reference_identity_without_sni_authenticates_and_binds() -> TestResult {
    let domain = "[2001:db8::1]";
    let (mut suite, config) = host_suite(domain, "2001:db8::1")?;
    suite.create_account_jid("alice@[2001:db8::1]", ALTERNATE_PASSWORD)?;
    let mut plain = suite.tcp_client()?;
    assert_eq!(
        plain.open_with(&opening(domain))?.attribute("from"),
        Some(domain)
    );
    plain.features()?.child(TLS_NAMESPACE, "starttls")?;
    let mut client =
        plain.start_tls_with_identity(Arc::new(config), ServerName::try_from("2001:db8::1")?)?;
    client.open_with(&opening(domain))?;
    client.features()?.child(SASL_NAMESPACE, "mechanisms")?;
    client.authenticate("alice", ALTERNATE_PASSWORD)?;
    let mut client = client.restart();
    client.open_with(&opening(domain))?;
    client.features()?.child(BIND_NAMESPACE, "bind")?;
    assert_eq!(client.bind(Some("desk"))?, "alice@[2001:db8::1]/desk");
    client.close()?;
    suite.stop()
}

#[test]
fn selected_idn_and_ip_hosts_reject_unrelated_sni() -> TestResult {
    for (domain, reference) in [
        ("bücher.example", "xn--bcher-kva.example"),
        ("192.0.2.1", "192.0.2.1"),
        ("[2001:db8::1]", "2001:db8::1"),
    ] {
        let (mut suite, config) = host_suite(domain, reference)?;
        let mut plain = suite.tcp_client()?;
        plain.open_with(&opening(domain))?;
        plain.features()?;
        let mut client = plain.start_tls_with_identity(
            Arc::new(config),
            ServerName::try_from("unrelated.example")?,
        )?;
        assert!(client.transport().flush().is_err() || client.open_with(&opening(domain)).is_err());
        suite.wait_for_log("outcome=\"tls_failure\"")?;
        let mut selected = suite.unauthenticated_client()?;
        selected.close()?;
        suite.stop()?;
    }
    Ok(())
}

#[test]
fn selected_dns_hosts_keep_case_insensitive_and_absent_sni_policy() -> TestResult {
    let mut suite = C2sSuite::with_hosts(
        "[hosts.'other.localhost'.tls]\ncertificate_chain_path = 'certificate.pem'\nprivate_key_path = 'private-key.pem'",
    )?;
    suite.create_account_jid("alice@other.localhost", ALTERNATE_PASSWORD)?;
    for (domain, identity, sni) in [
        ("localhost", "LOCALHOST", true),
        ("other.localhost", "OTHER.LOCALHOST", true),
        ("other.localhost", "other.localhost", false),
    ] {
        let mut config = (*suite.tls).clone();
        config.enable_sni = sni;
        let mut plain = suite.tcp_client()?;
        plain.open_with(&opening(domain))?;
        plain.features()?.child(TLS_NAMESPACE, "starttls")?;
        let mut client =
            plain.start_tls_with_identity(Arc::new(config), ServerName::try_from(identity)?)?;
        client.open_with(&opening(domain))?;
        client.features()?.child(SASL_NAMESPACE, "mechanisms")?;
        if domain == "other.localhost" {
            client.authenticate("alice", ALTERNATE_PASSWORD)?;
            let mut bound = client.restart();
            bound.open_with(&opening(domain))?;
            bound.features()?.child(BIND_NAMESPACE, "bind")?;
            assert_eq!(bound.bind(Some("desk"))?, "alice@other.localhost/desk");
            bound.close()?;
        } else {
            client.close()?;
        }
    }
    suite.stop()
}

#[test]
fn pending_managed_host_rejects_starttls_before_proceed_without_disrupting_file_host() -> TestResult
{
    let directory_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    directory_listener.set_nonblocking(true)?;
    let directory_url = format!("https://{}/directory", directory_listener.local_addr()?);
    let http_reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let hosts = format!(
        "[hosts.'example.com'.tls]\nprovider = 'letsencrypt'\n[letsencrypt]\nlisten = ['{}']\nstate_path = 'acme.redb'\ndirectory_url = '{directory_url}'",
        http_reservation.local_addr()?,
    );
    let mut suite = C2sSuite::with_hosts_and_setup(&hosts, |directory| {
        let not_before_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            .checked_add(86_400)
            .ok_or("retry deadline overflow")?;
        compio::runtime::Runtime::new()?.block_on(async {
            let store =
                lonewolf_acme::StateStore::open(directory.join("acme.redb"), directory_url).await?;
            store
                .save_host(lonewolf_acme::StoredHost {
                    host: lonewolf_acme::ManagedHost {
                        xmpp_domain: "example.com".into(),
                        dns_name: "example.com".into(),
                    },
                    certificate: None,
                    order: None,
                    retry: lonewolf_acme::RetryState {
                        failures: 1,
                        not_before_unix,
                    },
                })
                .await?;
            store
                .drain(std::time::Instant::now() + std::time::Duration::from_secs(5))
                .await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        drop(http_reservation);
        Ok(())
    })?;
    let mut pending = suite.tcp_client()?;
    pending.open_with(&opening("example.com"))?;
    pending.features()?.child(TLS_NAMESPACE, "starttls")?;
    pending.send(&format!("<starttls xmlns='{TLS_NAMESPACE}'/>"))?;
    pending.receive()?.assert_name(TLS_NAMESPACE, "failure");
    pending.expect_footer()?;
    pending.send("</stream:stream>")?;
    pending.expect_eof()?;
    suite.wait_for_log("outcome=\"starttls_rejected\"")?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut healthy = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    healthy.close()?;
    suite.stop()?;
    assert!(
        matches!(directory_listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}
