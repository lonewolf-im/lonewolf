// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::support::OPEN;
use crate::support::tls::{self, ClientCertificates, with_client_certificate};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::sync::Arc;

const NO_TO: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>";
struct HostFixture {
    suite: C2sSuite,
    first: ClientCertificates,
    second: ClientCertificates,
    idn_tls: Arc<rustls::ClientConfig>,
    localhost_certificate: CertificateDer<'static>,
    idn_certificate: CertificateDer<'static>,
}
fn fixture() -> TestResult<HostFixture> {
    let mut first = None;
    let mut second = None;
    let mut roots = None;
    let hosts = "[hosts.localhost]\nextensions=[]\n[hosts.'bücher.example']\nextensions=[]\n[hosts.'bücher.example'.tls]\ncertificate_chain_path='certificate-idn.pem'\nprivate_key_path='private-key-idn.pem'\n[hosts.'bücher.example'.tls.client_auth]\ntrust_anchors_path='idn/client-roots.pem'\ncrls_path='idn/client-crls.pem'";
    let suite = C2sSuite::with_listener_setup("tls_mode='direct'", "", hosts, |directory| {
        roots = Some(tls::configure_host(
            directory,
            "-idn",
            &["xn--bcher-kva.example"],
        )?);
        first = Some(ClientCertificates::configure(directory)?);
        let idn = directory.join("idn");
        std::fs::create_dir(&idn)?;
        std::fs::write(idn.join("lonewolf.toml"), "")?;
        second = Some(ClientCertificates::configure(&idn)?);
        Ok(())
    })?;
    let localhost_certificate =
        CertificateDer::from_pem_file(suite.fixture_path().join("certificate.pem"))?;
    let idn_certificate =
        CertificateDer::from_pem_file(suite.fixture_path().join("certificate-idn.pem"))?;
    assert_ne!(localhost_certificate, idn_certificate);
    let idn_tls = Arc::new(tls::client_config(
        roots.ok_or("missing IDN roots")?,
        rustls::DEFAULT_VERSIONS,
    )?);
    Ok(HostFixture {
        suite,
        first: first.ok_or("missing first policy")?,
        second: second.ok_or("missing second policy")?,
        idn_tls,
        localhost_certificate,
        idn_certificate,
    })
}

#[test]
fn direct_tls_two_host_certificates_policies_idna_case_and_omitted_to_survive_restart() -> TestResult
{
    let mut fixture = fixture()?;
    fixture.suite.create_account("alice", PASSWORD)?;
    fixture
        .suite
        .create_account_jid("alice@bücher.example", PASSWORD)?;
    let second_key = fixture.second.identity_key(
        &["alice@bücher.example"],
        time::OffsetDateTime::now_utc() + time::Duration::days(1),
    )?;
    for (sni, domain, config, certificate) in [
        (
            "LOCALHOST",
            "localhost",
            with_client_certificate(&fixture.suite.tls, Arc::clone(&fixture.first.trusted)),
            &fixture.localhost_certificate,
        ),
        (
            "XN--BCHER-KVA.EXAMPLE",
            "bücher.example",
            with_client_certificate(&fixture.idn_tls, second_key),
            &fixture.idn_certificate,
        ),
    ] {
        let mut client = Client::direct_tls_with_config(
            fixture.suite.address,
            config,
            ServerName::try_from(sni)?,
        )?;
        client.complete_tls()?;
        assert_eq!(
            client
                .transport()
                .conn
                .peer_certificates()
                .ok_or("missing peer certificate")?[0],
            *certificate
        );
        let header = client.open_with(NO_TO)?;
        assert_eq!(header.attribute("from"), Some(domain));
        assert_eq!(header.attribute("version"), Some("1.0"));
        client.features()?.assert_xml(EXTERNAL_FEATURES)?;
        client.send_external_auth(Some(&format!("alice@{domain}")))?;
        client.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
        let mut client = client.restart();
        assert_eq!(client.open_with(NO_TO)?.attribute("from"), Some(domain));
        client.features()?.assert_xml(BIND_FEATURES)?;
        assert_eq!(
            client.bind(Some("selected"))?,
            format!("alice@{domain}/selected")
        );
        client.send(&format!("<message to='alice@{domain}/selected' type='chat' id='selected'><body>Selected host</body></message>"))?;
        client.expect_xml(&format!("<message xmlns='jabber:client' from='alice@{domain}/selected' to='alice@{domain}/selected' type='chat' id='selected'><body>Selected host</body></message>"))?;
        client.close()?;
    }
    fixture.suite.wait_for_metric("lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"EXTERNAL\",outcome=\"success\"} 2")?;
    fixture.suite.wait_for_metric(
        "lonewolf_c2s_resource_bindings_total{listener=\"0\",outcome=\"success\"} 2",
    )?;
    fixture
        .suite
        .wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_router_sessions 0")?;
    fixture.suite.stop()
}

#[test]
fn direct_tls_two_host_client_trust_policies_reject_cross_signed_credentials() -> TestResult {
    use std::io::Read;
    let mut fixture = fixture()?;
    let second_key = fixture.second.identity_key(
        &["alice@localhost"],
        time::OffsetDateTime::now_utc() + time::Duration::days(1),
    )?;
    for (sni, config) in [
        (
            "localhost",
            with_client_certificate(&fixture.suite.tls, second_key),
        ),
        (
            "xn--bcher-kva.example",
            with_client_certificate(&fixture.idn_tls, Arc::clone(&fixture.first.trusted)),
        ),
    ] {
        let mut client = Client::direct_tls_with_config(
            fixture.suite.address,
            config,
            ServerName::try_from(sni)?,
        )?;
        let error = match client.complete_tls() {
            Err(error) => error,
            Ok(()) => match client.transport().read(&mut [0; 1]) {
                Err(error) => error,
                Ok(_) => return Err("cross-host client policy accepted".into()),
            },
        };
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof, "{error:?}");
    }
    fixture.suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"establishing\",outcome=\"tls_failure\"} 2")?;
    let body = fixture
        .suite
        .wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    assert!(!body.contains("lonewolf_c2s_authentications_total"));
    fixture
        .suite
        .wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    fixture.suite.stop()
}

#[test]
fn direct_tls_sni_to_mismatch_and_sasl_restart_host_switch_never_bind_another_host() -> TestResult {
    let mut fixture = fixture()?;
    fixture
        .suite
        .create_account_jid("alice@bücher.example", PASSWORD)?;
    let mut client = Client::direct_tls_with_config(
        fixture.suite.address,
        Arc::clone(&fixture.idn_tls),
        ServerName::try_from("xn--bcher-kva.example")?,
    )?;
    assert_eq!(
        client.open_with(OPEN)?.attribute("from"),
        Some("bücher.example")
    );
    client.expect_stream_error("host-unknown")?;
    fixture.suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"establishing\",outcome=\"host_unknown\"} 1")?;
    let mut client = Client::direct_tls_with_config(
        fixture.suite.address,
        Arc::clone(&fixture.idn_tls),
        ServerName::try_from("xn--bcher-kva.example")?,
    )?;
    assert_eq!(
        client.open_with(NO_TO)?.attribute("from"),
        Some("bücher.example")
    );
    client.features()?.assert_xml(DEFAULT_FEATURES)?;
    client.authenticate("alice", PASSWORD)?;
    let mut client = client.restart();
    assert_eq!(
        client.open_with(OPEN)?.attribute("from"),
        Some("bücher.example")
    );
    client.expect_stream_error("host-unknown")?;
    fixture.suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"binding\",outcome=\"host_unknown\"} 1")?;
    fixture.suite.wait_for_metric("lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256\",outcome=\"success\"} 1")?;
    let body = fixture
        .suite
        .wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    assert!(!body.contains("lonewolf_c2s_resource_bindings_total"));
    fixture
        .suite
        .wait_for_metric("lonewolf_router_sessions 0")?;
    fixture.suite.stop()
}
