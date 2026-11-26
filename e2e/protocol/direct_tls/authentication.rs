// SPDX-License-Identifier: Apache-2.0

use super::*;
use rustls::{HandshakeKind, pki_types::ServerName, version};
use std::sync::Arc;

#[test]
fn direct_tls_plus_tls12_ems_tls13_exporter_endpoint_and_wrong_binding_matrix() -> TestResult {
    let mut suite = C2sSuite::with_listener_setup(
        "tls_mode='direct'\nauth_mechanisms=['SCRAM-SHA-512-PLUS','SCRAM-SHA-256-PLUS','SCRAM-SHA-256']",
        "",
        "[hosts.localhost]\nextensions=[]",
        |_| Ok(()),
    )?;
    suite.create_account("alice", PASSWORD)?;
    for version in [&version::TLS12, &version::TLS13] {
        for binding in ["tls-exporter", "tls-server-end-point"] {
            for mechanism in ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-512-PLUS"] {
                let mut config = (*suite.tls_with_versions(&[version])?).clone();
                config.require_ems = true;
                config.alpn_protocols = vec![b"xmpp-client".to_vec()];
                let config = Arc::new(config);
                let mut client = Client::direct_tls_with_config(
                    suite.address,
                    Arc::clone(&config),
                    ServerName::try_from("localhost")?,
                )?;
                let features = client.open()?;
                features.assert_xml("<stream:features xmlns:stream='http://etherx.jabber.org/streams'><sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/><channel-binding type='tls-exporter'/></sasl-channel-binding><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-512-PLUS</mechanism><mechanism>SCRAM-SHA-256-PLUS</mechanism><mechanism>SCRAM-SHA-256</mechanism></mechanisms></stream:features>")?;
                assert_eq!(
                    client.transport().conn.protocol_version(),
                    Some(version.version)
                );
                assert_eq!(
                    client.transport().conn.handshake_kind(),
                    Some(HandshakeKind::Full)
                );
                let wrong = client.begin_scram_with_channel_binding(
                    "alice",
                    PASSWORD,
                    mechanism,
                    binding,
                    &[0xa5; 32],
                )?;
                client.finish_scram(wrong)?.assert_xml(
                    "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
                )?;
                client.close()?;
                let mut client = Client::direct_tls_with_config(
                    suite.address,
                    config,
                    ServerName::try_from("localhost")?,
                )?;
                client.open()?.child(SASL_NAMESPACE, "mechanisms")?;
                client
                    .scram("alice", PASSWORD, mechanism, Some(binding))?
                    .assert_name(SASL_NAMESPACE, "success");
                let mut client = client.restart();
                client.open()?.assert_xml(BIND_FEATURES)?;
                assert_eq!(client.bind(Some("plus"))?, "alice@localhost/plus");
                client.send("<message to='alice@localhost/plus' type='chat' id='integrity'><body>Verified</body></message>")?;
                client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/plus' to='alice@localhost/plus' type='chat' id='integrity'><body>Verified</body></message>")?;
                client.close()?;
            }
        }
    }
    for mechanism in ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-512-PLUS"] {
        for outcome in ["success", "not_authorized"] {
            suite.wait_for_metric(&format!("lonewolf_c2s_authentications_total{{listener=\"0\",mechanism=\"{mechanism}\",outcome=\"{outcome}\"}} 4"))?;
        }
    }
    suite.wait_for_metric(
        "lonewolf_c2s_resource_bindings_total{listener=\"0\",outcome=\"success\"} 8",
    )?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}

#[test]
fn direct_tls_default_sha512_plus_exclusion_preserves_scram256_login() -> TestResult {
    let mut suite = C2sSuite::with_listener_setup(
        "tls_mode='direct'",
        "",
        "[hosts.localhost]\nextensions=[]",
        |_| Ok(()),
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut client = Client::direct_tls(&suite)?;
    client.open()?.assert_xml(DEFAULT_FEATURES)?;
    client.send_sasl_auth("SCRAM-SHA-512-PLUS", "p=tls-exporter,,n=alice,r=nonce")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
    )?;
    client.authenticate("alice", PASSWORD)?;
    let mut client = client.restart();
    client.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(client.bind(Some("default"))?, "alice@localhost/default");
    client.close()?;
    suite.wait_for_metric("lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"none\",outcome=\"invalid_mechanism\"} 1")?;
    suite.wait_for_metric("lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256\",outcome=\"success\"} 1")?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}

fn certificate_fixture() -> TestResult<(C2sSuite, crate::support::tls::ClientCertificates)> {
    let mut certificates = None;
    let suite = C2sSuite::with_listener_setup(
        "tls_mode='direct'",
        "",
        "[hosts.localhost]\nextensions=[]",
        |directory| {
            certificates = Some(crate::support::tls::ClientCertificates::configure(
                directory,
            )?);
            Ok(())
        },
    )?;
    Ok((suite, certificates.ok_or("missing client certificates")?))
}

#[test]
fn direct_tls_external_account_authzid_forms_and_optional_certificate_scram() -> TestResult {
    use crate::support::tls::with_client_certificate;
    let (mut suite, certificates) = certificate_fixture()?;
    suite.create_account("alice", PASSWORD)?;
    for key in [None, Some(Arc::clone(&certificates.without_xmpp_addr))] {
        let config = key.map_or_else(
            || Arc::clone(&suite.tls),
            |key| with_client_certificate(&suite.tls, key),
        );
        let mut client = Client::direct_tls_with_config(
            suite.address,
            config,
            ServerName::try_from("localhost")?,
        )?;
        client.open()?.assert_xml(DEFAULT_FEATURES)?;
        client.send_external_auth(Some("alice@localhost"))?;
        client.expect_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
        )?;
        client.authenticate("alice", PASSWORD)?;
        let mut client = client.restart();
        client.open()?.assert_xml(BIND_FEATURES)?;
        assert_eq!(client.bind(Some("password"))?, "alice@localhost/password");
        client.close()?;
    }
    for authzid in [Some("Alice@LOCALHOST"), Some(""), None] {
        let config = with_client_certificate(&suite.tls, Arc::clone(&certificates.trusted));
        let mut client = Client::direct_tls_with_config(
            suite.address,
            config,
            ServerName::try_from("localhost")?,
        )?;
        client.open()?.assert_xml(EXTERNAL_FEATURES)?;
        client.send_external_auth(authzid)?;
        if authzid.is_none() {
            client.expect_xml("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
            client.send_sasl_response("")?;
        }
        client.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
        let mut client = client.restart();
        client.open()?.assert_xml(BIND_FEATURES)?;
        assert_eq!(client.bind(Some("external"))?, "alice@localhost/external");
        client.send("<message to='alice@localhost/external' type='chat' id='external-direct'><body>Certificate</body></message>")?;
        client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/external' to='alice@localhost/external' type='chat' id='external-direct'><body>Certificate</body></message>")?;
        client.close()?;
    }
    for sample in [
        "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"EXTERNAL\",outcome=\"success\"} 3",
        "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256\",outcome=\"success\"} 2",
        "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"none\",outcome=\"invalid_mechanism\"} 2",
        "lonewolf_c2s_resource_bindings_total{listener=\"0\",outcome=\"success\"} 5",
        "lonewolf_c2s_connections{listener=\"0\"} 0",
        "lonewolf_c2s_unauthenticated_connections 0",
        "lonewolf_router_sessions 0",
    ] {
        suite.wait_for_metric(sample)?;
    }
    suite.stop()
}

#[test]
fn direct_tls_external_denies_unauthorized_authzid_and_unprovisioned_identity() -> TestResult {
    use crate::support::tls::with_client_certificate;
    let (mut suite, certificates) = certificate_fixture()?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let ghost = certificates.identity_key(
        &["ghost@localhost"],
        time::OffsetDateTime::now_utc() + time::Duration::days(1),
    )?;
    for (key, authzid, failure) in [
        (certificates.trusted, "bob@localhost", "invalid-authzid"),
        (ghost, "", "not-authorized"),
    ] {
        let mut client = Client::direct_tls_with_config(
            suite.address,
            with_client_certificate(&suite.tls, key),
            ServerName::try_from("localhost")?,
        )?;
        client.open()?.assert_xml(EXTERNAL_FEATURES)?;
        client.send_external_auth(Some(authzid))?;
        client.expect_xml(&format!(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><{failure}/></failure>"
        ))?;
        client.close()?;
    }
    for outcome in ["invalid_authzid", "not_authorized"] {
        suite.wait_for_metric(&format!("lonewolf_c2s_authentications_total{{listener=\"0\",mechanism=\"EXTERNAL\",outcome=\"{outcome}\"}} 1"))?;
    }
    let body = suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    assert!(
        !body.contains("lonewolf_c2s_resource_bindings_total"),
        "{body}"
    );
    suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}

#[test]
fn direct_tls_invalid_presented_certificate_is_not_silently_ignored() -> TestResult {
    use crate::support::tls::with_client_certificate;
    use std::io::Read;
    let (mut suite, certificates) = certificate_fixture()?;
    let key = certificates
        .rejected
        .into_iter()
        .find_map(|(name, key)| (name == "untrusted").then_some(key))
        .ok_or("missing untrusted certificate")?;
    let mut client = Client::direct_tls_with_config(
        suite.address,
        with_client_certificate(&suite.tls, key),
        ServerName::try_from("localhost")?,
    )?;
    let error = match client.complete_tls() {
        Err(error) => error,
        Ok(()) => match client.transport().read(&mut [0; 1]) {
            Err(error) => error,
            Ok(_) => return Err("invalid certificate accepted".into()),
        },
    };
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof, "{error:?}");
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"establishing\",outcome=\"tls_failure\"} 1")?;
    let body = suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    assert!(!body.contains("lonewolf_c2s_authentications_total"));
    suite.wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    suite.stop()
}
