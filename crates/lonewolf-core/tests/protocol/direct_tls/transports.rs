// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::support::PlainClient;
use rustls::pki_types::ServerName;
use std::sync::Arc;

#[test]
fn direct_tls_and_starttls_parallel_listeners_keep_distinct_profiles_and_mechanisms() -> TestResult
{
    let hosts = "[[c2s.listeners]]\naddress='127.0.0.1:0'\ntls_mode='direct'\nlimits='direct'\nauth_mechanisms=['SCRAM-SHA-512-PLUS']\n[limits.c2s.profiles.direct]\nmax_stanza_bytes=20000\n[hosts.localhost]\nextensions=[]";
    let mut suite = C2sSuite::with_listener_setup(
        "auth_mechanisms=['SCRAM-SHA-256']",
        "max_stanza_bytes=10000",
        hosts,
        |_| Ok(()),
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut plain = PlainClient::tcp(&suite)?;
    plain.open()?.assert_xml("<stream:features xmlns:stream='http://etherx.jabber.org/streams'><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>")?;
    let mut legacy = plain.start_tls(&suite)?;
    legacy.open()?.assert_xml("<stream:features xmlns:stream='http://etherx.jabber.org/streams'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-256</mechanism></mechanisms></stream:features>")?;
    legacy.send_sasl_auth("SCRAM-SHA-512-PLUS", "p=tls-exporter,,n=alice,r=nonce")?;
    legacy.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
    )?;
    legacy.authenticate("alice", PASSWORD)?;
    let mut legacy = legacy.restart();
    legacy.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(legacy.bind(Some("legacy"))?, "alice@localhost/legacy");
    let mut config = (*suite.tls).clone();
    config.alpn_protocols = vec![b"xmpp-client".to_vec()];
    let mut direct = Client::direct_tls_with_config(
        suite.listener_address(1)?,
        Arc::new(config),
        ServerName::try_from("localhost")?,
    )?;
    direct.open()?.assert_xml("<stream:features xmlns:stream='http://etherx.jabber.org/streams'><sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/><channel-binding type='tls-exporter'/></sasl-channel-binding><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-512-PLUS</mechanism></mechanisms></stream:features>")?;
    direct.send_sasl_auth("SCRAM-SHA-256", "n,,n=alice,r=nonce")?;
    direct.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
    )?;
    direct
        .scram(
            "alice",
            PASSWORD,
            "SCRAM-SHA-512-PLUS",
            Some("tls-exporter"),
        )?
        .assert_name(SASL_NAMESPACE, "success");
    let mut direct = direct.restart();
    direct.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(direct.bind(Some("direct"))?, "alice@localhost/direct");
    legacy.send("<message to='alice@localhost/direct' type='chat' id='parallel'><body>Legacy to direct</body></message>")?;
    direct.expect_xml("<message xmlns='jabber:client' from='alice@localhost/legacy' to='alice@localhost/direct' type='chat' id='parallel'><body>Legacy to direct</body></message>")?;
    direct.send("<message to='alice@localhost/legacy' type='chat' id='parallel-back'><body>Direct to legacy</body></message>")?;
    legacy.expect_xml("<message xmlns='jabber:client' from='alice@localhost/direct' to='alice@localhost/legacy' type='chat' id='parallel-back'><body>Direct to legacy</body></message>")?;
    let large = "x".repeat(11_000);
    direct.send(&format!(
        "<message to='alice@localhost/direct' type='chat' id='large'><body>{large}</body></message>"
    ))?;
    direct.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/direct' to='alice@localhost/direct' type='chat' id='large'><body>{large}</body></message>"))?;
    legacy.send(&format!(
        "<message to='alice@localhost/legacy' type='chat'><body>{large}</body></message>"
    ))?;
    legacy.expect_stream_error("policy-violation")?;
    direct.close()?;
    for (listener, mode, mechanism) in [
        (0, "starttls", "SCRAM-SHA-256"),
        (1, "direct", "SCRAM-SHA-512-PLUS"),
    ] {
        suite.wait_for_metric(&format!(
            "lonewolf_c2s_listener_info{{listener=\"{listener}\",tls_mode=\"{mode}\"}} 1"
        ))?;
        suite.wait_for_metric(&format!("lonewolf_c2s_authentications_total{{listener=\"{listener}\",mechanism=\"{mechanism}\",outcome=\"success\"}} 1"))?;
        suite.wait_for_metric(&format!("lonewolf_c2s_authentications_total{{listener=\"{listener}\",mechanism=\"none\",outcome=\"invalid_mechanism\"}} 1"))?;
        suite.wait_for_metric(&format!(
            "lonewolf_c2s_connections{{listener=\"{listener}\"}} 0"
        ))?;
    }
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"bound\",outcome=\"size_limit_exceeded\"} 1")?;
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"1\",phase=\"bound\",outcome=\"stream_end\"} 1")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}

#[test]
fn direct_tls_and_starttls_no_sni_preserve_occupied_resources_and_reuse_after_close() -> TestResult
{
    let mut suite = C2sSuite::with_listener_setup(
        "",
        "",
        "[[c2s.listeners]]\naddress='127.0.0.1:0'\ntls_mode='direct'\n[hosts.localhost]\nextensions=[]",
        |_| Ok(()),
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut plain = PlainClient::tcp(&suite)?;
    plain.open()?.child(TLS_NAMESPACE, "starttls")?;
    let mut no_sni = (*suite.tls).clone();
    no_sni.enable_sni = false;
    let mut legacy = plain.start_tls_with_config(Arc::new(no_sni))?;
    legacy.open()?.assert_xml(DEFAULT_FEATURES)?;
    legacy.authenticate("alice", PASSWORD)?;
    let mut legacy = legacy.restart();
    legacy.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(legacy.bind(Some("desk"))?, "alice@localhost/desk");
    let mut direct = Client::direct_tls_with_config(
        suite.listener_address(1)?,
        Arc::clone(&suite.tls),
        ServerName::try_from("localhost")?,
    )?;
    direct.open()?.assert_xml(DEFAULT_FEATURES)?;
    direct.authenticate("alice", PASSWORD)?;
    let mut direct = direct.restart();
    direct.open()?.assert_xml(BIND_FEATURES)?;
    let assigned = direct.bind(Some("desk"))?;
    let random = assigned
        .strip_prefix("alice@localhost/lw-")
        .ok_or("missing conflict resource")?;
    assert_eq!(random.len(), 32);
    assert!(random.bytes().all(|byte| byte.is_ascii_hexdigit()));
    direct.send("<message to='alice@localhost/desk' type='chat' id='occupied'><body>Original resource</body></message>")?;
    legacy.expect_xml(&format!("<message xmlns='jabber:client' from='{assigned}' to='alice@localhost/desk' type='chat' id='occupied'><body>Original resource</body></message>"))?;
    legacy.close()?;
    suite.wait_for_metric("lonewolf_router_sessions 1")?;
    let mut replacement = Client::direct_tls_with_config(
        suite.listener_address(1)?,
        Arc::clone(&suite.tls),
        ServerName::try_from("localhost")?,
    )?;
    replacement.open()?.assert_xml(DEFAULT_FEATURES)?;
    replacement.authenticate("alice", PASSWORD)?;
    let mut replacement = replacement.restart();
    replacement.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(replacement.bind(Some("desk"))?, "alice@localhost/desk");
    replacement.send(&format!(
        "<message to='{assigned}' type='chat' id='reused'><body>Still connected</body></message>"
    ))?;
    direct.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desk' to='{assigned}' type='chat' id='reused'><body>Still connected</body></message>"))?;
    replacement.close()?;
    direct.close()?;
    for (listener, count) in [(0, 1), (1, 2)] {
        suite.wait_for_metric(&format!("lonewolf_c2s_authentications_total{{listener=\"{listener}\",mechanism=\"SCRAM-SHA-256\",outcome=\"success\"}} {count}"))?;
        suite.wait_for_metric(&format!("lonewolf_c2s_connections_closed_total{{listener=\"{listener}\",phase=\"bound\",outcome=\"stream_end\"}} {count}"))?;
        suite.wait_for_metric(&format!(
            "lonewolf_c2s_connections{{listener=\"{listener}\"}} 0"
        ))?;
    }
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}
