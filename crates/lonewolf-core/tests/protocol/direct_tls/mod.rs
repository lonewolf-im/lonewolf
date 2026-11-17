// SPDX-License-Identifier: Apache-2.0

use super::support::{C2sSuite, Client, PASSWORD, SASL_NAMESPACE, TLS_NAMESPACE, TestResult};

mod authentication;
mod deadlines;
mod hosts;
mod lifecycle;
mod protocol;
mod transports;

const DEFAULT_FEATURES: &str = "<stream:features xmlns:stream='http://etherx.jabber.org/streams'><sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/><channel-binding type='tls-exporter'/></sasl-channel-binding><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-256-PLUS</mechanism><mechanism>SCRAM-SHA-256</mechanism><mechanism>SCRAM-SHA-1-PLUS</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms></stream:features>";
const EXTERNAL_FEATURES: &str = "<stream:features xmlns:stream='http://etherx.jabber.org/streams'><sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/><channel-binding type='tls-exporter'/></sasl-channel-binding><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism><mechanism>SCRAM-SHA-256-PLUS</mechanism><mechanism>SCRAM-SHA-256</mechanism><mechanism>SCRAM-SHA-1-PLUS</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms></stream:features>";
const BIND_FEATURES: &str = "<stream:features xmlns:stream='http://etherx.jabber.org/streams'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>";

#[test]
fn direct_tls_login_bind_message_and_close() -> TestResult {
    let mut suite = C2sSuite::with_listener_setup(
        "tls_mode='direct'",
        "",
        "[hosts.localhost]\nextensions=['ping']",
        |_| Ok(()),
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut client = Client::direct_tls(&suite)?;

    suite.create_account("bob", PASSWORD)?;
    let features = client.open()?;
    features.assert_xml(DEFAULT_FEATURES)?;
    assert!(
        !features
            .children
            .iter()
            .any(|child| child.namespace == TLS_NAMESPACE)
    );
    assert_eq!(
        client.transport().conn.alpn_protocol(),
        Some(b"xmpp-client".as_slice())
    );
    client
        .scram(
            "alice",
            PASSWORD,
            "SCRAM-SHA-256-PLUS",
            Some("tls-exporter"),
        )?
        .assert_name(SASL_NAMESPACE, "success");
    let mut client = client.restart();
    client.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(client.bind(Some("direct"))?, "alice@localhost/direct");
    client.send(
        "<message to='alice@localhost/direct' type='chat' id='direct'><body>Ready</body></message>",
    )?;
    client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/direct' to='alice@localhost/direct' type='chat' id='direct'><body>Ready</body></message>")?;
    let mut bob = Client::direct_tls(&suite)?;
    bob.open()?.assert_xml(DEFAULT_FEATURES)?;
    bob.authenticate("bob", PASSWORD)?;
    let mut bob = bob.restart();
    bob.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(bob.bind(Some("phone"))?, "bob@localhost/phone");
    client.send(
        "<message to='bob@localhost/phone' type='chat' id='to-bob'><body>Forward</body></message>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/direct' to='bob@localhost/phone' type='chat' id='to-bob'><body>Forward</body></message>")?;
    bob.send("<message to='alice@localhost/direct' type='chat' id='to-alice'><body>Return</body></message>")?;
    client.expect_xml("<message xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/direct' type='chat' id='to-alice'><body>Return</body></message>")?;
    client.send(
        "<iq type='get' to='localhost' id='ping-direct'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    client.expect_xml("<iq xmlns='jabber:client' from='localhost' to='alice@localhost/direct' type='result' id='ping-direct'/>")?;
    let body = suite.wait_for_metric(
        "lonewolf_c2s_resource_bindings_total{listener=\"0\",outcome=\"success\"} 2",
    )?;
    assert_eq!(
        body.lines()
            .filter(|line| line.starts_with("lonewolf_c2s_listener_info{"))
            .count(),
        1
    );
    assert!(
        body.lines()
            .any(|line| line == "lonewolf_c2s_listener_info{listener=\"0\",tls_mode=\"direct\"} 1"),
        "{body}"
    );
    for sample in [
        "lonewolf_c2s_connections{listener=\"0\"} 2",
        "lonewolf_c2s_connections_accepted_total{listener=\"0\"} 2",
        "lonewolf_c2s_unauthenticated_connections 0",
        "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256-PLUS\",outcome=\"success\"} 1",
        "lonewolf_c2s_phase_duration_seconds_count{phase=\"establishing\"} 2",
    ] {
        assert!(body.lines().any(|line| line == sample), "{body}");
    }
    client.close()?;
    bob.close()?;
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"bound\",outcome=\"stream_end\"} 2")?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}
