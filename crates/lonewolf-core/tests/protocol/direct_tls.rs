// SPDX-License-Identifier: Apache-2.0

use super::support::{
    BIND_NAMESPACE, C2sSuite, Client, PASSWORD, SASL_NAMESPACE, TLS_NAMESPACE, TestResult,
};

#[test]
fn direct_tls_login_bind_message_and_close() -> TestResult {
    let mut suite = C2sSuite::direct_tls()?;
    suite.create_account("alice", PASSWORD)?;
    let mut client = Client::direct_tls(&suite)?;

    let features = client.open()?;
    features.child(SASL_NAMESPACE, "mechanisms")?;
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
    client.open()?.child(BIND_NAMESPACE, "bind")?;
    assert_eq!(client.bind(Some("direct"))?, "alice@localhost/direct");
    client.send(
        "<message to='alice@localhost/direct' type='chat' id='direct'><body>Ready</body></message>",
    )?;
    client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/direct' to='alice@localhost/direct' type='chat' id='direct'><body>Ready</body></message>")?;
    let body = suite.wait_for_metric(
        "lonewolf_c2s_resource_bindings_total{listener=\"0\",outcome=\"success\"} 1",
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
        "lonewolf_c2s_connections{listener=\"0\"} 1",
        "lonewolf_c2s_connections_accepted_total{listener=\"0\"} 1",
        "lonewolf_c2s_unauthenticated_connections 0",
        "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256-PLUS\",outcome=\"success\"} 1",
        "lonewolf_c2s_phase_duration_seconds_count{phase=\"establishing\"} 1",
    ] {
        assert!(body.lines().any(|line| line == sample), "{body}");
    }
    client.close()?;
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"bound\",outcome=\"stream_end\"} 1")?;
    suite.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    suite.wait_for_metric("lonewolf_router_sessions 0")?;
    suite.stop()
}
