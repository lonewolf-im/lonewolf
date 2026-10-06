// SPDX-License-Identifier: Apache-2.0

use crate::support::{C2sSuite, TestResult};

#[test]
fn unknown_extensions_prevent_server_startup() -> TestResult {
    let error = C2sSuite::with_extensions("'missing-extension'")
        .err()
        .ok_or("server started with an unknown extension")?;
    let message = error.to_string();
    assert!(
        message.contains("unknown extension") && message.contains("missing-extension"),
        "{message}"
    );
    Ok(())
}

#[test]
fn conflicting_enabled_handlers_prevent_server_startup() -> TestResult {
    let error = C2sSuite::with_extensions("'test-iq', 'test-conflicting-iq'")
        .err()
        .ok_or("server started with conflicting handlers")?;
    assert!(
        error.to_string().contains("conflicting IQ route"),
        "{error}"
    );
    Ok(())
}

#[test]
fn conflicting_presence_handlers_prevent_server_startup() -> TestResult {
    let error = C2sSuite::with_extensions("'test-presence', 'test-conflicting-presence'")
        .err()
        .ok_or("server started with conflicting presence handlers")?;
    assert!(
        error.to_string().contains("conflicting presence route"),
        "{error}"
    );
    Ok(())
}

#[test]
fn requests_to_another_local_host_use_its_enabled_handlers() -> TestResult {
    let suite = C2sSuite::with_hosts(
        r#"
[hosts."other.localhost"]
extensions = ["test-server-iq"]
[hosts."other.localhost".tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
"#,
    )?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='other-host' to='other.localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='other-host' from='other.localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='other.localhost'/></iq>")?;
    alice.close()
}

#[test]
fn enabled_account_handler_receives_an_iq_request() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='extension-1'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='extension-1' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='alice@localhost'/></iq>")?;
    alice.close()
}

#[test]
fn subscription_presence_handlers_receive_authenticated_directed_requests() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-presence'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    for kind in ["subscribe", "subscribed", "unsubscribe", "unsubscribed"] {
        alice.send(&format!("<presence type='{kind}' id='{kind}' from='mallory@localhost/spy' to='bob@localhost'><nick xmlns='http://jabber.org/protocol/nick'>Robert</nick></presence>"))?;
        alice.expect_xml(&format!("<presence xmlns='jabber:client' type='error' id='{kind}' from='bob@localhost' to='alice@localhost/desk'><nick xmlns='http://jabber.org/protocol/nick'>Robert</nick><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>"))?;
    }

    alice.close()
}

#[test]
fn outbound_presence_uses_the_sender_hosts_extensions() -> TestResult {
    let suite = C2sSuite::with_hosts(
        r#"
[hosts.localhost]
extensions = ["test-presence"]
[hosts."other.localhost".tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
"#,
    )?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<presence type='subscribe' id='other-host' to='bob@other.localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='error' id='other-host' from='bob@other.localhost' to='alice@localhost/desk'><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")?;

    alice.close()
}

#[test]
fn undirected_subscription_presence_does_not_enter_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-presence'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<presence type='subscribe' id='undirected'/>")?;
    alice.send("<message to='alice@localhost/desk' id='sentinel'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel'/>")?;

    alice.close()
}

#[test]
fn presence_extensions_do_not_intercept_availability() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-presence'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    alice.send("<presence type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost' type='unavailable'/>")?;

    alice.close()
}

#[test]
fn get_and_set_with_the_same_payload_select_different_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='get'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='get' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='alice@localhost'/></iq>")?;
    alice.send("<iq type='set' id='set'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='set' to='alice@localhost/desk'/>",
    )?;
    alice.close()
}

#[test]
fn disabled_extension_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='disabled'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='disabled'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn unknown_payload_namespace_does_not_match_a_handler() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='unknown'><query xmlns='urn:lonewolf:test:unknown'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='unknown'><query xmlns='urn:lonewolf:test:unknown'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn only_the_direct_payload_element_selects_the_handler() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send(
        "<iq type='get' id='nested'><other xmlns='urn:lonewolf:test:iq'><query/></other></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='nested'><other xmlns='urn:lonewolf:test:iq'><query/></other><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn qualified_payload_and_authenticated_identity_reach_the_handler() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='a&amp;b' from='mallory@localhost/spy' to='bob@localhost'><t:query xmlns:t='urn:lonewolf:test:iq' value='one &amp; two'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='a&amp;b' from='bob@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='bob@localhost' value='one &amp; two'/></iq>")?;
    alice.close()
}

#[test]
fn handler_errors_preserve_the_request_payload_and_address_the_bound_resource() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-error-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='set' id='denied' from='mallory@localhost/spy' to='alice@localhost'><deny xmlns='urn:lonewolf:test:iq'><detail>Keep &amp; escape</detail></deny></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='denied' from='alice@localhost' to='alice@localhost/desk'><deny xmlns='urn:lonewolf:test:iq'><detail>Keep &amp; escape</detail></deny><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn server_scope_does_not_handle_account_requests() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-server-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='account'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='account'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.send(
        "<iq type='get' id='server' to='localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='server' from='localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='localhost'/></iq>")?;
    alice.close()
}

#[test]
fn account_scope_does_not_handle_server_requests() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send(
        "<iq type='get' id='server' to='localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='server' from='localhost'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn full_jid_requests_are_not_consumed_by_account_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='resource' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='get' id='resource' from='alice@localhost/desk' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.close()
}

#[test]
fn remote_requests_are_not_consumed_by_local_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq', 'test-server-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='remote' to='bob@remote.example'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='remote' from='bob@remote.example'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.send("<iq type='get' id='remote-server' to='remote.example'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='remote-server' from='remote.example'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn iq_results_and_errors_do_not_enter_request_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='result' id='result'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.send("<iq type='error' id='error'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.send("<iq type='get' id='request'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='request' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='alice@localhost'/></iq>")?;
    alice.close()
}

#[test]
fn extension_activation_is_scoped_to_the_destination_host() -> TestResult {
    let suite = C2sSuite::with_hosts(
        r#"
[hosts.localhost]
extensions = ["test-server-iq"]
[hosts."other.localhost".tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
"#,
    )?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='other-host' to='other.localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='other-host' from='other.localhost'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.send("<iq type='get' id='enabled-host' to='localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='enabled-host' from='localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='localhost'/></iq>")?;
    alice.close()
}
