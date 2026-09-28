// SPDX-License-Identifier: Apache-2.0

use super::support::{BIND_NAMESPACE, C2sSuite, OPEN, TestResult};

#[test]
fn requested_resource_is_returned_in_the_bound_jid() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    let jid = client.bind(Some("desk"))?;

    assert_eq!(jid, "alice@localhost/desk");
    client.close()
}

#[test]
fn requested_resource_preserves_xml_special_characters() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    let jid = client.bind(Some("Desk & <Phone>"))?;

    assert_eq!(jid, "alice@localhost/Desk & <Phone>");
    client.close()
}

#[test]
fn omitted_resource_generates_a_random_identifier() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    let jid = client.bind(None)?;

    let random = jid
        .strip_prefix("alice@localhost/lw-")
        .ok_or("missing generated resource")?;
    assert_eq!(random.len(), 32);
    assert!(random.bytes().all(|byte| byte.is_ascii_hexdigit()));
    client.close()
}

#[test]
fn conflicting_resource_gets_a_new_identifier_without_replacing_the_first_client() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut desktop = suite.connect("alice", "pencil", "desk")?;
    let mut second = suite.authenticated_client("alice", "pencil")?;
    let mut third = suite.authenticated_client("alice", "pencil")?;

    let generated = second.bind(None)?;
    let conflict = third.bind(Some("desk"))?;

    assert_ne!(generated, conflict);
    let random = conflict
        .strip_prefix("alice@localhost/lw-")
        .ok_or("missing generated resource")?;
    assert_eq!(random.len(), 32);
    assert!(random.bytes().all(|byte| byte.is_ascii_hexdigit()));
    desktop.close()?;
    second.close()?;
    third.close()
}

#[test]
fn empty_resource_returns_bad_request_and_allows_retry() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource/></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
    </iq>",
    )?;

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn resource_attributes_returns_bad_request_and_allows_retry() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'>desk</resource></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
    </iq>",
    )?;

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn duplicate_resources_returns_bad_request_and_allows_retry() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource><resource>phone</resource></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
    </iq>",
    )?;

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn unknown_child_returns_bad_request_and_allows_retry() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><other/></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
    </iq>",
    )?;

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn text_content_returns_bad_request_and_allows_retry() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(
        "<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>text</bind></iq>",
    )?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
    </iq>",
    )?;

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn fifth_binding_failure_still_allows_success() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    for _ in 0..5 {
        client.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource/></bind></iq>")?;
        client.expect_xml(
            "<iq xmlns='jabber:client' type='error' id='bad'>
            <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
        </iq>",
        )?;
    }

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn sixth_binding_failure_closes_the_stream() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    for _ in 0..5 {
        client.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource/></bind></iq>")?;
        client.expect_xml(
            "<iq xmlns='jabber:client' type='error' id='bad'>
            <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
        </iq>",
        )?;
    }

    client.send("<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource/></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
    </iq>",
    )?;
    client.expect_stream_error("policy-violation")
}

#[test]
fn different_sender_closes_binding_without_registering_the_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("<iq type='set' id='bad' from='bob@localhost'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    client.expect_stream_error("invalid-from")?;

    let mut replacement = suite.connect("alice", "pencil", "desk")?;
    replacement.close()
}

#[test]
fn full_jid_sender_closes_binding_without_registering_the_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("<iq type='set' id='bad' from='alice@localhost/desk'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    client.expect_stream_error("invalid-from")?;

    let mut replacement = suite.connect("alice", "pencil", "desk")?;
    replacement.close()
}

#[test]
fn account_destination_closes_binding_without_registering_the_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("<iq type='set' id='bad' to='bob@localhost'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    client.expect_stream_error("not-authorized")?;

    let mut replacement = suite.connect("alice", "pencil", "desk")?;
    replacement.close()
}

#[test]
fn server_namespace_closes_binding_without_registering_the_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("<iq type='set' id='bad' xmlns='jabber:server' from='alice@localhost' to='localhost'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    client.expect_stream_error("invalid-namespace")?;

    let mut replacement = suite.connect("alice", "pencil", "desk")?;
    replacement.close()
}

#[test]
fn resource_limit_allows_retry_after_another_client_disconnects() -> TestResult {
    let suite = C2sSuite::resource_limit(1)?;
    suite.create_account("alice", "pencil")?;
    let mut desktop = suite.connect("alice", "pencil", "desk")?;
    let mut phone = suite.authenticated_client("alice", "pencil")?;

    phone.send("<iq type='set' id='full'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>phone</resource></bind></iq>")?;
    phone.expect_xml("<iq xmlns='jabber:client' type='error' id='full'>
        <error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
    </iq>")?;

    desktop.close()?;
    suite.wait_for_log("stream disconnected")?;
    assert_eq!(phone.bind(Some("phone"))?, "alice@localhost/phone");
    phone.close()
}

#[test]
fn prefix_free_stream_returns_client_namespace_binding_and_iq_replies() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();
    client.open_with(&OPEN.replace(" xmlns='jabber:client'", ""))?;
    client.features()?.child(BIND_NAMESPACE, "bind")?;

    client.send("<iq xmlns='jabber:client' type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource/></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
    </iq>",
    )?;

    client.send("<iq xmlns='jabber:client' type='set' id='good'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='good'>
        <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>alice@localhost/desk</jid></bind>
    </iq>",
    )?;

    client.send("<iq xmlns='jabber:client' type='get' id='unsupported'><query xmlns='urn:test:unknown'/></iq>")?;
    client.expect_xml("<iq xmlns='jabber:client' type='error' id='unsupported'>
        <query xmlns='urn:test:unknown'/>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
    </iq>")?;
    client.close()
}
