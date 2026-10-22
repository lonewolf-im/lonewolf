// SPDX-License-Identifier: Apache-2.0

use crate::support::ALTERNATE_PASSWORD;

use super::support::{BIND_NAMESPACE, C2sSuite, OPEN, TestResult};

#[test]
fn requested_resource_is_returned_in_the_bound_jid() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    let jid = client.bind(Some("desk"))?;

    assert_eq!(jid, "alice@localhost/desk");
    client.close()
}

#[test]
fn requested_resource_preserves_xml_special_characters() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    let jid = client.bind(Some("Desk & <Phone>"))?;

    assert_eq!(jid, "alice@localhost/Desk & <Phone>");
    client.close()
}

#[test]
fn omitted_resource_generates_a_random_identifier() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut desktop = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut second = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
    let mut third = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

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
fn rejected_iq_envelopes_return_bad_request_and_allow_binding_on_the_same_connection() -> TestResult
{
    for (envelope, id) in [
        ("type='bogus' id='a&amp;b'", "a&amp;b"),
        ("id='absent-type'", "absent-type"),
        ("type='' id='empty-type'", "empty-type"),
        ("type='set'", ""),
        (
            "type='bogus' id='addressed' from='alice@localhost' to='localhost'",
            "addressed",
        ),
    ] {
        let suite = C2sSuite::resource_limit(1)?;
        suite.create_account("alice", ALTERNATE_PASSWORD)?;
        let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
        client.send(&format!("<iq {envelope}><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>"))?;
        client.expect_xml(&format!(
            "<iq xmlns='jabber:client' type='error' id='{id}'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>"
        ))?;

        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.close()?;
    }
    Ok(())
}

#[test]
fn rejected_iq_child_counts_return_bad_request_and_allow_binding_retry() -> TestResult {
    for children in [
        "",
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/><other/>",
    ] {
        let suite = C2sSuite::resource_limit(1)?;
        suite.create_account("alice", ALTERNATE_PASSWORD)?;
        let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

        client.send(&format!("<iq type='set' id='bad'>{children}</iq>"))?;
        client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;

        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.close()?;
    }
    Ok(())
}

#[test]
fn rejected_iq_envelopes_preserve_binding_authorization_and_namespace_gates() -> TestResult {
    for (attributes, condition) in [
        ("from='bob@localhost'", "invalid-from"),
        ("from='alice@localhost/desk'", "invalid-from"),
        ("from='bad@'", "invalid-from"),
        ("from=''", "invalid-from"),
        ("to='bob@localhost'", "not-authorized"),
        ("to='localhost/desk'", "not-authorized"),
        ("to='remote.example'", "not-authorized"),
        ("to='bad@'", "not-authorized"),
        ("to=''", "not-authorized"),
        (
            "xmlns='jabber:server' from='alice@localhost' to='localhost'",
            "invalid-namespace",
        ),
    ] {
        let suite = C2sSuite::start()?;
        suite.create_account("alice", ALTERNATE_PASSWORD)?;
        let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

        client.send(&format!("<iq type='bogus' id='bad' {attributes}><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>"))?;
        client.expect_stream_error(condition)?;

        let mut replacement = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
        assert_eq!(replacement.bind(Some("desk"))?, "alice@localhost/desk");
        replacement.close()?;
    }
    Ok(())
}

const PRE_BIND_RESPONSES: &[&str] = &[
    "type='result' id='reply'",
    "type='error' id='reply'",
    "type='result'",
    "type='error'",
];

#[test]
fn iq_responses_are_ignored_before_binding_for_permitted_addresses() -> TestResult {
    for response in [
        "<iq type='result' id='reply'{address}/>",
        "<iq type='error' id='reply'{address}><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
        "<iq type='result'{address}/>",
        "<iq type='result' id='bad'{address}><first/><second/></iq>",
        "<iq type='error' id='bad'{address}/>",
        "<iq type='error'{address}><error/></iq>",
    ] {
        for address in [
            "",
            " to='localhost'",
            " from='alice@localhost' to='alice@localhost'",
        ] {
            let suite = C2sSuite::resource_limit(1)?;
            suite.create_account("alice", ALTERNATE_PASSWORD)?;
            let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

            client.send(&response.replace("{address}", address))?;
            assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
            client.close()?;
        }
    }
    Ok(())
}

#[test]
fn fifth_rejected_iq_envelope_still_allows_success() -> TestResult {
    let suite = C2sSuite::resource_limit(1)?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    for _ in 0..5 {
        client.send("<iq type='bogus' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
        client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
    }

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn rejected_iq_envelopes_share_the_binding_failure_limit() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    for attempt in 0..6 {
        let input = if attempt % 2 == 0 {
            "<iq type='bogus' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>"
        } else {
            "<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>"
        };
        client.send(input)?;
        client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
    }
    client.expect_stream_error("policy-violation")?;

    let mut replacement = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
    assert_eq!(replacement.bind(Some("desk"))?, "alice@localhost/desk");
    replacement.close()
}

fn assert_generated_identifier(jid: &str) -> TestResult {
    let random = jid
        .strip_prefix("alice@localhost/lw-")
        .ok_or("missing generated resource")?;
    assert_eq!(random.len(), 32);
    assert!(
        random
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    Ok(())
}

fn assert_generated_resource_lifecycle(suite: &C2sSuite, resource: &str) -> TestResult {
    let logs = suite.wait_for_log("stream disconnected")?;
    let bound = logs
        .lines()
        .find(|line| line.contains("resource bound"))
        .ok_or("missing bound lifecycle event")?;
    assert!(bound.contains("resource_requested=false"), "{logs}");
    if !resource.is_empty() {
        assert!(!logs.contains(resource), "{logs}");
    }
    Ok(())
}

#[test]
fn empty_resource_gets_a_generated_identifier() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    assert_generated_identifier(&client.bind(Some(""))?)?;
    client.close()?;
    assert_generated_resource_lifecycle(&suite, "")
}

#[test]
fn oversized_resource_gets_a_generated_identifier() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
    let resource = "x".repeat(1100);

    assert_generated_identifier(&client.bind(Some(&resource))?)?;
    client.close()?;
    assert_generated_resource_lifecycle(&suite, &resource)
}

#[test]
fn unpreparable_resource_gets_a_generated_identifier() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
    let resource = "private\u{200b}resource";

    assert_generated_identifier(&client.bind(Some(resource))?)?;
    client.close()?;
    assert_generated_resource_lifecycle(&suite, resource)
}

#[test]
fn requested_resource_is_normalized_in_the_bound_jid() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    assert_eq!(
        client.bind(Some("Desk\u{a0}Phone"))?,
        "alice@localhost/Desk Phone"
    );
    client.close()
}

#[test]
fn resource_attributes_returns_bad_request_and_allows_retry() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    client.send("<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'>desk</resource></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error>
    </iq>",
    )?;

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn duplicate_resources_returns_bad_request_and_allows_retry() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    client.send("<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource><resource>phone</resource></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error>
    </iq>",
    )?;

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn unknown_child_returns_bad_request_and_allows_retry() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    client.send("<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><other/></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error>
    </iq>",
    )?;

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn text_content_returns_bad_request_and_allows_retry() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    client.send(
        "<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>text</bind></iq>",
    )?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error>
    </iq>",
    )?;

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn fifth_binding_failure_still_allows_success() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    for _ in 0..5 {
        client.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
        client.expect_xml(
            "<iq xmlns='jabber:client' type='error' id='bad'>
            <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error>
        </iq>",
        )?;
    }

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn sixth_binding_failure_closes_the_stream() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    for _ in 0..5 {
        client.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
        client.expect_xml(
            "<iq xmlns='jabber:client' type='error' id='bad'>
            <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error>
        </iq>",
        )?;
    }

    client.send("<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error>
    </iq>",
    )?;
    client.expect_stream_error("policy-violation")
}

#[test]
fn configured_resource_binding_retries_close_after_eight_failed_attempts() -> TestResult {
    let suite = C2sSuite::with_profile_settings(
        "custom",
        "[limits.c2s.profiles.custom]\nresource_binding_retries = 7",
    )?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    for _ in 0..8 {
        client.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
        client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
    }
    client.expect_stream_error("policy-violation")
}

#[test]
fn different_sender_closes_binding_without_registering_the_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    client.send("<iq type='set' id='bad' from='bob@localhost'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    client.expect_stream_error("invalid-from")?;

    let mut replacement = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    replacement.close()
}

#[test]
fn full_jid_sender_closes_binding_without_registering_the_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    client.send("<iq type='set' id='bad' from='alice@localhost/desk'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    client.expect_stream_error("invalid-from")?;

    let mut replacement = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    replacement.close()
}

#[test]
fn account_destination_closes_binding_without_registering_the_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    client.send("<iq type='set' id='bad' to='bob@localhost'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    client.expect_stream_error("not-authorized")?;

    let mut replacement = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    replacement.close()
}

#[test]
fn server_namespace_closes_binding_without_registering_the_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    client.send("<iq type='set' id='bad' xmlns='jabber:server' from='alice@localhost' to='localhost'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    client.expect_stream_error("invalid-namespace")?;

    let mut replacement = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    replacement.close()
}

#[test]
fn resource_limit_allows_retry_after_another_client_disconnects() -> TestResult {
    let suite = C2sSuite::resource_limit(1)?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut desktop = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut phone = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    phone.send("<iq type='set' id='full'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>phone</resource></bind></iq>")?;
    phone.expect_xml("<iq xmlns='jabber:client' type='error' id='full'>
        <error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot allocate another resource for this account. Close an existing session or try again later.</text></error>
    </iq>")?;

    desktop.close()?;
    suite.wait_for_log("stream disconnected")?;
    assert_eq!(phone.bind(Some("phone"))?, "alice@localhost/phone");
    phone.close()
}

#[test]
fn resource_limit_bind_failures_close_the_stream_at_the_retry_limit() -> TestResult {
    let suite = C2sSuite::resource_limit(1)?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let _desktop = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut phone = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    for _ in 0..6 {
        phone.send("<iq type='set' id='full'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>phone</resource></bind></iq>")?;
        phone.expect_xml("<iq xmlns='jabber:client' type='error' id='full'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot allocate another resource for this account. Close an existing session or try again later.</text></error></iq>")?;
    }
    phone.expect_stream_error("policy-violation")
}

#[test]
fn malformed_and_resource_limit_bind_failures_share_the_retry_limit() -> TestResult {
    let suite = C2sSuite::resource_limit(1)?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let _desktop = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut phone = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    for attempt in 0..6 {
        if attempt % 2 == 0 {
            phone.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
            phone.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
        } else {
            phone.send("<iq type='set' id='full'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>phone</resource></bind></iq>")?;
            phone.expect_xml("<iq xmlns='jabber:client' type='error' id='full'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot allocate another resource for this account. Close an existing session or try again later.</text></error></iq>")?;
        }
    }
    phone.expect_stream_error("policy-violation")
}

#[test]
fn unusable_resource_fallback_and_resource_limit_share_the_retry_limit() -> TestResult {
    let suite = C2sSuite::with_limits("resource_binding_timeout_secs = 20")?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut desktops = Vec::with_capacity(10);
    for index in 0..10 {
        desktops.push(suite.connect("alice", ALTERNATE_PASSWORD, &format!("desktop-{index}"))?);
    }
    let mut phone = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
    let overlong_resource = "a".repeat(1024);

    for attempt in 0..6 {
        if attempt % 2 == 0 {
            phone.send(&format!("<iq type='set' id='invalid'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{overlong_resource}</resource></bind></iq>"))?;
            phone.expect_xml("<iq xmlns='jabber:client' type='error' id='invalid'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot allocate another resource for this account. Close an existing session or try again later.</text></error></iq>")?;
        } else {
            phone.send("<iq type='set' id='full'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>phone</resource></bind></iq>")?;
            phone.expect_xml("<iq xmlns='jabber:client' type='error' id='full'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot allocate another resource for this account. Close an existing session or try again later.</text></error></iq>")?;
        }
    }
    phone.expect_stream_error("policy-violation")
}

#[test]
fn prefix_free_stream_returns_client_namespace_binding_and_iq_replies() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", ALTERNATE_PASSWORD)?;
    let mut client = client.restart();
    client.open_with(&OPEN.replace(" xmlns='jabber:client'", ""))?;
    client.features()?.child(BIND_NAMESPACE, "bind")?;

    client.send("<iq xmlns='jabber:client' type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error>
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
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error>
    </iq>")?;
    client.close()
}

#[test]
fn fifth_structural_failure_still_allows_unusable_resource_fallback() -> TestResult {
    let oversized = "x".repeat(1100);
    for resource in ["", oversized.as_str(), "private\u{200b}resource"] {
        let suite = C2sSuite::resource_limit(1)?;
        suite.create_account("alice", ALTERNATE_PASSWORD)?;
        let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

        for payload in [
            "<resource><other/></resource>",
            "<resource>desk<other/></resource>",
            "<other/>",
            "<resource attr='1'/>",
            "text",
        ] {
            client.send(&format!(
                "<iq type='set' id='bad'><bind xmlns='{BIND_NAMESPACE}'>{payload}</bind></iq>"
            ))?;
            client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
        }

        assert_generated_identifier(&client.bind(Some(resource))?)?;
        client.close()?;
    }
    Ok(())
}

#[test]
fn saturated_unusable_resource_fallback_counts_one_failure_per_request() -> TestResult {
    let oversized = "x".repeat(1100);
    for resource in ["", oversized.as_str(), "private\u{200b}resource"] {
        let suite = C2sSuite::resource_limit(1)?;
        suite.create_account("alice", ALTERNATE_PASSWORD)?;
        let mut desktop = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
        let mut phone = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

        for _ in 0..6 {
            phone.send(&format!("<iq type='set' id='full'><bind xmlns='{BIND_NAMESPACE}'><resource>{resource}</resource></bind></iq>"))?;
            phone.expect_xml("<iq xmlns='jabber:client' type='error' id='full'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot allocate another resource for this account. Close an existing session or try again later.</text></error></iq>")?;
        }
        phone.expect_stream_error("policy-violation")?;
        desktop.close()?;
    }
    Ok(())
}

#[test]
fn structural_bind_errors_each_close_at_the_retry_limit() -> TestResult {
    for bind in [
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource/><resource/></bind>",
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource/><resource>phone</resource></bind>",
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><other/></bind>",
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind>",
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind' attr='1'/>",
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>text</bind>",
    ] {
        let suite = C2sSuite::resource_limit(1)?;
        suite.create_account("alice", ALTERNATE_PASSWORD)?;
        let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

        for _ in 0..6 {
            client.send(&format!("<iq type='set' id='bad'>{bind}</iq>"))?;
            client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
        }
        client.expect_stream_error("policy-violation")?;
    }
    Ok(())
}

#[test]
fn nested_resource_children_close_at_the_retry_limit() -> TestResult {
    let suite = C2sSuite::resource_limit(1)?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    for _ in 0..6 {
        client.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource><other/></resource></bind></iq>")?;
        client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
    }
    client.expect_stream_error("policy-violation")
}

#[test]
fn mixed_resource_children_close_at_the_retry_limit() -> TestResult {
    let suite = C2sSuite::resource_limit(1)?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    for _ in 0..6 {
        client.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk<other/></resource></bind></iq>")?;
        client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
    }
    client.expect_stream_error("policy-violation")
}

#[test]
fn pre_bind_disco_without_destination_returns_service_unavailable_then_binds() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    client.send(
        "<iq type='get' id='disco'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
    )?;
    client.expect_xml("<iq xmlns='jabber:client' type='error' id='disco'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested operation is not available before resource binding completes.</text></error></iq>")?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn pre_bind_requests_to_permitted_destinations_return_service_unavailable() -> TestResult {
    for attributes in [
        "",
        " to='localhost'",
        " from='alice@localhost' to='alice@localhost'",
    ] {
        for (kind, payload) in [
            ("get", "<ping xmlns='urn:xmpp:ping'/>"),
            ("get", "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"),
            ("set", "<query xmlns='urn:test:unsupported'/>"),
            ("set", "<bind xmlns='urn:test:unsupported'/>"),
        ] {
            let suite = C2sSuite::start()?;
            suite.create_account("alice", ALTERNATE_PASSWORD)?;
            let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

            client.send(&format!(
                "<iq type='{kind}' id='a&amp;b'{attributes}>{payload}</iq>"
            ))?;
            client.expect_xml("<iq xmlns='jabber:client' type='error' id='a&amp;b'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested operation is not available before resource binding completes.</text></error></iq>")?;
            assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
            client.close()?;
        }
    }
    Ok(())
}

#[test]
fn own_bare_destination_accepts_binding_and_rejected_request_recovery() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    client.send("<iq type='get' id='bad' to='alice@localhost'><first/><second/></iq>")?;
    client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
    client.send("<iq type='set' id='bind' to='alice@localhost'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    client.expect_xml("<iq xmlns='jabber:client' type='result' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>alice@localhost/desk</jid></bind></iq>")?;
    client.close()
}

#[test]
fn pre_bind_iqs_to_other_entities_close_before_request_or_response_handling() -> TestResult {
    for destination in [
        "bob@localhost",
        "alice@localhost/desk",
        "localhost/desk",
        "remote.example",
        "bob@remote.example",
    ] {
        for stanza in [
            "type='get' id='query'><ping xmlns='urn:xmpp:ping'/></iq>",
            "type='set' id='query'><query xmlns='urn:test:unsupported'/></iq>",
            "type='result' id='reply'/>",
            "type='error' id='reply'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
            "type='result'/>",
            "type='error'/>",
        ] {
            let suite = C2sSuite::start()?;
            suite.create_account("alice", ALTERNATE_PASSWORD)?;
            let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

            client.send(&format!("<iq to='{destination}' {stanza}"))?;
            client.expect_stream_error("not-authorized")?;
        }
    }
    Ok(())
}

#[test]
fn pre_bind_responses_preserve_namespace_and_address_gate_precedence() -> TestResult {
    for envelope in PRE_BIND_RESPONSES {
        for (address, condition) in [
            (
                "xmlns='jabber:server' from='bob@localhost' to='bob@localhost'",
                "invalid-namespace",
            ),
            ("from='bob@localhost' to='bob@localhost'", "invalid-from"),
            ("from='localhost'", "invalid-from"),
            ("from='alice@localhost/desk'", "invalid-from"),
            ("from='bad@'", "invalid-from"),
            ("from=''", "invalid-from"),
            ("to='bad@'", "not-authorized"),
            ("to=''", "not-authorized"),
        ] {
            let suite = C2sSuite::start()?;
            suite.create_account("alice", ALTERNATE_PASSWORD)?;
            let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

            let payload = if envelope.starts_with("type='error' id=") {
                "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
            } else {
                ""
            };
            client.send(&format!("<iq {envelope} {address}>{payload}</iq>"))?;
            client.expect_stream_error(condition)?;
        }
    }
    Ok(())
}

#[test]
fn ignored_pre_bind_responses_do_not_increment_or_reset_the_failure_count() -> TestResult {
    for bind_after_responses in [true, false] {
        let suite = C2sSuite::start()?;
        suite.create_account("alice", ALTERNATE_PASSWORD)?;
        let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

        for _ in 0..5 {
            client.send("<iq type='set' id='bad'><query xmlns='urn:test:unsupported'/></iq>")?;
            client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested operation is not available before resource binding completes.</text></error></iq>")?;
        }
        for _ in 0..7 {
            client.send("<iq type='result' id='reply'/>")?;
            client.send("<iq type='error' id='reply'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
            client.send("<iq type='result'/>")?;
            client.send("<iq type='error'/>")?;
        }
        if bind_after_responses {
            assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
            client.close()?;
        } else {
            client.send("<iq type='get' id='sixth'><ping xmlns='urn:xmpp:ping'/></iq>")?;
            client.expect_xml("<iq xmlns='jabber:client' type='error' id='sixth'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested operation is not available before resource binding completes.</text></error></iq>")?;
            client.expect_stream_error("policy-violation")?;
        }
    }
    Ok(())
}

#[test]
fn unsupported_pre_bind_requests_close_at_default_and_configured_retry_limits() -> TestResult {
    for (retries, max_failures) in [(5, 6), (7, 8)] {
        let suite = C2sSuite::with_profile_settings(
            "custom",
            &format!("[limits.c2s.profiles.custom]\nresource_binding_retries = {retries}"),
        )?;
        suite.create_account("alice", ALTERNATE_PASSWORD)?;
        let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

        for attempt in 0..max_failures {
            let kind = if attempt % 2 == 0 { "get" } else { "set" };
            client.send(&format!(
                "<iq type='{kind}' id='bad'><query xmlns='urn:test:unsupported'/></iq>"
            ))?;
            client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested operation is not available before resource binding completes.</text></error></iq>")?;
        }
        client.expect_stream_error("policy-violation")?;
    }
    Ok(())
}

#[test]
fn unsupported_malformed_and_resource_limit_failures_share_the_pre_bind_budget() -> TestResult {
    let suite = C2sSuite::resource_limit(1)?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut desktop = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut phone = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    for _ in 0..2 {
        phone.send("<iq type='set' id='unsupported'><query xmlns='urn:test:unsupported'/></iq>")?;
        phone.expect_xml("<iq xmlns='jabber:client' type='error' id='unsupported'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested operation is not available before resource binding completes.</text></error></iq>")?;
        phone.send("<iq type='set' id='malformed'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
        phone.expect_xml("<iq xmlns='jabber:client' type='error' id='malformed'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
        phone.send("<iq type='set' id='full'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>phone</resource></bind></iq>")?;
        phone.expect_xml("<iq xmlns='jabber:client' type='error' id='full'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot allocate another resource for this account. Close an existing session or try again later.</text></error></iq>")?;
    }
    phone.expect_stream_error("policy-violation")?;
    desktop.close()
}

#[test]
fn ignored_pre_bind_responses_do_not_extend_the_shaped_binding_deadline() -> TestResult {
    let suite = C2sSuite::with_limits(
        "incoming_stanzas_per_connection = { per_second = 1, burst = 1 }\nresource_binding_timeout_secs = 1",
    )?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut client = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
    let started = std::time::Instant::now();

    client.send("<iq type='result' id='reply'/><iq type='result'/><iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    client.expect_stream_error("policy-violation")?;
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    suite.wait_for_log("outcome=\"binding_timeout\"")?;
    let mut replacement = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    replacement.close()
}
