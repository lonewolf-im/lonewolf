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
        suite.create_account("alice", "pencil")?;
        let mut client = suite.authenticated_client("alice", "pencil")?;
        client.send(&format!("<iq {envelope}><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>"))?;
        client.expect_xml(&format!(
            "<iq xmlns='jabber:client' type='error' id='{id}'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
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
        suite.create_account("alice", "pencil")?;
        let mut client = suite.authenticated_client("alice", "pencil")?;

        client.send(&format!("<iq type='set' id='bad'>{children}</iq>"))?;
        client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;

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
        suite.create_account("alice", "pencil")?;
        let mut client = suite.authenticated_client("alice", "pencil")?;

        client.send(&format!("<iq type='bogus' id='bad' {attributes}><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>"))?;
        client.expect_stream_error(condition)?;

        let mut replacement = suite.authenticated_client("alice", "pencil")?;
        assert_eq!(replacement.bind(Some("desk"))?, "alice@localhost/desk");
        replacement.close()?;
    }
    Ok(())
}

#[test]
fn rejected_iq_responses_close_binding_without_an_iq_error_reply() -> TestResult {
    for input in [
        "<iq type='result'/>",
        "<iq type='result' id='bad'><first/><second/></iq>",
        "<iq type='error' id='bad'/>",
        "<iq type='error'><error/></iq>",
    ] {
        let suite = C2sSuite::start()?;
        suite.create_account("alice", "pencil")?;
        let mut client = suite.authenticated_client("alice", "pencil")?;

        client.send(input)?;
        client.expect_stream_error("not-authorized")?;

        let mut replacement = suite.authenticated_client("alice", "pencil")?;
        assert_eq!(replacement.bind(Some("desk"))?, "alice@localhost/desk");
        replacement.close()?;
    }
    Ok(())
}

#[test]
fn fifth_rejected_iq_envelope_still_allows_success() -> TestResult {
    let suite = C2sSuite::resource_limit(1)?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    for _ in 0..5 {
        client.send("<iq type='bogus' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
        client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    }

    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn rejected_iq_envelopes_share_the_binding_failure_limit() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    for attempt in 0..6 {
        let input = if attempt % 2 == 0 {
            "<iq type='bogus' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>"
        } else {
            "<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>"
        };
        client.send(input)?;
        client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    }
    client.expect_stream_error("policy-violation")?;

    let mut replacement = suite.authenticated_client("alice", "pencil")?;
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
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    assert_generated_identifier(&client.bind(Some(""))?)?;
    client.close()?;
    assert_generated_resource_lifecycle(&suite, "")
}

#[test]
fn oversized_resource_gets_a_generated_identifier() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;
    let resource = "x".repeat(1100);

    assert_generated_identifier(&client.bind(Some(&resource))?)?;
    client.close()?;
    assert_generated_resource_lifecycle(&suite, &resource)
}

#[test]
fn unpreparable_resource_gets_a_generated_identifier() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;
    let resource = "private\u{200b}resource";

    assert_generated_identifier(&client.bind(Some(resource))?)?;
    client.close()?;
    assert_generated_resource_lifecycle(&suite, resource)
}

#[test]
fn requested_resource_is_normalized_in_the_bound_jid() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    assert_eq!(
        client.bind(Some("Desk\u{a0}Phone"))?,
        "alice@localhost/Desk Phone"
    );
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
        client.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
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
        client.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
        client.expect_xml(
            "<iq xmlns='jabber:client' type='error' id='bad'>
            <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
        </iq>",
        )?;
    }

    client.send("<iq type='set' id='bad' ><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='error' id='bad'>
        <error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
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
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    for _ in 0..8 {
        client.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
        client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    }
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
fn resource_limit_bind_failures_close_the_stream_at_the_retry_limit() -> TestResult {
    let suite = C2sSuite::resource_limit(1)?;
    suite.create_account("alice", "pencil")?;
    let _desktop = suite.connect("alice", "pencil", "desk")?;
    let mut phone = suite.authenticated_client("alice", "pencil")?;

    for _ in 0..6 {
        phone.send("<iq type='set' id='full'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>phone</resource></bind></iq>")?;
        phone.expect_xml("<iq xmlns='jabber:client' type='error' id='full'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    }
    phone.expect_stream_error("policy-violation")
}

#[test]
fn malformed_and_resource_limit_bind_failures_share_the_retry_limit() -> TestResult {
    let suite = C2sSuite::resource_limit(1)?;
    suite.create_account("alice", "pencil")?;
    let _desktop = suite.connect("alice", "pencil", "desk")?;
    let mut phone = suite.authenticated_client("alice", "pencil")?;

    for attempt in 0..6 {
        if attempt % 2 == 0 {
            phone.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
            phone.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
        } else {
            phone.send("<iq type='set' id='full'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>phone</resource></bind></iq>")?;
            phone.expect_xml("<iq xmlns='jabber:client' type='error' id='full'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
        }
    }
    phone.expect_stream_error("policy-violation")
}

#[test]
fn unusable_resource_fallback_and_resource_limit_share_the_retry_limit() -> TestResult {
    let suite = C2sSuite::with_limits("resource_binding_timeout_secs = 20")?;
    suite.create_account("alice", "pencil")?;
    let mut desktops = Vec::with_capacity(10);
    for index in 0..10 {
        desktops.push(suite.connect("alice", "pencil", &format!("desktop-{index}"))?);
    }
    let mut phone = suite.authenticated_client("alice", "pencil")?;
    let overlong_resource = "a".repeat(1024);

    for attempt in 0..6 {
        if attempt % 2 == 0 {
            phone.send(&format!("<iq type='set' id='invalid'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{overlong_resource}</resource></bind></iq>"))?;
            phone.expect_xml("<iq xmlns='jabber:client' type='error' id='invalid'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
        } else {
            phone.send("<iq type='set' id='full'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>phone</resource></bind></iq>")?;
            phone.expect_xml("<iq xmlns='jabber:client' type='error' id='full'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
        }
    }
    phone.expect_stream_error("policy-violation")
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

    client.send("<iq xmlns='jabber:client' type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
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

#[test]
fn fifth_structural_failure_still_allows_unusable_resource_fallback() -> TestResult {
    let oversized = "x".repeat(1100);
    for resource in ["", oversized.as_str(), "private\u{200b}resource"] {
        let suite = C2sSuite::resource_limit(1)?;
        suite.create_account("alice", "pencil")?;
        let mut client = suite.authenticated_client("alice", "pencil")?;

        for payload in [
            "<resource/><resource>phone</resource>",
            "<resource>desk</resource><resource/>",
            "<other/>",
            "<resource attr='1'/>",
            "text",
        ] {
            client.send(&format!(
                "<iq type='set' id='bad'><bind xmlns='{BIND_NAMESPACE}'>{payload}</bind></iq>"
            ))?;
            client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
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
        suite.create_account("alice", "pencil")?;
        let mut desktop = suite.connect("alice", "pencil", "desk")?;
        let mut phone = suite.authenticated_client("alice", "pencil")?;

        for _ in 0..6 {
            phone.send(&format!("<iq type='set' id='full'><bind xmlns='{BIND_NAMESPACE}'><resource>{resource}</resource></bind></iq>"))?;
            phone.expect_xml("<iq xmlns='jabber:client' type='error' id='full'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
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
        suite.create_account("alice", "pencil")?;
        let mut client = suite.authenticated_client("alice", "pencil")?;

        for _ in 0..6 {
            client.send(&format!("<iq type='set' id='bad'>{bind}</iq>"))?;
            client.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
        }
        client.expect_stream_error("policy-violation")?;
    }
    Ok(())
}
