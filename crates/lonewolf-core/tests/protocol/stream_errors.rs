// SPDX-License-Identifier: Apache-2.0

use super::support::{C2sSuite, TestResult};

#[test]
fn server_namespace_message_returns_invalid_namespace_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<message xmlns='jabber:server' from='alice@localhost' to='localhost'/>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn server_namespace_element_returns_invalid_namespace_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<other xmlns='jabber:server'/>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn rejected_iq_is_not_authorized_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<iq type='subscribe'/>"#)?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn unbound_prefix_returns_not_well_formed_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<x:message/>"#)?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn mismatched_tags_returns_bad_format_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<message><body></message>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn duplicate_attributes_returns_bad_format_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<message id='a' id='b'/>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn xml_comment_returns_restricted_xml_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<message><!--forbidden--></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn processing_instruction_returns_restricted_xml_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<message><?instruction value?></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn doctype_returns_restricted_xml_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<!DOCTYPE message><message/>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn unknown_entity_returns_restricted_xml_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<message><body>&unknown;</body></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn invalid_utf8_returns_unsupported_encoding_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send_bytes(b"<message>\xff</message>")?;
    client.expect_stream_error("unsupported-encoding")
}

#[test]
fn server_namespace_message_returns_invalid_namespace_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<message xmlns='jabber:server' from='alice@localhost' to='localhost'/>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn server_namespace_element_returns_invalid_namespace_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<other xmlns='jabber:server'/>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn rejected_iq_is_not_authorized_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<iq type='subscribe'/>"#)?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn unbound_prefix_returns_not_well_formed_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<x:message/>"#)?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn mismatched_tags_returns_bad_format_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<message><body></message>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn duplicate_attributes_returns_bad_format_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<message id='a' id='b'/>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn xml_comment_returns_restricted_xml_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<message><!--forbidden--></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn processing_instruction_returns_restricted_xml_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<message><?instruction value?></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn doctype_returns_restricted_xml_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<!DOCTYPE message><message/>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn unknown_entity_returns_restricted_xml_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<message><body>&unknown;</body></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn invalid_utf8_returns_unsupported_encoding_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send_bytes(b"<message>\xff</message>")?;
    client.expect_stream_error("unsupported-encoding")
}

#[test]
fn server_namespace_message_returns_invalid_namespace_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<message xmlns='jabber:server' from='alice@localhost' to='localhost'/>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn server_namespace_element_returns_invalid_namespace_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<other xmlns='jabber:server'/>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn rejected_iq_is_not_authorized_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<iq type='subscribe'/>"#)?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn unbound_prefix_returns_not_well_formed_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<x:message/>"#)?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn mismatched_tags_returns_bad_format_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<message><body></message>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn duplicate_attributes_returns_bad_format_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<message id='a' id='b'/>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn xml_comment_returns_restricted_xml_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<message><!--forbidden--></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn processing_instruction_returns_restricted_xml_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<message><?instruction value?></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn doctype_returns_restricted_xml_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<!DOCTYPE message><message/>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn unknown_entity_returns_restricted_xml_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<message><body>&unknown;</body></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn invalid_utf8_returns_unsupported_encoding_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send_bytes(b"<message>\xff</message>")?;
    client.expect_stream_error("unsupported-encoding")
}

#[test]
fn server_namespace_message_returns_invalid_namespace_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<message xmlns='jabber:server' from='alice@localhost' to='localhost'/>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn server_namespace_element_returns_invalid_namespace_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<other xmlns='jabber:server'/>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn unbound_prefix_returns_not_well_formed_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<x:message/>"#)?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn mismatched_tags_returns_bad_format_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<message><body></message>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn duplicate_attributes_returns_bad_format_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<message id='a' id='b'/>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn xml_comment_returns_restricted_xml_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<message><!--forbidden--></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn processing_instruction_returns_restricted_xml_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<message><?instruction value?></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn doctype_returns_restricted_xml_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<!DOCTYPE message><message/>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn unknown_entity_returns_restricted_xml_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<message><body>&unknown;</body></message>"#)?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn invalid_utf8_returns_unsupported_encoding_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send_bytes(b"<message>\xff</message>")?;
    client.expect_stream_error("unsupported-encoding")
}

#[test]
fn message_is_not_authorized_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send("<message/>")?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn presence_is_not_authorized_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send("<presence/>")?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn other_is_not_authorized_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send("<other/>")?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn message_is_not_authorized_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send("<message/>")?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn presence_is_not_authorized_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send("<presence/>")?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn application_stanzas_during_empty_sasl_challenge_close_before_reauthentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;

    for stanza in [
        "<message to='bob@localhost'><body>hello</body></message>",
        "<presence to='bob@localhost'/>",
        "<iq to='bob@localhost' type='get' id='one'><query xmlns='urn:test'/></iq>",
        "<message to='bad jid'/>",
        "<presence to='bob@localhost' type='invalid'/>",
        "<iq to='bob@localhost' type='get'><query xmlns='urn:test'/></iq>",
    ] {
        let mut client = suite.unauthenticated_client()?;
        client.send_sasl_auth("SCRAM-SHA-256", "")?;
        assert!(client.receive_sasl_challenge()?.is_empty());

        client.send(&format!(
            "{stanza}<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256'/>"
        ))?;
        client.expect_stream_error("not-authorized")?;
    }
    Ok(())
}

#[test]
fn application_stanzas_during_scram_proof_challenge_close_before_reauthentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;

    for stanza in [
        "<message to='bob@localhost'><body>hello</body></message>",
        "<presence to='bob@localhost'/>",
        "<iq to='bob@localhost' type='get' id='one'><query xmlns='urn:test'/></iq>",
        "<message to='bad jid'/>",
        "<presence to='bob@localhost' type='invalid'/>",
        "<iq to='bob@localhost' type='get'><query xmlns='urn:test'/></iq>",
    ] {
        let mut client = suite.unauthenticated_client()?;
        client.send_sasl_auth("SCRAM-SHA-256", "n,,n=alice,r=nonce")?;
        assert!(client.receive_sasl_challenge()?.starts_with("r=nonce"));

        client.send(&format!(
            "{stanza}<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256'/>"
        ))?;
        client.expect_stream_error("not-authorized")?;
    }
    Ok(())
}

#[test]
fn unknown_element_during_sasl_returns_malformed_request() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send("<other/>")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><malformed-request/></failure>",
    )?;
    client.close()
}

#[test]
fn message_is_not_authorized_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("<message/>")?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn presence_is_not_authorized_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("<presence/>")?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn other_is_not_authorized_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send("<other/>")?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn unknown_client_namespace_stanza_after_binding_closes_the_stream() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send("<other/>")?;
    client.expect_stream_error("unsupported-stanza-type")
}

#[test]
fn unknown_extension_namespace_stanza_after_binding_closes_the_stream() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send("<other xmlns='urn:test:unknown'/>")?;
    client.expect_stream_error("unsupported-stanza-type")
}

#[test]
fn rejected_stanzas_return_errors_and_leave_roster_requests_usable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;
    for (request, kind, id, condition, from) in [
        (
            "<iq><query xmlns='jabber:iq:roster'/></iq>",
            "iq",
            "",
            "bad-request",
            "",
        ),
        (
            "<iq type='get'><query xmlns='jabber:iq:roster'/></iq>",
            "iq",
            "",
            "bad-request",
            "",
        ),
        ("<iq type='future' id=''/>", "iq", "", "bad-request", ""),
        (
            "<iq type='get' id='zero'/>",
            "iq",
            "zero",
            "bad-request",
            "",
        ),
        (
            "<iq type='set' id='two'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'/></query><extra/></iq>",
            "iq",
            "two",
            "bad-request",
            "",
        ),
        (
            "<iq type='future' id='precedence' to='bad@'><query/></iq>",
            "iq",
            "precedence",
            "bad-request",
            "",
        ),
        (
            "<presence type='future' id='presence'/>",
            "presence",
            "presence",
            "bad-request",
            "",
        ),
        (
            "<message id='text'>text<extra/></message>",
            "message",
            "text",
            "bad-request",
            "",
        ),
        (
            "<message to='bad@' id='destination'><body>private payload</body></message>",
            "message",
            "destination",
            "jid-malformed",
            "",
        ),
        (
            "<iq type='get' to='bad@' id='iq-to'><query/></iq>",
            "iq",
            "iq-to",
            "jid-malformed",
            "",
        ),
        (
            "<presence to='bad@' id='presence-to'/>",
            "presence",
            "presence-to",
            "jid-malformed",
            "",
        ),
        (
            "<message from='bad@' to='alice@localhost/desktop' id='source'/>",
            "message",
            "source",
            "jid-malformed",
            " from='alice@localhost/desktop'",
        ),
        (
            "<message from='mallory@localhost' to='bad@' id='spoofed'/>",
            "message",
            "spoofed",
            "jid-malformed",
            "",
        ),
    ] {
        client.send(request)?;
        client.send("<iq type='get' id='sentinel'><query xmlns='jabber:iq:roster'/></iq>")?;
        client.expect_xml(&format!("<{kind} xmlns='jabber:client' type='error' id='{id}' to='alice@localhost/desktop'{from}><error type='modify'><{condition} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></{kind}>"))?;
        client.expect_xml("<iq xmlns='jabber:client' type='result' id='sentinel' to='alice@localhost/desktop'><query xmlns='jabber:iq:roster'/></iq>")?;
    }
    client.close()?;
    let logs = suite.wait_for_log("stream disconnected")?;
    assert!(!logs.contains("bad@") && !logs.contains("private payload"));
    Ok(())
}

#[test]
fn malformed_responses_are_dropped_without_error_loops() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;
    for response in [
        "<iq type='result'/>",
        "<iq type='result' id='two'><query/><query/></iq>",
        "<iq type='result' id='address' to='bad@'/>",
        "<iq type='error'/>",
        "<iq type='error' id='two' to='bad@'><query/><query/><error/></iq>",
        "<message type='error' to='bad@'/>",
        "<presence type='error' from='bad@'><error/></presence>",
        "<presence type='error'>invalid root text</presence>",
    ] {
        client.send(response)?;
        client.send("<message to='alice@localhost/desktop' type='chat' id='sentinel'/>")?;
        client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost/desktop' type='chat' id='sentinel'/>")?;
    }
    client.close()
}

#[test]
fn explicit_empty_ids_survive_valid_stanzas_and_error_replies() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;
    client.send("<iq type='get' id=''><query xmlns='jabber:iq:roster'/></iq>")?;
    client.expect_xml("<iq xmlns='jabber:client' type='result' id='' to='alice@localhost/desktop'><query xmlns='jabber:iq:roster'/></iq>")?;
    client.send("<message to='alice@localhost/desktop' id=''/>")?;
    client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost/desktop' id=''/>")?;
    client.send("<presence type='probe' to='bad@' id=''/>")?;
    client.expect_xml("<presence xmlns='jabber:client' to='alice@localhost/desktop' id='' type='error'><error type='modify'><jid-malformed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")?;
    client.close()
}

#[test]
fn malformed_source_cannot_bypass_binding_identity_validation() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;
    client.send("<iq type='set' id='bind' from='bad@'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desktop</resource></bind></iq>")?;
    client.expect_stream_error("not-authorized")
}

#[test]
fn invalid_namespace_wins_over_recoverable_stanza_errors() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;
    client.send("<iq xmlns='jabber:server' type='future' to='bad@'/>")?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn fatal_errors_in_rejected_envelopes_withdraw_the_bound_resource() -> TestResult {
    let suite = C2sSuite::with_limits("max_stanza_bytes = 10000")?;
    suite.create_account("alice", "pencil")?;
    let mut observer = suite.connect("alice", "pencil", "observer")?;
    observer.send("<presence/>")?;
    observer.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/observer' to='alice@localhost'/>",
    )?;
    for (input, condition) in [
        ("<iq type='future'><query></iq>".to_owned(), "bad-format"),
        (
            "<iq type='future'><!--forbidden--></iq>".to_owned(),
            "restricted-xml",
        ),
        (
            format!(
                "<iq type='future'>{}{}</iq>",
                "<x>".repeat(128),
                "</x>".repeat(128)
            ),
            "bad-format",
        ),
        (
            format!(
                "<iq type='future'><query>{}</query></iq>",
                "x".repeat(10000)
            ),
            "policy-violation",
        ),
    ] {
        let mut client = suite.connect("alice", "pencil", "invalid")?;
        client.send("<presence/>")?;
        client.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/observer' to='alice@localhost'/>")?;
        client.expect_xml(
            "<presence xmlns='jabber:client' from='alice@localhost/invalid' to='alice@localhost'/>",
        )?;
        observer.expect_xml(
            "<presence xmlns='jabber:client' from='alice@localhost/invalid' to='alice@localhost'/>",
        )?;
        client.send(&input)?;
        client.expect_stream_error(condition)?;
        observer.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/invalid' to='alice@localhost' type='unavailable'/>")?;
    }
    observer.close()
}
