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
fn invalid_iq_type_returns_invalid_xml_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<iq type='subscribe'/>"#)?;
    client.expect_stream_error("invalid-xml")
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
fn invalid_iq_type_returns_invalid_xml_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<iq type='subscribe'/>"#)?;
    client.expect_stream_error("invalid-xml")
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
fn invalid_iq_type_returns_invalid_xml_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<iq type='subscribe'/>"#)?;
    client.expect_stream_error("invalid-xml")
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
fn invalid_iq_type_returns_invalid_xml_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<iq type='subscribe'/>"#)?;
    client.expect_stream_error("invalid-xml")
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
