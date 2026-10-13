// SPDX-License-Identifier: Apache-2.0

use super::support::{C2sSuite, TestResult};
use std::io::Read as _;
use std::net::Shutdown;
use std::time::{Duration, Instant};

#[test]
fn plaintext_parser_failure_half_closes_and_holds_capacity_until_peer_eof() -> TestResult {
    let suite = C2sSuite::with_limits("max_connections_per_ip = 1")?;
    let mut client = suite.tcp_client()?;
    client.open()?;
    let mut input = Vec::from(b"<message><body></message>".as_slice());
    input.extend_from_slice(&[b'x'; 4096]);
    client.send_bytes(&input)?;
    let error = client.receive()?;
    error.assert_name(super::support::xml::STREAM_NAMESPACE, "error");
    assert_eq!(error.children.len(), 1);
    error.child(super::support::STREAM_ERRORS, "not-well-formed")?;
    client.expect_footer()?;
    assert!(!client.has_buffered_input());
    assert_eq!(client.transport().read(&mut [0; 1])?, 0);

    let mut rejected = suite.tcp_client()?;
    rejected
        .transport()
        .set_read_timeout(Some(Duration::from_millis(200)))?;
    rejected.expect_eof()?;
    client.transport().shutdown(Shutdown::Write)?;
    suite.wait_for_log("outcome=\"not_well_formed\"")?;
    let mut replacement = suite.tcp_client()?;
    replacement.open()?;
    replacement.close()
}

#[test]
fn silent_plaintext_drain_peer_releases_capacity_at_the_original_deadline() -> TestResult {
    let suite = C2sSuite::with_limits("max_connections_per_ip = 1")?;
    let mut client = suite.tcp_client()?;
    client.open()?;
    let started = Instant::now();
    client.send("<message><body></message>")?;
    client
        .receive()?
        .child(super::support::STREAM_ERRORS, "not-well-formed")?;
    client.expect_footer()?;
    assert!(!client.has_buffered_input());
    assert_eq!(client.transport().read(&mut [0; 1])?, 0);
    let mut rejected = suite.tcp_client()?;
    rejected
        .transport()
        .set_read_timeout(Some(Duration::from_millis(200)))?;
    rejected.expect_eof()?;
    suite.wait_for_log("outcome=\"not_well_formed\"")?;
    assert!((Duration::from_secs(5)..Duration::from_secs(7)).contains(&started.elapsed()));
    let mut replacement = suite.tcp_client()?;
    replacement.open()?;
    replacement.close()
}

#[test]
fn healthy_plaintext_close_waits_for_footer_then_holds_capacity_until_peer_eof() -> TestResult {
    let suite = C2sSuite::with_limits("max_connections_per_ip = 1")?;
    let mut client = suite.tcp_client()?;
    client.open()?;
    client.send("<message/>")?;
    client
        .receive()?
        .child(super::support::STREAM_ERRORS, "not-authorized")?;
    client.expect_footer()?;
    assert!(!client.has_buffered_input());
    client
        .transport()
        .set_read_timeout(Some(Duration::from_millis(100)))?;
    let error = client
        .transport()
        .read(&mut [0; 1])
        .expect_err("FIN preceded the reciprocal footer");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    client
        .transport()
        .set_read_timeout(Some(Duration::from_secs(2)))?;
    client.send("</stream:stream>")?;
    assert_eq!(client.transport().read(&mut [0; 1])?, 0);
    let mut rejected = suite.tcp_client()?;
    rejected
        .transport()
        .set_read_timeout(Some(Duration::from_millis(200)))?;
    rejected.expect_eof()?;
    client.transport().shutdown(Shutdown::Write)?;
    suite.wait_for_log("outcome=\"unsupported_input\"")?;
    let mut replacement = suite.tcp_client()?;
    replacement.open()?;
    replacement.close()
}

const PREFIXED_CONTENT_STANZAS: [&str; 6] = [
    "<c:message xmlns:c='jabber:client' to='bob@localhost/desk'/>",
    "<c:message xmlns:c='jabber:client' xmlns='urn:x' to='bob@localhost/desk'><c:body>forbidden</c:body></c:message>",
    "<c:presence xmlns:c='jabber:client' to='bob@localhost/desk'/>",
    "<c:iq xmlns:c='jabber:client' to='bob@localhost/desk' type='get' id='forbidden'><query xmlns='urn:x'/></c:iq>",
    "<message to='bob@localhost/desk'><c:body xmlns:c='jabber:client'>forbidden</c:body></message>",
    "<c:message xmlns:c='jabber:server' to='bob@localhost/desk'/>",
];

#[test]
fn prefixed_content_returns_bad_namespace_prefix_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    for input in PREFIXED_CONTENT_STANZAS {
        let mut client = suite.tcp_client()?;
        client.open()?;
        client.send(input)?;
        client.expect_stream_error("bad-namespace-prefix")?;
    }
    Ok(())
}

#[test]
fn prefixed_content_returns_bad_namespace_prefix_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    for input in PREFIXED_CONTENT_STANZAS {
        let mut client = suite.unauthenticated_client()?;
        client.send(input)?;
        client.expect_stream_error("bad-namespace-prefix")?;
    }
    Ok(())
}

#[test]
fn prefixed_content_returns_bad_namespace_prefix_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    for input in PREFIXED_CONTENT_STANZAS {
        let mut client = suite.authenticated_client("alice", "pencil")?;
        client.send(input)?;
        client.expect_stream_error("bad-namespace-prefix")?;
    }
    Ok(())
}

#[test]
fn prefixed_content_returns_bad_namespace_prefix_without_delivery_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "pencil")?;
    let mut recipient = suite.connect("bob", "pencil", "desk")?;
    for input in PREFIXED_CONTENT_STANZAS {
        let mut sender = suite.connect("alice", "pencil", "desk")?;
        sender.send(&format!(
            "{input}<message to='bob@localhost/desk' id='forbidden'/>"
        ))?;
        sender.expect_stream_error("bad-namespace-prefix")?;
        recipient.send("<message to='bob@localhost/desk' id='sentinel'/>")?;
        recipient.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='bob@localhost/desk' id='sentinel'/>")?;
    }
    recipient.expect_no_tls_input()?;
    let logs = suite.wait_for_log("outcome=\"bad_namespace_prefix\"")?;
    assert!(!logs.contains("<c:message"));
    recipient.close()
}

#[test]
fn explicit_unprefixed_content_routes_on_streams_without_a_default_namespace() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "pencil")?;
    let mut recipient = suite.connect("bob", "pencil", "desk")?;
    let opening = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    let mut plain = suite.tcp_client()?;
    assert_eq!(plain.open_with(opening)?.attribute("xmlns"), None);
    plain.features()?;
    let mut sender = plain.start_tls(&suite)?;
    assert_eq!(sender.open_with(opening)?.attribute("xmlns"), None);
    sender.features()?;
    sender.authenticate("alice", "pencil")?;
    let mut sender = sender.restart();
    assert_eq!(sender.open_with(opening)?.attribute("xmlns"), None);
    sender.features()?;
    sender.send("<iq xmlns='jabber:client' type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    let binding = sender.receive()?;
    binding.assert_name("jabber:client", "iq");
    assert_eq!(binding.attribute("type"), Some("result"));
    assert_eq!(
        binding
            .child("urn:ietf:params:xml:ns:xmpp-bind", "bind")?
            .child("urn:ietf:params:xml:ns:xmpp-bind", "jid")?
            .text,
        "alice@localhost/desk"
    );
    sender.send("<message xmlns='jabber:client' to='bob@localhost/desk' id='valid'><body>allowed</body><forwarded xmlns='urn:xmpp:forward:0'><c:message xmlns:c='jabber:client'/></forwarded><p:x xmlns:p='urn:x'/></message>")?;
    recipient.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' id='valid'><body>allowed</body><forwarded xmlns='urn:xmpp:forward:0'><c:message xmlns:c='jabber:client'/></forwarded><p:x xmlns:p='urn:x'/></message>")?;
    sender.close()?;
    recipient.close()
}

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
fn invalid_namespace_declarations_return_not_well_formed_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send("<message><x xmlns:p=''/></message>")?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn invalid_xml_prefix_binding_returns_not_well_formed_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send("<message xmlns:xml='urn:bad'/>")?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn mismatched_tags_returns_not_well_formed_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<message><body></message>"#)?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn duplicate_attributes_returns_not_well_formed_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;
    client.open()?;

    client.send(r#"<message id='a' id='b'/>"#)?;
    client.expect_stream_error("not-well-formed")
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
fn mismatched_tags_returns_not_well_formed_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<message><body></message>"#)?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn duplicate_attributes_returns_not_well_formed_before_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(r#"<message id='a' id='b'/>"#)?;
    client.expect_stream_error("not-well-formed")
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
fn rejected_iq_allows_correction_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<iq type='subscribe'/>"#)?;
    client.expect_xml("<iq xmlns='jabber:client' type='error' id=''><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    assert_eq!(client.bind(Some("desktop"))?, "alice@localhost/desktop");
    client.close()
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
fn mismatched_tags_returns_not_well_formed_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<message><body></message>"#)?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn duplicate_attributes_returns_not_well_formed_before_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.authenticated_client("alice", "pencil")?;

    client.send(r#"<message id='a' id='b'/>"#)?;
    client.expect_stream_error("not-well-formed")
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
fn invalid_namespace_declarations_return_not_well_formed_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send("<message><x xmlns:p=''/></message>")?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn invalid_xml_prefix_binding_returns_not_well_formed_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send("<message xmlns:xml='urn:bad'/>")?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn undeclared_entity_in_attribute_returns_restricted_xml_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send("<message to='&foo;'/>")?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn undeclared_entity_between_stanzas_returns_restricted_xml_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send("&foo;")?;
    client.expect_stream_error("restricted-xml")
}

#[test]
fn malformed_entity_name_in_attribute_returns_not_well_formed_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send("<message id='&123;'/>")?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn malformed_entity_name_between_stanzas_returns_not_well_formed_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send("&foo:bar;")?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn attribute_count_limit_returns_policy_violation_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;
    let attributes = (0..257)
        .map(|index| format!(" a{index}='v'"))
        .collect::<String>();
    let input = format!("<message{attributes}/>");

    client.send(&input)?;
    client.expect_stream_error("policy-violation")
}

#[test]
fn mismatched_tags_returns_not_well_formed_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<message><body></message>"#)?;
    client.expect_stream_error("not-well-formed")
}

#[test]
fn duplicate_attributes_returns_not_well_formed_after_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desktop")?;

    client.send(r#"<message id='a' id='b'/>"#)?;
    client.expect_stream_error("not-well-formed")
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
    client.expect_stream_error("invalid-from")?;

    let mut replacement = suite.authenticated_client("alice", "pencil")?;
    assert_eq!(
        replacement.bind(Some("desktop"))?,
        "alice@localhost/desktop"
    );
    replacement.close()
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
        (
            "<iq type='future'><query></iq>".to_owned(),
            "not-well-formed",
        ),
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
            "policy-violation",
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

#[test]
fn peer_stream_errors_end_each_open_stream_phase_without_a_reciprocal_error() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    for condition in ["policy-violation", "future-condition"] {
        let error = format!(
            "<stream:error><{condition} xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>private peer error text</text></stream:error>"
        );
        let mut plain = suite.tcp_client()?;
        plain.open()?;
        plain.send(&error)?;
        plain.expect_end()?;
        for phase in 0..4 {
            let mut client = if phase < 2 {
                suite.unauthenticated_client()?
            } else {
                suite.authenticated_client("alice", "pencil")?
            };
            if phase == 1 {
                client.send_sasl_auth("SCRAM-SHA-256", "n,,n=alice,r=nonce")?;
                client.receive_sasl_challenge()?;
            } else if phase == 3 {
                client.bind(Some("desk"))?;
            }
            client.send(&error)?;
            client.expect_end()?;
        }
    }
    let logs = suite.wait_for_log("peer_stream_error")?;
    assert!(!logs.contains("private peer error text"));
    Ok(())
}

#[test]
fn a_stream_error_in_another_namespace_is_not_a_peer_termination() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desk")?;
    client.send("<error xmlns='urn:example:wrong'><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></error>")?;
    client.expect_stream_error("unsupported-stanza-type")
}

#[test]
fn failed_parser_enters_tls_closure_without_interpreting_footer_text() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desk")?;
    client.send("<message><!--forbidden--></message>")?;
    client
        .receive()?
        .child("urn:ietf:params:xml:ns:xmpp-streams", "restricted-xml")?;
    client.expect_footer()?;
    client.expect_tls_close()?;
    client.expect_tcp_open()?;
    client.send_tls_close()?;
    client.expect_tcp_eof()
}

#[test]
fn xml_grammar_errors_close_every_phase_with_complete_and_fragmented_input() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    for phase in 0..4 {
        for fragmented in [false, true] {
            for (prefix, suffix) in [
                ("<message><body></mes", "sage>"),
                ("<message id='a' i", "d='b'/>"),
                ("<message id='a", "<b'/>"),
                ("<message><body>]", "]></body></message>"),
            ] {
                if phase == 0 {
                    let mut client = suite.tcp_client()?;
                    client.open()?;
                    if fragmented {
                        client.send(prefix)?;
                        client.send(suffix)?;
                    } else {
                        client.send(&format!("{prefix}{suffix}"))?;
                    }
                    client.expect_stream_error("not-well-formed")?;
                } else {
                    let mut client = if phase == 1 {
                        suite.unauthenticated_client()?
                    } else {
                        suite.authenticated_client("alice", "pencil")?
                    };
                    if phase == 3 {
                        client.bind(Some("desk"))?;
                    }
                    if fragmented {
                        client.send(prefix)?;
                        client.send(suffix)?;
                    } else {
                        client.send(&format!("{prefix}{suffix}"))?;
                    }
                    client.expect_stream_error("not-well-formed")?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn malformed_xml_prevents_following_stanza_delivery() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "pencil")?;
    let mut recipient = suite.connect("bob", "pencil", "desk")?;
    for malformed in [
        "<message><body></message>",
        "<message id='a' id='b'/>",
        "<message id='a<b'/>",
        "<message><body>]]></body></message>",
    ] {
        let mut sender = suite.connect("alice", "pencil", "desk")?;
        sender.send(&format!(
            "{malformed}<message to='bob@localhost/desk' id='forbidden'/>"
        ))?;
        sender.expect_stream_error("not-well-formed")?;
        recipient.send("<message to='bob@localhost/desk' id='sentinel'/>")?;
        recipient.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='bob@localhost/desk' id='sentinel'/>")?;
    }
    recipient.expect_no_tls_input()?;
    recipient.close()
}
