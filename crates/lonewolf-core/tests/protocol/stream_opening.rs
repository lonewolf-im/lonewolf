// SPDX-License-Identifier: Apache-2.0

use super::support::{C2sSuite, TestResult};

#[test]
fn initial_opening_selects_the_served_host() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0'>"#)?;
    assert_eq!(header.attribute("from"), Some("localhost"));
    assert_eq!(header.attribute("version"), Some("1.0"));
    assert_eq!(header.attribute("xml:lang"), Some("en"));
    assert_eq!(header.attribute("to"), None);
    assert_eq!(header.attribute("xmlns"), Some("jabber:client"));
    let id = header.attribute("id").ok_or("missing stream id")?;
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>
    </stream:features>",
    )?;
    client.close()
}

#[test]
fn opening_without_to_selects_the_default_host() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>"#)?;
    assert_eq!(header.attribute("from"), Some("localhost"));
    assert_eq!(header.attribute("version"), Some("1.0"));
    assert_eq!(header.attribute("xml:lang"), Some("en"));
    assert_eq!(header.attribute("to"), None);
    assert_eq!(header.attribute("xmlns"), Some("jabber:client"));
    let id = header.attribute("id").ok_or("missing stream id")?;
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>
    </stream:features>",
    )?;
    client.close()
}

#[test]
fn zero_padded_version_is_compared_numerically() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='01.000'>"#)?;
    assert_eq!(header.attribute("from"), Some("localhost"));
    assert_eq!(header.attribute("version"), Some("1.0"));
    assert_eq!(header.attribute("xml:lang"), Some("en"));
    assert_eq!(header.attribute("to"), None);
    assert_eq!(header.attribute("xmlns"), Some("jabber:client"));
    let id = header.attribute("id").ok_or("missing stream id")?;
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>
    </stream:features>",
    )?;
    client.close()
}

#[test]
fn higher_minor_version_negotiates_one() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.13'>"#)?;
    assert_eq!(header.attribute("from"), Some("localhost"));
    assert_eq!(header.attribute("version"), Some("1.0"));
    assert_eq!(header.attribute("xml:lang"), Some("en"));
    assert_eq!(header.attribute("to"), None);
    assert_eq!(header.attribute("xmlns"), Some("jabber:client"));
    let id = header.attribute("id").ok_or("missing stream id")?;
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>
    </stream:features>",
    )?;
    client.close()
}

#[test]
fn higher_major_version_negotiates_one() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='12.3'>"#)?;
    assert_eq!(header.attribute("from"), Some("localhost"));
    assert_eq!(header.attribute("version"), Some("1.0"));
    assert_eq!(header.attribute("xml:lang"), Some("en"));
    assert_eq!(header.attribute("to"), None);
    assert_eq!(header.attribute("xmlns"), Some("jabber:client"));
    let id = header.attribute("id").ok_or("missing stream id")?;
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>
    </stream:features>",
    )?;
    client.close()
}

#[test]
fn large_version_number_negotiates_one() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='999999999999999999999.0'>"#)?;
    assert_eq!(header.attribute("from"), Some("localhost"));
    assert_eq!(header.attribute("version"), Some("1.0"));
    assert_eq!(header.attribute("xml:lang"), Some("en"));
    assert_eq!(header.attribute("to"), None);
    assert_eq!(header.attribute("xmlns"), Some("jabber:client"));
    let id = header.attribute("id").ok_or("missing stream id")?;
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>
    </stream:features>",
    )?;
    client.close()
}

#[test]
fn opening_response_addresses_the_normalized_bare_sender() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' from='Alice@LOCALHOST/Phone' xml:lang='es' version='1.0'>"#)?;
    assert_eq!(header.attribute("from"), Some("localhost"));
    assert_eq!(header.attribute("version"), Some("1.0"));
    assert_eq!(header.attribute("xml:lang"), Some("en"));
    assert_eq!(header.attribute("to"), Some("alice@localhost"));
    assert_eq!(header.attribute("xmlns"), Some("jabber:client"));
    let id = header.attribute("id").ok_or("missing stream id")?;
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>
    </stream:features>",
    )?;
    client.close()
}

#[test]
fn opening_preserves_a_prefix_free_content_namespace() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>"#)?;
    assert_eq!(header.attribute("from"), Some("localhost"));
    assert_eq!(header.attribute("version"), Some("1.0"));
    assert_eq!(header.attribute("xml:lang"), Some("en"));
    assert_eq!(header.attribute("to"), None);
    assert_eq!(header.attribute("xmlns"), None);
    let id = header.attribute("id").ok_or("missing stream id")?;
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>
    </stream:features>",
    )?;
    client.close()
}

#[test]
fn utf8_bom_and_declaration_are_accepted() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with("\u{feff}<?xml version='1.0' encoding='UTF-8'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0'>")?;
    assert_eq!(header.attribute("from"), Some("localhost"));
    assert_eq!(header.attribute("version"), Some("1.0"));
    assert_eq!(header.attribute("xml:lang"), Some("en"));
    assert_eq!(header.attribute("to"), None);
    assert_eq!(header.attribute("xmlns"), Some("jabber:client"));
    let id = header.attribute("id").ok_or("missing stream id")?;
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>
    </stream:features>",
    )?;
    client.close()
}

#[test]
fn unknown_host_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='unknown.example' version='1.0'>"#)?;
    client.expect_stream_error("host-unknown")
}

#[test]
fn account_destination_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='alice@localhost' version='1.0'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn resource_destination_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost/phone' version='1.0'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn malformed_destination_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='bad domain' version='1.0'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn old_version_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='0.9'>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn missing_version_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' >"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn signed_version_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='+1.0'>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn nonnumeric_version_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.x'>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn malformed_language_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' xml:lang='en_US'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn empty_language_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' xml:lang=''>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn malformed_sender_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' from='bad domain'>"#)?;
    client.expect_stream_error("invalid-from")
}

#[test]
fn duplicate_attribute_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' to='localhost'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn server_content_namespace_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' to='localhost' version='1.0'>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn wrong_stream_namespace_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='urn:invalid:stream' xmlns='jabber:client' to='localhost' version='1.0'>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn xml_version_1_1_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    let header = client.open_with(r#"<?xml version='1.1'?>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn non_utf8_declaration_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with(r#"<?xml version='1.0' encoding='ISO-8859-1'?>"#)?;
    client.expect_stream_error("unsupported-encoding")
}

#[test]
fn non_xml_opening_is_rejected_before_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tcp_client()?;

    client.open_with("!")?;
    client.expect_stream_error("bad-format")
}

#[test]
fn unknown_host_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='unknown.example' version='1.0'>"#)?;
    client.expect_stream_error("host-unknown")
}

#[test]
fn account_destination_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='alice@localhost' version='1.0'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn resource_destination_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost/phone' version='1.0'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn malformed_destination_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='bad domain' version='1.0'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn old_version_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='0.9'>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn missing_version_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' >"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn signed_version_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='+1.0'>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn nonnumeric_version_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.x'>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn malformed_language_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' xml:lang='en_US'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn empty_language_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' xml:lang=''>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn malformed_sender_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' from='bad domain'>"#)?;
    client.expect_stream_error("invalid-from")
}

#[test]
fn duplicate_attribute_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' to='localhost'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn server_content_namespace_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' to='localhost' version='1.0'>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn wrong_stream_namespace_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with(r#"<stream:stream xmlns:stream='urn:invalid:stream' xmlns='jabber:client' to='localhost' version='1.0'>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn xml_version_1_1_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    let header = client.open_with(r#"<?xml version='1.1'?>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn non_utf8_declaration_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with(r#"<?xml version='1.0' encoding='ISO-8859-1'?>"#)?;
    client.expect_stream_error("unsupported-encoding")
}

#[test]
fn non_xml_opening_is_rejected_after_tls() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.tls_client()?;

    client.open_with("!")?;
    client.expect_stream_error("bad-format")
}

#[test]
fn unknown_host_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='unknown.example' version='1.0'>"#)?;
    client.expect_stream_error("host-unknown")
}

#[test]
fn account_destination_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='alice@localhost' version='1.0'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn resource_destination_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost/phone' version='1.0'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn malformed_destination_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='bad domain' version='1.0'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn old_version_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='0.9'>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn missing_version_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' >"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn signed_version_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='+1.0'>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn nonnumeric_version_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    let header = client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.x'>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn malformed_language_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' xml:lang='en_US'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn empty_language_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' xml:lang=''>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn malformed_sender_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' from='bad domain'>"#)?;
    client.expect_stream_error("invalid-from")
}

#[test]
fn duplicate_attribute_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0' to='localhost'>"#)?;
    client.expect_stream_error("bad-format")
}

#[test]
fn server_content_namespace_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' to='localhost' version='1.0'>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn wrong_stream_namespace_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<stream:stream xmlns:stream='urn:invalid:stream' xmlns='jabber:client' to='localhost' version='1.0'>"#)?;
    client.expect_stream_error("invalid-namespace")
}

#[test]
fn xml_version_1_1_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    let header = client.open_with(r#"<?xml version='1.1'?>"#)?;
    assert_eq!(header.attribute("version"), None);
    client.expect_stream_error("unsupported-version")
}

#[test]
fn non_utf8_declaration_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<?xml version='1.0' encoding='ISO-8859-1'?>"#)?;
    client.expect_stream_error("unsupported-encoding")
}

#[test]
fn non_xml_opening_is_rejected_after_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with("!")?;
    client.expect_stream_error("bad-format")
}

#[test]
fn restart_sender_must_match_the_authenticated_account() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();

    client.open_with(r#"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' from='bob@localhost' to='localhost' version='1.0'>"#)?;
    client.expect_stream_error("invalid-from")
}
