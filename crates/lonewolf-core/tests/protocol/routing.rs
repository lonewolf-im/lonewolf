// SPDX-License-Identifier: Apache-2.0

use super::support::{C2sSuite, TestResult};

#[test]
fn ipv6_zone_destinations_return_recoverable_jid_malformed_errors() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desktop")?;

    for destination in ["bob@[fe80::1%eth0]", "bob@[fe80::1%25eth0]/phone"] {
        for (kind, attributes, payload) in [
            ("message", "type='chat'", "<body>Hello</body>"),
            ("presence", "", ""),
            ("iq", "type='get'", "<query xmlns='test:query'/>"),
        ] {
            alice.send(&format!(
                "<{kind} {attributes} to='{destination}' id='scoped'>{payload}</{kind}>"
            ))?;
            alice.expect_xml(&format!("<{kind} xmlns='jabber:client' type='error' id='scoped' to='alice@localhost/desktop'><error type='modify'><jid-malformed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></{kind}>"))?;
            alice.send("<message to='alice@localhost/desktop' type='chat' id='sentinel'/>")?;
            alice.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost/desktop' type='chat' id='sentinel'/>")?;
        }
    }
    alice.close()
}

#[test]
fn full_jid_normal_and_chat_reach_unavailable_and_negative_priority_resources() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "secret")?;
    let mut alice = suite.connect("alice", "pencil", "desktop")?;
    let mut bob = suite.connect("bob", "secret", "phone")?;

    for priority in [None, Some(-1)] {
        if let Some(priority) = priority {
            bob.send(&format!(
                "<presence><priority>{priority}</priority></presence>"
            ))?;
            bob.expect_xml(&format!("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'><priority>{priority}</priority></presence>"))?;
        }
        for kind in ["normal", "chat"] {
            alice.send(&format!("<message to='bob@localhost/phone' type='{kind}' id='hello'><body>Hello</body></message>"))?;
            bob.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desktop' to='bob@localhost/phone' type='{kind}' id='hello'><body>Hello</body></message>"))?;
        }
    }
    alice.close()?;
    bob.close()
}

#[test]
fn bare_chat_reaches_the_highest_priority_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut desktop = suite.connect("alice", "pencil", "desktop")?;
    let mut phone = suite.connect("alice", "pencil", "phone")?;

    desktop.send(r#"<presence/>"#)?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.send(
        r#"<presence>
        <priority>5</priority>
     </presence>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>5</priority>
     </presence>"#,
    )?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>5</priority>
     </presence>"#,
    )?;

    desktop.send(r#"<message to='alice@localhost' type='chat' id='hello'/>"#)?;
    phone.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost' id='hello' type='chat'/>"#)?;
    phone.close()?;
    desktop.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost' type='unavailable'/>")?;
    desktop.close()
}

#[test]
fn bare_normal_reaches_the_highest_priority_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut desktop = suite.connect("alice", "pencil", "desktop")?;
    let mut phone = suite.connect("alice", "pencil", "phone")?;

    desktop.send(r#"<presence/>"#)?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.send(
        r#"<presence>
        <priority>5</priority>
     </presence>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>5</priority>
     </presence>"#,
    )?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>5</priority>
     </presence>"#,
    )?;

    desktop.send(r#"<message to='alice@localhost' type='normal' id='hello'/>"#)?;
    phone.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost' id='hello' type='normal'/>"#)?;
    phone.close()?;
    desktop.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost' type='unavailable'/>")?;
    desktop.close()
}

#[test]
fn unavailable_resource_stops_receiving_bare_messages() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut desktop = suite.connect("alice", "pencil", "desktop")?;
    let mut phone = suite.connect("alice", "pencil", "phone")?;

    desktop.send(r#"<presence/>"#)?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.send(
        r#"<presence>
        <priority>5</priority>
     </presence>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>5</priority>
     </presence>"#,
    )?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>5</priority>
     </presence>"#,
    )?;

    phone.send(r#"<presence type='unavailable'/>"#)?;
    desktop.expect_xml(r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost' type='unavailable'/>"#)?;
    phone.expect_xml(r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost' type='unavailable'/>"#)?;

    desktop.send(r#"<message to='alice@localhost' type='normal' id='hello'/>"#)?;
    desktop.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost' id='hello' type='normal'/>"#)?;
    phone.close()?;
    desktop.close()
}

#[test]
fn full_jid_delivery_ignores_unavailable_presence() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence/>"#)?;
    alice.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>"#,
    )?;
    alice.send(r#"<presence type='unavailable'/>"#)?;
    alice.expect_xml(r#"<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost' type='unavailable'/>"#)?;

    alice.send(r#"<message to='alice@localhost/desk' type='chat' id='hello'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='hello' type='chat'/>"#)?;
    alice.close()
}

#[test]
fn negative_priority_excludes_a_resource_from_bare_delivery() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<presence>
        <priority>-1</priority>
     </presence>"#,
    )?;
    alice.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'>
        <priority>-1</priority>
     </presence>"#,
    )?;

    alice.send(r#"<message to='alice@localhost' type='chat' id='hello'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='hello' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn full_jid_delivery_ignores_negative_priority() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<presence>
        <priority>-1</priority>
     </presence>"#,
    )?;
    alice.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'>
        <priority>-1</priority>
     </presence>"#,
    )?;

    alice.send(r#"<message to='alice@localhost/desk' type='chat' id='hello'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='hello' type='chat'/>"#)?;
    alice.close()
}

#[test]
fn equal_priorities_route_chat_to_the_oldest_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut desktop = suite.connect("alice", "pencil", "desktop")?;
    let mut phone = suite.connect("alice", "pencil", "phone")?;

    desktop.send(r#"<presence/>"#)?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.send(
        r#"<presence>
        <priority>0</priority>
     </presence>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>0</priority>
     </presence>"#,
    )?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>0</priority>
     </presence>"#,
    )?;

    desktop.send(r#"<message to='alice@localhost' type='chat' id='hello'/>"#)?;
    desktop.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost' id='hello' type='chat'/>"#)?;
    phone.close()?;
    desktop.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost' type='unavailable'/>")?;
    desktop.close()
}

#[test]
fn headline_reaches_every_available_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut desktop = suite.connect("alice", "pencil", "desktop")?;
    let mut phone = suite.connect("alice", "pencil", "phone")?;

    desktop.send(r#"<presence/>"#)?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.send(
        r#"<presence>
        <priority>0</priority>
     </presence>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>0</priority>
     </presence>"#,
    )?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>0</priority>
     </presence>"#,
    )?;

    desktop.send(r#"<message to='alice@localhost' type='headline' id='news'/>"#)?;
    desktop.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost' id='news' type='headline'/>"#)?;
    phone.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost' id='news' type='headline'/>"#)?;
    phone.close()?;
    desktop.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost' type='unavailable'/>")?;
    desktop.close()
}

#[test]
fn headline_skips_a_negative_priority_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut desktop = suite.connect("alice", "pencil", "desktop")?;
    let mut phone = suite.connect("alice", "pencil", "phone")?;

    desktop.send(r#"<presence/>"#)?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.send(
        r#"<presence>
        <priority>-1</priority>
     </presence>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>-1</priority>
     </presence>"#,
    )?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>-1</priority>
     </presence>"#,
    )?;

    desktop.send(r#"<message to='alice@localhost' type='headline' id='news'/>"#)?;
    desktop.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost' id='news' type='headline'/>"#)?;
    desktop.send(r#"<message to='alice@localhost/phone' type='normal' id='sentinel'/>"#)?;
    phone.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost/phone' id='sentinel' type='normal'/>"#)?;
    phone.close()?;
    desktop.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost' type='unavailable'/>")?;
    desktop.close()
}

#[test]
fn missing_full_jid_chat_falls_back_without_changing_the_destination() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence/>"#)?;
    alice.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>"#,
    )?;

    alice.send(r#"<message to='alice@localhost/missing' type='chat' id='hello'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/missing' id='hello' type='chat'/>"#)?;
    alice.close()
}

#[test]
fn missing_full_jid_normal_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence/>"#)?;
    alice.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>"#,
    )?;

    alice.send(r#"<message to='alice@localhost/missing' type='normal' id='hello'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='hello' from='alice@localhost/missing' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn missing_full_jid_headline_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence/>"#)?;
    alice.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>"#,
    )?;

    alice.send(r#"<message to='alice@localhost/missing' type='headline' id='hello'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='hello' from='alice@localhost/missing' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn missing_full_jid_groupchat_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence/>"#)?;
    alice.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>"#,
    )?;

    alice.send(r#"<message to='alice@localhost/missing' type='groupchat' id='hello'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='hello' from='alice@localhost/missing' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn unavailable_account_returns_service_unavailable_with_the_original_payload() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<message to='alice@localhost' from='mallory@localhost' type='chat' id='failed'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra>
     </message>"#,
    )?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='failed' from='alice@localhost' to='alice@localhost/desk'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn offline_account_returns_service_unavailable_with_the_original_payload() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("offline", "secret")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<message to='offline@localhost' from='mallory@localhost' type='normal' id='failed'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra>
     </message>"#,
    )?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='failed' from='offline@localhost' to='alice@localhost/desk'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn unknown_account_returns_service_unavailable_with_the_original_payload() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<message to='missing@localhost' from='mallory@localhost' type='chat' id='failed'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra>
     </message>"#,
    )?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='failed' from='missing@localhost' to='alice@localhost/desk'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn missing_full_jid_without_fallback_returns_service_unavailable_with_the_original_payload()
-> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<message to='alice@localhost/missing' from='mallory@localhost' type='chat' id='failed'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra>
     </message>"#,
    )?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='failed' from='alice@localhost/missing' to='alice@localhost/desk'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn remote_account_returns_service_unavailable_with_the_original_payload() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<message to='alice@remote.example' from='mallory@localhost' type='chat' id='failed'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra>
     </message>"#,
    )?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='failed' from='alice@remote.example' to='alice@localhost/desk'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn server_domain_returns_service_unavailable_with_the_original_payload() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<message to='localhost' from='mallory@localhost' type='chat' id='failed'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra>
     </message>"#,
    )?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='failed' from='localhost' to='alice@localhost/desk'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn bare_groupchat_returns_service_unavailable_with_the_original_payload() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<message to='alice@localhost' from='mallory@localhost' type='groupchat' id='failed'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra>
     </message>"#,
    )?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='failed' from='alice@localhost' to='alice@localhost/desk'>
        <body>Keep &amp; escape</body><extra xmlns='urn:test:payload'>value</extra><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn bare_error_is_silently_dropped() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<message to='alice@localhost' type='error' id='silent'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.send(r#"<message to='alice@localhost/desk' type='normal' id='sentinel'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel' type='normal'/>"#)?;
    alice.close()
}

#[test]
fn unknown_account_error_is_silently_dropped() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<message to='missing@localhost' type='error' id='silent'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.send(r#"<message to='alice@localhost/desk' type='normal' id='sentinel'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel' type='normal'/>"#)?;
    alice.close()
}

#[test]
fn missing_full_jid_error_is_silently_dropped() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<message to='alice@localhost/missing' type='error' id='silent'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.send(r#"<message to='alice@localhost/desk' type='normal' id='sentinel'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel' type='normal'/>"#)?;
    alice.close()
}

#[test]
fn remote_error_is_silently_dropped() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<message to='alice@remote.example' type='error' id='silent'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.send(r#"<message to='alice@localhost/desk' type='normal' id='sentinel'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel' type='normal'/>"#)?;
    alice.close()
}

#[test]
fn unavailable_account_headline_is_silently_dropped() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<message to='alice@localhost' type='headline' id='silent'/>"#)?;
    alice.send(r#"<message to='alice@localhost/desk' type='normal' id='sentinel'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel' type='normal'/>"#)?;
    alice.close()
}

#[test]
fn unknown_account_headline_is_silently_dropped() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<message to='missing@localhost' type='headline' id='silent'/>"#)?;
    alice.send(r#"<message to='alice@localhost/desk' type='normal' id='sentinel'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel' type='normal'/>"#)?;
    alice.close()
}

#[test]
fn bare_error_is_dropped_but_full_jid_error_is_delivered() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence/>"#)?;
    alice.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>"#,
    )?;

    alice.send(r#"<message to='alice@localhost' type='error' id='bare-error'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.send(r#"<message to='alice@localhost/desk' type='error' id='full-error'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='full-error' type='error'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn message_without_destination_routes_to_own_bare_jid() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence/>"#)?;
    alice.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>"#,
    )?;

    alice.send(r#"<message id='self' xml:lang='es'><body>Hola &amp; adiós</body><x xmlns='urn:test:outer'><value xmlns='urn:test:inner'>✓</value></x></message>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost' id='self' xml:lang='es'>
        <body>Hola &amp; adiós</body>
        <x xmlns='urn:test:outer'><value xmlns='urn:test:inner'>✓</value></x>
     </message>"#)?;
    alice.close()
}

#[test]
fn presence_sender_is_replaced_with_the_authenticated_full_jid() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence from='mallory@localhost/spy'><priority>7</priority></presence>"#)?;
    alice.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'>
        <priority>7</priority>
     </presence>"#,
    )?;
    alice.close()
}

#[test]
fn presence_priority_above_maximum_does_not_make_the_resource_available() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<presence id='priority'>
        <priority>128</priority>
     </presence>"#,
    )?;
    alice.expect_xml(r#"<presence xmlns='jabber:client' type='error' id='priority' from='alice@localhost' to='alice@localhost/desk'>
        <priority>128</priority><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </presence>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn presence_priority_below_minimum_does_not_make_the_resource_available() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<presence id='priority'>
        <priority>-129</priority>
     </presence>"#,
    )?;
    alice.expect_xml(r#"<presence xmlns='jabber:client' type='error' id='priority' from='alice@localhost' to='alice@localhost/desk'>
        <priority>-129</priority><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </presence>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn presence_priority_nonnumeric_does_not_make_the_resource_available() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<presence id='priority'>
        <priority>many</priority>
     </presence>"#,
    )?;
    alice.expect_xml(r#"<presence xmlns='jabber:client' type='error' id='priority' from='alice@localhost' to='alice@localhost/desk'>
        <priority>many</priority><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </presence>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn presence_priority_empty_does_not_make_the_resource_available() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<presence id='priority'>
        <priority/>
     </presence>"#,
    )?;
    alice.expect_xml(r#"<presence xmlns='jabber:client' type='error' id='priority' from='alice@localhost' to='alice@localhost/desk'>
        <priority/><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </presence>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn presence_priority_with_attributes_does_not_make_the_resource_available() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<presence id='priority'>
        <priority extra='1'>1</priority>
     </presence>"#,
    )?;
    alice.expect_xml(r#"<presence xmlns='jabber:client' type='error' id='priority' from='alice@localhost' to='alice@localhost/desk'>
        <priority extra='1'>1</priority><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </presence>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn presence_priority_duplicate_does_not_make_the_resource_available() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<presence id='priority'>
        <priority>1</priority><priority>2</priority>
     </presence>"#,
    )?;
    alice.expect_xml(r#"<presence xmlns='jabber:client' type='error' id='priority' from='alice@localhost' to='alice@localhost/desk'>
        <priority>1</priority><priority>2</priority><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </presence>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn directed_presence_does_not_change_local_availability() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence to='alice@localhost'/>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn subscribe_presence_does_not_change_local_availability() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence type='subscribe'/>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn subscribed_presence_does_not_change_local_availability() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence type='subscribed'/>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn unsubscribe_presence_does_not_change_local_availability() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence type='unsubscribe'/>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn unsubscribed_presence_does_not_change_local_availability() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence type='unsubscribed'/>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn probe_presence_does_not_change_local_availability() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence type='probe'/>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn error_presence_does_not_change_local_availability() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<presence type='error'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </presence>"#)?;
    alice.send(r#"<message to='alice@localhost' type='chat' id='unavailable'/>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' type='error' id='unavailable' from='alice@localhost' to='alice@localhost/desk'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </message>"#)?;
    alice.close()
}

#[test]
fn stream_close_broadcasts_unavailable_and_releases_the_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut desktop = suite.connect("alice", "pencil", "desktop")?;
    let mut phone = suite.connect("alice", "pencil", "phone")?;

    desktop.send(r#"<presence/>"#)?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.send(
        r#"<presence>
        <priority>5</priority>
     </presence>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>5</priority>
     </presence>"#,
    )?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>5</priority>
     </presence>"#,
    )?;

    phone.close()?;
    drop(phone);
    desktop.expect_xml(r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost' type='unavailable'/>"#)?;

    desktop.send(r#"<message to='alice@localhost' type='chat' id='remaining'/>"#)?;
    desktop.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost' id='remaining' type='chat'/>"#)?;
    let mut rebound = suite.connect("alice", "pencil", "phone")?;
    rebound.close()?;
    desktop.close()
}

#[test]
fn tcp_disconnect_broadcasts_unavailable_and_releases_the_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut desktop = suite.connect("alice", "pencil", "desktop")?;
    let mut phone = suite.connect("alice", "pencil", "phone")?;

    desktop.send(r#"<presence/>"#)?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.send(
        r#"<presence>
        <priority>5</priority>
     </presence>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost'/>"#,
    )?;
    phone.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>5</priority>
     </presence>"#,
    )?;
    desktop.expect_xml(
        r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'>
        <priority>5</priority>
     </presence>"#,
    )?;

    drop(phone);
    desktop.expect_xml(r#"<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost' type='unavailable'/>"#)?;

    desktop.send(r#"<message to='alice@localhost' type='chat' id='remaining'/>"#)?;
    desktop.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desktop' to='alice@localhost' id='remaining' type='chat'/>"#)?;
    let mut rebound = suite.connect("alice", "pencil", "phone")?;
    rebound.close()?;
    desktop.close()
}

#[test]
fn unsupported_unaddressed_iq_get_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<iq from='mallory@localhost/spy' type='get' id='unsupported'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#,
    )?;
    alice.expect_xml(r#"<iq xmlns='jabber:client' type='error' id='unsupported'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </iq>"#)?;
    alice.close()
}

#[test]
fn unsupported_server_iq_get_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<iq from='mallory@localhost/spy' type='get' id='unsupported' to='localhost'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#,
    )?;
    alice.expect_xml(r#"<iq xmlns='jabber:client' type='error' id='unsupported' from='localhost'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </iq>"#)?;
    alice.close()
}

#[test]
fn unsupported_remote_server_iq_get_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<iq from='mallory@localhost/spy' type='get' id='unsupported' to='remote.example'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#,
    )?;
    alice.expect_xml(r#"<iq xmlns='jabber:client' type='error' id='unsupported' from='remote.example'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </iq>"#)?;
    alice.close()
}

#[test]
fn unsupported_bare_jid_iq_get_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<iq from='mallory@localhost/spy' type='get' id='unsupported' to='alice@localhost'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#,
    )?;
    alice.expect_xml(r#"<iq xmlns='jabber:client' type='error' id='unsupported' from='alice@localhost'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </iq>"#)?;
    alice.close()
}

#[test]
fn full_jid_iq_get_reaches_its_sender_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<iq from='mallory@localhost/spy' type='get' id='unsupported' to='alice@localhost/desk'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#,
    )?;
    alice.expect_xml(r#"<iq xmlns='jabber:client' type='get' id='unsupported' from='alice@localhost/desk' to='alice@localhost/desk'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#)?;
    alice.close()
}

#[test]
fn unsupported_unaddressed_iq_set_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<iq from='mallory@localhost/spy' type='set' id='unsupported'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#,
    )?;
    alice.expect_xml(r#"<iq xmlns='jabber:client' type='error' id='unsupported'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </iq>"#)?;
    alice.close()
}

#[test]
fn unsupported_server_iq_set_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<iq from='mallory@localhost/spy' type='set' id='unsupported' to='localhost'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#,
    )?;
    alice.expect_xml(r#"<iq xmlns='jabber:client' type='error' id='unsupported' from='localhost'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </iq>"#)?;
    alice.close()
}

#[test]
fn unsupported_remote_server_iq_set_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<iq from='mallory@localhost/spy' type='set' id='unsupported' to='remote.example'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#,
    )?;
    alice.expect_xml(r#"<iq xmlns='jabber:client' type='error' id='unsupported' from='remote.example'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </iq>"#)?;
    alice.close()
}

#[test]
fn unsupported_bare_jid_iq_set_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<iq from='mallory@localhost/spy' type='set' id='unsupported' to='alice@localhost'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#,
    )?;
    alice.expect_xml(r#"<iq xmlns='jabber:client' type='error' id='unsupported' from='alice@localhost'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </iq>"#)?;
    alice.close()
}

#[test]
fn full_jid_iq_set_reaches_its_sender_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(
        r#"<iq from='mallory@localhost/spy' type='set' id='unsupported' to='alice@localhost/desk'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#,
    )?;
    alice.expect_xml(r#"<iq xmlns='jabber:client' type='set' id='unsupported' from='alice@localhost/desk' to='alice@localhost/desk'>
        <query xmlns='urn:test:outer'><child xmlns='urn:test:inner'/></query>
     </iq>"#)?;
    alice.close()
}

#[test]
fn unsolicited_iq_result_is_ignored() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<iq type='result' id='orphan'/>"#)?;
    alice.close()
}

#[test]
fn unsolicited_iq_error_is_ignored() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<iq type='error' id='orphan'>
        <error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     </iq>"#)?;
    alice.close()
}

#[test]
fn pipelined_self_messages_drain_the_outbound_mailbox_in_order() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.connect("alice", "pencil", "desk")?;
    let mut batch = String::new();
    for index in 0..64 {
        use std::fmt::Write;
        write!(
            batch,
            "<message to='alice@localhost/desk' type='chat' id='{index}'/>"
        )?;
    }
    client.send(&batch)?;
    for index in 0..64 {
        client.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' type='chat' id='{index}'/>"))?;
    }
    client.close()
}

#[test]
fn message_sender_is_replaced_with_the_authenticated_full_jid() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send(r#"<message from='mallory@localhost/spy' to='alice@localhost/desk' type='chat' id='spoof'><body>Hello</body></message>"#)?;
    alice.expect_xml(r#"<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='spoof' type='chat'>
        <body>Hello</body>
     </message>"#)?;
    alice.close()
}

#[test]
fn unknown_message_type_uses_normal_routing_and_preserves_the_original_xml() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "secret")?;
    let mut alice = suite.unauthenticated_client()?;
    alice.authenticate("alice", "pencil")?;
    let mut alice = alice.restart();
    alice.open_with(&super::support::OPEN.replace('>', " xml:lang='es'>"))?;
    alice.features()?;
    alice.bind(Some("sender"))?;
    let mut desktop = suite.connect("bob", "secret", "desktop")?;
    let mut phone = suite.connect("bob", "secret", "phone")?;
    desktop.send("<presence/>")?;
    desktop.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/desktop' to='bob@localhost'/>",
    )?;
    phone.send("<presence><priority>5</priority></presence>")?;
    phone.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/desktop' to='bob@localhost'/>",
    )?;
    phone.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'><priority>5</priority></presence>")?;
    desktop.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'><priority>5</priority></presence>")?;

    alice.send("<message to='bob@localhost' from='mallory@localhost' type='future-type' id='bare' custom='kept'><body>Hello</body><extra xmlns='urn:test:payload'>value</extra></message>")?;
    phone.expect_xml("<message xmlns='jabber:client' from='alice@localhost/sender' to='bob@localhost' type='future-type' id='bare' custom='kept' xml:lang='es'><body>Hello</body><extra xmlns='urn:test:payload'>value</extra></message>")?;
    alice.send("<message to='bob@localhost/desktop' type='future-type' id='full'><body>Exact</body></message>")?;
    desktop.expect_xml("<message xmlns='jabber:client' from='alice@localhost/sender' to='bob@localhost/desktop' type='future-type' id='full' xml:lang='es'><body>Exact</body></message>")?;
    alice.send("<message to='bob@localhost/desktop' id='absent' xml:lang=''/>")?;
    desktop.expect_xml("<message xmlns='jabber:client' from='alice@localhost/sender' to='bob@localhost/desktop' id='absent' xml:lang=''/>")?;
    alice.close()?;
    phone.close()?;
    desktop.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost' type='unavailable'/>")?;
    desktop.close()
}

#[test]
fn directed_full_jid_iq_exchanges_preserve_envelopes_and_sender_order() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    bob.send("<presence to='alice@localhost/desk'/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk'/>",
    )?;

    alice.send("<iq type='get' from='mallory@localhost/spy' to='bob@localhost/phone' id='get' xml:lang='es'><query xmlns='urn:lonewolf:test:iq'><value>kept</value></query></iq>")?;
    alice.send("<iq type='set' to='bob@localhost/phone' id='set' xml:lang='fr'><query xmlns='urn:lonewolf:test:iq'><value>changed</value></query></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='get' from='alice@localhost/desk' to='bob@localhost/phone' id='get' xml:lang='es'><query xmlns='urn:lonewolf:test:iq'><value>kept</value></query></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='set' from='alice@localhost/desk' to='bob@localhost/phone' id='set' xml:lang='fr'><query xmlns='urn:lonewolf:test:iq'><value>changed</value></query></iq>")?;
    bob.send("<iq type='result' from='mallory@localhost/spy' to='alice@localhost/desk' id='get' xml:lang='es'><query xmlns='urn:lonewolf:test:iq'><value>answer</value></query></iq>")?;
    bob.send("<iq type='error' to='alice@localhost/desk' id='set' xml:lang='fr'><query xmlns='urn:lonewolf:test:iq'><value>changed</value></query><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='bob@localhost/phone' to='alice@localhost/desk' id='get' xml:lang='es'><query xmlns='urn:lonewolf:test:iq'><value>answer</value></query></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='bob@localhost/phone' to='alice@localhost/desk' id='set' xml:lang='fr'><query xmlns='urn:lonewolf:test:iq'><value>changed</value></query><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    bob.send("<presence to='alice@localhost/desk' type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='bob@localhost/phone' to='alice@localhost/desk'/>")?;
    alice.send(
        "<iq type='get' to='bob@localhost/phone' id='revoked'><query xmlns='urn:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='bob@localhost/phone' to='alice@localhost/desk' id='revoked'><query xmlns='urn:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn missing_and_unauthorized_full_jid_iq_requests_have_the_same_error() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    for target in [
        "bob@localhost/phone",
        "bob@localhost/missing",
        "nobody@localhost/phone",
    ] {
        alice.send(&format!(
            "<iq type='get' to='{target}' id='denied'><query xmlns='urn:test:iq'/></iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}' to='alice@localhost/desk' id='denied'><query xmlns='urn:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"))?;
    }
    alice.close()?;
    bob.close()
}

#[test]
fn full_jid_iq_responses_ignore_presence_and_do_not_generate_error_loops() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    for priority in ["", "<priority>-1</priority>"] {
        if !priority.is_empty() {
            bob.send(&format!("<presence>{priority}</presence>"))?;
            bob.expect_xml(&format!("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'>{priority}</presence>"))?;
        }
        alice.send("<iq type='result' to='bob@localhost/phone' id='answer'><query xmlns='urn:test:iq'/></iq>")?;
        alice.send("<iq type='error' to='bob@localhost/phone' id='failure'><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
        bob.expect_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost/desk' to='bob@localhost/phone' id='answer'><query xmlns='urn:test:iq'/></iq>")?;
        bob.expect_xml("<iq xmlns='jabber:client' type='error' from='alice@localhost/desk' to='bob@localhost/phone' id='failure'><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    }
    for target in [
        "bob@localhost/missing",
        "bob@remote.example/phone",
        "localhost",
        "bob@localhost",
    ] {
        alice.send(&format!("<iq type='result' to='{target}' id='discard'/><iq type='error' to='{target}' id='discard'><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"))?;
    }
    alice.send("<iq type='get' id='sentinel'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='sentinel' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='alice@localhost'/></iq>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn roster_subscription_authorizes_full_jid_iq_until_revoked() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    alice.send("<presence type='subscribe' to='bob@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='subscribe' from='alice@localhost' to='bob@localhost'/>")?;
    bob.send("<presence type='subscribed' to='alice@localhost'/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost'/>",
    )?;
    alice.send(
        "<iq type='get' to='bob@localhost/phone' id='allowed'><query xmlns='urn:test:iq'/></iq>",
    )?;
    bob.expect_xml("<iq xmlns='jabber:client' type='get' from='alice@localhost/desk' to='bob@localhost/phone' id='allowed'><query xmlns='urn:test:iq'/></iq>")?;
    bob.send("<presence type='unsubscribed' to='alice@localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='bob@localhost/phone' to='alice@localhost'/>")?;
    alice.send(
        "<iq type='set' to='bob@localhost/phone' id='revoked'><query xmlns='urn:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='bob@localhost/phone' to='alice@localhost/desk' id='revoked'><query xmlns='urn:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()?;
    bob.close()
}
