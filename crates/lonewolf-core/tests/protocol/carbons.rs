// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use rustls::pki_types::ServerName;

use crate::support::{C2sSuite, Client, OPEN, PASSWORD, TestResult, barrier};

const UNAVAILABLE: &str = "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error>";
const FEATURES: &str =
    "<feature var='urn:xmpp:carbons:2'/><feature var='urn:xmpp:carbons:rules:0'/>";

fn accounts(suite: &C2sSuite) -> TestResult {
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)
}

fn enable(client: &mut Client, full: &str) -> TestResult {
    client.send("<iq type='set' id='enable'><enable xmlns='urn:xmpp:carbons:2'/></iq>")?;
    client.expect_xml(&format!(
        "<iq xmlns='jabber:client' type='result' id='enable' to='{full}'/>"
    ))
}

fn disable(client: &mut Client, full: &str) -> TestResult {
    client.send("<iq type='set' id='disable'><disable xmlns='urn:xmpp:carbons:2'/></iq>")?;
    client.expect_xml(&format!(
        "<iq xmlns='jabber:client' type='result' id='disable' to='{full}'/>"
    ))
}

fn available(client: &mut Client, full: &str, priority: i8) -> TestResult {
    let bare = full.split_once('/').ok_or("missing resource")?.0;
    client.send(&format!(
        "<presence><priority>{priority}</priority></presence>"
    ))?;
    client.expect_xml(&format!("<presence xmlns='jabber:client' from='{full}' to='{bare}'><priority>{priority}</priority></presence>"))
}

fn sentinel(client: &mut Client, full: &str) -> TestResult {
    client.send(&format!("<message to='{full}' id='sentinel'/>"))?;
    client.expect_xml(&format!(
        "<message xmlns='jabber:client' from='{full}' to='{full}' id='sentinel'/>"
    ))
}

fn copy(client: &mut Client, full: &str, direction: &str, kind: &str, inner: &str) -> TestResult {
    let bare = full.split_once('/').ok_or("missing resource")?.0;
    client.expect_xml(&format!("<message xmlns='jabber:client' from='{bare}' to='{full}'{kind}><{direction} xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'>{inner}</forwarded></{direction}></message>"))
}

fn discovery(
    client: &mut Client,
    full: &str,
    target: &str,
    disco: bool,
    extra: &str,
) -> TestResult {
    client.send(&format!("<iq type='get' to='{target}' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>"))?;
    if disco {
        let (category, kind) = if target.contains('@') {
            ("account", "registered")
        } else {
            ("server", "im")
        };
        client.expect_xml(&format!("<iq xmlns='jabber:client' type='result' from='{target}' to='{full}' id='info'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='{category}' type='{kind}'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/>{extra}</query></iq>"))
    } else {
        client.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/>{UNAVAILABLE}</iq>"))
    }
}

#[test]
fn discovery_advertises_carbons_on_the_server_only() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    discovery(
        &mut desk,
        "alice@localhost/desk",
        "localhost",
        true,
        &format!(
            "<feature var='jabber:iq:roster'/><feature var='msgoffline'/>{FEATURES}<feature var='urn:xmpp:ping'/><feature var='vcard-temp'/>"
        ),
    )?;
    discovery(
        &mut desk,
        "alice@localhost/desk",
        "alice@localhost",
        true,
        "<feature var='urn:xmpp:ping'/><feature var='vcard-temp'/>",
    )?;
    desk.close()
}

#[test]
fn enable_and_disable_are_idempotent_iq_results() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    enable(&mut desk, "alice@localhost/desk")?;
    enable(&mut desk, "alice@localhost/desk")?;
    disable(&mut desk, "alice@localhost/desk")?;
    disable(&mut desk, "alice@localhost/desk")?;
    enable(&mut desk, "alice@localhost/desk")?;
    for operation in ["enable", "disable"] {
        desk.send(&format!("<iq type='set' to='alice@localhost' id='own'><{operation} xmlns='urn:xmpp:carbons:2'/></iq>"))?;
        desk.expect_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost' to='alice@localhost/desk' id='own'/>")?;
    }
    desk.close()
}

#[test]
fn carbons_requests_for_other_targets_are_refused_or_routed() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    desk.send(
        "<iq type='set' to='bob@localhost' id='other'><enable xmlns='urn:xmpp:carbons:2'/></iq>",
    )?;
    desk.expect_xml("<iq xmlns='jabber:client' type='error' from='bob@localhost' to='alice@localhost/desk' id='other'><enable xmlns='urn:xmpp:carbons:2'/><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Carbons can be changed only for your own session. Omit the destination or use your bare JID.</text></error></iq>")?;
    for (destination, source, kind, payload) in [
        (
            " to='localhost'",
            " from='localhost'",
            "set",
            "<enable xmlns='urn:xmpp:carbons:2'/>",
        ),
        ("", "", "get", "<enable xmlns='urn:xmpp:carbons:2'/>"),
        ("", "", "set", "<private xmlns='urn:xmpp:carbons:2'/>"),
    ] {
        desk.send(&format!(
            "<iq type='{kind}'{destination} id='unsupported'>{payload}</iq>"
        ))?;
        desk.expect_xml(&format!("<iq xmlns='jabber:client' type='error'{source} id='unsupported'>{payload}{UNAVAILABLE}</iq>"))?;
    }
    desk.send("<iq type='set' to='alice@localhost/phone' id='routed'><enable xmlns='urn:xmpp:carbons:2'/></iq>")?;
    phone.expect_xml("<iq xmlns='jabber:client' type='set' from='alice@localhost/desk' to='alice@localhost/phone' id='routed'><enable xmlns='urn:xmpp:carbons:2'/></iq>")?;
    phone.send("<iq type='result' to='alice@localhost/desk' id='routed'/>")?;
    desk.expect_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost/phone' to='alice@localhost/desk' id='routed'/>")?;
    phone.close()?;
    desk.close()
}

#[test]
fn enable_payload_content_is_ignored() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    available(&mut bob, "bob@localhost/desk", 0)?;
    phone.send("<iq type='set' id='enable'><enable xmlns='urn:xmpp:carbons:2' foo='bar'><x/></enable></iq>")?;
    phone.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='enable' to='alice@localhost/phone'/>",
    )?;
    desk.send("<message to='bob@localhost' type='chat' id='content'><body>one</body></message>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='content'><body>one</body></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "sent",
        " type='chat'",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='content'><body>one</body></message>",
    )?;
    desk.close()?;
    phone.close()?;
    bob.close()
}

#[test]
fn sent_copies_reach_only_other_enabled_resources() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut laptop = suite.connect("alice", PASSWORD, "laptop")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    available(&mut bob, "bob@localhost/desk", 0)?;
    enable(&mut phone, "alice@localhost/phone")?;
    for id in ["m1", "m1-enabled"] {
        if id == "m1-enabled" {
            enable(&mut desk, "alice@localhost/desk")?;
        }
        desk.send(&format!(
            "<message to='bob@localhost' type='chat' id='{id}'><body>one</body></message>"
        ))?;
        bob.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='{id}'><body>one</body></message>"))?;
        copy(
            &mut phone,
            "alice@localhost/phone",
            "sent",
            " type='chat'",
            &format!(
                "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='{id}'><body>one</body></message>"
            ),
        )?;
        barrier(&mut desk)?;
        sentinel(&mut desk, "alice@localhost/desk")?;
        sentinel(&mut laptop, "alice@localhost/laptop")?;
        sentinel(&mut phone, "alice@localhost/phone")?;
    }
    desk.close()?;
    phone.close()?;
    laptop.close()?;
    bob.close()
}

#[test]
fn received_copies_skip_the_routed_resource_for_bare_messages() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut laptop = suite.connect("alice", PASSWORD, "laptop")?;
    let mut tablet = suite.connect("alice", PASSWORD, "tablet")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    for (client, full) in [
        (&mut phone, "alice@localhost/phone"),
        (&mut laptop, "alice@localhost/laptop"),
        (&mut tablet, "alice@localhost/tablet"),
    ] {
        enable(client, full)?;
    }
    available(&mut phone, "alice@localhost/phone", 5)?;
    laptop.send("<presence><priority>1</priority></presence>")?;
    laptop.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'><priority>5</priority></presence>")?;
    laptop.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/laptop' to='alice@localhost'><priority>1</priority></presence>")?;
    phone.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/laptop' to='alice@localhost'><priority>1</priority></presence>")?;
    bob.send("<message to='alice@localhost' type='chat' id='m2'><body>two</body></message>")?;
    phone.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost' type='chat' id='m2'><body>two</body></message>")?;
    for (client, full) in [
        (&mut laptop, "alice@localhost/laptop"),
        (&mut tablet, "alice@localhost/tablet"),
    ] {
        copy(
            client,
            full,
            "received",
            " type='chat'",
            "<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost' type='chat' id='m2'><body>two</body></message>",
        )?;
    }
    barrier(&mut bob)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    sentinel(&mut desk, "alice@localhost/desk")?;
    laptop.close()?;
    phone.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/laptop' to='alice@localhost' type='unavailable'/>")?;
    phone.close()?;
    tablet.close()?;
    desk.close()?;
    bob.close()
}

#[test]
fn received_copies_for_full_jid_messages_skip_only_the_addressed_resource() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut laptop = suite.connect("alice", PASSWORD, "laptop")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    enable(&mut laptop, "alice@localhost/laptop")?;
    enable(&mut phone, "alice@localhost/phone")?;
    bob.send(
        "<message to='alice@localhost/laptop' type='chat' id='full'><body>two</body></message>",
    )?;
    laptop.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/laptop' type='chat' id='full'><body>two</body></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "received",
        " type='chat'",
        "<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/laptop' type='chat' id='full'><body>two</body></message>",
    )?;
    barrier(&mut bob)?;
    sentinel(&mut laptop, "alice@localhost/laptop")?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    laptop.close()?;
    phone.close()?;
    bob.close()
}

#[test]
fn missing_full_chat_falls_back_and_copies_around_the_new_recipient() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut laptop = suite.connect("alice", PASSWORD, "laptop")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    enable(&mut phone, "alice@localhost/phone")?;
    enable(&mut laptop, "alice@localhost/laptop")?;
    available(&mut phone, "alice@localhost/phone", 5)?;
    bob.send(
        "<message to='alice@localhost/gone' type='chat' id='fallback'><body>two</body></message>",
    )?;
    phone.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/gone' type='chat' id='fallback'><body>two</body></message>")?;
    copy(
        &mut laptop,
        "alice@localhost/laptop",
        "received",
        " type='chat'",
        "<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/gone' type='chat' id='fallback'><body>two</body></message>",
    )?;
    barrier(&mut bob)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    phone.close()?;
    laptop.close()?;
    bob.close()
}

#[test]
fn stored_messages_copy_to_enabled_resources_without_eligible_priority() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut tablet = suite.connect("alice", PASSWORD, "tablet")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    enable(&mut phone, "alice@localhost/phone")?;
    enable(&mut tablet, "alice@localhost/tablet")?;
    available(&mut phone, "alice@localhost/phone", -1)?;
    bob.send("<message to='alice@localhost' type='chat' id='stored'><body>two</body></message>")?;
    for (client, full) in [
        (&mut phone, "alice@localhost/phone"),
        (&mut tablet, "alice@localhost/tablet"),
    ] {
        copy(
            client,
            full,
            "received",
            " type='chat'",
            "<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost' type='chat' id='stored'><body>two</body></message>",
        )?;
    }
    barrier(&mut bob)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    sentinel(&mut tablet, "alice@localhost/tablet")?;
    available(&mut phone, "alice@localhost/phone", 0)?;
    let replay = phone.receive()?;
    let delay = replay.child("urn:xmpp:delay", "delay")?;
    assert_eq!(delay.attribute("from"), Some("localhost"));
    let stamp = delay.attribute("stamp").ok_or("missing delay stamp")?;
    assert_eq!(stamp.len(), 20);
    assert!(stamp.ends_with('Z') && stamp.as_bytes()[10] == b'T');
    replay.assert_xml(&format!("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost' type='chat' id='stored'><body>two</body><delay xmlns='urn:xmpp:delay' from='localhost' stamp='{stamp}'/></message>"))?;
    barrier(&mut phone)?;
    sentinel(&mut tablet, "alice@localhost/tablet")?;
    phone.close()?;
    tablet.close()?;
    bob.close()
}

#[test]
fn rejected_messages_copy_the_server_error_after_the_sent_copy() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    enable(&mut phone, "alice@localhost/phone")?;
    desk.send("<message to='bob@localhost/absent' id='r1'><body>lost</body></message>")?;
    desk.expect_xml(&format!("<message xmlns='jabber:client' from='bob@localhost/absent' to='alice@localhost/desk' type='error' id='r1'><body>lost</body>{UNAVAILABLE}</message>"))?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "sent",
        "",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/absent' id='r1'><body>lost</body></message>",
    )?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "received",
        "",
        &format!(
            "<message xmlns='jabber:client' from='bob@localhost/absent' to='alice@localhost/desk' type='error' id='r1'><body>lost</body>{UNAVAILABLE}</message>"
        ),
    )?;
    barrier(&mut desk)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    desk.close()?;
    phone.close()
}

#[test]
fn remote_destinations_copy_the_sent_message_and_its_error() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    enable(&mut phone, "alice@localhost/phone")?;
    desk.send(
        "<message type='chat' to='juliet@capulet.example' id='remote'><body>lost</body></message>",
    )?;
    let error = "<message xmlns='jabber:client' from='juliet@capulet.example' to='alice@localhost/desk' type='error' id='remote'><body>lost</body><error type='cancel'><remote-server-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot deliver this request to a remote domain.</text></error></message>";
    desk.expect_xml(error)?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "sent",
        " type='chat'",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='juliet@capulet.example' type='chat' id='remote'><body>lost</body></message>",
    )?;
    copy(&mut phone, "alice@localhost/phone", "received", "", error)?;
    barrier(&mut desk)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    desk.close()?;
    phone.close()
}

#[test]
fn discarded_messages_produce_only_sent_copies() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    enable(&mut phone, "alice@localhost/phone")?;
    desk.send(
        "<message to='nobody@localhost' type='chat' id='discarded'><body>lost</body></message>",
    )?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "sent",
        " type='chat'",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='nobody@localhost' type='chat' id='discarded'><body>lost</body></message>",
    )?;
    barrier(&mut desk)?;
    sentinel(&mut desk, "alice@localhost/desk")?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    desk.close()?;
    phone.close()
}

#[test]
fn eligibility_matrix_controls_copies() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let mut bob_phone = suite.connect("bob", PASSWORD, "phone")?;
    enable(&mut phone, "alice@localhost/phone")?;
    enable(&mut bob_phone, "bob@localhost/phone")?;
    available(&mut bob, "bob@localhost/desk", 0)?;
    for (id, kind, payload, copied) in [
        ("body", "", "<body/>", true),
        ("receipt", "", "<request xmlns='urn:xmpp:receipts'/>", true),
        (
            "state",
            "",
            "<composing xmlns='http://jabber.org/protocol/chatstates'/>",
            true,
        ),
        (
            "marker",
            "",
            "<displayed xmlns='urn:xmpp:chat-markers:0' id='x'/>",
            true,
        ),
        (
            "invitation",
            "",
            "<x xmlns='jabber:x:conference' jid='room@conference.localhost'/>",
            true,
        ),
        (
            "headline-state",
            " type='headline'",
            "<active xmlns='http://jabber.org/protocol/chatstates'/>",
            true,
        ),
        ("empty", "", "", false),
        (
            "headline-body",
            " type='headline'",
            "<body>headline</body>",
            false,
        ),
        (
            "private",
            " type='chat'",
            "<body>private</body><private xmlns='urn:xmpp:carbons:2'/>",
            false,
        ),
        (
            "no-copy",
            " type='chat'",
            "<body>hinted</body><no-copy xmlns='urn:xmpp:hints'/>",
            false,
        ),
        (
            "forged",
            " type='chat'",
            "<received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='carol@localhost/x' to='alice@localhost' type='chat'><body>forged</body></message></forwarded></received>",
            false,
        ),
        (
            "chat-state",
            " type='chat'",
            "<composing xmlns='http://jabber.org/protocol/chatstates'/>",
            true,
        ),
    ] {
        desk.send(&format!(
            "<message to='bob@localhost'{kind} id='{id}'>{payload}</message>"
        ))?;
        bob.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost'{kind} id='{id}'>{payload}</message>"))?;
        if copied {
            copy(
                &mut phone,
                "alice@localhost/phone",
                "sent",
                kind,
                &format!(
                    "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost'{kind} id='{id}'>{payload}</message>"
                ),
            )?;
        }
        if copied {
            copy(
                &mut bob_phone,
                "bob@localhost/phone",
                "received",
                kind,
                &format!(
                    "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost'{kind} id='{id}'>{payload}</message>"
                ),
            )?;
        }
        barrier(&mut desk)?;
        sentinel(&mut phone, "alice@localhost/phone")?;
        sentinel(&mut bob_phone, "bob@localhost/phone")?;
    }
    desk.close()?;
    phone.close()?;
    bob.close()?;
    bob_phone.close()
}

#[test]
fn muc_rules_follow_message_direction() -> TestResult {
    let suite = C2sSuite::with_extensions("'disco', 'carbons', 'test-service'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    enable(&mut phone, "alice@localhost/phone")?;
    desk.send("<message type='chat' to='room@echo.localhost/nick'><body>pm</body><x xmlns='http://jabber.org/protocol/muc#user'/></message>")?;
    desk.expect_xml("<message xmlns='jabber:client' from='room@echo.localhost/nick' to='alice@localhost/desk' type='chat'><body>pm</body><x xmlns='http://jabber.org/protocol/muc#user'/></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "sent",
        " type='chat'",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='room@echo.localhost/nick' type='chat'><body>pm</body><x xmlns='http://jabber.org/protocol/muc#user'/></message>",
    )?;
    barrier(&mut desk)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    desk.send("<message to='room@echo.localhost'><x xmlns='http://jabber.org/protocol/muc#user'><invite to='carol@localhost'/></x></message>")?;
    desk.expect_xml("<message xmlns='jabber:client' from='room@echo.localhost' to='alice@localhost/desk'><x xmlns='http://jabber.org/protocol/muc#user'><invite to='carol@localhost'/></x></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "received",
        "",
        "<message xmlns='jabber:client' from='room@echo.localhost' to='alice@localhost/desk'><x xmlns='http://jabber.org/protocol/muc#user'><invite to='carol@localhost'/></x></message>",
    )?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "sent",
        "",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='room@echo.localhost'><x xmlns='http://jabber.org/protocol/muc#user'><invite to='carol@localhost'/></x></message>",
    )?;
    desk.send("<message type='groupchat' to='room@echo.localhost'><body>room</body></message>")?;
    desk.expect_xml("<message xmlns='jabber:client' from='room@echo.localhost' to='alice@localhost/desk' type='groupchat'><body>room</body></message>")?;
    barrier(&mut desk)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    desk.close()?;
    phone.close()
}

#[test]
fn copies_never_reach_another_account() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let mut bob_phone = suite.connect("bob", PASSWORD, "phone")?;
    enable(&mut phone, "alice@localhost/phone")?;
    enable(&mut bob_phone, "bob@localhost/phone")?;
    available(&mut bob, "bob@localhost/desk", 0)?;
    desk.send("<message type='chat' to='bob@localhost' id='out'><body>one</body></message>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='out'><body>one</body></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "sent",
        " type='chat'",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='out'><body>one</body></message>",
    )?;
    copy(
        &mut bob_phone,
        "bob@localhost/phone",
        "received",
        " type='chat'",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='out'><body>one</body></message>",
    )?;
    barrier(&mut desk)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    sentinel(&mut bob_phone, "bob@localhost/phone")?;
    bob.send("<message type='chat' to='alice@localhost/desk' id='in'><body>two</body></message>")?;
    desk.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/desk' type='chat' id='in'><body>two</body></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "received",
        " type='chat'",
        "<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/desk' type='chat' id='in'><body>two</body></message>",
    )?;
    copy(
        &mut bob_phone,
        "bob@localhost/phone",
        "sent",
        " type='chat'",
        "<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/desk' type='chat' id='in'><body>two</body></message>",
    )?;
    barrier(&mut bob)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    sentinel(&mut bob_phone, "bob@localhost/phone")?;
    desk.close()?;
    phone.close()?;
    bob.close()?;
    bob_phone.close()
}

#[test]
fn same_account_messages_copy_both_directions_to_other_resources() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut laptop = suite.connect("alice", PASSWORD, "laptop")?;
    enable(&mut desk, "alice@localhost/desk")?;
    enable(&mut phone, "alice@localhost/phone")?;
    enable(&mut laptop, "alice@localhost/laptop")?;
    available(&mut phone, "alice@localhost/phone", 5)?;
    for (id, target) in [
        ("bare", "alice@localhost"),
        ("full", "alice@localhost/phone"),
    ] {
        desk.send(&format!(
            "<message type='chat' to='{target}' id='{id}'><body>self</body></message>"
        ))?;
        phone.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desk' to='{target}' type='chat' id='{id}'><body>self</body></message>"))?;
        for direction in ["sent", "received"] {
            copy(
                &mut laptop,
                "alice@localhost/laptop",
                direction,
                " type='chat'",
                &format!(
                    "<message xmlns='jabber:client' from='alice@localhost/desk' to='{target}' type='chat' id='{id}'><body>self</body></message>"
                ),
            )?;
        }
        barrier(&mut desk)?;
        sentinel(&mut desk, "alice@localhost/desk")?;
        sentinel(&mut phone, "alice@localhost/phone")?;
        sentinel(&mut laptop, "alice@localhost/laptop")?;
    }
    desk.close()?;
    phone.close()?;
    laptop.close()
}

#[test]
fn copies_are_not_observed_or_archived_again() -> TestResult {
    let suite =
        C2sSuite::with_extensions("'disco', 'carbons', 'test-archive', 'test-message-observer'")?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let mut bob_phone = suite.connect("bob", PASSWORD, "phone")?;
    enable(&mut phone, "alice@localhost/phone")?;
    enable(&mut bob_phone, "bob@localhost/phone")?;
    available(&mut bob, "bob@localhost/desk", 0)?;
    desk.send("<message type='chat' to='bob@localhost' id='archived'><body>one</body><stanza-id xmlns='urn:xmpp:sid:0' by='alice@localhost' id='forged'/><stanza-id xmlns='urn:xmpp:sid:0' by='carol@localhost' id='third'/></message>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='archived'><body>one</body><stanza-id xmlns='urn:xmpp:sid:0' by='alice@localhost' id='forged'/><stanza-id xmlns='urn:xmpp:sid:0' by='carol@localhost' id='third'/><stanza-id xmlns='urn:xmpp:sid:0' by='bob@localhost' id='2'/></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "sent",
        " type='chat'",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='archived'><body>one</body><stanza-id xmlns='urn:xmpp:sid:0' by='carol@localhost' id='third'/><stanza-id xmlns='urn:xmpp:sid:0' by='alice@localhost' id='1'/></message>",
    )?;
    copy(
        &mut bob_phone,
        "bob@localhost/phone",
        "received",
        " type='chat'",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='archived'><body>one</body><stanza-id xmlns='urn:xmpp:sid:0' by='alice@localhost' id='forged'/><stanza-id xmlns='urn:xmpp:sid:0' by='carol@localhost' id='third'/><stanza-id xmlns='urn:xmpp:sid:0' by='bob@localhost' id='2'/></message>",
    )?;
    desk.send("<iq type='get' to='localhost' id='events'><messages xmlns='urn:lonewolf:test:observer'/></iq>")?;
    desk.expect_xml("<iq xmlns='jabber:client' from='localhost' to='alice@localhost/desk' type='result' id='events'><messages xmlns='urn:lonewolf:test:observer'><event account='alice@localhost' role='sent' outcome='routed' archived='1'/><event account='bob@localhost' role='received' outcome='routed' archived='2'/></messages></iq>")?;
    desk.send("<iq type='get' to='localhost' id='archive'><entries xmlns='urn:lonewolf:test:archive'/></iq>")?;
    desk.expect_xml("<iq xmlns='jabber:client' from='localhost' to='alice@localhost/desk' type='result' id='archive'><entries xmlns='urn:lonewolf:test:archive'><entry owner='alice@localhost' direction='sent' id='1'/><entry owner='bob@localhost' direction='received' id='2'/></entries></iq>")?;
    desk.close()?;
    phone.close()?;
    bob.close()?;
    bob_phone.close()
}

#[test]
fn errors_answering_copies_reach_nobody() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    enable(&mut desk, "alice@localhost/desk")?;
    enable(&mut phone, "alice@localhost/phone")?;
    bob.send(
        "<message type='chat' to='alice@localhost/desk' id='original'><body>two</body></message>",
    )?;
    desk.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/desk' type='chat' id='original'><body>two</body></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "received",
        " type='chat'",
        "<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/desk' type='chat' id='original'><body>two</body></message>",
    )?;
    barrier(&mut bob)?;
    phone.send("<message type='error' to='alice@localhost'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
    barrier(&mut phone)?;
    sentinel(&mut desk, "alice@localhost/desk")?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    sentinel(&mut bob, "bob@localhost/desk")?;
    desk.close()?;
    phone.close()?;
    bob.close()
}

#[test]
fn routed_errors_are_copied_unless_addressed_to_the_account() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let mut bob_phone = suite.connect("bob", PASSWORD, "phone")?;
    enable(&mut phone, "alice@localhost/phone")?;
    enable(&mut bob_phone, "bob@localhost/phone")?;
    for hint in ["", "<no-copy xmlns='urn:xmpp:hints'/>"] {
        bob.send(&format!("<message type='error' to='alice@localhost/desk' id='e1'>{hint}<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>"))?;
        desk.expect_xml(&format!("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/desk' type='error' id='e1'>{hint}<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>"))?;
        for (client, full, direction) in [
            (&mut phone, "alice@localhost/phone", "received"),
            (&mut bob_phone, "bob@localhost/phone", "sent"),
        ] {
            copy(
                client,
                full,
                direction,
                "",
                &format!(
                    "<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/desk' type='error' id='e1'>{hint}<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>"
                ),
            )?;
        }
        barrier(&mut bob)?;
        sentinel(&mut phone, "alice@localhost/phone")?;
        sentinel(&mut bob_phone, "bob@localhost/phone")?;
    }
    desk.close()?;
    phone.close()?;
    bob.close()?;
    bob_phone.close()
}

#[test]
fn policy_rejections_produce_no_copies() -> TestResult {
    let suite = C2sSuite::with_extensions("'carbons', 'test-policy'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    enable(&mut phone, "alice@localhost/phone")?;
    desk.send("<message type='chat' to='blocked@localhost' id='blocked'/>")?;
    desk.expect_xml("<message xmlns='jabber:client' from='blocked@localhost' to='alice@localhost/desk' type='error' id='blocked'><error type='modify'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>A request value exceeds an allowed limit or has an unsupported format.</text><blocked xmlns='urn:lonewolf:test:policy'/></error></message>")?;
    barrier(&mut desk)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    desk.close()?;
    phone.close()
}

#[test]
fn hosts_without_carbons_neither_advertise_nor_copy() -> TestResult {
    let suite = C2sSuite::with_hosts(
        "[hosts.localhost]\nextensions=['carbons']\n[hosts.'other.localhost']\nextensions=['disco']\n[hosts.'other.localhost'.tls]\ncertificate_chain_path='certificate.pem'\nprivate_key_path='private-key.pem'",
    )?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account_jid("bob@other.localhost", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let [other, sibling] = ["desk", "phone"].map(|resource| -> TestResult<Client> {
        let opening = OPEN.replace("to='localhost'", "to='other.localhost'");
        let mut plain = suite.tcp_client()?;
        plain.open_with(&opening)?;
        plain.features()?;
        let mut client = plain.start_tls_with_identity(
            Arc::clone(&suite.tls),
            ServerName::try_from("other.localhost")?,
        )?;
        client.open_with(&opening)?;
        client.features()?;
        client.authenticate("bob", PASSWORD)?;
        let mut client = client.restart();
        client.open_with(&opening)?;
        client.features()?;
        assert_eq!(
            client.bind(Some(resource))?,
            format!("bob@other.localhost/{resource}")
        );
        Ok(client)
    });
    let mut other = other?;
    let mut sibling = sibling?;
    enable(&mut phone, "alice@localhost/phone")?;
    for operation in ["enable", "disable"] {
        sibling.send(&format!(
            "<iq type='set' id='{operation}'><{operation} xmlns='urn:xmpp:carbons:2'/></iq>"
        ))?;
        sibling.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='{operation}'><{operation} xmlns='urn:xmpp:carbons:2'/>{UNAVAILABLE}</iq>"))?;
    }
    desk.send("<message type='chat' to='bob@other.localhost/desk' id='cross-out'><body>one</body></message>")?;
    other.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@other.localhost/desk' type='chat' id='cross-out'><body>one</body></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "sent",
        " type='chat'",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@other.localhost/desk' type='chat' id='cross-out'><body>one</body></message>",
    )?;
    barrier(&mut desk)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    sentinel(&mut sibling, "bob@other.localhost/phone")?;
    other.send(
        "<message type='chat' to='alice@localhost/desk' id='cross-in'><body>two</body></message>",
    )?;
    desk.expect_xml("<message xmlns='jabber:client' from='bob@other.localhost/desk' to='alice@localhost/desk' type='chat' id='cross-in'><body>two</body></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "received",
        " type='chat'",
        "<message xmlns='jabber:client' from='bob@other.localhost/desk' to='alice@localhost/desk' type='chat' id='cross-in'><body>two</body></message>",
    )?;
    barrier(&mut other)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    sentinel(&mut sibling, "bob@other.localhost/phone")?;
    discovery(&mut desk, "alice@localhost/desk", "localhost", false, "")?;
    discovery(
        &mut desk,
        "alice@localhost/desk",
        "alice@localhost",
        false,
        "",
    )?;
    discovery(
        &mut other,
        "bob@other.localhost/desk",
        "other.localhost",
        true,
        "",
    )?;
    discovery(
        &mut other,
        "bob@other.localhost/desk",
        "bob@other.localhost",
        true,
        "",
    )?;
    desk.close()?;
    phone.close()?;
    other.close()?;
    sibling.close()
}

#[test]
fn carbons_state_ends_with_the_session() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    enable(&mut phone, "alice@localhost/phone")?;
    desk.send(
        "<message type='chat' to='bob@localhost/desk' id='before'><body>one</body></message>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='before'><body>one</body></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "sent",
        " type='chat'",
        "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='before'><body>one</body></message>",
    )?;
    phone.close()?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    for (id, enabled) in [("rebound", false), ("reenabled", true)] {
        if enabled {
            enable(&mut phone, "alice@localhost/phone")?;
        }
        desk.send(&format!(
            "<message type='chat' to='bob@localhost/desk' id='{id}'><body>one</body></message>"
        ))?;
        bob.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='{id}'><body>one</body></message>"))?;
        if enabled {
            copy(
                &mut phone,
                "alice@localhost/phone",
                "sent",
                " type='chat'",
                &format!(
                    "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='{id}'><body>one</body></message>"
                ),
            )?;
        }
        barrier(&mut desk)?;
        sentinel(&mut phone, "alice@localhost/phone")?;
    }
    suite.delete_account("alice")?;
    desk.expect_stream_error("not-authorized")?;
    phone.expect_stream_error("not-authorized")?;
    bob.send("<message type='chat' to='alice@localhost' id='deleted'><body>gone</body></message>")?;
    barrier(&mut bob)?;
    sentinel(&mut bob, "bob@localhost/desk")?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    bob.send(
        "<message type='chat' to='alice@localhost/desk' id='recreated'><body>two</body></message>",
    )?;
    desk.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/desk' type='chat' id='recreated'><body>two</body></message>")?;
    barrier(&mut bob)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    desk.close()?;
    phone.close()?;
    bob.close()
}

#[test]
fn disable_stops_later_copies_and_enable_starts_them() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    for (id, enabled) in [
        ("on1", true),
        ("off1", false),
        ("on2", true),
        ("off2", false),
        ("on3", true),
    ] {
        if enabled {
            enable(&mut phone, "alice@localhost/phone")?;
        } else {
            disable(&mut phone, "alice@localhost/phone")?;
        }
        desk.send(&format!(
            "<message type='chat' to='bob@localhost/desk' id='{id}'><body>one</body></message>"
        ))?;
        bob.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='{id}'><body>one</body></message>"))?;
        if enabled {
            copy(
                &mut phone,
                "alice@localhost/phone",
                "sent",
                " type='chat'",
                &format!(
                    "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='{id}'><body>one</body></message>"
                ),
            )?;
        }
        barrier(&mut desk)?;
        sentinel(&mut phone, "alice@localhost/phone")?;
    }
    desk.close()?;
    phone.close()?;
    bob.close()
}

#[test]
fn deep_messages_skip_copies_without_affecting_delivery() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    enable(&mut phone, "alice@localhost/phone")?;
    for depth in [125, 126] {
        let payload = format!(
            "{}<body>deep</body>{}",
            "<x>".repeat(depth - 2),
            "</x>".repeat(depth - 2)
        );
        desk.send(&format!(
            "<message type='chat' to='bob@localhost/desk' id='depth-{depth}'>{payload}</message>"
        ))?;
        bob.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='depth-{depth}'>{payload}</message>"))?;
        if depth == 125 {
            copy(
                &mut phone,
                "alice@localhost/phone",
                "sent",
                " type='chat'",
                &format!(
                    "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='depth-{depth}'>{payload}</message>"
                ),
            )?;
        }
        barrier(&mut desk)?;
        sentinel(&mut phone, "alice@localhost/phone")?;
    }
    desk.close()?;
    phone.close()?;
    bob.close()
}

#[test]
fn copies_preserve_the_original_payload() -> TestResult {
    let suite = C2sSuite::start()?;
    accounts(&suite)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    enable(&mut phone, "alice@localhost/phone")?;
    desk.send("<message xmlns:p='urn:p' p:a='1' xml:lang='es' type='chat' to='bob@localhost/desk' id='payload'><body>Hola &amp; adiós</body><thread parent='before'>thread</thread><p:e p:b='2'/><unknown xmlns='urn:unknown'><child xml:lang='fr'>inconnu</child></unknown></message>")?;
    bob.expect_xml("<message xmlns='jabber:client' xmlns:p='urn:p' p:a='1' xml:lang='es' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='payload'><body>Hola &amp; adiós</body><thread parent='before'>thread</thread><p:e p:b='2'/><unknown xmlns='urn:unknown'><child xml:lang='fr'>inconnu</child></unknown></message>")?;
    copy(
        &mut phone,
        "alice@localhost/phone",
        "sent",
        " type='chat'",
        "<message xmlns='jabber:client' xmlns:p='urn:p' p:a='1' xml:lang='es' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='payload'><body>Hola &amp; adiós</body><thread parent='before'>thread</thread><p:e p:b='2'/><unknown xmlns='urn:unknown'><child xml:lang='fr'>inconnu</child></unknown></message>",
    )?;
    barrier(&mut desk)?;
    sentinel(&mut phone, "alice@localhost/phone")?;
    desk.close()?;
    phone.close()?;
    bob.close()
}

#[test]
fn carbons_and_disco_are_independently_selectable() -> TestResult {
    for (extensions, carbons, disco) in [
        ("", false, false),
        ("'carbons'", true, false),
        ("'disco'", false, true),
        ("'carbons', 'disco'", true, true),
        ("'disco', 'carbons'", true, true),
    ] {
        let suite = C2sSuite::with_extensions(extensions)?;
        accounts(&suite)?;
        let mut desk = suite.connect("alice", PASSWORD, "desk")?;
        let mut phone = suite.connect("alice", PASSWORD, "phone")?;
        let mut bob = suite.connect("bob", PASSWORD, "desk")?;
        if carbons {
            enable(&mut phone, "alice@localhost/phone")?;
        } else {
            phone.send("<iq type='set' id='enable'><enable xmlns='urn:xmpp:carbons:2'/></iq>")?;
            phone.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='enable'><enable xmlns='urn:xmpp:carbons:2'/>{UNAVAILABLE}</iq>"))?;
        }
        for (id, enabled) in [("before-discovery", carbons), ("after-disable", false)] {
            if id == "after-disable" {
                discovery(
                    &mut desk,
                    "alice@localhost/desk",
                    "localhost",
                    disco,
                    if carbons { FEATURES } else { "" },
                )?;
                discovery(
                    &mut desk,
                    "alice@localhost/desk",
                    "alice@localhost",
                    disco,
                    "",
                )?;
                if carbons {
                    disable(&mut phone, "alice@localhost/phone")?;
                } else {
                    phone.send(
                        "<iq type='set' id='disable'><disable xmlns='urn:xmpp:carbons:2'/></iq>",
                    )?;
                    phone.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='disable'><disable xmlns='urn:xmpp:carbons:2'/>{UNAVAILABLE}</iq>"))?;
                }
            }
            desk.send(&format!("<message type='chat' to='bob@localhost/desk' id='{id}-out'><body>one</body></message>"))?;
            bob.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='{id}-out'><body>one</body></message>"))?;
            if enabled {
                copy(
                    &mut phone,
                    "alice@localhost/phone",
                    "sent",
                    " type='chat'",
                    &format!(
                        "<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk' type='chat' id='{id}-out'><body>one</body></message>"
                    ),
                )?;
            }
            barrier(&mut desk)?;
            sentinel(&mut phone, "alice@localhost/phone")?;
            bob.send(&format!("<message type='chat' to='alice@localhost/desk' id='{id}-in'><body>two</body></message>"))?;
            desk.expect_xml(&format!("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/desk' type='chat' id='{id}-in'><body>two</body></message>"))?;
            if enabled {
                copy(
                    &mut phone,
                    "alice@localhost/phone",
                    "received",
                    " type='chat'",
                    &format!(
                        "<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/desk' type='chat' id='{id}-in'><body>two</body></message>"
                    ),
                )?;
            }
            barrier(&mut bob)?;
            sentinel(&mut phone, "alice@localhost/phone")?;
        }
        desk.close()?;
        phone.close()?;
        bob.close()?;
    }
    Ok(())
}
