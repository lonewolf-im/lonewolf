// SPDX-License-Identifier: Apache-2.0

use crate::support::component::{ComponentClient, NAMESPACE};
use crate::support::xml::Element;
use crate::support::{C2sSuite, Client, PASSWORD, TestResult, barrier};

const DOMAIN: &str = "muc.localhost";
const SECRET: &str = "component-test-secret-0001";
const CONFIG: &str = "[components.domains.'muc.localhost']\nsecret='component-test-secret-0001'\n[components.domains.'pubsub.localhost']\nsecret='component-test-secret-0001'";
const ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";

pub(super) fn ping(component: &mut ComponentClient, id: &str) -> TestResult {
    component.send(&format!("<iq type='get' from='muc.localhost' to='localhost' id='{id}'><ping xmlns='urn:xmpp:ping'/></iq>"))
}

fn ping_result(component: &mut ComponentClient, id: &str) -> TestResult {
    component.expect_xml(&format!(
        "<iq xmlns='{NAMESPACE}' type='result' from='localhost' to='muc.localhost' id='{id}'/>"
    ))
}

pub(super) fn traffic(suite: &C2sSuite, kind: &str, received: u64, sent: u64) -> TestResult {
    for (direction, count) in [("received", received), ("sent", sent)] {
        let sample = format!("lonewolf_component_stanzas_{direction}_total{{kind=\"{kind}\"}}");
        if count > 0 {
            suite.wait_for_metric(&format!("{sample} {count}"))?;
        } else {
            let metrics = suite.scrape_metrics()?;
            let value = metrics
                .lines()
                .find_map(|line| {
                    line.strip_prefix(&sample)
                        .and_then(|value| value.strip_prefix(' '))
                })
                .unwrap_or("0")
                .parse::<u64>()?;
            assert_eq!(value, 0, "{sample}");
        }
    }
    Ok(())
}

fn error(
    stanza: &Element,
    kind: &str,
    id: &str,
    from: &str,
    to: &str,
    condition: &str,
) -> TestResult {
    stanza.assert_name(NAMESPACE, kind);
    assert_eq!(stanza.attribute("type"), Some("error"));
    assert_eq!(stanza.attribute("id"), Some(id));
    assert_eq!(stanza.attribute("from"), Some(from));
    assert_eq!(stanza.attribute("to"), Some(to));
    let error = stanza.child(NAMESPACE, "error")?;
    let kind = match condition {
        "forbidden" => "auth",
        "remote-server-timeout" => "wait",
        _ => "cancel",
    };
    assert_eq!(error.attribute("type"), Some(kind));
    error.child(ERRORS, condition)?;
    Ok(())
}

fn available_pair(desk: &mut Client, phone: &mut Client) -> TestResult {
    desk.send("<presence/>")?;
    desk.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    phone.send("<presence/>")?;
    phone.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    phone.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'/>",
    )?;
    desk.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'/>",
    )
}

fn close_available_pair(mut desk: Client, mut phone: Client) -> TestResult {
    phone.close()?;
    desk.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='alice@localhost/phone' to='alice@localhost'/>")?;
    desk.close()
}

#[test]
fn component_chat_and_groupchat_reach_full_jids_and_reject_missing_or_bare_groupchat_targets()
-> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for kind in ["chat", "groupchat"] {
        component.send(&format!("<message type='{kind}' from='room@muc.localhost/nick' to='alice@localhost/desk' id='{kind}'><body>room message</body></message>"))?;
        alice.expect_xml(&format!("<message xmlns='jabber:client' type='{kind}' from='room@muc.localhost/nick' to='alice@localhost/desk' id='{kind}'><body>room message</body></message>")).map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
    }
    for (kind, target) in [
        ("chat", "nobody@localhost"),
        ("groupchat", "alice@localhost"),
        ("chat", "localhost"),
        ("chat", "localhost/unknown"),
    ] {
        component.send(&format!("<message type='{kind}' from='room@muc.localhost/nick' to='{target}' id='unavailable'><body>preserve</body></message>"))?;
        let reply = component.receive()?;
        error(
            &reply,
            "message",
            "unavailable",
            target,
            "room@muc.localhost/nick",
            "service-unavailable",
        )?;
        assert_eq!(reply.child(NAMESPACE, "body")?.text, "preserve");
    }
    traffic(&suite, "message", 6, 4)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn component_chat_is_stored_offline_and_replayed_with_delay_at_next_available_login() -> TestResult
{
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("bob", PASSWORD)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    component.send("<message type='chat' from='room@muc.localhost/nick' to='bob@localhost' id='offline'><body>saved message</body></message>")?;
    ping(&mut component, "stored")?;
    ping_result(&mut component, "stored")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/desk' to='bob@localhost'/>",
    )?;
    let mut saved = bob.receive()?;
    let delay = saved.child("urn:xmpp:delay", "delay")?;
    assert_eq!(delay.attribute("from"), Some("localhost"));
    let stamp = delay.attribute("stamp").ok_or("missing delay timestamp")?;
    assert_eq!(stamp.len(), 20);
    assert!(stamp.ends_with('Z') && stamp.as_bytes()[10] == b'T');
    saved
        .children
        .retain(|child| child.namespace != "urn:xmpp:delay" || child.name != "delay");
    saved.assert_xml("<message xmlns='jabber:client' type='chat' from='room@muc.localhost/nick' to='bob@localhost' id='offline'><body>saved message</body></message>")?;
    barrier(&mut bob)?;
    traffic(&suite, "message", 1, 0)?;
    traffic(&suite, "iq", 1, 1)?;
    component.close()?;
    bob.close()?;
    suite.stop()
}

#[test]
fn component_chat_delivers_received_carbons_to_the_other_enabled_resource() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    for (client, resource) in [(&mut desk, "desk"), (&mut phone, "phone")] {
        client.send("<iq type='set' id='enable'><enable xmlns='urn:xmpp:carbons:2'/></iq>")?;
        client.expect_xml(&format!(
            "<iq xmlns='jabber:client' type='result' id='enable' to='alice@localhost/{resource}'/>"
        ))?;
    }
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    component.send("<message type='chat' from='room@muc.localhost/nick' to='alice@localhost/desk' id='carbon'><body>copied</body></message>")?;
    desk.expect_xml("<message xmlns='jabber:client' type='chat' from='room@muc.localhost/nick' to='alice@localhost/desk' id='carbon'><body>copied</body></message>").map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
    phone.expect_xml("<message xmlns='jabber:client' type='chat' from='alice@localhost' to='alice@localhost/phone'><received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' type='chat' from='room@muc.localhost/nick' to='alice@localhost/desk' id='carbon'><body>copied</body></message></forwarded></received></message>").map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
    ping(&mut component, "done")?;
    ping_result(&mut component, "done")?;
    traffic(&suite, "message", 1, 0)?;
    component.close()?;
    desk.close()?;
    phone.close()?;
    suite.stop()
}

#[test]
fn component_server_and_public_account_iqs_use_handlers_but_private_xml_is_forbidden() -> TestResult
{
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<iq type='set' id='publish'><vCard xmlns='vcard-temp'><FN>Alice</FN></vCard></iq>",
    )?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' to='alice@localhost/desk' id='publish'/>",
    )?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    component.send("<iq type='get' from='muc.localhost' to='localhost' id='disco'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    component.expect_xml("<iq xmlns='jabber:component:accept' type='result' from='localhost' to='muc.localhost' id='disco'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='jabber:iq:private'/><feature var='jabber:iq:roster'/><feature var='jabber:iq:version'/><feature var='msgoffline'/><feature var='urn:xmpp:carbons:2'/><feature var='urn:xmpp:carbons:rules:0'/><feature var='urn:xmpp:ping'/><feature var='vcard-temp'/></query></iq>")?;
    ping(&mut component, "ping")?;
    ping_result(&mut component, "ping")?;
    component.send("<iq type='get' from='muc.localhost' to='alice@localhost' id='card'><vCard xmlns='vcard-temp'/></iq>")?;
    component.expect_xml("<iq xmlns='jabber:component:accept' type='result' from='alice@localhost' to='muc.localhost' id='card'><vCard xmlns='vcard-temp' xml:lang='' xml:space='default'><FN>Alice</FN></vCard></iq>")?;
    component.send("<iq type='get' from='muc.localhost' to='alice@localhost' id='private'><query xmlns='jabber:iq:private'><value xmlns='urn:test'/></query></iq>")?;
    let reply = component.receive()?;
    error(
        &reply,
        "iq",
        "private",
        "alice@localhost",
        DOMAIN,
        "forbidden",
    )?;
    assert_eq!(reply.children.len(), 1);
    component.send("<iq type='get' from='muc.localhost' to='localhost' id='unknown'><query xmlns='urn:test:unknown'/></iq>")?;
    let reply = component.receive()?;
    error(
        &reply,
        "iq",
        "unknown",
        "localhost",
        DOMAIN,
        "service-unavailable",
    )?;
    reply.child("urn:test:unknown", "query")?;
    traffic(&suite, "iq", 5, 5)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn component_available_and_unavailable_presence_reach_full_or_available_bare_resources()
-> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    available_pair(&mut desk, &mut phone)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for attributes in ["", " type='unavailable'"] {
        component.send(&format!("<presence{attributes} from='room@muc.localhost/nick' to='alice@localhost/desk'><status>room state</status></presence>"))?;
        desk.expect_xml(&format!("<presence xmlns='jabber:client'{attributes} from='room@muc.localhost/nick' to='alice@localhost/desk'><status>room state</status></presence>")).map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
        component.send(&format!("<presence{attributes} from='room@muc.localhost/nick' to='alice@localhost'><status>room state</status></presence>"))?;
        for client in [&mut desk, &mut phone] {
            client.expect_xml(&format!("<presence xmlns='jabber:client'{attributes} from='room@muc.localhost/nick' to='alice@localhost'><status>room state</status></presence>")).map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
        }
    }
    ping(&mut component, "done")?;
    ping_result(&mut component, "done")?;
    barrier(&mut phone)?;
    traffic(&suite, "presence", 4, 0)?;
    component.close()?;
    close_available_pair(desk, phone)?;
    suite.stop()
}

#[test]
fn component_probes_without_presence_access_return_only_unsubscribed_to_each_originating_connection()
-> TestResult {
    let mut suite = C2sSuite::with_components(
        "[components.domains.'muc.localhost']\nsecret='component-test-secret-0001'\nmax_connections=2",
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<presence><status>private</status></presence>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'><status>private</status></presence>")?;
    let mut failed = ComponentClient::connect(suite.component_address(0)?)?;
    failed.open(DOMAIN, None)?;
    failed.send("<handshake>wrong</handshake>")?;
    failed.expect_stream_error("not-authorized")?;
    failed.expect_footer()?;
    failed.shutdown_write()?;
    failed.expect_eof()?;
    let mut first = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let mut second = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for component in [&mut first, &mut second] {
        component.send("<presence type='probe' from='bot@muc.localhost' to='alice@localhost'/>")?;
        component.expect_xml("<presence xmlns='jabber:component:accept' type='unsubscribed' from='alice@localhost' to='bot@muc.localhost'/>").map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
        ping(component, "done")?;
        ping_result(component, "done")?;
    }
    traffic(&suite, "presence", 2, 2)?;
    first.close()?;
    second.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn component_presence_errors_reach_only_the_addressed_full_or_available_bare_resources()
-> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    available_pair(&mut desk, &mut phone)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let payload = "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>";
    component.send(&format!("<presence type='error' from='room@muc.localhost/nick' to='alice@localhost/desk' id='full'>{payload}</presence>"))?;
    desk.expect_xml(&format!("<presence xmlns='jabber:client' type='error' from='room@muc.localhost/nick' to='alice@localhost/desk' id='full'>{payload}</presence>")).map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
    component.send(&format!("<presence type='error' from='room@muc.localhost/nick' to='alice@localhost' id='bare'>{payload}</presence>"))?;
    for client in [&mut desk, &mut phone] {
        client.expect_xml(&format!("<presence xmlns='jabber:client' type='error' from='room@muc.localhost/nick' to='alice@localhost' id='bare'>{payload}</presence>")).map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
    }
    ping(&mut component, "done")?;
    ping_result(&mut component, "done")?;
    barrier(&mut phone)?;
    traffic(&suite, "presence", 2, 0)?;
    component.close()?;
    close_available_pair(desk, phone)?;
    suite.stop()
}

#[test]
fn component_subscription_types_pass_through_to_available_resources_without_roster_changes()
-> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    available_pair(&mut desk, &mut phone)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for kind in ["subscribe", "subscribed", "unsubscribe", "unsubscribed"] {
        component.send(&format!("<presence type='{kind}' from='bot@muc.localhost' to='alice@localhost' id='{kind}'><status>subscription request</status></presence>"))?;
        for client in [&mut desk, &mut phone] {
            client.expect_xml(&format!("<presence xmlns='jabber:client' type='{kind}' from='bot@muc.localhost' to='alice@localhost' id='{kind}'><status>subscription request</status></presence>")).map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
            client.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
            let reply = client.receive()?;
            assert_eq!(reply.attribute("type"), Some("result"));
            assert_eq!(reply.attribute("id"), Some("roster"));
            assert!(
                reply
                    .child("jabber:iq:roster", "query")?
                    .children
                    .is_empty()
            );
        }
    }
    ping(&mut component, "done")?;
    ping_result(&mut component, "done")?;
    traffic(&suite, "presence", 4, 0)?;
    component.close()?;
    close_available_pair(desk, phone)?;
    suite.stop()
}

#[test]
fn component_full_jid_subscriptions_preserve_addresses_and_fan_out_without_roster_changes()
-> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    available_pair(&mut desk, &mut phone)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for kind in ["subscribe", "subscribed", "unsubscribe", "unsubscribed"] {
        component.send(&format!("<presence type='{kind}' from='bot@muc.localhost' to='alice@localhost/desk' id='{kind}'><status>full target subscription</status></presence>"))?;
        ping(&mut component, kind)?;
        ping_result(&mut component, kind)?;
        for (client, resource) in [(&mut desk, "desk"), (&mut phone, "phone")] {
            client.expect_xml(&format!("<presence xmlns='jabber:client' type='{kind}' from='bot@muc.localhost' to='alice@localhost/desk' id='{kind}'><status>full target subscription</status></presence>"))?;
            client.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
            client.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='roster' to='alice@localhost/{resource}'><query xmlns='jabber:iq:roster'/></iq>"))?;
        }
    }
    component.close()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    traffic(&suite, "presence", 4, 0)?;
    traffic(&suite, "iq", 4, 4)?;
    close_available_pair(desk, phone)?;
    suite.stop()
}

#[test]
fn component_subscriptions_to_missing_full_jids_are_silent_and_keep_the_stream_usable() -> TestResult
{
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for kind in ["subscribe", "subscribed", "unsubscribe", "unsubscribed"] {
        component.send(&format!("<presence type='{kind}' from='bot@muc.localhost' to='nobody@localhost/desk' id='{kind}'><status>missing full target</status></presence>"))?;
        ping(&mut component, kind)?;
        ping_result(&mut component, kind)?;
    }
    component.close()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    traffic(&suite, "presence", 4, 0)?;
    traffic(&suite, "iq", 4, 4)?;
    suite.stop()
}

#[test]
fn component_stanzas_route_to_other_and_own_service_domains_without_recursive_dispatch()
-> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let mut pubsub = ComponentClient::authenticated(&suite, "pubsub.localhost", SECRET)?;
    for target in ["node@pubsub.localhost", "self@muc.localhost"] {
        for (kind, attributes, payload) in [
            ("message", "type='chat'", "<body>service message</body>"),
            ("iq", "type='get'", "<query xmlns='urn:test'/>"),
            ("presence", "type='subscribe'", ""),
            ("presence", "type='subscribed'", ""),
            ("presence", "type='unsubscribe'", ""),
            ("presence", "type='unsubscribed'", ""),
            ("presence", "type='unavailable'", ""),
            (
                "presence",
                "type='error'",
                "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>",
            ),
            ("presence", "type='probe'", ""),
            ("presence", "", "<status>service state</status>"),
        ] {
            component.send(&format!("<{kind} {attributes} from='muc.localhost' to='{target}' id='service'>{payload}</{kind}>"))?;
            let receiver = if target.starts_with("self@") {
                &mut component
            } else {
                &mut pubsub
            };
            receiver.expect_xml(&format!("<{kind} xmlns='{NAMESPACE}' {attributes} from='muc.localhost' to='{target}' id='service'>{payload}</{kind}>")).map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
        }
    }
    traffic(&suite, "message", 2, 2)?;
    traffic(&suite, "iq", 2, 2)?;
    traffic(&suite, "presence", 16, 16)?;
    pubsub.close()?;
    suite.wait_for_metric("lonewolf_component_streams 1")?;
    for (kind, attributes, payload) in [
        ("message", "type='chat'", "<body>offline service</body>"),
        ("iq", "type='get'", "<query xmlns='urn:test'/>"),
    ] {
        component.send(&format!("<{kind} {attributes} from='muc.localhost' to='node@pubsub.localhost' id='offline'>{payload}</{kind}>"))?;
        error(
            &component.receive()?,
            kind,
            "offline",
            "node@pubsub.localhost",
            DOMAIN,
            "remote-server-timeout",
        )?;
    }
    suite.wait_for_metric(
        "lonewolf_component_admission_rejections_total{reason=\"not_connected\"} 2",
    )?;
    component.close()?;
    suite.stop()
}

#[test]
fn component_messages_and_iqs_to_remote_domains_report_federation_disabled() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for (kind, attributes, payload) in [
        ("message", "type='chat'", "<body>remote</body>"),
        ("iq", "type='get'", "<ping xmlns='urn:xmpp:ping'/>"),
    ] {
        component.send(&format!("<{kind} {attributes} from='muc.localhost' to='user@remote.example' id='remote'>{payload}</{kind}>"))?;
        error(
            &component.receive()?,
            kind,
            "remote",
            "user@remote.example",
            DOMAIN,
            "remote-server-not-found",
        )?;
    }
    traffic(&suite, "message", 1, 1)?;
    traffic(&suite, "iq", 1, 1)?;
    component.close()?;
    suite.stop()
}

#[test]
fn component_error_stanzas_and_server_iq_results_never_generate_replies() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for target in [
        "localhost",
        "localhost/unknown",
        "nobody@localhost",
        "nobody@localhost/desk",
        "user@remote.example",
        "node@pubsub.localhost",
    ] {
        for kind in ["message", "iq", "presence"] {
            component.send(&format!("<{kind} type='error' from='muc.localhost' to='{target}' id='error'><error type='cancel'><service-unavailable xmlns='{ERRORS}'/></error></{kind}>"))?;
        }
    }
    component.send("<iq type='result' from='muc.localhost' to='localhost' id='result'/>")?;
    for target in ["localhost", "localhost/unknown", "user@remote.example"] {
        for attributes in [
            "",
            "type='unavailable'",
            "type='probe'",
            "type='subscribe'",
            "type='subscribed'",
            "type='unsubscribe'",
            "type='unsubscribed'",
        ] {
            component.send(&format!(
                "<presence {attributes} from='muc.localhost' to='{target}'/>"
            ))?;
        }
    }
    ping(&mut component, "done")?;
    ping_result(&mut component, "done")?;
    component.close()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    traffic(&suite, "message", 6, 0)?;
    traffic(&suite, "iq", 8, 1)?;
    traffic(&suite, "presence", 27, 0)?;
    suite.stop()
}

pub(super) fn through_ping(component: &mut ComponentClient, id: &str) -> TestResult<Vec<Element>> {
    let mut stanzas = Vec::new();
    loop {
        let stanza = component.receive()?;
        if stanza.name == "iq" && stanza.attribute("id") == Some(id) {
            stanza.assert_xml(&format!("<iq xmlns='{NAMESPACE}' type='result' from='localhost' to='muc.localhost' id='{id}'/>"))?;
            return Ok(stanzas);
        }
        stanzas.push(stanza);
    }
}

#[test]
fn generated_replies_keep_connection_affinity_while_authorized_client_results_follow_balancing()
-> TestResult {
    let mut suite = C2sSuite::with_components(
        "[components.domains.'muc.localhost']\nsecret='component-test-secret-0001'\nmax_connections=2\nbalancing='bare_destination'",
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut failed = ComponentClient::connect(suite.component_address(0)?)?;
    failed.open(DOMAIN, None)?;
    failed.send("<handshake>wrong</handshake>")?;
    failed.expect_stream_error("not-authorized")?;
    failed.expect_footer()?;
    failed.shutdown_write()?;
    failed.expect_eof()?;
    let mut first = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let mut second = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for (component, id) in [(&mut first, "first"), (&mut second, "second")] {
        ping(component, id)?;
        ping_result(component, id)?;
        component.send(&format!("<message type='chat' from='room@muc.localhost' to='nobody@localhost' id='{id}'><body>missing</body></message>"))?;
        error(
            &component.receive()?,
            "message",
            id,
            "nobody@localhost",
            "room@muc.localhost",
            "service-unavailable",
        )?;
        component.send(&format!("<iq type='get' from='room@muc.localhost' to='alice@localhost/desk' id='{id}'><query xmlns='urn:test:resource'/></iq>"))?;
        error(
            &component.receive()?,
            "iq",
            id,
            "alice@localhost/desk",
            "room@muc.localhost",
            "service-unavailable",
        )?;
    }
    barrier(&mut alice)?;
    alice.send("<presence to='room@muc.localhost'/>")?;
    for n in 0..20 {
        for room in ["room", "other"] {
            alice.send(&format!("<message type='chat' to='{room}@muc.localhost' id='{room}-{n}'><body>{n}</body></message>"))?;
        }
    }
    barrier(&mut alice)?;
    ping(&mut first, "first-boundary")?;
    ping(&mut second, "second-boundary")?;
    let distribution = [
        through_ping(&mut first, "first-boundary")?,
        through_ping(&mut second, "second-boundary")?,
    ];
    let mut room_owner = None;
    for room in ["room", "other"] {
        let target = format!("{room}@muc.localhost");
        let counts: Vec<_> = distribution
            .iter()
            .map(|stanzas| {
                stanzas
                    .iter()
                    .filter(|stanza| {
                        stanza.name == "message" && stanza.attribute("to") == Some(target.as_str())
                    })
                    .count()
            })
            .collect();
        assert_eq!(counts.iter().sum::<usize>(), 20);
        let owner = counts
            .iter()
            .position(|count| *count == 20)
            .ok_or("destination traffic split across connections")?;
        let messages: Vec<_> = distribution[owner]
            .iter()
            .filter(|stanza| {
                stanza.name == "message" && stanza.attribute("to") == Some(target.as_str())
            })
            .collect();
        for (n, message) in messages.into_iter().enumerate() {
            message.assert_xml(&format!("<message xmlns='{NAMESPACE}' type='chat' from='alice@localhost/desk' to='{target}' id='{room}-{n}'><body>{n}</body></message>"))?;
        }
        if room == "room" {
            room_owner = Some(owner);
        }
    }
    for index in 0..20 {
        let nick = if index % 2 == 0 { "north" } else { "south" };
        alice.send(&format!("<message type='chat' to='room@muc.localhost/{nick}' id='occupant-{index}'><body>{index}</body></message>"))?;
    }
    barrier(&mut alice)?;
    ping(&mut first, "first-occupants")?;
    ping(&mut second, "second-occupants")?;
    for (i, stanzas) in [
        through_ping(&mut first, "first-occupants")?,
        through_ping(&mut second, "second-occupants")?,
    ]
    .into_iter()
    .enumerate()
    {
        if Some(i) == room_owner {
            assert_eq!(stanzas.len(), 20);
            for (index, stanza) in stanzas.iter().enumerate() {
                let nick = if index % 2 == 0 { "north" } else { "south" };
                stanza.assert_xml(&format!("<message xmlns='{NAMESPACE}' from='alice@localhost/desk' type='chat' to='room@muc.localhost/{nick}' id='occupant-{index}'><body>{index}</body></message>"))?;
            }
        } else {
            assert!(stanzas.is_empty());
        }
    }
    let owner = room_owner.ok_or("missing room owner")?;
    let presence: Vec<_> = distribution
        .iter()
        .flatten()
        .filter(|stanza| stanza.name == "presence")
        .collect();
    assert_eq!(presence.len(), 1);
    presence[0].assert_xml(&format!(
        "<presence xmlns='{NAMESPACE}' from='alice@localhost/desk' to='room@muc.localhost'/>"
    ))?;
    assert!(
        distribution[owner]
            .iter()
            .any(|stanza| stanza.name == "presence")
    );
    let (selected, requesting) = if owner == 0 {
        (&mut first, &mut second)
    } else {
        (&mut second, &mut first)
    };
    requesting.send("<iq type='get' from='room@muc.localhost' to='alice@localhost/desk' id='allowed'><query xmlns='urn:test:resource'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='get' from='room@muc.localhost' to='alice@localhost/desk' id='allowed'><query xmlns='urn:test:resource'/></iq>").map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
    alice.send("<iq type='result' to='room@muc.localhost' id='allowed'><answer xmlns='urn:test:resource'>yes</answer></iq>")?;
    barrier(&mut alice)?;
    ping(selected, "selected-boundary")?;
    ping(requesting, "requester-boundary")?;
    let results = through_ping(selected, "selected-boundary")?;
    assert_eq!(results.len(), 1);
    results[0].assert_xml("<iq xmlns='jabber:component:accept' type='result' from='alice@localhost/desk' to='room@muc.localhost' id='allowed'><answer xmlns='urn:test:resource'>yes</answer></iq>")?;
    assert!(through_ping(requesting, "requester-boundary")?.is_empty());
    traffic(&suite, "message", 2, 62)?;
    traffic(&suite, "iq", 11, 11)?;
    traffic(&suite, "presence", 0, 1)?;
    first.close()?;
    second.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn component_dispatch_to_an_extension_service_returns_its_result() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\n[hosts.localhost]\nextensions=['test-service']"
    ))?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    component.send("<iq type='get' from='room@muc.localhost' to='echo.localhost' id='extension'><query xmlns='urn:lonewolf:test:service'/></iq>")?;
    component.expect_xml("<iq xmlns='jabber:component:accept' type='result' from='echo.localhost' to='room@muc.localhost' id='extension'><query xmlns='urn:lonewolf:test:service'><count>0</count></query></iq>")?;
    traffic(&suite, "iq", 1, 1)?;
    component.close()?;
    suite.stop()
}
#[test]
fn inbound_policy_drops_component_messages_and_presence_before_permitted_delivery() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\n[hosts.localhost]\nextensions=['test-policy','ping']"
    ))?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for (kind, ty) in [("message", " type='chat'"), ("presence", "")] {
        for user in ["spammer", "friend"] {
            component.send(&format!(
                "<{kind}{ty} from='{user}@muc.localhost' to='alice@localhost/desk' id='{user}'/>"
            ))?;
        }
        alice.expect_xml(&format!("<{kind} xmlns='jabber:client'{ty} from='friend@muc.localhost' to='alice@localhost/desk' id='friend'/>"))?;
        traffic(&suite, kind, 2, 0)?;
    }
    ping(&mut component, "end-policy")?;
    ping_result(&mut component, "end-policy")?;
    traffic(&suite, "iq", 1, 1)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn extension_iq_results_return_only_to_the_requesting_component_attachment() -> TestResult {
    const SENDER: &str = "room@muc.localhost/occupant";
    let mut suite = C2sSuite::with_components(
        "[components.domains.'muc.localhost']\nsecret='component-test-secret-0001'\nmax_connections=2\nbalancing='source'\n[hosts.localhost]\nextensions=['test-service','ping']",
    )?;
    let mut sockets = [
        ComponentClient::authenticated(&suite, DOMAIN, SECRET)?,
        ComponentClient::authenticated(&suite, DOMAIN, SECRET)?,
    ];
    suite.wait_for_metric("lonewolf_component_streams 2")?;
    let mut outputs = [Vec::new(), Vec::new()];
    for (i, socket) in sockets.iter_mut().enumerate() {
        socket.send(&format!("<iq type='get' from='{SENDER}' to='echo.localhost' id='count-{i}'><query xmlns='urn:lonewolf:test:service'/></iq>"))?;
        ping(socket, &format!("processed-{i}"))?;
    }
    for (i, socket) in sockets.iter_mut().enumerate() {
        outputs[i] = through_ping(socket, &format!("processed-{i}"))?;
    }
    for (i, socket) in sockets.iter_mut().enumerate() {
        let id = format!("after-both-requests-{i}");
        ping(socket, &id)?;
        outputs[i].extend(through_ping(socket, &id)?);
        assert_eq!(
            outputs[i].len(),
            1,
            "attachment {i} received {:?}",
            outputs[i]
        );
        outputs[i][0].assert_xml(&format!("<iq xmlns='{NAMESPACE}' type='result' from='echo.localhost' to='{SENDER}' id='count-{i}'><query xmlns='urn:lonewolf:test:service'><count>0</count></query></iq>"))?;
    }
    traffic(&suite, "iq", 6, 6)?;
    for socket in &mut sockets {
        socket.close()?;
    }
    suite.stop()
}
