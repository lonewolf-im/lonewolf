// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use rustls::pki_types::ServerName;

use crate::support::{C2sSuite, OPEN, PASSWORD, TestResult, barrier, mutually_subscribe, toggle};

#[test]
fn server_and_owner_ping_replies_preserve_addresses() -> TestResult {
    let suite = C2sSuite::start()?;
    for name in ["alice", "victim"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut victim = suite.connect("victim", PASSWORD, "spy")?;
    for (client, resource) in [(&mut alice, "desk"), (&mut phone, "phone")] {
        for (destination, source) in [
            (" to='localhost'", " from='localhost'"),
            (" to='alice@localhost'", " from='alice@localhost'"),
            ("", ""),
        ] {
            for id in ["", "&lt;&amp;&quot;&apos;&gt;", "reused", "reused"] {
                client.send(&format!("<iq type='get'{destination} from='victim@localhost/spy' id='{id}'><ping xmlns='urn:xmpp:ping'/></iq>"))?;
                client.expect_xml(&format!("<iq xmlns='jabber:client' type='result'{source} to='alice@localhost/{resource}' id='{id}'/>"))?;
            }
            client.send(&format!("<iq type='get'{destination} from='victim@localhost/spy' id='reused'><ping xmlns='urn:xmpp:ping' invalid='true'/></iq>"))?;
            client.expect_xml(&format!("<iq xmlns='jabber:client' type='error'{source} to='alice@localhost/{resource}' id='reused'><ping xmlns='urn:xmpp:ping' invalid='true'/><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>A ping must be empty and may only include the xml:lang attribute. Remove other attributes, text, and child elements.</text></error></iq>"))?;
            client.send(&format!(
                "<iq type='get'{destination} id='reused'><ping xmlns='urn:xmpp:ping'/></iq>"
            ))?;
            client.expect_xml(&format!("<iq xmlns='jabber:client' type='result'{source} to='alice@localhost/{resource}' id='reused'/>"))?;
        }
        barrier(client)?;
    }
    barrier(&mut victim)?;
    victim.close()?;
    phone.close()?;
    alice.close()
}

#[test]
fn ping_payload_validation_is_namespace_aware() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for payload in [
        "<ping xmlns='urn:xmpp:ping'/>",
        "<ping xmlns='urn:xmpp:ping'></ping>",
        "<p:ping xmlns:p='urn:xmpp:ping'/>",
        "<ping xmlns='urn:xmpp:ping' xmlns:unused='urn:test'/>",
        "<ping xmlns='urn:xmpp:ping' xml:lang='es'/>",
        "<ping xmlns='urn:xmpp:ping' xml:lang=''/>",
    ] {
        alice.send(&format!(
            "<iq type='get' to='localhost' id='valid' xml:lang='fr'>{payload}</iq>"
        ))?;
        alice.expect_xml("<iq xmlns='jabber:client' type='result' from='localhost' to='alice@localhost/desk' id='valid'/>")?;
    }
    alice
        .send("<iq xmlns:p='urn:xmpp:ping' type='get' to='localhost' id='prefix'><p:ping/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='localhost' to='alice@localhost/desk' id='prefix'/>")?;
    for payload in [
        "<ping xmlns='urn:xmpp:ping' unknown='true'/>",
        "<ping xmlns='urn:xmpp:ping' lang='es'/>",
        "<ping xmlns='urn:xmpp:ping' xmlns:f='urn:foreign' f:lang='es'/>",
        "<ping xmlns='urn:xmpp:ping' xml:space='preserve'/>",
        "<ping xmlns='urn:xmpp:ping' xml:base='urn:test'/>",
        "<ping xmlns='urn:xmpp:ping' xml:id='unexpected'/>",
        "<ping xmlns='urn:xmpp:ping' xml:lang='es' unknown='true'/>",
        "<ping xmlns='urn:xmpp:ping'> </ping>",
        "<ping xmlns='urn:xmpp:ping'>text</ping>",
        "<ping xmlns='urn:xmpp:ping'><child/></ping>",
        "<ping xmlns='urn:xmpp:ping'>before<child/>after</ping>",
    ] {
        alice.send(&format!(
            "<iq type='get' to='localhost' id='invalid'>{payload}</iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='localhost' to='alice@localhost/desk' id='invalid'>{payload}<error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>A ping must be empty and may only include the xml:lang attribute. Remove other attributes, text, and child elements.</text></error></iq>"))?;
        alice.send(
            "<iq type='get' to='localhost' id='recovery'><ping xmlns='urn:xmpp:ping'/></iq>",
        )?;
        alice.expect_xml("<iq xmlns='jabber:client' type='result' from='localhost' to='alice@localhost/desk' id='recovery'/>")?;
    }
    alice.close()?;
    let mut alice = suite.unauthenticated_client()?;
    alice.authenticate("alice", PASSWORD)?;
    let mut alice = alice.restart();
    alice.open_with(&OPEN.replace('>', " xml:lang='es'>"))?;
    alice.features()?;
    alice.bind(Some("desk"))?;
    alice
        .send("<iq type='get' to='localhost' id='inherited'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='localhost' to='alice@localhost/desk' id='inherited'/>")?;
    alice.close()
}

#[test]
fn ping_unsupported_requests_keep_generic_iq_errors() -> TestResult {
    for enabled in [true, false] {
        let suite = C2sSuite::with_extensions(if enabled {
            "'disco', 'ping'"
        } else {
            "'disco'"
        })?;
        suite.create_account("alice", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        for target in ["localhost", "alice@localhost"] {
            for (kind, payload) in [
                ("set", "<ping xmlns='urn:xmpp:ping'/>"),
                ("get", "<ping xmlns='urn:wrong'/>"),
                ("get", "<wrong xmlns='urn:xmpp:ping'/>"),
            ] {
                alice.send(&format!(
                    "<iq type='{kind}' to='{target}' id='unsupported'>{payload}</iq>"
                ))?;
                alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}' id='unsupported'>{payload}<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
            }
            if !enabled {
                alice.send(&format!(
                    "<iq type='get' to='{target}' id='disabled'><ping xmlns='urn:xmpp:ping'/></iq>"
                ))?;
                alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}' id='disabled'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
            }
        }
        alice.close()?;
    }
    Ok(())
}

#[test]
fn ping_invalid_iq_shapes_use_existing_rejections() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for (attributes, payload, id) in [
        ("type='get'", "<ping xmlns='urn:xmpp:ping'/>", ""),
        (
            "id='missing-type'",
            "<ping xmlns='urn:xmpp:ping'/>",
            "missing-type",
        ),
        (
            "type='' id='empty-type'",
            "<ping xmlns='urn:xmpp:ping'/>",
            "empty-type",
        ),
        (
            "type='unknown' id='unknown'",
            "<ping xmlns='urn:xmpp:ping'/>",
            "unknown",
        ),
        ("type='get' id='zero'", "", "zero"),
        (
            "type='get' id='two'",
            "<ping xmlns='urn:xmpp:ping'/><extra/>",
            "two",
        ),
    ] {
        alice.send(&format!("<iq {attributes} to='localhost'>{payload}</iq>"))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='localhost' to='alice@localhost/desk' id='{id}'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The request has an invalid structure or value. Check the request format.</text></error></iq>"))?;
        alice.send("<iq type='get' to='localhost' id=''><ping xmlns='urn:xmpp:ping'/></iq>")?;
        alice.expect_xml("<iq xmlns='jabber:client' type='result' from='localhost' to='alice@localhost/desk' id=''/>")?;
    }
    alice.close()
}

#[test]
fn ping_and_disco_are_independently_selectable() -> TestResult {
    for (extensions, disco, ping, extra) in [
        ("", false, false, ""),
        ("'ping'", false, true, ""),
        ("'disco'", true, false, ""),
        ("'ping', 'disco'", true, true, ""),
        ("'disco', 'ping'", true, true, ""),
        (
            "'roster', 'offline', 'disco'",
            true,
            false,
            "<feature var='jabber:iq:roster'/><feature var='msgoffline'/>",
        ),
    ] {
        let suite = C2sSuite::with_extensions(extensions)?;
        suite.create_account("alice", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        for (target, category, identity) in [
            ("localhost", "server", "im"),
            ("alice@localhost", "account", "registered"),
        ] {
            for query in ["info", "items"] {
                alice.send(&format!("<iq type='get' to='{target}' id='disco'><query xmlns='http://jabber.org/protocol/disco#{query}'/></iq>"))?;
                if disco {
                    if query == "info" {
                        let extra = if category == "server" { extra } else { "" };
                        let feature = if ping {
                            "<feature var='urn:xmpp:ping'/>"
                        } else {
                            ""
                        };
                        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' from='{target}' to='alice@localhost/desk' id='disco'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='{category}' type='{identity}'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/>{extra}{feature}</query></iq>"))?;
                    } else {
                        let items = if category == "account" {
                            "<item jid='alice@localhost/desk'/>"
                        } else {
                            ""
                        };
                        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' from='{target}' to='alice@localhost/desk' id='disco'><query xmlns='http://jabber.org/protocol/disco#items'>{items}</query></iq>"))?;
                    }
                } else {
                    alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}' id='disco'><query xmlns='http://jabber.org/protocol/disco#{query}'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
                    if ping {
                        alice.send(&format!("<iq type='get' to='{target}' id='after-disco'><ping xmlns='urn:xmpp:ping'/></iq>"))?;
                        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' from='{target}' to='alice@localhost/desk' id='after-disco'/>"))?;
                    }
                }
            }
            alice.send(&format!(
                "<iq type='get' to='{target}' id='ping'><ping xmlns='urn:xmpp:ping'/></iq>"
            ))?;
            if ping {
                alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' from='{target}' to='alice@localhost/desk' id='ping'/>"))?;
            } else {
                alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}' id='ping'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
            }
        }
        if ping {
            alice.send("<iq type='get' id='omitted'><ping xmlns='urn:xmpp:ping'/></iq>")?;
            alice.expect_xml(
                "<iq xmlns='jabber:client' type='result' to='alice@localhost/desk' id='omitted'/>",
            )?;
        }
        alice.close()?;
    }
    Ok(())
}

#[test]
fn ping_does_not_bypass_tls_or_authentication() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut plain = suite.tcp_client()?;
    plain.open()?;
    plain.send("<iq type='get' to='localhost' id='plain'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    plain.expect_stream_error("not-authorized")?;
    let mut encrypted = suite.unauthenticated_client()?;
    encrypted.send(
        "<iq type='get' to='localhost' id='unauthenticated'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    encrypted.expect_stream_error("not-authorized")
}

#[test]
fn pipelined_ping_recovery_preserves_sender_order() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    alice.send("<iq type='get' to='localhost' id='first'><ping xmlns='urn:xmpp:ping'/></iq><iq type='get' to='alice@localhost' id='bad'><ping xmlns='urn:xmpp:ping'>bad</ping></iq><iq type='get' id='last'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='localhost' to='alice@localhost/desk' id='first'/>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='alice@localhost' to='alice@localhost/desk' id='bad'><ping xmlns='urn:xmpp:ping'>bad</ping><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>A ping must be empty and may only include the xml:lang attribute. Remove other attributes, text, and child elements.</text></error></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' to='alice@localhost/desk' id='last'/>",
    )?;
    barrier(&mut phone)?;
    phone.close()?;
    alice.close()
}

#[test]
fn bare_ping_uses_existing_account_authorization() -> TestResult {
    let suite = C2sSuite::start()?;
    for name in ["alice", "bob"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    let mut sibling = suite.connect("bob", PASSWORD, "desk")?;
    for target in ["bob@localhost", "nobody@localhost"] {
        for payload in [
            "<ping xmlns='urn:xmpp:ping'/>",
            "<ping xmlns='urn:xmpp:ping' bad='true'>text</ping>",
        ] {
            alice.send(&format!(
                "<iq type='get' to='{target}' id='hidden'>{payload}</iq>"
            ))?;
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}' to='alice@localhost/desk' id='hidden'>{payload}<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
        }
    }
    bob.send("<presence to='alice@localhost/desk'/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk'/>",
    )?;
    alice.send(
        "<iq type='get' to='bob@localhost' id='directed'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='bob@localhost' to='alice@localhost/desk' id='directed'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    bob.send("<presence to='alice@localhost/desk' type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk' type='unavailable'/>")?;
    bob.send("<presence type='subscribed' to='alice@localhost'/>")?;
    barrier(&mut bob)?;
    alice.send("<presence type='subscribe' to='bob@localhost'/>")?;
    barrier(&mut alice)?;
    alice.send(
        "<iq type='get' to='bob@localhost' id='one-way'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='bob@localhost' to='alice@localhost/desk' id='one-way'/>")?;
    bob.send(
        "<iq type='get' to='alice@localhost' id='reverse'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    bob.expect_xml("<iq xmlns='jabber:client' type='error' from='alice@localhost' to='bob@localhost/phone' id='reverse'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    bob.send("<presence type='unsubscribed' to='alice@localhost'/>")?;
    barrier(&mut bob)?;
    alice.send("<presence type='subscribed' to='bob@localhost'/>")?;
    barrier(&mut alice)?;
    bob.send("<presence type='subscribe' to='alice@localhost'/>")?;
    barrier(&mut bob)?;
    bob.send("<iq type='get' to='alice@localhost' id='opposite-one-way'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost' to='bob@localhost/phone' id='opposite-one-way'/>")?;
    alice.send(
        "<iq type='get' to='bob@localhost' id='opposite-denied'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='bob@localhost' to='alice@localhost/desk' id='opposite-denied'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
    bob.send("<iq type='get' to='alice@localhost' id='mutual'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost' to='bob@localhost/phone' id='mutual'/>")?;
    bob.send("<presence type='unavailable'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost' type='unavailable'/>")?;
    barrier(&mut bob)?;
    alice.send(
        "<iq type='get' to='bob@localhost' id='unavailable'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='bob@localhost' to='alice@localhost/desk' id='unavailable'/>")?;
    barrier(&mut sibling)?;
    sibling.close()?;
    bob.close()?;
    alice.send(
        "<iq type='get' to='bob@localhost' id='offline'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='bob@localhost' to='alice@localhost/desk' id='offline'/>")?;
    alice.close()?;

    let suite = C2sSuite::with_extensions("'disco', 'ping'")?;
    for name in ["alice", "bob"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for target in ["localhost", "alice@localhost"] {
        alice.send(&format!(
            "<iq type='get' to='{target}' id='owner'><ping xmlns='urn:xmpp:ping'/></iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' from='{target}' to='alice@localhost/desk' id='owner'/>"))?;
    }
    alice.send(
        "<iq type='get' to='bob@localhost' id='no-roster'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='bob@localhost' to='alice@localhost/desk' id='no-roster'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.close()
}

#[test]
fn ping_follows_the_target_hosts_configuration() -> TestResult {
    for target_enabled in [false, true] {
        for ping_host_disco in [true, false] {
            let enabled = if ping_host_disco {
                "\"roster\", \"disco\", \"ping\""
            } else {
                "\"roster\", \"ping\""
            };
            let disabled = "\"roster\", \"disco\"";
            let local = if target_enabled { disabled } else { enabled };
            let other = if target_enabled { enabled } else { disabled };
            let suite = C2sSuite::with_hosts(&format!(
                r#"
[hosts.localhost]
extensions = [{local}]
[hosts."other.localhost"]
extensions = [{other}]
[hosts."other.localhost".tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
"#
            ))?;
            suite.create_account("alice", PASSWORD)?;
            suite.create_account_jid("alice@other.localhost", PASSWORD)?;
            let mut alice = suite.connect("alice", PASSWORD, "desk")?;
            let opening = OPEN.replace("to='localhost'", "to='other.localhost'");
            let mut plain = suite.tcp_client()?;
            plain.open_with(&opening)?;
            plain.features()?;
            let mut other = plain.start_tls_with_identity(
                Arc::clone(&suite.tls),
                ServerName::try_from("other.localhost")?,
            )?;
            other.open_with(&opening)?;
            other.features()?;
            other.authenticate("alice", PASSWORD)?;
            let mut other = other.restart();
            other.open_with(&opening)?;
            other.features()?;
            assert_eq!(other.bind(Some("desk"))?, "alice@other.localhost/desk");
            alice.send("<iq type='get' to='alice@other.localhost' id='not-owner'><ping xmlns='urn:xmpp:ping'/></iq>")?;
            let to = if target_enabled {
                " to='alice@localhost/desk'"
            } else {
                ""
            };
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='alice@other.localhost'{to} id='not-owner'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
            other.send("<presence type='subscribed' to='alice@localhost'/>")?;
            barrier(&mut other)?;
            alice.send("<presence type='subscribe' to='alice@other.localhost'/>")?;
            barrier(&mut alice)?;
            alice.send("<presence type='subscribed' to='alice@other.localhost'/>")?;
            barrier(&mut alice)?;
            other.send("<presence type='subscribe' to='alice@localhost'/>")?;
            barrier(&mut other)?;
            for (client, source, domain, ping_enabled, disco_enabled) in [
                (
                    &mut alice,
                    "alice@localhost/desk",
                    "other.localhost",
                    target_enabled,
                    !target_enabled || ping_host_disco,
                ),
                (
                    &mut other,
                    "alice@other.localhost/desk",
                    "localhost",
                    !target_enabled,
                    target_enabled || ping_host_disco,
                ),
            ] {
                for (target, category, kind) in [
                    (domain.to_owned(), "server", "im"),
                    (format!("alice@{domain}"), "account", "registered"),
                ] {
                    client.send(&format!(
                    "<iq type='get' to='{target}' id='target'><ping xmlns='urn:xmpp:ping'/></iq>"
                ))?;
                    if ping_enabled {
                        client.expect_xml(&format!("<iq xmlns='jabber:client' type='result' from='{target}' to='{source}' id='target'/>"))?;
                    } else {
                        client.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}' id='target'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
                    }
                    for query in ["info", "items"] {
                        client.send(&format!("<iq type='get' to='{target}' id='disco'><query xmlns='http://jabber.org/protocol/disco#{query}'/></iq>"))?;
                        if disco_enabled {
                            if query == "info" {
                                let roster = if category == "server" {
                                    "<feature var='jabber:iq:roster'/>"
                                } else {
                                    ""
                                };
                                let ping = if ping_enabled {
                                    "<feature var='urn:xmpp:ping'/>"
                                } else {
                                    ""
                                };
                                client.expect_xml(&format!("<iq xmlns='jabber:client' type='result' from='{target}' to='{source}' id='disco'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='{category}' type='{kind}'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/>{roster}{ping}</query></iq>"))?;
                            } else {
                                client.expect_xml(&format!("<iq xmlns='jabber:client' type='result' from='{target}' to='{source}' id='disco'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>"))?;
                            }
                        } else {
                            client.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}' id='disco'><query xmlns='http://jabber.org/protocol/disco#{query}'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
                        }
                    }
                }
            }
            let (client, target) = if target_enabled {
                (&mut alice, "alice@localhost")
            } else {
                (&mut other, "alice@other.localhost")
            };
            client.send(&format!(
                "<iq type='get' to='{target}' id='own-disabled'><ping xmlns='urn:xmpp:ping'/></iq>"
            ))?;
            client.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}' id='own-disabled'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
            other.close()?;
            alice.close()?;
        }
    }
    Ok(())
}

#[test]
fn full_jid_ping_is_answered_by_the_client_even_when_extension_disabled() -> TestResult {
    for extensions in ["'roster', 'disco', 'ping'", "'roster', 'disco'"] {
        let suite = C2sSuite::with_extensions(extensions)?;
        for name in ["alice", "bob"] {
            suite.create_account(name, PASSWORD)?;
        }
        let mut alice = suite.unauthenticated_client()?;
        alice.authenticate("alice", PASSWORD)?;
        let mut alice = alice.restart();
        alice.open_with(&OPEN.replace('>', " xml:lang='es'>"))?;
        alice.features()?;
        alice.bind(Some("desk"))?;
        let mut phone = suite.connect("alice", PASSWORD, "phone")?;
        alice.send("<iq type='get' to='alice@localhost/phone' from='victim@localhost/spy' id='sibling'><ping xmlns='urn:xmpp:ping'/></iq>")?;
        phone.expect_xml("<iq xmlns='jabber:client' type='get' from='alice@localhost/desk' to='alice@localhost/phone' id='sibling' xml:lang='es'><ping xmlns='urn:xmpp:ping'/></iq>")?;
        alice.send(
            "<iq type='get' id='barrier' xml:lang=''><query xmlns='urn:test:barrier'/></iq>",
        )?;
        alice.expect_xml("<iq xmlns='jabber:client' type='error' id='barrier' xml:lang=''><query xmlns='urn:test:barrier'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
        phone.send("<iq type='result' to='alice@localhost/desk' id='sibling'/>")?;
        alice.expect_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost/phone' to='alice@localhost/desk' id='sibling'/>")?;
        let mut bob = suite.unauthenticated_client()?;
        bob.authenticate("bob", PASSWORD)?;
        let mut bob = bob.restart();
        bob.open_with(&OPEN.replace('>', " xml:lang='fr'>"))?;
        bob.features()?;
        bob.bind(Some("phone"))?;
        bob.send("<presence to='alice@localhost/desk'/>")?;
        alice.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk' xml:lang='fr'/>")?;
        for (kind, payload, language, effective) in [
            (
                "get",
                "<ping xmlns='urn:xmpp:ping'/>",
                " xml:lang='de'",
                "de",
            ),
            (
                "get",
                "<ping xmlns='urn:xmpp:ping' extra='kept'>before<child/>after</ping>",
                "",
                "es",
            ),
            ("set", "<ping xmlns='urn:xmpp:ping'/>", "", "es"),
        ] {
            alice.send(&format!("<iq type='{kind}' to='bob@localhost/phone' from='victim@localhost/spy' id='endpoint'{language}>{payload}</iq>"))?;
            bob.expect_xml(&format!("<iq xmlns='jabber:client' type='{kind}' from='alice@localhost/desk' to='bob@localhost/phone' id='endpoint' xml:lang='{effective}'>{payload}</iq>"))?;
            alice.send(
                "<iq type='get' id='barrier' xml:lang=''><query xmlns='urn:test:barrier'/></iq>",
            )?;
            alice.expect_xml("<iq xmlns='jabber:client' type='error' id='barrier' xml:lang=''><query xmlns='urn:test:barrier'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
            if kind == "set" {
                bob.send("<iq type='error' to='alice@localhost/desk' id='endpoint'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
                alice.expect_xml("<iq xmlns='jabber:client' type='error' from='bob@localhost/phone' to='alice@localhost/desk' id='endpoint' xml:lang='fr'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
            } else {
                bob.send("<iq type='result' to='alice@localhost/desk' from='victim@localhost/spy' id='endpoint' xml:lang='es'/>")?;
                alice.expect_xml("<iq xmlns='jabber:client' type='result' from='bob@localhost/phone' to='alice@localhost/desk' id='endpoint' xml:lang='es'/>")?;
            }
        }
        alice.send("<iq type='get' to='bob@localhost/phone' id='explicit-error' xml:lang='es'><ping xmlns='urn:xmpp:ping'/></iq>")?;
        bob.expect_xml("<iq xmlns='jabber:client' type='get' from='alice@localhost/desk' to='bob@localhost/phone' id='explicit-error' xml:lang='es'><ping xmlns='urn:xmpp:ping'/></iq>")?;
        bob.send("<iq type='error' to='alice@localhost/desk' id='explicit-error' xml:lang='es'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
        alice.expect_xml("<iq xmlns='jabber:client' type='error' from='bob@localhost/phone' to='alice@localhost/desk' id='explicit-error' xml:lang='es'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
        alice.send("<iq type='get' to='bob@localhost/phone' id='revoke'><ping xmlns='urn:xmpp:ping'/></iq>")?;
        bob.expect_xml("<iq xmlns='jabber:client' type='get' from='alice@localhost/desk' to='bob@localhost/phone' id='revoke' xml:lang='es'><ping xmlns='urn:xmpp:ping'/></iq>")?;
        bob.send("<presence to='alice@localhost/desk' type='unavailable'/>")?;
        alice.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk' type='unavailable' xml:lang='fr'/>")?;
        bob.send("<iq type='result' to='alice@localhost/desk' id='revoke'/>")?;
        alice.expect_xml("<iq xmlns='jabber:client' type='result' from='bob@localhost/phone' to='alice@localhost/desk' id='revoke' xml:lang='fr'/>")?;
        bob.close()?;
        phone.close()?;
        alice.close()?;
    }
    Ok(())
}

#[test]
fn full_jid_ping_preserves_visibility_and_disconnect_errors() -> TestResult {
    let suite = C2sSuite::start()?;
    for name in ["alice", "bob"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    let mut sibling = suite.connect("bob", PASSWORD, "desk")?;
    for target in [
        "bob@localhost/phone",
        "bob@localhost/missing",
        "nobody@localhost/phone",
    ] {
        alice.send(&format!(
            "<iq type='get' to='{target}' id='denied'><ping xmlns='urn:xmpp:ping'/></iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}' to='alice@localhost/desk' id='denied'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
    }
    bob.send("<presence to='alice@localhost/desk'/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk'/>",
    )?;
    alice.send(
        "<iq type='get' to='bob@localhost/phone' id='directed'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    bob.expect_xml("<iq xmlns='jabber:client' type='get' from='alice@localhost/desk' to='bob@localhost/phone' id='directed'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    bob.send("<iq type='result' to='alice@localhost/desk' id='directed'/>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='bob@localhost/phone' to='alice@localhost/desk' id='directed'/>")?;
    bob.send("<presence to='alice@localhost/desk' type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk' type='unavailable'/>")?;
    alice.send(
        "<iq type='get' to='bob@localhost/phone' id='revoked'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='bob@localhost/phone' to='alice@localhost/desk' id='revoked'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    bob.send("<presence type='subscribed' to='alice@localhost'/>")?;
    barrier(&mut bob)?;
    alice.send("<presence type='subscribe' to='bob@localhost'/>")?;
    barrier(&mut alice)?;
    alice.send("<iq type='get' to='bob@localhost/phone' id='unavailable'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='get' from='alice@localhost/desk' to='bob@localhost/phone' id='unavailable'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    bob.send("<iq type='result' to='alice@localhost/desk' id='unavailable'/>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='bob@localhost/phone' to='alice@localhost/desk' id='unavailable'/>")?;
    bob.send(
        "<iq type='get' to='alice@localhost/desk' id='reverse'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    bob.expect_xml("<iq xmlns='jabber:client' type='error' from='alice@localhost/desk' to='bob@localhost/phone' id='reverse'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    bob.send("<presence><priority>-1</priority></presence>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'><priority>-1</priority></presence>")?;
    alice.send(
        "<iq type='get' to='bob@localhost/phone' id='negative'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    bob.expect_xml("<iq xmlns='jabber:client' type='get' from='alice@localhost/desk' to='bob@localhost/phone' id='negative'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    bob.send("<iq type='result' to='alice@localhost/desk' id='negative'/>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='bob@localhost/phone' to='alice@localhost/desk' id='negative'/>")?;
    sibling.send("<presence><priority>5</priority></presence>")?;
    sibling.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'><priority>-1</priority></presence>")?;
    sibling.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/desk' to='bob@localhost'><priority>5</priority></presence>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/desk' to='bob@localhost'><priority>5</priority></presence>")?;
    bob.close()?;
    sibling.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost' type='unavailable'/>")?;
    alice.send(
        "<iq type='get' to='bob@localhost/phone' id='closed'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='bob@localhost/phone' to='alice@localhost/desk' id='closed'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    barrier(&mut sibling)?;
    sibling.close()?;
    alice.close()
}

#[test]
fn ping_uses_normalized_jids_without_folding_resource_case() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut upper = suite.connect("alice", PASSWORD, "Desk")?;
    for (target, source) in [
        ("LOCALHOST.", "localhost"),
        ("ｌｏｃａｌｈｏｓｔ", "localhost"),
        ("ALICE@LOCALHOST.", "alice@localhost"),
    ] {
        alice.send(&format!(
            "<iq type='get' to='{target}' id='normalized'><ping xmlns='urn:xmpp:ping'/></iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' from='{source}' to='alice@localhost/desk' id='normalized'/>"))?;
    }
    alice.send(
        "<iq type='get' to='alice@localhost/Desk' id='upper'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    upper.expect_xml("<iq xmlns='jabber:client' type='get' from='alice@localhost/desk' to='alice@localhost/Desk' id='upper'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    upper.send("<iq type='result' to='alice@localhost/desk' id='upper'/>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost/Desk' to='alice@localhost/desk' id='upper'/>")?;
    alice.close()?;
    upper.send("<iq type='get' to='alice@localhost/desk' id='missing-case'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    upper.expect_xml("<iq xmlns='jabber:client' type='error' from='alice@localhost/desk' to='alice@localhost/Desk' id='missing-case'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    let mut lower = suite.connect("alice", PASSWORD, "desk")?;
    upper.send(
        "<iq type='get' to='alice@localhost/desk' id='separate'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    lower.expect_xml("<iq xmlns='jabber:client' type='get' from='alice@localhost/Desk' to='alice@localhost/desk' id='separate'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    lower.send("<iq type='result' to='alice@localhost/Desk' id='separate'/>")?;
    upper.expect_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost/desk' to='alice@localhost/Desk' id='separate'/>")?;
    lower.close()?;
    upper.close()
}

#[test]
fn ping_policy_and_nonlocal_targets_keep_existing_routing() -> TestResult {
    let suite =
        C2sSuite::with_extensions("'roster', 'disco', 'ping', 'test-policy', 'test-service'")?;
    for name in ["alice", "blocked"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut blocked = suite.connect("blocked", PASSWORD, "phone")?;
    toggle(&mut alice, false)?;
    mutually_subscribe(&mut alice, "alice", &mut blocked, "blocked")?;
    alice.send(
        "<iq type='get' to='blocked@localhost' id='allowed'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='blocked@localhost' to='alice@localhost/desk' id='allowed'/>")?;
    toggle(&mut alice, true)?;
    alice.send(
        "<iq type='get' to='blocked@localhost' id='policy'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='blocked@localhost' id='policy'><ping xmlns='urn:xmpp:ping'/><error type='modify'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>A request value exceeds an allowed limit or has an unsupported format.</text><blocked xmlns='urn:lonewolf:test:policy'/></error></iq>")?;
    toggle(&mut alice, false)?;
    alice.send(
        "<iq type='get' to='blocked@localhost' id='recovered'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='blocked@localhost' to='alice@localhost/desk' id='recovered'/>")?;
    for (target, condition) in [
        ("localhost/resource", "service-unavailable"),
        ("remote.example", "remote-server-not-found"),
        ("user@remote.example", "remote-server-not-found"),
        ("user@remote.example/resource", "remote-server-not-found"),
    ] {
        alice.send(&format!(
            "<iq type='get' to='{target}' id='nonlocal'><ping xmlns='urn:xmpp:ping'/></iq>"
        ))?;
        let to = if target == "localhost/resource" {
            " to='alice@localhost/desk'"
        } else {
            ""
        };
        let text = match condition {
            "remote-server-not-found" => {
                "The server cannot deliver this request to a remote domain."
            }
            _ => {
                "The requested service or operation is unavailable for this target. Check the address and requested feature."
            }
        };
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='{target}'{to} id='nonlocal'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><{condition} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>{text}</text></error></iq>"))?;
    }
    alice.send("<iq type='get' to='echo.localhost' id='service-ping'><ping xmlns='urn:xmpp:ping'/></iq><iq type='get' to='echo.localhost' id='service-control'><query xmlns='urn:lonewolf:test:service'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='echo.localhost' to='alice@localhost/desk' id='service-control'><query xmlns='urn:lonewolf:test:service'><count>0</count></query></iq>")?;
    alice.send(
        "<iq type='set' to='echo.localhost' id='service-set'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='echo.localhost' to='alice@localhost/desk' id='service-set'><ping xmlns='urn:xmpp:ping'/><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The request has an invalid structure or value. Check the request format.</text></error></iq>")?;
    blocked.close()?;
    alice.close()
}

#[test]
fn ping_results_and_errors_do_not_trigger_response_loops() -> TestResult {
    let suite = C2sSuite::with_extensions_limits_and_setup(
        "'ping', 'test-policy'",
        "incoming_stanzas_per_connection = { per_second = 1000, burst = 1000 }\nnew_recipients_per_connection = { per_second = 1, burst = 1 }",
        |_| Ok(()),
    )?;
    for name in ["alice", "bob", "blocked", "carol"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    let mut blocked = suite.connect("blocked", PASSWORD, "phone")?;
    let mut carol = suite.connect("carol", PASSWORD, "phone")?;
    carol.send("<presence to='alice@localhost/desk'/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='carol@localhost/phone' to='alice@localhost/desk'/>",
    )?;
    alice.send("<message to='bob@localhost/phone' id='burn'/>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/phone' id='burn'/>")?;
    alice.send(
        "<iq type='get' to='carol@localhost/phone' id='budget'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='carol@localhost/phone' to='alice@localhost/desk' id='budget'><ping xmlns='urn:xmpp:ping'/><error type='wait'><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Too many distinct recipients were contacted. Wait before contacting additional recipients.</text></error></iq>")?;
    toggle(&mut alice, true)?;
    carol.send("<presence to='alice@localhost/desk' type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='carol@localhost/phone' to='alice@localhost/desk' type='unavailable'/>")?;
    alice.send("<iq type='result' to='carol@localhost/phone' id='peer-result'><ping xmlns='urn:xmpp:ping'/></iq><iq type='error' to='carol@localhost/phone' id='peer-error'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    carol.expect_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost/desk' to='carol@localhost/phone' id='peer-result'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    carol.expect_xml("<iq xmlns='jabber:client' type='error' from='alice@localhost/desk' to='carol@localhost/phone' id='peer-error'><ping xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.send("<iq type='get' to='carol@localhost/phone' id='still-limited'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='carol@localhost/phone' to='alice@localhost/desk' id='still-limited'><ping xmlns='urn:xmpp:ping'/><error type='wait'><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Too many distinct recipients were contacted. Wait before contacting additional recipients.</text></error></iq>")?;
    for destination in [
        "",
        " to='localhost'",
        " to='alice@localhost'",
        " to='bob@localhost'",
        " to='nobody@localhost'",
        " to='bob@localhost/missing'",
        " to='nobody@localhost/phone'",
        " to='blocked@localhost'",
        " to='blocked@localhost/phone'",
        " to='remote.example'",
        " to='user@remote.example'",
        " to='user@remote.example/phone'",
    ] {
        for response in [
            format!("<iq type='result'{destination} id='unsolicited-result'/>"),
            format!(
                "<iq type='result'{destination} id='unsolicited-ping'><ping xmlns='urn:xmpp:ping'/></iq>"
            ),
            format!(
                "<iq type='error'{destination} id='unsolicited-error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
            ),
            format!(
                "<iq type='result'{destination} id='malformed-two'><ping xmlns='urn:xmpp:ping'/><extra/></iq>"
            ),
            format!(
                "<iq type='error'{destination} id='malformed-error'><ping xmlns='urn:xmpp:ping'/></iq>"
            ),
            format!("<iq type='result'{destination}><ping xmlns='urn:xmpp:ping'/></iq>"),
            format!(
                "<iq type='error'{destination}><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
            ),
        ] {
            alice.send(&response)?;
            alice.send(
                "<iq type='get' to='localhost' id='sentinel'><ping xmlns='urn:xmpp:ping'/></iq>",
            )?;
            alice.expect_xml("<iq xmlns='jabber:client' type='result' from='localhost' to='alice@localhost/desk' id='sentinel'/>")?;
        }
    }
    barrier(&mut blocked)?;
    barrier(&mut carol)?;
    carol.close()?;
    blocked.close()?;
    bob.close()?;
    alice.close()
}
