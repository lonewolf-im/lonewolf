// SPDX-License-Identifier: Apache-2.0

use crate::support::{C2sSuite, Client, PASSWORD, TestResult, barrier};

const MARKER: &str = "PRIVATE-XML-MARKER-0049";
const FORBIDDEN: &str = "This operation requires an omitted destination or your authenticated bare JID without a resource.";
const UNAVAILABLE: &str = "The requested service or operation is unavailable for this target. Check the address and requested feature.";
const RESERVED: &str = "Private XML cannot use an empty or reserved namespace, such as one that starts with jabber: or http://jabber.org/.";
const DESK: &str = "alice@localhost/desk";

fn query(children: &str) -> String {
    format!("<query xmlns='jabber:iq:private'>{children}</query>")
}

fn expect_result(
    client: &mut Client,
    id: &str,
    from: Option<&str>,
    to: &str,
    payload: &str,
) -> TestResult {
    let from = from
        .map(|from| format!(" from='{from}'"))
        .unwrap_or_default();
    client.expect_xml(&format!(
        "<iq xmlns='jabber:client' type='result' id='{id}'{from} to='{to}'>{payload}</iq>"
    ))
}

struct Expected<'a> {
    kind: &'a str,
    condition: &'a str,
    text: &'a str,
}

fn expect_error(
    client: &mut Client,
    id: &str,
    from: Option<&str>,
    to: &str,
    error: Expected<'_>,
) -> TestResult {
    let Expected {
        kind,
        condition,
        text,
    } = error;
    let from = from
        .map(|from| format!(" from='{from}'"))
        .unwrap_or_default();
    client.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='{id}'{from} to='{to}'><error type='{kind}'><{condition} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>{text}</text></error></iq>"))
}

#[test]
fn private_xml_round_trips_between_resources_and_owner_aliases() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    desk.send(&format!(
        "<iq type='set' id='store'>{}</iq>",
        query("<exodus xmlns='exodus:prefs'><defaultnick>Hamlet</defaultnick></exodus>")
    ))?;
    expect_result(&mut desk, "store", None, DESK, "")?;
    let stored = query(
        "<exodus xmlns='exodus:prefs' xml:lang='' xml:space='default'><defaultnick>Hamlet</defaultnick></exodus>",
    );
    let read = query("<exodus xmlns='exodus:prefs'/>");
    phone.send(&format!("<iq type='get' id='read'>{read}</iq>"))?;
    expect_result(&mut phone, "read", None, "alice@localhost/phone", &stored)?;
    phone.send(&format!(
        "<iq type='get' id='read' to='alice@localhost'>{read}</iq>"
    ))?;
    expect_result(
        &mut phone,
        "read",
        Some("alice@localhost"),
        "alice@localhost/phone",
        &stored,
    )?;
    desk.send(&format!(
        "<iq type='get' id='read' to='ALICE@LocalHost'>{read}</iq>"
    ))?;
    expect_result(&mut desk, "read", Some("alice@localhost"), DESK, &stored)?;
    desk.send(&format!(
        "<iq type='set' id='alias' to='Alice@localhost'>{}</iq>",
        query("<n xmlns='urn:n'>1</n>")
    ))?;
    expect_result(&mut desk, "alias", Some("alice@localhost"), DESK, "")?;
    phone.close()?;
    desk.close()
}

#[test]
fn private_xml_set_replaces_removes_and_keeps_other_elements() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(&format!("<iq type='set' id='store'>{}</iq>", query("<storage xmlns='storage:bookmarks'><conference jid='room@conference.example' autojoin='true'/></storage><storage xmlns='storage:rosternotes'><note jid='bob@localhost'>met at work</note></storage>")))?;
    expect_result(&mut alice, "store", None, DESK, "")?;
    alice.send(&format!(
        "<iq type='get' id='bookmarks'>{}</iq>",
        query("<storage xmlns='storage:bookmarks'/>")
    ))?;
    expect_result(
        &mut alice,
        "bookmarks",
        None,
        DESK,
        &query(
            "<storage xmlns='storage:bookmarks' xml:lang='' xml:space='default'><conference jid='room@conference.example' autojoin='true'/></storage>",
        ),
    )?;
    let notes = query(
        "<storage xmlns='storage:rosternotes' xml:lang='' xml:space='default'><note jid='bob@localhost'>met at work</note></storage>",
    );
    alice.send(&format!(
        "<iq type='get' id='notes'>{}</iq>",
        query("<storage xmlns='storage:rosternotes'/>")
    ))?;
    expect_result(&mut alice, "notes", None, DESK, &notes)?;
    alice.send(&format!(
        "<iq type='set' id='remove'>{}</iq>",
        query("<storage xmlns='storage:bookmarks'/>")
    ))?;
    expect_result(&mut alice, "remove", None, DESK, "")?;
    alice.send(&format!(
        "<iq type='get' id='bookmarks'>{}</iq>",
        query("<storage xmlns='storage:bookmarks'/>")
    ))?;
    expect_result(
        &mut alice,
        "bookmarks",
        None,
        DESK,
        &query("<storage xmlns='storage:bookmarks'/>"),
    )?;
    alice.send(&format!(
        "<iq type='get' id='notes'>{}</iq>",
        query("<storage xmlns='storage:rosternotes'/>")
    ))?;
    expect_result(&mut alice, "notes", None, DESK, &notes)?;
    alice.send(&format!(
        "<iq type='set' id='last'>{}</iq>",
        query("<n xmlns='urn:n'>2</n><n xmlns='urn:n'/>")
    ))?;
    expect_result(&mut alice, "last", None, DESK, "")?;
    alice.send(&format!(
        "<iq type='get' id='n'>{}</iq>",
        query("<n xmlns='urn:n'/>")
    ))?;
    expect_result(&mut alice, "n", None, DESK, &query("<n xmlns='urn:n'/>"))?;
    alice.send(&format!(
        "<iq type='get' id='miss'>{}</iq>",
        query("<p:storage xmlns:p='storage:bookmarks' extra='1'><x/>text</p:storage>")
    ))?;
    expect_result(
        &mut alice,
        "miss",
        None,
        DESK,
        &query("<storage xmlns='storage:bookmarks'/>"),
    )?;
    alice.close()
}

#[test]
fn private_xml_queries_are_validated_without_changing_storage() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(&format!(
        "<iq type='set' id='store'>{}</iq>",
        query("<n xmlns='urn:n'>kept</n>")
    ))?;
    expect_result(&mut alice, "store", None, DESK, "")?;
    let none = "Include one child element with its own namespace in the private XML query.";
    let marker = format!("<n xmlns='urn:n'>{MARKER}</n><m xmlns='jabber:client'/>");
    let cases = [
        ("get", "", "not-acceptable", none),
        ("set", " ", "not-acceptable", none),
        (
            "set",
            "text",
            "bad-request",
            "A private XML query can contain only child elements.",
        ),
        (
            "get",
            "<a xmlns='urn:a'/><b xmlns='urn:b'/>",
            "bad-request",
            "Request one private XML element at a time.",
        ),
        ("set", "<foo>bar</foo>", "not-acceptable", RESERVED),
        ("set", "<a xmlns=''>1</a>", "not-acceptable", RESERVED),
        (
            "set",
            "<x xmlns='jabber:x:data'/>",
            "not-acceptable",
            RESERVED,
        ),
        (
            "set",
            "<query xmlns='http://jabber.org/protocol/muc'>1</query>",
            "not-acceptable",
            RESERVED,
        ),
        (
            "set",
            "<vCard xmlns='vcard-temp'><FN>x</FN></vCard>",
            "not-acceptable",
            RESERVED,
        ),
        (
            "set",
            "<features xmlns='http://etherx.jabber.org/streams'/>",
            "not-acceptable",
            RESERVED,
        ),
        ("set", marker.as_str(), "not-acceptable", RESERVED),
        (
            "set",
            "<n xmlns='urn:n' xml:space='keep'>x</n>",
            "bad-request",
            "Private XML must use an xml:space value of default or preserve.",
        ),
    ];
    for (kind, children, condition, text) in cases {
        alice.send(&format!(
            "<iq type='{kind}' id='invalid'>{}</iq>",
            query(children)
        ))?;
        expect_error(
            &mut alice,
            "invalid",
            None,
            DESK,
            Expected {
                kind: "modify",
                condition,
                text,
            },
        )?;
    }
    for request in [
        "<iq type='set' id='invalid'><query xmlns='jabber:iq:private' xml:space='keep'><n xmlns='urn:n'>x</n></query></iq>",
        "<iq type='set' id='invalid' xml:space='keep'><query xmlns='jabber:iq:private'><n xmlns='urn:n'>x</n></query></iq>",
    ] {
        alice.send(request)?;
        expect_error(
            &mut alice,
            "invalid",
            None,
            DESK,
            Expected {
                kind: "modify",
                condition: "bad-request",
                text: "Private XML must use an xml:space value of default or preserve.",
            },
        )?;
    }
    alice.send(&format!(
        "<iq type='get' id='read'>{}</iq>",
        query("<n xmlns='urn:n'/>")
    ))?;
    expect_result(
        &mut alice,
        "read",
        None,
        DESK,
        &query("<n xmlns='urn:n' xml:lang='' xml:space='default'>kept</n>"),
    )?;
    alice.close()
}

#[test]
fn private_xml_other_destinations_are_forbidden_without_reflection_or_delivery() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "visible")?;
    bob.send(&format!(
        "<iq type='set' id='store'>{}</iq>",
        query("<n xmlns='urn:n'>bob</n>")
    ))?;
    expect_result(&mut bob, "store", None, "bob@localhost/visible", "")?;
    desk.send(&format!(
        "<iq type='set' id='store'>{}</iq>",
        query("<n xmlns='urn:n'>alice</n>")
    ))?;
    expect_result(&mut desk, "store", None, DESK, "")?;
    let write = format!("<n xmlns='urn:n'>{MARKER}</n>");
    for target in [
        "bob@localhost",
        "missing@localhost",
        "alice@localhost/desk",
        "alice@localhost/phone",
        "alice@localhost/absent",
        "bob@localhost/visible",
        "localhost",
        "localhost/resource",
        "remote.example",
        "bob@remote.example",
        "bob@remote.example/phone",
    ] {
        for (kind, payload) in [("get", "<n xmlns='urn:n'/>"), ("set", write.as_str())] {
            desk.send(&format!(
                "<iq type='{kind}' id='forbidden' to='{target}'>{}</iq>",
                query(payload)
            ))?;
            expect_error(
                &mut desk,
                "forbidden",
                Some(target),
                DESK,
                Expected {
                    kind: "auth",
                    condition: "forbidden",
                    text: FORBIDDEN,
                },
            )?;
            barrier(&mut phone)?;
            barrier(&mut bob)?;
        }
    }
    for (client, to, value) in [
        (&mut bob, "bob@localhost/visible", "bob"),
        (&mut desk, DESK, "alice"),
    ] {
        client.send(&format!(
            "<iq type='get' id='read'>{}</iq>",
            query("<n xmlns='urn:n'/>")
        ))?;
        expect_result(
            client,
            "read",
            None,
            to,
            &query(&format!(
                "<n xmlns='urn:n' xml:lang='' xml:space='default'>{value}</n>"
            )),
        )?;
    }
    bob.close()?;
    phone.close()?;
    desk.close()
}

#[test]
fn private_xml_limits_follow_the_host_configuration() -> TestResult {
    let suite = C2sSuite::with_hosts(
        "[hosts.localhost]\nextensions = ['private']\n[hosts.localhost.private]\nmax_items = 2\nmax_bytes = 400",
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(&format!(
        "<iq type='set' id='store'>{}</iq>",
        query("<a xmlns='urn:a'>1</a><b xmlns='urn:b'>1</b>")
    ))?;
    expect_result(&mut alice, "store", None, DESK, "")?;
    let quota = "Private XML storage for this account is limited to 2 elements and 400 bytes. Remove stored elements or store less XML.";
    let large = format!("<b xmlns='urn:b'>{}</b>", "x".repeat(250));
    for children in [
        "<c xmlns='urn:c'>1</c>",
        "<a xmlns='urn:a'>new</a><c xmlns='urn:c'>1</c>",
        large.as_str(),
    ] {
        alice.send(&format!(
            "<iq type='set' id='full'>{}</iq>",
            query(children)
        ))?;
        expect_error(
            &mut alice,
            "full",
            None,
            DESK,
            Expected {
                kind: "wait",
                condition: "resource-constraint",
                text: quota,
            },
        )?;
    }
    alice.send(&format!(
        "<iq type='set' id='element'>{}</iq>",
        query(&format!("<c xmlns='urn:c'>{}</c>", "x".repeat(400)))
    ))?;
    expect_error(
        &mut alice,
        "element",
        None,
        DESK,
        Expected {
            kind: "wait",
            condition: "resource-constraint",
            text: quota,
        },
    )?;
    for (name, value) in [("a", "1"), ("b", "1")] {
        alice.send(&format!(
            "<iq type='get' id='read'>{}</iq>",
            query(&format!("<{name} xmlns='urn:{name}'/>"))
        ))?;
        expect_result(
            &mut alice,
            "read",
            None,
            DESK,
            &query(&format!(
                "<{name} xmlns='urn:{name}' xml:lang='' xml:space='default'>{value}</{name}>"
            )),
        )?;
    }
    alice.send(&format!(
        "<iq type='set' id='swap'>{}</iq>",
        query("<b xmlns='urn:b'/><c xmlns='urn:c'>1</c>")
    ))?;
    expect_result(&mut alice, "swap", None, DESK, "")?;
    alice.send(&format!(
        "<iq type='get' id='read'>{}</iq>",
        query("<b xmlns='urn:b'/>")
    ))?;
    expect_result(&mut alice, "read", None, DESK, &query("<b xmlns='urn:b'/>"))?;
    alice.send(&format!(
        "<iq type='get' id='read'>{}</iq>",
        query("<c xmlns='urn:c'/>")
    ))?;
    expect_result(
        &mut alice,
        "read",
        None,
        DESK,
        &query("<c xmlns='urn:c' xml:lang='' xml:space='default'>1</c>"),
    )?;
    alice.close()
}

#[test]
fn private_xml_inherited_context_is_detached_from_retrieval() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='set' id='context' xml:lang='fr'><query xmlns='jabber:iq:private' xml:space='preserve'><a xmlns='urn:a'> keep </a><b xmlns='urn:b' xml:lang='de'>x</b></query></iq>")?;
    expect_result(&mut alice, "context", None, DESK, "")?;
    for (name, expected) in [
        (
            "a",
            "<a xmlns='urn:a' xml:lang='fr' xml:space='preserve'> keep </a>",
        ),
        (
            "b",
            "<b xmlns='urn:b' xml:lang='de' xml:space='preserve'>x</b>",
        ),
    ] {
        alice.send(&format!(
            "<iq type='get' id='{name}' xml:lang='en'>{}</iq>",
            query(&format!("<{name} xmlns='urn:{name}'/>"))
        ))?;
        expect_result(&mut alice, name, None, DESK, &query(expected))?;
    }
    alice.close()
}

#[test]
fn private_xml_pipelined_requests_observe_commit_order() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(&format!(
        "<iq type='set' id='one'>{}</iq>",
        query("<n xmlns='urn:n'>1</n>")
    ))?;
    alice.send(&format!(
        "<iq type='set' id='two'>{}</iq>",
        query("<n xmlns='urn:n'>2</n>")
    ))?;
    alice.send(&format!(
        "<iq type='get' id='read'>{}</iq>",
        query("<n xmlns='urn:n'/>")
    ))?;
    expect_result(&mut alice, "one", None, DESK, "")?;
    expect_result(&mut alice, "two", None, DESK, "")?;
    expect_result(
        &mut alice,
        "read",
        None,
        DESK,
        &query("<n xmlns='urn:n' xml:lang='' xml:space='default'>2</n>"),
    )?;
    alice.close()
}

#[test]
fn private_and_disco_are_independently_selectable() -> TestResult {
    for (extensions, disco, private) in [
        ("'private'", false, true),
        ("'disco'", true, false),
        ("'disco', 'private'", true, true),
        ("'private', 'disco'", true, true),
    ] {
        let suite = C2sSuite::with_extensions(extensions)?;
        suite.create_account("alice", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        let own = query("<n xmlns='urn:n'/>");
        alice.send(&format!("<iq type='get' id='own'>{own}</iq>"))?;
        if private {
            expect_result(&mut alice, "own", None, DESK, &own)?;
        } else {
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='own'>{own}<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>{UNAVAILABLE}</text></error></iq>"))?;
        }
        if disco {
            let feature = if private {
                "<feature var='jabber:iq:private'/>"
            } else {
                ""
            };
            alice.send("<iq type='get' to='localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='info' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/>{feature}</query></iq>"))?;
            alice.send("<iq type='get' to='alice@localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
            alice.expect_xml("<iq xmlns='jabber:client' type='result' id='info' from='alice@localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='account' type='registered'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/></query></iq>")?;
        }
        alice.close()?;
    }
    Ok(())
}

#[test]
fn private_xml_is_isolated_per_account() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    alice.send(&format!(
        "<iq type='set' id='store'>{}</iq>",
        query("<n xmlns='urn:n'>alice</n>")
    ))?;
    expect_result(&mut alice, "store", None, DESK, "")?;
    let read = query("<n xmlns='urn:n'/>");
    bob.send(&format!("<iq type='get' id='read'>{read}</iq>"))?;
    expect_result(&mut bob, "read", None, "bob@localhost/desk", &read)?;
    bob.send(&format!(
        "<iq type='set' id='store'>{}</iq>",
        query("<n xmlns='urn:n'>bob</n>")
    ))?;
    expect_result(&mut bob, "store", None, "bob@localhost/desk", "")?;
    for (client, to, value) in [
        (&mut alice, DESK, "alice"),
        (&mut bob, "bob@localhost/desk", "bob"),
    ] {
        client.send(&format!("<iq type='get' id='read'>{read}</iq>"))?;
        expect_result(
            client,
            "read",
            None,
            to,
            &query(&format!(
                "<n xmlns='urn:n' xml:lang='' xml:space='default'>{value}</n>"
            )),
        )?;
    }
    bob.close()?;
    alice.close()
}
