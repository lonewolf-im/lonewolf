// SPDX-License-Identifier: Apache-2.0

use super::mutations;
use crate::support::component::{ComponentClient, NAMESPACE};
use crate::support::federation::peer::RawS2sPeer;
use crate::support::xml::Element;
use crate::support::{Client, TestResult, barrier};

const CLIENT: &str = "jabber:client";
const ERROR: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";

pub(crate) trait ExternalStream {
    const NS: &'static str;
    fn send(&mut self, xml: &str) -> TestResult;
    fn receive(&mut self) -> TestResult<Element>;
}

impl ExternalStream for ComponentClient {
    const NS: &'static str = NAMESPACE;

    fn send(&mut self, xml: &str) -> TestResult {
        self.send(xml)
    }

    fn receive(&mut self) -> TestResult<Element> {
        self.receive()
    }
}

impl ExternalStream for RawS2sPeer {
    const NS: &'static str = "jabber:server";

    fn send(&mut self, xml: &str) -> TestResult {
        self.send(xml)
    }

    fn receive(&mut self) -> TestResult<Element> {
        self.receive()
    }
}

pub(crate) fn envelope(
    stanza: &Element,
    ns: &str,
    name: &str,
    from: &str,
    to: &str,
    kind: Option<&str>,
) {
    stanza.assert_name(ns, name);
    assert_eq!(stanza.attribute("from"), Some(from), "{stanza:?}");
    assert_eq!(stanza.attribute("to"), Some(to), "{stanza:?}");
    assert_eq!(stanza.attribute("type"), kind, "{stanza:?}");
}

fn has_blocked_marker(stanza: &Element) -> bool {
    (stanza.namespace == "urn:xmpp:blocking:errors" && stanza.name == "blocked")
        || stanza.children.iter().any(has_blocked_marker)
}

fn delivery_error(
    stanza: &Element,
    ns: &str,
    name: &str,
    from: &str,
    to: &str,
    own: bool,
) -> TestResult {
    envelope(stanza, ns, name, from, to, Some("error"));
    assert_eq!(stanza.attribute("id"), Some("attempt"), "{stanza:?}");
    let error = stanza.child(ns, "error")?;
    assert_eq!(error.attribute("type"), Some("cancel"));
    error.child(
        ERROR,
        if own {
            "not-acceptable"
        } else {
            "service-unavailable"
        },
    )?;
    assert_eq!(
        error.child("urn:xmpp:blocking:errors", "blocked").is_ok(),
        own,
        "{stanza:?}"
    );
    assert_eq!(has_blocked_marker(stanza), own, "{stanza:?}");
    if name == "message" {
        assert_eq!(stanza.child(ns, "body")?.text, "hello");
    } else if name == "iq" {
        stanza.child("urn:test:example", "query")?;
    }
    Ok(())
}

pub(crate) fn chats<P: ExternalStream>(
    alice: &mut Client,
    peer: &mut P,
    local: &str,
    remote: &str,
    allowed: bool,
) -> TestResult {
    alice.send(&format!(
        "<message type='chat' to='{remote}' id='attempt'><body>hello</body></message>"
    ))?;
    if allowed {
        peer.receive()?.assert_xml(&format!("<message xmlns='{}' type='chat' from='{local}' to='{remote}' id='attempt'><body>hello</body></message>", P::NS))?;
    } else {
        delivery_error(&alice.receive()?, CLIENT, "message", remote, local, true)?;
    }
    peer.send(&format!("<message type='chat' from='{remote}' to='{local}' id='attempt'><body>hello</body></message>"))?;
    if allowed {
        alice.expect_xml(&format!("<message xmlns='{CLIENT}' type='chat' from='{remote}' to='{local}' id='attempt'><body>hello</body></message>"))?;
    } else {
        delivery_error(&peer.receive()?, P::NS, "message", local, remote, false)?;
    }
    Ok(())
}

pub(crate) fn blocked_matrix<P: ExternalStream>(
    alice: &mut Client,
    peer: &mut P,
    local: &str,
    remote: &str,
) -> TestResult {
    chats(alice, peer, local, remote, false)?;
    for kind in ["get", "set"] {
        alice.send(&format!(
            "<iq type='{kind}' to='{remote}' id='attempt'><query xmlns='urn:test:example'/></iq>"
        ))?;
        delivery_error(&alice.receive()?, CLIENT, "iq", remote, local, true)?;
        peer.send(&format!("<iq type='{kind}' from='{remote}' to='{local}' id='attempt'><query xmlns='urn:test:example'/></iq>"))?;
        delivery_error(&peer.receive()?, P::NS, "iq", local, remote, false)?;
    }
    let (local_bare, _) = local.split_once('/').ok_or("owner resource required")?;
    let (remote_bare, _) = remote.split_once('/').ok_or("peer resource required")?;
    for (kind, subscription) in [
        ("", false),
        (" type='unavailable'", false),
        (" type='probe'", false),
        (" type='subscribe'", true),
        (" type='subscribed'", true),
        (" type='unsubscribe'", true),
        (" type='unsubscribed'", true),
    ] {
        let (source, target) = if subscription {
            (remote_bare, local_bare)
        } else {
            (remote, local)
        };
        alice.send(&format!("<presence{kind} to='{source}' id='attempt'/>"))?;
        delivery_error(&alice.receive()?, CLIENT, "presence", source, local, true)?;
        peer.send(&format!(
            "<presence{kind} from='{source}' to='{target}' id='silent'/>"
        ))?;
    }
    for (name, kind, payload) in [
        ("iq", "result", ""),
        (
            "iq",
            "error",
            "<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>",
        ),
        (
            "presence",
            "error",
            "<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>",
        ),
        (
            "message",
            "error",
            "<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>",
        ),
    ] {
        alice.send(&format!(
            "<{name} type='{kind}' to='{remote}' id='terminal'>{payload}</{name}>"
        ))?;
        peer.send(&format!(
            "<{name} type='{kind}' from='{remote}' to='{local}' id='terminal'>{payload}</{name}>"
        ))?;
    }
    barrier(alice)
}

pub(crate) fn foreign_commands<P: ExternalStream>(
    peer: &mut P,
    principal: &str,
    owner: &str,
    missing: &str,
) -> TestResult {
    for (kind, payload) in [
        ("get", "<blocklist xmlns='urn:xmpp:blocking'/>"),
        (
            "set",
            "<block xmlns='urn:xmpp:blocking'><item jid='other.example'/></block>",
        ),
    ] {
        let mut first_reply: Option<Element> = None;
        for account in [owner, missing] {
            peer.send(&format!(
                "<iq type='{kind}' from='{principal}' to='{account}' id='foreign'>{payload}</iq>"
            ))?;
            let reply = peer.receive()?;
            envelope(&reply, P::NS, "iq", account, principal, Some("error"));
            assert_eq!(reply.attribute("id"), Some("foreign"));
            assert_eq!(reply.children.len(), 1, "{reply:?}");
            let error = reply.child(P::NS, "error")?;
            assert_eq!(error.attribute("type"), Some("auth"));
            error.child(ERROR, "forbidden")?;
            let normalized_reply = reply.without_attribute("from");
            if let Some(first) = &first_reply {
                assert_eq!(*first, normalized_reply);
            } else {
                first_reply = Some(normalized_reply);
            }
        }
    }
    Ok(())
}

pub(crate) fn verify_owner_list(alice: &mut Client) -> TestResult {
    mutations::fetch(alice, "<item jid='private.example'/>")
}

pub(crate) fn restored_traffic<P: ExternalStream>(
    alice: &mut Client,
    peer: &mut P,
    local: &str,
    remote: &str,
) -> TestResult {
    chats(alice, peer, local, remote, true)?;
    let peer_ns = P::NS;
    let (owner, _) = local.split_once('/').ok_or("owner resource required")?;
    for (kind, reply, payload) in [
        ("get", "result", "<answer xmlns='urn:test:example'/>"),
        (
            "set",
            "error",
            "<query xmlns='urn:test:example'/><error type='cancel'><feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>",
        ),
    ] {
        alice.send(&format!(
            "<iq type='{kind}' to='{remote}' id='out'><query xmlns='urn:test:example'/></iq>"
        ))?;
        peer.receive()?.assert_xml(&format!("<iq xmlns='{peer_ns}' type='{kind}' from='{local}' to='{remote}' id='out'><query xmlns='urn:test:example'/></iq>"))?;
        peer.send(&format!(
            "<iq type='{reply}' from='{remote}' to='{local}' id='out'>{payload}</iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='{CLIENT}' type='{reply}' from='{remote}' to='{local}' id='out'>{payload}</iq>"))?;
        peer.send(&format!("<iq type='{kind}' from='{remote}' to='{local}' id='in'><query xmlns='urn:test:example'/></iq>"))?;
        alice.expect_xml(&format!("<iq xmlns='{CLIENT}' type='{kind}' from='{remote}' to='{local}' id='in'><query xmlns='urn:test:example'/></iq>"))?;
        alice.send(&format!(
            "<iq type='{reply}' to='{remote}' id='in'>{payload}</iq>"
        ))?;
        peer.receive()?.assert_xml(&format!("<iq xmlns='{peer_ns}' type='{reply}' from='{local}' to='{remote}' id='in'>{payload}</iq>"))?;
    }
    alice.send(&format!(
        "<presence to='{remote}'><status>directed</status></presence>"
    ))?;
    peer.receive()?.assert_xml(&format!("<presence xmlns='{peer_ns}' from='{local}' to='{remote}'><status>directed</status></presence>"))?;
    peer.send(&format!(
        "<presence from='{remote}' to='{local}'><status>peer</status></presence>"
    ))?;
    alice.expect_xml(&format!(
        "<presence xmlns='{CLIENT}' from='{remote}' to='{local}'><status>peer</status></presence>"
    ))?;
    alice.send(&format!(
        "<presence type='probe' to='{remote}' id='probe'/>"
    ))?;
    peer.receive()?.assert_xml(&format!(
        "<presence xmlns='{peer_ns}' from='{local}' to='{remote}' type='probe' id='probe'/>"
    ))?;
    peer.send(&format!(
        "<presence type='probe' from='{remote}' to='{owner}'/>"
    ))?;
    let presence = peer.receive()?;
    envelope(&presence, peer_ns, "presence", local, remote, None);
    assert_eq!(presence.child(peer_ns, "status")?.text, "ready");

    Ok(())
}
