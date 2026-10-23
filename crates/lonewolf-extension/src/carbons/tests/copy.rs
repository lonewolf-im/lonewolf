// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::ArenaRead;
use lonewolf_xmpp::stanza::{
    CLIENT_NAMESPACE, Element, ElementRef, MAX_ELEMENT_DEPTH, MAX_ELEMENT_NODES, MessageType,
    NodeRef, Stanza, StanzaNamespace, StanzaType,
};

use super::*;
use crate::archive::ArchiveId;
use crate::carbons::copy::{Original, build};
use crate::carbons::{FORWARD_NAMESPACE, NAMESPACE};
use crate::delivery::HostLookup;
use crate::observer::MessageRole;

struct Hosts;

impl HostLookup for Hosts {
    fn is_local_host(&self, domain: &str) -> bool {
        domain == "localhost"
    }
}

fn copies(
    original: &Message,
    role: MessageRole,
    archived: Option<ArchiveId>,
) -> TestResult<Vec<Message>> {
    Ok(build(
        &owner()?,
        Original {
            stanza: original,
            role,
            archived,
        },
        &Hosts,
        &["alice@localhost/phone", "alice@localhost/tablet"],
        arena()?,
    )?)
}

fn expected(inner: &str, role: MessageRole, resource: &str, kind: &str) -> String {
    let container = match role {
        MessageRole::Sent => "sent",
        MessageRole::Received => "received",
    };
    format!(
        r#"<message xmlns="jabber:client" from="alice@localhost" to="alice@localhost/{resource}"{kind}><{container} xmlns="urn:xmpp:carbons:2"><forwarded xmlns="urn:xmpp:forward:0">{inner}</forwarded></{container}></message>"#
    )
}

fn assert_copies(copies: &[Message], inner: &str, role: MessageRole, kind: &str) -> TestResult {
    assert_eq!(copies.len(), 2);
    for (copy, resource) in copies.iter().zip(["phone", "tablet"]) {
        assert_eq!(serialize(copy)?, expected(inner, role, resource, kind));
    }
    let first = copies[0]
        .resolve()?
        .children()?
        .next()
        .transpose()?
        .ok_or("container")?;
    let second = copies[1]
        .resolve()?
        .children()?
        .next()
        .transpose()?
        .ok_or("container")?;
    assert!(std::ptr::eq(first.name().as_ptr(), second.name().as_ptr()));
    Ok(())
}

fn assert_equivalent<R: ArenaRead, S: ArenaRead>(
    actual: &ElementRef<'_, R>,
    expected: &ElementRef<'_, S>,
) -> TestResult {
    assert_eq!(actual.name(), expected.name());
    assert_eq!(actual.namespace(), expected.namespace());
    let actual_attributes = actual
        .attributes()?
        .map(|attribute| {
            attribute.map(|attribute| (attribute.name, attribute.namespace, attribute.value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_attributes = expected
        .attributes()?
        .map(|attribute| {
            attribute.map(|attribute| (attribute.name, attribute.namespace, attribute.value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(actual_attributes, expected_attributes);
    let mut actual_children = actual.children()?;
    let mut expected_children = expected.children()?;
    loop {
        match (
            actual_children.next().transpose()?,
            expected_children.next().transpose()?,
        ) {
            (Some(NodeRef::Element(actual)), Some(NodeRef::Element(expected))) => {
                assert_equivalent(&actual, &expected)?
            }
            (Some(NodeRef::Text(actual)), Some(NodeRef::Text(expected))) => {
                assert_eq!(actual, expected)
            }
            (None, None) => break,
            _ => return Err("forwarded children differ".into()),
        }
    }
    Ok(())
}

#[test]
fn sent_copies_wrap_the_original_for_each_target() -> TestResult {
    let original = parse(
        "<message from='alice@localhost/desk' to='bob@localhost' type='chat' id='x'><body>hi</body></message>",
    )?;
    let before = serialize(&original)?;
    assert_copies(
        &copies(&original, MessageRole::Sent, None)?,
        r#"<message xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" from="alice@localhost/desk" to="bob@localhost" id="x" type="chat"><body>hi</body></message>"#,
        MessageRole::Sent,
        r#" type="chat""#,
    )?;
    assert_eq!(serialize(&original)?, before);
    Ok(())
}

#[test]
fn received_copies_keep_the_routed_stanza_and_its_archive_id() -> TestResult {
    let original = parse(
        "<message from='bob@localhost/desk' to='alice@localhost' type='chat'><body>hi</body><stanza-id xmlns='urn:xmpp:sid:0' id='42' by='alice@localhost'/></message>",
    )?;
    assert_copies(
        &copies(&original, MessageRole::Received, Some(ArchiveId::new(7)))?,
        r#"<message xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" from="bob@localhost/desk" to="alice@localhost" type="chat"><body>hi</body><stanza-id xmlns="urn:xmpp:sid:0" id="42" by="alice@localhost"/></message>"#,
        MessageRole::Received,
        r#" type="chat""#,
    )
}

#[test]
fn wrapper_types_follow_the_original() -> TestResult {
    for (kind, wrapper_type) in [
        ("chat", r#" type="chat""#),
        ("headline", r#" type="headline""#),
        ("normal", ""),
        ("unknown", ""),
        ("error", ""),
    ] {
        let body = if kind == "error" {
            r#"<error type="cancel"/>"#
        } else {
            "<body/>"
        };
        let original = parse(&format!("<message type='{kind}'>{body}</message>"))?;
        let inner = format!(
            r#"<message xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" type="{kind}">{body}</message>"#
        );
        for role in [MessageRole::Sent, MessageRole::Received] {
            assert_copies(&copies(&original, role, None)?, &inner, role, wrapper_type)?;
        }
    }
    let original = parse("<message/>")?;
    assert_copies(
        &copies(&original, MessageRole::Sent, None)?,
        r#"<message xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client"/>"#,
        MessageRole::Sent,
        "",
    )
}

#[test]
fn copies_keep_namespaces_language_attributes_and_child_order() -> TestResult {
    let original = parse(
        "<message xmlns:p='urn:opaque' from='alice@localhost/desk' to='bob@remote' id='a&amp;b' type='chat' xml:lang='es' p:flag='v&amp;q'><p:before p:attr='x'>first<p:child/>last</p:before><body>hi</body><thread parent='a'>t</thread><p:after/></message>",
    )?;
    let inner = r#"<message xmlns:p="urn:opaque" xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" from="alice@localhost/desk" to="bob@remote" id="a&amp;b" type="chat" xml:lang="es" p:flag="v&amp;q"><p:before p:attr="x">first<p:child/>last</p:before><body>hi</body><thread parent="a">t</thread><p:after/></message>"#;
    for role in [MessageRole::Sent, MessageRole::Received] {
        assert_copies(
            &copies(&original, role, None)?,
            inner,
            role,
            r#" type="chat""#,
        )?;
    }
    Ok(())
}

#[test]
fn sent_copies_replace_owner_and_local_recipient_archive_ids() -> TestResult {
    let payload = r#"<stanza-id xmlns="urn:xmpp:sid:0" id="spoof" by="alice@localhost"/><stanza-id xmlns="urn:xmpp:sid:0" id="recipient" by="bob@localhost"/><stanza-id xmlns="urn:xmpp:sid:0" id="remote" by="bob@remote"/><stanza-id xmlns="urn:xmpp:sid:0" id="muc" by="room@conference"/>"#;
    let kept = r#"<stanza-id xmlns="urn:xmpp:sid:0" id="remote" by="bob@remote"/><stanza-id xmlns="urn:xmpp:sid:0" id="muc" by="room@conference"/>"#;
    for to in ["bob@localhost", "bob@localhost/desk"] {
        let original = parse(&format!("<message to='{to}'>{payload}</message>"))?;
        let before = serialize(&original)?;
        for archived in [None, Some(ArchiveId::new(7))] {
            let stamp = if archived.is_some() {
                r#"<stanza-id xmlns="urn:xmpp:sid:0" id="7" by="alice@localhost"/>"#
            } else {
                ""
            };
            let inner = format!(
                r#"<message xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" to="{to}">{kept}{stamp}</message>"#
            );
            assert_copies(
                &copies(&original, MessageRole::Sent, archived)?,
                &inner,
                MessageRole::Sent,
                "",
            )?;
            assert_eq!(serialize(&original)?, before);
        }
    }
    for to in ["bob@remote", "bob@remote/desk"] {
        let original = parse(&format!("<message to='{to}'>{payload}</message>"))?;
        let inner = format!(
            r#"<message xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" to="{to}"><stanza-id xmlns="urn:xmpp:sid:0" id="recipient" by="bob@localhost"/>{kept}</message>"#
        );
        assert_copies(
            &copies(&original, MessageRole::Sent, None)?,
            &inner,
            MessageRole::Sent,
            "",
        )?;
    }
    let payload = r#"<stanza-id xmlns="other" by="alice@localhost"/><stanza-id xmlns="urn:xmpp:sid:0"/><stanza-id xmlns="urn:xmpp:sid:0" by="alice@localhost/desk"/><x xmlns="urn:xmpp:sid:0" by="alice@localhost"/><outer><stanza-id xmlns="urn:xmpp:sid:0" by="alice@localhost"/></outer>"#;
    let original = parse(&format!("<message>{payload}</message>"))?;
    assert_copies(
        &copies(&original, MessageRole::Sent, None)?,
        &format!(
            r#"<message xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client">{payload}</message>"#
        ),
        MessageRole::Sent,
        "",
    )
}

#[test]
fn copies_exceeding_tree_limits_are_skipped() -> TestResult {
    for depth in [MAX_ELEMENT_DEPTH - 3, MAX_ELEMENT_DEPTH - 2] {
        let original = parse(&format!(
            "<message>{}{}</message>",
            "<x>".repeat(depth - 1),
            "</x>".repeat(depth - 1)
        ))?;
        for role in [MessageRole::Sent, MessageRole::Received] {
            let result = copies(&original, role, None)?;
            assert_eq!(
                result.len(),
                if depth == MAX_ELEMENT_DEPTH - 3 { 2 } else { 0 }
            );
        }
    }
    for nodes in [MAX_ELEMENT_NODES - 3, MAX_ELEMENT_NODES - 2] {
        let mut source = arena()?;
        let child = Element::builder_in("x", CLIENT_NAMESPACE, &mut source)?.build()?;
        let mut builder = Stanza::builder_in(
            StanzaType::Message(MessageType::Normal),
            StanzaNamespace::Client,
            &mut source,
        );
        for _ in 1..nodes {
            builder = builder.child(child)?;
        }
        let original = Message::from_parts(builder.build()?, source);
        for role in [MessageRole::Sent, MessageRole::Received] {
            let result = copies(&original, role, None)?;
            assert_eq!(
                result.len(),
                if nodes == MAX_ELEMENT_NODES - 3 { 2 } else { 0 }
            );
        }
    }
    Ok(())
}

#[test]
fn copies_reparse_as_client_stanzas() -> TestResult {
    let original = parse(
        "<message from='bob@remote/desk' to='alice@localhost' type='chat' xml:lang='en'><body>hi</body><p:x xmlns:p='urn:opaque'/></message>",
    )?;
    let mut inner_arena = arena()?;
    let inner = original.resolve()?.to_element_in(&mut inner_arena)?;
    let expected_inner = inner.resolve(&inner_arena)?;
    for role in [MessageRole::Sent, MessageRole::Received] {
        for copy in copies(&original, role, None)? {
            let xml = serialize(&copy)?;
            let reparsed = parse(&xml)?;
            let view = reparsed.resolve()?;
            assert_eq!(view.namespace(), StanzaNamespace::Client);
            assert_eq!(view.stanza_type(), StanzaType::Message(MessageType::Chat));
            assert_eq!(
                view.from()?.map(|jid| jid.as_str()),
                Some("alice@localhost")
            );
            assert_eq!(
                view.to()?.map(|jid| jid.as_str()),
                copy.resolve()?.to()?.map(|jid| jid.as_str())
            );
            let container = view
                .child(
                    if role == MessageRole::Sent {
                        "sent"
                    } else {
                        "received"
                    },
                    NAMESPACE,
                )?
                .ok_or("container")?;
            let forwarded = container
                .child("forwarded", FORWARD_NAMESPACE)?
                .ok_or("forwarded")?;
            let inner = forwarded
                .child("message", CLIENT_NAMESPACE)?
                .ok_or("inner message")?;
            assert_equivalent(&inner, &expected_inner)?;
        }
    }
    Ok(())
}

#[test]
fn non_message_or_server_namespace_originals_are_rejected() -> TestResult {
    for xml in [
        "<presence/>",
        "<iq type='result' id='x'/>",
        "<message xmlns='jabber:server' from='alice@localhost/desk' to='bob@remote' type='chat'/>",
    ] {
        let original = parse(xml)?;
        for role in [MessageRole::Sent, MessageRole::Received] {
            assert!(copies(&original, role, None).is_err());
        }
    }
    Ok(())
}
