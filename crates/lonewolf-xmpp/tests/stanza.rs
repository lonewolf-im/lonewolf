// SPDX-License-Identifier: Apache-2.0

use std::alloc::Layout;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lonewolf_util::arena::{
    AllocationError, Arena, ArenaConfig, ArenaError, ArenaRead, Chunk, ChunkAllocator,
    GlobalChunkAllocator, HandleError,
};
use lonewolf_util::pool::{MIN_POOL_SIZE, PoolConfig, PooledChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{
    BuildError, CLIENT_NAMESPACE, Element, IqType, MAX_ELEMENT_DEPTH, MessageType, NodeRef,
    PresenceType, SERVER_NAMESPACE, STANZA_ERROR_NAMESPACE, STREAM_NAMESPACE, Stanza,
    StanzaErrorCondition, StanzaKind, StanzaNamespace, StanzaType, WriteError, XML_NAMESPACE,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn stanza_xml(
    stanza: Stanza,
    arena: &impl ArenaRead,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut xml = String::new();
    stanza.resolve(arena)?.write_xml(&mut xml)?;
    Ok(xml)
}

fn element_xml(
    element: Element,
    arena: &impl ArenaRead,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut xml = String::new();
    element.resolve(arena)?.write_xml(&mut xml)?;
    Ok(xml)
}

fn body(arena: &mut Arena, text: &str) -> Result<Element, BuildError> {
    Element::builder_in("body", CLIENT_NAMESPACE, arena)?
        .text(text)?
        .build()
}

fn message(arena: &mut Arena, child: Element) -> Result<Stanza, BuildError> {
    Stanza::builder_in(
        StanzaType::Message(MessageType::Chat),
        StanzaNamespace::Client,
        arena,
    )
    .child(child)?
    .build()
}

#[test]
fn builds_message_with_normalized_addresses_and_extensions() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let from = Jid::parse_in("Alice@EXAMPLE.COM/Desk", &mut arena)?;
    let to = Jid::parse_in("bob@example.net", &mut arena)?;
    let body = body(&mut arena, "Hello <Bob> & friends")?;
    let receipt = Element::builder_in("request", "urn:xmpp:receipts", &mut arena)?.build()?;
    let stanza = Stanza::builder_in(
        StanzaType::Message(MessageType::Chat),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(from))?
    .to(Some(to))?
    .id(Some("msg-1"))?
    .lang(Some("en"))?
    .child(body)?
    .child(receipt)?
    .attribute("flag", "urn:example:flags", "yes")?
    .build()?;
    let view = stanza.resolve(&arena)?;
    assert_eq!(view.kind(), StanzaKind::Message);
    assert_eq!(view.stanza_type(), StanzaType::Message(MessageType::Chat));
    assert_eq!(
        view.from()?.ok_or("from")?.as_str(),
        "alice@example.com/Desk"
    );
    assert_eq!(view.to()?.ok_or("to")?.as_str(), "bob@example.net");
    assert_eq!(view.id()?, Some("msg-1"));
    assert_eq!(view.lang()?, Some("en"));
    assert_eq!(view.attribute("flag", "urn:example:flags")?, Some("yes"));
    assert_eq!(
        view.child("body", CLIENT_NAMESPACE)?
            .ok_or("body")?
            .text()?,
        Some("Hello <Bob> & friends")
    );
    assert!(view.child("body", "urn:wrong")?.is_none());
    assert_eq!(
        stanza_xml(stanza, &arena)?,
        concat!(
            "<message xmlns=\"jabber:client\" from=\"alice@example.com/Desk\" to=\"bob@example.net\" id=\"msg-1\" type=\"chat\" xml:lang=\"en\"",
            " xmlns:ns0=\"urn:example:flags\" ns0:flag=\"yes\"><body>Hello &lt;Bob&gt; &amp; friends</body>",
            "<request xmlns=\"urn:xmpp:receipts\"/></message>"
        )
    );
    Ok(())
}

#[test]
fn writes_default_and_explicit_stanza_types() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    for (kind, name, value) in [
        (StanzaType::Message(MessageType::Normal), "message", None),
        (
            StanzaType::Message(MessageType::Chat),
            "message",
            Some("chat"),
        ),
        (
            StanzaType::Message(MessageType::Groupchat),
            "message",
            Some("groupchat"),
        ),
        (
            StanzaType::Message(MessageType::Headline),
            "message",
            Some("headline"),
        ),
        (
            StanzaType::Presence(PresenceType::Available),
            "presence",
            None,
        ),
        (
            StanzaType::Presence(PresenceType::Unavailable),
            "presence",
            Some("unavailable"),
        ),
        (
            StanzaType::Presence(PresenceType::Subscribe),
            "presence",
            Some("subscribe"),
        ),
        (
            StanzaType::Presence(PresenceType::Subscribed),
            "presence",
            Some("subscribed"),
        ),
        (
            StanzaType::Presence(PresenceType::Unsubscribe),
            "presence",
            Some("unsubscribe"),
        ),
        (
            StanzaType::Presence(PresenceType::Unsubscribed),
            "presence",
            Some("unsubscribed"),
        ),
        (
            StanzaType::Presence(PresenceType::Probe),
            "presence",
            Some("probe"),
        ),
    ] {
        let stanza = Stanza::builder_in(kind, StanzaNamespace::Client, &mut arena).build()?;
        let expected = match value {
            Some(value) => format!("<{name} xmlns=\"jabber:client\" type=\"{value}\"/>"),
            None => format!("<{name} xmlns=\"jabber:client\"/>"),
        };
        assert_eq!(stanza_xml(stanza, &arena)?, expected);
    }
    Ok(())
}

#[test]
fn represents_connection_elements_without_stanza_validation() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let tls = "urn:ietf:params:xml:ns:xmpp-tls";
    let sasl = "urn:ietf:params:xml:ns:xmpp-sasl";
    let required = Element::builder_in("required", tls, &mut arena)?.build()?;
    let starttls = Element::builder_in("starttls", tls, &mut arena)?
        .child(required)?
        .build()?;
    let mechanism = Element::builder_in("mechanism", sasl, &mut arena)?
        .text("SCRAM-SHA-256")?
        .build()?;
    let mechanisms = Element::builder_in("mechanisms", sasl, &mut arena)?
        .child(mechanism)?
        .build()?;
    let features = Element::builder_in("features", STREAM_NAMESPACE, &mut arena)?
        .child(starttls)?
        .child(mechanisms)?
        .build()?;
    assert_eq!(
        element_xml(features, &arena)?,
        concat!(
            "<stream:features xmlns:stream=\"http://etherx.jabber.org/streams\">",
            "<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"><required/></starttls>",
            "<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>SCRAM-SHA-256</mechanism></mechanisms></stream:features>"
        )
    );
    let auth = Element::builder_in("auth", sasl, &mut arena)?
        .attribute("mechanism", "", "SCRAM-SHA-256")?
        .text("c2FzbC1wYXlsb2Fk")?
        .build()?;
    assert_eq!(
        element_xml(auth, &arena)?,
        "<auth xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\" mechanism=\"SCRAM-SHA-256\">c2FzbC1wYXlsb2Fk</auth>"
    );
    let condition = Element::builder_in(
        "not-authorized",
        "urn:ietf:params:xml:ns:xmpp-streams",
        &mut arena,
    )?
    .build()?;
    let error = Element::builder_in("error", STREAM_NAMESPACE, &mut arena)?
        .child(condition)?
        .build()?;
    assert!(element_xml(error, &arena)?.starts_with("<stream:error xmlns:stream="));
    let ack = Element::builder_in("a", "urn:xmpp:sm:3", &mut arena)?
        .attribute("h", "", "42")?
        .build()?;
    assert_eq!(
        element_xml(ack, &arena)?,
        "<a xmlns=\"urn:xmpp:sm:3\" h=\"42\"/>"
    );
    let derived = ack
        .derive_in(&mut arena)?
        .attribute("h", "", "43")?
        .build()?;
    assert_eq!(ack.resolve(&arena)?.attribute("h", "")?, Some("42"));
    assert_eq!(derived.resolve(&arena)?.attribute("h", "")?, Some("43"));
    Ok(())
}

#[test]
fn preserves_mixed_content_expanded_names_and_xml_whitespace() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let empty = Element::builder_in("empty", "", &mut arena)?.build()?;
    let emphasis = Element::builder_in("em", "urn:text", &mut arena)?
        .text("bold")?
        .build()?;
    let element = Element::builder_in("p", "urn:text", &mut arena)?
        .attribute("lang", XML_NAMESPACE, "en")?
        .attribute("key", "", "a\t\n\r\"<&>")?
        .attribute("key", "urn:other", "namespaced")?
        .text("before\r")?
        .child(emphasis)?
        .text("after & ]]>\n")?
        .child(empty)?
        .build()?;
    assert_eq!(
        element_xml(element, &arena)?,
        concat!(
            "<p xmlns=\"urn:text\" xml:lang=\"en\" key=\"a&#x9;&#xA;&#xD;&quot;&lt;&amp;&gt;\" xmlns:ns2=\"urn:other\" ns2:key=\"namespaced\">",
            "before&#xD;<em>bold</em>after &amp; ]]&gt;\n<empty xmlns=\"\"/></p>"
        )
    );
    let view = element.resolve(&arena)?;
    assert_eq!(view.attribute("key", "")?, Some("a\t\n\r\"<&>"));
    assert_eq!(view.attribute("key", "urn:other")?, Some("namespaced"));
    assert_eq!(view.text()?, None);
    let children = view.children()?.collect::<Result<Vec<_>, _>>()?;
    assert!(matches!(
        children.as_slice(),
        [
            NodeRef::Text("before\r"),
            NodeRef::Element(_),
            NodeRef::Text("after & ]]>\n"),
            NodeRef::Element(_)
        ]
    ));
    let xml_element = Element::builder_in("custom", XML_NAMESPACE, &mut arena)?
        .child(empty)?
        .build()?;
    assert_eq!(
        element_xml(xml_element, &arena)?,
        "<xml:custom><empty xmlns=\"\"/></xml:custom>"
    );
    assert_eq!(element_xml(empty, &arena)?, "<empty xmlns=\"\"/>");
    Ok(())
}

#[test]
fn header_derivation_shares_large_payload_and_jid_storage() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let original_to = Jid::parse_in("alice@example.com", &mut arena)?;
    let next_to = Jid::parse_in("bob@example.com", &mut arena)?;
    let payload = body(&mut arena, &"x".repeat(32 * 1024))?;
    let original = Stanza::builder_in(
        StanzaType::Message(MessageType::Chat),
        StanzaNamespace::Client,
        &mut arena,
    )
    .to(Some(original_to))?
    .id(Some("unchanged"))?
    .child(payload)?
    .build()?;
    let before = arena.stats();
    let derived = original.derive_in(&mut arena)?.to(Some(next_to))?.build()?;
    assert!(arena.stats().used_bytes - before.used_bytes < 1024);
    let source = original.resolve(&arena)?;
    let target = derived.resolve(&arena)?;
    assert_eq!(source.to()?.ok_or("to")?.as_str(), "alice@example.com");
    assert_eq!(target.to()?.ok_or("to")?.as_str(), "bob@example.com");
    assert!(std::ptr::eq(
        source.id()?.ok_or("id")?,
        target.id()?.ok_or("id")?
    ));
    assert!(std::ptr::eq(
        source
            .child("body", CLIENT_NAMESPACE)?
            .ok_or("body")?
            .text()?
            .ok_or("text")?,
        target
            .child("body", CLIENT_NAMESPACE)?
            .ok_or("body")?
            .text()?
            .ok_or("text")?
    ));
    assert!(std::ptr::eq(
        target.to()?.ok_or("to")?.as_str(),
        next_to.resolve(&arena)?.as_str()
    ));
    Ok(())
}

#[test]
fn derived_edits_detach_lists_and_preserve_all_prior_versions() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let first = Element::builder_in("item", "urn:one", &mut arena)?
        .text("first")?
        .build()?;
    let second = Element::builder_in("item", "urn:two", &mut arena)?
        .text("second")?
        .build()?;
    let mut builder = Element::builder_in("root", "urn:root", &mut arena)?
        .child(first)?
        .child(second)?;
    for index in 0..9 {
        builder = builder.attribute(&format!("a{index}"), "", &index.to_string())?;
    }
    let original = builder.build()?;
    let before = element_xml(original, &arena)?;
    let changed_child = original
        .resolve(&arena)?
        .child("item", "urn:one")?
        .ok_or("child")?
        .handle()
        .derive_in(&mut arena)?
        .clear_children()
        .text("changed")?
        .build()?;
    let derived = original
        .derive_in(&mut arena)?
        .attribute("a4", "", "new")?
        .remove_attribute("a0", "")?
        .attribute("extra", "urn:attr", "last")?
        .remove_children("item", "urn:one")?
        .child(changed_child)?
        .text("tail")?
        .build()?;
    let derived_before = element_xml(derived, &arena)?;
    let cleared = derived
        .derive_in(&mut arena)?
        .remove_attribute("a4", "")?
        .clear_children()
        .build()?;
    assert_eq!(element_xml(original, &arena)?, before);
    assert_eq!(element_xml(derived, &arena)?, derived_before);
    assert_eq!(derived.resolve(&arena)?.attribute("a4", "")?, Some("new"));
    assert_eq!(derived.resolve(&arena)?.attribute("a0", "")?, None);
    assert_eq!(derived.resolve(&arena)?.attributes()?.count(), 9);
    assert_eq!(
        derived
            .resolve(&arena)?
            .child("item", "urn:one")?
            .ok_or("child")?
            .text()?,
        Some("changed")
    );
    assert_eq!(
        derived
            .resolve(&arena)?
            .child("item", "urn:two")?
            .ok_or("child")?
            .text()?,
        Some("second")
    );
    assert_eq!(cleared.resolve(&arena)?.children()?.count(), 0);
    assert_eq!(cleared.resolve(&arena)?.attribute("a4", "")?, None);
    Ok(())
}

#[test]
fn removing_repeated_children_preserves_order_and_shared_tail_storage() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let remove = Element::builder_in("remove", "urn:items", &mut arena)?.build()?;
    let keep = Element::builder_in("keep", "urn:items", &mut arena)?.build()?;
    let mut builder = Element::builder_in("root", "urn:items", &mut arena)?;
    for _ in 0..16 {
        builder = builder.child(remove)?.text("between")?.child(keep)?;
    }
    let original = builder.child(remove)?.build()?;
    let original_xml = element_xml(original, &arena)?;
    let filtered = original
        .derive_in(&mut arena)?
        .remove_children("remove", "urn:items")?
        .build()?;
    let expected = format!(
        "<root xmlns=\"urn:items\">{}</root>",
        "between<keep/>".repeat(16)
    );
    assert_eq!(element_xml(filtered, &arena)?, expected);
    assert_eq!(element_xml(original, &arena)?, original_xml);

    let tail = Element::builder_in("root", "urn:items", &mut arena)?
        .child(keep)?
        .child(remove)?
        .build()?;
    let trimmed = tail
        .derive_in(&mut arena)?
        .remove_children("remove", "urn:items")?
        .child(keep)?
        .build()?;
    assert_eq!(
        element_xml(trimmed, &arena)?,
        "<root xmlns=\"urn:items\"><keep/><keep/></root>"
    );
    assert_eq!(
        element_xml(tail, &arena)?,
        "<root xmlns=\"urn:items\"><keep/><remove/></root>"
    );
    Ok(())
}

#[test]
fn stanza_derivation_can_replace_payloads_and_clear_common_attributes() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let from = Jid::parse_in("alice@example.com", &mut arena)?;
    let first = body(&mut arena, "first")?;
    let second = body(&mut arena, "second")?;
    let extension = Element::builder_in("body", "urn:extension", &mut arena)?.build()?;
    let original = Stanza::builder_in(
        StanzaType::Message(MessageType::Chat),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(from))?
    .to(Some(from))?
    .id(Some("id"))?
    .lang(Some("en"))?
    .attribute("a", "urn:attr", "old")?
    .child(first)?
    .child(extension)?
    .build()?;
    let before = stanza_xml(original, &arena)?;
    let derived = original
        .derive_in(&mut arena)?
        .from(None)?
        .to(None)?
        .id(None)?
        .lang(None)?
        .stanza_type(StanzaType::Message(MessageType::Normal))
        .attribute("a", "urn:attr", "new")?
        .remove_children("body", CLIENT_NAMESPACE)?
        .child(second)?
        .build()?;
    assert_eq!(stanza_xml(original, &arena)?, before);
    let view = derived.resolve(&arena)?;
    assert!(view.from()?.is_none() && view.to()?.is_none());
    assert_eq!(view.id()?, None);
    assert_eq!(view.lang()?, None);
    assert_eq!(view.attribute("a", "urn:attr")?, Some("new"));
    assert_eq!(view.children()?.count(), 2);
    assert!(view.child("body", "urn:extension")?.is_some());
    let cleared = derived
        .derive_in(&mut arena)?
        .remove_attribute("a", "urn:attr")?
        .clear_children()
        .build()?;
    assert_eq!(
        stanza_xml(cleared, &arena)?,
        "<message xmlns=\"jabber:client\"/>"
    );
    Ok(())
}

#[test]
fn copies_from_frozen_arena_survive_source_destruction() -> TestResult {
    let mut destination = Arena::try_new(ArenaConfig::default())?;
    let (copy, edited, element, expected) = {
        let mut source = Arena::try_new(ArenaConfig::default())?;
        let from = Jid::parse_in("Alice@EXAMPLE.COM/Phone", &mut source)?;
        let body = body(&mut source, "retained text")?;
        let inner = Element::builder_in("item", "urn:items", &mut source)?
            .attribute("id", "urn:ids", "private")?
            .child(body)?
            .text("tail")?
            .build()?;
        let stanza = Stanza::builder_in(
            StanzaType::Message(MessageType::Chat),
            StanzaNamespace::Client,
            &mut source,
        )
        .from(Some(from))?
        .to(Some(from.bare()))?
        .id(Some("secret"))?
        .lang(Some("en"))?
        .attribute("mode", "urn:mode", "private")?
        .child(inner)?
        .build()?;
        let source = source.freeze();
        let expected = stanza_xml(stanza, &source)?;
        let view = stanza.resolve(&source)?;
        let copy = view.clone_in(&mut destination)?;
        let edited = view
            .to_builder_in(&mut destination)?
            .id(Some("new"))?
            .build()?;
        let element = inner
            .resolve(&source)?
            .to_builder_in(&mut destination)?
            .attribute("id", "urn:ids", "new")?
            .build()?;
        assert!(!std::ptr::eq(
            view.id()?.ok_or("id")?,
            copy.resolve(&destination)?.id()?.ok_or("copy ID")?
        ));
        (copy, edited, element, expected)
    };
    assert_eq!(stanza_xml(copy, &destination)?, expected);
    assert_eq!(edited.resolve(&destination)?.id()?, Some("new"));
    assert_eq!(
        element.resolve(&destination)?.attribute("id", "urn:ids")?,
        Some("new")
    );
    assert!(element_xml(element, &destination)?.contains("retained text"));
    Ok(())
}

#[test]
fn rejects_foreign_and_expired_handles() -> TestResult {
    let mut source = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in("example.com", &mut source)?;
    let element = body(&mut source, "source")?;
    let stanza = message(&mut source, element)?;
    let mut other = Arena::try_new(ArenaConfig::default())?;
    let wrong = BuildError::Access(HandleError::WrongArena);
    assert_eq!(stanza.resolve(&other).err(), Some(HandleError::WrongArena));
    assert_eq!(element.resolve(&other).err(), Some(HandleError::WrongArena));
    assert_eq!(
        stanza.derive_in(&mut other).err(),
        Some(HandleError::WrongArena)
    );
    assert_eq!(
        element.derive_in(&mut other).err(),
        Some(HandleError::WrongArena)
    );
    assert_eq!(
        Stanza::builder_in(
            StanzaType::Message(MessageType::Normal),
            StanzaNamespace::Client,
            &mut other
        )
        .to(Some(jid))
        .err(),
        Some(wrong)
    );
    assert_eq!(
        Stanza::builder_in(
            StanzaType::Message(MessageType::Normal),
            StanzaNamespace::Client,
            &mut other
        )
        .from(Some(jid))
        .err(),
        Some(wrong)
    );
    assert_eq!(message(&mut other, element).err(), Some(wrong));
    assert_eq!(
        Element::builder_in("root", "", &mut other)?
            .child(element)
            .err(),
        Some(wrong)
    );
    drop(source);
    let replacement = Arena::try_new(ArenaConfig::default())?;
    assert_eq!(
        stanza.resolve(&replacement).err(),
        Some(HandleError::WrongArena)
    );
    assert_eq!(
        element.resolve(&replacement).err(),
        Some(HandleError::WrongArena)
    );
    Ok(())
}

#[test]
fn enforces_iq_shape_and_generates_result_replies() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let from = Jid::parse_in("alice@example.com/Phone", &mut arena)?;
    let to = Jid::parse_in("example.com", &mut arena)?;
    let query = Element::builder_in("query", "jabber:iq:version", &mut arena)?.build()?;
    for iq_type in [IqType::Get, IqType::Set] {
        assert_eq!(
            Stanza::builder_in(StanzaType::Iq(iq_type), StanzaNamespace::Client, &mut arena)
                .child(query)?
                .build()
                .err(),
            Some(BuildError::MissingIqId)
        );
        for count in [0, 2] {
            let mut builder =
                Stanza::builder_in(StanzaType::Iq(iq_type), StanzaNamespace::Client, &mut arena)
                    .id(Some("request"))?;
            for _ in 0..count {
                builder = builder.child(query)?;
            }
            assert_eq!(builder.build().err(), Some(BuildError::InvalidIqPayload));
        }
        let request =
            Stanza::builder_in(StanzaType::Iq(iq_type), StanzaNamespace::Client, &mut arena)
                .from(Some(from))?
                .to(Some(to))?
                .id(Some("request"))?
                .child(query)?
                .build()?;
        let result = request.reply_in(&mut arena)?.build()?;
        let view = result.resolve(&arena)?;
        assert_eq!(view.stanza_type(), StanzaType::Iq(IqType::Result));
        assert_eq!(view.id()?, Some("request"));
        assert_eq!(view.from()?.ok_or("from")?.as_str(), "example.com");
        assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@example.com/Phone");
        assert_eq!(view.children()?.count(), 0);
        assert_eq!(
            result.reply_in(&mut arena).err(),
            Some(BuildError::NotIqRequest)
        );
        assert_eq!(request.resolve(&arena)?.children()?.count(), 1);
    }
    assert_eq!(
        Stanza::builder_in(
            StanzaType::Iq(IqType::Result),
            StanzaNamespace::Client,
            &mut arena
        )
        .id(Some("result"))?
        .child(query)?
        .child(query)?
        .build()
        .err(),
        Some(BuildError::InvalidIqPayload)
    );
    Stanza::builder_in(
        StanzaType::Iq(IqType::Result),
        StanzaNamespace::Client,
        &mut arena,
    )
    .id(Some("result"))?
    .child(query)?
    .build()?;
    let presence = Stanza::builder_in(
        StanzaType::Presence(PresenceType::Available),
        StanzaNamespace::Client,
        &mut arena,
    )
    .build()?;
    assert_eq!(
        presence.reply_in(&mut arena).err(),
        Some(BuildError::NotIqRequest)
    );
    Ok(())
}

#[test]
fn requires_one_final_error_child_for_error_stanzas() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let condition =
        Element::builder_in("service-unavailable", STANZA_ERROR_NAMESPACE, &mut arena)?.build()?;
    let error = Element::builder_in("error", CLIENT_NAMESPACE, &mut arena)?
        .attribute("type", "", "cancel")?
        .child(condition)?
        .build()?;
    let payload = Element::builder_in("query", "urn:query", &mut arena)?.build()?;
    for stanza_type in [
        StanzaType::Message(MessageType::Error),
        StanzaType::Presence(PresenceType::Error),
        StanzaType::Iq(IqType::Error),
    ] {
        let stanza = Stanza::builder_in(stanza_type, StanzaNamespace::Client, &mut arena)
            .id(Some("error"))?
            .child(payload)?
            .child(error)?
            .build()?;
        assert!(stanza_xml(stanza, &arena)?.contains("type=\"error\""));
        assert_eq!(
            Stanza::builder_in(stanza_type, StanzaNamespace::Client, &mut arena)
                .id(Some("error"))?
                .build()
                .err(),
            Some(BuildError::InvalidErrorPayload)
        );
        assert_eq!(
            Stanza::builder_in(stanza_type, StanzaNamespace::Client, &mut arena)
                .id(Some("error"))?
                .child(error)?
                .child(payload)?
                .build()
                .err(),
            Some(BuildError::InvalidErrorPayload)
        );
        assert_eq!(
            Stanza::builder_in(stanza_type, StanzaNamespace::Client, &mut arena)
                .id(Some("error"))?
                .child(error)?
                .child(error)?
                .build()
                .err(),
            Some(BuildError::InvalidErrorPayload)
        );
    }
    assert_eq!(
        message(&mut arena, error).err(),
        Some(BuildError::InvalidErrorPayload)
    );
    assert_eq!(
        Stanza::builder_in(
            StanzaType::Iq(IqType::Error),
            StanzaNamespace::Client,
            &mut arena
        )
        .id(Some("error"))?
        .child(payload)?
        .child(payload)?
        .child(error)?
        .build()
        .err(),
        Some(BuildError::InvalidIqPayload)
    );
    Ok(())
}

#[test]
fn derives_stanza_errors_without_changing_the_source() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let from = Jid::parse_in("alice@example.com/Phone", &mut arena)?;
    let to = Jid::parse_in("example.com", &mut arena)?;
    let query = Element::builder_in("query", "jabber:iq:private", &mut arena)?.build()?;
    let request = Stanza::builder_in(
        StanzaType::Iq(IqType::Get),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(from))?
    .to(Some(to))?
    .id(Some("request"))?
    .child(query)?
    .build()?;
    let reply = request
        .error_reply_in(&mut arena, StanzaErrorCondition::ServiceUnavailable)?
        .build()?;
    let view = reply.resolve(&arena)?;
    assert_eq!(view.stanza_type(), StanzaType::Iq(IqType::Error));
    assert_eq!(view.id()?, Some("request"));
    assert_eq!(view.from()?.ok_or("from")?.as_str(), "example.com");
    assert_eq!(view.to()?.ok_or("to")?.as_str(), "alice@example.com/Phone");
    let children = view.children()?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(children.len(), 2);
    assert_eq!(children[0].name(), "query");
    assert_eq!(children[0].namespace(), "jabber:iq:private");
    assert_eq!(children[1].name(), "error");
    assert_eq!(children[1].attribute("type", "")?, Some("cancel"));
    let NodeRef::Element(condition) = children[1].children()?.next().ok_or("condition")?? else {
        return Err("condition is not an element".into());
    };
    assert_eq!(condition.name(), "service-unavailable");
    assert_eq!(condition.namespace(), STANZA_ERROR_NAMESPACE);
    assert_eq!(
        request.resolve(&arena)?.stanza_type(),
        StanzaType::Iq(IqType::Get)
    );
    assert_eq!(request.resolve(&arena)?.children()?.count(), 1);
    assert_eq!(
        reply
            .error_reply_in(&mut arena, StanzaErrorCondition::ServiceUnavailable)
            .err(),
        Some(BuildError::InvalidErrorSource)
    );
    let result = request.reply_in(&mut arena)?.build()?;
    assert_eq!(
        result
            .error_reply_in(&mut arena, StanzaErrorCondition::ServiceUnavailable)
            .err(),
        Some(BuildError::InvalidErrorSource)
    );
    Ok(())
}

#[test]
fn derives_message_and_presence_errors() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    for (source_type, error_type) in [
        (
            StanzaType::Message(MessageType::Chat),
            StanzaType::Message(MessageType::Error),
        ),
        (
            StanzaType::Presence(PresenceType::Available),
            StanzaType::Presence(PresenceType::Error),
        ),
    ] {
        let source =
            Stanza::builder_in(source_type, StanzaNamespace::Client, &mut arena).build()?;
        let reply = source
            .error_reply_in(&mut arena, StanzaErrorCondition::InternalServerError)?
            .build()?;
        let view = reply.resolve(&arena)?;
        assert_eq!(view.stanza_type(), error_type);
        let error = view.children()?.next().ok_or("missing error")??;
        assert_eq!(error.attribute("type", "")?, Some("wait"));
        assert_eq!(source.resolve(&arena)?.stanza_type(), source_type);
    }
    Ok(())
}

#[test]
fn validates_server_addresses_and_protects_common_attributes() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let from = Jid::parse_in("alice@example.com", &mut arena)?;
    let to = Jid::parse_in("bob@example.net", &mut arena)?;
    for (from, to) in [(None, None), (Some(from), None), (None, Some(to))] {
        assert_eq!(
            Stanza::builder_in(
                StanzaType::Presence(PresenceType::Available),
                StanzaNamespace::Server,
                &mut arena
            )
            .from(from)?
            .to(to)?
            .build()
            .err(),
            Some(BuildError::MissingServerAddresses)
        );
    }
    let body = Element::builder_in("body", SERVER_NAMESPACE, &mut arena)?
        .text("hello")?
        .build()?;
    let stanza = Stanza::builder_in(
        StanzaType::Message(MessageType::Normal),
        StanzaNamespace::Server,
        &mut arena,
    )
    .from(Some(from))?
    .to(Some(to))?
    .child(body)?
    .build()?;
    assert_eq!(
        stanza_xml(stanza, &arena)?,
        "<message xmlns=\"jabber:server\" from=\"alice@example.com\" to=\"bob@example.net\"><body>hello</body></message>"
    );
    for (name, namespace) in [
        ("from", ""),
        ("to", ""),
        ("id", ""),
        ("type", ""),
        ("xmlns", ""),
        ("lang", XML_NAMESPACE),
    ] {
        assert_eq!(
            stanza
                .derive_in(&mut arena)?
                .attribute(name, namespace, "wrong")
                .err(),
            Some(BuildError::ReservedAttribute)
        );
        assert_eq!(
            stanza
                .derive_in(&mut arena)?
                .remove_attribute(name, namespace)
                .err(),
            Some(BuildError::ReservedAttribute)
        );
    }
    assert_eq!(
        stanza.derive_in(&mut arena)?.id(Some("")).err(),
        Some(BuildError::EmptyId)
    );
    assert_eq!(
        stanza.derive_in(&mut arena)?.id(Some("\0")).err(),
        Some(BuildError::InvalidText)
    );
    assert_eq!(
        stanza.derive_in(&mut arena)?.lang(Some("\0")).err(),
        Some(BuildError::InvalidText)
    );
    Ok(())
}

#[test]
fn rejects_invalid_xml_names_characters_and_namespace_declarations() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    for name in [
        "",
        "1item",
        "prefix:item",
        "a b",
        "a/",
        "a<",
        "\u{b7}bad",
        "\u{f0000}",
    ] {
        assert_eq!(
            Element::builder_in(name, "", &mut arena).err(),
            Some(BuildError::InvalidName),
            "{name:?}"
        );
    }
    for name in ["_item", "é", "項目", "a-b.c", "a\u{300}", "\u{10000}"] {
        Element::builder_in(name, "", &mut arena)?.build()?;
    }
    for text in [
        "\0", "\u{8}", "\u{b}", "\u{c}", "\u{1f}", "\u{fffe}", "\u{ffff}",
    ] {
        assert_eq!(
            Element::builder_in("x", "", &mut arena)?.text(text).err(),
            Some(BuildError::InvalidText)
        );
        assert_eq!(
            Element::builder_in("x", "", &mut arena)?
                .attribute("a", "", text)
                .err(),
            Some(BuildError::InvalidText)
        );
        assert_eq!(
            Element::builder_in("x", text, &mut arena).err(),
            Some(BuildError::InvalidText)
        );
    }
    let xmlns = "http://www.w3.org/2000/xmlns/";
    assert_eq!(
        Element::builder_in("x", xmlns, &mut arena).err(),
        Some(BuildError::InvalidNamespace)
    );
    for (name, namespace) in [("xmlns", ""), ("anything", xmlns)] {
        assert_eq!(
            Element::builder_in("x", "", &mut arena)?
                .attribute(name, namespace, "urn:test")
                .err(),
            Some(BuildError::InvalidNamespace)
        );
    }
    assert_eq!(
        Element::builder_in("x", "", &mut arena)?
            .attribute("xml:lang", "", "en")
            .err(),
        Some(BuildError::InvalidName)
    );
    let valid = Element::builder_in("x", "", &mut arena)?
        .text("\t\n\r\u{20}\u{d7ff}\u{e000}\u{fffd}\u{10000}\u{10ffff}")?
        .build()?;
    element_xml(valid, &arena)?;
    Ok(())
}

#[test]
fn bounds_depth_and_expansion_of_shared_subtrees() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let mut element = Element::builder_in("leaf", "urn:tree", &mut arena)?.build()?;
    for _ in 1..MAX_ELEMENT_DEPTH {
        element = Element::builder_in("node", "urn:tree", &mut arena)?
            .child(element)?
            .build()?;
    }
    element_xml(element, &arena)?;
    assert_eq!(
        Element::builder_in("too-deep", "urn:tree", &mut arena)?
            .child(element)?
            .build()
            .err(),
        Some(BuildError::TreeLimitExceeded)
    );
    assert_eq!(
        message(&mut arena, element).err(),
        Some(BuildError::TreeLimitExceeded)
    );
    let mut shared = Element::builder_in("leaf", "urn:tree", &mut arena)?.build()?;
    for _ in 0..15 {
        shared = Element::builder_in("node", "urn:tree", &mut arena)?
            .child(shared)?
            .child(shared)?
            .build()?;
    }
    assert_eq!(
        Element::builder_in("too-many", "urn:tree", &mut arena)?
            .child(shared)?
            .child(shared)?
            .build()
            .err(),
        Some(BuildError::TreeLimitExceeded)
    );
    assert_eq!(
        Stanza::builder_in(
            StanzaType::Message(MessageType::Normal),
            StanzaNamespace::Client,
            &mut arena
        )
        .child(shared)?
        .child(shared)?
        .build()
        .err(),
        Some(BuildError::TreeLimitExceeded)
    );
    Ok(())
}

struct FailingAllocator {
    fail: Arc<AtomicBool>,
}

// All live blocks retain the global allocator's layout and ownership contracts.
unsafe impl ChunkAllocator for FailingAllocator {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        if self.fail.load(Ordering::Relaxed) {
            Err(AllocationError::Exhausted)
        } else {
            GlobalChunkAllocator.allocate(layout)
        }
    }

    unsafe fn deallocate(&self, chunk: Chunk) {
        // Each block came from the global allocator and is no longer borrowed.
        unsafe { GlobalChunkAllocator.deallocate(chunk) };
    }
}

#[test]
fn allocation_failures_leave_published_values_unchanged() -> TestResult {
    let fail = Arc::new(AtomicBool::new(false));
    let mut arena = Arena::try_new_in(
        ArenaConfig::default(),
        FailingAllocator { fail: fail.clone() },
    )?;
    let element = Element::builder_in("body", CLIENT_NAMESPACE, &mut arena)?
        .attribute("flag", "", "retained")?
        .text("retained")?
        .build()?;
    let source = Stanza::builder_in(
        StanzaType::Message(MessageType::Normal),
        StanzaNamespace::Client,
        &mut arena,
    )
    .child(element)?
    .build()?;
    let expected = stanza_xml(source, &arena)?;
    fail.store(true, Ordering::Relaxed);
    let error = BuildError::Allocation(ArenaError::Allocation(AllocationError::Exhausted));
    assert_eq!(
        source
            .derive_in(&mut arena)?
            .id(Some(&"x".repeat(8192)))
            .err(),
        Some(error)
    );
    assert_eq!(
        element
            .derive_in(&mut arena)?
            .attribute("huge", "", &"x".repeat(8192))
            .err(),
        Some(error)
    );
    assert_eq!(stanza_xml(source, &arena)?, expected);
    while arena.try_alloc(0_u8).is_ok() {}
    assert_eq!(
        element
            .derive_in(&mut arena)?
            .attribute("flag", "", "")
            .err(),
        Some(error)
    );
    assert_eq!(
        element.resolve(&arena)?.attribute("flag", "")?,
        Some("retained")
    );
    assert_eq!(stanza_xml(source, &arena)?, expected);
    let mut full = Arena::try_new(ArenaConfig {
        max_reserved_bytes: NonZeroUsize::new(4096).ok_or("limit")?,
        ..ArenaConfig::default()
    })?;
    while full.try_alloc(0_u8).is_ok() {}
    let limit = BuildError::Allocation(ArenaError::ArenaLimitExceeded);
    assert_eq!(
        source.resolve(&arena)?.clone_in(&mut full).err(),
        Some(limit)
    );
    assert_eq!(
        element.resolve(&arena)?.clone_in(&mut full).err(),
        Some(limit)
    );
    assert_eq!(
        Stanza::builder_in(
            StanzaType::Presence(PresenceType::Available),
            StanzaNamespace::Client,
            &mut full
        )
        .build()
        .err(),
        Some(limit)
    );
    assert!(std::error::Error::source(&limit).is_some());
    assert_eq!(stanza_xml(source, &arena)?, expected);
    Ok(())
}

#[test]
fn frozen_pooled_storage_is_shared_across_threads_and_returned_on_drop() -> TestResult {
    let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
        total_bytes: NonZeroUsize::new(MIN_POOL_SIZE).ok_or("pool size")?,
        ..PoolConfig::default()
    })?);
    let initial = pool.stats();
    let mut arena = Arena::try_new_in(ArenaConfig::default(), pool.clone())?;
    let element = Element::builder_in("body", CLIENT_NAMESPACE, &mut arena)?
        .text("shared")?
        .build()?;
    let stanza = Stanza::builder_in(
        StanzaType::Message(MessageType::Normal),
        StanzaNamespace::Client,
        &mut arena,
    )
    .child(element)?
    .build()?;
    let arena = arena.freeze();
    let mut readers = Vec::new();
    for _ in 0..4 {
        let arena = arena.clone();
        readers.push(std::thread::spawn(move || {
            let mut output = String::new();
            stanza.resolve(&arena)?.write_xml(&mut output)?;
            Ok::<_, WriteError>(output)
        }));
    }
    drop(arena);
    for reader in readers {
        assert_eq!(
            reader.join().map_err(|_| "reader panicked")??,
            "<message xmlns=\"jabber:client\"><body>shared</body></message>"
        );
    }
    let after = pool.stats();
    assert_eq!(after.heap_allocation_count, initial.heap_allocation_count);
    for (before, after) in initial.buckets.iter().zip(after.buckets) {
        assert_eq!(before.available_chunks, after.available_chunks);
    }
    Ok(())
}

struct LimitedWriter {
    remaining: usize,
}

impl fmt::Write for LimitedWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.remaining = self.remaining.checked_sub(text.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}

#[test]
fn writer_propagates_output_failure_and_debug_omits_payloads() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let child = Element::builder_in("secret-element", "urn:secret", &mut arena)?
        .attribute("secret-name", "", "secret-value")?
        .text("secret-body")?
        .build()?;
    let stanza = Stanza::builder_in(
        StanzaType::Message(MessageType::Chat),
        StanzaNamespace::Client,
        &mut arena,
    )
    .id(Some("secret-id"))?
    .child(child)?
    .build()?;
    assert_eq!(
        stanza
            .resolve(&arena)?
            .write_xml(&mut LimitedWriter { remaining: 10 }),
        Err(WriteError::Output(fmt::Error))
    );
    assert_eq!(
        child
            .resolve(&arena)?
            .write_xml(&mut LimitedWriter { remaining: 1 }),
        Err(WriteError::Output(fmt::Error))
    );
    let view = child.resolve(&arena)?;
    let node = view.children()?.next().ok_or("node")??;
    let attribute = view.attributes()?.next().ok_or("attribute")??;
    let debug = format!(
        "{stanza:?} {:?} {child:?} {view:?} {node:?} {attribute:?}",
        stanza.resolve(&arena)?
    );
    assert!(!debug.contains("secret"));
    Ok(())
}
