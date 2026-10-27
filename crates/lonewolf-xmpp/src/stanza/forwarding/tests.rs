// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ArenaConfig, HandleError};

use super::build_in;
use crate::jid::Jid;
use crate::stanza::{
    BuildError, CLIENT_NAMESPACE, Element, IqType, MessageType, PresenceType, Stanza,
    StanzaNamespace, StanzaType,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn xml(element: Element, arena: &Arena) -> Result<String, Box<dyn std::error::Error>> {
    let mut output = String::new();
    element.resolve(arena)?.write_xml(&mut output)?;
    Ok(output)
}

#[test]
fn forwarded_stanzas_preserve_namespaces_and_share_content() -> TestResult {
    for namespace in [StanzaNamespace::Client, StanzaNamespace::Server] {
        for kind in [
            StanzaType::Message(MessageType::Chat),
            StanzaType::Presence(PresenceType::Available),
            StanzaType::Iq(IqType::Result),
        ] {
            let mut source = Arena::try_new(ArenaConfig::default())?;
            let from = Jid::parse_in("alice@example.org/desk", &mut source)?;
            let to = Jid::parse_in("bob@example.net/phone", &mut source)?;
            let payload = Element::builder_in("payload", "urn:opaque", &mut source)?
                .text("a<&")?
                .build()?;
            let stanza = Stanza::builder_in(kind, namespace, &mut source)
                .from(Some(from))?
                .to(Some(to))?
                .id(Some("original"))?
                .lang(Some("en"))?
                .child(payload)?
                .build()?;
            let mut arena = Arena::try_new(ArenaConfig::default())?;
            let inner = stanza.resolve(&source)?.to_element_in(&mut arena)?;
            drop(source);
            let original_xml = xml(inner, &arena)?;
            let forwarded = build_in(inner, None, &mut arena)?;
            let shared = forwarded
                .resolve(&arena)?
                .child(kind.kind().as_str(), namespace.as_str())?
                .ok_or("forwarded stanza")?;
            assert!(std::ptr::eq(
                shared.attribute("id", "")?.ok_or("shared ID")?.as_ptr(),
                inner
                    .resolve(&arena)?
                    .attribute("id", "")?
                    .ok_or("original ID")?
                    .as_ptr(),
            ));
            assert_eq!(
                xml(forwarded, &arena)?,
                format!("<forwarded xmlns=\"urn:xmpp:forward:0\">{original_xml}</forwarded>")
            );
            assert_eq!(xml(inner, &arena)?, original_xml);
        }
    }
    Ok(())
}

#[test]
fn forwarding_delay_precedes_the_stanza_and_preserves_its_own_delay() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let original_delay = Element::builder_in("delay", "urn:xmpp:delay", &mut arena)?
        .attribute("stamp", "", "2026-10-26T12:00:00Z")?
        .build()?;
    let inner = Element::builder_in("message", CLIENT_NAMESPACE, &mut arena)?
        .child(original_delay)?
        .build()?;
    let delay = Element::builder_in("delay", "urn:xmpp:delay", &mut arena)?
        .attribute("stamp", "", "2026-10-27T12:00:00Z")?
        .attribute("from", "", "example.org")?
        .text("Archived")?
        .build()?;
    let forwarded = build_in(inner, Some(delay), &mut arena)?;
    assert_eq!(
        xml(forwarded, &arena)?,
        concat!(
            "<forwarded xmlns=\"urn:xmpp:forward:0\">",
            "<delay xmlns=\"urn:xmpp:delay\" stamp=\"2026-10-27T12:00:00Z\" from=\"example.org\">Archived</delay>",
            "<message xmlns=\"jabber:client\">",
            "<delay xmlns=\"urn:xmpp:delay\" stamp=\"2026-10-26T12:00:00Z\"/>",
            "</message></forwarded>",
        )
    );
    Ok(())
}

#[test]
fn forwarded_elements_must_belong_to_the_destination_arena() -> TestResult {
    let mut source = Arena::try_new(ArenaConfig::default())?;
    let mut destination = Arena::try_new(ArenaConfig::default())?;
    let foreign = Element::builder_in("message", CLIENT_NAMESPACE, &mut source)?.build()?;
    assert!(matches!(
        build_in(foreign, None, &mut destination),
        Err(BuildError::Access(HandleError::WrongArena))
    ));
    let inner = Element::builder_in("message", CLIENT_NAMESPACE, &mut destination)?.build()?;
    let foreign_delay = Element::builder_in("delay", "urn:xmpp:delay", &mut source)?
        .attribute("stamp", "", "2026-10-27T12:00:00Z")?
        .build()?;
    assert!(matches!(
        build_in(inner, Some(foreign_delay), &mut destination),
        Err(BuildError::Access(HandleError::WrongArena))
    ));
    Ok(())
}
