// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::carbons::rules::*;
use crate::observer::MessageRole;
use lonewolf_xmpp::parser::parse_element;
use lonewolf_xmpp::stanza::{CLIENT_NAMESPACE, MessageType, Stanza, StanzaNamespace, StanzaType};

fn check(xml: &str, expected: bool) -> TestResult {
    let message = parse(xml)?;
    for role in [MessageRole::Sent, MessageRole::Received] {
        assert_eq!(
            eligible(&message.resolve()?, role, &owner()?)?,
            expected,
            "{role:?}: {xml}"
        );
    }
    Ok(())
}

#[test]
fn chat_and_bodied_normal_messages_are_eligible() -> TestResult {
    for xml in [
        "<message type='chat'/>",
        "<message type='chat'><body>hi</body></message>",
        "<message type='normal'><body/></message>",
        "<message type='normal'><body>x</body></message>",
        "<message><body/></message>",
        "<message type='unknown'><body/></message>",
        "<message xmlns='jabber:server' from='a@remote' to='alice@localhost'><body/></message>",
    ] {
        check(xml, true)?;
    }
    let (body, mut arena) = block_on(parse_element(
        "<c:body xmlns:c='jabber:client'/>".as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4096).ok_or("zero limit")?,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    ))?
    .into_parts();
    assert_eq!(body.resolve(&arena)?.name(), "body");
    assert_eq!(body.resolve(&arena)?.namespace(), CLIENT_NAMESPACE);
    let stanza = Stanza::builder_in(
        StanzaType::Message(MessageType::Normal),
        StanzaNamespace::Client,
        &mut arena,
    )
    .child(body)?
    .build()?;
    for role in [MessageRole::Sent, MessageRole::Received] {
        assert!(eligible(&stanza.resolve(&arena)?, role, &owner()?)?);
    }
    Ok(())
}

#[test]
fn normal_messages_without_im_payload_are_not_eligible() -> TestResult {
    for xml in [
        "<message/>",
        "<message><body xmlns='other'/></message>",
        "<message><x><body/></x></message>",
        "<message><x><active xmlns='http://jabber.org/protocol/chatstates'/></x></message>",
        "<presence/>",
        "<iq type='get' id='x'><query xmlns='other'/></iq>",
    ] {
        check(xml, false)?;
    }
    Ok(())
}

#[test]
fn im_payloads_make_any_non_groupchat_type_eligible() -> TestResult {
    for (namespace, names) in [
        (RECEIPTS_NAMESPACE, &["request", "received", "unknown"][..]),
        (
            CHAT_STATES_NAMESPACE,
            &[
                "active",
                "composing",
                "paused",
                "inactive",
                "gone",
                "unknown",
            ][..],
        ),
        (
            MARKERS_NAMESPACE,
            &[
                "markable",
                "received",
                "displayed",
                "acknowledged",
                "unknown",
            ][..],
        ),
    ] {
        for name in names {
            for kind in ["normal", "headline"] {
                check(
                    &format!("<message type='{kind}'><p:{name} xmlns:p='{namespace}'/></message>"),
                    true,
                )?;
            }
        }
    }
    Ok(())
}

#[test]
fn groupchat_is_never_eligible() -> TestResult {
    check(
        "<message type='groupchat'><body/><active xmlns='http://jabber.org/protocol/chatstates'/><x xmlns='jabber:x:conference'/></message>",
        false,
    )
}

#[test]
fn private_messages_are_never_eligible() -> TestResult {
    for kind in ["chat", "normal", "error"] {
        let error = if kind == "error" {
            "<error type='cancel'/>"
        } else {
            ""
        };
        check(
            &format!(
                "<message type='{kind}'><body/><p:private xmlns:p='urn:xmpp:carbons:2'/>{error}</message>"
            ),
            false,
        )?;
    }
    check(
        "<message type='chat'><private xmlns='other'/><x><private xmlns='urn:xmpp:carbons:2'/></x></message>",
        true,
    )
}

#[test]
fn no_copy_hints_exclude_non_error_messages() -> TestResult {
    for kind in ["chat", "normal"] {
        check(
            &format!("<message type='{kind}'><body/><no-copy xmlns='urn:xmpp:hints'/></message>"),
            false,
        )?;
    }
    check(
        "<message type='error'><no-copy xmlns='urn:xmpp:hints'/><error type='cancel'/></message>",
        true,
    )?;
    check(
        "<message type='chat'><no-copy xmlns='other'/><x><no-copy xmlns='urn:xmpp:hints'/></x></message>",
        true,
    )
}

#[test]
fn forged_carbons_are_not_eligible() -> TestResult {
    for name in ["sent", "received"] {
        check(
            &format!("<message type='chat'><c:{name} xmlns:c='urn:xmpp:carbons:2'/></message>"),
            false,
        )?;
        check(
            &format!(
                "<message type='chat'><{name} xmlns='other'/><x><{name} xmlns='urn:xmpp:carbons:2'/></x></message>"
            ),
            true,
        )?;
    }
    Ok(())
}

#[test]
fn invitations_are_eligible() -> TestResult {
    check("<message><x xmlns='jabber:x:conference'/></message>", true)?;
    for from in ["room@service", "room@service/nick"] {
        check(
            &format!(
                "<message from='{from}'><m:x xmlns:m='http://jabber.org/protocol/muc#user'><m:invite/></m:x></message>"
            ),
            true,
        )?;
    }
    check(
        "<message><x xmlns='http://jabber.org/protocol/muc#user'><invite xmlns='other'/></x></message>",
        false,
    )?;
    check(
        "<message><x xmlns='http://jabber.org/protocol/muc#user'><nested><invite/></nested></x></message>",
        false,
    )
}

#[test]
fn muc_private_messages_follow_direction() -> TestResult {
    let xml = "<message type='chat' from='room@service/nick' to='room@service/nick'><x xmlns='http://jabber.org/protocol/muc#user'/></message>";
    let message = parse(xml)?;
    assert!(!eligible(
        &message.resolve()?,
        MessageRole::Received,
        &owner()?
    )?);
    assert!(eligible(&message.resolve()?, MessageRole::Sent, &owner()?)?);
    check(
        "<message type='chat' from='room@service'><body/><x xmlns='http://jabber.org/protocol/muc#user'/></message>",
        true,
    )?;
    let message = parse(
        "<message type='chat' from='room@service/nick'><active xmlns='http://jabber.org/protocol/chatstates'/><x xmlns='http://jabber.org/protocol/muc#user'><invite/></x><x xmlns='http://jabber.org/protocol/muc#user'/></message>",
    )?;
    assert!(!eligible(
        &message.resolve()?,
        MessageRole::Received,
        &owner()?
    )?);
    Ok(())
}

#[test]
fn routed_errors_follow_the_documented_rule() -> TestResult {
    for (to, expected) in [
        ("bob@localhost", true),
        ("alice@localhost", false),
        ("alice@localhost/desk", true),
    ] {
        check(
            &format!("<message type='error' to='{to}'><error type='cancel'/></message>"),
            expected,
        )?;
    }
    check(
        "<message type='error'><error type='cancel'/></message>",
        true,
    )?;
    for child in [
        "<x xmlns='http://jabber.org/protocol/muc#user'><invite/></x>",
        "<private xmlns='urn:xmpp:carbons:2'/>",
        "<sent xmlns='urn:xmpp:carbons:2'/>",
        "<received xmlns='urn:xmpp:carbons:2'/>",
    ] {
        check(
            &format!(
                "<message type='error' to='bob@localhost'>{child}<error type='cancel'/></message>"
            ),
            false,
        )?;
    }
    Ok(())
}
