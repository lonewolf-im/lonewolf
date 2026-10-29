// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::StanzaNamespace;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn conservative_replies_swap_addresses_preserve_payload_and_never_answer_errors() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        for (xml, bounceable) in [
            ("<message type='chat'><body>body</body></message>", true),
            ("<message/>", true),
            ("<message type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>", false),
            ("<iq type='get' id='get'><query xmlns='urn:test'/></iq>", true),
            ("<iq type='set' id='set'><query xmlns='urn:test'/></iq>", true),
            ("<iq type='result' id='result'/>", false),
            ("<iq type='error' id='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>", false),
            ("<presence type='subscribe'/>", false),
            ("<presence/>", false),
            ("<presence type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>", false),
        ] {
            let (prefix, tail) = xml.split_once('>').ok_or("element")?;
            let insertion = if prefix.ends_with('/') { prefix.trim_end_matches('/') } else { prefix };
            let ending = if prefix.ends_with('/') { "/>" } else { ">" };
            let input = format!("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>{insertion} from='a@peer.test/remote' to='b@local.test/local'{ending}{tail}");
            let mut parser = XmppParser::new(input.as_bytes(), ParserConfig { max_stanza_bytes: std::num::NonZeroUsize::new(65536).ok_or("size")?, arena: ArenaConfig::default() }, GlobalChunkAllocator);
            assert!(matches!(parser.next_event().await?, Some(StreamEvent::StreamStart { .. })));
            let Some(StreamEvent::Stanza(parsed)) = parser.next_event().await? else { return Err(format!("expected stanza: {xml}").into()); };
            let stanza = RoutedStanza::from_parsed(parsed);
            let response = reply(&stanza, GlobalChunkAllocator).map_err(|_| "reply")?;
            assert_eq!(response.is_some(), bounceable, "{xml}");
            if let Some(response) = response {
                let view = response.resolve()?;
                assert_eq!(view.namespace(), StanzaNamespace::Client);
                assert!(view.stanza_type().is_error());
                assert_eq!(view.from()?.ok_or("from")?.as_str(), "b@local.test/local");
                assert_eq!(view.to()?.ok_or("to")?.as_str(), "a@peer.test/remote");
                let mut serialized = String::new();
                view.write_xml(&mut serialized)?;
                assert!(serialized.contains("service-unavailable"));
                if xml.contains("body") { assert_eq!(view.child("body", "jabber:client")?.ok_or("body")?.text()?, Some("body")); }
                if xml.contains("query") { assert!(serialized.contains("urn:test")); }
            }
        }
        Ok(())
    })
}

#[test]
fn domain_fields_omit_literals_and_bound_control_characters() {
    for domain in ["127.0.0.1", "::1", "[::1]", "2001:db8::1", "[2001:db8::1]"] {
        assert_eq!(log_domain(domain), "<literal>");
    }
    assert!(matches!(
        log_domain("peer.test"),
        std::borrow::Cow::Borrowed("peer.test")
    ));
    assert_eq!(log_domain("bad\nname\r"), "bad?name?");
    assert_eq!(log_domain(&"a".repeat(300)).len(), 253);
    assert_eq!(log_domain(&"é".repeat(300)).chars().count(), 253);
}
