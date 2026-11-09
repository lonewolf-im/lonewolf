// SPDX-License-Identifier: Apache-2.0

use compio::runtime::Runtime;
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::parser::{ParserConfig, XmppParser};

use super::super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const HEADER: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>";

fn parser(input: &[u8]) -> XmppParser<std::io::Cursor<Vec<u8>>, GlobalChunkAllocator> {
    XmppParser::new(
        std::io::Cursor::new(input.to_vec()),
        ParserConfig {
            max_stanza_bytes: std::num::NonZeroUsize::new(10_000)
                .unwrap_or(std::num::NonZeroUsize::MIN),
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    )
}

#[test]
fn peer_error_classifier_ignores_text_and_requires_exact_root_namespace() -> TestResult {
    Runtime::new()?.block_on(async {
        for (xml, expected) in [
            ("<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>private</text></stream:error>", Some(StreamErrorCondition::PolicyViolation)),
            ("<stream:error><unsupported-feature xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", Some(StreamErrorCondition::UnsupportedFeature)),
            ("<stream:error><unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", Some(StreamErrorCondition::UndefinedCondition)),
            ("<stream:error/>", Some(StreamErrorCondition::UndefinedCondition)),
            ("<stream:error><bad-format xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", Some(StreamErrorCondition::UndefinedCondition)),
            ("<error xmlns='urn:other'><bad-format xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></error>", None),
        ] {
            let mut input = parser(format!("{HEADER}{xml}").as_bytes());
            input.next_event().await.map_err(|outcome| format!("{outcome:?}"))?;
            let event = input.next_event().await.map_err(|outcome| format!("{outcome:?}"))?.ok_or("missing event")?;
            assert_eq!(peer_stream_error(&event).map_err(|outcome| format!("{outcome:?}"))?, expected);
        }
        Ok(())
    })
}

#[test]
fn attributes_escape_reserved_characters_and_preserve_whitespace() {
    let mut output = String::new();
    escape_attribute(&mut output, "a&<'\"\n\r\t>");
    assert_eq!(output, "a&amp;&lt;&apos;&quot;&#xA;&#xD;&#x9;>");
}

#[test]
fn stream_errors_include_the_condition_and_footer() {
    assert_eq!(
        stream_error_xml(StreamErrorCondition::HostUnknown),
        "<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>"
    );
}

#[test]
fn versions_normalize_digit_strings_without_integer_limits() {
    for (input, expected) in [
        ("1.0", Some(("1", "0"))),
        ("0001.009", Some(("1", "9"))),
        ("0000.000", Some(("0", "0"))),
        ("2.0", Some(("2", "0"))),
        ("12.3", Some(("12", "3"))),
        (
            "999999999999999999999.0",
            Some(("999999999999999999999", "0")),
        ),
        ("", None),
        ("1", None),
        ("1.", None),
        (".0", None),
        ("1.a", None),
        ("1.0.1", None),
        ("+1.0", None),
        ("١.0", None),
    ] {
        assert_eq!(version_components(input), expected, "{input}");
    }
}
