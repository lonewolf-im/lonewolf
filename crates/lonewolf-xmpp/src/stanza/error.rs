// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use lonewolf_util::arena::{Arena, ChunkAllocator};

use super::{
    ApplicationCondition, BuildError, Element, STANZA_ERROR_NAMESPACE, StanzaErrorCondition,
    StanzaNamespace, XML_NAMESPACE,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StanzaErrorText {
    Static(&'static str),
    TwoLimits {
        parts: &'static [&'static str; 3],
        values: [usize; 2],
    },
    Limit {
        prefix: &'static str,
        max: usize,
        suffix: &'static str,
    },
}

impl StanzaErrorCondition {
    pub const fn default_text(self) -> StanzaErrorText {
        StanzaErrorText::Static(match self {
            Self::BadRequest => {
                "The request has an invalid structure or value. Check the request format."
            }
            Self::Conflict => {
                "The request conflicts with the current state. Choose another value or refresh the state."
            }
            Self::Forbidden => "You do not have permission to perform this operation.",
            Self::InternalServerError => {
                "The server could not complete the request. Try again later."
            }
            Self::ItemNotFound => "The requested item is not available.",
            Self::JidMalformed => "An address is invalid. Use a valid XMPP address.",
            Self::NotAcceptable => {
                "A request value exceeds an allowed limit or has an unsupported format."
            }
            Self::NotAllowed => "This operation is not allowed for the requested target.",
            Self::PolicyViolation => {
                "The request violates a server policy. Change the request before retrying."
            }
            Self::RemoteServerNotFound => {
                "The server cannot deliver this request to a remote domain."
            }
            Self::ResourceConstraint => {
                "The server cannot complete this request within its resource limits."
            }
            Self::ServiceUnavailable => {
                "The requested service or operation is unavailable for this target. Check the address and requested feature."
            }
        })
    }
}

pub fn error_element_in<A: ChunkAllocator>(
    namespace: StanzaNamespace,
    condition: StanzaErrorCondition,
    application: Option<ApplicationCondition>,
    text: StanzaErrorText,
    arena: &mut Arena<A>,
) -> Result<Element, BuildError> {
    let defined =
        Element::builder_in(condition.as_str(), STANZA_ERROR_NAMESPACE, arena)?.build()?;
    let mut buffer = std::io::Cursor::new([0u8; 512]);
    let description = match text {
        StanzaErrorText::Static(text) => text,
        StanzaErrorText::TwoLimits {
            parts: [prefix, separator, suffix],
            values: [first, second],
        } => {
            write!(&mut buffer, "{prefix}{first}{separator}{second}{suffix}")
                .map_err(|_| BuildError::InvalidText)?;
            std::str::from_utf8(&buffer.get_ref()[..buffer.position() as usize])
                .map_err(|_| BuildError::InvalidText)?
        }
        StanzaErrorText::Limit {
            prefix,
            max,
            suffix,
        } => {
            write!(&mut buffer, "{prefix}{max}{suffix}").map_err(|_| BuildError::InvalidText)?;
            std::str::from_utf8(&buffer.get_ref()[..buffer.position() as usize])
                .map_err(|_| BuildError::InvalidText)?
        }
    };
    let text = Element::builder_in("text", STANZA_ERROR_NAMESPACE, arena)?
        .attribute("lang", XML_NAMESPACE, "en")?
        .text(description)?
        .build()?;
    let application = application
        .map(|application| {
            Element::builder_in(application.name, application.namespace, arena)?.build()
        })
        .transpose()?;
    let mut error = Element::builder_in("error", namespace.as_str(), arena)?
        .attribute("type", "", condition.error_type())?
        .child(defined)?
        .child(text)?;
    if let Some(application) = application {
        error = error.child(application)?;
    }
    error.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stanza::{IqType, MessageType, NodeRef, PresenceType, Stanza, StanzaType};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn descriptions_use_one_escaped_english_text_with_application_condition_last() -> TestResult {
        for kind in [
            StanzaType::Iq(IqType::Set),
            StanzaType::Message(MessageType::Chat),
            StanzaType::Presence(PresenceType::Subscribe),
        ] {
            let mut arena = Arena::try_new(Default::default())?;
            let payload = Element::builder_in("query", "urn:test", &mut arena)?.build()?;
            let mut source = Stanza::builder_in(kind, StanzaNamespace::Client, &mut arena)
                .lang(Some("es"))?
                .id(Some("test"))?;
            if kind == StanzaType::Iq(IqType::Set) {
                source = source.child(payload)?;
            }
            let source = source.build()?;
            let reply = source
                .error_reply_described_in(
                    &mut arena,
                    StanzaErrorCondition::PolicyViolation,
                    Some(ApplicationCondition {
                        name: "blocked",
                        namespace: "urn:test:policy",
                    }),
                    StanzaErrorText::Static("Use <allowed> values & try again."),
                )?
                .build()?;
            let view = reply.resolve(&arena)?;
            assert_eq!(view.lang()?, Some("es"));
            let error = view.children()?.last().ok_or("missing error")??;
            let children = error.children()?.collect::<Result<Vec<_>, _>>()?;
            assert_eq!(children.len(), 3);
            let [
                NodeRef::Element(condition),
                NodeRef::Element(text),
                NodeRef::Element(application),
            ] = children.as_slice()
            else {
                return Err("unexpected error children".into());
            };
            assert_eq!(
                (condition.name(), condition.namespace()),
                ("policy-violation", STANZA_ERROR_NAMESPACE)
            );
            assert_eq!(
                (text.name(), text.namespace()),
                ("text", STANZA_ERROR_NAMESPACE)
            );
            assert_eq!(text.attribute("lang", XML_NAMESPACE)?, Some("en"));
            assert_eq!(text.text()?, Some("Use <allowed> values & try again."));
            assert_eq!(
                (application.name(), application.namespace()),
                ("blocked", "urn:test:policy")
            );
            let mut xml = String::new();
            view.write_xml(&mut xml)?;
            assert!(xml.contains("Use &lt;allowed&gt; values &amp; try again."));
        }
        Ok(())
    }

    #[test]
    fn numeric_limits_render_exactly_without_unbounded_text() -> TestResult {
        let mut arena = Arena::try_new(Default::default())?;
        let error = error_element_in(
            StanzaNamespace::Client,
            StanzaErrorCondition::ResourceConstraint,
            None,
            StanzaErrorText::Limit {
                prefix: "Limit: ",
                max: usize::MAX,
                suffix: " bytes.",
            },
            &mut arena,
        )?;
        let view = error.resolve(&arena)?;
        let text = view
            .child("text", STANZA_ERROR_NAMESPACE)?
            .ok_or("missing text")?;
        assert_eq!(
            text.text()?,
            Some(format!("Limit: {} bytes.", usize::MAX).as_str())
        );
        let error = error_element_in(
            StanzaNamespace::Client,
            StanzaErrorCondition::ResourceConstraint,
            None,
            StanzaErrorText::TwoLimits {
                parts: &["At most ", " items and ", " bytes."],
                values: [42, 4096],
            },
            &mut arena,
        )?;
        assert_eq!(
            error
                .resolve(&arena)?
                .child("text", STANZA_ERROR_NAMESPACE)?
                .ok_or("text")?
                .text()?,
            Some("At most 42 items and 4096 bytes.")
        );
        const LONG: &str = concat!(
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        );
        assert!(matches!(
            error_element_in(
                StanzaNamespace::Client,
                StanzaErrorCondition::ResourceConstraint,
                None,
                StanzaErrorText::Limit {
                    prefix: LONG,
                    max: 1,
                    suffix: " bytes"
                },
                &mut arena
            ),
            Err(BuildError::InvalidText)
        ));
        Ok(())
    }
}
