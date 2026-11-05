// SPDX-License-Identifier: Apache-2.0

//! Stores one element as standalone XML that keeps its language and whitespace context.

use std::fmt;
use std::num::NonZeroUsize;

use lonewolf_util::arena::{Arena, ArenaConfig, ArenaRead, ChunkAllocator, GlobalChunkAllocator};
use lonewolf_xmpp::parser::{ParseError, Parsed, ParserConfig, parse_element};
use lonewolf_xmpp::stanza::{BuildError, Element, ElementRef, NodeRef, WriteError, XML_NAMESPACE};

use crate::iq::XmlSpace;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Inherited<'a> {
    pub(crate) lang: Option<&'a str>,
    pub(crate) space: Option<XmlSpace>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EncodeError {
    InvalidSpace,
    InheritedSpace,
    TooLarge { limit: usize },
    TooManyAttributes,
    Build(BuildError),
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SpaceError {
    Invalid,
    Access,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Corrupt;

struct BoundedOutput {
    bytes: usize,
    limit: usize,
    exceeded: bool,
    output: Option<String>,
}

impl fmt::Write for BoundedOutput {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let Some(bytes) = self
            .bytes
            .checked_add(value.len())
            .filter(|bytes| *bytes <= self.limit)
        else {
            self.exceeded = true;
            return Err(fmt::Error);
        };
        if let Some(output) = &mut self.output {
            output.push_str(value);
        }
        self.bytes = bytes;
        Ok(())
    }
}

impl BoundedOutput {
    fn write<R: ArenaRead>(&mut self, element: &ElementRef<'_, R>) -> Result<(), EncodeError> {
        element.write_xml(self).map_err(|error| match error {
            WriteError::Output(_) if self.exceeded => EncodeError::TooLarge { limit: self.limit },
            _ => EncodeError::Internal,
        })
    }
}

/// Accepts only `default` and `preserve` for every `xml:space` in the subtree.
pub(crate) fn check_space<R: ArenaRead>(element: &ElementRef<'_, R>) -> Result<(), SpaceError> {
    if let Some(value) = element
        .attribute("space", XML_NAMESPACE)
        .map_err(|_| SpaceError::Access)?
        && !matches!(value, "default" | "preserve")
    {
        return Err(SpaceError::Invalid);
    }
    for node in element.children().map_err(|_| SpaceError::Access)? {
        if let NodeRef::Element(child) = node.map_err(|_| SpaceError::Access)? {
            check_space(&child)?;
        }
    }
    Ok(())
}

/// Serializes `element` with explicit root `xml:lang` and `xml:space` values, then proves
/// that [`parse`] accepts the result and that `check` holds for the parsed root.
///
/// The size limit applies before any copy is made and again to the final document.
pub(crate) async fn encode<A: ChunkAllocator>(
    element: &ElementRef<'_, Arena<A>>,
    inherited: Inherited<'_>,
    limit: usize,
    ceiling: NonZeroUsize,
    scratch: &mut Arena<A>,
    check: impl FnOnce(&ElementRef<'_, Arena<GlobalChunkAllocator>>) -> bool,
) -> Result<String, EncodeError> {
    check_space(element).map_err(|error| match error {
        SpaceError::Invalid => EncodeError::InvalidSpace,
        SpaceError::Access => EncodeError::Internal,
    })?;
    let root_space = element
        .attribute("space", XML_NAMESPACE)
        .map_err(|_| EncodeError::Internal)?;
    if root_space.is_none() && inherited.space == Some(XmlSpace::Invalid) {
        return Err(EncodeError::InheritedSpace);
    }
    let mut output = BoundedOutput {
        bytes: 0,
        limit: limit.min(ceiling.get()),
        exceeded: false,
        output: None,
    };
    output.write(element)?;
    let lang_missing = element
        .attribute("lang", XML_NAMESPACE)
        .map_err(|_| EncodeError::Internal)?
        .is_none();
    output.output = Some(String::with_capacity(output.bytes));
    output.bytes = 0;
    if lang_missing || root_space.is_none() {
        let mut builder = element.to_builder_in(scratch).map_err(EncodeError::Build)?;
        if lang_missing {
            builder = builder
                .attribute("lang", XML_NAMESPACE, inherited.lang.unwrap_or(""))
                .map_err(EncodeError::Build)?;
        }
        if root_space.is_none() {
            let space = if inherited.space == Some(XmlSpace::Preserve) {
                "preserve"
            } else {
                "default"
            };
            builder = builder
                .attribute("space", XML_NAMESPACE, space)
                .map_err(EncodeError::Build)?;
        }
        let materialized = builder.build().map_err(EncodeError::Build)?;
        let materialized = materialized
            .resolve(scratch)
            .map_err(|_| EncodeError::Internal)?;
        output.write(&materialized)?;
    } else {
        output.write(element)?;
    }
    let document = output.output.ok_or(EncodeError::Internal)?;
    let parsed = parse_document(&document, ceiling)
        .await
        .map_err(|error| match error {
            ParseError::SizeLimitExceeded { .. } => EncodeError::TooLarge {
                limit: ceiling.get(),
            },
            ParseError::TooManyAttributes => EncodeError::TooManyAttributes,
            ParseError::Build(
                error @ (BuildError::TreeLimitExceeded | BuildError::Allocation(_)),
            ) => EncodeError::Build(error),
            _ => EncodeError::Internal,
        })?;
    let root = parsed
        .value()
        .resolve(parsed.arena())
        .map_err(|_| EncodeError::Internal)?;
    if !has_context(&root) || !check(&root) {
        return Err(EncodeError::Internal);
    }
    Ok(document)
}

/// Parses a document that [`encode`] produced and requires its root context attributes.
pub(crate) async fn parse(
    xml: &str,
    ceiling: NonZeroUsize,
) -> Result<Parsed<Element, GlobalChunkAllocator>, Corrupt> {
    let parsed = parse_document(xml, ceiling).await.map_err(|_| Corrupt)?;
    let root = parsed
        .value()
        .resolve(parsed.arena())
        .map_err(|_| Corrupt)?;
    if !has_context(&root) {
        return Err(Corrupt);
    }
    Ok(parsed)
}

fn has_context<R: ArenaRead>(root: &ElementRef<'_, R>) -> bool {
    matches!(root.attribute("lang", XML_NAMESPACE), Ok(Some(_)))
        && matches!(
            root.attribute("space", XML_NAMESPACE),
            Ok(Some("default" | "preserve"))
        )
        && check_space(root).is_ok()
}

async fn parse_document(
    xml: &str,
    ceiling: NonZeroUsize,
) -> Result<Parsed<Element, GlobalChunkAllocator>, ParseError> {
    parse_element(
        xml.as_bytes(),
        ParserConfig {
            max_stanza_bytes: ceiling,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::BoundedOutput;

    #[test]
    fn checked_length_overflow_rejects_before_append() {
        let mut output = BoundedOutput {
            bytes: usize::MAX,
            limit: usize::MAX,
            exceeded: false,
            output: Some(String::new()),
        };
        assert!(output.write_str("x").is_err());
        assert!(output.exceeded);
        assert_eq!(output.bytes, usize::MAX);
        assert_eq!(output.output.as_deref(), Some(""));
    }
}
