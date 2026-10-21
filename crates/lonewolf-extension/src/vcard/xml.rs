// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::num::NonZeroUsize;

use lonewolf_storage::StorageErrorKind;
use lonewolf_storage::vcard::{MAX_VCARD_BYTES, VCardQuota};
use lonewolf_util::arena::{Arena, ArenaConfig, ArenaRead, ChunkAllocator, GlobalChunkAllocator};
use lonewolf_xmpp::parser::{ParseError, Parsed, ParserConfig, parse_element};
use lonewolf_xmpp::stanza::{
    BuildError, Element, ElementRef, NodeRef, StanzaErrorCondition, WriteError,
};

use super::{NAMESPACE, failure};
use crate::delivery::HandlerError;
use crate::iq::XmlSpace;

const XML: &str = "http://www.w3.org/XML/1998/namespace";

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
    fn write<R: ArenaRead>(&mut self, element: &ElementRef<'_, R>) -> Result<(), HandlerError> {
        element.write_xml(self).map_err(|error| match error {
            WriteError::Output(_) if self.exceeded => {
                StanzaErrorCondition::ResourceConstraint.into()
            }
            _ => StanzaErrorCondition::InternalServerError.into(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProfileError {
    Invalid,
    Access,
}

fn validate<R: ArenaRead>(root: &ElementRef<'_, R>, detached: bool) -> Result<(), ProfileError> {
    if root.name() != "vCard" || root.namespace() != NAMESPACE {
        return Err(ProfileError::Invalid);
    }
    let lang = root
        .attribute("lang", XML)
        .map_err(|_| ProfileError::Access)?;
    let space = root
        .attribute("space", XML)
        .map_err(|_| ProfileError::Access)?;
    if detached && (lang.is_none() || !matches!(space, Some("default" | "preserve"))) {
        return Err(ProfileError::Invalid);
    }
    for node in root.children().map_err(|_| ProfileError::Access)? {
        if let NodeRef::Text(text) = node.map_err(|_| ProfileError::Access)?
            && !text
                .bytes()
                .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            return Err(ProfileError::Invalid);
        }
    }
    validate_space(root)
}

fn validate_space<R: ArenaRead>(element: &ElementRef<'_, R>) -> Result<(), ProfileError> {
    if let Some(value) = element
        .attribute("space", XML)
        .map_err(|_| ProfileError::Access)?
        && !matches!(value, "default" | "preserve")
    {
        return Err(ProfileError::Invalid);
    }
    for node in element.children().map_err(|_| ProfileError::Access)? {
        if let NodeRef::Element(child) = node.map_err(|_| ProfileError::Access)? {
            validate_space(&child)?;
        }
    }
    Ok(())
}

pub(super) async fn encode<A: ChunkAllocator>(
    payload: &ElementRef<'_, Arena<A>>,
    inherited_lang: Option<&str>,
    inherited_space: Option<XmlSpace>,
    quota: VCardQuota,
    scratch: &mut Arena<A>,
) -> Result<String, HandlerError> {
    if payload.name() != "vCard" || payload.namespace() != NAMESPACE {
        return Err(StanzaErrorCondition::InternalServerError.into());
    }
    validate(payload, false).map_err(|error| match error {
        ProfileError::Invalid => StanzaErrorCondition::BadRequest.into(),
        ProfileError::Access => HandlerError::from(StanzaErrorCondition::InternalServerError),
    })?;
    let root_space = payload
        .attribute("space", XML)
        .map_err(|_| HandlerError::from(StanzaErrorCondition::InternalServerError))?;
    if root_space.is_none() && inherited_space == Some(XmlSpace::Invalid) {
        return Err(StanzaErrorCondition::BadRequest.into());
    }
    let limit = quota.max_bytes.get().min(MAX_VCARD_BYTES);
    let mut output = BoundedOutput {
        bytes: 0,
        limit,
        exceeded: false,
        output: None,
    };
    output.write(payload)?;
    let lang_missing = payload
        .attribute("lang", XML)
        .map_err(|_| HandlerError::from(StanzaErrorCondition::InternalServerError))?
        .is_none();
    output.output = Some(String::with_capacity(output.bytes));
    output.bytes = 0;
    if lang_missing || root_space.is_none() {
        let mut builder = payload.to_builder_in(scratch).map_err(build_error)?;
        if lang_missing {
            builder = builder
                .attribute("lang", XML, inherited_lang.unwrap_or(""))
                .map_err(build_error)?;
        }
        if root_space.is_none() {
            let space = if inherited_space == Some(XmlSpace::Preserve) {
                "preserve"
            } else {
                "default"
            };
            builder = builder
                .attribute("space", XML, space)
                .map_err(build_error)?;
        }
        let detached = builder.build().map_err(build_error)?;
        let element = detached
            .resolve(scratch)
            .map_err(|_| HandlerError::from(StanzaErrorCondition::InternalServerError))?;
        output.write(&element)?;
    } else {
        output.write(payload)?;
    }
    let document = output.output.ok_or(HandlerError::from(
        StanzaErrorCondition::InternalServerError,
    ))?;
    let parsed = parse_stored(&document).await.map_err(|error| {
        if capacity(&error) {
            StanzaErrorCondition::ResourceConstraint.into()
        } else {
            HandlerError::from(StanzaErrorCondition::InternalServerError)
        }
    })?;
    let root = parsed
        .value()
        .resolve(parsed.arena())
        .map_err(|_| HandlerError::from(StanzaErrorCondition::InternalServerError))?;
    validate(&root, true)
        .map_err(|_| HandlerError::from(StanzaErrorCondition::InternalServerError))?;
    Ok(document)
}

pub(super) async fn decode<A: ChunkAllocator>(
    xml: &str,
    response: &mut Arena<A>,
) -> Result<Element, HandlerError> {
    let corrupt = || failure(StorageErrorKind::CorruptData, "vcard_decode");
    let parsed = parse_stored(xml).await.map_err(|_| corrupt())?;
    let root = parsed
        .value()
        .resolve(parsed.arena())
        .map_err(|_| corrupt())?;
    validate(&root, true).map_err(|_| corrupt())?;
    root.clone_in(response).map_err(build_error)
}

async fn parse_stored(xml: &str) -> Result<Parsed<Element, GlobalChunkAllocator>, ParseError> {
    parse_element(
        xml.as_bytes(),
        ParserConfig {
            max_stanza_bytes: const { NonZeroUsize::new(MAX_VCARD_BYTES).unwrap() },
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    )
    .await
}

fn capacity(error: &ParseError) -> bool {
    matches!(
        error,
        ParseError::SizeLimitExceeded { .. }
            | ParseError::TooManyAttributes
            | ParseError::Build(BuildError::Allocation(_) | BuildError::TreeLimitExceeded)
    )
}

fn build_error(error: BuildError) -> HandlerError {
    match error {
        BuildError::Allocation(_) | BuildError::TreeLimitExceeded => {
            StanzaErrorCondition::ResourceConstraint.into()
        }
        _ => StanzaErrorCondition::InternalServerError.into(),
    }
}

#[cfg(test)]
mod output_tests {
    use super::BoundedOutput;
    use std::fmt::Write;

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
