// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;

use lonewolf_storage::StorageErrorKind;
use lonewolf_storage::vcard::{MAX_VCARD_BYTES, VCardQuota};
use lonewolf_util::arena::{Arena, ArenaError, ArenaRead, ChunkAllocator};
use lonewolf_xmpp::stanza::{
    BuildError, Element, ElementRef, NodeRef, StanzaErrorCondition, StanzaErrorText,
};

use super::{NAMESPACE, failure};
use crate::delivery::HandlerError;
use crate::detached::{self, EncodeError, Inherited, SpaceError};
use crate::iq::XmlSpace;

const CEILING: NonZeroUsize = NonZeroUsize::new(MAX_VCARD_BYTES).unwrap();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProfileError {
    Invalid,
    Access,
}

fn validate<R: ArenaRead>(root: &ElementRef<'_, R>) -> Result<(), ProfileError> {
    if root.name() != "vCard" || root.namespace() != NAMESPACE {
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
    detached::check_space(root).map_err(|error| match error {
        SpaceError::Invalid => ProfileError::Invalid,
        SpaceError::Access => ProfileError::Access,
    })
}

fn invalid_profile() -> HandlerError {
    HandlerError::described(
        StanzaErrorCondition::BadRequest,
        StanzaErrorText::Static(
            "vCard must contain profile elements without direct text and use valid xml:space values.",
        ),
    )
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
    validate(payload).map_err(|error| match error {
        ProfileError::Invalid => invalid_profile(),
        ProfileError::Access => HandlerError::from(StanzaErrorCondition::InternalServerError),
    })?;
    detached::encode(
        payload,
        Inherited {
            lang: inherited_lang,
            space: inherited_space,
        },
        quota.max_bytes.get(),
        CEILING,
        scratch,
        |root| validate(root).is_ok(),
    )
    .await
    .map_err(|error| match error {
        EncodeError::InvalidSpace => invalid_profile(),
        EncodeError::InheritedSpace => HandlerError::described(
            StanzaErrorCondition::BadRequest,
            StanzaErrorText::Static("vCard must use an xml:space value of default or preserve."),
        ),
        EncodeError::TooLarge { limit } => byte_quota(limit),
        EncodeError::TooManyAttributes => {
            structural("vCard has too many XML attributes. Reduce the profile's XML attributes.")
        }
        EncodeError::Build(error) => build_error(error),
        EncodeError::Internal => StanzaErrorCondition::InternalServerError.into(),
    })
}

pub(super) async fn decode<A: ChunkAllocator>(
    xml: &str,
    response: &mut Arena<A>,
) -> Result<Element, HandlerError> {
    let corrupt = || failure(StorageErrorKind::CorruptData, "vcard_decode");
    let parsed = detached::parse(xml, CEILING).await.map_err(|_| corrupt())?;
    let root = parsed
        .value()
        .resolve(parsed.arena())
        .map_err(|_| corrupt())?;
    validate(&root).map_err(|_| corrupt())?;
    root.clone_in(response).map_err(build_error)
}

pub(super) fn byte_quota(max: usize) -> HandlerError {
    HandlerError::described(
        StanzaErrorCondition::ResourceConstraint,
        StanzaErrorText::Limit {
            prefix: "vCard exceeds the ",
            max,
            suffix: "-byte limit, including XML and Base64 data. Use a smaller avatar or reduce profile data.",
        },
    )
}

fn structural(text: &'static str) -> HandlerError {
    HandlerError::described(
        StanzaErrorCondition::ResourceConstraint,
        StanzaErrorText::Static(text),
    )
}

fn build_error(error: BuildError) -> HandlerError {
    match error {
        BuildError::Allocation(ArenaError::ArenaLimitExceeded | ArenaError::CapacityOverflow) => {
            structural(
                "vCard exceeds the XML processing memory limit. Simplify the profile's XML structure.",
            )
        }
        BuildError::Allocation(_) => StanzaErrorCondition::ResourceConstraint.into(),
        BuildError::TreeLimitExceeded => structural(
            "vCard exceeds the XML tree depth or node limit. Simplify the profile's XML structure.",
        ),
        _ => StanzaErrorCondition::InternalServerError.into(),
    }
}

#[cfg(test)]
mod output_tests {
    use super::build_error;
    use lonewolf_util::arena::{AllocationError, ArenaError};
    use lonewolf_xmpp::stanza::{BuildError, StanzaErrorCondition, StanzaErrorText};

    #[test]
    fn memory_budget_and_allocator_failures_have_distinct_descriptions() {
        for error in [ArenaError::ArenaLimitExceeded, ArenaError::CapacityOverflow] {
            let error = build_error(BuildError::Allocation(error));
            assert_eq!(error.condition(), StanzaErrorCondition::ResourceConstraint);
            assert_eq!(
                error.text(),
                StanzaErrorText::Static(
                    "vCard exceeds the XML processing memory limit. Simplify the profile's XML structure."
                )
            );
        }
        for error in [
            AllocationError::Exhausted,
            AllocationError::UnsupportedLayout,
        ] {
            let error = build_error(BuildError::Allocation(ArenaError::Allocation(error)));
            assert_eq!(error.condition(), StanzaErrorCondition::ResourceConstraint);
            assert_eq!(
                error.text(),
                StanzaErrorCondition::ResourceConstraint.default_text()
            );
            assert!(error.failure().is_none());
        }
    }
}
