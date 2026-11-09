// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::Arc;

use lonewolf_util::arena::{AllocationError, ArenaError};
use lonewolf_xmpp::parser::ParseError;
use lonewolf_xmpp::stanza::BuildError;

use super::super::parse::{ParseFailure, classify_parse_error};

#[test]
fn classification_preserves_parser_limits_and_distinct_xml_failures() {
    for (error, expected) in [
        (
            ParseError::SizeLimitExceeded { limit: 1 },
            ParseFailure::SizeLimit,
        ),
        (ParseError::TooManyAttributes, ParseFailure::ParserLimit),
        (
            ParseError::Build(BuildError::TreeLimitExceeded),
            ParseFailure::ParserLimit,
        ),
        (
            ParseError::Build(BuildError::Allocation(ArenaError::ArenaLimitExceeded)),
            ParseFailure::ParserLimit,
        ),
        (
            ParseError::Build(BuildError::Allocation(ArenaError::Allocation(
                AllocationError::Exhausted,
            ))),
            ParseFailure::Allocation,
        ),
        (ParseError::InvalidNamespace, ParseFailure::InvalidNamespace),
        (
            ParseError::BadNamespacePrefix,
            ParseFailure::BadNamespacePrefix,
        ),
        (ParseError::InvalidXml, ParseFailure::InvalidXml),
        (ParseError::NotWellFormed, ParseFailure::NotWellFormed),
        (
            ParseError::UnboundNamespacePrefix,
            ParseFailure::NotWellFormed,
        ),
        (ParseError::RestrictedXml, ParseFailure::RestrictedXml),
        (
            ParseError::UnsupportedEncoding,
            ParseFailure::UnsupportedEncoding,
        ),
        (ParseError::UnexpectedEvent, ParseFailure::Other),
        (ParseError::UnexpectedEof, ParseFailure::Other),
        (ParseError::ParserFailed, ParseFailure::Other),
        (
            ParseError::Build(BuildError::InvalidText),
            ParseFailure::Other,
        ),
    ] {
        assert_eq!(
            std::mem::discriminant(&classify_parse_error(&error)),
            std::mem::discriminant(&expected)
        );
    }
}

#[test]
fn classification_borrows_the_original_transport_error() {
    for kind in [io::ErrorKind::TimedOut, io::ErrorKind::BrokenPipe] {
        let source = Arc::new(io::Error::from(kind));
        let error = ParseError::Xml(quick_xml::Error::Io(Arc::clone(&source)));
        let ParseFailure::Transport(Some(actual)) = classify_parse_error(&error) else {
            panic!("missing transport source");
        };
        assert!(std::ptr::eq(actual, source.as_ref()));
        assert_eq!(actual.kind(), kind);
    }
}
