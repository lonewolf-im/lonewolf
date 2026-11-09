// SPDX-License-Identifier: Apache-2.0

use std::error::Error as _;
use std::io;
use std::sync::Arc;

use lonewolf_util::arena::ArenaError;
use lonewolf_xmpp::parser::ParseError;
use lonewolf_xmpp::stanza::BuildError;

#[derive(Debug)]
pub(crate) enum ParseFailure<'a> {
    Transport(Option<&'a io::Error>),
    SizeLimit,
    ParserLimit,
    Allocation,
    InvalidNamespace,
    BadNamespacePrefix,
    InvalidXml,
    NotWellFormed,
    RestrictedXml,
    UnsupportedEncoding,
    Other,
}

pub(crate) fn classify_parse_error(error: &ParseError) -> ParseFailure<'_> {
    if error.is_transport_error() {
        let source = if let ParseError::Xml(xml) = error {
            xml.source()
                .and_then(|source| source.downcast_ref::<Arc<io::Error>>())
                .map(AsRef::as_ref)
        } else {
            None
        };
        return ParseFailure::Transport(source);
    }
    match error {
        ParseError::SizeLimitExceeded { .. } => ParseFailure::SizeLimit,
        ParseError::TooManyAttributes
        | ParseError::Build(BuildError::TreeLimitExceeded)
        | ParseError::Build(BuildError::Allocation(ArenaError::ArenaLimitExceeded)) => {
            ParseFailure::ParserLimit
        }
        ParseError::Build(BuildError::Allocation(_)) => ParseFailure::Allocation,
        ParseError::InvalidNamespace => ParseFailure::InvalidNamespace,
        ParseError::BadNamespacePrefix => ParseFailure::BadNamespacePrefix,
        ParseError::InvalidXml => ParseFailure::InvalidXml,
        ParseError::NotWellFormed | ParseError::UnboundNamespacePrefix => {
            ParseFailure::NotWellFormed
        }
        ParseError::RestrictedXml => ParseFailure::RestrictedXml,
        ParseError::UnsupportedEncoding => ParseFailure::UnsupportedEncoding,
        _ => ParseFailure::Other,
    }
}
