// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn validation_checks_namespace_then_required_addresses_then_sender_domain() -> TestResult {
    let mut arena = Arena::try_new_in(Default::default(), GlobalChunkAllocator)?;
    let from = Jid::parse_in("room@muc.localhost/a", &mut arena)?;
    let foreign = Jid::parse_in("room@other.localhost/a", &mut arena)?;
    let to = Jid::parse_in("alice@localhost/desk", &mut arena)?;
    let from = from.resolve(&arena)?;
    let foreign = foreign.resolve(&arena)?;
    let to = to.resolve(&arena)?;
    for namespace in [StanzaNamespace::Client, StanzaNamespace::Server] {
        assert_eq!(
            validate(namespace, None, None, "muc.localhost"),
            Err(StreamErrorCondition::InvalidNamespace)
        );
    }
    for (from, to) in [(None, Some(to)), (Some(from), None), (None, None)] {
        assert_eq!(
            validate(StanzaNamespace::ComponentAccept, from, to, "muc.localhost"),
            Err(StreamErrorCondition::ImproperAddressing)
        );
    }
    assert_eq!(
        validate(
            StanzaNamespace::ComponentAccept,
            Some(foreign),
            Some(to),
            "muc.localhost"
        ),
        Err(StreamErrorCondition::InvalidFrom)
    );
    assert_eq!(
        validate(
            StanzaNamespace::ComponentAccept,
            Some(from),
            Some(to),
            "muc.localhost"
        ),
        Ok(())
    );
    Ok(())
}

#[test]
fn violation_outcomes_preserve_parser_conditions_as_protocol_errors() {
    for (condition, expected) in [
        (
            StreamErrorCondition::ImproperAddressing,
            StreamClose::ImproperAddressing,
        ),
        (StreamErrorCondition::InvalidFrom, StreamClose::InvalidFrom),
        (
            StreamErrorCondition::InvalidNamespace,
            StreamClose::InvalidNamespace,
        ),
        (
            StreamErrorCondition::UnsupportedStanzaType,
            StreamClose::UnsupportedStanzaType,
        ),
        (
            StreamErrorCondition::InternalServerError,
            StreamClose::InternalError,
        ),
        (
            StreamErrorCondition::PolicyViolation,
            StreamClose::ProtocolError,
        ),
        (
            StreamErrorCondition::NotWellFormed,
            StreamClose::ProtocolError,
        ),
        (
            StreamErrorCondition::RestrictedXml,
            StreamClose::ProtocolError,
        ),
        (StreamErrorCondition::BadFormat, StreamClose::ProtocolError),
        (StreamErrorCondition::InvalidXml, StreamClose::ProtocolError),
        (
            StreamErrorCondition::BadNamespacePrefix,
            StreamClose::ProtocolError,
        ),
        (
            StreamErrorCondition::UnsupportedEncoding,
            StreamClose::ProtocolError,
        ),
    ] {
        assert_eq!(violation_close(condition).as_str(), expected.as_str());
    }
}
