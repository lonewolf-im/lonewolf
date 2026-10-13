// SPDX-License-Identifier: Apache-2.0

use std::error::Error as _;
use std::io;
use std::sync::Arc;

use lonewolf_storage::account::AccountKeyError;
use lonewolf_util::arena::{ArenaError, HandleError};
use lonewolf_xmpp::jid::JidError;
use lonewolf_xmpp::parser::ParseError;
use lonewolf_xmpp::stanza::BuildError;
use lonewolf_xmpp::stream::StreamErrorCondition;

use crate::router::local::RetireCause;
use crate::stages::StageFailure;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CloseOutcome {
    StreamEnd,
    LocalClose,
    PeerError(StreamErrorCondition),
    ClosingTimeout,
    SystemShutdown,
    Eof,
    UnsupportedInput,
    UnsupportedStanzaType,
    SizeLimitExceeded,
    ParserLimitExceeded,
    ParserError,
    HostUnknown,
    InvalidTo,
    UnsupportedVersion,
    InvalidNamespace,
    BadNamespacePrefix,
    InvalidFrom,
    InvalidLanguage,
    InvalidXml,
    NotWellFormed,
    RestrictedXml,
    UnsupportedEncoding,
    StartTlsRejected,
    TlsFailure,
    CertificateInvalid,
    AuthenticationTimeout,
    BindingTimeout,
    BindingAttemptsExceeded,
    EstablishmentTimeout,
    AuthenticationAttemptsExceeded,
    AccountDeleted,
    MailboxOverflow,
    InternalError,
    TransportError,
}

impl CloseOutcome {
    pub(super) fn is_phase_timeout(self) -> bool {
        matches!(
            self,
            Self::EstablishmentTimeout | Self::AuthenticationTimeout | Self::BindingTimeout
        )
    }

    pub(super) fn from_io_error(error: &io::Error) -> Self {
        if super::renegotiation::is_detected(error) {
            Self::TlsFailure
        } else {
            Self::TransportError
        }
    }

    pub(super) fn from_parse_error(error: &ParseError) -> Self {
        if error.is_transport_error() {
            if let ParseError::Xml(xml) = error
                && let Some(error) = xml
                    .source()
                    .and_then(|source| source.downcast_ref::<Arc<io::Error>>())
            {
                return Self::from_io_error(error);
            }
            return Self::TransportError;
        }
        match error {
            ParseError::SizeLimitExceeded { .. } => Self::SizeLimitExceeded,
            ParseError::TooManyAttributes
            | ParseError::Build(BuildError::TreeLimitExceeded)
            | ParseError::Build(BuildError::Allocation(ArenaError::ArenaLimitExceeded)) => {
                Self::ParserLimitExceeded
            }
            ParseError::Build(BuildError::Allocation(_)) => Self::InternalError,
            ParseError::InvalidNamespace => Self::InvalidNamespace,
            ParseError::BadNamespacePrefix => Self::BadNamespacePrefix,
            ParseError::InvalidXml => Self::InvalidXml,
            ParseError::NotWellFormed | ParseError::UnboundNamespacePrefix => Self::NotWellFormed,
            ParseError::RestrictedXml => Self::RestrictedXml,
            ParseError::UnsupportedEncoding => Self::UnsupportedEncoding,
            _ => Self::ParserError,
        }
    }

    pub(super) fn stream_condition(self) -> Option<StreamErrorCondition> {
        match self {
            Self::SystemShutdown => Some(StreamErrorCondition::SystemShutdown),
            Self::UnsupportedInput => Some(StreamErrorCondition::NotAuthorized),
            Self::SizeLimitExceeded => Some(StreamErrorCondition::PolicyViolation),
            Self::EstablishmentTimeout | Self::AuthenticationTimeout | Self::BindingTimeout => {
                Some(StreamErrorCondition::PolicyViolation)
            }
            Self::ParserLimitExceeded => Some(StreamErrorCondition::PolicyViolation),
            Self::ParserError | Self::InvalidLanguage | Self::InvalidTo => {
                Some(StreamErrorCondition::BadFormat)
            }
            Self::HostUnknown => Some(StreamErrorCondition::HostUnknown),
            Self::UnsupportedVersion => Some(StreamErrorCondition::UnsupportedVersion),
            Self::InvalidNamespace => Some(StreamErrorCondition::InvalidNamespace),
            Self::BadNamespacePrefix => Some(StreamErrorCondition::BadNamespacePrefix),
            Self::InvalidFrom => Some(StreamErrorCondition::InvalidFrom),
            Self::InvalidXml => Some(StreamErrorCondition::InvalidXml),
            Self::NotWellFormed => Some(StreamErrorCondition::NotWellFormed),
            Self::RestrictedXml => Some(StreamErrorCondition::RestrictedXml),
            Self::UnsupportedEncoding => Some(StreamErrorCondition::UnsupportedEncoding),
            Self::AuthenticationAttemptsExceeded => Some(StreamErrorCondition::PolicyViolation),
            Self::BindingAttemptsExceeded => Some(StreamErrorCondition::PolicyViolation),
            Self::UnsupportedStanzaType => Some(StreamErrorCondition::UnsupportedStanzaType),
            Self::CertificateInvalid => Some(StreamErrorCondition::Reset),
            Self::AccountDeleted => Some(StreamErrorCondition::NotAuthorized),
            Self::MailboxOverflow => Some(StreamErrorCondition::ResourceConstraint),
            Self::InternalError => Some(StreamErrorCondition::InternalServerError),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::StreamEnd | Self::LocalClose => "stream_end",
            Self::PeerError(_) => "peer_stream_error",
            Self::ClosingTimeout => "closing_timeout",
            Self::SystemShutdown => "system_shutdown",
            Self::Eof => "eof",
            Self::UnsupportedInput => "unsupported_input",
            Self::UnsupportedStanzaType => "unsupported_stanza_type",
            Self::SizeLimitExceeded => "size_limit_exceeded",
            Self::ParserLimitExceeded => "parser_limit_exceeded",
            Self::ParserError => "parser_error",
            Self::HostUnknown => "host_unknown",
            Self::InvalidTo => "invalid_to",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidNamespace => "invalid_namespace",
            Self::BadNamespacePrefix => "bad_namespace_prefix",
            Self::InvalidFrom => "invalid_from",
            Self::InvalidLanguage => "invalid_language",
            Self::InvalidXml => "invalid_xml",
            Self::NotWellFormed => "not_well_formed",
            Self::RestrictedXml => "restricted_xml",
            Self::UnsupportedEncoding => "unsupported_encoding",
            Self::StartTlsRejected => "starttls_rejected",
            Self::TlsFailure => "tls_failure",
            Self::CertificateInvalid => "certificate_invalid",
            Self::AuthenticationTimeout => "authentication_timeout",
            Self::BindingTimeout => "binding_timeout",
            Self::BindingAttemptsExceeded => "binding_attempts_exceeded",
            Self::EstablishmentTimeout => "establishment_timeout",
            Self::AuthenticationAttemptsExceeded => "authentication_attempts_exceeded",
            Self::AccountDeleted => "account_deleted",
            Self::MailboxOverflow => "mailbox_overflow",
            Self::InternalError => "internal_error",
            Self::TransportError => "transport_error",
        }
    }
}

impl From<RetireCause> for CloseOutcome {
    fn from(cause: RetireCause) -> Self {
        match cause {
            RetireCause::MailboxOverflow => Self::MailboxOverflow,
            RetireCause::Evicted | RetireCause::RouterStopped => Self::InternalError,
            RetireCause::AccountDeleted => Self::AccountDeleted,
        }
    }
}

/// Arena, handle, builder and JID failures are server faults, never client errors.
impl From<HandleError> for CloseOutcome {
    fn from(_: HandleError) -> Self {
        Self::InternalError
    }
}

impl From<ArenaError> for CloseOutcome {
    fn from(_: ArenaError) -> Self {
        Self::InternalError
    }
}

impl From<BuildError> for CloseOutcome {
    fn from(_: BuildError) -> Self {
        Self::InternalError
    }
}

impl From<JidError> for CloseOutcome {
    fn from(_: JidError) -> Self {
        Self::InternalError
    }
}

impl From<AccountKeyError> for CloseOutcome {
    fn from(_: AccountKeyError) -> Self {
        Self::InternalError
    }
}

impl From<StageFailure> for CloseOutcome {
    fn from(_: StageFailure) -> Self {
        Self::InternalError
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retirement_causes_preserve_policy_deletion_and_fault_outcomes() {
        for (cause, outcome, condition, name) in [
            (
                RetireCause::MailboxOverflow,
                CloseOutcome::MailboxOverflow,
                StreamErrorCondition::ResourceConstraint,
                "mailbox_overflow",
            ),
            (
                RetireCause::Evicted,
                CloseOutcome::InternalError,
                StreamErrorCondition::InternalServerError,
                "internal_error",
            ),
            (
                RetireCause::RouterStopped,
                CloseOutcome::InternalError,
                StreamErrorCondition::InternalServerError,
                "internal_error",
            ),
            (
                RetireCause::AccountDeleted,
                CloseOutcome::AccountDeleted,
                StreamErrorCondition::NotAuthorized,
                "account_deleted",
            ),
        ] {
            assert_eq!(CloseOutcome::from(cause), outcome);
            assert_eq!(outcome.stream_condition(), Some(condition));
            assert_eq!(outcome.as_str(), name);
            assert!(!outcome.is_phase_timeout());
        }
        assert_eq!(
            super::super::header::stream_error_xml(CloseOutcome::MailboxOverflow).as_deref(),
            Some(
                "<stream:error><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>"
            )
        );
    }

    #[test]
    fn parse_errors_preserve_distinct_close_categories() {
        for (error, outcome) in [
            (ParseError::NotWellFormed, CloseOutcome::NotWellFormed),
            (
                ParseError::UnboundNamespacePrefix,
                CloseOutcome::NotWellFormed,
            ),
            (ParseError::RestrictedXml, CloseOutcome::RestrictedXml),
            (
                ParseError::UnsupportedEncoding,
                CloseOutcome::UnsupportedEncoding,
            ),
            (
                ParseError::SizeLimitExceeded { limit: 1 },
                CloseOutcome::SizeLimitExceeded,
            ),
            (ParseError::InvalidNamespace, CloseOutcome::InvalidNamespace),
            (
                ParseError::BadNamespacePrefix,
                CloseOutcome::BadNamespacePrefix,
            ),
            (ParseError::InvalidXml, CloseOutcome::InvalidXml),
            (ParseError::UnexpectedEvent, CloseOutcome::ParserError),
            (ParseError::UnexpectedEof, CloseOutcome::ParserError),
            (
                ParseError::TooManyAttributes,
                CloseOutcome::ParserLimitExceeded,
            ),
            (
                ParseError::Build(BuildError::InvalidText),
                CloseOutcome::ParserError,
            ),
            (
                ParseError::Build(BuildError::TreeLimitExceeded),
                CloseOutcome::ParserLimitExceeded,
            ),
            (
                ParseError::Build(BuildError::Allocation(ArenaError::ArenaLimitExceeded)),
                CloseOutcome::ParserLimitExceeded,
            ),
            (
                ParseError::Build(BuildError::Allocation(ArenaError::Allocation(
                    lonewolf_util::arena::AllocationError::Exhausted,
                ))),
                CloseOutcome::InternalError,
            ),
            (
                ParseError::from(quick_xml::Error::from(std::io::Error::other("transport"))),
                CloseOutcome::TransportError,
            ),
            (
                ParseError::from(quick_xml::Error::Namespace(
                    quick_xml::name::NamespaceError::UnknownPrefix("p".to_owned()),
                )),
                CloseOutcome::NotWellFormed,
            ),
            (
                ParseError::from(quick_xml::Error::Namespace(
                    quick_xml::name::NamespaceError::InvalidXmlPrefixBind("urn:bad".to_owned()),
                )),
                CloseOutcome::NotWellFormed,
            ),
            (
                ParseError::from(quick_xml::Error::Namespace(
                    quick_xml::name::NamespaceError::InvalidXmlnsPrefixBind("urn:bad".to_owned()),
                )),
                CloseOutcome::NotWellFormed,
            ),
            (
                ParseError::from(quick_xml::Error::Namespace(
                    quick_xml::name::NamespaceError::InvalidPrefixForXml("p".to_owned()),
                )),
                CloseOutcome::NotWellFormed,
            ),
            (
                ParseError::from(quick_xml::Error::Namespace(
                    quick_xml::name::NamespaceError::InvalidPrefixForXmlns("p".to_owned()),
                )),
                CloseOutcome::NotWellFormed,
            ),
            (
                ParseError::from(quick_xml::Error::Namespace(
                    quick_xml::name::NamespaceError::TooManyBindings(1),
                )),
                CloseOutcome::ParserError,
            ),
            (ParseError::ParserFailed, CloseOutcome::ParserError),
        ] {
            assert_eq!(CloseOutcome::from_parse_error(&error), outcome, "{error:?}");
        }
    }

    #[test]
    fn negotiation_timeouts_keep_distinct_log_names_and_share_policy_violation() {
        for (outcome, name) in [
            (CloseOutcome::EstablishmentTimeout, "establishment_timeout"),
            (
                CloseOutcome::AuthenticationTimeout,
                "authentication_timeout",
            ),
            (CloseOutcome::BindingTimeout, "binding_timeout"),
        ] {
            assert_eq!(
                outcome.stream_condition(),
                Some(StreamErrorCondition::PolicyViolation)
            );
            assert_eq!(outcome.as_str(), name);
        }
    }

    #[test]
    fn bad_namespace_prefix_has_a_distinct_stream_condition_and_name() {
        assert_eq!(
            CloseOutcome::BadNamespacePrefix.stream_condition(),
            Some(StreamErrorCondition::BadNamespacePrefix)
        );
        assert_eq!(
            CloseOutcome::BadNamespacePrefix.as_str(),
            "bad_namespace_prefix"
        );
    }

    #[test]
    fn parser_limit_outcome_is_policy_violation_and_has_a_distinct_name() {
        assert_eq!(
            CloseOutcome::ParserLimitExceeded.stream_condition(),
            Some(StreamErrorCondition::PolicyViolation)
        );
        assert_eq!(
            CloseOutcome::ParserLimitExceeded.as_str(),
            "parser_limit_exceeded"
        );
    }
}
