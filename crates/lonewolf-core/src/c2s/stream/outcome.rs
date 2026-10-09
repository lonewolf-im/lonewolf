// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::account::AccountKeyError;
use lonewolf_util::arena::{ArenaError, HandleError};
use lonewolf_xmpp::jid::JidError;
use lonewolf_xmpp::parser::ParseError;
use lonewolf_xmpp::stanza::BuildError;
use lonewolf_xmpp::stream::StreamErrorCondition;

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
    ParserError,
    HostUnknown,
    InvalidTo,
    UnsupportedVersion,
    InvalidNamespace,
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
    InternalError,
    TransportError,
}

impl CloseOutcome {
    pub(super) fn from_parse_error(error: &ParseError) -> Self {
        if error.is_transport_error() {
            return Self::TransportError;
        }
        match error {
            ParseError::SizeLimitExceeded { .. } => Self::SizeLimitExceeded,
            ParseError::InvalidNamespace => Self::InvalidNamespace,
            ParseError::InvalidXml => Self::InvalidXml,
            ParseError::UnboundNamespacePrefix => Self::NotWellFormed,
            ParseError::RestrictedXml => Self::RestrictedXml,
            ParseError::UnsupportedEncoding => Self::UnsupportedEncoding,
            ParseError::UnsupportedVersion => Self::UnsupportedVersion,
            _ => Self::ParserError,
        }
    }

    pub(super) fn stream_condition(self) -> Option<StreamErrorCondition> {
        match self {
            Self::SystemShutdown => Some(StreamErrorCondition::SystemShutdown),
            Self::UnsupportedInput => Some(StreamErrorCondition::NotAuthorized),
            Self::SizeLimitExceeded => Some(StreamErrorCondition::PolicyViolation),
            Self::ParserError | Self::InvalidLanguage | Self::InvalidTo => {
                Some(StreamErrorCondition::BadFormat)
            }
            Self::HostUnknown => Some(StreamErrorCondition::HostUnknown),
            Self::UnsupportedVersion => Some(StreamErrorCondition::UnsupportedVersion),
            Self::InvalidNamespace => Some(StreamErrorCondition::InvalidNamespace),
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
            Self::ParserError => "parser_error",
            Self::HostUnknown => "host_unknown",
            Self::InvalidTo => "invalid_to",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidNamespace => "invalid_namespace",
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
            Self::InternalError => "internal_error",
            Self::TransportError => "transport_error",
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
