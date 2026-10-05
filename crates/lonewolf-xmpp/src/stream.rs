// SPDX-License-Identifier: Apache-2.0

use std::fmt;

pub const STREAM_ERROR_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-streams";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamErrorCondition {
    BadFormat,
    BadNamespacePrefix,
    Conflict,
    ConnectionTimeout,
    HostGone,
    HostUnknown,
    ImproperAddressing,
    InternalServerError,
    InvalidFrom,
    InvalidNamespace,
    InvalidXml,
    NotAuthorized,
    NotWellFormed,
    PolicyViolation,
    RemoteConnectionFailed,
    Reset,
    ResourceConstraint,
    RestrictedXml,
    SeeOtherHost,
    SystemShutdown,
    UndefinedCondition,
    UnsupportedEncoding,
    UnsupportedFeature,
    UnsupportedStanzaType,
    UnsupportedVersion,
}

impl StreamErrorCondition {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "bad-format" => Self::BadFormat,
            "bad-namespace-prefix" => Self::BadNamespacePrefix,
            "conflict" => Self::Conflict,
            "connection-timeout" => Self::ConnectionTimeout,
            "host-gone" => Self::HostGone,
            "host-unknown" => Self::HostUnknown,
            "improper-addressing" => Self::ImproperAddressing,
            "internal-server-error" => Self::InternalServerError,
            "invalid-from" => Self::InvalidFrom,
            "invalid-namespace" => Self::InvalidNamespace,
            "invalid-xml" => Self::InvalidXml,
            "not-authorized" => Self::NotAuthorized,
            "not-well-formed" => Self::NotWellFormed,
            "policy-violation" => Self::PolicyViolation,
            "remote-connection-failed" => Self::RemoteConnectionFailed,
            "reset" => Self::Reset,
            "resource-constraint" => Self::ResourceConstraint,
            "restricted-xml" => Self::RestrictedXml,
            "see-other-host" => Self::SeeOtherHost,
            "system-shutdown" => Self::SystemShutdown,
            "undefined-condition" => Self::UndefinedCondition,
            "unsupported-encoding" => Self::UnsupportedEncoding,
            "unsupported-feature" => Self::UnsupportedFeature,
            "unsupported-stanza-type" => Self::UnsupportedStanzaType,
            "unsupported-version" => Self::UnsupportedVersion,
            _ => return None,
        })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadFormat => "bad-format",
            Self::BadNamespacePrefix => "bad-namespace-prefix",
            Self::Conflict => "conflict",
            Self::ConnectionTimeout => "connection-timeout",
            Self::HostGone => "host-gone",
            Self::HostUnknown => "host-unknown",
            Self::ImproperAddressing => "improper-addressing",
            Self::InternalServerError => "internal-server-error",
            Self::InvalidFrom => "invalid-from",
            Self::InvalidNamespace => "invalid-namespace",
            Self::InvalidXml => "invalid-xml",
            Self::NotAuthorized => "not-authorized",
            Self::NotWellFormed => "not-well-formed",
            Self::PolicyViolation => "policy-violation",
            Self::RemoteConnectionFailed => "remote-connection-failed",
            Self::Reset => "reset",
            Self::ResourceConstraint => "resource-constraint",
            Self::RestrictedXml => "restricted-xml",
            Self::SeeOtherHost => "see-other-host",
            Self::SystemShutdown => "system-shutdown",
            Self::UndefinedCondition => "undefined-condition",
            Self::UnsupportedEncoding => "unsupported-encoding",
            Self::UnsupportedFeature => "unsupported-feature",
            Self::UnsupportedStanzaType => "unsupported-stanza-type",
            Self::UnsupportedVersion => "unsupported-version",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamError {
    condition: StreamErrorCondition,
}

impl StreamError {
    pub const fn new(condition: StreamErrorCondition) -> Self {
        Self { condition }
    }

    pub const fn condition(self) -> StreamErrorCondition {
        self.condition
    }

    /// The enclosing stream must bind the `stream` prefix to the stream namespace.
    pub fn write_xml(self, output: &mut impl fmt::Write) -> fmt::Result {
        output.write_str("<stream:error><")?;
        output.write_str(self.condition.as_str())?;
        output.write_str(" xmlns='")?;
        output.write_str(STREAM_ERROR_NAMESPACE)?;
        output.write_str("'/></stream:error>")
    }
}

#[cfg(test)]
mod tests;
