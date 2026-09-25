// SPDX-License-Identifier: Apache-2.0

use std::fmt;

pub const STREAM_ERROR_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-streams";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamErrorCondition {
    BadFormat,
    HostUnknown,
    InternalServerError,
    InvalidFrom,
    InvalidNamespace,
    InvalidXml,
    NotAuthorized,
    NotWellFormed,
    PolicyViolation,
    RestrictedXml,
    UnsupportedEncoding,
    UnsupportedStanzaType,
    UnsupportedVersion,
}

impl StreamErrorCondition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadFormat => "bad-format",
            Self::HostUnknown => "host-unknown",
            Self::InternalServerError => "internal-server-error",
            Self::InvalidFrom => "invalid-from",
            Self::InvalidNamespace => "invalid-namespace",
            Self::InvalidXml => "invalid-xml",
            Self::NotAuthorized => "not-authorized",
            Self::NotWellFormed => "not-well-formed",
            Self::PolicyViolation => "policy-violation",
            Self::RestrictedXml => "restricted-xml",
            Self::UnsupportedEncoding => "unsupported-encoding",
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
