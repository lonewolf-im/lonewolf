// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use lonewolf_xmpp::stream::{STREAM_ERROR_NAMESPACE, StreamError, StreamErrorCondition};

#[test]
fn stream_error_conditions_write_their_protocol_names() -> fmt::Result {
    for (condition, name) in [
        (StreamErrorCondition::BadFormat, "bad-format"),
        (StreamErrorCondition::HostUnknown, "host-unknown"),
        (
            StreamErrorCondition::InternalServerError,
            "internal-server-error",
        ),
        (StreamErrorCondition::InvalidFrom, "invalid-from"),
        (StreamErrorCondition::InvalidNamespace, "invalid-namespace"),
        (StreamErrorCondition::InvalidXml, "invalid-xml"),
        (StreamErrorCondition::NotAuthorized, "not-authorized"),
        (StreamErrorCondition::NotWellFormed, "not-well-formed"),
        (StreamErrorCondition::PolicyViolation, "policy-violation"),
        (StreamErrorCondition::RestrictedXml, "restricted-xml"),
        (
            StreamErrorCondition::UnsupportedEncoding,
            "unsupported-encoding",
        ),
        (
            StreamErrorCondition::UnsupportedStanzaType,
            "unsupported-stanza-type",
        ),
        (
            StreamErrorCondition::UnsupportedVersion,
            "unsupported-version",
        ),
    ] {
        let error = StreamError::new(condition);
        assert_eq!(error.condition(), condition);
        let mut xml = String::new();
        error.write_xml(&mut xml)?;
        assert_eq!(
            xml,
            format!("<stream:error><{name} xmlns='{STREAM_ERROR_NAMESPACE}'/></stream:error>")
        );
    }
    Ok(())
}

struct RejectingWriter;

impl fmt::Write for RejectingWriter {
    fn write_str(&mut self, _: &str) -> fmt::Result {
        Err(fmt::Error)
    }
}

#[test]
fn stream_error_propagates_output_failure() {
    let error = StreamError::new(StreamErrorCondition::BadFormat);
    assert_eq!(error.write_xml(&mut RejectingWriter), Err(fmt::Error));
}
