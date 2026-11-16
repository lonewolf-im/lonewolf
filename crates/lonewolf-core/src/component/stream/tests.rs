// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn response_header_has_exact_bytes_and_escaped_domain() -> Result<(), ComponentError> {
    for domain in [None, Some("muc.localhost"), Some("a'&<>\"\n\r\t")] {
        let (xml, id) = response_header_xml(domain)?;
        assert_eq!(id.len(), 32);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let suffix = match domain {
            None => "",
            Some("muc.localhost") => " from='muc.localhost'",
            Some(_) => " from='a&apos;&amp;&lt;>&quot;&#xA;&#xD;&#x9;'",
        };
        assert_eq!(
            xml,
            format!(
                "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:component:accept' id='{id}'{suffix}>"
            )
        );
    }
    Ok(())
}

#[test]
fn parser_errors_keep_the_federation_stream_conditions() {
    for (error, condition) in [
        (
            ParseError::SizeLimitExceeded { limit: 10_000 },
            StreamErrorCondition::PolicyViolation,
        ),
        (
            ParseError::TooManyAttributes,
            StreamErrorCondition::PolicyViolation,
        ),
        (
            ParseError::InvalidNamespace,
            StreamErrorCondition::InvalidNamespace,
        ),
        (
            ParseError::BadNamespacePrefix,
            StreamErrorCondition::BadNamespacePrefix,
        ),
        (ParseError::InvalidXml, StreamErrorCondition::InvalidXml),
        (
            ParseError::NotWellFormed,
            StreamErrorCondition::NotWellFormed,
        ),
        (
            ParseError::RestrictedXml,
            StreamErrorCondition::RestrictedXml,
        ),
        (
            ParseError::UnsupportedEncoding,
            StreamErrorCondition::UnsupportedEncoding,
        ),
        (ParseError::UnexpectedEvent, StreamErrorCondition::BadFormat),
    ] {
        assert_eq!(
            ComponentError::from(error),
            ComponentError::Stream(condition)
        );
    }
}
