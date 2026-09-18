// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use super::BuildError;

pub(super) const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

pub(super) fn validate_name(
    name: &str,
    namespace: &str,
    attribute: bool,
) -> Result<(), BuildError> {
    let mut chars = name.chars();
    if !chars.next().is_some_and(name_start) || !chars.all(name_char) {
        return Err(BuildError::InvalidName);
    }
    if namespace == XMLNS_NAMESPACE || (attribute && namespace.is_empty() && name == "xmlns") {
        return Err(BuildError::InvalidNamespace);
    }
    validate_text(namespace)
}

fn name_char(ch: char) -> bool {
    name_start(ch)
        || matches!(ch, '-' | '.' | '0'..='9' | '\u{b7}' | '\u{300}'..='\u{36f}' | '\u{203f}'..='\u{2040}')
}

fn name_start(ch: char) -> bool {
    matches!(ch, 'A'..='Z' | '_' | 'a'..='z' | '\u{c0}'..='\u{d6}' | '\u{d8}'..='\u{f6}'
        | '\u{f8}'..='\u{2ff}' | '\u{370}'..='\u{37d}' | '\u{37f}'..='\u{1fff}'
        | '\u{200c}'..='\u{200d}' | '\u{2070}'..='\u{218f}' | '\u{2c00}'..='\u{2fef}'
        | '\u{3001}'..='\u{d7ff}' | '\u{f900}'..='\u{fdcf}' | '\u{fdf0}'..='\u{fffd}'
        | '\u{10000}'..='\u{effff}')
}

pub(super) fn validate_text(text: &str) -> Result<(), BuildError> {
    if text.chars().all(|ch| {
        matches!(ch, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
    }) {
        Ok(())
    } else {
        Err(BuildError::InvalidText)
    }
}

pub(super) fn escape(output: &mut impl fmt::Write, text: &str, attribute: bool) -> fmt::Result {
    let mut start = 0;
    for (index, ch) in text.char_indices() {
        let replacement = match ch {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' if attribute => "&quot;",
            '\t' if attribute => "&#x9;",
            '\n' if attribute => "&#xA;",
            '\r' => "&#xD;",
            _ => continue,
        };
        output.write_str(&text[start..index])?;
        output.write_str(replacement)?;
        start = index + ch.len_utf8();
    }
    output.write_str(&text[start..])
}

pub(super) fn attribute(output: &mut impl fmt::Write, name: &str, value: &str) -> fmt::Result {
    write!(output, " {name}=\"")?;
    escape(output, value, true)?;
    output.write_char('"')
}
