// SPDX-License-Identifier: Apache-2.0

//! Validates XML local names and escapes text without changing parsed values.

use std::fmt;

use futures_util::io::{AsyncWrite, AsyncWriteExt};

use super::{AsyncWriteError, BuildError};

pub(super) const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

pub(crate) fn validate_name(
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

pub(crate) fn validate_text(text: &str) -> Result<(), BuildError> {
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
        let Some(replacement) = escape_replacement(ch, attribute) else {
            continue;
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

pub(super) async fn escape_async<W: AsyncWrite + Unpin>(
    output: &mut W,
    text: &str,
    attribute: bool,
) -> Result<(), AsyncWriteError> {
    let mut start = 0;
    for (index, ch) in text.char_indices() {
        let Some(replacement) = escape_replacement(ch, attribute) else {
            continue;
        };
        if start < index {
            output.write_all(&text.as_bytes()[start..index]).await?;
        }
        output.write_all(replacement.as_bytes()).await?;
        start = index + ch.len_utf8();
    }
    if start < text.len() {
        output.write_all(&text.as_bytes()[start..]).await?;
    }
    Ok(())
}

fn escape_replacement(ch: char, attribute: bool) -> Option<&'static str> {
    match ch {
        '&' => Some("&amp;"),
        '<' => Some("&lt;"),
        '>' => Some("&gt;"),
        '"' if attribute => Some("&quot;"),
        // Character references bypass XML whitespace normalization.
        '\t' if attribute => Some("&#x9;"),
        '\n' if attribute => Some("&#xA;"),
        '\r' => Some("&#xD;"),
        _ => None,
    }
}

pub(super) async fn attribute_async<W: AsyncWrite + Unpin>(
    output: &mut W,
    name: &str,
    value: &str,
) -> Result<(), AsyncWriteError> {
    output.write_all(b" ").await?;
    output.write_all(name.as_bytes()).await?;
    output.write_all(b"=\"").await?;
    escape_async(output, value, true).await?;
    output.write_all(b"\"").await?;
    Ok(())
}

pub(super) async fn number_async<W: AsyncWrite + Unpin>(
    output: &mut W,
    mut number: usize,
) -> Result<(), AsyncWriteError> {
    let mut digits = [0_u8; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (number % 10) as u8;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    output.write_all(&digits[start..]).await?;
    Ok(())
}
