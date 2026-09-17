// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::{self, Write};
use std::net::Ipv6Addr;

use icu_properties::props::{
    ChangesWhenNfkcCasefolded, GeneralCategory, HangulSyllableType, Script,
};
use icu_properties::{CodePointMapData, CodePointSetData};
use idna::uts46::{
    AsciiDenyList, ErrorPolicy, Hyphens, ProcessingSuccess, Uts46, verify_dns_length,
};
use precis_profiles::precis_core::profile::{PrecisFastInvocation, Rules};
use precis_profiles::{OpaqueString, UsernameCaseMapped};

use super::{JidError, JidPart, MAX_PART_LEN, check_length};

// NFC combines at most four scalars. Each input scalar uses at most four UTF-8 bytes.
const MAX_INPUT_PART_LEN: usize = 16 * MAX_PART_LEN;

pub(super) fn localpart(input: &str) -> Result<Cow<'_, str>, JidError> {
    check_input_length(input, JidPart::Localpart)?;
    let output = UsernameCaseMapped::enforce(input)
        .map_err(|_| JidError::InvalidPart(JidPart::Localpart))?;
    if output.contains(['"', '&', '\'', '/', ':', '<', '>', '@']) {
        return Err(JidError::InvalidPart(JidPart::Localpart));
    }
    check_length(&output, JidPart::Localpart)?;
    Ok(output)
}

pub(super) fn resourcepart(input: &str) -> Result<Cow<'_, str>, JidError> {
    check_input_length(input, JidPart::Resourcepart)?;
    let output =
        OpaqueString::enforce(input).map_err(|_| JidError::InvalidPart(JidPart::Resourcepart))?;
    check_length(&output, JidPart::Resourcepart)?;
    Ok(output)
}

pub(super) fn domainpart<'input>(
    input: &'input str,
    ip_buffer: &'input mut [u8; MAX_PART_LEN],
) -> Result<Cow<'input, str>, JidError> {
    let input = input
        .strip_suffix(['.', '\u{3002}', '\u{ff0e}', '\u{ff61}'])
        .unwrap_or(input);
    check_input_length(input, JidPart::Domainpart)?;
    if input.contains(['@', '/']) {
        return Err(JidError::InvalidPart(JidPart::Domainpart));
    }
    if input.starts_with('[') {
        return ip_literal(input, ip_buffer).map(Cow::Borrowed);
    }

    let mapped = if input.contains(['\u{3002}', '\u{ff0e}', '\u{ff61}']) {
        Cow::Owned(input.replace(['\u{3002}', '\u{ff0e}', '\u{ff61}'], "."))
    } else {
        Cow::Borrowed(input)
    };
    let mapped = if mapped.is_ascii() {
        mapped
    } else {
        let profile = UsernameCaseMapped::new();
        profile
            .width_mapping_rule(mapped)
            .and_then(|text| profile.normalization_rule(text))
            .map_err(|_| JidError::InvalidPart(JidPart::Domainpart))?
    };
    // Reject other UTS #46 mappings before they erase disallowed input.
    if !mapped.chars().all(|c| {
        c == '.'
            || valid_idna_character(c)
            || (c.is_uppercase() && c.to_lowercase().all(valid_idna_character))
    }) {
        return Err(JidError::InvalidPart(JidPart::Domainpart));
    }

    let mut unicode = String::new();
    let mut ascii = String::new();
    let output = match Uts46::new()
        .process(
            mapped.as_bytes(),
            AsciiDenyList::STD3,
            Hyphens::Check,
            ErrorPolicy::FailFast,
            |_, _, _| true,
            &mut unicode,
            Some(&mut ascii),
        )
        .map_err(|_| JidError::InvalidPart(JidPart::Domainpart))?
    {
        ProcessingSuccess::Passthrough => mapped,
        ProcessingSuccess::WroteToSink => Cow::Owned(unicode),
    };
    check_length(&output, JidPart::Domainpart)?;
    let dns_name = if ascii.is_empty() {
        output.as_ref()
    } else {
        &ascii
    };
    if !verify_dns_length(dns_name, false) || !output.split('.').all(valid_idna_label) {
        return Err(JidError::InvalidPart(JidPart::Domainpart));
    }
    Ok(output)
}

fn ip_literal<'buffer>(
    input: &str,
    buffer: &'buffer mut [u8; MAX_PART_LEN],
) -> Result<&'buffer str, JidError> {
    let inner = input
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(JidError::InvalidPart(JidPart::Domainpart))?;
    let (address, zone) = inner
        .split_once("%25")
        .map_or((inner, None), |(address, zone)| (address, Some(zone)));
    let address: Ipv6Addr = address
        .parse()
        .map_err(|_| JidError::InvalidPart(JidPart::Domainpart))?;
    if zone.is_some_and(|zone| !valid_zone(zone)) {
        return Err(JidError::InvalidPart(JidPart::Domainpart));
    }
    let mut writer = SliceWriter { buffer, length: 0 };
    write!(writer, "[{address}").map_err(|_| JidError::PartTooLong(JidPart::Domainpart))?;
    if let Some(zone) = zone {
        write!(writer, "%25{zone}").map_err(|_| JidError::PartTooLong(JidPart::Domainpart))?;
    }
    writer
        .write_char(']')
        .map_err(|_| JidError::PartTooLong(JidPart::Domainpart))?;
    let length = writer.length;
    std::str::from_utf8(&buffer[..length]).map_err(|_| JidError::InvalidPart(JidPart::Domainpart))
}

fn valid_zone(zone: &str) -> bool {
    if zone.is_empty() {
        return false;
    }
    let mut bytes = zone.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            if !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
            {
                return false;
            }
        } else if !byte.is_ascii_alphanumeric() && !b"-._~".contains(&byte) {
            return false;
        }
    }
    true
}

// UTS #46 alone permits symbols and omits CONTEXTO checks required by RFC 5892.
fn valid_idna_label(label: &str) -> bool {
    label
        .char_indices()
        .all(|(offset, c)| valid_idna_character(c) && valid_context(label, offset, c))
}

fn valid_idna_character(c: char) -> bool {
    match c {
        'a'..='z'
        | '0'..='9'
        | '-'
        | '\u{00df}'
        | '\u{03c2}'
        | '\u{06fd}'
        | '\u{06fe}'
        | '\u{0f0b}'
        | '\u{3007}'
        | '\u{00b7}'
        | '\u{0375}'
        | '\u{05f3}'
        | '\u{05f4}'
        | '\u{0660}'..='\u{0669}'
        | '\u{06f0}'..='\u{06f9}'
        | '\u{30fb}'
        | '\u{200c}'
        | '\u{200d}' => return true,
        '\u{0640}'
        | '\u{07fa}'
        | '\u{302e}'
        | '\u{302f}'
        | '\u{3031}'..='\u{3035}'
        | '\u{303b}'
        | '\u{20d0}'..='\u{20ff}'
        | '\u{1d100}'..='\u{1d24f}' => return false,
        _ => {}
    }
    if CodePointSetData::new::<ChangesWhenNfkcCasefolded>().contains(c)
        || matches!(
            CodePointMapData::<HangulSyllableType>::new().get(c),
            HangulSyllableType::LeadingJamo
                | HangulSyllableType::VowelJamo
                | HangulSyllableType::TrailingJamo
        )
    {
        return false;
    }
    matches!(
        CodePointMapData::<GeneralCategory>::new().get(c),
        GeneralCategory::LowercaseLetter
            | GeneralCategory::UppercaseLetter
            | GeneralCategory::OtherLetter
            | GeneralCategory::DecimalNumber
            | GeneralCategory::ModifierLetter
            | GeneralCategory::NonspacingMark
            | GeneralCategory::SpacingMark
    )
}

fn valid_context(label: &str, offset: usize, c: char) -> bool {
    let scripts = CodePointMapData::<Script>::new();
    match c {
        '\u{00b7}' => {
            label[..offset].ends_with('l') && label[offset + c.len_utf8()..].starts_with('l')
        }
        '\u{0375}' => label[offset + c.len_utf8()..]
            .chars()
            .next()
            .is_some_and(|next| scripts.get(next) == Script::Greek),
        '\u{05f3}' | '\u{05f4}' => label[..offset]
            .chars()
            .next_back()
            .is_some_and(|previous| scripts.get(previous) == Script::Hebrew),
        '\u{30fb}' => label.chars().any(|c| {
            matches!(
                scripts.get(c),
                Script::Hiragana | Script::Katakana | Script::Han
            )
        }),
        '\u{0660}'..='\u{0669}' => !label.contains(|c| matches!(c, '\u{06f0}'..='\u{06f9}')),
        '\u{06f0}'..='\u{06f9}' => !label.contains(|c| matches!(c, '\u{0660}'..='\u{0669}')),
        _ => true,
    }
}

fn check_input_length(input: &str, part: JidPart) -> Result<(), JidError> {
    if input.is_empty() {
        Err(JidError::EmptyPart(part))
    } else if input.len() > MAX_INPUT_PART_LEN {
        Err(JidError::PartTooLong(part))
    } else {
        Ok(())
    }
}

struct SliceWriter<'buffer> {
    buffer: &'buffer mut [u8],
    length: usize,
}

impl Write for SliceWriter<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.length.checked_add(text.len()).ok_or(fmt::Error)?;
        self.buffer
            .get_mut(self.length..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.length = end;
        Ok(())
    }
}
