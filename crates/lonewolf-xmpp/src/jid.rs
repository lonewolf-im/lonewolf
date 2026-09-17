// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::{self, Write};
use std::hash::{Hash, Hasher};
use std::net::Ipv6Addr;
use std::num::NonZeroU16;

use bumpalo::Bump;
use icu_properties::props::{
    ChangesWhenNfkcCasefolded, GeneralCategory, HangulSyllableType, Script,
};
use icu_properties::{CodePointMapData, CodePointSetData};
use idna::uts46::{
    AsciiDenyList, ErrorPolicy, Hyphens, ProcessingSuccess, Uts46, verify_dns_length,
};
use precis_profiles::precis_core::profile::{PrecisFastInvocation, Rules};
use precis_profiles::{OpaqueString, UsernameCaseMapped};

/// Maximum UTF-8 bytes in a component after normalization.
pub const MAX_PART_LEN: usize = 1023;
pub const MAX_JID_LEN: usize = 3 * MAX_PART_LEN + 2;

// NFC combines at most four scalars. Each input scalar uses at most four UTF-8 bytes.
const MAX_INPUT_PART_LEN: usize = 16 * MAX_PART_LEN;

/// Text is normalized under [RFC 7622]. Resourceparts remain case-sensitive.
/// Storage uses the caller's arena. Unicode preparation can allocate temporary heap buffers.
/// Localpart escaping is not automatic.
///
/// [RFC 7622]: https://www.rfc-editor.org/rfc/rfc7622.html
#[derive(Clone)]
pub struct Jid<'arena> {
    text: &'arena str,
    localpart_end: Option<NonZeroU16>,
    resourcepart_start: Option<NonZeroU16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JidPart {
    Localpart,
    Domainpart,
    Resourcepart,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JidError {
    EmptyPart(JidPart),
    PartTooLong(JidPart),
    InvalidPart(JidPart),
    /// Only arena allocation failures are reported.
    AllocationFailed,
}

impl<'arena> Jid<'arena> {
    pub fn parse_in(input: &str, arena: &'arena Bump) -> Result<Self, JidError> {
        let (bare, resourcepart) = input
            .split_once('/')
            .map_or((input, None), |(bare, resource)| (bare, Some(resource)));
        let (localpart, domainpart) = bare
            .split_once('@')
            .map_or((None, bare), |(local, domain)| (Some(local), domain));
        Self::from_parts_in(localpart, domainpart, resourcepart, arena)
    }

    pub fn from_parts_in(
        localpart: Option<&str>,
        domainpart: &str,
        resourcepart: Option<&str>,
        arena: &'arena Bump,
    ) -> Result<Self, JidError> {
        let localpart = localpart.map(prepare_localpart).transpose()?;
        let mut ip_buffer = [0; MAX_PART_LEN];
        let domainpart = prepare_domainpart(domainpart, &mut ip_buffer)?;
        let resourcepart = resourcepart.map(prepare_resourcepart).transpose()?;
        Self::from_trusted_parts_in(
            localpart.as_deref(),
            &domainpart,
            resourcepart.as_deref(),
            arena,
        )
    }

    /// Requires components validated and normalized by this library before storage.
    /// Skips Unicode preparation to reuse trusted stored values.
    pub fn from_trusted_parts_in(
        localpart: Option<&str>,
        domainpart: &str,
        resourcepart: Option<&str>,
        arena: &'arena Bump,
    ) -> Result<Self, JidError> {
        if let Some(localpart) = localpart {
            check_length(localpart, JidPart::Localpart)?;
            if localpart.contains(['@', '/']) {
                return Err(JidError::InvalidPart(JidPart::Localpart));
            }
        }
        check_length(domainpart, JidPart::Domainpart)?;
        if domainpart.contains(['@', '/']) {
            return Err(JidError::InvalidPart(JidPart::Domainpart));
        }
        if let Some(resourcepart) = resourcepart {
            check_length(resourcepart, JidPart::Resourcepart)?;
        }

        let local_len = localpart.map_or(0, str::len);
        let domain_start = localpart.map_or(0, |s| s.len() + 1);
        let bare_len = domain_start + domainpart.len();
        let total_len = bare_len + resourcepart.map_or(0, |s| s.len() + 1);
        let bytes = arena
            .try_alloc_slice_fill_copy(total_len, 0)
            .map_err(|_| JidError::AllocationFailed)?;
        if let Some(localpart) = localpart {
            bytes[..local_len].copy_from_slice(localpart.as_bytes());
            bytes[local_len] = b'@';
        }
        bytes[domain_start..bare_len].copy_from_slice(domainpart.as_bytes());
        if let Some(resourcepart) = resourcepart {
            bytes[bare_len] = b'/';
            bytes[bare_len + 1..].copy_from_slice(resourcepart.as_bytes());
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| JidError::InvalidPart(JidPart::Domainpart))?;
        Ok(Self {
            text,
            localpart_end: NonZeroU16::new(local_len as u16),
            resourcepart_start: resourcepart.and_then(|_| NonZeroU16::new((bare_len + 1) as u16)),
        })
    }

    pub fn localpart(&self) -> Option<&'arena str> {
        self.localpart_end
            .map(|end| &self.text[..usize::from(end.get())])
    }

    pub fn domainpart(&self) -> &'arena str {
        let start = self
            .localpart_end
            .map_or(0, |end| usize::from(end.get()) + 1);
        &self.text[start..self.bare_len()]
    }

    pub fn resourcepart(&self) -> Option<&'arena str> {
        self.resourcepart_start
            .map(|start| &self.text[usize::from(start.get())..])
    }

    pub fn as_str(&self) -> &'arena str {
        self.text
    }

    pub fn is_bare(&self) -> bool {
        self.resourcepart_start.is_none()
    }

    pub fn is_full(&self) -> bool {
        self.resourcepart_start.is_some()
    }

    /// Reuses existing storage without allocation.
    pub fn bare(&self) -> Self {
        Self {
            text: &self.text[..self.bare_len()],
            localpart_end: self.localpart_end,
            resourcepart_start: None,
        }
    }

    pub fn with_resource_in<'target>(
        &self,
        resourcepart: &str,
        arena: &'target Bump,
    ) -> Result<Jid<'target>, JidError> {
        let resourcepart = prepare_resourcepart(resourcepart)?;
        Jid::from_trusted_parts_in(
            self.localpart(),
            self.domainpart(),
            Some(&resourcepart),
            arena,
        )
    }

    /// Only arena allocation failure returns an error.
    pub fn clone_in<'target>(&self, arena: &'target Bump) -> Result<Jid<'target>, JidError> {
        Ok(Jid {
            text: arena
                .try_alloc_str(self.text)
                .map_err(|_| JidError::AllocationFailed)?,
            localpart_end: self.localpart_end,
            resourcepart_start: self.resourcepart_start,
        })
    }

    fn bare_len(&self) -> usize {
        self.resourcepart_start
            .map_or(self.text.len(), |start| usize::from(start.get()) - 1)
    }
}

/// Omit address text to prevent disclosure in logs.
impl fmt::Debug for Jid<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Jid").finish_non_exhaustive()
    }
}

impl fmt::Display for Jid<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text)
    }
}

impl PartialEq for Jid<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl Eq for Jid<'_> {}

impl Hash for Jid<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.text.hash(state);
    }
}

impl fmt::Display for JidError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (part, message) = match self {
            Self::EmptyPart(part) => (part, "must not be empty"),
            Self::PartTooLong(part) => (part, "exceeds the byte limit"),
            Self::InvalidPart(part) => (part, "is invalid"),
            Self::AllocationFailed => return formatter.write_str("JID arena allocation failed"),
        };
        let name = match part {
            JidPart::Localpart => "localpart",
            JidPart::Domainpart => "domainpart",
            JidPart::Resourcepart => "resourcepart",
        };
        write!(formatter, "{name} {message}")
    }
}

impl std::error::Error for JidError {}

fn check_length(text: &str, part: JidPart) -> Result<(), JidError> {
    if text.is_empty() {
        Err(JidError::EmptyPart(part))
    } else if text.len() > MAX_PART_LEN {
        Err(JidError::PartTooLong(part))
    } else {
        Ok(())
    }
}

fn prepare_localpart(input: &str) -> Result<Cow<'_, str>, JidError> {
    check_input_length(input, JidPart::Localpart)?;
    let output = UsernameCaseMapped::enforce(input)
        .map_err(|_| JidError::InvalidPart(JidPart::Localpart))?;
    if output.contains(['"', '&', '\'', '/', ':', '<', '>', '@']) {
        return Err(JidError::InvalidPart(JidPart::Localpart));
    }
    check_length(&output, JidPart::Localpart)?;
    Ok(output)
}

fn prepare_resourcepart(input: &str) -> Result<Cow<'_, str>, JidError> {
    check_input_length(input, JidPart::Resourcepart)?;
    let output =
        OpaqueString::enforce(input).map_err(|_| JidError::InvalidPart(JidPart::Resourcepart))?;
    check_length(&output, JidPart::Resourcepart)?;
    Ok(output)
}

fn prepare_domainpart<'input>(
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
