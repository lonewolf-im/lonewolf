// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::hash::{Hash, Hasher};
use std::num::NonZeroU16;

use bumpalo::Bump;

mod prepare;

/// Maximum UTF-8 bytes in a component after normalization.
pub const MAX_PART_LEN: usize = 1023;
pub const MAX_JID_LEN: usize = 3 * MAX_PART_LEN + 2;

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
        let localpart = localpart.map(prepare::localpart).transpose()?;
        let mut ip_buffer = [0; MAX_PART_LEN];
        let domainpart = prepare::domainpart(domainpart, &mut ip_buffer)?;
        let resourcepart = resourcepart.map(prepare::resourcepart).transpose()?;
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
        let resourcepart = prepare::resourcepart(resourcepart)?;
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
