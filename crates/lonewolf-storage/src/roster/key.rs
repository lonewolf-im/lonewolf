// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use lonewolf_xmpp::jid::JidRef;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RosterJid {
    text: Box<str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosterJidError {
    ResourceNotAllowed,
}

impl RosterJid {
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl TryFrom<JidRef<'_>> for RosterJid {
    type Error = RosterJidError;

    /// Accepts domain-only and bare account JIDs.
    fn try_from(jid: JidRef<'_>) -> Result<Self, Self::Error> {
        if jid.is_full() {
            return Err(RosterJidError::ResourceNotAllowed);
        }
        Ok(Self {
            text: Box::from(jid.as_str()),
        })
    }
}

impl fmt::Debug for RosterJid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RosterJid").finish_non_exhaustive()
    }
}

impl fmt::Display for RosterJidError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("roster JID must not contain a resource")
    }
}

impl std::error::Error for RosterJidError {}
