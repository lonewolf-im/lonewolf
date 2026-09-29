// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use lonewolf_xmpp::jid::JidRef;

use crate::account::AccountKey;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RosterJid {
    text: Box<str>,
}

impl RosterJid {
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl From<JidRef<'_>> for RosterJid {
    fn from(jid: JidRef<'_>) -> Self {
        Self {
            text: Box::from(jid.as_str()),
        }
    }
}

impl From<&AccountKey> for RosterJid {
    fn from(key: &AccountKey) -> Self {
        Self {
            text: Box::from(key.as_str()),
        }
    }
}

impl fmt::Debug for RosterJid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RosterJid").finish_non_exhaustive()
    }
}
