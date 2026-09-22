// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use lonewolf_xmpp::jid::JidRef;

/// Owns a canonical bare JID with a username, independent of its source arena.
///
/// Ordering uses the canonical JID text. [`Debug`](fmt::Debug) omits the JID.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountKey {
    text: Box<str>,
    username_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountKeyError {
    MissingUsername,
    ResourceNotAllowed,
}

impl AccountKey {
    pub fn username(&self) -> &str {
        &self.text[..self.username_len]
    }

    pub fn domain(&self) -> &str {
        &self.text[self.username_len + 1..]
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl TryFrom<JidRef<'_>> for AccountKey {
    type Error = AccountKeyError;

    /// Rejects resources with [`AccountKeyError::ResourceNotAllowed`] and
    /// domain-only JIDs with [`AccountKeyError::MissingUsername`].
    fn try_from(jid: JidRef<'_>) -> Result<Self, Self::Error> {
        if jid.is_full() {
            return Err(AccountKeyError::ResourceNotAllowed);
        }
        let username = jid.localpart().ok_or(AccountKeyError::MissingUsername)?;
        Ok(Self {
            text: Box::from(jid.as_str()),
            username_len: username.len(),
        })
    }
}

impl fmt::Debug for AccountKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("AccountKey").finish_non_exhaustive()
    }
}

impl fmt::Display for AccountKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingUsername => "account username is required",
            Self::ResourceNotAllowed => "account identity must not contain a resource",
        })
    }
}

impl std::error::Error for AccountKeyError {}
