// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::future::Future;

use lonewolf_xmpp::jid::JidRef;

use crate::StorageError;
use crate::account::AccountKey;
use crate::roster::RosterJid;

pub(crate) mod redb;

pub const MAX_BLOCKLIST_ITEMS: usize = 1024;

/// Counts serialized item elements, excluding their enclosing stanza and blocklist element.
pub const MAX_BLOCKLIST_ITEM_BYTES: usize = 64 * 1024;

pub enum BlockChange<'a> {
    Block(&'a [RosterJid]),
    Unblock(&'a [RosterJid]),
    Clear,
}

#[derive(Debug, Default)]
pub struct BlockDelta {
    pub inserted: Vec<RosterJid>,
    pub removed: Vec<RosterJid>,
    unchanged: Vec<RosterJid>,
}

impl BlockDelta {
    pub fn before_rules(&self) -> impl Iterator<Item = &RosterJid> {
        self.unchanged.iter().chain(&self.removed)
    }

    pub fn after_rules(&self) -> impl Iterator<Item = &RosterJid> {
        self.unchanged.iter().chain(&self.inserted)
    }
}

#[derive(Debug)]
pub enum BlockError {
    NoAccount,
    QuotaExceeded,
    Storage(StorageError),
}

impl fmt::Display for BlockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAccount => formatter.write_str("blocklist owner has no account"),
            Self::QuotaExceeded => formatter.write_str("blocklist exceeds the account quota"),
            Self::Storage(error) => write!(formatter, "blocklist storage failed: {error}"),
        }
    }
}

impl std::error::Error for BlockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StorageError> for BlockError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

pub trait BlockingReads {
    fn blocklist(
        &self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<Vec<RosterJid>, BlockError>> + Send;

    fn is_blocked(
        &self,
        owner: &AccountKey,
        peer: JidRef<'_>,
    ) -> impl Future<Output = Result<bool, BlockError>> + Send;
}

pub trait BlockingWrites {
    /// Clear can remove an owner's entries after account deletion within the same transaction.
    fn change_blocklist(
        &mut self,
        owner: &AccountKey,
        change: BlockChange<'_>,
    ) -> impl Future<Output = Result<BlockDelta, BlockError>> + Send;
}

#[cfg(test)]
mod tests;
