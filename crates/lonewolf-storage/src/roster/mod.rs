// SPDX-License-Identifier: Apache-2.0

pub mod redb;

use std::error::Error;
use std::fmt;
use std::future::Future;

use crate::StorageError;
use crate::account::AccountKey;

mod key;

pub use key::RosterJid;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SubscriptionState {
    #[default]
    None,
    To,
    From,
    Both,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RosterSubscription {
    pub state: SubscriptionState,
    pub pending_out: bool,
    pub approved: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct RosterVersion(u64);

impl RosterVersion {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RosterItem {
    pub jid: RosterJid,
    pub name: Option<Box<str>>,
    pub groups: Vec<Box<str>>,
    pub subscription: RosterSubscription,
}

impl fmt::Debug for RosterItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RosterItem").finish_non_exhaustive()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct RosterSnapshot {
    pub version: RosterVersion,
    pub items: Vec<RosterItem>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RosterMutation<T> {
    pub version: RosterVersion,
    pub value: T,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PendingSubscription {
    pub sender: RosterJid,
    pub stanza: Box<[u8]>,
}

impl fmt::Debug for PendingSubscription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingSubscription")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum RosterError {
    ValueTooLarge,
    /// The owner of the written state has no account record.
    NoAccount,
    Storage(StorageError),
}

/// Roster reads available on any transaction.
pub trait RosterReads {
    /// Reads one consistent roster version and item set.
    fn roster(
        &self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<RosterSnapshot, RosterError>> + Send;

    fn roster_item(
        &self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> impl Future<Output = Result<Option<RosterItem>, RosterError>> + Send;

    /// Returns pending requests in sender order.
    fn pending_requests(
        &self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<Vec<PendingSubscription>, RosterError>> + Send;

    fn pending_request(
        &self,
        owner: &AccountKey,
        sender: &RosterJid,
    ) -> impl Future<Output = Result<Option<PendingSubscription>, RosterError>> + Send;
}

/// Roster writes, each taking effect when the transaction commits.
pub trait RosterWrites {
    /// Stores the item as given, replacing any item for the same JID, and advances the
    /// owner's roster version. Fails with [`RosterError::NoAccount`] when the owner has
    /// no account record, so nothing can be written for a deleted account.
    fn put_roster_item(
        &mut self,
        owner: &AccountKey,
        item: &RosterItem,
    ) -> impl Future<Output = Result<RosterVersion, RosterError>> + Send;

    /// Removes an item and returns `None` without advancing the version if absent.
    fn remove_roster_item(
        &mut self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> impl Future<Output = Result<Option<RosterMutation<RosterItem>>, RosterError>> + Send;

    /// Replaces any pending request from the same sender. Fails with
    /// [`RosterError::NoAccount`] when the owner has no account record.
    fn put_pending_request(
        &mut self,
        owner: &AccountKey,
        request: PendingSubscription,
    ) -> impl Future<Output = Result<(), RosterError>> + Send;

    /// Returns whether a pending request existed.
    fn remove_pending_request(
        &mut self,
        owner: &AccountKey,
        sender: &RosterJid,
    ) -> impl Future<Output = Result<bool, RosterError>> + Send;

    /// Deletes items, pending requests, and the version for one account.
    fn clear_roster(
        &mut self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<(), RosterError>> + Send;
}

impl fmt::Display for RosterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooLarge => formatter.write_str("roster value is too large"),
            Self::NoAccount => formatter.write_str("roster owner has no account"),
            Self::Storage(error) => write!(formatter, "roster storage failed: {error}"),
        }
    }
}

impl Error for RosterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ValueTooLarge | Self::NoAccount => None,
            Self::Storage(error) => Some(error),
        }
    }
}

impl From<StorageError> for RosterError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[cfg(test)]
mod tests;
