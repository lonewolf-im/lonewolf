// SPDX-License-Identifier: Apache-2.0

pub mod redb;

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;

use crate::StorageError;
use crate::account::AccountKey;

mod key;

pub use key::RosterJid;

/// Bounds XML node metadata independently of stored string bytes.
pub const MAX_GROUPS_PER_ITEM: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterQuota {
    pub max_items: NonZeroUsize,
    /// Includes each encoded owner/contact key and item value.
    pub max_bytes: NonZeroUsize,
}

impl Default for RosterQuota {
    fn default() -> Self {
        Self {
            max_items: const { NonZeroUsize::new(1_000).unwrap() },
            max_bytes: const { NonZeroUsize::new(2_097_152).unwrap() },
        }
    }
}

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
    PendingLimitExceeded,
    QuotaExceeded,
    /// The owner of the written state has no account record.
    NoAccount,
    Storage(StorageError),
}

pub trait RosterReads {
    /// Rejects raw count and byte overflow before decoding each item.
    fn roster(
        &self,
        owner: &AccountKey,
        quota: RosterQuota,
    ) -> impl Future<Output = Result<RosterSnapshot, RosterError>> + Send;

    fn roster_item(
        &self,
        owner: &AccountKey,
        jid: &RosterJid,
        quota: RosterQuota,
    ) -> impl Future<Output = Result<Option<RosterItem>, RosterError>> + Send;

    fn roster_version(
        &self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<RosterVersion, RosterError>> + Send;

    fn roster_subscription(
        &self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> impl Future<Output = Result<Option<RosterSubscription>, RosterError>> + Send;

    /// Returns one header after the exclusive cursor without decoding metadata.
    fn next_roster_subscription(
        &self,
        owner: &AccountKey,
        after: Option<&RosterJid>,
    ) -> impl Future<Output = Result<Option<(RosterJid, RosterSubscription)>, RosterError>> + Send;

    /// Returns one sender after the exclusive cursor without copying its stanza.
    fn next_pending_sender(
        &self,
        owner: &AccountKey,
        after: Option<&RosterJid>,
    ) -> impl Future<Output = Result<Option<RosterJid>, RosterError>> + Send;

    fn pending_request_exists(
        &self,
        owner: &AccountKey,
        sender: &RosterJid,
    ) -> impl Future<Output = Result<bool, RosterError>> + Send;

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
    type Snapshot: crate::ReadTransaction;
    /// Advances the version only after admission; non-growing replacements may recover over-budget accounts.
    fn put_roster_item(
        &mut self,
        owner: &AccountKey,
        item: &RosterItem,
        quota: RosterQuota,
    ) -> impl Future<Output = Result<RosterVersion, RosterError>> + Send;

    /// Rejects a stale source and copies its unchanged metadata without decoding it.
    fn set_roster_subscription(
        &mut self,
        before: &Self::Snapshot,
        owner: &AccountKey,
        jid: &RosterJid,
        subscription: RosterSubscription,
    ) -> impl Future<Output = Result<Option<RosterVersion>, RosterError>> + Send;

    /// Changes only the expected header while preserving the committed metadata bytes.
    fn transition_roster_subscription(
        &mut self,
        owner: &AccountKey,
        jid: &RosterJid,
        expected: RosterSubscription,
        subscription: RosterSubscription,
    ) -> impl Future<Output = Result<Option<RosterVersion>, RosterError>> + Send;

    /// Removes legacy rows without decoding metadata or applying snapshot quotas.
    fn remove_roster_subscription(
        &mut self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> impl Future<Output = Result<Option<RosterMutation<RosterSubscription>>, RosterError>> + Send;

    /// Removes an item and returns `None` without advancing the version if absent.
    fn remove_roster_item(
        &mut self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> impl Future<Output = Result<Option<RosterMutation<RosterItem>>, RosterError>> + Send;

    /// Replaces existing senders even at the limit; rejects new senders at capacity.
    /// Returns [`RosterError::NoAccount`] for owners without an account.
    fn put_pending_request(
        &mut self,
        owner: &AccountKey,
        request: PendingSubscription,
        max_pending_subscription_requests: NonZeroUsize,
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
            Self::QuotaExceeded => formatter.write_str("roster quota exceeded"),
            Self::ValueTooLarge => formatter.write_str("roster value is too large"),
            Self::NoAccount => formatter.write_str("roster owner has no account"),
            Self::PendingLimitExceeded => {
                formatter.write_str("pending subscription request limit reached")
            }
            Self::Storage(error) => write!(formatter, "roster storage failed: {error}"),
        }
    }
}

impl Error for RosterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ValueTooLarge
            | Self::NoAccount
            | Self::PendingLimitExceeded
            | Self::QuotaExceeded => None,
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
