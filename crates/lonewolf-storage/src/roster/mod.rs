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
    /// Creates a version token for a repository implementation.
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

#[derive(Clone, Eq, PartialEq)]
pub struct RosterItemUpdate {
    pub jid: RosterJid,
    pub name: Option<Box<str>>,
    pub groups: Vec<Box<str>>,
}

impl fmt::Debug for RosterItemUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RosterItemUpdate")
            .finish_non_exhaustive()
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

#[derive(Debug, Eq, PartialEq)]
pub struct PendingResolution {
    pub mutation: Option<RosterMutation<RosterItem>>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SubscriptionRequestOutcome {
    Pending {
        mutation: Option<RosterMutation<RosterItem>>,
    },
    AutoApprove,
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
    Storage(StorageError),
}

pub trait RosterRepository: Send + Sync {
    /// Reads one consistent roster version and item set.
    fn snapshot(
        &self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<RosterSnapshot, RosterError>> + Send;

    /// Returns `None` if the item is absent.
    fn get(
        &self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> impl Future<Output = Result<Option<RosterItem>, RosterError>> + Send;

    /// Replaces user-managed fields while preserving subscription state.
    fn upsert(
        &self,
        owner: &AccountKey,
        item: RosterItemUpdate,
    ) -> impl Future<Output = Result<RosterMutation<RosterItem>, RosterError>> + Send;

    /// Applies `update` in one write, or leaves the roster unchanged on `None`.
    fn update_subscription<F>(
        &self,
        owner: &AccountKey,
        jid: &RosterJid,
        update: F,
    ) -> impl Future<Output = Result<Option<RosterMutation<RosterItem>>, RosterError>> + Send
    where
        F: FnOnce(RosterSubscription) -> Option<RosterSubscription> + Send + 'static;

    /// Stores both sides in one write when approval is required.
    /// Returns `AutoApprove` for an established subscription.
    fn request_subscription(
        &self,
        subscriber: &AccountKey,
        contact: &RosterJid,
        recipient: &AccountKey,
        request: PendingSubscription,
    ) -> impl Future<Output = Result<SubscriptionRequestOutcome, RosterError>> + Send;

    /// Removes an item and returns `None` without advancing the version if absent.
    fn remove(
        &self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> impl Future<Output = Result<Option<RosterMutation<RosterItem>>, RosterError>> + Send;

    /// Replaces any pending request from the same sender.
    fn put_pending(
        &self,
        owner: &AccountKey,
        subscription: PendingSubscription,
    ) -> impl Future<Output = Result<(), RosterError>> + Send;

    /// Returns pending requests in sender order.
    fn pending(
        &self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<Vec<PendingSubscription>, RosterError>> + Send;

    /// Removes a pending request and applies its roster transition in one write.
    fn resolve_pending<F>(
        &self,
        owner: &AccountKey,
        sender: &RosterJid,
        update: F,
    ) -> impl Future<Output = Result<Option<PendingResolution>, RosterError>> + Send
    where
        F: FnOnce(RosterSubscription) -> Option<RosterSubscription> + Send + 'static;

    /// Returns whether a pending request existed.
    fn remove_pending(
        &self,
        owner: &AccountKey,
        sender: &RosterJid,
    ) -> impl Future<Output = Result<bool, RosterError>> + Send;

    /// Removes all roster state for one account.
    fn delete_all(
        &self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<(), RosterError>> + Send;
}

impl fmt::Display for RosterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooLarge => formatter.write_str("roster value is too large"),
            Self::Storage(error) => write!(formatter, "roster storage failed: {error}"),
        }
    }
}

impl Error for RosterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ValueTooLarge => None,
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
