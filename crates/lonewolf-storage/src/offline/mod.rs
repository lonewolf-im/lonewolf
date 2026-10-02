// SPDX-License-Identifier: Apache-2.0

pub mod redb;

use std::error::Error;
use std::fmt;
use std::future::Future;

use crate::StorageError;
use crate::account::AccountKey;

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct OfflineSequence(u64);

impl OfflineSequence {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StoredMessage {
    pub sequence: OfflineSequence,
    /// Seconds since the Unix epoch.
    pub stored_at: u64,
    pub stanza: Box<[u8]>,
}

impl fmt::Debug for StoredMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredMessage")
            .field("sequence", &self.sequence)
            .field("stored_at", &self.stored_at)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum OfflineError {
    /// The owner has no account record.
    NoAccount,
    /// The record exceeds the storage limit or the sequence overflows.
    ValueTooLarge,
    Storage(StorageError),
}

pub trait OfflineReads {
    /// Returns all stored messages in sequence order.
    fn offline_messages(
        &self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<Vec<StoredMessage>, OfflineError>> + Send;

    fn offline_count(
        &self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<usize, OfflineError>> + Send;
}

pub trait OfflineWrites {
    /// Fails with [`OfflineError::NoAccount`] if the owner has no account record.
    fn push_offline_message(
        &mut self,
        owner: &AccountKey,
        stored_at: u64,
        stanza: &[u8],
    ) -> impl Future<Output = Result<OfflineSequence, OfflineError>> + Send;

    /// Removes messages up to and including `through` without resetting the sequence.
    fn remove_offline_messages_through(
        &mut self,
        owner: &AccountKey,
        through: OfflineSequence,
    ) -> impl Future<Output = Result<usize, OfflineError>> + Send;

    fn remove_offline_message(
        &mut self,
        owner: &AccountKey,
        sequence: OfflineSequence,
    ) -> impl Future<Output = Result<bool, OfflineError>> + Send;

    /// Removes all messages and resets the sequence; use only for account deletion.
    fn clear_offline_messages(
        &mut self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<(), OfflineError>> + Send;
}

impl fmt::Display for OfflineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAccount => formatter.write_str("offline message owner has no account"),
            Self::ValueTooLarge => formatter.write_str("offline message value is too large"),
            Self::Storage(error) => write!(formatter, "offline message storage failed: {error}"),
        }
    }
}

impl Error for OfflineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NoAccount | Self::ValueTooLarge => None,
            Self::Storage(error) => Some(error),
        }
    }
}

impl From<StorageError> for OfflineError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[cfg(test)]
mod tests;
