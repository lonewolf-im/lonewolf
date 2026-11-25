// SPDX-License-Identifier: Apache-2.0

//! Storage traits are internal to this workspace.

#![cfg_attr(test, allow(clippy::cognitive_complexity))]

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod account;
pub mod blocking;
pub mod cache;
pub mod metrics;
pub mod offline;
pub mod page;
pub mod private;
pub mod roster;
pub mod vcard;

mod error;
mod redb;
mod storage;

#[cfg(test)]
mod tests;

pub use cache::{CachedRead, CachedStorage, CachedWrite};
pub use error::{StorageError, StorageErrorKind};
pub use redb::{RedbBackend, RedbBackendRead, RedbBackendWrite};
pub use storage::{CommitObserver, ReadTransaction, Storage, WriteTransaction};

pub type RedbStorage = CachedStorage<RedbBackend>;
pub type RedbRead = CachedRead<RedbBackendRead>;
pub type RedbWrite = CachedWrite<RedbBackendWrite>;
