// SPDX-License-Identifier: Apache-2.0

//! Stores server state behind one transaction domain per store.

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod account;
pub mod roster;

mod error;
mod redb;
mod storage;

#[cfg(test)]
mod tests;

pub use error::{StorageError, StorageErrorKind};
pub use redb::{RedbRead, RedbStorage, RedbWrite};
pub use storage::{ReadTransaction, Storage, WriteTransaction};
