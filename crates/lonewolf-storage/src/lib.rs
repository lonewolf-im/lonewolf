// SPDX-License-Identifier: Apache-2.0

//! Storage traits are internal to this workspace.

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod account;
pub mod blocking;
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

pub use error::{StorageError, StorageErrorKind};
pub use redb::{RedbRead, RedbStorage, RedbWrite};
pub use storage::{ReadTransaction, Storage, WriteTransaction};
