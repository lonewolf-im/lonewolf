// SPDX-License-Identifier: Apache-2.0

//! Stores server state behind repository contracts with explicit commit outcomes.

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod account;
pub mod roster;

mod error;
mod redb;

pub use error::{StorageError, StorageErrorKind};
pub use redb::RedbDatabase;
