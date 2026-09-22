// SPDX-License-Identifier: Apache-2.0

//! Stores canonical account identities and SCRAM verifiers behind repository
//! contracts with explicit commit outcomes.

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod account;

mod error;
mod redb;

pub use error::{StorageError, StorageErrorKind};
pub use redb::RedbDatabase;
