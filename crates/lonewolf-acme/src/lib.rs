// SPDX-License-Identifier: Apache-2.0

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod store;
pub mod types;

pub use store::StateStore;
pub use types::{
    CertificateMaterial, ManagedHost, PendingOrder, RetryState, StateError, StoredAccount,
    StoredCertificate, StoredHost,
};
