// SPDX-License-Identifier: Apache-2.0

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod challenge;
pub mod crypto;
pub mod http;
mod resolver;
pub mod store;
pub mod transport;
pub mod types;

pub use challenge::{ChallengeError, ChallengeLease, Challenges};
pub use crypto::{crypto_provider, new_certificate_request};
pub use http::Http01Server;
pub use store::StateStore;
pub use transport::{AcmeHttpClient, TransportOptions};
pub use types::{
    AcmeError, AcmeErrorKind, CertificateMaterial, ManagedHost, PendingOrder, RetryState,
    StateError, StoredAccount, StoredCertificate, StoredHost,
};
