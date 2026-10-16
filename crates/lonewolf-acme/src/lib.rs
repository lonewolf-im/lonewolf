// SPDX-License-Identifier: Apache-2.0

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod challenge;
pub mod crypto;
pub mod http;
pub mod issuer;
pub mod manager;
mod resolver;
mod schedule;
pub mod store;
pub mod transport;
pub mod types;

pub use challenge::{ChallengeError, ChallengeLease, Challenges};
pub use crypto::{crypto_provider, new_certificate_request};
pub use http::Http01Server;
pub use issuer::Issuer;
pub use manager::{
    FAILURE_KIND_COUNT, HostEvent, HostState, HostStatus, Manager, ManagerError, ManagerOptions,
    StatusHandle,
};
pub use store::StateStore;
pub use transport::{AcmeHttpClient, TransportOptions};
pub use types::{
    AcmeError, AcmeErrorKind, AriWindow, AttemptFailure, AttemptSuccess, CertificateMaterial,
    CertificateValidity, FailureKind, InstallError, Installer, ManagedHost, PendingOrder,
    PreparedInstall, RetryState, StateError, StoredAccount, StoredCertificate, StoredHost,
};
