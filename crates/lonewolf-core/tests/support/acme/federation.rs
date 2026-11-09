// SPDX-License-Identifier: Apache-2.0

#[path = "../federation/peer.rs"]
pub mod peer;
#[path = "../federation/pki.rs"]
pub mod pki;

use super::TestResult;
pub use pki::FederationCa;

pub fn phase<T>(name: &'static str, result: TestResult<T>) -> TestResult<T> {
    result.map_err(|error| format!("{name}: {error}").into())
}
