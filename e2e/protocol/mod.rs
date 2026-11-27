// SPDX-License-Identifier: Apache-2.0

#![expect(
    unreachable_pub,
    reason = "Test targets compile shared fixtures as private modules."
)]
#![expect(
    clippy::disallowed_macros,
    reason = "Integration fixtures report diagnostics on the console."
)]
#![expect(
    clippy::cognitive_complexity,
    reason = "Keep each test scenario and its assertions together."
)]

#[path = "../support/mod.rs"]
mod support;

mod blocking;
mod carbons;
mod core;
mod disco;
mod offline;
mod ping;
mod private;
mod roster;
mod vcard;
mod version;
