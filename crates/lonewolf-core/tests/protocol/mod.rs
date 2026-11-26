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

mod carbons;

mod blocking;

mod component;

mod observers;

mod archive;

mod policy;

mod discovery;

mod ping;

mod private;

mod version;

mod extensions;

mod services;

mod stream;

mod tls_hosts;

mod direct_tls;

mod routing;

mod stanza_rate;

mod offline;

mod roster;

mod presence;

mod authentication;

mod binding;

mod lifecycle;

mod stream_opening;

mod stream_errors;

mod sessions;

mod metrics;

mod vcard;

mod s2s_services;

mod s2s;
