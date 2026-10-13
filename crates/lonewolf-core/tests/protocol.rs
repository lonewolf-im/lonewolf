// SPDX-License-Identifier: Apache-2.0

mod support;

#[path = "protocol/observers.rs"]
mod observers;

#[path = "protocol/archive.rs"]
mod archive;

#[path = "protocol/policy.rs"]
mod policy;

#[path = "protocol/extensions.rs"]
mod extensions;

#[path = "protocol/services.rs"]
mod services;

#[path = "protocol/stream.rs"]
mod stream;

#[path = "protocol/tls_hosts.rs"]
mod tls_hosts;

#[path = "protocol/routing.rs"]
mod routing;

#[path = "protocol/stanza_rate.rs"]
mod stanza_rate;

#[path = "protocol/offline.rs"]
mod offline;

#[path = "protocol/roster/mod.rs"]
mod roster;

#[path = "protocol/presence.rs"]
mod presence;

#[path = "protocol/authentication.rs"]
mod authentication;

#[path = "protocol/binding.rs"]
mod binding;

#[path = "protocol/lifecycle.rs"]
mod lifecycle;

#[path = "protocol/stream_opening.rs"]
mod stream_opening;

#[path = "protocol/stream_errors.rs"]
mod stream_errors;

#[path = "protocol/sessions.rs"]
mod sessions;
