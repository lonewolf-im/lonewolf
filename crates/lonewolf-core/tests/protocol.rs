// SPDX-License-Identifier: Apache-2.0

mod support;

#[path = "protocol/extensions.rs"]
mod extensions;

#[path = "protocol/stream.rs"]
mod stream;

#[path = "protocol/routing.rs"]
mod routing;

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
