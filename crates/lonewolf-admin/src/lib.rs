// SPDX-License-Identifier: Apache-2.0

//! Serves the account administration API over a private Unix socket.
//! Socket permissions control access; requests have no separate authentication.

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

mod api;
mod server;

pub use server::Server;
