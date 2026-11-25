// SPDX-License-Identifier: Apache-2.0

//! Serves the administration API for accounts and federation connections over a private Unix socket.
//! Access relies on socket permissions.

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

mod api;
mod deleter;
mod s2s;
mod server;

pub use deleter::{AccountDeleter, DeleterError, RecordDeleter};
pub use s2s::{S2sConnection, S2sConnections, S2sDirection, S2sTlsMode};
pub use server::Server;
