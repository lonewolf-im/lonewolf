// SPDX-License-Identifier: Apache-2.0

//! Verifies client and component credentials; component secrets stay in memory because the handshake needs them.

#![cfg_attr(test, allow(clippy::cognitive_complexity))]

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod component;
pub mod scram;
pub mod server;
