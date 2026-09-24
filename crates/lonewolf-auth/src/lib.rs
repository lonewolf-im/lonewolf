// SPDX-License-Identifier: Apache-2.0

//! Derives stored credentials without retaining plaintext passwords.

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod scram;
pub mod server;
