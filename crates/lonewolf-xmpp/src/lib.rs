// SPDX-License-Identifier: Apache-2.0

//! Uses caller-owned arenas for normalized JIDs and immutable XML trees.

#![cfg_attr(test, allow(clippy::cognitive_complexity))]

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod jid;
pub mod parser;
pub mod stanza;
pub mod stream;
