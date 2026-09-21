// SPDX-License-Identifier: Apache-2.0

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod jid;
pub mod parser;
pub mod stanza;
