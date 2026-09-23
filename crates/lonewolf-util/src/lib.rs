// SPDX-License-Identifier: Apache-2.0

//! Provides bounded storage and execution primitives for Unix services.

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

pub mod arena;
pub mod blocking;
pub mod core_dispatcher;
pub mod pool;
pub mod rate_limited_reader;
