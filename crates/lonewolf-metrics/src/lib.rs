// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(test, allow(clippy::cognitive_complexity))]

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

mod per_worker;
mod process;
mod server;
#[cfg(test)]
mod test_allocator;

pub use per_worker::PerWorker;
pub use process::ProcessCollector;
pub use server::MetricsServer;
