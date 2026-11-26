// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(
    test,
    expect(
        clippy::cognitive_complexity,
        reason = "Keep each test scenario and its assertions together."
    )
)]

pub mod accounts;
pub mod cli;
pub mod client;
pub mod compare;
pub mod config;
pub mod cpu;
pub mod error;
pub mod fixture;
pub mod measurement;
pub mod report;
pub mod run;
pub mod scenario;
pub mod telemetry;

pub use run::run;
