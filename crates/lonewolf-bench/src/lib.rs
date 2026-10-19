// SPDX-License-Identifier: Apache-2.0

pub mod cli;
pub mod client;
pub mod config;
pub mod error;
pub mod measurement;
pub mod report;

use config::RunConfig;
use error::{BenchError, BenchResult};
use report::RunReport;
use std::path::Path;

pub async fn run(_config: RunConfig, _output: &Path) -> BenchResult<RunReport> {
    Err(BenchError::staged())
}
