// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(test, allow(clippy::cognitive_complexity))]

use clap::Parser;
use lonewolfbench::{
    cli::Cli,
    error::{BenchError, ErrorCode},
};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    if !cfg!(unix) {
        eprintln!(
            "{}",
            BenchError::new(ErrorCode::UnsupportedPlatform, "Unix is required")
        );
        return ExitCode::from(2);
    }
    match cli.execute() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.exit_code())
        }
    }
}
