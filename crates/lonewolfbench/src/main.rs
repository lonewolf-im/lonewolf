// SPDX-License-Identifier: Apache-2.0

#![expect(
    clippy::disallowed_macros,
    reason = "The command reports results and errors on the console."
)]

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
