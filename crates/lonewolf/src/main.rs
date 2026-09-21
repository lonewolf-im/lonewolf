// SPDX-License-Identifier: Apache-2.0

use std::process::ExitCode;

use clap::Parser;
use lonewolf::config::Config;

mod cli;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    match Config::load(cli.config.as_deref()) {
        Ok(_config) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
