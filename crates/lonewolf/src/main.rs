// SPDX-License-Identifier: Apache-2.0

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

use std::process::ExitCode;

use clap::Parser;
use lonewolf_core::BuildInfo;

mod cli;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    let build = BuildInfo {
        version: env!("CARGO_PKG_VERSION"),
        branch: env!("LONEWOLF_GIT_BRANCH"),
        commit: env!("LONEWOLF_GIT_COMMIT"),
    };

    match lonewolf_core::run(cli.config.as_deref(), build) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
