// SPDX-License-Identifier: Apache-2.0

use std::process::ExitCode;

use clap::Parser;
use lonewolf::config::Config;
use tracing::Level;
use tracing_appender::non_blocking::NonBlockingBuilder;

mod cli;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    let (writer, logging_guard) = NonBlockingBuilder::default()
        .buffered_lines_limit(1024)
        .lossy(true)
        .finish(std::io::stderr());
    if let Err(error) = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_ansi(false)
        .with_writer(writer)
        .try_init()
    {
        eprintln!("cannot initialize logging: {error}");
        return ExitCode::FAILURE;
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        branch = env!("LONEWOLF_GIT_BRANCH"),
        commit = env!("LONEWOLF_GIT_COMMIT"),
        "lonewolf is starting..."
    );

    match Config::load(cli.config.as_deref()) {
        Ok(_config) => {
            tracing::info!("heading back to the den");
            ExitCode::SUCCESS
        }
        Err(error) => {
            // Flush queued logs so the startup event precedes this diagnostic.
            drop(logging_guard);
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
