// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
    #[arg(
        short,
        long,
        value_name = "PATH",
        help = "Path to the TOML configuration file",
        long_help = "Path to the TOML configuration file. Defaults to ./lonewolf.toml; uses built-in defaults if that file is absent. An explicit path must exist."
    )]
    pub config: Option<PathBuf>,
}
