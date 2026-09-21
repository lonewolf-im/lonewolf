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

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use clap::Parser;

    use super::Cli;

    #[test]
    fn config_paths_preserve_non_utf8_bytes() -> Result<(), clap::Error> {
        let path = OsStr::from_bytes(b"config-\xff.toml");
        let cli = Cli::try_parse_from([OsStr::new("lonewolf"), OsStr::new("--config"), path])?;

        assert_eq!(cli.config.as_deref(), Some(Path::new(path)));
        Ok(())
    }
}
