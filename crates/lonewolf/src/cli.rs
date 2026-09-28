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
    use lonewolf_core::config::DEFAULT_CONFIG_PATH;

    use super::Cli;

    #[test]
    fn help_and_version_succeed_without_loading_configuration()
    -> Result<(), Box<dyn std::error::Error>> {
        for flag in ["--help", "--version"] {
            let error = Cli::try_parse_from(["lonewolf", "--config", "missing.conf", flag])
                .err()
                .ok_or("help or version was not handled")?;
            assert_eq!(error.exit_code(), 0);
            assert!(!error.use_stderr());
            let output = error.to_string();
            assert!(output.contains("lonewolf"));
            if flag == "--help" {
                assert!(output.contains("--config <PATH>"));
                assert!(output.contains("TOML configuration file"));
                assert!(output.contains(DEFAULT_CONFIG_PATH));
                assert!(output.starts_with("A modern and highly efficient XMPP server\n"));
            }
        }
        Ok(())
    }

    #[test]
    fn invalid_arguments_return_usage_errors() -> Result<(), Box<dyn std::error::Error>> {
        for argument in ["--config", "--unknown", "unexpected"] {
            let error = Cli::try_parse_from(["lonewolf", argument])
                .err()
                .ok_or("invalid arguments were accepted")?;
            assert_eq!(error.exit_code(), 2);
            assert!(error.use_stderr());
            assert!(!error.to_string().is_empty());
        }
        Ok(())
    }

    #[test]
    fn config_paths_preserve_non_utf8_bytes() -> Result<(), clap::Error> {
        let path = OsStr::from_bytes(b"config-\xff.toml");
        let cli = Cli::try_parse_from([OsStr::new("lonewolf"), OsStr::new("--config"), path])?;

        assert_eq!(cli.config.as_deref(), Some(Path::new(path)));
        Ok(())
    }
}
