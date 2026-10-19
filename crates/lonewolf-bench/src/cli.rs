// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::{RunConfig, absolute_path, validate_new_output},
    error::{BenchError, BenchResult, ErrorCode},
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        server_binary: Option<PathBuf>,
    },
    Accounts {
        #[command(subcommand)]
        command: AccountsCommand,
    },
    Compare {
        baseline_dir: PathBuf,
        candidate_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum AccountsCommand {
    Generate {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        prefix: String,
        #[arg(long)]
        count: usize,
        #[arg(long)]
        output: PathBuf,
    },
    Provision {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        credentials: PathBuf,
    },
}

impl Cli {
    pub fn execute(self) -> BenchResult<u8> {
        match self.command {
            Command::Run {
                config,
                output,
                server_binary,
            } => {
                let config = RunConfig::load(&config, server_binary.as_deref())?;
                let cwd = std::env::current_dir().map_err(|_| {
                    BenchError::new(ErrorCode::InvalidPath, "working directory is unavailable")
                })?;
                let output = absolute_path(&cwd, &output)?;
                validate_new_output(&output)?;
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(config.measurement.driver_workers)
                    .enable_all()
                    .build()
                    .map_err(|_| {
                        BenchError::new(ErrorCode::Runtime, "cannot construct driver runtime")
                    })?;
                let report = runtime.block_on(crate::run(config, &output))?;
                println!("{:?}", report.status);
                Ok(report.status.exit_code())
            }
            Command::Accounts {
                command:
                    AccountsCommand::Generate {
                        domain,
                        prefix,
                        count,
                        output,
                    },
            } => {
                crate::accounts::generate_credentials(&domain, &prefix, count, &output).map(|()| 0)
            }
            Command::Compare { output, .. } => {
                validate_new_output(&output)?;
                Err(BenchError::staged())
            }
            Command::Accounts {
                command:
                    AccountsCommand::Provision {
                        socket,
                        credentials,
                    },
            } => {
                let result = (|| {
                    let credentials =
                        crate::accounts::CredentialSet::read(&credentials, None, None)?;
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| {
                            BenchError::new(
                                ErrorCode::Runtime,
                                "cannot construct provisioning runtime",
                            )
                        })?;
                    runtime.block_on(crate::accounts::provision_accounts(&socket, &credentials))
                })();
                let summary = result.map_err(|error| {
                    let summary = error.provision_summary().unwrap_or_default();
                    error.with_provision_summary(summary)
                })?;
                println!(
                    "confirmed_created={}; uncertain_last_create={}",
                    summary.confirmed_created, summary.uncertain_last_create
                );
                Ok(0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_and_version_do_not_load_configuration() {
        for flag in ["--help", "--version"] {
            let result = Cli::try_parse_from(["lonewolf-bench", flag]);
            assert!(matches!(result, Err(error) if error.exit_code() == 0));
        }
        assert!(
            Cli::try_parse_from([
                "lonewolf-bench",
                "run",
                "--config",
                "missing",
                "--output",
                "new",
                "--help"
            ])
            .is_err_and(|error| error.exit_code() == 0)
        );
    }

    #[test]
    fn commands_are_explicit_and_reject_unrequested_options() {
        for args in [
            vec![
                "run",
                "--config",
                "x",
                "--output",
                "y",
                "--server-binary",
                "server",
            ],
            vec![
                "accounts",
                "generate",
                "--domain",
                "localhost",
                "--prefix",
                "a",
                "--count",
                "10",
                "--output",
                "x",
            ],
            vec![
                "accounts",
                "provision",
                "--socket",
                "x",
                "--credentials",
                "y",
            ],
            vec!["compare", "baseline", "candidate", "--output", "result"],
        ] {
            assert!(Cli::try_parse_from(std::iter::once("bench").chain(args)).is_ok());
        }
        for option in [
            "--password",
            "--insecure",
            "--admin-url",
            "--server-command",
        ] {
            assert!(Cli::try_parse_from(["bench", "run", option]).is_err());
        }
    }

    #[test]
    fn staged_commands_return_explicit_errors() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("new");
        let output = output.to_str().ok_or("test path encoding")?;
        let result =
            Cli::try_parse_from(["bench", "compare", "absent", "absent", "--output", output])?
                .execute();
        assert!(result.is_err_and(|error| error.code == ErrorCode::NotImplemented));
        Ok(())
    }
}

#[cfg(test)]
mod run_exit_tests {
    use super::*;

    #[test]
    fn run_returns_failed_status_after_writing_partial_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let config_path = directory.path().join("config.toml");
        std::fs::write(
            &config_path,
            "schema_version=1\nenvironment_id='test'\n[target]\nmode='local'\nserver_binary='/absent/lonewolf'\n[scenario]\nkind='idle'\nconnections=1",
        )?;
        let output = directory.path().join("output");
        let status = Cli {
            command: Command::Run {
                config: config_path,
                output: output.clone(),
                server_binary: None,
            },
        }
        .execute()?;
        assert_eq!(status, 1);
        assert!(output.join("result.json").is_file());
        Ok(())
    }
}
