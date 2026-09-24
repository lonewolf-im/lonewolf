// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Manage a running Lonewolf XMPP server")]
pub(crate) struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        default_value = "./run/lonewolf/admin.sock",
        help = "Path to the admin Unix socket"
    )]
    pub(crate) socket: PathBuf,

    #[arg(long, global = true, help = "Print JSON results and operation errors")]
    pub(crate) json: bool,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    #[command(about = "Manage accounts")]
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum AccountCommand {
    #[command(about = "List accounts")]
    List {
        #[arg(long, value_name = "COUNT", help = "Maximum accounts to print")]
        limit: Option<NonZeroUsize>,
    },
    #[command(about = "Show an account")]
    Get { jid: String },
    #[command(about = "Create an account")]
    Create {
        jid: String,
        #[arg(long, help = "Read one password line from standard input")]
        password_stdin: bool,
    },
    #[command(about = "Delete an account")]
    Delete {
        jid: String,
        #[arg(long, help = "Skip deletion confirmation")]
        yes: bool,
    },
    #[command(about = "Change an account password")]
    Password {
        jid: String,
        #[arg(long, help = "Read one password line from standard input")]
        password_stdin: bool,
    },
}
