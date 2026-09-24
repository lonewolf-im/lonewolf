// SPDX-License-Identifier: Apache-2.0

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

use std::fmt;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::num::NonZeroUsize;
use std::process::ExitCode;

use clap::Parser;
use hyper::{Method, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use tokio::runtime::Builder;
use zeroize::Zeroizing;

use crate::cli::{AccountCommand, Cli, Command};
use crate::client::Client;

mod cli;
mod client;

const MAX_PASSWORD_BYTES: usize = 8192;
const PAGE_SIZE: usize = 100;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if json {
                let mut stderr = io::stderr().lock();
                let _ = serde_json::to_writer(
                    &mut stderr,
                    &serde_json::json!({"error": {"code": error.code}}),
                );
                let _ = stderr.write_all(b"\n");
            } else {
                eprintln!("{error}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), CtlError> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CtlError::new("runtime_failed", format!("cannot start client: {error}"))
        })?;
    runtime.block_on(execute(cli))
}

async fn execute(cli: Cli) -> Result<(), CtlError> {
    let client = Client::new(cli.socket);
    match cli.command {
        Command::Account { command } => match command {
            AccountCommand::List { limit } => list_accounts(&client, cli.json, limit).await,
            AccountCommand::Get { jid } => {
                let body = client
                    .request(Method::GET, &account_path(&jid), Vec::new())
                    .await?
                    .expect_status(StatusCode::OK)?;
                print_account(&body, cli.json)
            }
            AccountCommand::Create {
                jid,
                password_stdin,
            } => {
                let password = read_password(password_stdin)?;
                let body = serialize(&CreateAccount {
                    jid: &jid,
                    password: &password,
                })?;
                let body = client
                    .request(Method::POST, "/v1/accounts", body)
                    .await?
                    .expect_status(StatusCode::CREATED)?;
                print_account(&body, cli.json)
            }
            AccountCommand::Delete { jid, yes } => {
                if !yes {
                    confirm_delete(&jid)?;
                }
                client
                    .request(Method::DELETE, &account_path(&jid), Vec::new())
                    .await?
                    .expect_status(StatusCode::NO_CONTENT)?;
                print_mutation(cli.json)
            }
            AccountCommand::Password {
                jid,
                password_stdin,
            } => {
                let password = read_password(password_stdin)?;
                let body = serialize(&ChangePassword {
                    password: &password,
                })?;
                let path = format!("{}/password", account_path(&jid));
                client
                    .request(Method::PUT, &path, body)
                    .await?
                    .expect_status(StatusCode::NO_CONTENT)?;
                print_mutation(cli.json)
            }
        },
    }
}

fn account_path(jid: &str) -> String {
    format!(
        "/v1/accounts/{}",
        utf8_percent_encode(jid, NON_ALPHANUMERIC)
    )
}

#[derive(Deserialize, Serialize)]
struct Account {
    jid: String,
}

#[derive(Deserialize)]
struct AccountPage {
    accounts: Vec<Account>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct CreateAccount<'a> {
    jid: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct ChangePassword<'a> {
    password: &'a str,
}

async fn list_accounts(
    client: &Client,
    json: bool,
    limit: Option<NonZeroUsize>,
) -> Result<(), CtlError> {
    let mut output = io::BufWriter::new(io::stdout().lock());
    if json {
        output
            .write_all(b"{\"accounts\":[")
            .map_err(CtlError::output)?;
    }
    let mut count = 0;
    let mut cursor: Option<String> = None;
    loop {
        let remaining = limit.map_or(PAGE_SIZE, |limit| limit.get().saturating_sub(count));
        if remaining == 0 {
            break;
        }
        let page_size = remaining.min(PAGE_SIZE);
        let mut uri = format!("/v1/accounts?limit={page_size}");
        if let Some(cursor) = cursor.as_deref() {
            uri.push_str("&after=");
            uri.extend(utf8_percent_encode(cursor, NON_ALPHANUMERIC));
        }
        let body = client
            .request(Method::GET, &uri, Vec::new())
            .await?
            .expect_status(StatusCode::OK)?;
        let page: AccountPage =
            serde_json::from_slice(&body).map_err(|_| CtlError::invalid_response())?;
        if page.accounts.len() > page_size
            || (page.accounts.is_empty() && page.next_cursor.is_some())
        {
            return Err(CtlError::invalid_response());
        }
        for account in page.accounts {
            if json {
                if count > 0 {
                    output.write_all(b",").map_err(CtlError::output)?;
                }
                serde_json::to_writer(&mut output, &account)
                    .map_err(|_| CtlError::output(io::Error::other("cannot write JSON")))?;
            } else {
                writeln!(output, "{}", account.jid).map_err(CtlError::output)?;
            }
            count += 1;
        }
        output.flush().map_err(CtlError::output)?;
        match page.next_cursor {
            None => break,
            Some(_) if count == limit.map_or(usize::MAX, NonZeroUsize::get) => break,
            Some(next)
                if cursor
                    .as_deref()
                    .is_none_or(|current| next.as_str() > current) =>
            {
                cursor = Some(next);
            }
            Some(_) => return Err(CtlError::invalid_response()),
        }
    }
    if json {
        output.write_all(b"]}\n").map_err(CtlError::output)?;
    }
    output.flush().map_err(CtlError::output)
}

fn print_account(body: &[u8], json: bool) -> Result<(), CtlError> {
    let account: Account =
        serde_json::from_slice(body).map_err(|_| CtlError::invalid_response())?;
    let mut output = io::stdout().lock();
    if json {
        serde_json::to_writer(&mut output, &account)
            .map_err(|_| CtlError::output(io::Error::other("cannot write JSON")))?;
        output.write_all(b"\n").map_err(CtlError::output)?;
    } else {
        writeln!(output, "{}", account.jid).map_err(CtlError::output)?;
    }
    Ok(())
}

fn print_mutation(json: bool) -> Result<(), CtlError> {
    if json {
        io::stdout()
            .lock()
            .write_all(b"{\"ok\":true}\n")
            .map_err(CtlError::output)?;
    }
    Ok(())
}

fn serialize(value: &impl Serialize) -> Result<Vec<u8>, CtlError> {
    serde_json::to_vec(value).map_err(|_| CtlError::new("invalid_request", "cannot encode request"))
}

fn read_password(from_stdin: bool) -> Result<Zeroizing<String>, CtlError> {
    let password = if from_stdin {
        let mut password = Zeroizing::new(String::new());
        let stdin = io::stdin();
        let mut input = stdin.lock().take((MAX_PASSWORD_BYTES + 2) as u64);
        let read = input.read_line(&mut password).map_err(CtlError::input)?;
        if read == 0 {
            return Err(CtlError::new(
                "password_required",
                "password input is empty",
            ));
        }
        if password.ends_with('\n') {
            password.pop();
            if password.ends_with('\r') {
                password.pop();
            }
        }
        password
    } else {
        let password = prompt_password("Password: ")?;
        let confirmation = prompt_password("Confirm password: ")?;
        if password.as_str() != confirmation.as_str() {
            return Err(CtlError::new("password_mismatch", "passwords do not match"));
        }
        password
    };
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(CtlError::new(
            "invalid_password",
            "password must contain 1 to 8192 bytes",
        ));
    }
    Ok(password)
}

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>, CtlError> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|error| {
            CtlError::new(
                "terminal_unavailable",
                format!(
                    "cannot read password from terminal: {error}; use --password-stdin for automation"
                ),
            )
        })
}

fn confirm_delete(jid: &str) -> Result<(), CtlError> {
    if !io::stdin().is_terminal() {
        return Err(CtlError::new(
            "confirmation_required",
            "deletion requires a terminal confirmation or --yes",
        ));
    }
    eprint!("Delete account {jid}? [y/N] ");
    io::stderr().flush().map_err(CtlError::input)?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(CtlError::input)?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err(CtlError::new("cancelled", "deletion cancelled"))
    }
}

struct CtlError {
    code: String,
    message: String,
}

impl CtlError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    fn api(code: Option<&str>) -> Self {
        let code = code
            .filter(|code| {
                !code.is_empty()
                    && code.len() <= 64
                    && code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            })
            .unwrap_or("server_error");
        let message = match code {
            "account_exists" => "account already exists",
            "not_found" => "account not found",
            "invalid_jid" => "invalid bare JID",
            "invalid_password" => "invalid password",
            "storage_unavailable" => "account storage is unavailable",
            "commit_unknown" => "account change outcome is unknown",
            "invalid_request" => "admin service rejected the request",
            "body_too_large" => "password is too long for the admin service",
            "internal_error" => "admin service failed",
            _ => "admin service returned an error",
        };
        Self::new(code, message)
    }

    fn invalid_response() -> Self {
        Self::new(
            "invalid_response",
            "admin service returned an invalid response",
        )
    }

    fn input(error: io::Error) -> Self {
        Self::new("input_failed", format!("cannot read input: {error}"))
    }

    fn output(error: io::Error) -> Self {
        Self::new("output_failed", format!("cannot write output: {error}"))
    }
}

impl fmt::Display for CtlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}
