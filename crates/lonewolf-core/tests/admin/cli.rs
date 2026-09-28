// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use compio::runtime::Runtime;
use futures_channel::oneshot;
use lonewolf_admin::Server;
use lonewolf_storage::RedbDatabase;
use lonewolf_storage::account::redb::RedbAccountRepository;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error>>;

fn with_admin_server(test: impl FnOnce(&Path) -> TestResult) -> TestResult {
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("run/lonewolf/admin.sock");
    let database = RedbDatabase::open(directory.path().join("accounts.redb"))?;
    let accounts = RedbAccountRepository::from_database(database)?;
    let (stop, stopped) = oneshot::channel::<()>();
    let (ready, readiness) = mpsc::channel();
    let worker = thread::spawn(move || -> io::Result<()> {
        Runtime::new()?.block_on(async {
            let server = Server::bind(&socket, accounts)?;
            ready.send(()).map_err(io::Error::other)?;
            server
                .run(async move {
                    let _ = stopped.await;
                    Ok(())
                })
                .await
        })
    });
    readiness.recv_timeout(Duration::from_secs(5))?;
    let result = test(directory.path());
    let _ = stop.send(());
    worker.join().map_err(|_| "admin thread panicked")??;
    result
}

fn ctl(directory: &Path, arguments: &[&str], input: Option<&str>) -> Result<Output, io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lonewolfctl"));
    command
        .current_dir(directory)
        .args(arguments)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing child stdin"))?
            .write_all(input.as_bytes())?;
    }
    child.wait_with_output()
}

#[test]
fn account_commands_use_the_default_socket_and_preserve_json_errors() -> TestResult {
    with_admin_server(|directory| {
        let created = ctl(
            directory,
            &["account", "create", "Alice@EXAMPLE.ORG", "--password-stdin"],
            Some("first password\n"),
        )?;
        assert!(created.status.success());
        assert_eq!(created.stdout, b"alice@example.org\n");
        assert!(created.stderr.is_empty());

        let got = ctl(
            directory,
            &["--json", "account", "get", "ALICE@example.org"],
            None,
        )?;
        assert!(got.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&got.stdout)?,
            json!({"jid":"alice@example.org"})
        );

        let listed = ctl(directory, &["account", "list"], None)?;
        assert!(listed.status.success());
        assert_eq!(listed.stdout, b"alice@example.org\n");
        let listed_json = ctl(directory, &["account", "list", "--json"], None)?;
        assert!(listed_json.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&listed_json.stdout)?,
            json!({"accounts":[{"jid":"alice@example.org"}]})
        );

        let duplicate = ctl(
            directory,
            &[
                "--json",
                "account",
                "create",
                "alice@example.org",
                "--password-stdin",
            ],
            Some("private password\n"),
        )?;
        assert_eq!(duplicate.status.code(), Some(1));
        assert!(duplicate.stdout.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&duplicate.stderr)?,
            json!({"error":{"code":"account_exists"}})
        );
        assert!(!String::from_utf8_lossy(&duplicate.stderr).contains("private password"));

        let changed = ctl(
            directory,
            &[
                "account",
                "password",
                "alice@example.org",
                "--password-stdin",
                "--json",
            ],
            Some("replacement\n"),
        )?;
        assert!(changed.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&changed.stdout)?,
            json!({"ok":true})
        );

        let unconfirmed = ctl(directory, &["account", "delete", "alice@example.org"], None)?;
        assert_eq!(unconfirmed.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&unconfirmed.stderr).contains("--yes"));
        assert!(
            ctl(directory, &["account", "get", "alice@example.org"], None)?
                .status
                .success()
        );

        let deleted = ctl(
            directory,
            &["account", "delete", "alice@example.org", "--yes", "--json"],
            None,
        )?;
        assert!(deleted.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&deleted.stdout)?,
            json!({"ok":true})
        );
        let missing = ctl(
            directory,
            &["--json", "account", "get", "alice@example.org"],
            None,
        )?;
        assert_eq!(missing.status.code(), Some(1));
        assert_eq!(
            serde_json::from_slice::<Value>(&missing.stderr)?,
            json!({"error":{"code":"not_found"}})
        );
        Ok(())
    })
}

#[test]
fn socket_override_and_usage_errors() -> TestResult {
    with_admin_server(|directory| {
        let socket = directory.join("run/lonewolf/admin.sock");
        let socket = socket.to_str().ok_or("invalid socket path")?;
        let output = ctl(
            directory,
            &["--socket", socket, "account", "list", "--limit", "1"],
            None,
        )?;
        assert!(output.status.success());
        assert!(output.stdout.is_empty());

        let invalid = ctl(directory, &["account", "list", "--limit", "0"], None)?;
        assert_eq!(invalid.status.code(), Some(2));
        let empty_password = ctl(
            directory,
            &[
                "--json",
                "account",
                "create",
                "alice@example.org",
                "--password-stdin",
            ],
            Some(""),
        )?;
        assert_eq!(empty_password.status.code(), Some(1));
        assert_eq!(
            serde_json::from_slice::<Value>(&empty_password.stderr)?,
            json!({"error":{"code":"password_required"}})
        );
        let missing = ctl(
            directory,
            &["--socket", "missing.sock", "--json", "account", "list"],
            None,
        )?;
        assert_eq!(missing.status.code(), Some(1));
        assert_eq!(
            serde_json::from_slice::<Value>(&missing.stderr)?,
            json!({"error":{"code":"connection_failed"}})
        );
        Ok(())
    })
}

fn scripted_server(
    path: PathBuf,
    script: Vec<(String, u16, Vec<u8>)>,
) -> io::Result<thread::JoinHandle<io::Result<()>>> {
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        for (target, status, body) in script {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(io::Error::other("client did not connect"));
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut request = Vec::new();
            loop {
                let mut buffer = [0_u8; 1024];
                let read = stream.read(&mut buffer)?;
                if read == 0 {
                    return Err(io::Error::other("request ended before headers"));
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).map_err(io::Error::other)?;
            if !request.starts_with(&format!("GET {target} HTTP/1.1\r\n")) {
                return Err(io::Error::other("unexpected request target"));
            }
            let reason = if status == 200 {
                "OK"
            } else {
                "Service Unavailable"
            };
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            stream.write_all(&body)?;
            stream.shutdown(Shutdown::Write)?;
        }
        Ok(())
    }))
}

#[test]
fn listing_follows_pages_and_honors_total_limit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let first_page: Vec<_> = (0..100)
        .map(|index| json!({"jid":format!("user{index:03}@example.org")}))
        .collect();
    let first = serde_json::to_vec(&json!({
        "accounts":first_page,
        "next_cursor":"user099@example.org"
    }))?;
    let second = serde_json::to_vec(&json!({
        "accounts":[{"jid":"user100@example.org"}],
        "next_cursor":null
    }))?;
    let socket = directory.path().join("page.sock");
    let worker = scripted_server(
        socket.clone(),
        vec![
            ("/v1/accounts?limit=100".into(), 200, first),
            (
                "/v1/accounts?limit=100&after=user099%40example%2Eorg".into(),
                200,
                second,
            ),
        ],
    )?;
    let socket = socket.to_str().ok_or("invalid socket path")?;
    let output = ctl(
        directory.path(),
        &["--socket", socket, "account", "list"],
        None,
    )?;
    worker.join().map_err(|_| "fake server panicked")??;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<_> = std::str::from_utf8(&output.stdout)?.lines().collect();
    assert_eq!(lines.len(), 101);
    assert_eq!(lines[0], "user000@example.org");
    assert_eq!(lines[100], "user100@example.org");

    let limited_socket = directory.path().join("limited.sock");
    let worker = scripted_server(
        limited_socket.clone(),
        vec![(
            "/v1/accounts?limit=1".into(),
            200,
            serde_json::to_vec(&json!({
                "accounts":[{"jid":"user000@example.org"}],
                "next_cursor":"user000@example.org"
            }))?,
        )],
    )?;
    let limited_socket = limited_socket.to_str().ok_or("invalid socket path")?;
    let output = ctl(
        directory.path(),
        &[
            "--socket",
            limited_socket,
            "--json",
            "account",
            "list",
            "--limit",
            "1",
        ],
        None,
    )?;
    worker.join().map_err(|_| "fake server panicked")??;
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)?,
        json!({"accounts":[{"jid":"user000@example.org"}]})
    );
    Ok(())
}

#[test]
fn a_later_page_failure_returns_nonzero_after_partial_output() -> TestResult {
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("failing.sock");
    let worker = scripted_server(
        socket.clone(),
        vec![
            (
                "/v1/accounts?limit=100".into(),
                200,
                serde_json::to_vec(&json!({
                    "accounts":[{"jid":"alice@example.org"}],
                    "next_cursor":"alice@example.org"
                }))?,
            ),
            (
                "/v1/accounts?limit=100&after=alice%40example%2Eorg".into(),
                503,
                serde_json::to_vec(&json!({"error":{"code":"future_error"}}))?,
            ),
        ],
    )?;
    let socket = socket.to_str().ok_or("invalid socket path")?;
    let output = ctl(
        directory.path(),
        &["--socket", socket, "--json", "account", "list"],
        None,
    )?;
    worker.join().map_err(|_| "fake server panicked")??;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        output.stdout,
        b"{\"accounts\":[{\"jid\":\"alice@example.org\"}"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr)?,
        json!({"error":{"code":"future_error"}})
    );
    Ok(())
}
