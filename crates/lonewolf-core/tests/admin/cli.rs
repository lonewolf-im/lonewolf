// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use compio::runtime::Runtime;
use futures_channel::oneshot;
use lonewolf_admin::{RecordDeleter, Server};
use lonewolf_storage::RedbStorage;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error>>;

fn with_admin_server(test: impl FnOnce(&Path) -> TestResult) -> TestResult {
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("run/lonewolf/admin.sock");
    let storage = RedbStorage::open(directory.path().join("accounts.redb"))?;
    let (stop, stopped) = oneshot::channel::<()>();
    let (ready, readiness) = mpsc::channel();
    let worker = thread::spawn(move || -> io::Result<()> {
        Runtime::new()?.block_on(async {
            let server = Server::bind(
                &socket,
                storage.clone(),
                Arc::new(RecordDeleter::new(storage)),
            )?;
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
            Some("first copper lantern meadow\n"),
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
        assert!(!String::from_utf8_lossy(&duplicate.stderr).contains("private password"));
        assert_eq!(duplicate.status.code(), Some(1));
        assert!(duplicate.stdout.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&duplicate.stderr)?,
            json!({"error":{"code":"account_exists"}})
        );

        let changed = ctl(
            directory,
            &[
                "account",
                "password",
                "alice@example.org",
                "--password-stdin",
                "--json",
            ],
            Some("violet cedar cloud orchard\n"),
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
    scripted_exchanges(
        path,
        script
            .into_iter()
            .map(|(target, status, body)| ScriptedExchange {
                method: "GET",
                target,
                request_body: None,
                response: http_response(status, &body),
            })
            .collect(),
    )
}

struct ScriptedExchange {
    method: &'static str,
    target: String,
    request_body: Option<Value>,
    response: Vec<u8>,
}

fn http_response(status: u16, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn scripted_exchanges(
    path: PathBuf,
    script: Vec<ScriptedExchange>,
) -> io::Result<thread::JoinHandle<io::Result<()>>> {
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let listener = {
            let _entered = runtime.enter();
            tokio::net::UnixListener::from_std(listener)?
        };
        for exchange in script {
            let (stream, _) = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "client did not connect")
                    })?
            })?;
            let mut stream = stream.into_std()?;
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut request = Vec::new();
            let header_end = loop {
                let mut buffer = [0_u8; 1024];
                let read = stream.read(&mut buffer)?;
                if read == 0 {
                    return Err(io::Error::other("request ended before headers"));
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = std::str::from_utf8(&request[..header_end]).map_err(io::Error::other)?;
            if !headers.starts_with(&format!(
                "{} {} HTTP/1.1\r\n",
                exchange.method, exchange.target
            )) {
                return Err(io::Error::other("unexpected request method or target"));
            }
            let content_length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>())
                .transpose()
                .map_err(io::Error::other)?
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let mut buffer = [0_u8; 1024];
                let read = stream.read(&mut buffer)?;
                if read == 0 {
                    return Err(io::Error::other("request ended before body"));
                }
                request.extend_from_slice(&buffer[..read]);
            }
            if let Some(expected) = exchange.request_body {
                let actual: Value =
                    serde_json::from_slice(&request[header_end..]).map_err(io::Error::other)?;
                assert_eq!(actual, expected);
            }
            stream.write_all(&exchange.response)?;
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

#[test]
fn weak_password_errors_are_private_in_plain_and_json_modes() -> TestResult {
    with_admin_server(|directory| {
        let created = ctl(
            directory,
            &["account", "create", "alice@example.org", "--password-stdin"],
            Some("ocean copper lantern meadow\n"),
        )?;
        assert!(created.status.success());
        for json_mode in [false, true] {
            for action in ["create", "password"] {
                let secret = "weak-unique";
                let mut arguments = vec![
                    "account",
                    action,
                    if action == "create" {
                        "missing@example.org"
                    } else {
                        "alice@example.org"
                    },
                    "--password-stdin",
                ];
                if json_mode {
                    arguments.push("--json");
                }
                let output = ctl(directory, &arguments, Some(&format!("{secret}\n")))?;
                assert_eq!(output.status.code(), Some(1));
                assert!(output.stdout.is_empty());
                assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
                if json_mode {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&output.stderr)?,
                        json!({"error":{"code":"weak_password"}})
                    );
                } else {
                    assert_eq!(
                        String::from_utf8(output.stderr)?,
                        "password must contain at least 15 characters and 3 distinct characters after SASLprep\n"
                    );
                }
            }
        }
        Ok(())
    })
}

#[test]
fn malformed_http_and_json_replies_return_specific_client_errors() -> TestResult {
    for (response, code) in [
        (b"not an HTTP response\r\n\r\n".to_vec(), "request_failed"),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length:".to_vec(),
            "request_failed",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n{}".to_vec(),
            "invalid_response",
        ),
        (http_response(200, b"not JSON"), "invalid_response"),
        (
            http_response(200, br#"{"jid":"truncated""#),
            "invalid_response",
        ),
        (http_response(200, br#"{"jid":42}"#), "invalid_response"),
        (
            http_response(201, br#"{"jid":"alice@example.org"}"#),
            "invalid_response",
        ),
    ] {
        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("hostile.sock");
        let worker = scripted_exchanges(
            socket.clone(),
            vec![ScriptedExchange {
                method: "GET",
                target: "/v1/accounts/alice%40example%2Eorg".into(),
                request_body: None,
                response,
            }],
        )?;
        let socket = socket.to_str().ok_or("invalid socket path")?;
        let output = ctl(
            directory.path(),
            &[
                "--socket",
                socket,
                "--json",
                "account",
                "get",
                "alice@example.org",
            ],
            None,
        )?;
        worker.join().map_err(|_| "fake server panicked")??;
        assert_eq!(output.status.code(), Some(1), "{code}");
        assert!(output.stdout.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stderr)?,
            json!({"error":{"code":code}})
        );
    }
    Ok(())
}

#[test]
fn response_body_accepts_one_mebibyte_and_rejects_the_next_byte() -> TestResult {
    for (length, accepted) in [(1024 * 1024, true), (1024 * 1024 + 1, false)] {
        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("boundary.sock");
        let mut body = br#"{"jid":"alice@example.org"}"#.to_vec();
        body.resize(length, b' ');
        let worker = scripted_server(
            socket.clone(),
            vec![("/v1/accounts/alice%40example%2Eorg".into(), 200, body)],
        )?;
        let socket = socket.to_str().ok_or("invalid socket path")?;
        let output = ctl(
            directory.path(),
            &[
                "--socket",
                socket,
                "--json",
                "account",
                "get",
                "alice@example.org",
            ],
            None,
        )?;
        worker.join().map_err(|_| "fake server panicked")??;
        if accepted {
            assert_eq!(output.status.code(), Some(0));
            assert_eq!(
                serde_json::from_slice::<Value>(&output.stdout)?,
                json!({"jid":"alice@example.org"})
            );
            assert!(output.stderr.is_empty());
        } else {
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert_eq!(
                serde_json::from_slice::<Value>(&output.stderr)?,
                json!({"error":{"code":"invalid_response"}})
            );
        }
    }
    Ok(())
}

#[test]
fn malformed_account_pages_fail_before_any_accounts_are_printed() -> TestResult {
    let oversized_page: Vec<_> = (0..101)
        .map(|index| json!({"jid":format!("user{index:03}@example.org")}))
        .collect();
    for page in [
        json!({"accounts":{},"next_cursor":null}),
        json!({"accounts":[{"jid":42}],"next_cursor":null}),
        json!({"accounts":[],"next_cursor":"alice@example.org"}),
        json!({"accounts":[{"jid":"alice@example.org"}],"next_cursor":42}),
        json!({"accounts":oversized_page,"next_cursor":null}),
    ] {
        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("invalid-page.sock");
        let worker = scripted_server(
            socket.clone(),
            vec![(
                "/v1/accounts?limit=100".into(),
                200,
                serde_json::to_vec(&page)?,
            )],
        )?;
        let socket = socket.to_str().ok_or("invalid socket path")?;
        let output = ctl(
            directory.path(),
            &["--socket", socket, "--json", "account", "list"],
            None,
        )?;
        worker.join().map_err(|_| "fake server panicked")??;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stdout, b"{\"accounts\":[");
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stderr)?,
            json!({"error":{"code":"invalid_response"}})
        );
    }
    Ok(())
}

#[test]
fn nonprogressing_page_cursors_fail_after_the_accounts_already_received() -> TestResult {
    for next in ["alice@example.org", "aardvark@example.org"] {
        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("cursor.sock");
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
                    200,
                    serde_json::to_vec(&json!({
                        "accounts":[{"jid":"bob@example.org"}],
                        "next_cursor":next
                    }))?,
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
            b"{\"accounts\":[{\"jid\":\"alice@example.org\"},{\"jid\":\"bob@example.org\"}"
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stderr)?,
            json!({"error":{"code":"invalid_response"}})
        );
    }
    Ok(())
}

#[test]
fn password_stdin_preserves_maximum_bytes_and_strips_only_line_endings() -> TestResult {
    let maximum_ascii = "a".repeat(8192);
    let maximum_utf8 = "é".repeat(4096);
    let mut cases = vec![
        ("a\n".into(), "a"),
        (" a \r\n".into(), " a "),
        ("a\r".into(), "a\r"),
    ];
    for password in [&maximum_ascii, &maximum_utf8] {
        for ending in ["", "\n", "\r\n"] {
            cases.push((format!("{password}{ending}"), password));
        }
    }
    for action in ["create", "password"] {
        for (input, normalized) in &cases {
            let directory = tempfile::tempdir()?;
            let socket = directory.path().join("password.sock");
            let (method, target, expected_body, status, response) = if action == "create" {
                (
                    "POST",
                    "/v1/accounts",
                    json!({"jid":"alice@example.org","password":normalized}),
                    201,
                    br#"{"jid":"alice@example.org"}"#.as_slice(),
                )
            } else {
                (
                    "PUT",
                    "/v1/accounts/alice%40example%2Eorg/password",
                    json!({"password":normalized}),
                    204,
                    b"".as_slice(),
                )
            };
            let worker = scripted_exchanges(
                socket.clone(),
                vec![ScriptedExchange {
                    method,
                    target: target.into(),
                    request_body: Some(expected_body),
                    response: http_response(status, response),
                }],
            )?;
            let socket = socket.to_str().ok_or("invalid socket path")?;
            let output = ctl(
                directory.path(),
                &[
                    "--socket",
                    socket,
                    "--json",
                    "account",
                    action,
                    "alice@example.org",
                    "--password-stdin",
                ],
                Some(input),
            )?;
            worker.join().map_err(|_| "fake server panicked")??;
            assert_eq!(output.status.code(), Some(0));
            assert!(output.stderr.is_empty());
            let expected = if action == "create" {
                json!({"jid":"alice@example.org"})
            } else {
                json!({"ok":true})
            };
            assert_eq!(serde_json::from_slice::<Value>(&output.stdout)?, expected);
        }
    }
    Ok(())
}

#[test]
fn empty_and_oversized_password_stdin_fail_before_connecting() -> TestResult {
    let directory = tempfile::tempdir()?;
    let oversized = "a".repeat(8193);
    let oversized_utf8 = "é".repeat(4097);
    for action in ["create", "password"] {
        for (input, code) in [
            ("", "password_required"),
            ("\n", "invalid_password"),
            ("\r\n", "invalid_password"),
            (oversized.as_str(), "invalid_password"),
            (oversized_utf8.as_str(), "invalid_password"),
        ] {
            let output = ctl(
                directory.path(),
                &[
                    "--json",
                    "account",
                    action,
                    "alice@example.org",
                    "--password-stdin",
                ],
                Some(input),
            )?;
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert_eq!(
                serde_json::from_slice::<Value>(&output.stderr)?,
                json!({"error":{"code":code}})
            );
        }
    }
    Ok(())
}
