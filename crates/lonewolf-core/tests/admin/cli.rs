// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cognitive_complexity)]

use std::error::Error;
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use compio::runtime::Runtime;
use futures_channel::oneshot;
use lonewolf_admin::{
    RecordDeleter, S2sConnection, S2sConnections, S2sDirection, S2sTlsMode, Server,
};
use lonewolf_storage::RedbStorage;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error>>;

fn with_admin_server(test: impl FnOnce(&Path) -> TestResult) -> TestResult {
    with_admin_server_and_s2s(None, test)
}

fn with_admin_server_and_s2s(
    source: Option<Arc<dyn S2sConnections>>,
    test: impl FnOnce(&Path) -> TestResult,
) -> TestResult {
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
                source,
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

struct ListedConnections(Vec<S2sConnection>);

impl S2sConnections for ListedConnections {
    fn connections(
        &self,
        after: Option<u64>,
        remote_domain: Option<&str>,
        limit: NonZeroUsize,
    ) -> Vec<S2sConnection> {
        self.0
            .iter()
            .filter(|c| after.is_none_or(|id| c.connection_id > id))
            .filter(|c| remote_domain.is_none_or(|domain| c.remote_domain.as_ref() == domain))
            .take(limit.get())
            .cloned()
            .collect()
    }
}

#[test]
fn s2s_list_prints_an_aligned_table_and_json() -> TestResult {
    let inbound = S2sConnection {
        connection_id: 1,
        direction: S2sDirection::Inbound,
        bidirectional: false,
        local_domain: "a.test".into(),
        remote_domain: "b.test".into(),
        remote_address: Some("192.0.2.1:5269".parse()?),
        tls_mode: S2sTlsMode::StartTls,
        tls_version: "TLSv1.3",
        cipher_suite: "TLS13_AES_256_GCM_SHA384",
        established_at: UNIX_EPOCH,
        uptime: Duration::from_secs(59),
        certificate_expires_at: UNIX_EPOCH + Duration::from_secs(86400),
        bytes_received: 1536,
        bytes_sent: 1,
    };
    let outbound = S2sConnection {
        connection_id: 23,
        direction: S2sDirection::Outbound,
        bidirectional: true,
        remote_domain: "long.example".into(),
        remote_address: Some("[2001:db8::1]:5269".parse()?),
        tls_mode: S2sTlsMode::Direct,
        tls_version: "TLSv1.2",
        cipher_suite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        uptime: Duration::from_secs(3720),
        bytes_received: 1048576,
        bytes_sent: 2048,
        ..inbound.clone()
    };
    let no_address = S2sConnection {
        connection_id: 300,
        remote_domain: "c.test".into(),
        remote_address: None,
        tls_mode: S2sTlsMode::Direct,
        uptime: Duration::from_secs(86400),
        bytes_received: 0,
        bytes_sent: 0,
        ..inbound.clone()
    };
    let source = ListedConnections(vec![inbound, outbound, no_address]);
    with_admin_server_and_s2s(Some(Arc::new(source)), |directory| {
        let plain = ctl(directory, &["s2s", "list"], None)?;
        assert!(
            plain.status.success(),
            "{}",
            String::from_utf8_lossy(&plain.stderr)
        );
        assert!(plain.stderr.is_empty());
        assert_eq!(
            std::str::from_utf8(&plain.stdout)?,
            concat!(
                "ID   DIRECTION  BIDI  LOCAL   REMOTE        ADDRESS             TLS               UPTIME  RECEIVED  SENT\n",
                "1    inbound    no    a.test  b.test        192.0.2.1:5269      starttls TLSv1.3  59s     1.5KiB    1B\n",
                "23   outbound   yes   a.test  long.example  [2001:db8::1]:5269  direct TLSv1.2    1h02m   1.0MiB    2.0KiB\n",
                "300  inbound    no    a.test  c.test        -                   direct TLSv1.3    1d00h   0B        0B\n",
            )
        );
        let output = ctl(directory, &["--json", "s2s", "list"], None)?;
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert_eq!(
            std::str::from_utf8(&output.stdout)?,
            concat!(
                r#"{"connections":["#,
                r#"{"connection_id":1,"direction":"inbound","bidirectional":false,"local_domain":"a.test","remote_domain":"b.test","remote_address":"192.0.2.1:5269","tls_mode":"starttls","tls_version":"TLSv1.3","cipher_suite":"TLS13_AES_256_GCM_SHA384","established_at":"1970-01-01T00:00:00Z","uptime_secs":59,"certificate_expires_at":"1970-01-02T00:00:00Z","bytes_received":1536,"bytes_sent":1},"#,
                r#"{"connection_id":23,"direction":"outbound","bidirectional":true,"local_domain":"a.test","remote_domain":"long.example","remote_address":"[2001:db8::1]:5269","tls_mode":"direct","tls_version":"TLSv1.2","cipher_suite":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","established_at":"1970-01-01T00:00:00Z","uptime_secs":3720,"certificate_expires_at":"1970-01-02T00:00:00Z","bytes_received":1048576,"bytes_sent":2048},"#,
                r#"{"connection_id":300,"direction":"inbound","bidirectional":false,"local_domain":"a.test","remote_domain":"c.test","remote_address":null,"tls_mode":"direct","tls_version":"TLSv1.3","cipher_suite":"TLS13_AES_256_GCM_SHA384","established_at":"1970-01-01T00:00:00Z","uptime_secs":86400,"certificate_expires_at":"1970-01-02T00:00:00Z","bytes_received":0,"bytes_sent":0}"#,
                "]}\n"
            )
        );
        let empty = ctl(directory, &["s2s", "list", "--domain", "absent.test"], None)?;
        assert!(empty.status.success());
        assert!(empty.stderr.is_empty());
        assert_eq!(
            empty.stdout,
            b"ID  DIRECTION  BIDI  LOCAL  REMOTE  ADDRESS  TLS  UPTIME  RECEIVED  SENT\n"
        );
        Ok(())
    })
}

fn s2s_connection(id: u64) -> Value {
    json!({
        "connection_id":id, "direction":"inbound", "bidirectional":false,
        "local_domain":"a.test", "remote_domain":"b.test", "remote_address":null,
        "tls_mode":"direct", "tls_version":"TLSv1.3", "cipher_suite":"TLS13_AES_128_GCM_SHA256",
        "established_at":null, "uptime_secs":42, "certificate_expires_at":null,
        "bytes_received":12, "bytes_sent":34
    })
}

fn scripted_listing(
    args: &[&str],
    script: &[(&str, u16, Value)],
) -> Result<Output, Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let exchanges = script
        .iter()
        .map(|(target, status, body)| {
            Ok(((*target).to_owned(), *status, serde_json::to_vec(body)?))
        })
        .collect::<serde_json::Result<_>>()?;
    let worker = scripted_server(directory.path().join("s2s.sock"), exchanges)?;
    let mut arguments = vec!["--socket", "s2s.sock", "s2s", "list"];
    arguments.extend_from_slice(args);
    let output = ctl(directory.path(), &arguments, None)?;
    assert_ne!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    worker.join().map_err(|_| "fake server panicked")??;
    Ok(output)
}

#[test]
fn s2s_list_follows_pages_and_honors_total_limit() -> TestResult {
    let rows = [s2s_connection(8), s2s_connection(11), s2s_connection(19)];
    let mut first = rows[0].clone();
    first["future_field"] = json!("ignored");
    let output = scripted_listing(
        &["--domain", "b.test", "--limit", "3", "--json"],
        &[
            (
                "/v1/s2s/connections?limit=3&remote_domain=b%2Etest",
                200,
                json!({"connections":[first,rows[1]],"next_cursor":11}),
            ),
            (
                "/v1/s2s/connections?limit=1&after=11&remote_domain=b%2Etest",
                200,
                json!({"connections":[rows[2]],"next_cursor":19}),
            ),
        ],
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)?,
        json!({"connections":rows})
    );
    Ok(())
}

#[test]
fn s2s_list_reports_inactive_federation_and_invalid_domains() -> TestResult {
    with_admin_server(|directory| {
        for (args, code, message) in [
            (
                vec!["s2s", "list"],
                "s2s_inactive",
                "federation is not active on this server\n",
            ),
            (
                vec!["s2s", "list", "--domain", "me@b.test"],
                "invalid_domain",
                "invalid domain name\n",
            ),
        ] {
            let plain = ctl(directory, &args, None)?;
            assert_eq!(
                plain.status.code(),
                Some(1),
                "{}",
                String::from_utf8_lossy(&plain.stderr)
            );
            assert!(plain.stdout.is_empty());
            assert_eq!(plain.stderr, message.as_bytes());
            let mut args = args;
            args.push("--json");
            let output = ctl(directory, &args, None)?;
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert_eq!(
                serde_json::from_slice::<Value>(&output.stderr)?,
                json!({"error":{"code":code}})
            );
        }
        Ok(())
    })
}

#[test]
fn s2s_list_rejects_malformed_pages_without_printing_rows() -> TestResult {
    let first = "/v1/s2s/connections?limit=2";
    let next = "/v1/s2s/connections?limit=1&after=8";
    let row = s2s_connection(8);
    let valid = json!({"connections":[row],"next_cursor":8});
    for (script, code) in [
        (
            vec![(
                first,
                200,
                json!({"connections":[row,row,row],"next_cursor":null}),
            )],
            "invalid_response",
        ),
        (
            vec![(first, 200, json!({"connections":[],"next_cursor":8}))],
            "invalid_response",
        ),
        (
            vec![
                (first, 200, valid.clone()),
                (
                    next,
                    200,
                    json!({"connections":[s2s_connection(9)],"next_cursor":8}),
                ),
            ],
            "invalid_response",
        ),
        (
            vec![
                (first, 200, valid),
                (next, 500, json!({"error":{"code":"internal_error"}})),
            ],
            "internal_error",
        ),
    ] {
        for json_mode in [false, true] {
            let mut args = vec!["--limit", "2"];
            if json_mode {
                args.push("--json");
            }
            let output = scripted_listing(&args, &script)?;
            assert_eq!(output.status.code(), Some(1), "{code}");
            assert!(output.stdout.is_empty(), "{code}");
            if json_mode {
                assert_eq!(
                    serde_json::from_slice::<Value>(&output.stderr)?,
                    json!({"error":{"code":code}})
                );
            } else {
                assert!(!output.stderr.is_empty());
            }
        }
    }
    Ok(())
}

#[test]
fn s2s_list_replaces_control_characters() -> TestResult {
    let mut row = s2s_connection(8);
    row["remote_domain"] = json!("b\u{1b}[31m.test");
    let output = scripted_listing(
        &[],
        &[(
            "/v1/s2s/connections?limit=100",
            200,
            json!({"connections":[row],"next_cursor":null}),
        )],
    )?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let table = std::str::from_utf8(&output.stdout)?;
    assert_eq!(
        table
            .lines()
            .nth(1)
            .and_then(|line| line.split_whitespace().nth(4)),
        Some("b?[31m.test")
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
