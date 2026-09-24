// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn connect(path: &Path, child: &mut Child) -> Result<UnixStream, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(stream) = UnixStream::connect(path) {
            return Ok(stream);
        }
        if child.try_wait()?.is_some() {
            return Err("server exited before accepting connections".into());
        }
        if Instant::now() >= deadline {
            return Err("admin socket was not ready".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn configured_account_store_logs_admin_commands_and_sigterm_cleans_up() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::write(
        directory.path().join("lonewolf.toml"),
        r#"
[logging]
level = "debug"
[xmpp]
stanza_pool_size_mib = 8
[[c2s.listeners]]
address = "127.0.0.1:0"
[admin]
socket_path = "private/admin.sock"
[account]
storage = "accounts"
[storage]
default = "primary"
[storage.stores.primary]
backend = "redb"
path = "unused.redb"
[storage.stores.accounts]
backend = "redb"
path = "accounts.redb"
"#,
    )?;
    let log_path = directory.path().join("server.log");
    let mut child = Process(
        Command::new(env!("CARGO_BIN_EXE_lonewolf"))
            .current_dir(directory.path())
            .env("LONEWOLF_WORKER_COUNT", "1")
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log_path)?)
            .spawn()?,
    );
    let path = directory.path().join("private/admin.sock");
    let mut stream = connect(&path, &mut child.0)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"GET /v1/accounts HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with(r#"{"accounts":[],"next_cursor":null}"#));
    assert!(directory.path().join("accounts.redb").exists());
    assert!(!directory.path().join("unused.redb").exists());

    let requests = [
        (
            "GET",
            "/v1/accounts?after=private-account%40example.org",
            "",
            "account_list",
            200,
        ),
        (
            "POST",
            "/v1/accounts",
            r#"{"jid":"private-account@example.org","password":"private-password"}"#,
            "account_create",
            201,
        ),
        (
            "GET",
            "/v1/accounts/private-account%40example.org",
            "",
            "account_get",
            200,
        ),
        (
            "PUT",
            "/v1/accounts/private-account%40example.org/password",
            r#"{"password":"private-new-password"}"#,
            "account_password",
            204,
        ),
        (
            "PATCH",
            "/v1/accounts/private-account%40example.org",
            "",
            "/v1/accounts/{jid}",
            405,
        ),
        (
            "GET",
            "/private-account%40example.org?token=private-token",
            "",
            "unmatched",
            404,
        ),
        (
            "GET",
            "/v1/accounts/private-account%40example.org?token=private-token",
            "",
            "account_get",
            400,
        ),
        (
            "DELETE",
            "/v1/accounts/private-account%40example.org",
            "",
            "account_delete",
            204,
        ),
        (
            "GET",
            "/v1/accounts/private-account%40example.org",
            "",
            "account_get",
            404,
        ),
    ];
    for (method, target, body, _, status) in &requests {
        let mut stream = connect(&path, &mut child.0)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let request = format!(
            "{method} {target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes())?;
        response.clear();
        stream
            .read_to_string(&mut response)
            .map_err(|error| format!("{method} {target}: {error}; response: {response}"))?;
        assert!(response.starts_with(&format!("HTTP/1.1 {status}")));
    }

    kill(Pid::from_raw(child.0.id().try_into()?), Signal::SIGTERM)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait()? {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            return Err("server did not stop after SIGTERM".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!path.exists());
    let logs = fs::read_to_string(log_path)?;
    assert!(logs.lines().any(|line| {
        line.contains("stanza arena pool initialized") && line.contains("reserved_bytes=8388608")
    }));
    assert!(logs.lines().any(|line| line.contains("core dispatcher started") && line.contains("worker_count=1")));
    let waiting = logs
        .find("waiting for stop signal... (press Ctrl+C to stop the server)")
        .ok_or("missing wait log")?;
    let admin_started = logs
        .find("admin service started")
        .ok_or("missing admin start log")?;
    let received = logs
        .find("received stop signal... gracefully shutting down...")
        .ok_or("missing stop signal log")?;
    let dispatcher_stopped = logs
        .find("core dispatcher stopped")
        .ok_or("missing dispatcher stop log")?;
    assert!(admin_started < waiting);
    assert!(waiting < received);
    assert!(received < dispatcher_stopped);
    let mut events = logs.lines().filter(|line| {
        line.contains("admin request completed") || line.contains("admin command handled")
    });
    for (action, status) in std::iter::once(("account_list", 200)).chain(
        requests
            .iter()
            .map(|(_, _, _, action, status)| (*action, *status)),
    ) {
        let event = events.next().ok_or("missing request log")?;
        if action == "unmatched" || action.starts_with("/v1/") {
            assert!(event.contains("admin request completed"), "{event}");
            assert!(event.contains(&format!("route={action:?}")), "{event}");
        } else {
            assert!(event.contains(" INFO "), "{event}");
            assert!(event.contains("admin command handled"), "{event}");
            assert!(event.contains(&format!("command={action:?}")), "{event}");
        }
        assert!(event.contains(&format!("status={status}")), "{event}");
    }
    assert!(events.next().is_none());
    assert!(!logs.contains("private-account"));
    assert!(!logs.contains("private-token"));
    assert!(!logs.contains("private-password"));
    assert!(!logs.contains("private-new-password"));
    Ok(())
}

#[test]
fn occupied_socket_path_fails_startup_without_overwriting_it() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::write(
        directory.path().join("lonewolf.toml"),
        "[xmpp]\nstanza_pool_size_mib = 8\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[admin]\nsocket_path = 'admin.sock'\n",
    )?;
    fs::write(directory.path().join("admin.sock"), "keep")?;
    let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
        .current_dir(directory.path())
        .env_remove("LONEWOLF_WORKER_COUNT")
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let logs = std::str::from_utf8(&output.stderr)?;
    let expected_count = format!("worker_count={}", thread::available_parallelism()?);
    assert!(
        logs.lines()
            .any(|line| line.contains("core dispatcher started") && line.contains(&expected_count))
    );
    assert!(logs.contains("core dispatcher stopped"));
    assert!(logs.contains("admin service failed"));
    assert_eq!(
        fs::read_to_string(directory.path().join("admin.sock"))?,
        "keep"
    );
    Ok(())
}
