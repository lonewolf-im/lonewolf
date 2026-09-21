// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

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
fn configured_account_store_is_served_and_sigterm_cleans_up() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::write(
        directory.path().join("lonewolf.toml"),
        r#"
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
    let mut child = Process(
        Command::new(env!("CARGO_BIN_EXE_lonewolf"))
            .current_dir(directory.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
    Ok(())
}

#[test]
fn occupied_socket_path_fails_startup_without_overwriting_it() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::write(
        directory.path().join("lonewolf.toml"),
        "[admin]\nsocket_path = 'admin.sock'\n",
    )?;
    fs::write(directory.path().join("admin.sock"), "keep")?;
    let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
        .current_dir(directory.path())
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("admin service failed"));
    assert_eq!(
        fs::read_to_string(directory.path().join("admin.sock"))?,
        "keep"
    );
    Ok(())
}
