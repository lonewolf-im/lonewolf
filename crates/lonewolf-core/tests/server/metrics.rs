// SPDX-License-Identifier: Apache-2.0

#[path = "../support/ports.rs"]
mod ports;

use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

type TestResult = Result<(), Box<dyn Error>>;
const TIMEOUT: Duration = Duration::from_secs(10);

struct Server {
    child: Child,
    directory: tempfile::TempDir,
}

impl Server {
    fn start(config: &str, workers: usize) -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::write(
            directory.path().join("lonewolf.toml"),
            format!("[xmpp]\nstanza_pool_size_mib = 8\n{config}"),
        )?;
        let child = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
            .current_dir(directory.path())
            .env("LONEWOLF_WORKER_COUNT", workers.to_string())
            .stdout(Stdio::null())
            .stderr(fs::File::create(directory.path().join("server.log"))?)
            .spawn()?;
        Ok(Self { child, directory })
    }

    fn logs(&self) -> std::io::Result<String> {
        fs::read_to_string(self.directory.path().join("server.log"))
    }

    fn ready(&mut self, metrics_enabled: bool) -> Result<String, Box<dyn Error>> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let logs = self.logs()?;
            if self.child.try_wait()?.is_some() {
                return Err(format!("server exited before readiness: {logs}").into());
            }
            if logs.contains("c2s TCP listener started")
                && (!metrics_enabled || logs.contains("metrics service started"))
                && logs.contains("waiting for stop signal")
            {
                return Ok(logs);
            }
            if Instant::now() >= deadline {
                return Err(format!("server did not become ready: {logs}").into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait(&mut self) -> Result<ExitStatus, Box<dyn Error>> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!("server did not exit: {}", self.logs()?).into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(&mut self, signal: Signal) -> TestResult {
        kill(Pid::from_raw(self.child.id().try_into()?), signal)?;
        assert!(self.wait()?.success(), "{}", self.logs()?);
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn field(line: &str, key: &str) -> Result<usize, Box<dyn Error>> {
    line.split_whitespace()
        .find_map(|field| field.strip_prefix(key))
        .ok_or_else(|| format!("missing {key} in {line}").into())
        .and_then(|value| value.parse().map_err(Into::into))
}

fn request(port: u16, path: &str) -> Result<String, Box<dyn Error>> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[test]
fn enabled_metrics_serve_openmetrics_and_stop_with_the_server() -> TestResult {
    let (_reservation, address) = ports::reserve_listener_address()?;
    let mut server = Server::start(
        &format!(
            "[logging]\nlevel = 'debug'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[metrics]\nenabled = true\naddress = '{address}'\n[admin]\nenabled = false\n"
        ),
        2,
    )?;
    let logs = server.ready(true)?;
    let line = logs
        .lines()
        .find(|line| line.contains("metrics service started"))
        .ok_or("missing metrics start log")?;
    let port = field(line, "port=")?.try_into()?;
    assert_eq!(port, address.port());
    let response = request(port, "/metrics")?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or("missing response body")?;
    assert!(headers.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("content-type: application/openmetrics-text; version=1.0.0; charset=utf-8"),
        "{headers}"
    );
    assert!(
        body.lines().any(|line| line.starts_with(&format!(
            "lonewolf_build_info{{version=\"{}\"",
            env!("CARGO_PKG_VERSION")
        ))),
        "{body}"
    );
    assert!(
        body.lines()
            .any(|line| line.starts_with("process_cpu_seconds_total ")),
        "{body}"
    );
    assert!(
        body.lines()
            .any(|line| line == "lonewolf_log_dropped_lines_total 0"),
        "{body}"
    );
    assert!(body.ends_with("# EOF\n"), "{body}");
    assert!(request(port, "/missing")?.starts_with("HTTP/1.1 404"));
    server.stop(Signal::SIGTERM)?;
    assert!(server.logs()?.contains("metrics service stopped"));
    let _listener = ports::bind_released_listener(address, Instant::now() + TIMEOUT)?;
    Ok(())
}

#[test]
fn occupied_metrics_address_stops_startup_before_client_listeners() -> TestResult {
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut server = Server::start(
        &format!(
            "[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[metrics]\nenabled = true\naddress = '{}'\n",
            occupied.local_addr()?
        ),
        2,
    )?;
    assert_eq!(server.wait()?.code(), Some(1));
    let logs = server.logs()?;
    assert!(logs.contains("metrics service failed"), "{logs}");
    assert!(!logs.contains("c2s TCP listener started"), "{logs}");
    assert!(
        !server
            .directory
            .path()
            .join("run/lonewolf/admin.sock")
            .exists()
    );
    Ok(())
}

#[test]
fn metrics_are_disabled_by_default() -> TestResult {
    let mut server = Server::start(
        "[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[admin]\nenabled = false\n",
        2,
    )?;
    server.ready(false)?;
    server.stop(Signal::SIGINT)?;
    assert!(!server.logs()?.contains("metrics service started"));
    Ok(())
}
