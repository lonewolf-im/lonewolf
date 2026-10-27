// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

#[path = "../../support/readiness.rs"]
mod readiness;

use readiness::ReadinessSocket;

pub(super) const TIMEOUT: Duration = Duration::from_secs(10);
type TestResult = Result<(), Box<dyn Error>>;

pub(super) struct Server {
    child: Child,
    pub(super) directory: tempfile::TempDir,
    readiness: ReadinessSocket,
    metrics: Option<SocketAddr>,
}

impl Server {
    pub(super) fn start(config: &str, workers: usize) -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::write(
            directory.path().join("lonewolf.toml"),
            format!("[xmpp]\nstanza_pool_size_mib = 8\n{config}"),
        )?;
        let readiness = ReadinessSocket::bind()?;
        let child = readiness
            .configure(&mut Command::new(env!("CARGO_BIN_EXE_lonewolf")))
            .current_dir(directory.path())
            .env("LONEWOLF_WORKER_COUNT", workers.to_string())
            .stdout(Stdio::null())
            .stderr(fs::File::create(directory.path().join("server.log"))?)
            .spawn()?;
        Ok(Self {
            child,
            directory,
            readiness,
            metrics: None,
        })
    }

    pub(super) fn logs(&self) -> std::io::Result<String> {
        fs::read_to_string(self.directory.path().join("server.log"))
    }

    /// Waits for the readiness notification and returns the C2S addresses in configuration order.
    pub(super) fn ready(&mut self) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if self.child.try_wait()?.is_some() {
                return Err(format!("server exited before readiness: {}", self.logs()?).into());
            }
            if let Some(readiness) = self.readiness.receive(Duration::from_millis(10))? {
                self.metrics = readiness.metrics;
                return Ok(readiness.c2s);
            }
            if Instant::now() >= deadline {
                return Err(format!("server did not become ready: {}", self.logs()?).into());
            }
        }
    }

    pub(super) fn metrics_address(&self) -> Option<SocketAddr> {
        self.metrics
    }

    pub(super) fn wait(&mut self) -> Result<ExitStatus, Box<dyn Error>> {
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

    pub(super) fn stop(&mut self, signal: Signal) -> TestResult {
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

pub(super) fn field(line: &str, key: &str) -> Result<usize, Box<dyn Error>> {
    line.split_whitespace()
        .find_map(|field| field.strip_prefix(key))
        .ok_or_else(|| format!("missing {key} in {line}").into())
        .and_then(|value| value.parse().map_err(Into::into))
}

pub(super) fn request(address: SocketAddr, path: &str) -> Result<String, Box<dyn Error>> {
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
