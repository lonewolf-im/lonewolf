// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
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
            format!("[logging]\nlevel = 'trace'\n[xmpp]\nstanza_pool_size_mib = 8\n{config}"),
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

    fn ready(&mut self, listener_count: usize) -> Result<String, Box<dyn Error>> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let logs = self.logs()?;
            if self.child.try_wait()?.is_some() {
                return Err(format!("server exited before readiness: {logs}").into());
            }
            if logs.matches("c2s TCP listener started").count() == listener_count
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

#[test]
fn multiple_endpoints_share_ports_across_workers_and_shutdown_with_admin() -> TestResult {
    let workers = thread::available_parallelism()?.get().min(2);
    let mut server = Server::start(
        "[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n",
        workers,
    )?;
    let logs = server.ready(2 * workers)?;
    let mut ports = [0_u16; 2];
    let mut sockets = std::collections::BTreeSet::new();
    for line in logs
        .lines()
        .filter(|line| line.contains("c2s TCP listener started"))
    {
        let listener = field(line, "listener_id=")?;
        let worker = field(line, "worker_id=")?;
        let port = field(line, "port=")?.try_into()?;
        assert!(listener < 2);
        assert!(worker < workers);
        assert!(sockets.insert((listener, worker)));
        if ports[listener] == 0 {
            ports[listener] = port;
        }
        assert_eq!(ports[listener], port);
    }
    assert_ne!(ports[0], ports[1]);
    assert!(!ports.contains(&0));
    for port in ports {
        for _ in 0..16 {
            let mut stream = TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                TIMEOUT,
            )?;
            stream.set_read_timeout(Some(TIMEOUT))?;
            assert_eq!(stream.read(&mut [0; 1])?, 0);
        }
    }
    let socket = server.directory.path().join("run/lonewolf/admin.sock");
    let mut admin = UnixStream::connect(&socket)?;
    admin.set_read_timeout(Some(TIMEOUT))?;
    admin.write_all(b"GET /v1/accounts HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    let mut response = String::new();
    admin.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 200"));
    server.stop(Signal::SIGTERM)?;
    assert!(!socket.exists());
    let logs = server.logs()?;
    assert_eq!(
        logs.matches("c2s TCP listener stopped").count(),
        2 * workers
    );
    assert_eq!(logs.matches("c2s connection closed").count(), 32);
    assert!(logs.contains("core dispatcher stopped"));
    assert!(!logs.contains("127.0.0.1"));
    for port in ports {
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
    }
    Ok(())
}

#[test]
fn c2s_runs_without_admin_and_stops_on_sigint() -> TestResult {
    let mut server = Server::start(
        "[admin]\nenabled = false\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n",
        1,
    )?;
    let logs = server.ready(1)?;
    assert!(!logs.contains("admin service started"));
    server.stop(Signal::SIGINT)?;
    assert!(server.logs()?.contains("c2s TCP listener stopped"));
    Ok(())
}

#[test]
fn empty_listener_list_keeps_signal_handling_active() -> TestResult {
    let mut server = Server::start("[admin]\nenabled = false\n[c2s]\nlisteners = []\n", 1)?;
    server.ready(0)?;
    server.stop(Signal::SIGTERM)?;
    assert!(!server.logs()?.contains("c2s TCP listener"));
    Ok(())
}

#[test]
fn occupied_endpoint_stops_started_listeners_and_removes_admin_socket() -> TestResult {
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut server = Server::start(
        &format!(
            "[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[[c2s.listeners]]\naddress = '{}'\n",
            occupied.local_addr()?
        ),
        1,
    )?;
    assert_eq!(server.wait()?.code(), Some(1));
    let logs = server.logs()?;
    assert!(logs.contains("c2s listener service failed: listener 1 on worker 0"));
    assert!(logs.contains("c2s TCP listener stopped"));
    assert!(logs.contains("core dispatcher stopped"));
    assert!(
        !server
            .directory
            .path()
            .join("run/lonewolf/admin.sock")
            .exists()
    );
    let started = logs
        .lines()
        .find(|line| line.contains("c2s TCP listener started"))
        .ok_or("missing listener start log")?;
    let port = u16::try_from(field(started, "port=")?)?;
    let _rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    Ok(())
}
