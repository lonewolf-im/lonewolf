// SPDX-License-Identifier: Apache-2.0

use super::{TIMEOUT, TestResult, tls};
use rustls::{ClientConfig, RootCertStore, SupportedProtocolVersion};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::ops::{Deref, DerefMut};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const CONFIG: &str = r#"[xmpp]
stanza_pool_size_mib = 8
default_host = "localhost"
[[c2s.listeners]]
address = "127.0.0.1:0"
auth_mechanisms = ["SCRAM-SHA-256"]
[hosts.localhost]
extensions = ["roster", "offline"]
[hosts.localhost.tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
[hosts.localhost.offline]
max_messages_per_account = 1000
[limits.c2s]
max_resources_per_account = 10
[limits.c2s.profiles.default]
max_connections_per_ip = 256
max_stanza_bytes = 65536
connection_attempts_per_ip = { per_second = 1000, burst = 128 }
incoming_stanzas_per_connection = { per_second = 100000, burst = 4096 }
incoming_xml_per_connection = { bytes_per_second = 67108864, burst_bytes = 67108864 }
"#;

pub struct C2sSuite {
    child: Child,
    directory: tempfile::TempDir,
    pub address: SocketAddr,
    pub tls: Arc<ClientConfig>,
    roots: RootCertStore,
    stopped: bool,
    watchdog_stop: Arc<AtomicBool>,
    timed_out: Arc<AtomicBool>,
    watchdog: Option<JoinHandle<()>>,
    controls: Arc<Mutex<Vec<Weak<TcpStream>>>>,
}

impl C2sSuite {
    pub fn start(binary: &Path) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let roots = tls::configure(directory.path())?;
        let config = tls::client_config(roots.clone(), rustls::DEFAULT_VERSIONS)?;
        fs::write(directory.path().join("lonewolf.toml"), CONFIG)?;
        let child = Command::new(binary)
            .current_dir(directory.path())
            .env("LONEWOLF_WORKER_COUNT", "2")
            .stdout(Stdio::null())
            .stderr(fs::File::create(directory.path().join("server.log"))?)
            .spawn()?;
        let pid = child.id();
        let watchdog_stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&watchdog_stop);
        let timed_out = Arc::new(AtomicBool::new(false));
        let timeout_latch = Arc::clone(&timed_out);
        let controls = Arc::new(Mutex::new(Vec::<Weak<TcpStream>>::new()));
        let deadline_controls = Arc::clone(&controls);
        let watchdog = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            while !stopped.load(Ordering::Relaxed) {
                if Instant::now() >= deadline {
                    timeout_latch.store(true, Ordering::Relaxed);
                    for socket in deadline_controls
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .iter()
                        .filter_map(Weak::upgrade)
                    {
                        let _ = socket.shutdown(Shutdown::Both);
                    }
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid as i32),
                        nix::sys::signal::Signal::SIGTERM,
                    );
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        let mut suite = Self {
            child,
            directory,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            tls: Arc::new(config),
            roots,
            stopped: false,
            watchdog_stop,
            timed_out,
            watchdog: Some(watchdog),
            controls,
        };
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let logs = fs::read_to_string(suite.directory.path().join("server.log"))?;
            if suite.child.try_wait()?.is_some() {
                return Err(format!("server exited before readiness: {logs}").into());
            }
            if logs.contains("waiting for stop signal") {
                let port = logs
                    .lines()
                    .find(|line| line.contains("c2s TCP listener started"))
                    .and_then(|line| {
                        line.split_whitespace()
                            .find_map(|part| part.strip_prefix("port="))
                    })
                    .ok_or("missing listener port")?
                    .parse()?;
                suite.address.set_port(port);
                return Ok(suite);
            }
            if Instant::now() >= deadline {
                return Err(format!("server startup timeout: {logs}").into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn tls_with_versions(
        &self,
        versions: &[&'static SupportedProtocolVersion],
    ) -> TestResult<Arc<ClientConfig>> {
        Ok(Arc::new(tls::client_config(self.roots.clone(), versions)?))
    }

    pub fn request(&self, method: &str, path: &str, body: &str) -> TestResult<(u16, Value)> {
        let mut socket =
            UnixStream::connect(self.directory.path().join("run/lonewolf/admin.sock"))?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        socket.set_write_timeout(Some(TIMEOUT))?;
        write!(
            socket,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )?;
        let mut response = String::new();
        socket.read_to_string(&mut response)?;
        let (headers, body) = response
            .split_once("\r\n\r\n")
            .ok_or("invalid HTTP response")?;
        let status = headers
            .split_whitespace()
            .nth(1)
            .ok_or("missing HTTP status")?
            .parse()?;
        let value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(body)?
        };
        Ok((status, value))
    }

    pub fn diagnostics(&self) -> TestResult<Option<Value>> {
        let (status, value) = self.request("GET", "/v1/diagnostics", "")?;
        Ok((status == 200).then_some(value))
    }

    pub fn account(&self, name: &str) -> TestResult {
        let (status, value) = self.request(
            "POST",
            "/v1/accounts",
            &serde_json::json!({"jid":format!("{name}@localhost"),"password":"capacity-password"})
                .to_string(),
        )?;
        if status != 201 {
            return Err(format!("account creation failed: {status} {value}").into());
        }
        Ok(())
    }

    pub fn wait_replay_acknowledgements(&self, recipients: usize) -> TestResult {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let logs = fs::read_to_string(self.directory.path().join("server.log"))?;
            let committed = (0..recipients).all(|index| {
                logs.lines().any(|line| {
                    line.contains("offline backlog acknowledgement handled")
                        && (line.contains("outcome=committed")
                            || line.contains("outcome=\"committed\""))
                        && line.contains(&format!("owner_jid=\"c{index:02}@localhost\""))
                })
            });
            if committed {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("replay acknowledgement did not commit".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn timed_out(&self) -> bool {
        self.timed_out.load(Ordering::Relaxed)
    }

    pub fn stop(&mut self) -> TestResult {
        self.watchdog_stop.store(true, Ordering::Relaxed);
        if let Some(status) = self.child.try_wait()? {
            self.stopped = true;
            self.watchdog_stop.store(true, Ordering::Relaxed);
            return if status.success() {
                Ok(())
            } else {
                Err(format!("server exited: {status}").into())
            };
        }
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.child.id().try_into()?),
            nix::sys::signal::Signal::SIGTERM,
        )?;
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.stopped = true;
                self.watchdog_stop.store(true, Ordering::Relaxed);
                if !status.success() {
                    return Err(format!("server shutdown failed: {status}").into());
                }
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("server shutdown exceeded deadline".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for C2sSuite {
    fn drop(&mut self) {
        self.watchdog_stop.store(true, Ordering::Relaxed);
        if let Some(watchdog) = self.watchdog.take() {
            let _ = watchdog.join();
        }
        if !self.stopped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub struct CapacityClient {
    inner: super::client::Client,
    _control: Arc<TcpStream>,
}

impl CapacityClient {
    pub fn connect(
        server: &C2sSuite,
        username: &str,
        password: &str,
        resource: &str,
    ) -> TestResult<Self> {
        let mut inner = super::client::Client::connect(server, username, password, resource)?;
        let control = Arc::new(inner.transport().sock.try_clone()?);
        server
            .controls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::downgrade(&control));
        Ok(Self {
            inner,
            _control: control,
        })
    }
}

impl Deref for CapacityClient {
    type Target = super::client::Client;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for CapacityClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
