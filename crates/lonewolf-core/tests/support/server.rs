// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::ClientConfig;

use super::{TIMEOUT, TestResult, tls};

static ACTIVE_SERVERS: Mutex<usize> = Mutex::new(0);
static SERVER_SLOT: Condvar = Condvar::new();

struct ServerPermit;

impl ServerPermit {
    fn acquire() -> Self {
        let active = ACTIVE_SERVERS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut active = SERVER_SLOT
            .wait_while(active, |count| *count >= 4)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *active += 1;
        Self
    }
}

impl Drop for ServerPermit {
    fn drop(&mut self) {
        let mut active = ACTIVE_SERVERS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *active -= 1;
        SERVER_SLOT.notify_one();
    }
}

pub struct Server {
    _permit: ServerPermit,
    child: Child,
    directory: tempfile::TempDir,
    pub address: SocketAddr,
    pub tls: Arc<ClientConfig>,
}

impl Server {
    pub fn start() -> TestResult<Self> {
        Self::configured("", "")
    }

    pub fn configured(listener: &str, limits: &str) -> TestResult<Self> {
        Self::settings(listener, limits, 10)
    }

    pub fn resource_limit(limit: usize) -> TestResult<Self> {
        Self::settings("", "", limit)
    }

    fn settings(listener: &str, limits: &str, resources: usize) -> TestResult<Self> {
        let permit = ServerPermit::acquire();
        let directory = tempfile::tempdir()?;
        let tls = tls::configure(directory.path())?;
        fs::write(
            directory.path().join("lonewolf.toml"),
            format!(
                r#"
[xmpp]
stanza_pool_size_mib = 8
[[c2s.listeners]]
address = "127.0.0.1:0"
{listener}
[hosts.localhost.tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
[limits.c2s]
max_resources_per_account = {resources}
[limits.c2s.profiles.default]
{limits}
"#
            ),
        )?;
        let child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "support::server::server_process",
                "--ignored",
                "--nocapture",
            ])
            .env("LONEWOLF_PROTOCOL_TEST_SERVER", "1")
            .current_dir(directory.path())
            .env("LONEWOLF_WORKER_COUNT", "2")
            .stdout(Stdio::null())
            .stderr(fs::File::create(directory.path().join("server.log"))?)
            .spawn()?;
        let mut server = Self {
            _permit: permit,
            child,
            directory,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            tls: Arc::new(tls),
        };
        server.wait_until_ready()?;
        Ok(server)
    }

    fn wait_until_ready(&mut self) -> TestResult {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let logs = fs::read_to_string(self.directory.path().join("server.log"))?;
            if self.child.try_wait()?.is_some() {
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
                    .ok_or("missing C2S listener port")?
                    .parse()?;
                self.address.set_port(port);
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("server did not become ready: {logs}").into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn wait_for_log(&self, event: &str) -> TestResult<String> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let logs = fs::read_to_string(self.directory.path().join("server.log"))?;
            if logs.contains(event) {
                return Ok(logs);
            }
            if Instant::now() >= deadline {
                return Err(format!("missing log event {event}: {logs}").into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn create_account(&self, username: &str, password: &str) -> TestResult {
        let mut stream =
            UnixStream::connect(self.directory.path().join("run/lonewolf/admin.sock"))?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let body = serde_json::json!({
            "jid": format!("{username}@localhost"),
            "password": password,
        })
        .to_string();
        write!(
            stream,
            "POST /v1/accounts HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len(),
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        assert!(response.starts_with("HTTP/1.1 201 "), "{response}");
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "subprocess entry point for the protocol fixture"]
fn server_process() -> TestResult {
    if std::env::var_os("LONEWOLF_PROTOCOL_TEST_SERVER").is_none() {
        return Ok(());
    }
    lonewolf_core::run(
        None,
        lonewolf_core::BuildInfo {
            version: "integration-test",
            branch: "test",
            commit: "test",
        },
    )?;
    Ok(())
}
