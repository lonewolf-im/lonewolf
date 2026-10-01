// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::ClientConfig;

use super::{Client, PlainClient, TIMEOUT, TestResult, tls};

static ACTIVE_SERVERS: Mutex<usize> = Mutex::new(0);
static SERVER_SLOT: Condvar = Condvar::new();

struct C2sSuitePermit;

impl C2sSuitePermit {
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

impl Drop for C2sSuitePermit {
    fn drop(&mut self) {
        let mut active = ACTIVE_SERVERS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *active -= 1;
        SERVER_SLOT.notify_one();
    }
}

pub struct C2sSuite {
    _permit: C2sSuitePermit,
    child: Child,
    directory: tempfile::TempDir,
    pub address: SocketAddr,
    pub tls: Arc<ClientConfig>,
}

impl C2sSuite {
    pub fn start() -> TestResult<Self> {
        Self::configured("", "")
    }

    pub fn with_extensions(extensions: &str) -> TestResult<Self> {
        Self::with_hosts(&format!("[hosts.localhost]\nextensions = [{extensions}]"))
    }

    pub fn with_extensions_and_setup(
        extensions: &str,
        setup: impl FnOnce(&Path) -> TestResult,
    ) -> TestResult<Self> {
        Self::settings_with_setup(
            "",
            "",
            10,
            &format!("[hosts.localhost]\nextensions = [{extensions}]"),
            setup,
        )
    }

    pub fn with_extensions_limits_and_setup(
        extensions: &str,
        limits: &str,
        setup: impl FnOnce(&Path) -> TestResult,
    ) -> TestResult<Self> {
        Self::settings_with_setup(
            "",
            limits,
            10,
            &format!("[hosts.localhost]\nextensions = [{extensions}]"),
            setup,
        )
    }

    pub fn with_hosts(hosts: &str) -> TestResult<Self> {
        Self::settings("", "", 10, hosts)
    }

    pub fn with_limits(limits: &str) -> TestResult<Self> {
        Self::configured("", limits)
    }

    pub fn with_auth_mechanisms(mechanisms: &[&str]) -> TestResult<Self> {
        let listener = format!(
            "auth_mechanisms = [{}]",
            mechanisms
                .iter()
                .map(|name| format!("'{name}'"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        Self::configured(&listener, "")
    }

    fn configured(listener: &str, limits: &str) -> TestResult<Self> {
        Self::settings(listener, limits, 10, "")
    }

    pub fn resource_limit(limit: usize) -> TestResult<Self> {
        Self::settings("", "", limit, "")
    }

    fn settings(listener: &str, limits: &str, resources: usize, hosts: &str) -> TestResult<Self> {
        Self::settings_with_setup(listener, limits, resources, hosts, |_| Ok(()))
    }

    fn settings_with_setup(
        listener: &str,
        limits: &str,
        resources: usize,
        hosts: &str,
        setup: impl FnOnce(&Path) -> TestResult,
    ) -> TestResult<Self> {
        let permit = C2sSuitePermit::acquire();
        let directory = tempfile::tempdir()?;
        let tls = tls::configure(directory.path())?;
        fs::write(
            directory.path().join("lonewolf.toml"),
            format!(
                r#"
[xmpp]
stanza_pool_size_mib = 8
default_host = "localhost"
[[c2s.listeners]]
address = "127.0.0.1:0"
{listener}
{hosts}
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
        setup(directory.path())?;
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
                let logs = fs::read_to_string(self.directory.path().join("server.log"))?;
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

    pub fn tcp_client(&self) -> TestResult<PlainClient> {
        PlainClient::tcp(self)
    }

    pub fn tls_client(&self) -> TestResult<Client> {
        Client::encrypted(self)
    }

    pub fn unauthenticated_client(&self) -> TestResult<Client> {
        Client::secure(self)
    }

    pub fn authenticated_client(&self, username: &str, password: &str) -> TestResult<Client> {
        Client::authenticated(self, username, password)
    }

    pub fn connect(&self, username: &str, password: &str, resource: &str) -> TestResult<Client> {
        Client::connect(self, username, password, resource)
    }

    pub fn create_account(&self, username: &str, password: &str) -> TestResult {
        self.create_account_jid(&format!("{username}@localhost"), password)
    }

    pub fn create_account_jid(&self, jid: &str, password: &str) -> TestResult {
        let mut stream =
            UnixStream::connect(self.directory.path().join("run/lonewolf/admin.sock"))?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let body = serde_json::json!({
            "jid": jid,
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

    pub fn delete_account(&self, username: &str) -> TestResult {
        let mut stream =
            UnixStream::connect(self.directory.path().join("run/lonewolf/admin.sock"))?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        write!(
            stream,
            "DELETE /v1/accounts/{username}%40localhost HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        assert!(response.starts_with("HTTP/1.1 204 "), "{response}");
        Ok(())
    }
}

impl Drop for C2sSuite {
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
    lonewolf_core::run_with_extensions(
        None,
        lonewolf_core::BuildInfo {
            version: "integration-test",
            branch: "test",
            commit: "test",
        },
        super::extensions::catalog()?,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}
