// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::{Condvar as PlCondvar, Mutex as PlMutex};
use rustls::{ClientConfig, RootCertStore, SupportedProtocolVersion};

use super::readiness::ReadinessSocket;
use super::{Client, PlainClient, Signal, TIMEOUT, TestResult, tls};

static ACTIVE_SERVERS: PlMutex<usize> = PlMutex::new(0);
static SERVER_SLOT: PlCondvar = PlCondvar::new();

pub(super) struct C2sSuitePermit;

impl C2sSuitePermit {
    pub(super) fn acquire() -> Self {
        let mut active = ACTIVE_SERVERS.lock();
        SERVER_SLOT.wait_while(&mut active, |count| *count >= 4);
        *active += 1;
        Self
    }

    pub(super) fn pair() -> [Self; 2] {
        let mut active = ACTIVE_SERVERS.lock();
        SERVER_SLOT.wait_while(&mut active, |count| *count > 2);
        *active += 2;
        [Self, Self]
    }
}

fn spawn_process(directory: &Path, readiness: &ReadinessSocket) -> std::io::Result<Child> {
    super::federation::remove_shutdown_receipt(directory)?;
    readiness
        .configure(&mut Command::new(std::env::current_exe()?))
        .args([
            "--exact",
            "support::server::server_process",
            "--ignored",
            "--nocapture",
        ])
        .env("LONEWOLF_PROTOCOL_TEST_SERVER", "1")
        .current_dir(directory)
        .env("LONEWOLF_WORKER_COUNT", "2")
        .stdout(Stdio::null())
        .stderr(fs::File::create(directory.join("server.log"))?)
        .spawn()
}

impl Drop for C2sSuitePermit {
    fn drop(&mut self) {
        let mut active = ACTIVE_SERVERS.lock();
        *active -= 1;
        SERVER_SLOT.notify_all();
    }
}

pub struct C2sSuite {
    permit: Option<C2sSuitePermit>,
    pub domain: String,
    completion: Option<super::federation::ProcessReceipts>,
    reaped: bool,
    child: Child,
    directory: tempfile::TempDir,
    readiness: ReadinessSocket,
    pub address: SocketAddr,
    pub s2s: Option<Vec<SocketAddr>>,
    federation_enabled: bool,
    listeners: Vec<SocketAddr>,
    metrics: SocketAddr,
    pub tls: Arc<ClientConfig>,
    tls_roots: RootCertStore,
}

impl C2sSuite {
    pub(super) fn client_domain_override(&self) -> Option<&str> {
        Some(&self.domain)
    }

    pub fn fixture_path(&self) -> &Path {
        self.directory.path()
    }

    pub fn start() -> TestResult<Self> {
        Self::configured("", "")
    }

    pub fn metrics_address(&self) -> SocketAddr {
        self.metrics
    }

    pub fn scrape_metrics(&self) -> TestResult<String> {
        let mut stream = TcpStream::connect_timeout(&self.metrics_address(), TIMEOUT)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
        let (_, body) = response
            .split_once("\r\n\r\n")
            .ok_or("missing metrics response body")?;
        Ok(body.to_owned())
    }

    pub fn wait_for_metric(&self, sample: &str) -> TestResult<String> {
        self.wait_for_metrics(sample, |body| body.lines().any(|line| line == sample))
    }

    pub fn wait_for_metrics(
        &self,
        expected: &str,
        ready: impl Fn(&str) -> bool,
    ) -> TestResult<String> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let body = self.scrape_metrics()?;
            if ready(&body) {
                return Ok(body);
            }
            if Instant::now() >= deadline {
                return Err(format!("missing metrics {expected}: {body}").into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn wait_for_closed(&self, outcome: &str, count: u64) -> TestResult {
        let series = format!(",outcome=\"{outcome}\"}} ");
        self.wait_for_metrics(
            &format!("{count} connections closed with {outcome}"),
            |body| {
                body.lines()
                    .filter(|line| line.starts_with("lonewolf_c2s_connections_closed_total{"))
                    .filter_map(|line| line.split_once(&series))
                    .filter_map(|(_, value)| value.parse::<u64>().ok())
                    .sum::<u64>()
                    >= count
            },
        )?;
        Ok(())
    }

    pub fn wait_for_signal(&self, signal: Signal, count: u64) -> TestResult {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let raised = self.signal_count(signal)?;
            if raised >= count {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let logs = fs::read_to_string(self.directory.path().join("server.log"))?;
                return Err(format!("{signal:?} raised {raised} of {count} times: {logs}").into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn signal_count(&self, signal: Signal) -> TestResult<u64> {
        match fs::metadata(signal.path(self.fixture_path())) {
            Ok(metadata) => Ok(metadata.len()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error.into()),
        }
    }

    /// Returns the full log after a clean stop and fails if earlier lines were dropped.
    pub fn stop_with_logs(&mut self) -> TestResult<String> {
        let metrics = self.scrape_metrics()?;
        assert!(
            metrics
                .lines()
                .any(|line| line == "lonewolf_log_dropped_lines_total 0"),
            "{metrics}"
        );
        self.stop()?;
        Ok(fs::read_to_string(
            self.directory.path().join("server.log"),
        )?)
    }

    pub fn stop_with_s2s_state(
        &mut self,
    ) -> TestResult<Option<lonewolf_core::test_support::S2sShutdownState>> {
        self.stop()?;
        let status = self.child.try_wait()?.ok_or("server has not been reaped")?;
        if !self.reaped || !status.success() {
            return Err("server did not complete successfully".into());
        }
        super::federation::read_shutdown_receipt(self.directory.path(), self.child.id())
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

    pub fn with_hosts_and_setup(
        hosts: &str,
        setup: impl FnOnce(&Path) -> TestResult,
    ) -> TestResult<Self> {
        Self::settings_with_setup("", "", 10, hosts, setup)
    }

    pub fn with_hosts_and_profile(hosts: &str, default: &str) -> TestResult<Self> {
        Self::settings_with_profile("", "", 10, hosts, Some(default), |_| Ok(()))
    }

    pub fn with_limits(limits: &str) -> TestResult<Self> {
        Self::configured("", limits)
    }

    pub fn with_profile_settings(default: &str, limits: &str) -> TestResult<Self> {
        Self::settings_with_profile("", limits, 10, "", Some(default), |_| Ok(()))
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
        Self::settings_with_profile(listener, limits, resources, hosts, None, setup)
    }

    fn settings_with_profile(
        listener: &str,
        limits: &str,
        resources: usize,
        hosts: &str,
        default: Option<&str>,
        setup: impl FnOnce(&Path) -> TestResult,
    ) -> TestResult<Self> {
        Self::settings_with_federation(listener, limits, resources, hosts, default, None, setup)
    }

    pub fn with_federation_and_setup(
        hosts: &str,
        federation: &str,
        setup: impl FnOnce(&Path) -> TestResult,
    ) -> TestResult<Self> {
        Self::settings_with_federation("", "", 10, hosts, None, Some(federation), setup)
    }

    fn settings_with_federation(
        listener: &str,
        limits: &str,
        resources: usize,
        hosts: &str,
        default: Option<&str>,
        federation: Option<&str>,
        setup: impl FnOnce(&Path) -> TestResult,
    ) -> TestResult<Self> {
        let federation_enabled = federation.is_some();
        let federation = federation.unwrap_or("[s2s]\nenabled = false");
        let permit = C2sSuitePermit::acquire();
        let directory = tempfile::tempdir()?;
        let tls_roots = tls::configure(directory.path())?;
        let tls = tls::client_config(tls_roots.clone(), rustls::DEFAULT_VERSIONS)?;
        let default = default.map_or_else(String::new, |name| format!("default = {name:?}"));
        fs::write(
            directory.path().join("lonewolf.toml"),
            format!(
                r#"
[xmpp]
stanza_pool_size_mib = 8
default_host = "localhost"
[metrics]
enabled = true
address = "127.0.0.1:0"
[[c2s.listeners]]
address = "127.0.0.1:0"
{listener}
{hosts}
{federation}
[hosts.localhost.tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
[limits.c2s]
max_resources_per_account = {resources}
{default}
[limits.c2s.profiles.default]
{limits}
"#
            ),
        )?;
        setup(directory.path())?;
        let readiness = ReadinessSocket::bind()?;
        let child = spawn_process(directory.path(), &readiness)?;
        let mut server = Self {
            permit: Some(permit),
            domain: "localhost".into(),
            completion: None,
            reaped: false,
            child,
            directory,
            readiness,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            listeners: Vec::new(),
            s2s: None,
            federation_enabled,
            metrics: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            tls: Arc::new(tls),
            tls_roots,
        };
        server.wait_until_ready()?;
        Ok(server)
    }

    pub fn federated(host: super::federation::FederatedHost) -> TestResult<Self> {
        Self::federated_with_permit(host, C2sSuitePermit::acquire())
    }

    pub(super) fn federated_with_permit(
        host: super::federation::FederatedHost,
        permit: C2sSuitePermit,
    ) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        host.ca.server(directory.path(), "host", &[&host.domain])?;
        let tls_roots = host.ca.roots()?;
        let tls = tls::client_config(tls_roots.clone(), rustls::DEFAULT_VERSIONS)?;
        let config = format!(
            r#"
[xmpp]
stanza_pool_size_mib = 8
default_host = {domain:?}
[metrics]
enabled = true
address = "127.0.0.1:0"
[[c2s.listeners]]
address = "127.0.0.1:0"
[hosts.{domain:?}]
{host_federation}
extensions = [{extensions}]
[hosts.{domain:?}.tls]
certificate_chain_path = "certificate-host.pem"
private_key_path = "private-key-host.pem"
[s2s]
{enabled}
listeners = [{{ address = "127.0.0.1:0" }}]
[s2s.tls]
trust_anchors_path = {anchors:?}
[s2s.dns]
nameservers = [{dns:?}]
timeout_secs = 1
{extra}
"#,
            domain = host.domain,
            extensions = host.extensions,
            anchors = host.ca.trust_anchors_path(),
            dns = host.dns.to_string(),
            extra = host.extra_toml,
            host_federation = host
                .federation
                .map(|enabled| format!("federation = {enabled}"))
                .unwrap_or_default(),
            enabled = host
                .enabled
                .map(|enabled| format!("enabled = {enabled}"))
                .unwrap_or_default(),
        );
        let federation_enabled = host.enabled.unwrap_or(true) && host.federation.unwrap_or(true);
        fs::write(directory.path().join("lonewolf.toml"), config)?;
        let readiness = ReadinessSocket::bind()?;
        let child = spawn_process(directory.path(), &readiness)?;
        if let Some(receipts) = &host.completion {
            receipts.lock().spawned.push(child.id());
        }
        let mut server = Self {
            permit: Some(permit),
            domain: host.domain,
            completion: host.completion,
            reaped: false,
            child,
            directory,
            readiness,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            s2s: None,
            federation_enabled,
            listeners: Vec::new(),
            metrics: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            tls: Arc::new(tls),
            tls_roots,
        };
        server.wait_until_ready()?;
        Ok(server)
    }

    pub fn s2s_addresses(&self) -> TestResult<&[SocketAddr]> {
        self.s2s
            .as_deref()
            .ok_or_else(|| "missing S2S listeners".into())
    }

    fn record_reaped(&mut self, status: std::process::ExitStatus) {
        if !self.reaped {
            if let Some(receipts) = &self.completion {
                receipts.lock().reaped.push((self.child.id(), status));
            }
            self.reaped = true;
        }
    }

    pub fn restart(&mut self) -> TestResult {
        self.stop()?;
        self.child = spawn_process(self.directory.path(), &self.readiness)?;
        self.reaped = false;
        if let Some(receipts) = &self.completion {
            receipts.lock().spawned.push(self.child.id());
        }
        self.wait_until_ready()
    }

    pub fn tls_with_versions(
        &self,
        versions: &[&'static SupportedProtocolVersion],
    ) -> TestResult<Arc<ClientConfig>> {
        Ok(Arc::new(tls::client_config(
            self.tls_roots.clone(),
            versions,
        )?))
    }

    fn wait_until_ready(&mut self) -> TestResult {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.record_reaped(status);
                let logs = fs::read_to_string(self.directory.path().join("server.log"))?;
                return Err(format!("server exited before readiness: {logs}").into());
            }
            if let Some(readiness) = self.readiness.receive(Duration::from_millis(10))? {
                assert_eq!(readiness.s2s.is_some(), self.federation_enabled);
                self.s2s = readiness.s2s;
                self.address = *readiness.c2s.first().ok_or("no C2S listener is ready")?;
                self.metrics = readiness.metrics.ok_or("metrics service is not ready")?;
                self.listeners = readiness.c2s;
                if let Some(receipts) = &self.completion {
                    receipts.lock().ready.push(self.child.id());
                }
                return Ok(());
            }
            if Instant::now() >= deadline {
                let logs = fs::read_to_string(self.directory.path().join("server.log"))?;
                return Err(format!("server did not become ready: {logs}").into());
            }
        }
    }

    pub fn listener_address(&self, listener_id: usize) -> TestResult<SocketAddr> {
        Ok(*self
            .listeners
            .get(listener_id)
            .ok_or("missing listener address")?)
    }

    pub fn wait_for_failure(&mut self) -> TestResult<String> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.record_reaped(status);
                let logs = fs::read_to_string(self.directory.path().join("server.log"))?;
                assert_eq!(status.code(), Some(101), "status={status} logs={logs}");
                return Ok(logs);
            }
            if Instant::now() >= deadline {
                return Err("server did not exit after failure".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn stop(&mut self) -> TestResult {
        if let Some(status) = self.child.try_wait()? {
            self.record_reaped(status);
            assert!(status.success(), "{status}");
            return Ok(());
        }
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.child.id().try_into()?),
            nix::sys::signal::Signal::SIGINT,
        )?;
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.record_reaped(status);
                assert!(status.success(), "{status}");
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("server did not stop".into());
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
        self.create_account_jid(&format!("{username}@{}", self.domain), password)
    }

    pub fn create_account_jid(&self, jid: &str, password: &str) -> TestResult {
        let mut stream = UnixStream::connect(self.fixture_path().join("run/lonewolf/admin.sock"))?;
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

    pub fn change_password(&self, username: &str, password: &str) -> TestResult {
        assert!(
            self.password_change_response(username, password)?
                .starts_with("HTTP/1.1 204 ")
        );
        Ok(())
    }

    pub fn reject_weak_password_change(&self, username: &str, password: &str) -> TestResult {
        let response = self.password_change_response(username, password)?;
        assert!(response.starts_with("HTTP/1.1 400 "));
        let (_, body) = response
            .split_once("\r\n\r\n")
            .ok_or("missing response body")?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body)?,
            serde_json::json!({"error":{"code":"weak_password"}})
        );
        Ok(())
    }

    fn password_change_response(&self, username: &str, password: &str) -> TestResult<String> {
        let mut stream = UnixStream::connect(self.fixture_path().join("run/lonewolf/admin.sock"))?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let body = serde_json::json!({ "password": password }).to_string();
        write!(
            stream,
            "PUT /v1/accounts/{username}%40{domain}/password HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len(),
            domain = self.domain,
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    pub fn delete_account(&self, username: &str) -> TestResult {
        let mut stream = UnixStream::connect(self.fixture_path().join("run/lonewolf/admin.sock"))?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        write!(
            stream,
            "DELETE /v1/accounts/{username}%40{domain} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            domain = self.domain,
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        assert!(response.starts_with("HTTP/1.1 204 "), "{response}");
        Ok(())
    }
}

impl C2sSuite {
    pub(super) fn terminate_and_reap(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            if let Ok(status) = self.child.wait() {
                self.record_reaped(status);
            }
        }
        if self.reaped {
            self.permit.take();
        }
    }
}

impl Drop for C2sSuite {
    fn drop(&mut self) {
        self.terminate_and_reap();
    }
}

#[test]
#[ignore = "subprocess entry point for the protocol fixture"]
fn server_process() -> TestResult {
    if std::env::var_os("LONEWOLF_PROTOCOL_TEST_SERVER").is_none() {
        return Ok(());
    }
    let state = lonewolf_core::test_support::run_with_extensions_and_s2s_shutdown_state(
        None,
        lonewolf_core::BuildInfo {
            version: "integration-test",
            branch: "test",
            commit: "test",
        },
        super::extensions::catalog()?,
    )
    .map_err(|error| error.to_string())?;
    super::federation::write_shutdown_receipt(&std::env::current_dir()?, state)
}
