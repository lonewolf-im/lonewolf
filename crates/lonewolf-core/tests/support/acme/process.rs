// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use futures_executor::block_on;
use lonewolf_acme::{StateStore, StoredAccount, StoredHost};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rustls::{ClientConfig, SupportedProtocolVersion};

use super::{Client, FakeAcmeCa, PASSWORD, PlainClient, TIMEOUT, TLS_NAMESPACE, TestResult, tls};

pub struct AcmeServer {
    pub directory: tempfile::TempDir,
    child: Option<Child>,
    pub address: SocketAddr,
    pub challenge: SocketAddr,
    pub tls: Arc<ClientConfig>,
    pub roots: rustls::RootCertStore,
    pub directory_url: String,
    reservation: Option<TcpListener>,
    pub launch_count: usize,
    pub setup_retries: usize,
    pub setup_failures: Vec<SetupFailure>,
}

pub struct SetupFailure {
    pub logs: String,
    pub ca_unchanged: bool,
    pub state_unchanged: bool,
}

struct StartBudget {
    deadline: Instant,
    launches: usize,
}
impl StartBudget {
    fn claim(&mut self) -> bool {
        if self.launches >= 3 || Instant::now() >= self.deadline {
            return false;
        }
        self.launches += 1;
        true
    }
}

fn retryable_bind_failure(
    owned: bool,
    reaped: bool,
    status: ExitStatus,
    logs: &str,
    unchanged: bool,
) -> bool {
    owned
        && reaped
        && status.code() == Some(1)
        && unchanged
        && logs.lines().last() == Some("ACME HTTP bind failed: ACME listener operation failed")
        && ![
            "ACME listener bound",
            "c2s TCP listener started",
            "waiting for stop signal",
        ]
        .iter()
        .any(|event| logs.contains(event))
}
impl AcmeServer {
    pub fn configure(ca: &FakeAcmeCa, hosts: &str, extra: &str) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let reservation = TcpListener::bind("127.0.0.1:0")?;
        let challenge = reservation.local_addr()?;
        fs::write(
            directory.path().join("lonewolf.toml"),
            format!(
                r#"
[xmpp]
stanza_pool_size_mib = 8
default_host = "xmpp.example.test"
[[c2s.listeners]]
address = "127.0.0.1:0"
[letsencrypt]
listen = ["{challenge}"]
state_path = "acme/state.redb"
directory_url = {:?}
ca_certificates_path = {:?}
{hosts}
{extra}
"#,
                ca.directory_url(),
                ca.trust_bundle_path()
            ),
        )?;
        ca.callback(challenge);
        let roots = ca.roots.clone();
        let tls = Arc::new(tls::client_config(roots.clone(), rustls::DEFAULT_VERSIONS)?);
        Ok(Self {
            directory,
            child: None,
            address: "127.0.0.1:0".parse()?,
            challenge,
            tls,
            roots,
            directory_url: ca.directory_url(),
            reservation: Some(reservation),
            launch_count: 0,
            setup_retries: 0,
            setup_failures: Vec::new(),
        })
    }
    pub fn managed(ca: &FakeAcmeCa) -> TestResult<Self> {
        Self::configure(
            ca,
            "[hosts.\"xmpp.example.test\".tls]\nprovider = 'letsencrypt'",
            "",
        )
    }
    pub fn path(&self) -> &Path {
        self.directory.path()
    }
    pub fn config(&self) -> TestResult<String> {
        Ok(fs::read_to_string(self.path().join("lonewolf.toml"))?)
    }
    pub fn replace_config(&self, text: &str) -> TestResult {
        fs::write(self.path().join("lonewolf.toml"), text)?;
        Ok(())
    }
    pub fn spawn(&mut self) -> TestResult {
        assert!(self.child.is_none());
        self.reservation.take();
        self.child = Some(
            Command::new(env!("CARGO_BIN_EXE_lonewolf"))
                .current_dir(self.path())
                .env("LONEWOLF_WORKER_COUNT", "2")
                .stdout(Stdio::null())
                .stderr(fs::File::create(self.path().join("server.log"))?)
                .spawn()?,
        );
        self.launch_count += 1;
        Ok(())
    }
    pub fn reserve_listener(&mut self, listener: TcpListener) -> TestResult {
        let address = listener.local_addr()?;
        self.retarget(address)?;
        self.reservation = Some(listener);
        Ok(())
    }
    fn retarget(&mut self, address: SocketAddr) -> TestResult {
        let config = self.config()?;
        let previous = format!("listen = [\"{}\"]", self.challenge);
        if config.lines().filter(|line| *line == previous).count() != 1 {
            return Err("fixture does not own one listener assignment".into());
        }
        self.replace_config(&config.replacen(&previous, &format!("listen = [\"{address}\"]"), 1))?;
        self.challenge = address;
        Ok(())
    }
    fn state_bytes(&self) -> TestResult<Option<Vec<u8>>> {
        match fs::read(self.path().join("acme/state.redb")) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    pub fn start(&mut self, ca: &FakeAcmeCa) -> TestResult {
        self.start_with_route(ca, |address| ca.callback(address))
    }
    pub fn start_with_route(
        &mut self,
        ca: &FakeAcmeCa,
        mut update_route: impl FnMut(SocketAddr),
    ) -> TestResult {
        let mut budget = StartBudget {
            deadline: Instant::now() + TIMEOUT,
            launches: 0,
        };
        while budget.claim() {
            let owned = self.challenge.ip().is_loopback()
                && self.challenge.port() != 0
                && lonewolf_core::config::Config::load(Some(&self.path().join("lonewolf.toml")))
                    .is_ok_and(|config| config.letsencrypt.listen.as_slice() == [self.challenge]);
            let before_ca = ca.counts();
            let before_state = self.state_bytes()?;
            update_route(self.challenge);
            if Instant::now() >= budget.deadline {
                return Err("ACME fixture startup deadline elapsed".into());
            }
            self.spawn()?;
            let Some(status) = self.ready_until(budget.deadline)? else {
                return Ok(());
            };
            let logs = self.logs()?;
            fs::write(
                self.path()
                    .join(format!("startup-failure-{}.log", self.launch_count)),
                &logs,
            )?;
            let ca_unchanged = ca.counts() == before_ca;
            let state_unchanged = self.state_bytes()? == before_state;
            let eligible = retryable_bind_failure(
                owned,
                self.child.is_none(),
                status,
                &logs,
                ca_unchanged && state_unchanged,
            );
            self.setup_failures.push(SetupFailure {
                logs: logs.clone(),
                ca_unchanged,
                state_unchanged,
            });
            if !eligible || budget.launches == 3 || Instant::now() >= budget.deadline {
                return Err(format!(
                    "server startup failed after {} launch(es): {logs}",
                    budget.launches
                )
                .into());
            }
            let reservation = TcpListener::bind(SocketAddr::new(self.challenge.ip(), 0))?;
            self.retarget(reservation.local_addr()?)?;
            update_route(self.challenge);
            self.reservation = Some(reservation);
            self.setup_retries += 1;
            eprintln!(
                "ACME fixture bind-phase setup retry {}/3",
                budget.launches + 1
            );
        }
        Err("ACME fixture startup budget exhausted".into())
    }
    fn ready_until(&mut self, deadline: Instant) -> TestResult<Option<ExitStatus>> {
        loop {
            if Instant::now() >= deadline {
                return Err("ACME fixture readiness deadline elapsed".into());
            }
            let logs = self.logs()?;
            if let Some(status) = self.child.as_mut().ok_or("missing child")?.try_wait()? {
                self.child.take();
                return Ok(Some(status));
            }
            if logs.contains("waiting for stop signal") {
                let port = logs
                    .lines()
                    .find(|line| line.contains("c2s TCP listener started"))
                    .and_then(|line| {
                        line.split_whitespace()
                            .find_map(|f| f.strip_prefix("port="))
                    })
                    .ok_or("listener port")?
                    .parse()?;
                self.address.set_port(port);
                return Ok(None);
            }
            if Instant::now() >= deadline {
                return Err(format!("server not ready: {logs}").into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn logs(&self) -> TestResult<String> {
        Ok(fs::read_to_string(self.path().join("server.log"))?)
    }
    pub fn wait_log(&self, event: &str) -> TestResult<String> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let logs = self.logs()?;
            if logs.contains(event) {
                return Ok(logs);
            }
            if Instant::now() >= deadline {
                return Err(format!("missing {event}: {logs}").into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn wait_exit(&mut self) -> TestResult<ExitStatus> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.as_mut().ok_or("missing child")?.try_wait()? {
                self.child.take();
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!("child still running: {}", self.logs()?).into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn stop(&mut self, signal: Signal) -> TestResult<ExitStatus> {
        kill(
            Pid::from_raw(
                self.child
                    .as_ref()
                    .ok_or("missing child")?
                    .id()
                    .try_into()?,
            ),
            signal,
        )?;
        self.wait_exit()
    }
    pub fn kill(&mut self) -> TestResult {
        self.child.as_mut().ok_or("missing child")?.kill()?;
        let status = self.wait_exit()?;
        assert!(!status.success());
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let probe = socket2::Socket::new(
                socket2::Domain::for_address(self.challenge),
                socket2::Type::STREAM,
                None,
            )?;
            probe.set_reuse_address(true)?;
            match probe.bind(&self.challenge.into()) {
                Ok(()) => break,
                Err(error)
                    if error.kind() == std::io::ErrorKind::AddrInUse
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => {
                    return Err(format!("post-kill challenge listener still owned: {error}").into());
                }
            }
        }
        let socket = self.path().join("run/lonewolf/admin.sock");
        if socket.try_exists()? {
            fs::remove_file(socket)?;
        }
        Ok(())
    }
    pub fn tls_with_versions(
        &self,
        versions: &[&'static SupportedProtocolVersion],
    ) -> TestResult<Arc<ClientConfig>> {
        Ok(Arc::new(tls::client_config(self.roots.clone(), versions)?))
    }
    pub fn plain(&self, domain: &str) -> TestResult<PlainClient> {
        let socket = TcpStream::connect_timeout(&self.address, TIMEOUT)?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        socket.set_write_timeout(Some(TIMEOUT))?;
        socket.set_nodelay(true)?;
        let mut client = PlainClient::new(socket);
        client.open_with(&format!("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='{domain}' version='1.0'>"))?;
        client.features()?.child(TLS_NAMESPACE, "starttls")?;
        Ok(client)
    }
    pub fn encrypted(&self, domain: &str, config: Arc<ClientConfig>) -> TestResult<Client> {
        let mut plain = self.plain(domain)?;
        plain.send(&format!("<starttls xmlns='{TLS_NAMESPACE}'/>"))?;
        let reply = plain.receive()?;
        if reply.namespace != TLS_NAMESPACE || reply.name != "proceed" {
            return Err(format!("STARTTLS unavailable: {reply:?}").into());
        }
        let socket = plain.into_inner();
        assert!(socket.buffer().is_empty());
        let connection = rustls::ClientConnection::new(
            config,
            rustls::pki_types::ServerName::try_from(idna::domain_to_ascii(domain)?)?,
        )?;
        let mut client = Client::new(rustls::StreamOwned::new(connection, socket.into_inner()));
        while client.transport().conn.is_handshaking() {
            let transport = client.transport();
            transport.conn.complete_io(&mut transport.sock)?;
        }
        Ok(client)
    }
    pub fn secure(&self, domain: &str) -> TestResult<Client> {
        let mut client = self.encrypted(domain, self.tls.clone())?;
        client.open_with(&format!("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='{domain}' version='1.0'>"))?;
        client.features()?;
        Ok(client)
    }
    pub fn wait_certificate(&self, old: Option<&[u8]>) -> TestResult<Vec<u8>> {
        let deadline = Instant::now() + TIMEOUT;
        let mut last_error = String::new();
        loop {
            match self.encrypted("xmpp.example.test", self.tls.clone()) {
                Ok(mut client) => {
                    let cert = peer(&mut client)?;
                    if old.is_none_or(|old| old != cert) {
                        return Ok(cert);
                    }
                }
                Err(error) => last_error = error.to_string(),
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "certificate not installed ({last_error}): {}",
                    self.logs()?
                        .lines()
                        .filter(|line| line.contains("ACME"))
                        .rev()
                        .take(10)
                        .collect::<Vec<_>>()
                        .join("\n")
                )
                .into());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    pub fn account(&self, domain: &str) -> TestResult {
        let mut stream = UnixStream::connect(self.path().join("run/lonewolf/admin.sock"))?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let body =
            serde_json::json!({"jid":format!("alice@{domain}"),"password":PASSWORD}).to_string();
        write!(
            stream,
            "POST /v1/accounts HTTP/1.1\r\nHost: xmpp.example.test\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        assert!(response.starts_with("HTTP/1.1 201 "), "{response}");
        Ok(())
    }
    pub fn state(&self) -> TestResult<StateStore> {
        assert!(self.child.is_none(), "inspect state only after exit");
        Ok(block_on(StateStore::open(
            self.path().join("acme/state.redb"),
            self.directory_url.clone(),
        ))?)
    }
    pub fn records(&self) -> TestResult<(StoredAccount, Option<StoredHost>)> {
        let store = self.state()?;
        let account = block_on(store.account())?.ok_or("missing durable account")?;
        let host = block_on(store.host("xmpp.example.test".into()))?;
        Ok((account, host))
    }
    pub fn metrics(&self) -> TestResult<String> {
        let logs = self.logs()?;
        let port = logs
            .lines()
            .find(|line| line.contains("metrics service started"))
            .and_then(|line| {
                line.split_whitespace()
                    .find_map(|s| s.strip_prefix("port="))
            })
            .ok_or("metrics port")?;
        super::http_get(
            format!("127.0.0.1:{port}").parse()?,
            "xmpp.example.test",
            "/metrics",
        )
    }
}
impl Drop for AcmeServer {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
pub fn peer(client: &mut Client) -> TestResult<Vec<u8>> {
    Ok(client
        .transport()
        .conn
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or("peer certificate")?
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn setup_retry_classifier_rejects_nonbind_signals_mutation_and_readiness() {
        let failure = "ACME HTTP bind failed: ACME listener operation failed\n";
        let ordinary = ExitStatus::from_raw(1 << 8);
        assert!(retryable_bind_failure(true, true, ordinary, failure, true));
        for (owned, reaped, unchanged) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            assert!(!retryable_bind_failure(
                owned, reaped, ordinary, failure, unchanged
            ));
        }
        for status in [
            ExitStatus::from_raw(0),
            ExitStatus::from_raw(101 << 8),
            ExitStatus::from_raw(9),
        ] {
            assert!(!retryable_bind_failure(true, true, status, failure, true));
        }
        for logs in [
            "",
            "invalid configuration file",
            "ACME load failed: state unavailable",
            "admin service failed",
            "ACME HTTP bind failed: other error",
            "ACME HTTP bind failed: ACME listener operation failed\nextra",
        ] {
            assert!(!retryable_bind_failure(true, true, ordinary, logs, true));
        }
        for event in [
            "ACME listener bound",
            "c2s TCP listener started",
            "waiting for stop signal",
        ] {
            assert!(!retryable_bind_failure(
                true,
                true,
                ordinary,
                &format!("{event}\n{failure}"),
                true
            ));
        }
    }

    #[test]
    fn setup_budget_has_three_total_launches_and_one_absolute_deadline() {
        let deadline = Instant::now() + TIMEOUT;
        let mut budget = StartBudget {
            deadline,
            launches: 0,
        };
        for launch in 1..=3 {
            assert!(budget.claim());
            assert_eq!(budget.launches, launch);
            assert_eq!(budget.deadline, deadline);
        }
        assert!(!budget.claim());
        assert_eq!(budget.launches, 3);
        let mut expired = StartBudget {
            deadline: Instant::now(),
            launches: 0,
        };
        assert!(!expired.claim());
        assert_eq!(expired.launches, 0);
    }
}
