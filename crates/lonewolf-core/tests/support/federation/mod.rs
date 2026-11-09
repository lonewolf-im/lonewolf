// SPDX-License-Identifier: Apache-2.0

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::{Arc, atomic::AtomicBool};
use std::thread;
use std::time::Instant;

use parking_lot::Mutex as PlMutex;

use super::server::C2sSuitePermit;
use super::{C2sSuite, Client, TIMEOUT, TestResult};
pub mod crl_server;
pub mod dns;
pub mod peer;
pub mod pki;
#[path = "../tcp.rs"]
mod tcp;

pub use dns::FakeDns;
pub use pki::FederationCa;
pub use tcp::RefusedEndpoint;

pub fn refused_endpoint() -> TestResult<RefusedEndpoint> {
    Ok(RefusedEndpoint::reserve(Instant::now() + TIMEOUT)?)
}

#[derive(Default, Debug)]
pub struct ProcessCompletions {
    pub spawned: Vec<u32>,
    pub ready: Vec<u32>,
    pub reaped: Vec<(u32, ExitStatus)>,
}
pub type ProcessReceipts = Arc<PlMutex<ProcessCompletions>>;

#[derive(Clone, Default)]
pub struct HostRevocation {
    pub crls_path: Option<PathBuf>,
    pub crl_url: Option<String>,
    pub fetch_crls: Option<bool>,
    pub public_destinations_only: bool,
    pub revalidation_interval: Option<std::time::Duration>,
}

pub struct FederatedHost {
    pub domain: String,
    pub revocation: HostRevocation,
    pub enabled: Option<bool>,
    pub bidirectional: Option<bool>,
    pub federation: Option<bool>,
    pub extensions: String,
    pub extra_toml: String,
    pub ca: Arc<FederationCa>,
    pub dns: SocketAddr,
    pub completion: Option<ProcessReceipts>,
}

pub struct PairOptions {
    pub crl_files: bool,
    pub a_revocation: HostRevocation,
    pub b_revocation: HostRevocation,
    pub a_enabled: Option<bool>,
    pub b_enabled: Option<bool>,
    pub a_bidirectional: Option<bool>,
    pub b_bidirectional: Option<bool>,
    pub a_federation: Option<bool>,
    pub b_federation: Option<bool>,
    pub a_extensions: String,
    pub b_extensions: String,
    pub limits: String,
    pub a_extra_toml: String,
    pub b_extra_toml: String,
    pub completion: Option<ProcessReceipts>,
    pub dns_join: Option<Arc<PlMutex<Option<Arc<AtomicBool>>>>>,
}

impl Default for PairOptions {
    fn default() -> Self {
        Self {
            crl_files: false,
            a_revocation: HostRevocation::default(),
            b_revocation: HostRevocation::default(),
            a_enabled: Some(true),
            b_enabled: Some(true),
            a_bidirectional: Some(false),
            b_bidirectional: Some(false),
            a_federation: None,
            b_federation: None,
            a_extensions: String::new(),
            b_extensions: String::new(),
            limits: String::new(),
            a_extra_toml: String::new(),
            b_extra_toml: String::new(),
            completion: None,
            dns_join: None,
        }
    }
}

pub struct FederatedPair {
    pub a: C2sSuite,
    pub b: C2sSuite,
    pub dns: FakeDns,
    pub ca: Arc<FederationCa>,
    pub a_crls: Option<PathBuf>,
    pub b_crls: Option<PathBuf>,
    _directory: tempfile::TempDir,
}
impl FederatedPair {
    pub fn start(a: &str, b: &str, mut options: PairOptions) -> TestResult<Self> {
        let [a_permit, b_permit] = C2sSuitePermit::pair();
        let directory = tempfile::tempdir()?;
        let ca = Arc::new(FederationCa::new(directory.path())?);
        let dns = FakeDns::start()?;
        let (a_crls, b_crls) = if options.crl_files {
            let a_crls = directory.path().join("a-crls.pem");
            let b_crls = directory.path().join("b-crls.pem");
            let now = time::OffsetDateTime::now_utc();
            for path in [&a_crls, &b_crls] {
                ca.write_crl(
                    path,
                    &[],
                    now - time::Duration::minutes(1),
                    now + time::Duration::days(1),
                    1,
                )?;
            }
            options.a_revocation.crls_path = Some(a_crls.clone());
            options.b_revocation.crls_path = Some(b_crls.clone());
            (Some(a_crls), Some(b_crls))
        } else {
            (None, None)
        };
        if let Some(receipt) = options.dns_join {
            *receipt.lock() = Some(dns.join_receipt());
        }
        let extra = if options.limits.is_empty() {
            String::new()
        } else {
            format!("\n[limits.s2s]\n{}", options.limits)
        };
        let a_host = FederatedHost {
            domain: a.into(),
            revocation: options.a_revocation,
            enabled: options.a_enabled,
            bidirectional: options.a_bidirectional,
            federation: options.a_federation,
            extensions: options.a_extensions,
            extra_toml: format!("{extra}\n{}", options.a_extra_toml),
            ca: Arc::clone(&ca),
            dns: dns.address(),
            completion: options.completion.clone(),
        };
        let b_host = FederatedHost {
            domain: b.into(),
            revocation: options.b_revocation,
            enabled: options.b_enabled,
            bidirectional: options.b_bidirectional,
            federation: options.b_federation,
            extensions: options.b_extensions,
            extra_toml: format!("{extra}\n{}", options.b_extra_toml),
            ca: Arc::clone(&ca),
            dns: dns.address(),
            completion: options.completion,
        };
        let (a_result, b_result) = thread::scope(|scope| {
            let a = scope.spawn(move || {
                C2sSuite::federated_with_permit(a_host, a_permit).map_err(|error| error.to_string())
            });
            let b = scope.spawn(move || {
                C2sSuite::federated_with_permit(b_host, b_permit).map_err(|error| error.to_string())
            });
            let a = a.join();
            let b = b.join();
            (a, b)
        });
        let a = a_result.map_err(|_| "first federation startup worker panicked")?;
        let b = b_result.map_err(|_| "second federation startup worker panicked")?;
        let a = a?;
        let b = b?;
        let pair = Self {
            a,
            b,
            dns,
            ca,
            a_crls,
            b_crls,
            _directory: directory,
        };
        for (prefix, suite) in [("a", &pair.a), ("b", &pair.b)] {
            let domain = &suite.domain;
            let target = format!("{prefix}.{domain}");
            if let Some(address) = suite.s2s.as_ref().and_then(|addresses| addresses.first()) {
                pair.dns.srv(domain, &[(0, 0, address.port(), &target)]);
            }
            pair.dns.a(&target, Ipv4Addr::LOCALHOST);
        }
        Ok(pair)
    }

    pub fn direct_tls(&mut self) -> TestResult {
        for (prefix, suite) in [("a", &mut self.a), ("b", &mut self.b)] {
            let path = suite.fixture_path().join("lonewolf.toml");
            let config = std::fs::read_to_string(&path)?;
            let listeners = "listeners = [{ address = \"127.0.0.1:0\" }]";
            assert!(config.contains(listeners));
            std::fs::write(
                path,
                config.replacen(
                    listeners,
                    "listeners=[{address='127.0.0.1:0',tls_mode='direct'}]",
                    1,
                ),
            )?;
            suite.restart()?;
            let target = format!("{prefix}.{}", suite.domain);
            self.dns.srv(&suite.domain, &[]);
            self.dns.direct_srv(
                &suite.domain,
                &[(0, 0, suite.s2s_addresses()?[0].port(), &target)],
            );
        }
        Ok(())
    }

    pub fn stop(&mut self) -> TestResult {
        assert_direct_transport_metrics(&self.a)?;
        assert_direct_transport_metrics(&self.b)?;
        let a = self.a.stop_with_s2s_state();
        let b = self.b.stop_with_s2s_state();
        assert_shutdown_empty(a?);
        assert_shutdown_empty(b?);
        self.dns.stop()
    }
}
impl Drop for FederatedPair {
    fn drop(&mut self) {
        self.a.terminate_and_reap();
        self.b.terminate_and_reap();
        let _ = self.dns.stop();
    }
}

pub fn assert_direct_transport_metrics(suite: &C2sSuite) -> TestResult {
    let config =
        lonewolf_core::config::Config::load(Some(&suite.fixture_path().join("lonewolf.toml")))?;
    if !config
        .s2s
        .listeners
        .iter()
        .all(|listener| listener.tls_mode == lonewolf_core::config::TlsMode::Direct)
    {
        return Ok(());
    }
    let body = suite.scrape_metrics()?;
    for line in body
        .lines()
        .filter(|line| line.starts_with("lonewolf_s2s_authentications_total{"))
    {
        let expected = line
            .replace(
                "lonewolf_s2s_authentications_total",
                "lonewolf_s2s_transport_attempts_total",
            )
            .replace(",outcome=", ",tls_mode=\"direct\",outcome=");
        assert!(
            body.lines().any(|line| line == expected),
            "missing {expected}: {body}"
        );
    }
    assert!(
        !body.lines().any(
            |line| line.starts_with("lonewolf_s2s_transport_attempts_total{")
                && line.contains("tls_mode=\"starttls\"")
        ),
        "{body}"
    );
    Ok(())
}

pub fn assert_shutdown_empty(state: Option<lonewolf_core::test_support::S2sShutdownState>) {
    if let Some(state) = state {
        assert_eq!(state.queued_stanzas, 0);
        assert_eq!(state.queued_bytes, 0);
        assert_eq!(state.transport_connections, [[0; 2]; 2]);
        assert_eq!(state.connections, [0; 2]);
    }
}

pub fn subscribe_mutually(a: &mut Client, a_jid: &str, b: &mut Client, b_jid: &str) -> TestResult {
    for client in [&mut *a, &mut *b] {
        client.send("<iq type='get' id='initial-roster'><query xmlns='jabber:iq:roster'/></iq>")?;
        let roster = client.receive()?;
        roster.assert_name("jabber:client", "iq");
        assert_eq!(roster.attribute("type"), Some("result"));
        assert_eq!(roster.attribute("id"), Some("initial-roster"));
        roster.child("jabber:iq:roster", "query")?;
        client.send("<presence/>")?;
        let presence = client.receive()?;
        presence.assert_name("jabber:client", "presence");
        assert_eq!(presence.attribute("type"), None);
    }
    subscribe(a, a_jid, b, b_jid, "none", "to", "from")?;
    subscribe(b, b_jid, a, a_jid, "from", "both", "both")?;
    for (client, jid) in [(&mut *a, b_jid), (&mut *b, a_jid)] {
        client.send("<iq type='get' id='mutual-roster'><query xmlns='jabber:iq:roster'/></iq>")?;
        let roster = client.receive()?;
        assert_eq!(roster.attribute("id"), Some("mutual-roster"));
        let item = roster
            .child("jabber:iq:roster", "query")?
            .child("jabber:iq:roster", "item")?;
        assert_eq!(item.attribute("jid"), Some(jid));
        assert_eq!(item.attribute("subscription"), Some("both"));
    }
    Ok(())
}
fn subscribe(
    a: &mut Client,
    a_jid: &str,
    b: &mut Client,
    b_jid: &str,
    pending: &str,
    approved: &str,
    grantor: &str,
) -> TestResult {
    a.send(&format!("<presence type='subscribe' to='{b_jid}'/>"))?;
    roster_push(a, b_jid, pending)?;
    let request = b.receive()?;
    request.assert_name("jabber:client", "presence");
    assert_eq!(request.attribute("type"), Some("subscribe"));
    assert_eq!(request.attribute("from"), Some(a_jid));
    b.send(&format!("<presence type='subscribed' to='{a_jid}'/>"))?;
    roster_push(b, a_jid, grantor)?;
    let response = a.receive()?;
    response.assert_name("jabber:client", "presence");
    assert_eq!(response.attribute("type"), Some("subscribed"));
    roster_push(a, b_jid, approved)?;
    let presence = a.receive()?;
    presence.assert_name("jabber:client", "presence");
    assert_eq!(presence.attribute("type"), None);
    assert!(
        presence
            .attribute("from")
            .is_some_and(|from| from.split_once('/').is_some_and(|(bare, _)| bare == b_jid))
    );
    Ok(())
}
fn roster_push(client: &mut Client, jid: &str, subscription: &str) -> TestResult {
    let push = client.receive()?;
    push.assert_name("jabber:client", "iq");
    assert_eq!(push.attribute("type"), Some("set"));
    let item = push
        .child("jabber:iq:roster", "query")?
        .child("jabber:iq:roster", "item")?;
    assert_eq!(item.attribute("jid"), Some(jid));
    assert_eq!(item.attribute("subscription"), Some(subscription));
    client.send(&format!(
        "<iq type='result' id='{}'/>",
        push.attribute("id").ok_or("missing roster push id")?
    ))
}

pub fn phase<T>(name: &'static str, result: TestResult<T>) -> TestResult<T> {
    result.map_err(|source| Box::new(PhaseError { name, source }) as Box<dyn std::error::Error>)
}

pub fn thread_result<T>(result: TestResult<T>) -> Result<T, Box<PhaseReport>> {
    result.map_err(|error| Box::new(PhaseReport::capture(error.as_ref())))
}

pub struct PhaseReport {
    phases: [&'static str; 8],
    count: usize,
    io_kind: Option<std::io::ErrorKind>,
    os_code: Option<i32>,
}
impl PhaseReport {
    fn capture(mut error: &(dyn std::error::Error + 'static)) -> Self {
        let mut report = Self {
            phases: [""; 8],
            count: 0,
            io_kind: None,
            os_code: None,
        };
        for _ in 0..8 {
            if let Some(phase) = error.downcast_ref::<PhaseError>() {
                report.phases[report.count] = phase.name;
                report.count += 1;
            }
            if let Some(previous) = error
                .downcast_ref::<Self>()
                .or_else(|| error.downcast_ref::<Box<Self>>().map(AsRef::as_ref))
            {
                for name in &previous.phases[..previous.count] {
                    if report.count == report.phases.len() {
                        break;
                    }
                    report.phases[report.count] = name;
                    report.count += 1;
                }
                report.io_kind = previous.io_kind;
                report.os_code = previous.os_code;
                break;
            }
            if let Some(io) = error.downcast_ref::<std::io::Error>() {
                report.io_kind = Some(io.kind());
                report.os_code = io.raw_os_error();
                break;
            }
            match error.source() {
                Some(source) => error = source,
                None => break,
            }
        }
        report
    }
}
impl std::fmt::Debug for PhaseReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FederationPhase")
            .field("phases", &(&self.phases[..self.count]))
            .field("io_kind", &self.io_kind)
            .field("os_code", &self.os_code)
            .finish()
    }
}
impl std::fmt::Display for PhaseReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, formatter)
    }
}
impl std::error::Error for PhaseReport {}

struct PhaseError {
    name: &'static str,
    source: Box<dyn std::error::Error>,
}
impl std::fmt::Debug for PhaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&PhaseReport::capture(self), formatter)
    }
}
impl std::fmt::Display for PhaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, formatter)
    }
}
impl std::error::Error for PhaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ShutdownReceipt {
    pid: u32,
    // A missing field must not be accepted as an inactive result.
    #[serde(deserialize_with = "serde::Deserialize::deserialize")]
    state: Option<lonewolf_core::test_support::S2sShutdownState>,
}

pub fn remove_shutdown_receipt(directory: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_file(directory.join("s2s-shutdown.json")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn write_shutdown_receipt(
    directory: &std::path::Path,
    state: Option<lonewolf_core::test_support::S2sShutdownState>,
) -> TestResult {
    let receipt = ShutdownReceipt {
        pid: std::process::id(),
        state,
    };
    std::fs::write(
        directory.join("s2s-shutdown.json"),
        serde_json::to_vec(&receipt)?,
    )?;
    Ok(())
}

pub fn read_shutdown_receipt(
    directory: &std::path::Path,
    pid: u32,
) -> TestResult<Option<lonewolf_core::test_support::S2sShutdownState>> {
    let receipt: ShutdownReceipt =
        serde_json::from_slice(&std::fs::read(directory.join("s2s-shutdown.json"))?)?;
    if receipt.pid != pid {
        return Err("S2S shutdown receipt belongs to another process".into());
    }
    Ok(receipt.state)
}
