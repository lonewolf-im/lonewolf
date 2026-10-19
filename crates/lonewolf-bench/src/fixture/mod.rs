// SPDX-License-Identifier: Apache-2.0

mod process;
#[cfg(test)]
mod tests;
mod tls;

use crate::{
    accounts,
    client::{PreparedAccount, ResolvedTarget, local_tls_config},
    config::{RunConfig, ScenarioConfig, TargetConfig},
    error::{BenchError, BenchResult, ErrorCode},
    report::{ByteRateLimitSettings, RateLimitSettings, ServerSettings},
};
use lonewolf_auth::scram::{SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramIterations};
use lonewolf_storage::{
    RedbStorage, Storage, WriteTransaction,
    account::{AccountKey, AccountWrites, NewAccount},
};
use lonewolf_util::{
    arena::{Arena, ArenaConfig},
    blocking::BlockingExecutor,
};
use lonewolf_xmpp::jid::Jid;
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use process::{Collector, Startup};
use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    sync::watch,
    time::{Instant, sleep, sleep_until},
};
use zeroize::Zeroizing;

fn failure(context: &'static str) -> BenchError {
    BenchError::new(ErrorCode::Runtime, context)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopOutcome {
    NotStarted,
    Graceful,
    Forced,
}

#[derive(Clone, Copy, Debug)]
pub struct DescriptorBudget {
    pub soft: u64,
    pub hard: u64,
    pub driver_required: u64,
    pub server_required: Option<u64>,
}

pub fn preflight_descriptors(
    accounts: usize,
    local_workers: Option<u16>,
) -> BenchResult<DescriptorBudget> {
    let mut limits = std::mem::MaybeUninit::<nix::libc::rlimit>::uninit();
    // getrlimit initializes this value only on success.
    if unsafe { nix::libc::getrlimit(nix::libc::RLIMIT_NOFILE, limits.as_mut_ptr()) } != 0 {
        return Err(failure("descriptor_limit_unavailable"));
    }
    let limits = unsafe { limits.assume_init() };
    let accounts = u64::try_from(accounts).map_err(|_| failure("descriptor_budget_overflow"))?;
    let driver_required = accounts
        .checked_add(128)
        .ok_or_else(|| failure("descriptor_budget_overflow"))?;
    let server_required = local_workers
        .map(|workers| {
            driver_required
                .checked_add(u64::from(workers) * 8)
                .ok_or_else(|| failure("descriptor_budget_overflow"))
        })
        .transpose()?;
    let budget = DescriptorBudget {
        soft: limits.rlim_cur,
        hard: limits.rlim_max,
        driver_required,
        server_required,
    };
    if budget.driver_required > budget.soft
        || budget
            .server_required
            .is_some_and(|required| required > budget.soft)
    {
        return Err(failure(
            "descriptor_limit_insufficient: raise ulimit -n for requested accounts plus 128 driver and 128+8*workers server overhead",
        ));
    }
    Ok(budget)
}

pub struct LocalFixture {
    directory: Option<TempDir>,
    binary: PathBuf,
    config_path: PathBuf,
    setup_deadline: Instant,
    accounts: Vec<PreparedAccount>,
    settings: ServerSettings,
    certificate: rustls::pki_types::CertificateDer<'static>,
    child: Option<Child>,
    collector: Option<Collector>,
    log: Option<Vec<u8>>,
    metrics: String,
    stop_requested: bool,
    forced: bool,
    reaped: bool,
    started: bool,
}
struct PreparationControl<'a> {
    deadline: Instant,
    interruption: Option<&'a mut watch::Receiver<bool>>,
    deadline_context: &'static str,
    cancelled: Arc<AtomicBool>,
    #[cfg(test)]
    probe: Option<Arc<tests::PreparationProbe>>,
}

impl PreparationControl<'_> {
    fn check(&self) -> BenchResult<()> {
        let result = if self
            .interruption
            .as_ref()
            .is_some_and(|receiver| *receiver.borrow())
        {
            Err(failure("interrupted"))
        } else if Instant::now() >= self.deadline || self.cancelled.load(Ordering::Acquire) {
            Err(failure(self.deadline_context))
        } else {
            Ok(())
        };
        if result.is_err() {
            self.cancelled.store(true, Ordering::Release);
        }
        result
    }

    async fn wait<T>(&mut self, work: impl Future<Output = BenchResult<T>>) -> BenchResult<T> {
        self.check()?;
        let mut work = std::pin::pin!(work);
        let stop = tokio::select! {
            biased;
            _ = async {
                match &mut self.interruption {
                    Some(receiver) => { let _ = receiver.changed().await; }
                    None => std::future::pending::<()>().await,
                }
            } => failure("interrupted"),
            _ = sleep_until(self.deadline) => failure(self.deadline_context),
            result = &mut work => {
                let value = result?;
                self.check()?;
                return Ok(value);
            }
        };
        self.cancelled.store(true, Ordering::Release);
        let _ = work.await;
        Err(stop)
    }

    async fn run_cpu<T: Send + 'static>(
        &mut self,
        cpu: &BlockingExecutor,
        operation: impl FnOnce(&AtomicBool) -> BenchResult<T> + Send + 'static,
    ) -> BenchResult<T> {
        let cancelled = self.cancelled.clone();
        let deadline = self.deadline;
        let context = self.deadline_context;
        #[cfg(test)]
        let probe = self.probe.clone();
        self.wait(cpu.run(move || {
            if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(failure(context));
            }
            #[cfg(test)]
            if let Some(probe) = probe {
                probe.cpu_started()?;
            }
            operation(&cancelled)
        }))
        .await
    }
}

impl LocalFixture {
    pub async fn prepare(config: &RunConfig, cpu: &BlockingExecutor) -> BenchResult<Self> {
        config.validate()?;
        let deadline = Instant::now() + Duration::from_millis(config.measurement.setup_timeout_ms);
        let mut control = PreparationControl {
            deadline,
            interruption: None,
            deadline_context: "fixture_setup_deadline",
            cancelled: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            probe: None,
        };
        Self::prepare_inner(config, cpu, &mut control).await
    }

    pub(crate) async fn prepare_for_run(
        config: &RunConfig,
        cpu: &BlockingExecutor,
        deadline: Instant,
        interruption: &mut watch::Receiver<bool>,
    ) -> BenchResult<Self> {
        let mut control = PreparationControl {
            deadline,
            interruption: Some(interruption),
            deadline_context: "setup_deadline",
            cancelled: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            probe: None,
        };
        Self::prepare_inner(config, cpu, &mut control).await
    }

    async fn prepare_inner(
        config: &RunConfig,
        cpu: &BlockingExecutor,
        control: &mut PreparationControl<'_>,
    ) -> BenchResult<Self> {
        control.check()?;
        let deadline = control.deadline;
        let deadline_context = control.deadline_context;
        config.validate()?;
        validate_limits(config)?;
        let TargetConfig::Local {
            server_binary,
            server_workers,
            stanza_pool_size_mib,
            ..
        } = &config.target
        else {
            return Err(failure("fixture_requires_local_target"));
        };
        preflight_descriptors(config.account_count(), Some(*server_workers))?;
        let binary = server_binary
            .canonicalize()
            .map_err(|_| failure("fixture_server_binary"))?;
        if !binary.is_file() {
            return Err(failure("fixture_server_binary"));
        }
        let count = config.account_count();
        let (directory, certificate, credentials) = control
            .run_cpu(cpu, move |_| {
                let directory = tempfile::Builder::new()
                    .prefix("lonewolf-bench-")
                    .permissions(std::fs::Permissions::from_mode(0o700))
                    .tempdir()
                    .map_err(|_| failure("fixture_directory"))?;
                let certificate = tls::configure(directory.path())?;
                let credentials = accounts::generated("localhost", "bench", count)?;
                Ok::<_, BenchError>((directory, certificate, credentials))
            })
            .await?;
        #[cfg(test)]
        let _owners = control
            .probe
            .as_ref()
            .map(|probe| probe.owners(directory.path()))
            .transpose()?;
        let path = directory.path().join("accounts.redb");
        let storage = control
            .run_cpu(cpu, move |_| {
                RedbStorage::open(path).map_err(|_| failure("fixture_storage"))
            })
            .await?;
        for chunk in credentials.accounts.chunks(256) {
            control.check()?;
            let secrets: Vec<_> = chunk
                .iter()
                .map(|account| {
                    (
                        account.jid.clone(),
                        Zeroizing::new(account.password.to_string()),
                    )
                })
                .collect();
            let batch = control
                .run_cpu(cpu, move |cancelled| {
                    let iterations = ScramIterations::new(SCRAM_POLICY_ITERATIONS.get())
                        .map_err(|_| failure("fixture_scram_policy"))?;
                    let mut batch = Vec::with_capacity(secrets.len());
                    for (jid, password) in secrets {
                        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                            return Err(failure(deadline_context));
                        }
                        let mut arena = Arena::try_new(ArenaConfig::default())
                            .map_err(|_| failure("fixture_arena"))?;
                        let jid =
                            Jid::parse_in(&jid, &mut arena).map_err(|_| failure("fixture_jid"))?;
                        let key = AccountKey::try_from(
                            jid.resolve(&arena).map_err(|_| failure("fixture_jid"))?,
                        )
                        .map_err(|_| failure("fixture_jid"))?;
                        let credentials = ScramCredentials::provision(&password, iterations)
                            .map_err(|_| failure("fixture_password"))?;
                        batch.push(NewAccount { key, credentials });
                    }
                    Ok::<_, BenchError>(batch)
                })
                .await?;
            #[cfg(test)]
            let probe = control.probe.clone();
            control
                .wait(async {
                    let mut transaction = storage
                        .begin_write()
                        .await
                        .map_err(|_| failure("fixture_storage"))?;
                    #[cfg(test)]
                    if let Some(probe) = &probe {
                        probe.transaction_started().await?;
                    }
                    for account in batch {
                        transaction
                            .create_account(account)
                            .await
                            .map_err(|_| failure("fixture_storage"))?;
                    }
                    transaction
                        .commit()
                        .await
                        .map_err(|_| failure("fixture_storage"))?;
                    #[cfg(test)]
                    if let Some(probe) = &probe {
                        probe.transaction_finished();
                    }
                    Ok(())
                })
                .await?;
        }
        control.check()?;
        drop(storage);
        let accounts = credentials.into_prepared()?;
        control.check()?;
        let settings = settings(*server_workers, *stanza_pool_size_mib);
        let config_path = directory.path().join("lonewolf.toml");
        control.check()?;
        tls::write_private(&config_path, server_config(&settings).as_bytes())?;
        control.check()?;
        Ok(Self {
            directory: Some(directory),
            binary,
            config_path,
            setup_deadline: deadline,
            accounts,
            settings,
            certificate,
            child: None,
            collector: None,
            log: None,
            metrics: String::new(),
            stop_requested: false,
            forced: false,
            reaped: false,
            started: false,
        })
    }
    pub async fn start(&mut self, deadline: Instant) -> BenchResult<ResolvedTarget> {
        let deadline = deadline.min(self.setup_deadline);
        if self.started || self.directory.is_none() || Instant::now() >= deadline {
            return Err(failure("fixture_start_state_or_deadline"));
        }
        self.started = true;
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| failure("fixture_directory"))?;
        self.child = Some(
            Command::new(&self.binary)
                .arg("--config")
                .arg(&self.config_path)
                .current_dir(directory.path())
                .env("LONEWOLF_WORKER_COUNT", self.settings.workers.to_string())
                .env("NO_COLOR", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| failure("fixture_spawn"))?,
        );
        let stderr = self
            .child
            .as_mut()
            .and_then(|child| child.stderr.take())
            .ok_or_else(|| failure("fixture_stderr"))?;
        self.collector = Some(Collector::start(stderr)?);
        let mut c2s = None;
        let mut metrics = None;
        let mut ready = false;
        loop {
            if self
                .child
                .as_mut()
                .ok_or_else(|| failure("fixture_child"))?
                .try_wait()
                .map_err(|_| failure("fixture_wait"))?
                .is_some()
            {
                self.reaped = true;
                return Err(failure("fixture_startup_exit"));
            }
            let collector = self
                .collector
                .as_ref()
                .ok_or_else(|| failure("fixture_capture"))?;
            loop {
                match collector.receiver.try_recv() {
                    Ok(Startup::C2s(port)) => c2s = Some(port),
                    Ok(Startup::Metrics(port)) => metrics = Some(port),
                    Ok(Startup::Ready) => ready = true,
                    Ok(Startup::Failed) => return Err(failure("fixture_startup_capture")),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err(failure("fixture_startup_capture"));
                    }
                }
            }
            if let (Some(port), Some(metrics_port), true) = (c2s, metrics, ready) {
                self.metrics = format!("http://127.0.0.1:{metrics_port}/metrics");
                return Ok(ResolvedTarget {
                    address: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                    xmpp_domain: "localhost".into(),
                    tls: local_tls_config(self.certificate.clone())?,
                });
            }
            if Instant::now() >= deadline {
                return Err(failure("fixture_startup_deadline"));
            }
            sleep(Duration::from_millis(5)).await;
        }
    }
    pub async fn stop(&mut self, timeout: Duration) -> BenchResult<StopOutcome> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| failure("fixture_shutdown_timeout_range"))?;
        if let Some(child) = &mut self.child {
            if !self.reaped
                && child
                    .try_wait()
                    .map_err(|_| failure("fixture_wait"))?
                    .is_some()
            {
                self.reaped = true;
            }
            if !self.reaped && !self.stop_requested {
                let pid = i32::try_from(child.id()).map_err(|_| failure("fixture_pid"))?;
                match kill(Pid::from_raw(pid), Signal::SIGTERM) {
                    Ok(()) | Err(nix::errno::Errno::ESRCH) => self.stop_requested = true,
                    Err(_) => return Err(failure("fixture_sigterm")),
                }
            }
            while !self.reaped {
                if child
                    .try_wait()
                    .map_err(|_| failure("fixture_wait"))?
                    .is_some()
                {
                    self.reaped = true;
                    break;
                }
                if Instant::now() >= deadline {
                    child.kill().map_err(|_| failure("fixture_kill"))?;
                    self.forced = true;
                    child.wait().map_err(|_| failure("fixture_reap"))?;
                    self.reaped = true;
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        }
        let mut capture_error = None;
        if let Some(collector) = &mut self.collector {
            collector.request_stop();
            while !collector.is_finished() {
                sleep(Duration::from_millis(5)).await;
            }
            match collector.join() {
                Ok(log) => self.log = Some(log),
                Err(error) => capture_error = Some(error),
            }
            self.collector = None;
        }
        if self.forced
            && let Some(log) = &mut self.log
            && !log.ends_with(b"forced_termination\n")
        {
            log.extend_from_slice(b"forced_termination\n");
        }
        self.accounts.clear();
        let cleanup = if let Some(directory) = self.directory.take() {
            directory.close().map_err(|_| failure("fixture_cleanup"))
        } else {
            Ok(())
        };
        if let Some(error) = capture_error {
            return Err(error);
        }
        cleanup?;
        Ok(if self.forced {
            StopOutcome::Forced
        } else if self.child.is_some() {
            StopOutcome::Graceful
        } else {
            StopOutcome::NotStarted
        })
    }
    pub fn metrics_url(&self) -> &str {
        &self.metrics
    }
    pub fn credentials(&mut self) -> &mut [PreparedAccount] {
        &mut self.accounts
    }
    pub fn sanitized_server_settings(&self) -> ServerSettings {
        self.settings.clone()
    }
    pub fn sanitized_server_log(&self) -> Option<&[u8]> {
        self.log.as_deref()
    }
}
impl Drop for LocalFixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child
            && !self.reaped
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(collector) = &mut self.collector {
            collector.request_stop();
            let _ = collector.join();
        }
        self.accounts.clear();
    }
}

fn validate_limits(config: &RunConfig) -> BenchResult<()> {
    if config.account_count() > 100_000
        || config.measurement.connect_concurrency > 100_000
        || config.measurement.ramp_rate_per_second > 1_000_000
        || config.offered_rate().is_some_and(|rate| rate > 1_000_000)
    {
        return Err(failure("fixture_workload_exceeds_bench_profile"));
    }
    if let ScenarioConfig::Messages {
        rate_per_second,
        pairs,
        body_bytes,
    } = config.scenario
    {
        let sender_rate = u64::from(rate_per_second).div_ceil(pairs.max(1) as u64);
        if body_bytes + 1024 > 262_144 || sender_rate * (body_bytes as u64 + 1024) > 1_073_741_824 {
            return Err(failure("fixture_workload_exceeds_bench_profile"));
        }
    }
    Ok(())
}
fn settings(workers: u16, pool: u64) -> ServerSettings {
    let rate = RateLimitSettings {
        rate_per_second: 1_000_000,
        burst: 1_000_000,
    };
    ServerSettings {
        workers,
        stanza_pool_size_mib: pool,
        logging_level: "info".into(),
        host_extensions: vec!["roster".into(), "offline".into()],
        storage_backend: "redb".into(),
        max_unauthenticated_connections: 100_000,
        max_resources_per_account: 1,
        max_directed_presence_recipients_per_resource: 256,
        max_connections_per_ip: 100_000,
        max_stanza_bytes: 262_144,
        connection_establishment_timeout_secs: 10,
        authentication_timeout_secs: 15,
        resource_binding_timeout_secs: 5,
        authentication_retries: 2,
        resource_binding_retries: 5,
        connection_attempts_per_ip: rate.clone(),
        incoming_stanzas_per_connection: rate.clone(),
        new_recipients_per_connection: rate,
        incoming_xml_per_connection: ByteRateLimitSettings {
            bytes_per_second: 1_073_741_824,
            burst_bytes: 1_073_741_824,
        },
        offered_auth_mechanisms: vec!["SCRAM-SHA-256".into()],
        tls_min: "TLSv1.2".into(),
        tls_max: "TLSv1.3".into(),
        empty_roster: true,
        offline_storage: true,
    }
}
fn server_config(settings: &ServerSettings) -> String {
    format!(
        r#"[logging]
level = "info"
[xmpp]
default_host = "localhost"
stanza_pool_size_mib = {}
[hosts.localhost]
extensions = ["roster", "offline"]
[hosts.localhost.tls]
provider = "files"
certificate_chain_path = "certificate.pem"
private_key_path = "key.pem"
[[c2s.listeners]]
address = "127.0.0.1:0"
auth_mechanisms = ["SCRAM-SHA-256"]
limits = "bench"
[limits.c2s]
default = "bench"
max_unauthenticated_connections = 100000
max_resources_per_account = 1
max_directed_presence_recipients_per_resource = 256
[limits.c2s.profiles.bench]
max_connections_per_ip = 100000
max_stanza_bytes = 262144
connection_establishment_timeout_secs = 10
authentication_timeout_secs = 15
resource_binding_timeout_secs = 5
authentication_retries = 2
resource_binding_retries = 5
connection_attempts_per_ip = {{ per_second = 1000000, burst = 1000000 }}
incoming_stanzas_per_connection = {{ per_second = 1000000, burst = 1000000 }}
new_recipients_per_connection = {{ per_second = 1000000, burst = 1000000 }}
incoming_xml_per_connection = {{ bytes_per_second = 1073741824, burst_bytes = 1073741824 }}
[storage]
default = "primary"
[storage.stores.primary]
backend = "redb"
path = "accounts.redb"
[admin]
enabled = false
[metrics]
enabled = true
address = "127.0.0.1:0"
"#,
        settings.stanza_pool_size_mib
    )
}
