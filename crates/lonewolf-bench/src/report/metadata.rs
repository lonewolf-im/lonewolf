// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    config::{RunConfig, TargetConfig, printable, validate_build},
    error::{BenchError, BenchResult, ErrorCode},
    run::policy,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    num::NonZeroUsize,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

pub(crate) fn initial_report(config: &RunConfig) -> RunReport {
    let mode = match config.target {
        TargetConfig::Local { .. } => TargetMode::Local,
        TargetConfig::Remote { .. } => TargetMode::Remote,
    };
    let (domain, endpoint, build) = match &config.target {
        TargetConfig::Local {
            server_revision,
            server_profile,
            server_toolchain,
            server_features,
            ..
        } => (
            "localhost".into(),
            None,
            Some(ServerBuildDeclaration {
                revision: server_revision.clone(),
                profile: server_profile.clone(),
                toolchain: server_toolchain.clone(),
                features: server_features.clone(),
            }),
        ),
        TargetConfig::Remote {
            xmpp_domain,
            connect_host,
            port,
            ..
        } => (
            xmpp_domain.clone(),
            Some(format!("{connect_host}:{port}")),
            None,
        ),
    };
    RunReport {
        schema_version: 1,
        measurement_version: 1,
        run_id: None,
        started_at_utc: None,
        status: RunStatus::Passed,
        reasons: vec![RunReason {
            code: ReasonCode::TelemetryUnavailable,
            context: None,
        }],
        telemetry_status: TelemetryStatus::Unavailable,
        phases: Vec::with_capacity(10),
        config: SanitizedConfig::from(config),
        driver: DriverMetadata {
            executable_sha256: None,
            package_version: env!("CARGO_PKG_VERSION").into(),
            revision: env!("LONEWOLF_BENCH_REVISION").into(),
            build_profile: env!("LONEWOLF_BENCH_PROFILE").into(),
            build_target: env!("LONEWOLF_BENCH_TARGET").into(),
            rustc: env!("LONEWOLF_BENCH_RUSTC").into(),
            worker_count: config.measurement.driver_workers,
            scheduler_policy: policy(&config.measurement).metadata(),
            available_parallelism: std::thread::available_parallelism()
                .ok()
                .map(NonZeroUsize::get),
            rlimit_nofile_soft: None,
            rlimit_nofile_hard: None,
            system: unknown_system(),
            sources: BTreeMap::new(),
        },
        target: TargetMetadata {
            mode,
            xmpp_domain: domain,
            configured_endpoint: endpoint,
            negotiated_tls: None,
            cipher: None,
            auth_mechanism: "SCRAM-SHA-256".into(),
            resumption: false,
            cache_primed: false,
            observed_scram_iterations: None,
            observed_build: None,
            observed_process_start_time_seconds: None,
            local_binary_sha256: None,
            declared_build: build,
        },
        environment: None,
        dataset: DatasetIdentity {
            account_jids_sha256: None,
            account_count: config.account_count() as u64,
            pair_count: match config.scenario {
                ScenarioConfig::Messages { pairs, .. } => Some(pairs as u64),
                _ => None,
            },
            resource_policy: match config.scenario {
                ScenarioConfig::Messages { .. } => "one_bound_resource_per_account:run_nonce",
                ScenarioConfig::Churn { .. } => {
                    "unique_resource_per_cycle:bench-RUN_NONCE-PHASE-SEQUENCE"
                }
                ScenarioConfig::Idle { .. } => "one_bound_resource_per_account:bench",
            }
            .into(),
            availability_policy: "unavailable_no_presence".into(),
            body_bytes: match config.scenario {
                ScenarioConfig::Messages { body_bytes, .. } => Some(body_bytes as u64),
                _ => None,
            },
        },
        counters: CounterReport::default(),
        rates: RateReport::default(),
        latencies: BTreeMap::new(),
        telemetry: TelemetryReport {
            quality: TelemetryStatus::Unavailable,
            samples_ok: 0,
            samples_failed: 0,
            missed_ticks: 0,
            queue_overflows: 0,
            bytes: 0,
            total_scrape_duration_ms: 0,
            server: ResourceSummary::default(),
            generator: ResourceSummary::default(),
            policy_rejections: BTreeMap::new(),
            identity_changes: 0,
            reasons: vec![RunReason {
                code: ReasonCode::TelemetryUnavailable,
                context: None,
            }],
        },
        artifacts: BTreeMap::new(),
    }
}

fn unknown_system() -> SystemMetadata {
    SystemMetadata {
        os_release: None,
        kernel: None,
        arch: None,
        cpu_model: None,
        logical_cpus: None,
        memory_bytes: None,
        virtualization: None,
        storage_description: None,
        cpu_affinity: None,
        cpu_quota: None,
    }
}
pub(crate) fn system_metadata() -> SystemMetadata {
    let mut system = unknown_system();
    let mut name = std::mem::MaybeUninit::<nix::libc::utsname>::uninit();
    // uname initializes all fields only on success.
    if unsafe { nix::libc::uname(name.as_mut_ptr()) } == 0 {
        let name = unsafe { name.assume_init() };
        let field = |value: &[nix::libc::c_char]| {
            let bytes: Vec<_> = value
                .iter()
                .take_while(|c| **c != 0)
                .map(|c| *c as u8)
                .collect();
            String::from_utf8(bytes).ok().filter(|v| printable(v, 1024))
        };
        system.kernel = field(&name.release);
        system.os_release = field(&name.sysname)
            .zip(system.kernel.as_deref())
            .map(|(os, release)| format!("{os} {release}"));
        system.arch = field(&name.machine);
    }
    system.logical_cpus = std::thread::available_parallelism()
        .ok()
        .map(|n| n.get() as u64);
    system
}

pub fn collect_metadata(config: &RunConfig) -> BenchResult<RunMetadata> {
    let report = initial_report(config);
    let mut driver = report.driver;
    let mut target = report.target;
    driver.system = system_metadata();
    driver.executable_sha256 = std::env::current_exe()
        .ok()
        .and_then(|path| hash_file(&path).ok());
    driver
        .sources
        .insert("executable_sha256".into(), "current_exe:sha256".into());
    driver
        .sources
        .insert("build".into(), "embedded_build_script".into());
    driver
        .sources
        .insert("os_release,kernel,arch".into(), "uname".into());
    driver
        .sources
        .insert("logical_cpus".into(), "available_parallelism".into());
    driver
        .sources
        .insert("server_build".into(), "explicit_target_declaration".into());
    driver.sources.insert(
        "telemetry_buffer_bytes".into(),
        "fixed_preallocated_touched:67108864".into(),
    );
    if let Ok((soft, hard)) =
        nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE)
    {
        driver.rlimit_nofile_soft = Some(soft);
        driver.rlimit_nofile_hard = Some(hard);
        driver
            .sources
            .insert("rlimit_nofile".into(), "getrlimit".into());
    }
    #[cfg(target_os = "linux")]
    {
        driver.system.cpu_model = read_fact("/proc/cpuinfo", 65536)
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("model name\t: ").map(str::to_owned))
            })
            .filter(|v| printable(v, 1024));
        driver
            .sources
            .insert("cpu_model".into(), "/proc/cpuinfo".into());
        driver.system.memory_bytes = read_fact("/proc/meminfo", 16384).and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("MemTotal:")
                    .and_then(|s| s.split_ascii_whitespace().next())
                    .and_then(|s| s.parse::<u64>().ok())
                    .and_then(|v| v.checked_mul(1024))
            })
        });
        driver
            .sources
            .insert("memory_bytes".into(), "/proc/meminfo:MemTotal".into());
        driver.system.cpu_affinity = read_fact("/proc/self/status", 65536).and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("Cpus_allowed_list:\t"))
                .and_then(parse_cpu_list)
        });
        driver.sources.insert(
            "cpu_affinity".into(),
            "/proc/self/status:Cpus_allowed_list".into(),
        );
        driver.system.cpu_quota = read_fact("/proc/self/cgroup", 8192)
            .filter(|text| text.lines().any(|line| line == "0::/"))
            .and_then(|_| read_fact("/sys/fs/cgroup/cpu.max", 1024))
            .and_then(|text| {
                let mut parts = text.split_ascii_whitespace();
                let quota = parts.next()?.parse::<f64>().ok()?;
                let period = parts.next()?.parse::<f64>().ok()?;
                (period > 0.0 && quota.is_finite()).then_some(quota / period)
            });
        driver.sources.insert(
            "cpu_quota".into(),
            "/proc/self/cgroup:root_membership;/sys/fs/cgroup/cpu.max".into(),
        );
    }
    if let TargetConfig::Local { server_binary, .. } = &config.target {
        target.local_binary_sha256 = hash_file(server_binary).ok();
    }
    Ok(RunMetadata {
        driver,
        target,
        environment: report.environment,
        dataset: report.dataset,
    })
}

#[cfg(target_os = "linux")]
fn read_fact(path: &str, limit: usize) -> Option<String> {
    let mut data = Vec::new();
    File::open(path)
        .ok()?
        .take(limit as u64 + 1)
        .read_to_end(&mut data)
        .ok()?;
    (data.len() <= limit)
        .then(|| String::from_utf8(data).ok())
        .flatten()
}
#[cfg(target_os = "linux")]
fn parse_cpu_list(value: &str) -> Option<Vec<u32>> {
    let mut cpus = Vec::new();
    for range in value.split(',') {
        let (first, last) = match range.split_once('-') {
            Some((first, last)) => (first.parse::<u32>().ok()?, last.parse::<u32>().ok()?),
            None => {
                let cpu = range.parse::<u32>().ok()?;
                (cpu, cpu)
            }
        };
        if last < first || last - first > 65536 || cpus.len() + (last - first) as usize + 1 > 65536
        {
            return None;
        }
        cpus.extend(first..=last);
    }
    Some(cpus)
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
pub(crate) fn hash_file(path: &Path) -> BenchResult<String> {
    let mut file = File::open(path).map_err(|_| error("executable_open"))?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = file
            .read(&mut bytes)
            .map_err(|_| error("executable_read"))?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(hex(&hash.finalize()))
}
fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    use std::fmt::Write;
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
fn error(context: &'static str) -> BenchError {
    BenchError::new(ErrorCode::InvalidConfig, context)
}

pub fn canonical_hash<T: Serialize>(value: &T) -> BenchResult<String> {
    let value = serde_json::to_value(value).map_err(|_| error("canonical_serialization"))?;
    let bytes = serde_json::to_vec(&value).map_err(|_| error("canonical_serialization"))?;
    Ok(hash_bytes(&bytes))
}

impl EnvironmentDescriptor {
    pub fn read(path: &Path) -> BenchResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| error("remote_descriptor_open"))?;
        let metadata = file
            .metadata()
            .map_err(|_| error("remote_descriptor_metadata"))?;
        if !metadata.is_file() || metadata.len() > 1_048_576 {
            return Err(error("remote_descriptor_size"));
        }
        let mut bytes = Vec::new();
        file.take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| error("remote_descriptor_read"))?;
        if bytes.len() > 1_048_576 {
            return Err(error("remote_descriptor_size"));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| error("remote_descriptor_schema"))?;
        for key in [
            "schema_version",
            "environment_id",
            "network_path",
            "server",
            "server_build",
            "server_settings",
        ] {
            if value.get(key).is_none() {
                return Err(error("remote_descriptor_required"));
            }
        }
        for key in [
            "os_release",
            "kernel",
            "arch",
            "cpu_model",
            "logical_cpus",
            "memory_bytes",
            "virtualization",
            "storage_description",
            "cpu_affinity",
            "cpu_quota",
        ] {
            if value["server"].get(key).is_none() {
                return Err(error("remote_descriptor_required"));
            }
        }
        for key in ["revision", "profile", "toolchain", "features"] {
            if value["server_build"].get(key).is_none() {
                return Err(error("remote_descriptor_required"));
            }
        }
        let mut descriptor: Self =
            serde_json::from_slice(&bytes).map_err(|_| error("remote_descriptor_schema"))?;
        descriptor.validate(&descriptor.environment_id)?;
        descriptor.server_settings.tls_min = descriptor
            .server_settings
            .tls_min
            .trim_start_matches("TLSv")
            .to_owned();
        descriptor.server_settings.tls_max = descriptor
            .server_settings
            .tls_max
            .trim_start_matches("TLSv")
            .to_owned();
        Ok(descriptor)
    }
    pub fn validate(&self, environment_id: &str) -> BenchResult<()> {
        let s = &self.server_settings;
        let host = &self.server;
        let build = &self.server_build;
        let rate = |v: &RateLimitSettings| v.rate_per_second > 0 && v.burst > 0;
        let strings = |vs: &[String]| vs.len() <= 256 && vs.iter().all(|v| printable(v, 128));
        if self.schema_version != 1
            || self.environment_id != environment_id
            || !printable(environment_id, 128)
            || !host
                .os_release
                .as_deref()
                .is_some_and(|v| printable(v, 1024))
            || !host.arch.as_deref().is_some_and(|v| printable(v, 128))
            || ![
                &host.kernel,
                &host.cpu_model,
                &host.virtualization,
                &host.storage_description,
            ]
            .iter()
            .all(|v| v.as_deref().is_none_or(|v| printable(v, 1024)))
            || host.logical_cpus == Some(0)
            || host.memory_bytes == Some(0)
            || host
                .cpu_affinity
                .as_ref()
                .is_some_and(|v| v.len() > 65536 || v.is_empty())
            || host.cpu_quota.is_some_and(|v| !v.is_finite() || v <= 0.0)
            || !printable(&build.revision, 1024)
            || s.workers == 0
            || s.stanza_pool_size_mib == 0
            || !matches!(
                s.logging_level.as_str(),
                "off" | "error" | "warn" | "info" | "debug" | "trace"
            )
            || !printable(&s.storage_backend, 64)
            || s.max_unauthenticated_connections == 0
            || s.max_resources_per_account == 0
            || s.max_directed_presence_recipients_per_resource == 0
            || s.max_connections_per_ip == 0
            || s.max_stanza_bytes == 0
            || s.connection_establishment_timeout_secs == 0
            || s.authentication_timeout_secs == 0
            || s.resource_binding_timeout_secs == 0
            || s.authentication_retries == 0
            || s.resource_binding_retries == 0
            || !rate(&s.connection_attempts_per_ip)
            || !rate(&s.incoming_stanzas_per_connection)
            || !rate(&s.new_recipients_per_connection)
            || s.incoming_xml_per_connection.bytes_per_second == 0
            || s.incoming_xml_per_connection.burst_bytes == 0
            || !strings(&s.host_extensions)
            || !strings(&s.offered_auth_mechanisms)
            || !s
                .offered_auth_mechanisms
                .iter()
                .any(|v| v == "SCRAM-SHA-256")
            || !s.empty_roster
            || !matches!(s.tls_min.as_str(), "1.2" | "1.3" | "TLSv1.2" | "TLSv1.3")
            || !matches!(s.tls_max.as_str(), "1.2" | "1.3" | "TLSv1.2" | "TLSv1.3")
            || s.tls_min.ends_with("1.3") && s.tls_max.ends_with("1.2")
        {
            return Err(error("remote_descriptor_invalid"));
        }
        validate_build(
            &build.profile,
            build.toolchain.as_deref(),
            build.features.as_deref(),
        )
    }
}
