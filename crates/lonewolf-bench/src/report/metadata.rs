// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::{TargetConfig, printable};
use sha2::{Digest, Sha256};
use std::fs::File;

pub(crate) fn initial_report(config: &RunConfig, cpu_pool_size: usize) -> RunReport {
    let (mode, domain, endpoint) = match &config.target {
        TargetConfig::Local { .. } => (TargetMode::Local, "localhost".into(), None),
        TargetConfig::Remote {
            xmpp_domain,
            connect_host,
            port,
            ..
        } => (
            TargetMode::Remote,
            xmpp_domain.clone(),
            Some(format!("{connect_host}:{port}")),
        ),
    };
    RunReport {
        run_id: None,
        status: RunStatus::Passed,
        reasons: vec![RunReason {
            code: ReasonCode::TelemetryUnavailable,
            context: None,
        }],
        started_at_utc: None,
        config: config.clone(),
        phases: Vec::with_capacity(10),
        driver: DriverMetadata {
            version: env!("CARGO_PKG_VERSION").into(),
            revision: env!("LONEWOLF_BENCH_REVISION").into(),
            build_profile: env!("LONEWOLF_BENCH_PROFILE").into(),
            executable_sha256: None,
            worker_count: config.measurement.driver_workers,
            cpu_pool_size,
            rlimit_nofile_soft: None,
            rlimit_nofile_hard: None,
            system: SystemMetadata::default(),
        },
        target: TargetMetadata {
            mode,
            xmpp_domain: domain,
            endpoint,
            server_binary_sha256: None,
            server_build: None,
            negotiated_tls: None,
            cipher: None,
            scram_iterations: None,
        },
        counters: CounterReport::default(),
        rates: RateReport::default(),
        latencies: BTreeMap::new(),
        telemetry: TelemetryReport {
            reasons: vec![RunReason {
                code: ReasonCode::TelemetryUnavailable,
                context: None,
            }],
            ..TelemetryReport::default()
        },
    }
}

pub(crate) fn collect_host_facts(report: &mut RunReport) {
    report.driver.system = system_metadata();
    report.driver.executable_sha256 = std::env::current_exe()
        .ok()
        .and_then(|path| hash_file(&path).ok());
    if let TargetConfig::Local { server_binary, .. } = &report.config.target {
        report.target.server_binary_sha256 = hash_file(server_binary).ok();
    }
}

pub(crate) fn system_metadata() -> SystemMetadata {
    let mut system = SystemMetadata::default();
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
        system.os = field(&name.sysname);
        system.kernel = field(&name.release);
        system.arch = field(&name.machine);
    }
    system.logical_cpus = std::thread::available_parallelism()
        .ok()
        .map(|n| n.get() as u64);
    #[cfg(target_os = "linux")]
    {
        system.cpu_model = read_fact("/proc/cpuinfo", 65536)
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("model name\t: ").map(str::to_owned))
            })
            .filter(|v| printable(v, 1024));
        system.memory_bytes = read_fact("/proc/meminfo", 16384).and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("MemTotal:")
                    .and_then(|s| s.split_ascii_whitespace().next())
                    .and_then(|s| s.parse::<u64>().ok())
                    .and_then(|v| v.checked_mul(1024))
            })
        });
    }
    system
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

pub(crate) fn hash_file(path: &Path) -> BenchResult<String> {
    let error = || BenchError::new(ErrorCode::InvalidPath, "binary_unreadable");
    let mut file = File::open(path).map_err(|_| error())?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = file.read(&mut bytes).map_err(|_| error())?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(hex(&hash.finalize()))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
