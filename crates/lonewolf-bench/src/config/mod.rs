// SPDX-License-Identifier: Apache-2.0

use crate::error::{BenchError, BenchResult, ErrorCode};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

pub const MAX_ACCOUNTS: usize = 100_000;
pub const MAX_PHASE_OPERATIONS: u64 = 10_000_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunConfig {
    pub schema_version: u32,
    pub environment_id: String,
    pub target: TargetConfig,
    pub scenario: ScenarioConfig,
    #[serde(default)]
    pub measurement: MeasurementConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetConfig {
    Local {
        server_binary: PathBuf,
        #[serde(default = "unknown")]
        server_revision: String,
        #[serde(default = "unknown")]
        server_profile: String,
        #[serde(default)]
        server_toolchain: Option<String>,
        #[serde(default)]
        server_features: Option<Vec<String>>,
        #[serde(default = "two")]
        server_workers: u16,
        #[serde(default = "pool_size")]
        stanza_pool_size_mib: u64,
    },
    Remote {
        connect_host: String,
        port: u16,
        xmpp_domain: String,
        credentials_file: PathBuf,
        environment_file: PathBuf,
        #[serde(default)]
        ca_pem: Option<PathBuf>,
        #[serde(default)]
        metrics_url: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScenarioConfig {
    Idle {
        #[serde(default = "connections")]
        connections: usize,
    },
    Messages {
        #[serde(default = "pairs")]
        pairs: usize,
        #[serde(default = "message_rate")]
        rate_per_second: u32,
        #[serde(default = "body_size")]
        body_bytes: usize,
    },
    Churn {
        #[serde(default = "accounts")]
        accounts: usize,
        #[serde(default = "churn_rate")]
        rate_per_second: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MeasurementConfig {
    pub warmup_ms: u64,
    pub duration_ms: u64,
    pub operation_timeout_ms: u64,
    pub setup_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
    pub ramp_rate_per_second: u32,
    pub connect_concurrency: usize,
    pub driver_workers: usize,
    pub max_in_flight: usize,
    pub dispatch_quantum_us: u64,
    pub max_dispatch_batch: u64,
    pub max_schedule_lag_ms: u64,
}

impl Default for MeasurementConfig {
    fn default() -> Self {
        Self {
            warmup_ms: 10_000,
            duration_ms: 60_000,
            operation_timeout_ms: 10_000,
            setup_timeout_ms: 900_000,
            shutdown_timeout_ms: 10_000,
            ramp_rate_per_second: 10,
            connect_concurrency: 16,
            driver_workers: 2,
            max_in_flight: 4096,
            dispatch_quantum_us: 1000,
            max_dispatch_batch: 256,
            max_schedule_lag_ms: 100,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    pub interval_ms: u64,
    pub timeout_ms: u64,
}
impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            interval_ms: 1000,
            timeout_ms: 2000,
        }
    }
}

fn unknown() -> String {
    "unknown".into()
}
fn two() -> u16 {
    2
}
fn pool_size() -> u64 {
    256
}
fn connections() -> usize {
    100
}
fn pairs() -> usize {
    50
}
fn message_rate() -> u32 {
    1000
}
fn body_size() -> usize {
    256
}
fn accounts() -> usize {
    64
}
fn churn_rate() -> u32 {
    20
}

fn invalid(context: &'static str) -> BenchError {
    BenchError::new(ErrorCode::InvalidConfig, context)
}
fn require(condition: bool, context: &'static str) -> BenchResult<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(context))
    }
}

pub fn printable(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.chars().count() <= max
        && !value.trim().is_empty()
        && value.chars().all(|c| !c.is_control())
}

pub fn normalize_dns(value: &str) -> BenchResult<String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    require(
        !value.is_empty() && value.len() <= 253 && value.is_ascii(),
        "invalid DNS name",
    )?;
    for label in value.split('.') {
        require(
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid DNS name",
        )?;
    }
    require(
        value.parse::<IpAddr>().is_err(),
        "DNS name cannot be an IP address",
    )?;
    Ok(value.to_ascii_lowercase())
}

pub fn validate_build(
    profile: &str,
    toolchain: Option<&str>,
    features: Option<&[String]>,
) -> BenchResult<()> {
    require(printable(profile, 64), "invalid server profile declaration")?;
    if let Some(value) = toolchain {
        require(
            printable(value, 1024),
            "invalid server toolchain declaration",
        )?;
    }
    if let Some(features) = features {
        require(features.len() <= 256, "too many server features")?;
        for (index, feature) in features.iter().enumerate() {
            require(
                printable(feature, 128),
                "invalid server feature declaration",
            )?;
            require(
                !features[..index].contains(feature),
                "duplicate server feature declaration",
            )?;
        }
    }
    Ok(())
}

pub fn validate_metrics_url(value: &str) -> BenchResult<()> {
    let uri: http::Uri = value.parse().map_err(|_| invalid("invalid metrics URL"))?;
    let authority = uri
        .authority()
        .ok_or_else(|| invalid("metrics URL requires a host"))?;
    let host = authority.host();
    require(
        !host.is_empty() && !authority.as_str().contains('@'),
        "invalid metrics authority",
    )?;
    let port_suffix = authority
        .as_str()
        .strip_prefix(host)
        .ok_or_else(|| invalid("invalid metrics authority"))?;
    require(
        port_suffix.is_empty()
            || port_suffix
                .strip_prefix(':')
                .and_then(|port| port.parse::<u16>().ok())
                .is_some_and(|port| port != 0),
        "invalid metrics port",
    )?;
    if let Some(address) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        require(
            address.parse::<std::net::Ipv6Addr>().is_ok(),
            "invalid metrics IPv6 address",
        )?;
    } else if host.parse::<IpAddr>().is_err() {
        normalize_dns(host)?;
    }
    require(
        uri.scheme_str() == Some("http")
            && uri.path() == "/metrics"
            && uri.query().is_none()
            && !value.contains('#'),
        "metrics URL must be explicit HTTP with path /metrics",
    )
}

pub fn absolute_path(base: &Path, path: &Path) -> BenchResult<PathBuf> {
    require(!path.as_os_str().is_empty(), "path must not be empty")?;
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    })
}

pub fn validate_new_output(path: &Path) -> BenchResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(BenchError::new(
            ErrorCode::OutputExists,
            "output path already exists",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            if parent.is_dir() && path.file_name().is_some() {
                Ok(())
            } else {
                Err(BenchError::new(
                    ErrorCode::InvalidPath,
                    "output parent directory is unavailable",
                ))
            }
        }
        Err(_) => Err(BenchError::new(
            ErrorCode::InvalidPath,
            "cannot inspect output path",
        )),
    }
}

impl RunConfig {
    pub fn load(path: &Path, server_override: Option<&Path>) -> BenchResult<Self> {
        let cwd =
            std::env::current_dir().map_err(|_| invalid("working directory is unavailable"))?;
        let path = absolute_path(&cwd, path)?;
        let metadata = fs::metadata(&path)
            .map_err(|_| BenchError::new(ErrorCode::ConfigRead, "cannot read configuration"))?;
        require(
            metadata.len() <= 1_048_576,
            "configuration exceeds size limit",
        )?;
        let text = fs::read_to_string(&path)
            .map_err(|_| BenchError::new(ErrorCode::ConfigRead, "cannot read configuration"))?;
        let mut config: Self =
            toml::from_str(&text).map_err(|_| invalid("invalid configuration syntax or fields"))?;
        let base = path
            .parent()
            .ok_or_else(|| invalid("configuration directory is unavailable"))?;
        match &mut config.target {
            TargetConfig::Local {
                server_binary,
                server_features,
                ..
            } => {
                *server_binary = match server_override {
                    Some(value) => absolute_path(&cwd, value)?,
                    None => absolute_path(base, server_binary)?,
                };
                if let Some(features) = server_features {
                    features.sort_unstable();
                }
            }
            TargetConfig::Remote {
                connect_host,
                xmpp_domain,
                credentials_file,
                environment_file,
                ca_pem,
                ..
            } => {
                require(
                    server_override.is_none(),
                    "server override requires a local target",
                )?;
                *xmpp_domain = normalize_dns(xmpp_domain)?;
                if connect_host.parse::<IpAddr>().is_err() {
                    *connect_host = normalize_dns(connect_host)?;
                }
                *credentials_file = absolute_path(base, credentials_file)?;
                *environment_file = absolute_path(base, environment_file)?;
                if let Some(ca) = ca_pem {
                    *ca = absolute_path(base, ca)?;
                }
            }
        }
        config.validate()?;
        Ok(config)
    }

    pub fn account_count(&self) -> usize {
        match self.scenario {
            ScenarioConfig::Idle { connections } => connections,
            ScenarioConfig::Messages { pairs, .. } => pairs.checked_mul(2).unwrap_or_default(),
            ScenarioConfig::Churn { accounts, .. } => accounts,
        }
    }

    pub fn offered_rate(&self) -> Option<u32> {
        match self.scenario {
            ScenarioConfig::Idle { .. } => None,
            ScenarioConfig::Messages {
                rate_per_second, ..
            }
            | ScenarioConfig::Churn {
                rate_per_second, ..
            } => Some(rate_per_second),
        }
    }

    pub fn validate(&self) -> BenchResult<()> {
        require(self.schema_version == 1, "unsupported configuration schema")?;
        require(
            printable(&self.environment_id, 64),
            "invalid environment identifier",
        )?;
        require(
            (1..=MAX_ACCOUNTS).contains(&self.account_count()),
            "account count is out of bounds",
        )?;
        if let ScenarioConfig::Messages { body_bytes, .. } = self.scenario {
            require(
                (1..=65_536).contains(&body_bytes),
                "body size is out of bounds",
            )?;
        }
        match &self.target {
            TargetConfig::Local {
                server_binary,
                server_profile,
                server_revision,
                server_toolchain,
                server_features,
                server_workers,
                stanza_pool_size_mib,
            } => {
                require(
                    !server_binary.as_os_str().is_empty(),
                    "server binary path is empty",
                )?;
                require(
                    printable(server_revision, 1024),
                    "invalid server revision declaration",
                )?;
                validate_build(
                    server_profile,
                    server_toolchain.as_deref(),
                    server_features.as_deref(),
                )?;
                require(
                    (1..=256).contains(server_workers),
                    "server workers are out of bounds",
                )?;
                require(
                    *stanza_pool_size_mib >= 8
                        && stanza_pool_size_mib.is_power_of_two()
                        && stanza_pool_size_mib
                            .checked_mul(1_048_576)
                            .and_then(|v| usize::try_from(v).ok())
                            .is_some(),
                    "invalid stanza pool size",
                )?;
            }
            TargetConfig::Remote {
                connect_host,
                port,
                xmpp_domain,
                credentials_file,
                environment_file,
                ca_pem,
                metrics_url,
            } => {
                require(*port != 0, "target port must be nonzero")?;
                normalize_dns(xmpp_domain)?;
                if connect_host.parse::<IpAddr>().is_err() {
                    normalize_dns(connect_host)?;
                }
                require(
                    !credentials_file.as_os_str().is_empty()
                        && !environment_file.as_os_str().is_empty()
                        && ca_pem.as_ref().is_none_or(|p| !p.as_os_str().is_empty()),
                    "remote input path is empty",
                )?;
                if let Some(url) = metrics_url {
                    validate_metrics_url(url)?;
                }
            }
        }
        let m = &self.measurement;
        require(
            (1..=3_600_000).contains(&m.duration_ms),
            "measurement duration is out of bounds",
        )?;
        require(
            (1..=600_000).contains(&m.operation_timeout_ms)
                && (1..=600_000).contains(&m.shutdown_timeout_ms)
                && (1..=86_400_000).contains(&m.setup_timeout_ms),
            "timeout is out of bounds",
        )?;
        require(
            (1..=256).contains(&m.driver_workers),
            "driver workers are out of bounds",
        )?;
        require(
            (1..=65_536).contains(&m.connect_concurrency)
                && (1..=65_536).contains(&m.max_in_flight),
            "concurrency is out of bounds",
        )?;
        require(
            (1000..=100_000).contains(&m.dispatch_quantum_us)
                && (1..=4096).contains(&m.max_dispatch_batch)
                && (1..=1000).contains(&m.max_schedule_lag_ms)
                && m.max_schedule_lag_ms >= m.dispatch_quantum_us.div_ceil(1000)
                && m.max_schedule_lag_ms < m.operation_timeout_ms,
            "invalid dispatch policy",
        )?;
        for rate in std::iter::once(m.ramp_rate_per_second).chain(self.offered_rate()) {
            require((1..=1_000_000).contains(&rate), "rate is out of bounds")?;
            require(
                (u128::from(rate) * u128::from(m.dispatch_quantum_us)).div_ceil(1_000_000)
                    <= u128::from(m.max_dispatch_batch),
                "rate exceeds dispatch batch capacity",
            )?;
        }
        for duration in [m.warmup_ms, m.duration_ms] {
            require(
                duration
                    .checked_add(m.operation_timeout_ms)
                    .and_then(|v| v.checked_add(m.shutdown_timeout_ms))
                    .and_then(|v| v.checked_mul(1_000_000))
                    .is_some(),
                "phase duration overflow",
            )?;
            if let Some(rate) = self.offered_rate() {
                let count = (u128::from(duration) * u128::from(rate)).div_ceil(1000);
                require(
                    count <= u128::from(MAX_PHASE_OPERATIONS),
                    "phase operation limit exceeded",
                )?;
                require(
                    usize::try_from(count)
                        .ok()
                        .and_then(|v| v.checked_mul(4))
                        .is_some(),
                    "ledger memory requirement overflow",
                )?;
            }
        }
        let body_bytes = match self.scenario {
            ScenarioConfig::Messages { body_bytes, .. } => body_bytes,
            _ => 0,
        };
        require(
            body_bytes
                .checked_mul(m.max_in_flight)
                .and_then(|bytes| bytes.checked_add(64 * 1024 * 1024))
                .is_some(),
            "workload memory requirement overflow",
        )?;
        require(
            (1000..=60_000).contains(&self.metrics.interval_ms)
                && (1..=10_000).contains(&self.metrics.timeout_ms),
            "metrics timing is out of bounds",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
