// SPDX-License-Identifier: Apache-2.0

use crate::config::{MeasurementConfig, MetricsConfig, RunConfig, ScenarioConfig, TargetConfig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod reader;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Passed,
    Failed,
    Interrupted,
    Invalid,
}
impl RunStatus {
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Passed => 0,
            Self::Failed => 1,
            Self::Invalid => 2,
            Self::Interrupted => 130,
        }
    }
    pub fn combine(self, other: Self) -> Self {
        self.max(other)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryStatus {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseName {
    Preflight,
    TargetSetup,
    AccountPrimingConnections,
    WarmupDrain,
    MeasurementDrain,
    ConnectionShutdown,
    LocalChildShutdown,
    ArtifactFinalization,
    Setup,
    Ramp,
    Warmup,
    Measurement,
    DispatchTail,
    Drain,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    Pending,
    Running,
    Completed,
    Truncated,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetMode {
    Local,
    Remote,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPath {
    Loopback,
    PrivateLan,
    Internet,
    Tunnel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Microseconds {
    Microseconds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Dns,
    Tcp,
    Tls,
    Auth,
    Bind,
    Protocol,
    Policy,
    Read,
    Write,
    Deadline,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyKind {
    DispatchSchedulingLag,
    SchedulingLag,
    MessageScheduleToReceive,
    MessageWriteStartToReceive,
    MessageWriteDuration,
    LoginScheduleToBound,
    LoginConnectToBound,
    TcpConnect,
    Starttls,
    Authenticate,
    Bind,
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    InvalidConfig,
    TargetFailure,
    SetupFailure,
    WorkloadFailure,
    ConfiguredCapacity,
    SchedulerMiss,
    EventOverflow,
    AccountingError,
    ServerRestarted,
    ArtifactFailure,
    Interrupted,
    WarmupObservationLag,
    HistogramError,
    OutputLimit,
    TelemetryUnavailable,
    TelemetryPartial,
    UnknownServerBuild,
    ToolchainDifference,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReason {
    pub code: ReasonCode,
    pub context: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReport {
    #[serde(with = "version_one")]
    pub schema_version: u32,
    #[serde(with = "version_one")]
    pub measurement_version: u32,
    pub run_id: Option<String>,
    pub status: RunStatus,
    pub reasons: Vec<RunReason>,
    pub telemetry_status: TelemetryStatus,
    pub started_at_utc: Option<String>,
    pub phases: Vec<PhaseReport>,
    pub config: SanitizedConfig,
    pub driver: DriverMetadata,
    pub target: TargetMetadata,
    pub environment: Option<EnvironmentDescriptor>,
    pub dataset: DatasetIdentity,
    pub counters: CounterReport,
    pub rates: RateReport,
    pub latencies: BTreeMap<LatencyKind, HistogramReport>,
    pub telemetry: TelemetryReport,
    pub artifacts: BTreeMap<ArtifactKind, ArtifactMetadata>,
}

impl RunReport {
    pub fn read(directory: &std::path::Path) -> crate::error::BenchResult<Self> {
        reader::read(directory)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizedConfig {
    #[serde(with = "version_one")]
    pub schema_version: u32,
    pub environment_id: String,
    pub target_mode: TargetMode,
    #[serde(deserialize_with = "strict_config::scenario")]
    pub scenario: ScenarioConfig,
    #[serde(deserialize_with = "strict_config::measurement")]
    pub measurement: MeasurementConfig,
    #[serde(deserialize_with = "strict_config::metrics")]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub instrumentation: Option<InstrumentationMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentationMetadata {
    pub policy_version: u32,
    pub server_metrics_enabled: bool,
    pub generator_metrics_enabled: bool,
    pub raw_capacity_bytes: u64,
    pub control_capacity: u64,
    pub response_body_limit_bytes: u64,
    pub result_limit_bytes: u64,
}

impl From<&RunConfig> for SanitizedConfig {
    fn from(config: &RunConfig) -> Self {
        Self {
            schema_version: config.schema_version,
            environment_id: config.environment_id.clone(),
            target_mode: match config.target {
                TargetConfig::Local { .. } => TargetMode::Local,
                TargetConfig::Remote { .. } => TargetMode::Remote,
            },
            scenario: config.scenario.clone(),
            measurement: config.measurement.clone(),
            metrics: config.metrics.clone(),
            instrumentation: Some(crate::telemetry::instrumentation_metadata(
                match &config.target {
                    TargetConfig::Local { .. } => true,
                    TargetConfig::Remote { metrics_url, .. } => metrics_url.is_some(),
                },
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CounterReport {
    pub planned: u64,
    pub dispatched: u64,
    pub skipped_scheduler: u64,
    pub skipped_in_flight: u64,
    pub skipped_writer_busy: u64,
    pub skipped_account_busy: u64,
    pub cancelled_before_dispatch: u64,
    pub write_succeeded: u64,
    pub message_body_bytes_write_succeeded: u64,
    pub serialized_stanza_bytes_write_succeeded: u64,
    pub write_failed: u64,
    pub write_cancelled: u64,
    pub received_on_time: u64,
    pub received_in_window: u64,
    pub received_during_drain: u64,
    pub late_receipts: u64,
    pub duplicates: u64,
    pub unknown_ids: u64,
    pub wrong_recipient: u64,
    pub unexpected_stanzas: u64,
    pub stale_phase_stanzas: u64,
    pub unreceived_timeout: u64,
    pub unreceived_connection_closed: u64,
    pub unreceived_send_failed: u64,
    pub unreceived_cancelled: u64,
    pub connection_attempts: u64,
    pub login_succeeded: u64,
    pub login_failed: u64,
    pub closed_cleanly: u64,
    pub close_failed: u64,
    pub unexpected_disconnects: u64,
    pub requested_connections: u64,
    pub established_connections: u64,
    pub connections_at_measurement_start: u64,
    pub connections_at_measurement_end: u64,
    pub peak_in_flight: u64,
    pub peak_connections: u64,
    pub dispatched_in_window: u64,
    pub dispatched_during_drain: u64,
    pub write_succeeded_in_window: u64,
    pub write_succeeded_during_drain: u64,
    pub login_in_window: u64,
    pub login_during_drain: u64,
    pub max_dispatch_batch_observed: u64,
    pub errors: BTreeMap<ErrorCategory, u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RateReport {
    #[serde(with = "finite_option")]
    pub planned_per_second: Option<f64>,
    #[serde(with = "finite_option")]
    pub dispatched_in_window_per_second: Option<f64>,
    #[serde(with = "finite_option")]
    pub write_succeeded_in_window_per_second: Option<f64>,
    #[serde(with = "finite_option")]
    pub received_in_window_per_second: Option<f64>,
    #[serde(with = "finite_option")]
    pub cohort_receipts_per_second: Option<f64>,
    #[serde(with = "finite_option")]
    pub login_in_window_per_second: Option<f64>,
    #[serde(with = "finite_option")]
    pub cohort_logins_per_second: Option<f64>,
    #[serde(with = "finite_option")]
    pub closed_cycles_per_second: Option<f64>,
    pub offered_rate_per_second: Option<u32>,
    #[serde(with = "finite_option")]
    pub window_seconds: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseReport {
    pub name: PhaseName,
    pub start_offset_ns: u64,
    pub end_offset_ns: Option<u64>,
    pub planned_end_offset_ns: Option<u64>,
    pub status: PhaseStatus,
    pub counters: CounterReport,
    pub rates: RateReport,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistogramBucket {
    pub upper_bound_us: u64,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistogramReport {
    pub unit: Microseconds,
    #[serde(with = "three_figures")]
    pub significant_figures: u8,
    pub count: u64,
    pub min_us: Option<u64>,
    #[serde(with = "finite_option")]
    pub mean_us: Option<f64>,
    pub p50_us: Option<u64>,
    pub p95_us: Option<u64>,
    pub p99_us: Option<u64>,
    pub max_us: Option<u64>,
    pub sum_us: u64,
    pub buckets: Vec<HistogramBucket>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchPolicyMetadata {
    pub dispatch_quantum_us: u64,
    pub max_dispatch_batch: u64,
    pub max_schedule_lag_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverMetadata {
    pub executable_sha256: Option<String>,
    pub package_version: String,
    pub revision: String,
    pub build_profile: String,
    pub build_target: String,
    pub rustc: String,
    pub worker_count: usize,
    pub scheduler_policy: DispatchPolicyMetadata,
    pub available_parallelism: Option<usize>,
    pub rlimit_nofile_soft: Option<u64>,
    pub rlimit_nofile_hard: Option<u64>,
    pub system: SystemMetadata,
    pub sources: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemMetadata {
    pub os_release: Option<String>,
    pub kernel: Option<String>,
    pub arch: Option<String>,
    pub cpu_model: Option<String>,
    pub logical_cpus: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub virtualization: Option<String>,
    pub storage_description: Option<String>,
    pub cpu_affinity: Option<Vec<u32>>,
    #[serde(with = "finite_option")]
    pub cpu_quota: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerBuildDeclaration {
    pub revision: String,
    pub profile: String,
    pub toolchain: Option<String>,
    pub features: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetMetadata {
    pub mode: TargetMode,
    pub xmpp_domain: String,
    pub configured_endpoint: Option<String>,
    pub negotiated_tls: Option<String>,
    pub cipher: Option<String>,
    pub auth_mechanism: String,
    pub resumption: bool,
    pub cache_primed: bool,
    pub observed_scram_iterations: Option<u32>,
    pub observed_build: Option<BTreeMap<String, String>>,
    #[serde(with = "finite_option")]
    pub observed_process_start_time_seconds: Option<f64>,
    pub local_binary_sha256: Option<String>,
    pub declared_build: Option<ServerBuildDeclaration>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentDescriptor {
    #[serde(with = "version_one")]
    pub schema_version: u32,
    pub environment_id: String,
    pub network_path: NetworkPath,
    pub server: SystemMetadata,
    pub server_build: ServerBuildDeclaration,
    pub server_settings: ServerSettings,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    pub workers: u16,
    pub stanza_pool_size_mib: u64,
    pub logging_level: String,
    pub host_extensions: Vec<String>,
    pub storage_backend: String,
    pub max_unauthenticated_connections: u64,
    pub max_resources_per_account: u64,
    pub max_directed_presence_recipients_per_resource: u64,
    pub max_connections_per_ip: u64,
    pub max_stanza_bytes: u64,
    pub connection_establishment_timeout_secs: u64,
    pub authentication_timeout_secs: u64,
    pub resource_binding_timeout_secs: u64,
    pub authentication_retries: u64,
    pub resource_binding_retries: u64,
    pub connection_attempts_per_ip: RateLimitSettings,
    pub incoming_stanzas_per_connection: RateLimitSettings,
    pub new_recipients_per_connection: RateLimitSettings,
    pub incoming_xml_per_connection: ByteRateLimitSettings,
    pub offered_auth_mechanisms: Vec<String>,
    pub tls_min: String,
    pub tls_max: String,
    pub empty_roster: bool,
    pub offline_storage: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitSettings {
    pub rate_per_second: u64,
    pub burst: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteRateLimitSettings {
    pub bytes_per_second: u64,
    pub burst_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetIdentity {
    pub account_jids_sha256: Option<String>,
    pub account_count: u64,
    pub pair_count: Option<u64>,
    pub resource_policy: String,
    pub availability_policy: String,
    pub body_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SampledValue {
    #[serde(with = "finite_option")]
    pub value: Option<f64>,
    pub sample_count: u64,
    pub start_offset_ns: Option<u64>,
    pub end_offset_ns: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SampledIntegerValue {
    pub value: Option<u64>,
    pub sample_count: u64,
    pub start_offset_ns: Option<u64>,
    pub end_offset_ns: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ResourceSummary {
    pub cpu_average_cores: SampledValue,
    pub rss_mean_bytes: SampledValue,
    pub rss_peak_bytes: SampledIntegerValue,
    pub open_fds_mean: SampledValue,
    pub open_fds_peak: SampledIntegerValue,
    pub incremental_rss_per_connection_bytes: SampledValue,
    pub generator_host_steal_seconds: SampledValue,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryReport {
    pub quality: TelemetryStatus,
    pub samples_ok: u64,
    pub samples_failed: u64,
    pub missed_ticks: u64,
    pub queue_overflows: u64,
    pub bytes: u64,
    pub total_scrape_duration_ms: u64,
    pub server: ResourceSummary,
    pub generator: ResourceSummary,
    pub policy_rejections: BTreeMap<String, u64>,
    pub identity_changes: u64,
    pub reasons: Vec<RunReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Summary,
    Telemetry,
    ServerLog,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactMetadata {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunMetadata {
    pub driver: DriverMetadata,
    pub target: TargetMetadata,
    pub environment: Option<EnvironmentDescriptor>,
    pub dataset: DatasetIdentity,
}

mod finite_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<f64>, serializer: S) -> Result<S::Ok, S::Error> {
        if value.is_some_and(|v| !v.is_finite()) {
            return Err(serde::ser::Error::custom("non-finite report value"));
        }
        value.serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<f64>, D::Error> {
        let value = Option::<f64>::deserialize(deserializer)?;
        if value.is_some_and(|v| !v.is_finite()) {
            return Err(serde::de::Error::custom("non-finite report value"));
        }
        Ok(value)
    }
}

#[cfg(test)]
pub(crate) mod tests;

mod version_one {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u32, serializer: S) -> Result<S::Ok, S::Error> {
        if *value != 1 {
            return Err(serde::ser::Error::custom("unsupported schema version"));
        }
        serializer.serialize_u32(*value)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        let value = u32::deserialize(deserializer)?;
        if value != 1 {
            return Err(serde::de::Error::custom("unsupported schema version"));
        }
        Ok(value)
    }
}

mod three_figures {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u8, serializer: S) -> Result<S::Ok, S::Error> {
        if *value != 3 {
            return Err(serde::ser::Error::custom(
                "histograms require three significant figures",
            ));
        }
        serializer.serialize_u8(*value)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
        let value = u8::deserialize(deserializer)?;
        if value != 3 {
            return Err(serde::de::Error::custom(
                "histograms require three significant figures",
            ));
        }
        Ok(value)
    }
}

pub mod artifacts;
pub mod metadata;
mod strict_config;
pub mod summary;
