// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::RunConfig,
    error::{BenchError, BenchResult, ErrorCode},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read, path::Path};

pub mod artifacts;
pub mod metadata;
pub mod summary;

pub const RESULT_FILE: &str = "result.json";
const RESULT_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Passed,
    Degraded,
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
            Self::Degraded => 3,
            Self::Interrupted => 130,
        }
    }
    pub fn combine(self, other: Self) -> Self {
        self.max(other)
    }
    /// True when the measurement window completed and its numbers can be read.
    pub fn measured(self) -> bool {
        matches!(self, Self::Passed | Self::Degraded)
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Invalid => "invalid",
        }
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
    Warmup,
    WarmupDrain,
    Measurement,
    MeasurementDrain,
    ConnectionShutdown,
    LocalChildShutdown,
    ArtifactFinalization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
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

impl LatencyKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::DispatchSchedulingLag => "Dispatch lag",
            Self::SchedulingLag => "Start lag",
            Self::MessageScheduleToReceive => "Schedule to receive",
            Self::MessageWriteStartToReceive => "Write to receive",
            Self::MessageWriteDuration => "Write duration",
            Self::LoginScheduleToBound => "Schedule to bound",
            Self::LoginConnectToBound => "Connect to bound",
            Self::TcpConnect => "TCP connect",
            Self::Starttls => "STARTTLS",
            Self::Authenticate => "Authenticate",
            Self::Bind => "Bind",
            Self::Close => "Close",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    InvalidConfig,
    SetupFailure,
    TargetFailure,
    WorkloadFailure,
    DriverLimited,
    OperationsFailed,
    Interrupted,
    EventOverflow,
    AccountingError,
    HistogramError,
    ServerRestarted,
    ArtifactFailure,
    TelemetryUnavailable,
    TelemetryPartial,
}

impl ReasonCode {
    pub const fn status(self) -> RunStatus {
        match self {
            Self::InvalidConfig
            | Self::EventOverflow
            | Self::AccountingError
            | Self::HistogramError
            | Self::ServerRestarted => RunStatus::Invalid,
            Self::Interrupted => RunStatus::Interrupted,
            Self::SetupFailure
            | Self::TargetFailure
            | Self::WorkloadFailure
            | Self::ArtifactFailure => RunStatus::Failed,
            Self::DriverLimited | Self::OperationsFailed => RunStatus::Degraded,
            Self::TelemetryUnavailable | Self::TelemetryPartial => RunStatus::Passed,
        }
    }
}

pub fn status_of(reasons: &[RunReason]) -> RunStatus {
    reasons.iter().fold(RunStatus::Passed, |status, reason| {
        status.combine(reason.code.status())
    })
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
    pub run_id: Option<String>,
    pub status: RunStatus,
    pub reasons: Vec<RunReason>,
    pub started_at_utc: Option<String>,
    pub config: RunConfig,
    pub phases: Vec<PhaseReport>,
    pub driver: DriverMetadata,
    pub target: TargetMetadata,
    pub counters: CounterReport,
    pub rates: RateReport,
    pub latencies: BTreeMap<LatencyKind, HistogramReport>,
    pub telemetry: TelemetryReport,
}

impl RunReport {
    pub fn read(directory: &Path) -> BenchResult<Self> {
        let invalid = |context| BenchError::new(ErrorCode::InvalidPath, context);
        let file = std::fs::File::open(directory.join(RESULT_FILE))
            .map_err(|_| invalid("result_unreadable"))?;
        let mut data = Vec::new();
        file.take(RESULT_LIMIT + 1)
            .read_to_end(&mut data)
            .map_err(|_| invalid("result_unreadable"))?;
        if data.len() as u64 > RESULT_LIMIT {
            return Err(invalid("result_too_large"));
        }
        serde_json::from_slice(&data).map_err(|_| invalid("result_format"))
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
    pub skipped_disconnected: u64,
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
    pub errors: BTreeMap<ErrorCategory, u64>,
}

impl CounterReport {
    pub fn driver_skips(&self) -> u64 {
        self.skipped_scheduler
            + self.skipped_in_flight
            + self.skipped_writer_busy
            + self.skipped_account_busy
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RateReport {
    pub planned_per_second: Option<f64>,
    pub dispatched_in_window_per_second: Option<f64>,
    pub write_succeeded_in_window_per_second: Option<f64>,
    pub received_in_window_per_second: Option<f64>,
    pub cohort_receipts_per_second: Option<f64>,
    pub login_in_window_per_second: Option<f64>,
    pub cohort_logins_per_second: Option<f64>,
    pub closed_cycles_per_second: Option<f64>,
    pub offered_rate_per_second: Option<u32>,
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
    pub count: u64,
    pub min_us: Option<u64>,
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
pub struct DriverMetadata {
    pub version: String,
    pub revision: String,
    pub build_profile: String,
    pub executable_sha256: Option<String>,
    pub worker_count: usize,
    pub cpu_pool_size: usize,
    pub rlimit_nofile_soft: Option<u64>,
    pub rlimit_nofile_hard: Option<u64>,
    pub system: SystemMetadata,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemMetadata {
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub arch: Option<String>,
    pub cpu_model: Option<String>,
    pub logical_cpus: Option<u64>,
    pub memory_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetMetadata {
    pub mode: TargetMode,
    pub xmpp_domain: String,
    pub endpoint: Option<String>,
    pub server_binary_sha256: Option<String>,
    pub server_build: Option<BTreeMap<String, String>>,
    pub negotiated_tls: Option<String>,
    pub cipher: Option<String>,
    pub scram_iterations: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SampledValue {
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
    pub server: ResourceSummary,
    pub generator: ResourceSummary,
    pub policy_rejections: BTreeMap<String, u64>,
    pub identity_changes: u64,
    pub reasons: Vec<RunReason>,
}

impl Default for TelemetryReport {
    fn default() -> Self {
        Self {
            quality: TelemetryStatus::Unavailable,
            samples_ok: 0,
            samples_failed: 0,
            missed_ticks: 0,
            queue_overflows: 0,
            server: ResourceSummary::default(),
            generator: ResourceSummary::default(),
            policy_rejections: BTreeMap::new(),
            identity_changes: 0,
            reasons: Vec::new(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
