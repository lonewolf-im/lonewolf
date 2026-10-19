// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    config::{RunConfig, TargetConfig},
    measurement::{LedgerTopology, MeasurementResult},
};
use std::{num::NonZeroU32, time::Duration};

pub(super) const KINDS: [LatencyKind; 12] = [
    LatencyKind::DispatchSchedulingLag,
    LatencyKind::SchedulingLag,
    LatencyKind::MessageScheduleToReceive,
    LatencyKind::MessageWriteStartToReceive,
    LatencyKind::MessageWriteDuration,
    LatencyKind::LoginScheduleToBound,
    LatencyKind::LoginConnectToBound,
    LatencyKind::TcpConnect,
    LatencyKind::Starttls,
    LatencyKind::Authenticate,
    LatencyKind::Bind,
    LatencyKind::Close,
];
pub(super) const PHASES: [PhaseName; 10] = [
    PhaseName::Preflight,
    PhaseName::TargetSetup,
    PhaseName::AccountPrimingConnections,
    PhaseName::Warmup,
    PhaseName::WarmupDrain,
    PhaseName::Measurement,
    PhaseName::MeasurementDrain,
    PhaseName::ConnectionShutdown,
    PhaseName::LocalChildShutdown,
    PhaseName::ArtifactFinalization,
];

fn sum(values: &[u64]) -> Option<u64> {
    values.iter().try_fold(0u64, |s, v| s.checked_add(*v))
}
fn hash(value: Option<&str>) -> bool {
    value.is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn known(value: Option<&str>) -> bool {
    value.is_some_and(|v| crate::config::printable(v, 1024) && v != "unknown")
}
fn near(a: f64, b: f64) -> bool {
    a.is_finite()
        && b.is_finite()
        && (a - b).abs() <= f64::EPSILON * 8.0 * a.abs().max(b.abs()).max(1.0)
}
fn safe(value: &Value) -> bool {
    match value {
        Value::String(v) => v.len() <= 1024 && !v.chars().any(char::is_control),
        Value::Array(v) => v.len() <= 65536 && v.iter().all(safe),
        Value::Object(v) => v.values().all(safe),
        _ => true,
    }
}

pub(super) fn validate(run: &RunReport, side: &str, report: &mut ComparisonReport) -> bool {
    if serde_json::to_value(run).is_err()
        || !projection(run).values().all(safe)
        || run
            .target
            .declared_build
            .as_ref()
            .is_some_and(|v| !safe(&json!(v)))
        || run.target.observed_build.as_ref().is_some_and(|v| {
            ["version", "commit"].iter().any(|k| {
                v.get(*k)
                    .is_some_and(|v| !crate::config::printable(v, 1024))
            })
        })
    {
        report.refuse(
            side,
            "result",
            "nonfinite, unsupported or invalid report value",
            ReasonCode::InvalidConfig,
        );
        return false;
    }
    let mut check = |condition: bool, path: &str, message: &str, code| {
        if !condition {
            report.refuse(side, path, message, code);
        }
    };
    check(
        run.schema_version == 1 && run.measurement_version == 1,
        "schema_version",
        "unsupported measurement semantics",
        ReasonCode::InvalidConfig,
    );
    check(
        run.status == RunStatus::Passed,
        "status",
        match run.status {
            RunStatus::Passed => "passed",
            RunStatus::Failed => "workload failed",
            RunStatus::Interrupted => "workload interrupted",
            RunStatus::Invalid => "workload invalid",
        },
        ReasonCode::WorkloadFailure,
    );
    for reason in &run.reasons {
        if !matches!(
            reason.code,
            ReasonCode::TelemetryUnavailable
                | ReasonCode::TelemetryPartial
                | ReasonCode::UnknownServerBuild
                | ReasonCode::ToolchainDifference
        ) {
            check(false, "reasons", reason_name(reason.code), reason.code);
        }
    }
    check(
        run.target.mode == run.config.target_mode,
        "target.mode",
        "target mode contradicts configuration",
        ReasonCode::InvalidConfig,
    );
    check(
        hash(run.driver.executable_sha256.as_deref()),
        "driver.executable_sha256",
        "required SHA-256 is unavailable or invalid",
        ReasonCode::InvalidConfig,
    );
    check(
        hash(run.dataset.account_jids_sha256.as_deref()),
        "dataset.account_jids_sha256",
        "required ordered dataset hash is unavailable or invalid",
        ReasonCode::InvalidConfig,
    );
    for (path, value) in [
        (
            "driver.package_version",
            Some(run.driver.package_version.as_str()),
        ),
        ("driver.revision", Some(run.driver.revision.as_str())),
        (
            "driver.build_profile",
            Some(run.driver.build_profile.as_str()),
        ),
        (
            "driver.build_target",
            Some(run.driver.build_target.as_str()),
        ),
        ("driver.rustc", Some(run.driver.rustc.as_str())),
        (
            "driver.system.os_release",
            run.driver.system.os_release.as_deref(),
        ),
        ("driver.system.arch", run.driver.system.arch.as_deref()),
        ("target.xmpp_domain", Some(run.target.xmpp_domain.as_str())),
        (
            "target.negotiated_tls",
            run.target.negotiated_tls.as_deref(),
        ),
        ("target.cipher", run.target.cipher.as_deref()),
        (
            "dataset.resource_policy",
            Some(run.dataset.resource_policy.as_str()),
        ),
        (
            "dataset.availability_policy",
            Some(run.dataset.availability_policy.as_str()),
        ),
    ] {
        check(
            known(value),
            path,
            "required compatibility fact is unavailable",
            ReasonCode::InvalidConfig,
        );
    }
    check(
        system(&run.driver.system),
        "driver.system",
        "invalid hardware fact",
        ReasonCode::InvalidConfig,
    );
    check(
        run.driver.available_parallelism != Some(0)
            && run.driver.rlimit_nofile_soft != Some(0)
            && run.driver.rlimit_nofile_hard != Some(0)
            && run
                .driver
                .rlimit_nofile_soft
                .zip(run.driver.rlimit_nofile_hard)
                .is_none_or(|(soft, hard)| soft <= hard),
        "driver",
        "invalid runtime resource descriptor",
        ReasonCode::InvalidConfig,
    );
    check(
        run.target.auth_mechanism == "SCRAM-SHA-256"
            && !run.target.resumption
            && run.target.cache_primed,
        "target.cache_primed",
        "required SCRAM priming or TLS policy is not established",
        ReasonCode::InvalidConfig,
    );
    check(
        run.target.observed_scram_iterations.is_some_and(|n| n > 0),
        "target.observed_scram_iterations",
        "required common iteration count is unavailable",
        ReasonCode::InvalidConfig,
    );
    check(
        run.target.mode != TargetMode::Local || hash(run.target.local_binary_sha256.as_deref()),
        "target.local_binary_sha256",
        "required local binary hash is unavailable",
        ReasonCode::InvalidConfig,
    );
    let config = RunConfig {
        schema_version: run.config.schema_version,
        environment_id: run.config.environment_id.clone(),
        target: TargetConfig::Local {
            server_binary: "server".into(),
            server_revision: "declared".into(),
            server_profile: "release".into(),
            server_toolchain: None,
            server_features: Some(Vec::new()),
            server_workers: 2,
            stanza_pool_size_mib: 256,
        },
        scenario: run.config.scenario.clone(),
        measurement: run.config.measurement.clone(),
        metrics: run.config.metrics.clone(),
    };
    check(
        config.validate().is_ok(),
        "config",
        "invalid workload or timing settings",
        ReasonCode::InvalidConfig,
    );
    let expected = metadata::initial_report(&config).dataset;
    check(
        run.dataset.account_count == expected.account_count
            && run.dataset.pair_count == expected.pair_count
            && run.dataset.body_bytes == expected.body_bytes,
        "dataset",
        "dataset topology contradicts scenario",
        ReasonCode::AccountingError,
    );
    let m = &run.config.measurement;
    check(
        run.driver.worker_count == m.driver_workers
            && run.driver.scheduler_policy.dispatch_quantum_us == m.dispatch_quantum_us
            && run.driver.scheduler_policy.max_dispatch_batch == m.max_dispatch_batch
            && run.driver.scheduler_policy.max_schedule_lag_ms == m.max_schedule_lag_ms,
        "driver.scheduler_policy",
        "driver configuration is inconsistent",
        ReasonCode::InvalidConfig,
    );
    match &run.config.instrumentation {
        None => check(
            false,
            "config.instrumentation",
            "required instrumentation declaration is unavailable",
            ReasonCode::InvalidConfig,
        ),
        Some(instrumentation) => {
            let expected =
                crate::telemetry::instrumentation_metadata(instrumentation.server_metrics_enabled);
            check(
                *instrumentation == expected,
                "config.instrumentation",
                "unknown or inconsistent collection policy",
                ReasonCode::InvalidConfig,
            );
            check(
                run.target.mode != TargetMode::Local || instrumentation.server_metrics_enabled,
                "config.instrumentation.server_metrics_enabled",
                "local server collection must be configured enabled",
                ReasonCode::InvalidConfig,
            );
        }
    }
    match &run.environment {
        None => check(
            false,
            "environment",
            "required environment declaration is unavailable",
            ReasonCode::InvalidConfig,
        ),
        Some(env) => {
            check(
                system(&env.server),
                "environment.server",
                "invalid hardware fact",
                ReasonCode::InvalidConfig,
            );
            check(
                env.validate(&run.config.environment_id).is_ok(),
                "environment",
                "invalid environment or resolved policy declaration",
                ReasonCode::InvalidConfig,
            );
            for (path, value) in [
                (
                    "environment.server.os_release",
                    env.server.os_release.as_deref(),
                ),
                ("environment.server.arch", env.server.arch.as_deref()),
            ] {
                check(
                    known(value),
                    path,
                    "required host fact is unavailable",
                    ReasonCode::InvalidConfig,
                );
            }
            check(
                run.target.mode != TargetMode::Local || env.network_path == NetworkPath::Loopback,
                "environment.network_path",
                "local target requires loopback topology",
                ReasonCode::InvalidConfig,
            );
            if let Some(build) = &run.target.declared_build {
                let canonical = |v: &Option<Vec<String>>| {
                    let mut v = v.clone();
                    if let Some(v) = &mut v {
                        v.sort();
                    }
                    v
                };
                check(
                    build.profile == env.server_build.profile
                        && canonical(&build.features) == canonical(&env.server_build.features)
                        && build.revision == env.server_build.revision
                        && build.toolchain == env.server_build.toolchain,
                    "target.declared_build",
                    "target and environment declarations conflict",
                    ReasonCode::InvalidConfig,
                );
            }
        }
    }
    match &run.target.declared_build {
        None => check(
            false,
            "target.declared_build",
            "required server build declaration is unavailable",
            ReasonCode::InvalidConfig,
        ),
        Some(build) => {
            check(
                known(Some(&build.profile)),
                "target.declared_build.profile",
                "server profile is unknown",
                ReasonCode::UnknownServerBuild,
            );
            check(
                build.features.is_some(),
                "target.declared_build.features",
                "effective named feature set is unknown",
                ReasonCode::UnknownServerBuild,
            );
            check(
                crate::config::validate_build(
                    &build.profile,
                    build.toolchain.as_deref(),
                    build.features.as_deref(),
                )
                .is_ok(),
                "target.declared_build",
                "invalid server build declaration",
                ReasonCode::InvalidConfig,
            );
            if let Some(observed) = run
                .target
                .observed_build
                .as_ref()
                .and_then(|v| v.get("commit"))
            {
                let hex = |v: &str| !v.is_empty() && v.bytes().all(|v| v.is_ascii_hexdigit());
                if build.revision.len() == 40
                    && hex(&build.revision)
                    && (1..=40).contains(&observed.len())
                    && hex(observed)
                {
                    check(
                        build.revision[..observed.len()].eq_ignore_ascii_case(observed),
                        "target.observed_build.commit",
                        "observed revision conflicts with declared full commit",
                        ReasonCode::InvalidConfig,
                    );
                }
            }
        }
    }
    check(
        run.telemetry.identity_changes == 0,
        "telemetry.identity_changes",
        "observed server identity changed",
        ReasonCode::ServerRestarted,
    );
    check(
        run.telemetry_status == run.telemetry.quality,
        "telemetry_status",
        "telemetry quality is inconsistent",
        ReasonCode::InvalidConfig,
    );
    let complete = run.phases.len() == PHASES.len()
        && run.phases.iter().zip(PHASES).all(|(p, name)| {
            p.name == name
                && p.status == PhaseStatus::Completed
                && p.end_offset_ns.is_some_and(|end| end >= p.start_offset_ns)
        })
        && run
            .phases
            .windows(2)
            .all(|ps| ordered_boundary(&ps[0], &ps[1], &run.config.scenario));
    check(
        complete,
        "phases",
        "all ten lifecycle phases must be complete and ordered",
        ReasonCode::AccountingError,
    );
    let measurement = run.phases.iter().find(|p| p.name == PhaseName::Measurement);
    let window = measurement.is_some_and(|p| {
        p.planned_end_offset_ns
            .zip(p.end_offset_ns)
            .is_some_and(|(planned, end)| {
                planned.checked_sub(p.start_offset_ns) == m.duration_ms.checked_mul(1_000_000)
                    && end >= planned
            })
    });
    check(
        window,
        "phases.measurement",
        "nominal measurement window is incomplete or inconsistent",
        ReasonCode::AccountingError,
    );
    check(
        measurement.is_some_and(|phase| {
            without_connection_gauges(&phase.counters) == without_connection_gauges(&run.counters)
                && phase.rates == run.rates
        }),
        "phases.measurement.counters",
        "root measurement totals contradict the measurement phase",
        ReasonCode::AccountingError,
    );
    check(
        counters(&run.counters, &run.config.scenario),
        "counters",
        "invalid measurement accounting",
        ReasonCode::AccountingError,
    );
    let rate = match run.config.scenario {
        ScenarioConfig::Idle { .. } => None,
        ScenarioConfig::Messages {
            rate_per_second, ..
        }
        | ScenarioConfig::Churn {
            rate_per_second, ..
        } => Some(rate_per_second),
    };
    check(
        rates(
            &run.counters,
            &run.rates,
            &run.config.scenario,
            m.duration_ms,
        ),
        "rates",
        "rates contradict nominal window or populations",
        ReasonCode::AccountingError,
    );
    if let Some(rate) = rate {
        check(
            u128::from(run.counters.planned)
                == (u128::from(rate) * u128::from(m.duration_ms)).div_ceil(1000),
            "counters.planned",
            "planned cohort contradicts offered schedule",
            ReasonCode::AccountingError,
        );
    }
    for phase in &run.phases {
        if matches!(phase.name, PhaseName::Warmup | PhaseName::Measurement) {
            let duration = if phase.name == PhaseName::Warmup {
                m.warmup_ms
            } else {
                m.duration_ms
            };
            check(
                counters(&phase.counters, &run.config.scenario),
                "phases.counters",
                "invalid timed-phase accounting",
                ReasonCode::AccountingError,
            );
            check(
                rates(
                    &phase.counters,
                    &phase.rates,
                    &run.config.scenario,
                    duration,
                ),
                "phases.rates",
                "invalid timed-phase rate",
                ReasonCode::AccountingError,
            );
            check(
                passing(&phase.counters),
                "phases.counters",
                "timed phase contains workload or generator failures",
                ReasonCode::WorkloadFailure,
            );
            check(
                occupancy(&phase.counters, &config),
                "phases.counters",
                "timed phase occupancy exceeds configured bounds",
                ReasonCode::AccountingError,
            );
            if let Some(rate) = rate {
                check(
                    u128::from(phase.counters.planned)
                        == (u128::from(rate) * u128::from(duration)).div_ceil(1000),
                    "phases.counters.planned",
                    "timed phase cohort contradicts the offered schedule",
                    ReasonCode::AccountingError,
                );
            }
        }
    }
    let c = &run.counters;
    check(
        passing(c),
        "counters",
        "workload or generator failures prevent comparison",
        ReasonCode::WorkloadFailure,
    );
    check(
        occupancy(c, &config),
        "counters",
        "observed generator occupancy exceeds configured bounds",
        ReasonCode::AccountingError,
    );
    if let ScenarioConfig::Messages { body_bytes, .. } = run.config.scenario {
        check(
            c.write_succeeded.checked_mul(body_bytes as u64)
                == Some(c.message_body_bytes_write_succeeded)
                && c.serialized_stanza_bytes_write_succeeded
                    >= c.message_body_bytes_write_succeeded,
            "counters.message_body_bytes_write_succeeded",
            "successful-write byte populations are inconsistent",
            ReasonCode::AccountingError,
        );
    }
    if let ScenarioConfig::Idle { connections } = run.config.scenario {
        check(
            c.requested_connections == connections as u64
                && c.established_connections == connections as u64
                && c.connections_at_measurement_start == connections as u64
                && c.connections_at_measurement_end == connections as u64,
            "counters.connections_at_measurement_end",
            "idle cohort was not sustained",
            ReasonCode::WorkloadFailure,
        );
    }
    check(
        histograms(run),
        "latencies",
        "invalid histogram totals, quantiles or sample populations",
        ReasonCode::HistogramError,
    );
    true
}
fn ordered_boundary(previous: &PhaseReport, next: &PhaseReport, scenario: &ScenarioConfig) -> bool {
    let Some(observed_end) = previous.end_offset_ns else {
        return false;
    };
    let traffic = matches!(
        scenario,
        ScenarioConfig::Messages { .. } | ScenarioConfig::Churn { .. }
    );
    let timed_drain = matches!(
        (previous.name, next.name),
        (PhaseName::Warmup, PhaseName::WarmupDrain)
            | (PhaseName::Measurement, PhaseName::MeasurementDrain)
    );
    if traffic && timed_drain {
        previous
            .planned_end_offset_ns
            .zip(next.end_offset_ns)
            .is_some_and(|(nominal, drain_end)| {
                previous.start_offset_ns <= nominal
                    && next.start_offset_ns == nominal
                    && nominal <= observed_end
                    && observed_end <= drain_end
            })
    } else {
        observed_end <= next.start_offset_ns
    }
}
fn passing(c: &CounterReport) -> bool {
    sum(&[
        c.skipped_scheduler,
        c.skipped_in_flight,
        c.skipped_writer_busy,
        c.skipped_account_busy,
        c.cancelled_before_dispatch,
        c.write_failed,
        c.write_cancelled,
        c.unreceived_timeout,
        c.unreceived_connection_closed,
        c.unreceived_send_failed,
        c.unreceived_cancelled,
        c.login_failed,
        c.close_failed,
        c.unexpected_disconnects,
        c.unknown_ids,
        c.wrong_recipient,
        c.unexpected_stanzas,
        c.stale_phase_stanzas,
    ]) == Some(0)
        && c.errors.values().all(|v| *v == 0)
}
fn without_connection_gauges(c: &CounterReport) -> CounterReport {
    CounterReport {
        requested_connections: 0,
        established_connections: 0,
        connections_at_measurement_start: 0,
        connections_at_measurement_end: 0,
        peak_connections: 0,
        ..c.clone()
    }
}
fn reason_name(code: ReasonCode) -> &'static str {
    match code {
        ReasonCode::SchedulerMiss => "scheduler integrity failure",
        ReasonCode::AccountingError => "accounting integrity failure",
        ReasonCode::HistogramError => "histogram integrity failure",
        ReasonCode::EventOverflow => "event queue overflow",
        ReasonCode::ServerRestarted => "observed server restart",
        ReasonCode::Interrupted => "interrupted workload",
        _ => "recorded workload or artifact failure",
    }
}
fn system(value: &SystemMetadata) -> bool {
    [
        &value.kernel,
        &value.cpu_model,
        &value.virtualization,
        &value.storage_description,
    ]
    .iter()
    .all(|v| {
        v.as_deref()
            .is_none_or(|v| crate::config::printable(v, 1024))
    }) && value.logical_cpus != Some(0)
        && value.memory_bytes != Some(0)
        && value.cpu_quota.is_none_or(|v| v.is_finite() && v > 0.0)
        && value
            .cpu_affinity
            .as_ref()
            .is_none_or(|v| !v.is_empty() && v.len() <= 65536)
}
fn counters(c: &CounterReport, scenario: &ScenarioConfig) -> bool {
    let common = Some(c.planned)
        == sum(&[
            c.dispatched,
            c.skipped_scheduler,
            c.skipped_in_flight,
            c.skipped_writer_busy,
            c.skipped_account_busy,
            c.cancelled_before_dispatch,
        ])
        && Some(c.dispatched) == sum(&[c.dispatched_in_window, c.dispatched_during_drain]);
    common
        && inapplicable_counters_are_zero(c, scenario)
        && match scenario {
            ScenarioConfig::Idle { .. } => without_connection_gauges(c) == CounterReport::default(),
            ScenarioConfig::Messages { .. } => {
                Some(c.dispatched) == sum(&[c.write_succeeded, c.write_failed, c.write_cancelled])
                    && Some(c.dispatched)
                        == sum(&[
                            c.received_on_time,
                            c.unreceived_timeout,
                            c.unreceived_connection_closed,
                            c.unreceived_send_failed,
                            c.unreceived_cancelled,
                        ])
                    && Some(c.received_on_time)
                        == sum(&[c.received_in_window, c.received_during_drain])
                    && Some(c.write_succeeded)
                        == sum(&[c.write_succeeded_in_window, c.write_succeeded_during_drain])
                    && c.connection_attempts == 0
                    && c.login_succeeded == 0
                    && c.closed_cleanly == 0
            }
            ScenarioConfig::Churn { .. } => {
                c.connection_attempts == c.dispatched
                    && Some(c.connection_attempts) == sum(&[c.login_succeeded, c.login_failed])
                    && Some(c.login_succeeded) == sum(&[c.closed_cleanly, c.close_failed])
                    && Some(c.login_succeeded) == sum(&[c.login_in_window, c.login_during_drain])
                    && c.write_succeeded == 0
                    && c.received_on_time == 0
            }
        }
}
fn occupancy(c: &CounterReport, config: &RunConfig) -> bool {
    let accounts = config.account_count() as u64;
    let connections = if matches!(config.scenario, ScenarioConfig::Churn { .. }) {
        accounts.min(config.measurement.connect_concurrency as u64)
    } else {
        accounts
    };
    c.peak_in_flight <= config.measurement.max_in_flight as u64
        && c.peak_in_flight <= c.dispatched
        && c.max_dispatch_batch_observed <= config.measurement.max_dispatch_batch
        && c.peak_connections <= connections
        && c.requested_connections <= accounts
        && c.established_connections <= accounts
        && c.connections_at_measurement_start <= accounts
        && c.connections_at_measurement_end <= accounts
}
fn inapplicable_counters_are_zero(c: &CounterReport, scenario: &ScenarioConfig) -> bool {
    match scenario {
        ScenarioConfig::Idle { .. } => true,
        ScenarioConfig::Messages { .. } => {
            sum(&[
                c.connection_attempts,
                c.login_succeeded,
                c.login_failed,
                c.closed_cleanly,
                c.close_failed,
                c.login_in_window,
                c.login_during_drain,
            ]) == Some(0)
        }
        ScenarioConfig::Churn { .. } => {
            sum(&[
                c.write_succeeded,
                c.message_body_bytes_write_succeeded,
                c.serialized_stanza_bytes_write_succeeded,
                c.write_failed,
                c.write_cancelled,
                c.received_on_time,
                c.received_in_window,
                c.received_during_drain,
                c.late_receipts,
                c.duplicates,
                c.unknown_ids,
                c.wrong_recipient,
                c.stale_phase_stanzas,
                c.unreceived_timeout,
                c.unreceived_connection_closed,
                c.unreceived_send_failed,
                c.unreceived_cancelled,
                c.write_succeeded_in_window,
                c.write_succeeded_during_drain,
            ]) == Some(0)
        }
    }
}
fn rates(c: &CounterReport, r: &RateReport, scenario: &ScenarioConfig, duration: u64) -> bool {
    if matches!(scenario, ScenarioConfig::Idle { .. }) {
        return *r == RateReport::default();
    }
    let (offered, topology) = match *scenario {
        ScenarioConfig::Messages {
            pairs,
            rate_per_second,
            ..
        } => (
            rate_per_second,
            NonZeroU32::new(pairs as u32).map(|pairs| LedgerTopology::Messages { pairs }),
        ),
        ScenarioConfig::Churn {
            accounts,
            rate_per_second,
        } => (
            rate_per_second,
            NonZeroU32::new(accounts as u32).map(|accounts| LedgerTopology::Churn { accounts }),
        ),
        _ => return false,
    };
    let Some(topology) = topology else {
        return false;
    };
    let expected = MeasurementResult {
        counters: c.clone(),
        latencies: BTreeMap::new(),
        reasons: Vec::new(),
    }
    .rates(Duration::from_millis(duration), offered, topology);
    let actual = json!(r);
    let expected = json!(expected);
    expected.as_object().is_some_and(|fields| {
        fields.iter().all(
            |(key, value)| match (value.as_f64(), actual[key].as_f64()) {
                (Some(a), Some(b)) => near(a, b),
                _ => *value == actual[key],
            },
        )
    })
}
fn histograms(run: &RunReport) -> bool {
    if matches!(run.config.scenario, ScenarioConfig::Idle { .. }) {
        return run.latencies.is_empty();
    }
    if run.latencies.len() != KINDS.len() {
        return false;
    }
    let Some(limit) = run
        .config
        .measurement
        .operation_timeout_ms
        .checked_add(run.config.measurement.shutdown_timeout_ms)
        .and_then(|v| v.checked_mul(1000))
        .filter(|v| *v > 0 && *v <= 1_200_000_000)
    else {
        return false;
    };
    let Ok(mut histogram) = hdrhistogram::Histogram::<u64>::new_with_bounds(1, limit.max(2), 3)
    else {
        return false;
    };
    histogram.auto(false);
    let c = &run.counters;
    let messages = matches!(run.config.scenario, ScenarioConfig::Messages { .. });
    for kind in KINDS {
        let Some(h) = run.latencies.get(&kind) else {
            return false;
        };
        let expected = match kind {
            LatencyKind::DispatchSchedulingLag | LatencyKind::SchedulingLag => c.dispatched,
            LatencyKind::MessageScheduleToReceive | LatencyKind::MessageWriteStartToReceive => {
                if messages {
                    c.received_on_time
                } else {
                    0
                }
            }
            LatencyKind::MessageWriteDuration => {
                if messages {
                    c.write_succeeded
                } else {
                    0
                }
            }
            LatencyKind::Close => {
                if messages {
                    0
                } else {
                    c.closed_cleanly
                }
            }
            _ => {
                if messages {
                    0
                } else {
                    c.login_succeeded
                }
            }
        };
        if h.unit != Microseconds::Microseconds
            || h.significant_figures != 3
            || h.count != expected
            || h.buckets
                .iter()
                .try_fold(0u64, |s, b| s.checked_add(b.count))
                != Some(h.count)
            || h.buckets.iter().any(|b| b.count == 0)
            || !h
                .buckets
                .windows(2)
                .all(|bs| bs[0].upper_bound_us < bs[1].upper_bound_us)
        {
            return false;
        }
        let quantiles = [h.min_us, h.p50_us, h.p95_us, h.p99_us, h.max_us];
        if h.count == 0 {
            if quantiles.iter().any(Option::is_some)
                || h.mean_us.is_some()
                || h.sum_us != 0
                || !h.buckets.is_empty()
            {
                return false;
            }
        } else {
            let (
                Some(min),
                Some(p50),
                Some(p95),
                Some(p99),
                Some(max),
                Some(mean),
                Some(first),
                Some(last),
            ) = (
                h.min_us,
                h.p50_us,
                h.p95_us,
                h.p99_us,
                h.max_us,
                h.mean_us,
                h.buckets.first(),
                h.buckets.last(),
            )
            else {
                return false;
            };
            if min > max
                || max > limit
                || !histogram.equivalent(min, first.upper_bound_us)
                || !histogram.equivalent(max, last.upper_bound_us)
            {
                return false;
            }
            histogram.reset();
            let mut lower = 0u128;
            let mut upper = 0u128;
            for (index, bucket) in h.buckets.iter().enumerate() {
                let bound = bucket.upper_bound_us;
                if bound > histogram.highest_equivalent(limit)
                    || histogram.highest_equivalent(bound) != bound
                    || histogram.record_n(bound, bucket.count).is_err()
                {
                    return false;
                }
                let reserves_min = index == 0;
                let reserves_max = index + 1 == h.buckets.len() && min != max;
                let reserved = u64::from(reserves_min) + u64::from(reserves_max);
                let Some(remaining) = bucket.count.checked_sub(reserved) else {
                    return false;
                };
                let fixed = if reserves_min { u128::from(min) } else { 0 }
                    + if reserves_max { u128::from(max) } else { 0 };
                lower += fixed
                    + u128::from(histogram.lowest_equivalent(bound).max(min))
                        * u128::from(remaining);
                upper += fixed + u128::from(bound.min(max)) * u128::from(remaining);
            }
            if p50 != histogram.value_at_quantile(0.5)
                || p95 != histogram.value_at_quantile(0.95)
                || p99 != histogram.value_at_quantile(0.99)
                || u128::from(h.sum_us) < lower
                || u128::from(h.sum_us) > upper
                || !near(mean, h.sum_us as f64 / h.count as f64)
            {
                return false;
            }
        }
    }
    true
}
