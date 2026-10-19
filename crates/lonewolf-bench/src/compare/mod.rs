// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests;
mod validation;

use crate::{config::ScenarioConfig, error::BenchResult, report::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fmt::Write, path::Path};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonReport {
    pub schema_version: u32,
    pub compatible: bool,
    pub eligible: bool,
    pub mismatches: Vec<FieldMismatch>,
    pub refusals: Vec<RunReason>,
    pub metrics: Vec<MetricComparison>,
    pub caveats: Vec<ComparisonCaveat>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldMismatch {
    pub path: String,
    pub baseline: Value,
    pub candidate: Value,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    Rate(String),
    Count(String),
    Coverage(String),
    Latency { kind: LatencyKind, quantile: String },
    Resource { scope: String, field: String },
    Duration(String),
}
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    OperationsPerSecond,
    Operations,
    Ratio,
    Microseconds,
    Seconds,
    Cores,
    Bytes,
    Descriptors,
    Connections,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricComparison {
    pub name: MetricKind,
    pub unit: Unit,
    pub baseline: Option<f64>,
    pub candidate: Option<f64>,
    pub absolute_delta: Option<f64>,
    pub percent_delta: Option<f64>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonCaveat {
    pub path: String,
    pub message: String,
}

impl ComparisonReport {
    fn empty() -> Self {
        Self {
            schema_version: 1,
            compatible: false,
            eligible: false,
            mismatches: Vec::new(),
            refusals: Vec::new(),
            metrics: Vec::new(),
            caveats: Vec::new(),
        }
    }
    fn caveat(&mut self, path: &str, message: impl Into<String>) {
        self.caveats.push(ComparisonCaveat {
            path: path.into(),
            message: message.into(),
        });
    }
    fn refuse(&mut self, side: &str, path: &str, reason: &str, code: ReasonCode) {
        self.refusals.push(RunReason {
            code,
            context: Some(format!("{side}.{path}: {reason}")),
        });
    }
}

pub fn compare_directories(
    baseline: &Path,
    candidate: &Path,
    output: &Path,
) -> BenchResult<ComparisonReport> {
    let writer = artifacts::ArtifactWriter::create(output)?;
    let a = RunReport::read(baseline);
    let b = RunReport::read(candidate);
    let report = match (&a, &b) {
        (Ok(a), Ok(b)) => compare_runs(a, b),
        _ => {
            let mut report = ComparisonReport::empty();
            for (side, result) in [("baseline", &a), ("candidate", &b)] {
                if let Err(error) = result {
                    report.refuse(side, "result", error.context(), ReasonCode::InvalidConfig);
                }
            }
            report
        }
    };
    writer.finish_comparison(&report, &render(&report))?;
    Ok(report)
}

pub fn compare_runs(baseline: &RunReport, candidate: &RunReport) -> ComparisonReport {
    let mut report = ComparisonReport::empty();
    if baseline.target.mode == TargetMode::Remote || candidate.target.mode == TargetMode::Remote {
        report.caveat("target.configured_endpoint", "Remote XMPP and metrics endpoints are excluded from compatibility checks. Matching declared environment, topology and settings does not prove endpoint identity or physical-machine equivalence. Metrics URL identity is not retained.");
    }
    let a = validation::validate(baseline, "baseline", &mut report);
    let b = validation::validate(candidate, "candidate", &mut report);
    if !a || !b {
        return report;
    }
    let a = projection(baseline);
    let b = projection(candidate);
    for path in a
        .keys()
        .chain(b.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let baseline = a.get(path).unwrap_or(&Value::Null);
        let candidate = b.get(path).unwrap_or(&Value::Null);
        if baseline != candidate {
            report.mismatches.push(FieldMismatch {
                path: path.clone(),
                baseline: baseline.clone(),
                candidate: candidate.clone(),
            });
        } else if baseline.is_null() && optional_hardware(path) {
            report.caveat(
                path,
                "This optional hardware fact is unavailable in both runs.",
            );
        }
    }
    report.compatible = report.mismatches.is_empty() && report.refusals.is_empty();
    report.eligible = report.compatible && report.refusals.is_empty();
    report.caveat("latencies", "Latency quantiles contain successful operations only. Timeouts have no invented latency. Coverage and outcome counts describe the original admitted cohort; cohort rates include the bounded drain and use the nominal window denominator. Higher delivery/login rates and lower latency/resource values are directional labels, not a regression verdict.");
    report.caveat("pair", "A single pair provides no confidence interval or statistical significance. Repeat A/A and alternating A/B experiments; do not average percentiles or merge these histograms.");
    if let Some(environment) = &baseline.environment {
        report.caveat(
            "environment.network_path",
            format!("Declared network topology: {:?}.", environment.network_path),
        );
    }
    if baseline.target.mode == TargetMode::Local {
        report.caveat("environment.network_path", "The generator and server share local hardware and may contend for CPU, memory and file descriptors.");
    } else {
        report.caveat("environment.network_path", "Remote results include the declared network path, network variability and possible VPS contention.");
    }
    for (side, run) in [("baseline", baseline), ("candidate", candidate)] {
        report.caveat(&format!("{side}.target.build"), build_display(run));
        if run.telemetry_status != TelemetryStatus::Complete {
            report.caveat(&format!("{side}.telemetry"), "Telemetry is incomplete or unavailable. Missing resource observations remain null; client workload comparisons remain possible.");
        }
    }
    if baseline
        .target
        .declared_build
        .as_ref()
        .and_then(|v| v.toolchain.as_ref())
        != candidate
            .target
            .declared_build
            .as_ref()
            .and_then(|v| v.toolchain.as_ref())
        || baseline
            .target
            .declared_build
            .as_ref()
            .is_none_or(|v| v.toolchain.as_deref().is_none_or(|v| v == "unknown"))
    {
        report.caveat("target.declared_build.toolchain", "Server toolchains differ or are unknown; toolchain effects are part of the tested server build.");
    }
    if report.eligible {
        metrics(baseline, candidate, &mut report);
    }
    report
}

fn optional_hardware(path: &str) -> bool {
    matches!(
        path,
        "driver.available_parallelism" | "driver.rlimit_nofile_soft" | "driver.rlimit_nofile_hard"
    ) || ["driver.system.", "environment.server."]
        .iter()
        .any(|prefix| {
            path.strip_prefix(prefix)
                .is_some_and(|field| !matches!(field, "os_release" | "arch"))
        })
}

fn build_display(run: &RunReport) -> String {
    let declared = run.target.declared_build.as_ref();
    let observed = run.target.observed_build.as_ref();
    format!(
        "Declared revision: {:?}; server binary SHA-256: {:?}; declared toolchain: {:?}; observed version: {:?}; observed commit: {:?}. Arbitrary revision labels remain unverified declarations.",
        declared.map(|v| &v.revision),
        run.target.local_binary_sha256,
        declared.and_then(|v| v.toolchain.as_ref()),
        observed.and_then(|v| v.get("version")),
        observed.and_then(|v| v.get("commit"))
    )
}

fn flatten(path: &str, value: &Value, result: &mut BTreeMap<String, Value>) {
    if let Value::Object(fields) = value {
        for (key, value) in fields {
            flatten(&format!("{path}.{key}"), value, result);
        }
    } else {
        result.insert(path.into(), value.clone());
    }
}
fn projection(run: &RunReport) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    let value = json!({
        "schema_version": run.schema_version, "measurement_version": run.measurement_version,
        "config": run.config, "dataset": run.dataset,
        "driver": { "executable_sha256": run.driver.executable_sha256, "package_version": run.driver.package_version,
            "revision": run.driver.revision, "build_profile": run.driver.build_profile, "build_target": run.driver.build_target,
            "rustc": run.driver.rustc, "worker_count": run.driver.worker_count, "scheduler_policy": run.driver.scheduler_policy,
            "available_parallelism": run.driver.available_parallelism, "rlimit_nofile_soft": run.driver.rlimit_nofile_soft,
            "rlimit_nofile_hard": run.driver.rlimit_nofile_hard, "system": run.driver.system },
        "target": { "mode": run.target.mode, "xmpp_domain": run.target.xmpp_domain, "negotiated_tls": run.target.negotiated_tls,
            "cipher": run.target.cipher, "auth_mechanism": run.target.auth_mechanism, "resumption": run.target.resumption,
            "cache_primed": run.target.cache_primed, "observed_scram_iterations": run.target.observed_scram_iterations }
    });
    if let Value::Object(values) = value {
        for (key, value) in values {
            flatten(&key, &value, &mut fields);
        }
    }
    if let Some(environment) = &run.environment {
        let mut value = json!(environment);
        if let Some(value) = value.as_object_mut() {
            value.remove("server_build");
        }
        flatten("environment", &value, &mut fields);
    }
    if let Some(build) = &run.target.declared_build {
        let mut features = build.features.clone();
        if let Some(features) = &mut features {
            features.sort();
        }
        flatten(
            "target.declared_build",
            &json!({"profile":build.profile,"features":features}),
            &mut fields,
        );
    }
    for (kind, histogram) in &run.latencies {
        let name = serde_json::to_value(kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned));
        if let Some(name) = name {
            flatten(
                &format!("latencies.{name}"),
                &json!({"unit":histogram.unit,"significant_figures":histogram.significant_figures}),
                &mut fields,
            );
        }
    }
    fields
}

fn add_metric(
    report: &mut ComparisonReport,
    name: MetricKind,
    unit: Unit,
    a: Option<f64>,
    b: Option<f64>,
) {
    let a = a.filter(|v| v.is_finite());
    let b = b.filter(|v| v.is_finite());
    let delta = a.zip(b).map(|(a, b)| b - a).filter(|v| v.is_finite());
    let percent = a
        .zip(delta)
        .filter(|(a, _)| *a != 0.0)
        .map(|(a, d)| d / a * 100.0)
        .filter(|v| v.is_finite());
    report.metrics.push(MetricComparison {
        name,
        unit,
        baseline: a,
        candidate: b,
        absolute_delta: delta,
        percent_delta: percent,
    });
}
fn number(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64)
}
fn metrics(a: &RunReport, b: &RunReport, report: &mut ComparisonReport) {
    let ar = json!(a.rates);
    let br = json!(b.rates);
    for key in [
        "offered_rate_per_second",
        "planned_per_second",
        "dispatched_in_window_per_second",
        "write_succeeded_in_window_per_second",
        "received_in_window_per_second",
        "cohort_receipts_per_second",
        "login_in_window_per_second",
        "cohort_logins_per_second",
        "closed_cycles_per_second",
    ] {
        add_metric(
            report,
            MetricKind::Rate(key.into()),
            Unit::OperationsPerSecond,
            number(&ar, key),
            number(&br, key),
        );
    }
    let ac = json!(a.counters);
    let bc = json!(b.counters);
    if let Some(counters) = ac.as_object() {
        for (key, value) in counters {
            if key == "errors" {
                for category in [
                    "dns", "tcp", "tls", "auth", "bind", "protocol", "policy", "read", "write",
                    "deadline", "cleanup",
                ] {
                    add_metric(
                        report,
                        MetricKind::Count(format!("errors.{category}")),
                        Unit::Operations,
                        Some(number(value, category).unwrap_or(0.0)),
                        Some(number(&bc["errors"], category).unwrap_or(0.0)),
                    );
                }
            } else {
                let unit = if key.ends_with("bytes_write_succeeded") {
                    Unit::Bytes
                } else if key.contains("connections") {
                    Unit::Connections
                } else {
                    Unit::Operations
                };
                add_metric(
                    report,
                    MetricKind::Count(key.clone()),
                    unit,
                    value.as_f64(),
                    number(&bc, key),
                );
            }
        }
    }
    let coverage = |run: &RunReport| {
        let c = &run.counters;
        let success = match run.config.scenario {
            ScenarioConfig::Messages { .. } => c.received_on_time,
            ScenarioConfig::Churn { .. } => c.closed_cleanly,
            ScenarioConfig::Idle { .. } => c.connections_at_measurement_end,
        };
        let total = if matches!(run.config.scenario, ScenarioConfig::Idle { .. }) {
            c.requested_connections
        } else {
            c.dispatched
        };
        (total > 0).then(|| success as f64 / total as f64)
    };
    add_metric(
        report,
        MetricKind::Coverage(
            match a.config.scenario {
                ScenarioConfig::Idle { .. } => "connections_at_end_over_requested",
                ScenarioConfig::Messages { .. } => "on_time_receipts_over_admitted",
                ScenarioConfig::Churn { .. } => "clean_cycles_over_admitted",
            }
            .into(),
        ),
        Unit::Ratio,
        coverage(a),
        coverage(b),
    );
    for (kind, histogram) in &a.latencies {
        let other = b.latencies.get(kind);
        add_metric(
            report,
            MetricKind::Count(format!("latencies.{kind:?}.successful_samples")),
            Unit::Operations,
            Some(histogram.count as f64),
            other.map(|h| h.count as f64),
        );
        for (name, av, bv) in [
            ("p50", histogram.p50_us, other.and_then(|h| h.p50_us)),
            ("p95", histogram.p95_us, other.and_then(|h| h.p95_us)),
            ("p99", histogram.p99_us, other.and_then(|h| h.p99_us)),
            ("max", histogram.max_us, other.and_then(|h| h.max_us)),
        ] {
            add_metric(
                report,
                MetricKind::Latency {
                    kind: *kind,
                    quantile: name.into(),
                },
                Unit::Microseconds,
                av.map(|v| v as f64),
                bv.map(|v| v as f64),
            );
        }
    }
    for (scope, av, bv) in [
        ("server", &a.telemetry.server, &b.telemetry.server),
        ("generator", &a.telemetry.generator, &b.telemetry.generator),
    ] {
        let av = json!(av);
        let bv = json!(bv);
        for (field, unit) in [
            ("cpu_average_cores", Unit::Cores),
            ("rss_mean_bytes", Unit::Bytes),
            ("rss_peak_bytes", Unit::Bytes),
            ("open_fds_mean", Unit::Descriptors),
            ("open_fds_peak", Unit::Descriptors),
            ("incremental_rss_per_connection_bytes", Unit::Bytes),
            ("generator_host_steal_seconds", Unit::Seconds),
        ] {
            let x = sample(&av[field]);
            let y = sample(&bv[field]);
            if x.is_none() || y.is_none() {
                report.caveat(&format!("telemetry.{scope}.{field}"), "At least one sampled resource value is unavailable; its delta and percentage remain null.");
            }
            add_metric(
                report,
                MetricKind::Resource {
                    scope: scope.into(),
                    field: field.into(),
                },
                unit,
                x,
                y,
            );
        }
    }
    let drain = |run: &RunReport| {
        run.phases
            .iter()
            .find(|p| p.name == PhaseName::MeasurementDrain)
            .and_then(|p| p.end_offset_ns?.checked_sub(p.start_offset_ns))
            .map(|v| v as f64 / 1e9)
    };
    add_metric(
        report,
        MetricKind::Duration("measurement_drain".into()),
        Unit::Seconds,
        drain(a),
        drain(b),
    );
}

fn render(report: &ComparisonReport) -> String {
    let mut text = format!(
        "# XMPP workload comparison\n\nCompatible: {}. Eligible: {}.\n\n",
        report.compatible, report.eligible
    );
    for refusal in &report.refusals {
        let _ = writeln!(
            text,
            "- Refused: {}.",
            refusal.context.as_deref().unwrap_or("unavailable")
        );
    }
    for mismatch in &report.mismatches {
        let _ = writeln!(
            text,
            "- `{}`: baseline {}; candidate {}.",
            mismatch.path,
            markdown(&mismatch.baseline.to_string()),
            markdown(&mismatch.candidate.to_string())
        );
    }
    text.push_str("\n| Metric (population) | Unit | Baseline | Candidate | Absolute delta | Percent delta |\n| --- | --- | ---: | ---: | ---: | ---: |\n");
    for metric in &report.metrics {
        let _ = writeln!(
            text,
            "| {:?} | {:?} | {} | {} | {} | {} |",
            metric.name,
            metric.unit,
            display(metric.baseline),
            display(metric.candidate),
            display(metric.absolute_delta),
            display(metric.percent_delta)
        );
    }
    text.push('\n');
    for caveat in &report.caveats {
        let _ = writeln!(text, "- {}: {}", caveat.path, markdown(&caveat.message));
    }
    text
}
fn display(value: Option<f64>) -> String {
    value.map_or_else(|| "null".into(), |v| format!("{v:.6}"))
}
fn sample(value: &Value) -> Option<f64> {
    let count = value["sample_count"].as_u64()?;
    let start = value["start_offset_ns"].as_u64()?;
    let end = value["end_offset_ns"].as_u64()?;
    (count > 0 && end >= start)
        .then(|| number(value, "value"))
        .flatten()
}
fn markdown(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "&#124;")
        .replace('`', "&#96;")
}
