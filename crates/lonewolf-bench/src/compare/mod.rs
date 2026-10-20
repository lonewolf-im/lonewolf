// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests;

use crate::{
    config::ScenarioConfig,
    error::BenchResult,
    report::{
        LatencyKind, ResourceSummary, RunReport, RunStatus, TargetMode, TelemetryStatus,
        artifacts::ArtifactWriter,
        summary::{Unit, format_value},
    },
};
use serde::{Deserialize, Serialize};
use std::{fmt::Write, path::Path};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonReport {
    pub comparable: bool,
    pub refusals: Vec<String>,
    pub warnings: Vec<String>,
    pub baseline: RunIdentity,
    pub candidate: RunIdentity,
    pub metrics: Vec<MetricComparison>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunIdentity {
    pub status: Option<RunStatus>,
    pub scenario: Option<String>,
    pub server_binary_sha256: Option<String>,
    pub server_version: Option<String>,
    pub server_commit: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    Load,
    Outcome,
    Latency,
    Resources,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricComparison {
    pub section: Section,
    pub key: String,
    pub label: String,
    pub unit: Unit,
    pub baseline: Option<f64>,
    pub candidate: Option<f64>,
    pub delta: Option<f64>,
    pub percent: Option<f64>,
}

impl RunIdentity {
    fn of(run: &RunReport) -> Self {
        let build = run.target.server_build.as_ref();
        Self {
            status: Some(run.status),
            scenario: Some(run.config.scenario.kind().into()),
            server_binary_sha256: run.target.server_binary_sha256.clone(),
            server_version: build.and_then(|b| b.get("version")).cloned(),
            server_commit: build.and_then(|b| b.get("commit")).cloned(),
        }
    }
}

pub fn compare_directories(
    baseline: &Path,
    candidate: &Path,
    output: &Path,
) -> BenchResult<ComparisonReport> {
    let writer = ArtifactWriter::create(output)?;
    let report = match (RunReport::read(baseline), RunReport::read(candidate)) {
        (Ok(a), Ok(b)) => compare_runs(&a, &b),
        (a, b) => {
            let mut refusals = Vec::new();
            for (side, result) in [("baseline", &a), ("candidate", &b)] {
                if let Err(error) = result {
                    refusals.push(format!(
                        "Cannot read the {side} result: {}.",
                        error.context()
                    ));
                }
            }
            ComparisonReport {
                comparable: false,
                refusals,
                warnings: Vec::new(),
                baseline: a.as_ref().map(RunIdentity::of).unwrap_or_default(),
                candidate: b.as_ref().map(RunIdentity::of).unwrap_or_default(),
                metrics: Vec::new(),
            }
        }
    };
    writer.write_json("comparison.json", &report)?;
    writer.write("comparison.md", render(&report).as_bytes())?;
    Ok(report)
}

pub fn compare_runs(baseline: &RunReport, candidate: &RunReport) -> ComparisonReport {
    let mut refusals = Vec::new();
    let mut warnings = Vec::new();
    for (side, run) in [("baseline", baseline), ("candidate", candidate)] {
        if !run.status.measured() {
            refusals.push(format!(
                "The {side} run is {}, so it has no complete measurement.",
                run.status.as_str()
            ));
        } else if run.status == RunStatus::Degraded {
            warnings.push(format!("The {side} run is degraded: {}.", reason_list(run)));
        }
        if run.driver.build_profile != "release" {
            warnings.push(format!(
                "The {side} driver is a {} build, so its own overhead can distort the results.",
                run.driver.build_profile
            ));
        }
        if run.telemetry.quality != TelemetryStatus::Complete {
            warnings.push(format!(
                "The {side} run has incomplete resource samples; some resource values are missing."
            ));
        }
    }
    if baseline.config.scenario != candidate.config.scenario {
        refusals.push(format!(
            "The workloads differ: {} versus {}.",
            describe(&baseline.config.scenario),
            describe(&candidate.config.scenario)
        ));
    }
    if baseline.config.measurement != candidate.config.measurement {
        refusals.push("The measurement settings differ.".into());
    }
    if baseline.config.metrics != candidate.config.metrics {
        warnings.push("The metrics sampling settings differ.".into());
    }
    if baseline.target.mode != candidate.target.mode {
        warnings.push("One run used a local server and the other a remote server.".into());
    } else if baseline.target.mode == TargetMode::Remote {
        warnings.push(
            "Remote results include network variability and any other load on the server host."
                .into(),
        );
    }
    let (a, b) = (&baseline.driver, &candidate.driver);
    if (&a.version, &a.revision, &a.build_profile) != (&b.version, &b.revision, &b.build_profile)
        || a.executable_sha256 != b.executable_sha256
    {
        warnings.push("The runs used different lonewolf-bench builds.".into());
    }
    if a.system != b.system || a.worker_count != b.worker_count {
        warnings.push("The runs used different driver hosts or driver settings.".into());
    }
    if baseline.target.server_binary_sha256.is_some()
        && baseline.target.server_binary_sha256 == candidate.target.server_binary_sha256
    {
        warnings.push(
            "Both runs used the same server binary, so differences show run-to-run noise.".into(),
        );
    }
    let comparable = refusals.is_empty();
    let metrics = if comparable {
        let a = metrics(baseline);
        let b = metrics(candidate);
        a.into_iter()
            .zip(b)
            .map(|(a, b)| {
                let delta = a.value.zip(b.value).map(|(a, b)| b - a);
                MetricComparison {
                    section: a.section,
                    key: a.key,
                    label: a.label,
                    unit: a.unit,
                    baseline: a.value,
                    candidate: b.value,
                    delta,
                    percent: a
                        .value
                        .zip(delta)
                        .filter(|(base, _)| *base != 0.0)
                        .map(|(base, delta)| delta / base * 100.0),
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    ComparisonReport {
        comparable,
        refusals,
        warnings,
        baseline: RunIdentity::of(baseline),
        candidate: RunIdentity::of(candidate),
        metrics,
    }
}

fn reason_list(run: &RunReport) -> String {
    let names: std::collections::BTreeSet<_> = run
        .reasons
        .iter()
        .filter(|reason| reason.code.status() == RunStatus::Degraded)
        .map(|reason| reason.context.as_deref().unwrap_or("unspecified"))
        .collect();
    names.into_iter().collect::<Vec<_>>().join(", ")
}

fn describe(scenario: &ScenarioConfig) -> String {
    match scenario {
        ScenarioConfig::Idle { connections } => format!("idle with {connections} connections"),
        ScenarioConfig::Messages {
            pairs,
            rate_per_second,
            body_bytes,
        } => format!(
            "messages with {pairs} pairs at {rate_per_second}/s and {body_bytes}-byte bodies"
        ),
        ScenarioConfig::Churn {
            accounts,
            rate_per_second,
        } => format!("churn with {accounts} accounts at {rate_per_second}/s"),
    }
}

struct Metric {
    section: Section,
    key: String,
    label: String,
    unit: Unit,
    value: Option<f64>,
}

fn metrics(run: &RunReport) -> Vec<Metric> {
    let mut list = Vec::new();
    let mut add = |section, key: &str, label: &str, unit, value: Option<f64>| {
        list.push(Metric {
            section,
            key: key.into(),
            label: label.into(),
            unit,
            value: value.filter(|v| v.is_finite()),
        });
    };
    let c = &run.counters;
    let r = &run.rates;
    let count = |value: u64| Some(value as f64);
    let ratio = |part: u64, total: u64| (total > 0).then(|| part as f64 / total as f64);
    match run.config.scenario {
        ScenarioConfig::Idle { .. } => {
            add(
                Section::Load,
                "counters.requested_connections",
                "Requested connections",
                Unit::Count,
                count(c.requested_connections),
            );
            add(
                Section::Outcome,
                "counters.connections_at_measurement_end",
                "Connections open at the end",
                Unit::Count,
                count(c.connections_at_measurement_end),
            );
            add(
                Section::Outcome,
                "counters.unexpected_disconnects",
                "Unexpected disconnects",
                Unit::Count,
                count(c.unexpected_disconnects),
            );
        }
        ScenarioConfig::Messages { .. } => {
            add(
                Section::Load,
                "rates.offered_rate_per_second",
                "Offered rate",
                Unit::PerSecond,
                r.offered_rate_per_second.map(f64::from),
            );
            add(
                Section::Load,
                "rates.dispatched_in_window_per_second",
                "Sent",
                Unit::PerSecond,
                r.dispatched_in_window_per_second,
            );
            add(
                Section::Load,
                "counters.driver_skips",
                "Skipped by the driver",
                Unit::Count,
                count(c.driver_skips()),
            );
            add(
                Section::Outcome,
                "rates.cohort_receipts_per_second",
                "Delivered on time",
                Unit::PerSecond,
                r.cohort_receipts_per_second,
            );
            add(
                Section::Outcome,
                "ratios.on_time",
                "On time of sent",
                Unit::Ratio,
                ratio(c.received_on_time, c.dispatched),
            );
            add(
                Section::Outcome,
                "counters.unreceived_timeout",
                "Timed out",
                Unit::Count,
                count(c.unreceived_timeout),
            );
            add(
                Section::Outcome,
                "counters.failed",
                "Failed to send",
                Unit::Count,
                count(c.write_failed + c.unreceived_send_failed),
            );
            add(
                Section::Outcome,
                "counters.unexpected_disconnects",
                "Unexpected disconnects",
                Unit::Count,
                count(c.unexpected_disconnects),
            );
            for (kind, quantiles) in [
                (LatencyKind::MessageScheduleToReceive, ALL_QUANTILES),
                (LatencyKind::MessageWriteStartToReceive, SHORT_QUANTILES),
                (LatencyKind::DispatchSchedulingLag, TAIL_QUANTILES),
            ] {
                latency(&mut add, run, kind, quantiles);
            }
        }
        ScenarioConfig::Churn { .. } => {
            add(
                Section::Load,
                "rates.offered_rate_per_second",
                "Offered rate",
                Unit::PerSecond,
                r.offered_rate_per_second.map(f64::from),
            );
            add(
                Section::Load,
                "rates.dispatched_in_window_per_second",
                "Started",
                Unit::PerSecond,
                r.dispatched_in_window_per_second,
            );
            add(
                Section::Load,
                "counters.driver_skips",
                "Skipped by the driver",
                Unit::Count,
                count(c.driver_skips()),
            );
            add(
                Section::Outcome,
                "rates.closed_cycles_per_second",
                "Clean cycles",
                Unit::PerSecond,
                r.closed_cycles_per_second,
            );
            add(
                Section::Outcome,
                "ratios.clean",
                "Clean of started",
                Unit::Ratio,
                ratio(c.closed_cleanly, c.dispatched),
            );
            add(
                Section::Outcome,
                "counters.login_failed",
                "Login failures",
                Unit::Count,
                count(c.login_failed),
            );
            add(
                Section::Outcome,
                "counters.close_failed",
                "Close failures",
                Unit::Count,
                count(c.close_failed),
            );
            latency(
                &mut add,
                run,
                LatencyKind::LoginConnectToBound,
                ALL_QUANTILES,
            );
            for kind in [
                LatencyKind::TcpConnect,
                LatencyKind::Starttls,
                LatencyKind::Authenticate,
                LatencyKind::Bind,
                LatencyKind::Close,
            ] {
                latency(&mut add, run, kind, SHORT_QUANTILES);
            }
            latency(
                &mut add,
                run,
                LatencyKind::DispatchSchedulingLag,
                TAIL_QUANTILES,
            );
        }
    }
    resources(&mut add, "server", "Server", &run.telemetry.server, true);
    resources(
        &mut add,
        "generator",
        "Driver",
        &run.telemetry.generator,
        false,
    );
    list
}

const ALL_QUANTILES: &[&str] = &["p50", "p95", "p99", "max"];
const SHORT_QUANTILES: &[&str] = &["p50", "p99"];
const TAIL_QUANTILES: &[&str] = &["p99"];

fn latency(
    add: &mut impl FnMut(Section, &str, &str, Unit, Option<f64>),
    run: &RunReport,
    kind: LatencyKind,
    quantiles: &[&str],
) {
    let histogram = run.latencies.get(&kind);
    let name = serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    for quantile in quantiles {
        let value = histogram.and_then(|h| match *quantile {
            "p50" => h.p50_us,
            "p95" => h.p95_us,
            "p99" => h.p99_us,
            _ => h.max_us,
        });
        add(
            Section::Latency,
            &format!("latencies.{name}.{quantile}"),
            &format!("{} {quantile}", kind.label()),
            Unit::Microseconds,
            value.map(|v| v as f64),
        );
    }
}

fn resources(
    add: &mut impl FnMut(Section, &str, &str, Unit, Option<f64>),
    scope: &str,
    label: &str,
    summary: &ResourceSummary,
    server: bool,
) {
    add(
        Section::Resources,
        &format!("telemetry.{scope}.cpu_average_cores"),
        &format!("{label} CPU"),
        Unit::Cores,
        summary.cpu_average_cores.value,
    );
    add(
        Section::Resources,
        &format!("telemetry.{scope}.rss_peak_bytes"),
        &format!("{label} memory peak"),
        Unit::Bytes,
        summary.rss_peak_bytes.value.map(|v| v as f64),
    );
    if server {
        add(
            Section::Resources,
            &format!("telemetry.{scope}.rss_mean_bytes"),
            &format!("{label} memory mean"),
            Unit::Bytes,
            summary.rss_mean_bytes.value,
        );
        add(
            Section::Resources,
            &format!("telemetry.{scope}.incremental_rss_per_connection_bytes"),
            &format!("{label} memory per connection"),
            Unit::Bytes,
            summary.incremental_rss_per_connection_bytes.value,
        );
        add(
            Section::Resources,
            &format!("telemetry.{scope}.open_fds_peak"),
            &format!("{label} open files peak"),
            Unit::Count,
            summary.open_fds_peak.value.map(|v| v as f64),
        );
    }
}

fn render(report: &ComparisonReport) -> String {
    let mut text = String::from("# Comparison\n\n");
    let _ = writeln!(
        text,
        "{}\n",
        if report.comparable {
            "The runs are comparable. Change is candidate minus baseline."
        } else {
            "The runs are not comparable."
        }
    );
    text.push_str("| | Baseline | Candidate |\n| --- | --- | --- |\n");
    let identity = |f: fn(&RunIdentity) -> Option<String>| {
        [&report.baseline, &report.candidate].map(|run| f(run).unwrap_or_else(|| "-".into()))
    };
    for (label, values) in [
        ("Workload", identity(|r| r.scenario.clone())),
        ("Status", identity(|r| r.status.map(|s| s.as_str().into()))),
        (
            "Server binary",
            identity(|r| r.server_binary_sha256.as_ref().map(|v| short(v))),
        ),
        (
            "Server version",
            identity(|r| {
                r.server_version
                    .as_ref()
                    .map(|version| match &r.server_commit {
                        Some(commit) => format!("{version} ({commit})"),
                        None => version.clone(),
                    })
            }),
        ),
    ] {
        let _ = writeln!(text, "| {label} | {} | {} |", values[0], values[1]);
    }
    for (title, items) in [
        ("Refused", &report.refusals),
        ("Warnings", &report.warnings),
    ] {
        if !items.is_empty() {
            let _ = writeln!(text, "\n## {title}\n");
            for item in items {
                let _ = writeln!(text, "- {item}");
            }
        }
    }
    for (section, title) in [
        (Section::Load, "Load"),
        (Section::Outcome, "Outcome"),
        (Section::Latency, "Latency (successful operations only)"),
        (Section::Resources, "Resources (measurement window)"),
    ] {
        let rows: Vec<_> = report
            .metrics
            .iter()
            .filter(|m| m.section == section && shown(m))
            .collect();
        if rows.is_empty() {
            continue;
        }
        let _ = writeln!(
            text,
            "\n## {title}\n\n| Metric | Baseline | Candidate | Change |\n| --- | ---: | ---: | ---: |"
        );
        for m in rows {
            let _ = writeln!(
                text,
                "| {} | {} | {} | {} |",
                m.label,
                format_value(m.unit, m.baseline),
                format_value(m.unit, m.candidate),
                change(m)
            );
        }
    }
    if report.comparable {
        text.push_str("\nA single pair of runs has no statistical significance. Compare several A/A pairs first to see the normal spread.\n");
    }
    text
}

fn shown(metric: &MetricComparison) -> bool {
    match (metric.baseline, metric.candidate) {
        (None, None) => false,
        (Some(a), Some(b)) if metric.unit == Unit::Count && metric.section == Section::Outcome => {
            a != 0.0 || b != 0.0
        }
        _ => true,
    }
}

fn change(metric: &MetricComparison) -> String {
    let Some(delta) = metric.delta else {
        return "-".into();
    };
    let sign = if delta > 0.0 { "+" } else { "" };
    let delta_text = if metric.unit == Unit::Ratio {
        format!("{sign}{:.2} pp", delta * 100.0)
    } else {
        format!("{sign}{}", format_value(metric.unit, Some(delta)))
    };
    match metric.percent {
        Some(percent) if metric.unit != Unit::Ratio => {
            format!(
                "{delta_text} ({}{percent:.1}%)",
                if percent > 0.0 { "+" } else { "" }
            )
        }
        _ => delta_text,
    }
}

fn short(hash: &str) -> String {
    hash.chars().take(12).collect()
}
