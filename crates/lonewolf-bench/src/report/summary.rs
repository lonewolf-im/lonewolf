// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::{ScenarioConfig, TargetConfig};
use std::fmt::Write;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    PerSecond,
    Count,
    Ratio,
    Microseconds,
    Cores,
    Bytes,
}

pub fn format_value(unit: Unit, value: Option<f64>) -> String {
    let Some(value) = value.filter(|v| v.is_finite()) else {
        return "-".into();
    };
    match unit {
        Unit::PerSecond => format!("{}/s", decimal(value, 1)),
        Unit::Count => decimal(value, 0),
        Unit::Ratio => format!("{:.2}%", value * 100.0),
        Unit::Microseconds => duration_us(value),
        Unit::Cores => format!("{value:.2} cores"),
        Unit::Bytes => bytes(value),
    }
}

fn decimal(value: f64, places: usize) -> String {
    let text = format!("{:.*}", places, value.abs());
    let (whole, fraction) = text.split_once('.').unwrap_or((&text, ""));
    let mut grouped = String::with_capacity(text.len() + whole.len() / 3 + 1);
    if value < 0.0 && text.bytes().any(|b| b.is_ascii_digit() && b != b'0') {
        grouped.push('-');
    }
    for (index, digit) in whole.chars().enumerate() {
        if index > 0 && (whole.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    if !fraction.is_empty() {
        grouped.push('.');
        grouped.push_str(fraction);
    }
    grouped
}

fn duration_us(value: f64) -> String {
    let magnitude = value.abs();
    if magnitude >= 1_000_000.0 {
        format!("{:.2} s", value / 1_000_000.0)
    } else if magnitude >= 1000.0 {
        format!("{:.2} ms", value / 1000.0)
    } else {
        format!("{value:.0} µs")
    }
}

fn bytes(value: f64) -> String {
    let magnitude = value.abs();
    for (size, suffix) in [(1u64 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")] {
        if magnitude >= size as f64 {
            return format!("{:.1} {suffix}", value / size as f64);
        }
    }
    format!("{value:.0} B")
}

fn count(value: u64) -> String {
    format_value(Unit::Count, Some(value as f64))
}

fn counted(value: usize, singular: &str, plural: &str) -> String {
    format!(
        "{} {}",
        count(value as u64),
        if value == 1 { singular } else { plural }
    )
}

fn per_second(value: Option<f64>) -> String {
    format_value(Unit::PerSecond, value)
}

fn seconds(ms: u64) -> String {
    if ms.is_multiple_of(1000) {
        format!("{} s", ms / 1000)
    } else {
        format!("{} ms", decimal(ms as f64, 0))
    }
}

pub fn render(report: &RunReport) -> String {
    let mut text = format!(
        "# {} workload: {}\n\n",
        report.config.scenario.kind(),
        report.status.as_str()
    );
    overview(&mut text, report);
    explain(&mut text, report);
    let measured = report
        .phases
        .iter()
        .any(|phase| phase.name == PhaseName::Measurement);
    if !report.status.measured() {
        text.push_str(if measured {
            "\nThe measurement did not complete. The results below cover only the part that ran.\n"
        } else {
            "\nThe run has no complete measurement, so it reports no results.\n"
        });
    }
    if measured {
        outcome(&mut text, report);
        latencies(&mut text, report);
        resources(&mut text, report);
    }
    phases(&mut text, report);
    environment(&mut text, report);
    text
}

fn overview(text: &mut String, report: &RunReport) {
    let target = match &report.config.target {
        TargetConfig::Local { server_workers, .. } => {
            format!("Local server with {server_workers} workers")
        }
        TargetConfig::Remote {
            connect_host,
            port,
            xmpp_domain,
            ..
        } => format!("Remote server {connect_host}:{port} for {xmpp_domain}"),
    };
    let workload = match report.config.scenario {
        ScenarioConfig::Idle { connections } => {
            counted(connections, "idle connection", "idle connections")
        }
        ScenarioConfig::Messages {
            pairs,
            rate_per_second,
            body_bytes,
        } => format!(
            "{}, {} messages/s in total, {body_bytes}-byte bodies",
            counted(pairs, "pair", "pairs"),
            count(rate_per_second.into())
        ),
        ScenarioConfig::Churn {
            accounts,
            rate_per_second,
        } => format!(
            "{}, {} login cycles/s in total",
            counted(accounts, "account", "accounts"),
            count(rate_per_second.into())
        ),
    };
    let m = &report.config.measurement;
    let _ = writeln!(
        text,
        "| | |\n| --- | --- |\n| Target | {target} |\n| Workload | {workload} |\n| Timing | {} warmup, {} measurement, {} operation timeout |\n| Started | {} |",
        seconds(m.warmup_ms),
        seconds(m.duration_ms),
        seconds(m.operation_timeout_ms),
        report.started_at_utc.as_deref().unwrap_or("-"),
    );
}

fn explain(text: &mut String, report: &RunReport) {
    let c = &report.counters;
    let has = |code| report.reasons.iter().any(|reason| reason.code == code);
    let mut lines = Vec::new();
    if has(ReasonCode::DriverLimited) {
        lines.push(format!(
            "The driver skipped {} of {} scheduled operations ({}). The offered load was not fully applied, so the driver may be the bottleneck. Spread the rate over more pairs or accounts, or raise `max_in_flight`.",
            count(c.driver_skips()),
            count(c.planned),
            skip_breakdown(c)
        ));
    }
    if has(ReasonCode::OperationsFailed) {
        lines.push(format!(
            "Some operations did not succeed on time: {}.",
            failure_breakdown(report)
        ));
    }
    for reason in &report.reasons {
        if reason.code.status().measured() {
            continue;
        }
        let line = format!(
            "`{}`: {}",
            serde_json::to_value(reason.code)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
            reason.context.as_deref().unwrap_or("no detail")
        );
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    if lines.is_empty() {
        return;
    }
    let _ = writeln!(text, "\n## Why the run is {}\n", report.status.as_str());
    for line in lines {
        let _ = writeln!(text, "- {line}");
    }
}

fn skip_breakdown(c: &CounterReport) -> String {
    let parts: Vec<_> = [
        ("scheduler lag", c.skipped_scheduler),
        ("in-flight limit", c.skipped_in_flight),
        ("sender busy", c.skipped_writer_busy),
        ("account busy", c.skipped_account_busy),
    ]
    .into_iter()
    .filter(|(_, value)| *value > 0)
    .map(|(name, value)| format!("{name} {}", count(value)))
    .collect();
    if parts.is_empty() {
        "some operations started too late".into()
    } else {
        parts.join(", ")
    }
}

fn failure_breakdown(report: &RunReport) -> String {
    let c = &report.counters;
    let parts: Vec<_> = [
        ("timed out", c.unreceived_timeout),
        ("lost with their connection", c.unreceived_connection_closed),
        ("failed to send", c.write_failed + c.unreceived_send_failed),
        ("received late", c.late_receipts),
        ("duplicated", c.duplicates),
        ("misrouted", c.wrong_recipient + c.unknown_ids),
        ("skipped on a closed connection", c.skipped_disconnected),
        ("unexpected disconnects", c.unexpected_disconnects),
        ("login failures", c.login_failed),
        ("close failures", c.close_failed),
    ]
    .into_iter()
    .filter(|(_, value)| *value > 0)
    .map(|(name, value)| format!("{} {name}", count(value)))
    .collect();
    if parts.is_empty() {
        "see the phase counters in result.json".into()
    } else {
        parts.join(", ")
    }
}

fn outcome(text: &mut String, report: &RunReport) {
    let c = &report.counters;
    let r = &report.rates;
    text.push_str("\n## Outcome\n\n");
    let mut line = |label: &str, value: String| {
        let _ = writeln!(text, "- {label}: {value}");
    };
    let percent = |part: u64, total: u64| {
        format_value(Unit::Ratio, (total > 0).then(|| part as f64 / total as f64))
    };
    match report.config.scenario {
        ScenarioConfig::Idle { .. } => {
            line("Requested connections", count(c.requested_connections));
            line(
                "Open at the start of the measurement",
                count(c.connections_at_measurement_start),
            );
            line(
                "Open at the end of the measurement",
                count(c.connections_at_measurement_end),
            );
        }
        ScenarioConfig::Messages { .. } => {
            line(
                "Scheduled",
                format!(
                    "{} ({})",
                    count(c.planned),
                    per_second(r.planned_per_second)
                ),
            );
            line(
                "Sent",
                format!(
                    "{} ({})",
                    count(c.dispatched),
                    per_second(r.dispatched_in_window_per_second)
                ),
            );
            line(
                "Delivered on time",
                format!(
                    "{}, {} of sent ({})",
                    count(c.received_on_time),
                    percent(c.received_on_time, c.dispatched),
                    per_second(r.cohort_receipts_per_second)
                ),
            );
            let bytes = c.serialized_stanza_bytes_write_succeeded;
            if bytes > 0 {
                line(
                    "Bytes written",
                    format_value(Unit::Bytes, Some(bytes as f64)),
                );
            }
        }
        ScenarioConfig::Churn { .. } => {
            line(
                "Scheduled cycles",
                format!(
                    "{} ({})",
                    count(c.planned),
                    per_second(r.planned_per_second)
                ),
            );
            line(
                "Started",
                format!(
                    "{} ({})",
                    count(c.dispatched),
                    per_second(r.dispatched_in_window_per_second)
                ),
            );
            line(
                "Clean cycles",
                format!(
                    "{}, {} of started ({})",
                    count(c.closed_cleanly),
                    percent(c.closed_cleanly, c.dispatched),
                    per_second(r.closed_cycles_per_second)
                ),
            );
            line("Peak concurrent sessions", count(c.peak_connections));
        }
    }
    if c.driver_skips() > 0 {
        line(
            "Skipped by the driver",
            format!("{} ({})", count(c.driver_skips()), skip_breakdown(c)),
        );
    }
    let failures = failure_breakdown(report);
    if !failures.starts_with("see ") {
        line("Problems", failures);
    }
    if !c.errors.is_empty() {
        let errors: Vec<_> = c
            .errors
            .iter()
            .map(|(category, value)| {
                format!(
                    "{} {}",
                    serde_json::to_value(category)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_default(),
                    count(*value)
                )
            })
            .collect();
        line("Errors by stage", errors.join(", "));
    }
}

fn latencies(text: &mut String, report: &RunReport) {
    let rows: Vec<_> = report
        .latencies
        .iter()
        .filter(|(_, histogram)| histogram.count > 0)
        .collect();
    if rows.is_empty() {
        return;
    }
    text.push_str("\n## Latency\n\nOnly successful operations have a latency. Read these numbers together with the outcome above.\n\n| Measure | Samples | p50 | p95 | p99 | Max |\n| --- | ---: | ---: | ---: | ---: | ---: |\n");
    for (kind, h) in rows {
        let us = |value: Option<u64>| format_value(Unit::Microseconds, value.map(|v| v as f64));
        let _ = writeln!(
            text,
            "| {} | {} | {} | {} | {} | {} |",
            kind.label(),
            count(h.count),
            us(h.p50_us),
            us(h.p95_us),
            us(h.p99_us),
            us(h.max_us)
        );
    }
}

fn resources(text: &mut String, report: &RunReport) {
    let t = &report.telemetry;
    let (server, driver) = (&t.server, &t.generator);
    text.push_str("\n## Resources\n\nSampled during the measurement window.\n\n| | Server | Driver |\n| --- | ---: | ---: |\n");
    let mut row = |label: &str, unit: Unit, a: Option<f64>, b: Option<f64>| {
        if a.is_some() || b.is_some() {
            let _ = writeln!(
                text,
                "| {label} | {} | {} |",
                format_value(unit, a),
                format_value(unit, b)
            );
        }
    };
    row(
        "CPU",
        Unit::Cores,
        server.cpu_average_cores.value,
        driver.cpu_average_cores.value,
    );
    row(
        "Memory mean",
        Unit::Bytes,
        server.rss_mean_bytes.value,
        driver.rss_mean_bytes.value,
    );
    row(
        "Memory peak",
        Unit::Bytes,
        server.rss_peak_bytes.value.map(|v| v as f64),
        driver.rss_peak_bytes.value.map(|v| v as f64),
    );
    row(
        "Open files peak",
        Unit::Count,
        server.open_fds_peak.value.map(|v| v as f64),
        driver.open_fds_peak.value.map(|v| v as f64),
    );
    row(
        "Memory per connection",
        Unit::Bytes,
        server.incremental_rss_per_connection_bytes.value,
        None,
    );
    row(
        "Host CPU steal",
        Unit::Microseconds,
        None,
        driver
            .generator_host_steal_seconds
            .value
            .map(|seconds| seconds * 1_000_000.0),
    );
    let quality = match t.quality {
        TelemetryStatus::Complete => "complete",
        TelemetryStatus::Partial => "partial",
        TelemetryStatus::Unavailable => "unavailable",
    };
    let _ = writeln!(
        text,
        "\nSamples: {quality}, {} succeeded and {} failed. Memory is resident set size, not allocator usage.",
        count(t.samples_ok),
        count(t.samples_failed)
    );
    if !t.policy_rejections.is_empty() {
        let rejections: Vec<_> = t
            .policy_rejections
            .iter()
            .map(|(policy, value)| format!("{policy} {}", count(*value)))
            .collect();
        let _ = writeln!(
            text,
            "\nThe server rejected connections by policy: {}.",
            rejections.join(", ")
        );
    }
}

fn phases(text: &mut String, report: &RunReport) {
    text.push_str("\n## Phases\n\n| Phase | Status | Duration |\n| --- | --- | ---: |\n");
    for phase in &report.phases {
        let name = serde_json::to_value(phase.name)
            .ok()
            .and_then(|v| v.as_str().map(|v| v.replace('_', " ")))
            .unwrap_or_default();
        let status = serde_json::to_value(phase.status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let duration = phase.end_offset_ns.and_then(|end| {
            end.checked_sub(phase.start_offset_ns)
                .map(|ns| ns as f64 / 1000.0)
        });
        let _ = writeln!(
            text,
            "| {name} | {status} | {} |",
            format_value(Unit::Microseconds, duration)
        );
    }
}

fn environment(text: &mut String, report: &RunReport) {
    let d = &report.driver;
    let s = &d.system;
    let t = &report.target;
    text.push_str("\n## Environment\n\n");
    let _ = writeln!(
        text,
        "- Driver: lonewolf-bench {} ({}, {} build), {} workers, {} CPU jobs at once.",
        d.version,
        short(&d.revision),
        d.build_profile,
        d.worker_count,
        d.cpu_pool_size
    );
    let host = [
        s.os.clone(),
        s.kernel.clone(),
        s.arch.clone(),
        s.cpu_model.clone(),
        s.logical_cpus.map(|n| format!("{n} logical CPUs")),
        s.memory_bytes
            .map(|n| format!("{} memory", format_value(Unit::Bytes, Some(n as f64)))),
        d.rlimit_nofile_soft.map(|n| format!("open file limit {n}")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(", ");
    let _ = writeln!(text, "- Driver host: {host}.");
    let build = t.server_build.as_ref();
    let _ = writeln!(
        text,
        "- Server: binary {}, version {}, commit {}.",
        t.server_binary_sha256.as_deref().map_or("-".into(), short),
        build
            .and_then(|b| b.get("version"))
            .map_or("-", String::as_str),
        build
            .and_then(|b| b.get("commit"))
            .map_or("-", String::as_str),
    );
    if let (Some(tls), Some(cipher)) = (&t.negotiated_tls, &t.cipher) {
        let _ = writeln!(
            text,
            "- Session: {tls} with {cipher}, SCRAM-SHA-256 with {} iterations, no TLS resumption.",
            t.scram_iterations.map_or("-".into(), |n| n.to_string())
        );
    }
    if d.build_profile != "release" {
        let _ = writeln!(
            text,
            "\nThe driver is a {} build. Its own overhead can distort the results, so use a release build.",
            d.build_profile
        );
    }
    match t.mode {
        TargetMode::Local => text.push_str(
            "\nThe driver and the server share this machine and compete for CPU and memory.\n",
        ),
        TargetMode::Remote => text.push_str(
            "\nRemote results include network latency and any other load on the server host.\n",
        ),
    }
}

fn short(value: &str) -> String {
    value.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_use_readable_units_and_separators() {
        assert_eq!(format_value(Unit::Count, Some(1_234_567.0)), "1,234,567");
        assert_eq!(format_value(Unit::Count, Some(-1234.0)), "-1,234");
        assert_eq!(format_value(Unit::PerSecond, Some(19_996.66)), "19,996.7/s");
        assert_eq!(format_value(Unit::Ratio, Some(0.9997)), "99.97%");
        assert_eq!(format_value(Unit::Microseconds, Some(950.0)), "950 µs");
        assert_eq!(format_value(Unit::Microseconds, Some(30_943.0)), "30.94 ms");
        assert_eq!(
            format_value(Unit::Microseconds, Some(2_500_000.0)),
            "2.50 s"
        );
        assert_eq!(format_value(Unit::Bytes, Some(107_151.36)), "104.6 KiB");
        assert_eq!(format_value(Unit::Bytes, Some(14_286_848.0)), "13.6 MiB");
        assert_eq!(format_value(Unit::Cores, Some(0.0009)), "0.00 cores");
        assert_eq!(format_value(Unit::Count, None), "-");
        assert_eq!(format_value(Unit::Count, Some(f64::NAN)), "-");
        assert_eq!(format_value(Unit::Count, Some(-0.2)), "0");
    }
}
