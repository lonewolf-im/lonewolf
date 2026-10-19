// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::fmt::Write;

pub fn render(report: &RunReport) -> String {
    let c = &report.counters;
    let mut text = format!(
        "# XMPP workload result\n\nOutcome: {:?}. Telemetry: {:?}.\n\n",
        report.status, report.telemetry_status
    );
    let _ = writeln!(
        text,
        "Offered operations: {}. Admitted: {}. On-time receipts: {}. Unreceived: {}. Late: {}. Duplicates: {}.\n",
        c.planned,
        c.dispatched,
        c.received_on_time,
        c.unreceived_timeout
            + c.unreceived_connection_closed
            + c.unreceived_send_failed
            + c.unreceived_cancelled,
        c.late_receipts,
        c.duplicates
    );
    let _ = writeln!(
        text,
        "Login successes/failures: {}/{}. Clean/failed closes: {}/{}. Active at window start/end: {}/{}. Peak active: {}.\n",
        c.login_succeeded,
        c.login_failed,
        c.closed_cleanly,
        c.close_failed,
        c.connections_at_measurement_start,
        c.connections_at_measurement_end,
        c.peak_connections
    );
    let coverage = (c.dispatched > 0).then(|| c.received_on_time as f64 / c.dispatched as f64);
    let _ = writeln!(
        text,
        "Receipt coverage (on-time/admitted): {coverage:?}. Error categories: {:?}.\n",
        c.errors
    );
    for reason in &report.reasons {
        let _ = writeln!(
            text,
            "- {:?}: {}",
            reason.code,
            reason.context.as_deref().unwrap_or("unavailable")
        );
    }
    text.push_str("\n## Phases and rates\n\nOffsets use monotonic nanoseconds. The nominal window excludes setup, dispatch tail, drain and shutdown.\n\n");
    for phase in &report.phases {
        let _ = writeln!(
            text,
            "- {:?}: {:?}; start {}; nominal end {:?}; observed end {:?}.",
            phase.name,
            phase.status,
            phase.start_offset_ns,
            phase.planned_end_offset_ns,
            phase.end_offset_ns
        );
    }
    let r = &report.rates;
    let _ = writeln!(
        text,
        "\nNominal seconds: {:?}; configured offered rate: {:?}/s.\n\nPlanned: {:?}/s; admitted in window: {:?}/s; flushed in window: {:?}/s; received in window: {:?}/s; on-time cohort receipts: {:?}/s; bound in window: {:?}/s; cohort logins: {:?}/s; clean cohort cycles: {:?}/s.\n",
        r.window_seconds,
        r.offered_rate_per_second,
        r.planned_per_second,
        r.dispatched_in_window_per_second,
        r.write_succeeded_in_window_per_second,
        r.received_in_window_per_second,
        r.cohort_receipts_per_second,
        r.login_in_window_per_second,
        r.cohort_logins_per_second,
        r.closed_cycles_per_second
    );
    let _ = writeln!(
        text,
        "Dispatch tail: original cohort only, bounded by max_schedule_lag_ms={}; skipped scheduler/in-flight/writer/account: {}/{}/{}/{}. Operation deadline: {} ms. Shutdown budget: {} ms.\n",
        report.config.measurement.max_schedule_lag_ms,
        c.skipped_scheduler,
        c.skipped_in_flight,
        c.skipped_writer_busy,
        c.skipped_account_busy,
        report.config.measurement.operation_timeout_ms,
        report.config.measurement.shutdown_timeout_ms
    );
    let drain_policy = match report.config.scenario {
        ScenarioConfig::Idle { .. } => {
            "Idle uses a reader barrier without an offered-operation cohort."
        }
        ScenarioConfig::Messages { .. } => {
            "Message drain ends at nominal end plus operation timeout."
        }
        ScenarioConfig::Churn { .. } => {
            "Churn drain ends at nominal end plus operation timeout plus shutdown timeout."
        }
    };
    let _ = writeln!(
        text,
        "{drain_policy} Admitted/flushed/bound after the window: {}/{}/{}. Receipts during drain: {}.\n",
        c.dispatched_during_drain,
        c.write_succeeded_during_drain,
        c.login_during_drain,
        c.received_during_drain
    );
    text.push_str("## Successful-only latency distributions\n\nTimeouts have no invented latency. Receipt quantiles exclude unreceived operations.\n\n");
    for (kind, h) in &report.latencies {
        let _ = writeln!(
            text,
            "- {kind:?}: count {}; p50/p95/p99/max us {:?}/{:?}/{:?}/{:?}.",
            h.count, h.p50_us, h.p95_us, h.p99_us, h.max_us
        );
    }
    text.push_str("\n## Sampled resources\n\n");
    let _ = writeln!(
        text,
        "Configured instrumentation: {:?}. Collection interval/timeout: {}/{} ms. These settings describe intent, not collection success.\n",
        report.config.instrumentation,
        report.config.metrics.interval_ms,
        report.config.metrics.timeout_ms
    );
    for (scope, r) in [
        ("server", &report.telemetry.server),
        ("generator", &report.telemetry.generator),
    ] {
        for (name, v) in [
            ("CPU average cores", &r.cpu_average_cores),
            ("RSS mean bytes", &r.rss_mean_bytes),
            ("open FDs mean", &r.open_fds_mean),
            (
                "sampled incremental RSS bytes per achieved connection",
                &r.incremental_rss_per_connection_bytes,
            ),
            (
                "generator host steal seconds",
                &r.generator_host_steal_seconds,
            ),
        ] {
            let _ = writeln!(
                text,
                "- {scope} {name}: {:?}; samples {}; offsets {:?}..{:?}.",
                v.value, v.sample_count, v.start_offset_ns, v.end_offset_ns
            );
        }
        let _ = writeln!(
            text,
            "- {scope} RSS peak bytes: {:?}; samples {}. Open FDs peak: {:?}; samples {}.",
            r.rss_peak_bytes.value,
            r.rss_peak_bytes.sample_count,
            r.open_fds_peak.value,
            r.open_fds_peak.sample_count
        );
    }
    let t = &report.telemetry;
    let _ = writeln!(
        text,
        "\nSamples ok/failed: {}/{}; missed ticks {}; queue overflows {}; encoded/received bytes {}; sampler scrape/encoding time {} ms. Fixed preallocated and touched telemetry buffer: 67108864 bytes. Policy rejections: {:?}.\n",
        t.samples_ok,
        t.samples_failed,
        t.missed_ticks,
        t.queue_overflows,
        t.bytes,
        t.total_scrape_duration_ms,
        t.policy_rejections
    );
    text.push_str("## Provenance and limitations\n\n");
    let _ = writeln!(
        text,
        "Driver executable SHA-256: {:?}; revision {}; profile {}; target {}; toolchain {}. Metadata sources: {:?}.\n",
        report.driver.executable_sha256,
        report.driver.revision,
        report.driver.build_profile,
        report.driver.build_target,
        report.driver.rustc,
        report.driver.sources
    );
    let _ = writeln!(
        text,
        "Target executable SHA-256: {:?}; explicitly declared build: {:?}. Unknown profile/features prevent comparison. Unavailable observations remain null.\n",
        report.target.local_binary_sha256, report.target.declared_build
    );
    let _ = writeln!(
        text,
        "Negotiated TLS/cipher: {:?}/{:?}. SCRAM-SHA-256 cache primed: {}; common observed iterations: {:?}; TLS resumption: false.\n",
        report.target.negotiated_tls,
        report.target.cipher,
        report.target.cache_primed,
        report.target.observed_scram_iterations
    );
    text.push_str("RSS is sampled process memory, not allocator bytes; negative incremental noise is preserved. CPU uses actual successful sample timestamps. RSS/FD samples require their full request interval inside the nominal window. Missing telemetry does not establish workload failure. Linux-only process values remain unavailable on macOS. Generator host steal does not describe a remote server.\n\n");
    match report.target.mode { TargetMode::Local => text.push_str("The generator and server share local hardware and may contend for CPU, memory and file descriptors.\n"), TargetMode::Remote => text.push_str("Remote results include the declared network path, network variability and possible VPS contention. Remote server steal requires operator observations.\n") }
    text.push_str("A single run does not establish server capacity or statistical significance.\n");
    text
}
