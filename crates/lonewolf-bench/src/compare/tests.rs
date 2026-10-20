// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::report::{
    RESULT_FILE, ReasonCode, RunReason,
    tests::{TestResult, sample_report},
};
use std::os::unix::fs::PermissionsExt;

fn metric<'a>(report: &'a ComparisonReport, key: &str) -> Option<&'a MetricComparison> {
    report.metrics.iter().find(|metric| metric.key == key)
}

#[test]
fn identical_runs_are_comparable_with_zero_change_and_an_a_a_warning() -> TestResult {
    for scenario in ["idle", "messages", "churn"] {
        let run = sample_report(scenario)?;
        let report = compare_runs(&run, &run);
        assert!(report.comparable, "{scenario}");
        assert!(report.refusals.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("same server binary"))
        );
        assert!(!report.metrics.is_empty());
        assert!(
            report
                .metrics
                .iter()
                .all(|m| m.delta.is_none_or(|delta| delta == 0.0))
        );
    }
    Ok(())
}

#[test]
fn deltas_and_percentages_are_candidate_minus_baseline() -> TestResult {
    let baseline = sample_report("messages")?;
    let mut candidate = baseline.clone();
    candidate.target.server_binary_sha256 = Some("c".repeat(64));
    if let Some(histogram) = candidate
        .latencies
        .get_mut(&LatencyKind::MessageScheduleToReceive)
    {
        histogram.p99_us = Some(3000);
    }
    candidate.telemetry.server.cpu_average_cores.value = Some(0.25);
    let report = compare_runs(&baseline, &candidate);
    assert!(report.comparable);
    assert!(
        !report
            .warnings
            .iter()
            .any(|warning| warning.contains("same server binary"))
    );
    let p99 = metric(&report, "latencies.message_schedule_to_receive.p99").ok_or("p99")?;
    assert_eq!((p99.baseline, p99.candidate), (Some(1500.0), Some(3000.0)));
    assert_eq!((p99.delta, p99.percent), (Some(1500.0), Some(100.0)));
    let cpu = metric(&report, "telemetry.server.cpu_average_cores").ok_or("cpu")?;
    assert_eq!((cpu.delta, cpu.percent), (Some(-0.25), Some(-50.0)));
    let markdown = render(&report);
    assert!(
        markdown.contains("| Schedule to receive p99 | 1.50 ms | 3.00 ms | +1.50 ms (+100.0%) |")
    );
    assert!(markdown.contains("| Server CPU | 0.50 cores | 0.25 cores | -0.25 cores (-50.0%) |"));
    assert!(!markdown.contains("Timed out"));
    Ok(())
}

#[test]
fn degraded_runs_compare_with_a_warning() -> TestResult {
    let baseline = sample_report("messages")?;
    let mut candidate = baseline.clone();
    candidate.counters.skipped_writer_busy = 10;
    candidate.counters.unreceived_timeout = 4;
    candidate.reasons.push(RunReason {
        code: ReasonCode::DriverLimited,
        context: Some("message_operations_skipped".into()),
    });
    candidate.status = RunStatus::Degraded;
    let report = compare_runs(&baseline, &candidate);
    assert!(report.comparable);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.starts_with("The candidate run is degraded"))
    );
    let skips = metric(&report, "counters.driver_skips").ok_or("skips")?;
    assert_eq!(skips.candidate, Some(10.0));
    assert!(render(&report).contains("| Timed out | 0 | 4 | +4 |"));
    Ok(())
}

#[test]
fn runs_without_a_complete_measurement_or_with_different_workloads_are_refused() -> TestResult {
    let baseline = sample_report("messages")?;
    for status in [
        RunStatus::Failed,
        RunStatus::Interrupted,
        RunStatus::Invalid,
    ] {
        let mut candidate = baseline.clone();
        candidate.status = status;
        let report = compare_runs(&baseline, &candidate);
        assert!(!report.comparable);
        assert!(report.metrics.is_empty());
        assert!(report.refusals[0].contains(status.as_str()));
    }
    let mut candidate = baseline.clone();
    candidate.config.scenario = ScenarioConfig::Messages {
        pairs: 50,
        rate_per_second: 2000,
        body_bytes: 256,
    };
    assert!(!compare_runs(&baseline, &candidate).comparable);
    let mut candidate = baseline.clone();
    candidate.config.measurement.duration_ms += 1;
    assert!(!compare_runs(&baseline, &candidate).comparable);
    let report = compare_runs(&baseline, &sample_report("idle")?);
    assert!(!report.comparable);
    assert!(report.refusals[0].contains("workloads differ"));
    Ok(())
}

#[test]
fn environment_differences_only_warn() -> TestResult {
    let baseline = sample_report("churn")?;
    let mut candidate = baseline.clone();
    candidate.driver.executable_sha256 = Some("d".repeat(64));
    candidate.driver.system.logical_cpus = Some(99);
    candidate.driver.build_profile = "debug".into();
    candidate.config.metrics.interval_ms = 2000;
    let report = compare_runs(&baseline, &candidate);
    assert!(report.comparable);
    for expected in [
        "different lonewolf-bench builds",
        "different driver hosts",
        "debug build",
        "metrics sampling settings differ",
    ] {
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "{expected}"
        );
    }
    Ok(())
}

#[test]
fn directories_write_private_reports_and_refuse_unreadable_inputs() -> TestResult {
    let directory = tempfile::tempdir()?;
    let run = directory.path().join("run");
    ArtifactWriter::create(&run)?.write_json(RESULT_FILE, &sample_report("idle")?)?;
    let output = directory.path().join("comparison");
    let report = compare_directories(&run, &run, &output)?;
    assert!(report.comparable);
    assert_eq!(
        std::fs::metadata(&output)?.permissions().mode() & 0o777,
        0o700
    );
    let saved: ComparisonReport =
        serde_json::from_slice(&std::fs::read(output.join("comparison.json"))?)?;
    assert_eq!(saved, report);
    assert!(std::fs::read_to_string(output.join("comparison.md"))?.starts_with("# Comparison"));
    let missing = compare_directories(
        &directory.path().join("absent"),
        &run,
        &directory.path().join("refused"),
    )?;
    assert!(!missing.comparable);
    assert!(missing.refusals[0].contains("baseline"));
    assert!(compare_directories(&run, &run, &output).is_err());
    Ok(())
}
