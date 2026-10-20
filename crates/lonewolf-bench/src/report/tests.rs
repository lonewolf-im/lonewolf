// SPDX-License-Identifier: Apache-2.0

use super::{metadata::initial_report, *};
use crate::config::ScenarioConfig;
use serde_json::json;

pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) fn sample_report(scenario: &str) -> Result<RunReport, Box<dyn std::error::Error>> {
    let config: RunConfig = toml::from_str(&format!(
        "[target]\nmode='local'\nserver_binary='/bin/lonewolf'\n[scenario]\nkind='{scenario}'"
    ))?;
    let mut report = initial_report(&config, 4);
    report.run_id = Some("0".repeat(32));
    report.started_at_utc = Some("2026-10-20T00:00:00Z".into());
    report.reasons.clear();
    report.driver.build_profile = "release".into();
    report.driver.executable_sha256 = Some("a".repeat(64));
    report.target.server_binary_sha256 = Some("b".repeat(64));
    report.target.server_build = Some(
        [("version", "0.1.0"), ("commit", "abc1234")]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect(),
    );
    report.counters = CounterReport {
        planned: 1000,
        dispatched: 1000,
        dispatched_in_window: 1000,
        write_succeeded: 1000,
        received_on_time: 1000,
        received_in_window: 1000,
        closed_cleanly: 1000,
        login_succeeded: 1000,
        requested_connections: 100,
        connections_at_measurement_start: 100,
        connections_at_measurement_end: 100,
        ..CounterReport::default()
    };
    report.rates = RateReport {
        offered_rate_per_second: config.offered_rate(),
        planned_per_second: Some(1000.0),
        dispatched_in_window_per_second: Some(1000.0),
        cohort_receipts_per_second: Some(1000.0),
        closed_cycles_per_second: Some(1000.0),
        window_seconds: Some(1.0),
        ..RateReport::default()
    };
    for kind in [
        LatencyKind::MessageScheduleToReceive,
        LatencyKind::LoginConnectToBound,
    ] {
        report.latencies.insert(
            kind,
            HistogramReport {
                count: 1000,
                min_us: Some(100),
                mean_us: Some(500.0),
                p50_us: Some(400),
                p95_us: Some(900),
                p99_us: Some(1500),
                max_us: Some(3000),
                sum_us: 500_000,
                buckets: vec![HistogramBucket {
                    upper_bound_us: 3000,
                    count: 1000,
                }],
            },
        );
    }
    report.phases.push(PhaseReport {
        name: PhaseName::Measurement,
        start_offset_ns: 0,
        end_offset_ns: Some(1_000_000_000),
        planned_end_offset_ns: Some(1_000_000_000),
        status: PhaseStatus::Completed,
        counters: report.counters.clone(),
        rates: report.rates.clone(),
    });
    report.telemetry.quality = TelemetryStatus::Complete;
    report.telemetry.samples_ok = 10;
    report.telemetry.reasons.clear();
    report.telemetry.server.cpu_average_cores.value = Some(0.5);
    report.telemetry.server.rss_peak_bytes.value = Some(32 << 20);
    Ok(report)
}

#[test]
fn report_round_trips_and_rejects_unknown_fields() -> TestResult {
    let report = sample_report("messages")?;
    let value = serde_json::to_value(&report)?;
    assert_eq!(serde_json::from_value::<RunReport>(value.clone())?, report);
    let mut unknown = value;
    unknown["invented"] = json!(1);
    assert!(serde_json::from_value::<RunReport>(unknown).is_err());
    assert!(serde_json::from_value::<CounterReport>(json!({"invented":1})).is_err());
    assert!(serde_json::from_str::<LatencyKind>("\"per_account_123\"").is_err());
    Ok(())
}

#[test]
fn non_finite_values_serialize_as_null() -> TestResult {
    let rates = RateReport {
        planned_per_second: Some(f64::NAN),
        ..RateReport::default()
    };
    let value = serde_json::to_value(&rates)?;
    assert!(value["planned_per_second"].is_null());
    assert_eq!(
        serde_json::from_value::<RateReport>(value)?,
        RateReport::default()
    );
    Ok(())
}

#[test]
fn statuses_preserve_precedence_and_exit_codes() {
    for (status, code, measured) in [
        (RunStatus::Passed, 0, true),
        (RunStatus::Degraded, 3, true),
        (RunStatus::Failed, 1, false),
        (RunStatus::Invalid, 2, false),
        (RunStatus::Interrupted, 130, false),
    ] {
        assert_eq!(status.exit_code(), code);
        assert_eq!(status.measured(), measured);
    }
    let ordered = [
        RunStatus::Passed,
        RunStatus::Degraded,
        RunStatus::Failed,
        RunStatus::Interrupted,
        RunStatus::Invalid,
    ];
    for pair in ordered.windows(2) {
        assert_eq!(pair[0].combine(pair[1]), pair[1]);
        assert_eq!(pair[1].combine(pair[0]), pair[1]);
    }
    let reasons = |codes: &[ReasonCode]| -> Vec<RunReason> {
        codes
            .iter()
            .map(|&code| RunReason {
                code,
                context: None,
            })
            .collect()
    };
    assert_eq!(
        status_of(&reasons(&[ReasonCode::TelemetryPartial])),
        RunStatus::Passed
    );
    assert_eq!(
        status_of(&reasons(&[
            ReasonCode::TelemetryPartial,
            ReasonCode::DriverLimited
        ])),
        RunStatus::Degraded
    );
    assert_eq!(
        status_of(&reasons(&[
            ReasonCode::OperationsFailed,
            ReasonCode::SetupFailure
        ])),
        RunStatus::Failed
    );
    assert_eq!(
        status_of(&reasons(&[
            ReasonCode::Interrupted,
            ReasonCode::AccountingError
        ])),
        RunStatus::Invalid
    );
}

#[test]
fn reader_loads_written_results_and_rejects_missing_or_corrupt_files() -> TestResult {
    let directory = tempfile::tempdir()?;
    let report = sample_report("idle")?;
    let output = directory.path().join("run");
    artifacts::ArtifactWriter::create(&output)?.write_json(RESULT_FILE, &report)?;
    assert_eq!(RunReport::read(&output)?, report);
    assert!(RunReport::read(directory.path()).is_err());
    let corrupt = directory.path().join("corrupt");
    std::fs::create_dir(&corrupt)?;
    std::fs::write(corrupt.join(RESULT_FILE), b"{\"status\":")?;
    assert!(RunReport::read(&corrupt).is_err());
    Ok(())
}

#[test]
fn summary_explains_degradation_and_shows_readable_results() -> TestResult {
    let mut report = sample_report("messages")?;
    report.counters.skipped_writer_busy = 25;
    report.counters.unreceived_timeout = 3;
    for code in [ReasonCode::DriverLimited, ReasonCode::OperationsFailed] {
        report.reasons.push(RunReason {
            code,
            context: Some("message_operations_skipped".into()),
        });
    }
    report.status = status_of(&report.reasons);
    let text = summary::render(&report);
    assert!(text.starts_with("# messages workload: degraded"));
    assert!(text.contains("The driver skipped 25 of 1,000 scheduled operations (sender busy 25)"));
    assert!(text.contains("3 timed out"));
    assert!(text.contains("| Schedule to receive | 1,000 | 400 µs | 900 µs | 1.50 ms | 3.00 ms |"));
    assert!(text.contains("| CPU | 0.50 cores | - |"));
    assert!(!text.contains("Some("));
    assert!(text.find("## Why").ok_or("why")? < text.find("## Outcome").ok_or("outcome")?);
    Ok(())
}

#[test]
fn failed_summary_reports_reasons_without_results() -> TestResult {
    let mut report = sample_report("churn")?;
    report.phases.clear();
    report.reasons.push(RunReason {
        code: ReasonCode::SetupFailure,
        context: Some("setup_deadline".into()),
    });
    report.status = status_of(&report.reasons);
    let text = summary::render(&report);
    assert!(text.contains("`setup_failure`: setup_deadline"));
    assert!(text.contains("no complete measurement"));
    assert!(!text.contains("## Latency"));
    Ok(())
}

#[test]
fn interrupted_summary_keeps_partial_measurement_results() -> TestResult {
    let mut report = sample_report("messages")?;
    report.reasons.push(RunReason {
        code: ReasonCode::Interrupted,
        context: Some("signal_received".into()),
    });
    report.status = status_of(&report.reasons);
    let text = summary::render(&report);
    assert!(text.starts_with("# messages workload: interrupted"));
    assert!(text.contains("cover only the part that ran"));
    assert!(text.contains("## Outcome"));
    Ok(())
}

#[test]
fn all_rates_use_exact_nominal_window_and_distinct_populations() {
    use crate::measurement::{LedgerTopology, MeasurementResult};
    use std::{num::NonZeroU32, time::Duration};
    let counters = CounterReport {
        planned: 11,
        dispatched_in_window: 10,
        write_succeeded_in_window: 9,
        received_in_window: 8,
        received_on_time: 7,
        login_in_window: 6,
        login_succeeded: 5,
        closed_cleanly: 4,
        ..CounterReport::default()
    };
    let result = MeasurementResult {
        counters,
        latencies: Default::default(),
        reasons: vec![],
    };
    let messages = result.rates(
        Duration::from_millis(100),
        101,
        LedgerTopology::Messages {
            pairs: NonZeroU32::MIN,
        },
    );
    assert_eq!(messages.window_seconds, Some(0.1));
    assert_eq!(messages.offered_rate_per_second, Some(101));
    assert_eq!(messages.planned_per_second, Some(110.0));
    assert_eq!(messages.dispatched_in_window_per_second, Some(100.0));
    assert_eq!(messages.write_succeeded_in_window_per_second, Some(90.0));
    assert_eq!(messages.received_in_window_per_second, Some(80.0));
    assert_eq!(messages.cohort_receipts_per_second, Some(70.0));
    let churn = result.rates(
        Duration::from_millis(100),
        101,
        LedgerTopology::Churn {
            accounts: NonZeroU32::MIN,
        },
    );
    assert_eq!(churn.login_in_window_per_second, Some(60.0));
    assert_eq!(churn.cohort_logins_per_second, Some(50.0));
    assert_eq!(churn.closed_cycles_per_second, Some(40.0));
    assert_eq!(
        result
            .rates(
                Duration::ZERO,
                101,
                LedgerTopology::Churn {
                    accounts: NonZeroU32::MIN
                }
            )
            .window_seconds,
        None
    );
}

#[test]
fn initial_report_records_the_target_without_inventing_observations() -> TestResult {
    let report = sample_report("idle")?;
    assert_eq!(report.target.mode, TargetMode::Local);
    assert_eq!(report.target.xmpp_domain, "localhost");
    assert!(matches!(
        report.config.scenario,
        ScenarioConfig::Idle { connections: 100 }
    ));
    let fresh = initial_report(&report.config, 1);
    assert_eq!(fresh.status, RunStatus::Passed);
    assert_eq!(fresh.telemetry.quality, TelemetryStatus::Unavailable);
    assert!(fresh.target.server_build.is_none());
    assert!(fresh.target.negotiated_tls.is_none());
    Ok(())
}
