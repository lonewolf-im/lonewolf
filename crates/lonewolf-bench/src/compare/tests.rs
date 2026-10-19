// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    config::ScenarioConfig,
    measurement::{LatencyHistogram, LedgerTopology, MeasurementResult},
};
use std::{
    fs,
    num::NonZeroU32,
    os::unix::fs::{PermissionsExt, symlink},
    time::Duration,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> Result<RunReport, Box<dyn std::error::Error>> {
    let mut run: RunReport = serde_json::from_value(crate::report::tests::report_fixture()?)?;
    run.driver.executable_sha256 = Some("a".repeat(64));
    run.driver.revision = "driver-fixed".into();
    run.driver.build_target = "x86_64-unknown-linux-gnu".into();
    run.driver.rustc = "rustc fixed".into();
    run.target.declared_build = Some(ServerBuildDeclaration {
        revision: "server-A".into(),
        profile: "release".into(),
        toolchain: None,
        features: Some(Vec::new()),
    });
    run.target.local_binary_sha256 = Some("b".repeat(64));
    run.target.negotiated_tls = Some("TLSv1_3".into());
    run.target.cipher = Some("TLS13_AES_256_GCM_SHA384".into());
    run.target.cache_primed = true;
    run.target.observed_scram_iterations = Some(100000);
    if let Some(env) = &mut run.environment {
        env.server_build = run.target.declared_build.clone().ok_or("build")?;
    }
    run.dataset.account_jids_sha256 = Some("c".repeat(64));
    run.config.measurement.duration_ms = 1000;
    run.config.measurement.warmup_ms = 0;
    run.counters = CounterReport {
        requested_connections: 100,
        established_connections: 100,
        connections_at_measurement_start: 100,
        connections_at_measurement_end: 100,
        peak_connections: 100,
        ..CounterReport::default()
    };
    phases(&mut run);
    Ok(run)
}
fn phases(run: &mut RunReport) {
    run.phases = validation::PHASES
        .iter()
        .enumerate()
        .map(|(i, name)| PhaseReport {
            name: *name,
            start_offset_ns: i as u64 * 2_000_000_000,
            end_offset_ns: Some(i as u64 * 2_000_000_000 + 1_000_000_000),
            planned_end_offset_ns: if *name == PhaseName::Measurement {
                Some(i as u64 * 2_000_000_000 + run.config.measurement.duration_ms * 1_000_000)
            } else {
                None
            },
            status: PhaseStatus::Completed,
            counters: if *name == PhaseName::Measurement {
                run.counters.clone()
            } else {
                CounterReport::default()
            },
            rates: if *name == PhaseName::Measurement {
                run.rates.clone()
            } else if *name == PhaseName::Warmup {
                test_rates(
                    run,
                    CounterReport::default(),
                    run.config.measurement.warmup_ms,
                )
            } else {
                RateReport::default()
            },
        })
        .collect();
    if !matches!(run.config.scenario, ScenarioConfig::Idle { .. }) {
        for (timed, drain, duration) in [
            (3, 4, run.config.measurement.warmup_ms),
            (5, 6, run.config.measurement.duration_ms),
        ] {
            let nominal = run.phases[timed].start_offset_ns + duration * 1_000_000;
            run.phases[timed].planned_end_offset_ns = Some(nominal);
            run.phases[timed].end_offset_ns = Some(nominal + 1);
            run.phases[drain].start_offset_ns = nominal;
        }
    }
}
fn test_rates(run: &RunReport, counters: CounterReport, duration: u64) -> RateReport {
    let (rate, topology) = match run.config.scenario {
        ScenarioConfig::Idle { .. } => return RateReport::default(),
        ScenarioConfig::Messages {
            pairs,
            rate_per_second,
            ..
        } => (
            rate_per_second,
            LedgerTopology::Messages {
                pairs: NonZeroU32::new(pairs as u32).unwrap(),
            },
        ),
        ScenarioConfig::Churn {
            accounts,
            rate_per_second,
        } => (
            rate_per_second,
            LedgerTopology::Churn {
                accounts: NonZeroU32::new(accounts as u32).unwrap(),
            },
        ),
    };
    MeasurementResult {
        counters,
        latencies: BTreeMap::new(),
        reasons: Vec::new(),
    }
    .rates(Duration::from_millis(duration), rate, topology)
}
fn messages() -> Result<RunReport, Box<dyn std::error::Error>> {
    let mut run = fixture()?;
    run.config.scenario = ScenarioConfig::Messages {
        pairs: 1,
        rate_per_second: 1,
        body_bytes: 4,
    };
    run.dataset.account_count = 2;
    run.dataset.pair_count = Some(1);
    run.dataset.body_bytes = Some(4);
    run.counters = CounterReport {
        planned: 1,
        dispatched: 1,
        write_succeeded: 1,
        received_on_time: 1,
        received_in_window: 1,
        write_succeeded_in_window: 1,
        dispatched_in_window: 1,
        message_body_bytes_write_succeeded: 4,
        serialized_stanza_bytes_write_succeeded: 100,
        ..CounterReport::default()
    };
    for kind in validation::KINDS {
        let mut h = LatencyHistogram::new(Duration::from_secs(20))?;
        if matches!(
            kind,
            LatencyKind::DispatchSchedulingLag
                | LatencyKind::SchedulingLag
                | LatencyKind::MessageScheduleToReceive
                | LatencyKind::MessageWriteStartToReceive
                | LatencyKind::MessageWriteDuration
        ) {
            h.record(Duration::from_micros(100))?;
        }
        run.latencies.insert(kind, h.report());
    }
    run.rates = test_rates(&run, run.counters.clone(), 1000);
    phases(&mut run);
    Ok(run)
}
fn build(run: &mut RunReport, f: impl Fn(&mut ServerBuildDeclaration)) {
    if let Some(b) = &mut run.target.declared_build {
        f(b);
    }
    if let Some(e) = &mut run.environment {
        f(&mut e.server_build);
    }
}
fn mutate(
    run: &RunReport,
    path: &str,
    value: Value,
) -> Result<RunReport, Box<dyn std::error::Error>> {
    let mut json = serde_json::to_value(run)?;
    let parts: Vec<_> = path.split('.').collect();
    let mut slot = &mut json;
    for key in &parts[..parts.len() - 1] {
        slot = &mut slot[*key];
    }
    slot[parts[parts.len() - 1]] = value;
    Ok(serde_json::from_value(json)?)
}
#[test]
fn compare_self_and_aa_have_zero_deltas_without_statistical_verdict() -> TestResult {
    for run in [fixture()?, messages()?] {
        let report = compare_runs(&run, &run);
        assert!(report.eligible, "{:?}", report.refusals);
        assert!(report.compatible);
        assert!(report.mismatches.is_empty());
        assert!(
            report
                .metrics
                .iter()
                .filter_map(|m| m.absolute_delta)
                .all(|v| v == 0.0)
        );
        assert!(
            report
                .metrics
                .iter()
                .filter_map(|m| m.percent_delta)
                .all(|v| v == 0.0)
        );
        assert!(render(&report).contains("no confidence interval or statistical significance"));
    }
    Ok(())
}
#[test]
fn compare_every_setting_class_reports_deterministic_exact_field_paths() -> TestResult {
    let run = fixture()?;
    for (path, value) in [
        ("config.environment_id", json!("different")),
        ("config.scenario.connections", json!(50)),
        ("config.measurement.warmup_ms", json!(1)),
        ("config.measurement.operation_timeout_ms", json!(9999)),
        ("config.measurement.setup_timeout_ms", json!(800000)),
        ("config.measurement.shutdown_timeout_ms", json!(9000)),
        ("config.measurement.duration_ms", json!(999)),
        ("config.measurement.ramp_rate_per_second", json!(9)),
        ("config.measurement.connect_concurrency", json!(15)),
        ("config.measurement.max_in_flight", json!(2048)),
        ("config.measurement.dispatch_quantum_us", json!(2000)),
        ("config.measurement.max_dispatch_batch", json!(255)),
        ("config.measurement.max_schedule_lag_ms", json!(99)),
        ("config.measurement.driver_workers", json!(1)),
        ("driver.executable_sha256", json!("d".repeat(64))),
        ("driver.revision", json!("another-driver")),
        ("driver.package_version", json!("2.0")),
        ("driver.build_profile", json!("release")),
        ("driver.build_target", json!("aarch64-apple-darwin")),
        ("driver.rustc", json!("different rustc")),
        ("driver.worker_count", json!(1)),
        ("driver.scheduler_policy.dispatch_quantum_us", json!(2000)),
        ("driver.available_parallelism", json!(4)),
        ("driver.rlimit_nofile_soft", json!(10000)),
        ("driver.rlimit_nofile_hard", json!(20000)),
        ("driver.system.os_release", json!("different")),
        ("driver.system.arch", json!("aarch64")),
        ("target.mode", json!("remote")),
        ("target.xmpp_domain", json!("example.test")),
        ("target.negotiated_tls", json!("TLSv1_2")),
        ("target.cipher", json!("different")),
        ("target.auth_mechanism", json!("different")),
        ("target.observed_scram_iterations", json!(200000)),
        ("target.cache_primed", json!(false)),
        ("target.resumption", json!(true)),
        ("dataset.account_jids_sha256", json!("d".repeat(64))),
        ("dataset.resource_policy", json!("different")),
        ("dataset.availability_policy", json!("different")),
        ("environment.environment_id", json!("different")),
        ("environment.network_path", json!("internet")),
        ("environment.server.os_release", json!("different")),
        ("environment.server.arch", json!("different")),
        ("config.metrics.interval_ms", json!(2000)),
        ("config.metrics.timeout_ms", json!(1000)),
    ] {
        let candidate = mutate(&run, path, value)?;
        let report = compare_runs(&run, &candidate);
        assert!(!report.eligible, "{path}");
        assert!(
            report.mismatches.iter().any(|m| m.path == path),
            "{path}: {:?} {:?}",
            report.mismatches,
            report.refusals
        );
        assert!(report.metrics.is_empty());
        let paths: Vec<_> = report.mismatches.iter().map(|m| &m.path).collect();
        assert!(paths.windows(2).all(|ps| ps[0] < ps[1]));
    }
    Ok(())
}
#[test]
fn compare_all_resolved_limits_and_hardware_facts_are_checked() -> TestResult {
    let run = fixture()?;
    let settings = serde_json::to_value(
        &run.environment
            .as_ref()
            .ok_or("environment")?
            .server_settings,
    )?;
    let mut paths = BTreeMap::new();
    flatten("environment.server_settings", &settings, &mut paths);
    for (path, value) in paths {
        let next = match value {
            Value::Number(n) => json!(n.as_u64().ok_or("integer")? + 1),
            Value::String(_) => json!("different"),
            Value::Bool(v) => json!(!v),
            Value::Array(_) => json!(["different"]),
            _ => return Err("setting type".into()),
        };
        let report = compare_runs(&run, &mutate(&run, &path, next)?);
        assert!(!report.eligible, "{path}");
        assert!(report.mismatches.iter().any(|m| m.path == path), "{path}");
    }
    for prefix in ["driver.system", "environment.server"] {
        for (field, value) in [
            ("kernel", json!("known")),
            ("cpu_model", json!("known")),
            ("logical_cpus", json!(4)),
            ("memory_bytes", json!(8192)),
            ("virtualization", json!("known")),
            ("storage_description", json!("known")),
            ("cpu_affinity", json!([0, 1])),
            ("cpu_quota", json!(2.0)),
        ] {
            let path = format!("{prefix}.{field}");
            let candidate = mutate(&run, &path, value)?;
            assert!(
                compare_runs(&run, &candidate)
                    .mismatches
                    .iter()
                    .any(|m| m.path == path)
            );
            assert!(compare_runs(&candidate, &candidate).eligible);
        }
    }
    assert!(
        compare_runs(&run, &run)
            .caveats
            .iter()
            .any(|c| c.path == "driver.system.cpu_model")
    );
    Ok(())
}
#[test]
fn compare_profile_features_known_empty_and_canonical_named_sets() -> TestResult {
    let run = fixture()?;
    assert!(compare_runs(&run, &run).eligible);
    for (profile, features) in [
        ("unknown", None),
        ("release", None),
        ("unknown", Some(vec![])),
    ] {
        let mut other = run.clone();
        build(&mut other, |b| {
            b.profile = profile.into();
            b.features = features.clone();
        });
        assert!(!compare_runs(&other, &other).eligible);
        assert!(!compare_runs(&run, &other).eligible);
    }
    let mut other = run.clone();
    build(&mut other, |b| b.profile = "test".into());
    assert!(
        compare_runs(&run, &other)
            .mismatches
            .iter()
            .any(|m| m.path == "target.declared_build.profile")
    );
    build(&mut other, |b| {
        b.profile = "release".into();
        b.features = Some(vec!["b".into(), "a".into()]);
    });
    assert!(!compare_runs(&run, &other).eligible);
    let mut reordered = other.clone();
    build(&mut reordered, |b| {
        b.features = Some(vec!["a".into(), "b".into()])
    });
    assert!(compare_runs(&other, &reordered).eligible);
    Ok(())
}
#[test]
fn compare_missing_required_facts_are_independently_refused() -> TestResult {
    let run = fixture()?;
    for path in [
        "environment",
        "dataset.account_jids_sha256",
        "target.declared_build",
        "driver.executable_sha256",
        "driver.system.os_release",
        "driver.system.arch",
        "environment.server.os_release",
        "environment.server.arch",
        "target.negotiated_tls",
        "target.cipher",
        "target.observed_scram_iterations",
        "target.local_binary_sha256",
        "config.instrumentation",
    ] {
        let missing = mutate(&run, path, Value::Null)?;
        for pair in [(&missing, &missing), (&run, &missing)] {
            let report = compare_runs(pair.0, pair.1);
            assert!(!report.eligible, "{path}");
            assert!(
                report
                    .refusals
                    .iter()
                    .any(|r| r.context.as_ref().is_some_and(|s| s.contains(path))),
                "{path}"
            );
            assert!(report.metrics.is_empty());
        }
    }
    Ok(())
}
#[test]
fn compare_server_build_changes_prefix_checks_and_incidental_fields() -> TestResult {
    let run = fixture()?;
    let mut other = run.clone();
    build(&mut other, |b| {
        b.revision = "a".repeat(40);
        b.toolchain = Some("different toolchain".into());
    });
    other.target.local_binary_sha256 = Some("d".repeat(64));
    other.target.observed_build = Some(BTreeMap::from([
        ("commit".into(), "AAAAAAA".into()),
        ("version".into(), "2.0".into()),
    ]));
    other.target.observed_process_start_time_seconds = Some(123.0);
    other.target.configured_endpoint =
        Some("http://USER:PASSWORD@secret/endpoint?token=SECRET".into());
    other.run_id = Some("incidental".into());
    other.started_at_utc = Some("different".into());
    other
        .driver
        .sources
        .insert("secret/path".into(), "/credentials/private".into());
    let report = compare_runs(&run, &other);
    assert!(report.eligible, "{:?}", report.refusals);
    let output = serde_json::to_string(&report)? + &render(&report);
    assert!(!output.contains("PASSWORD"));
    assert!(!output.contains("/credentials/private"));
    assert!(output.contains("different toolchain"));
    other
        .target
        .observed_build
        .as_mut()
        .ok_or("observed")?
        .insert("commit".into(), "bbbbbbb".into());
    assert!(!compare_runs(&run, &other).eligible);
    build(&mut other, |b| b.revision = "arbitrary-label".into());
    assert!(compare_runs(&run, &other).eligible);
    Ok(())
}
#[test]
fn compare_failed_invalid_interrupted_or_forged_passed_inputs_have_no_percentages() -> TestResult {
    let run = messages()?;
    for status in [
        RunStatus::Failed,
        RunStatus::Invalid,
        RunStatus::Interrupted,
    ] {
        let mut bad = run.clone();
        bad.status = status;
        let report = compare_runs(&run, &bad);
        assert!(!report.eligible);
        assert!(report.metrics.is_empty());
        assert!(report.refusals.iter().any(|r| {
            r.context
                .as_ref()
                .is_some_and(|v| v.starts_with("candidate.status"))
        }));
    }
    for change in [0, 1, 2, 3, 4, 5, 6, 7, 8] {
        let mut bad = run.clone();
        match change {
            0 => bad.counters.dispatched = 2,
            1 => bad.counters.received_in_window = 0,
            2 => bad.rates.received_in_window_per_second = Some(99.0),
            3 => bad.phases[5].planned_end_offset_ns = Some(12_000_000_000),
            4 => bad.phases[5].status = PhaseStatus::Truncated,
            5 => {
                bad.latencies
                    .get_mut(&LatencyKind::MessageScheduleToReceive)
                    .ok_or("histogram")?
                    .buckets[0]
                    .count = 2
            }
            6 => {
                bad.latencies
                    .get_mut(&LatencyKind::MessageScheduleToReceive)
                    .ok_or("histogram")?
                    .sum_us = 0
            }
            7 => bad.reasons.push(RunReason {
                code: ReasonCode::EventOverflow,
                context: Some("SECRET-PAYLOAD".into()),
            }),
            _ => bad.telemetry.identity_changes = 1,
        }
        let report = compare_runs(&run, &bad);
        assert!(!report.eligible, "{change}");
        assert!(report.metrics.is_empty());
        assert!(!serde_json::to_string(&report)?.contains("SECRET-PAYLOAD"));
    }
    Ok(())
}
#[test]
fn compare_zero_missing_and_nonfinite_operands_never_produce_infinity() -> TestResult {
    let mut report = ComparisonReport::empty();
    for (a, b) in [
        (Some(0.0), Some(2.0)),
        (None, Some(1.0)),
        (Some(1.0), None),
        (Some(f64::NAN), Some(1.0)),
        (Some(1.0), Some(f64::INFINITY)),
        (Some(f64::MIN_POSITIVE), Some(f64::MAX)),
    ] {
        add_metric(
            &mut report,
            MetricKind::Coverage("test".into()),
            Unit::Ratio,
            a,
            b,
        );
        assert_eq!(report.metrics.last().ok_or("metric")?.percent_delta, None);
    }
    serde_json::to_vec(&report)?;
    let mut run = messages()?;
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        run.rates.planned_per_second = Some(value);
        assert!(!compare_runs(&run, &run).eligible);
    }
    Ok(())
}
#[test]
fn compare_telemetry_nullable_resources_preserve_client_eligibility() -> TestResult {
    let a = messages()?;
    let mut b = a.clone();
    b.telemetry_status = TelemetryStatus::Partial;
    b.telemetry.quality = TelemetryStatus::Partial;
    b.telemetry.server.cpu_average_cores = SampledValue {
        value: Some(2.0),
        sample_count: 2,
        start_offset_ns: Some(1),
        end_offset_ns: Some(2),
    };
    let report = compare_runs(&a, &b);
    assert!(report.eligible, "{:?}", report.refusals);
    let metric = report
        .metrics
        .iter()
        .find(|m| {
            m.name
                == MetricKind::Resource {
                    scope: "server".into(),
                    field: "cpu_average_cores".into(),
                }
        })
        .ok_or("resource")?;
    assert_eq!(metric.baseline, None);
    assert_eq!(metric.candidate, Some(2.0));
    assert_eq!(metric.percent_delta, None);
    Ok(())
}
#[test]
fn compare_remote_endpoint_exclusion_has_unconditional_caveat() -> TestResult {
    let mut a = fixture()?;
    a.target.mode = TargetMode::Remote;
    a.config.target_mode = TargetMode::Remote;
    a.target.local_binary_sha256 = None;
    a.target.configured_endpoint = Some("first.invalid:1".into());
    let mut b = a.clone();
    b.target.configured_endpoint = Some("USER:PASSWORD@second.invalid:2".into());
    for pair in [(&a, &a), (&a, &b)] {
        let report = compare_runs(pair.0, pair.1);
        assert!(report.eligible, "{:?}", report.refusals);
        assert!(
            report
                .caveats
                .iter()
                .any(|c| c.message.contains("Metrics URL identity is not retained."))
        );
        assert!(!serde_json::to_string(&report)?.contains("PASSWORD"));
    }
    b.config
        .instrumentation
        .as_mut()
        .ok_or("instrumentation")?
        .server_metrics_enabled = false;
    assert!(
        compare_runs(&a, &b)
            .mismatches
            .iter()
            .any(|m| m.path == "config.instrumentation.server_metrics_enabled")
    );
    assert!(compare_runs(&b, &b).eligible);
    Ok(())
}
#[test]
fn compare_instrumentation_policy_is_recognized_and_each_field_has_path() -> TestResult {
    let run = fixture()?;
    for (field, value) in [
        ("policy_version", json!(2)),
        ("server_metrics_enabled", json!(false)),
        ("generator_metrics_enabled", json!(false)),
        ("raw_capacity_bytes", json!(1)),
        ("control_capacity", json!(1)),
        ("response_body_limit_bytes", json!(1)),
        ("result_limit_bytes", json!(1)),
    ] {
        let path = format!("config.instrumentation.{field}");
        let changed = mutate(&run, &path, value)?;
        assert!(!compare_runs(&changed, &changed).eligible);
        assert!(
            compare_runs(&run, &changed)
                .mismatches
                .iter()
                .any(|m| m.path == path)
        );
    }
    Ok(())
}
#[test]
fn compare_directory_reader_is_bounded_strict_private_and_does_not_modify_inputs() -> TestResult {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("input");
    let mut run = fixture()?;
    let writer = artifacts::ArtifactWriter::create(&input)?;
    writer.prepare(&mut run, b"", None)?;
    writer.finish(&run)?;
    let bytes = fs::read(input.join("result.json"))?;
    let output = directory.path().join("output");
    let report = compare_directories(&input, &input, &output)?;
    assert!(report.eligible);
    assert!(!output.join(".incomplete").exists());
    assert_eq!(fs::read(input.join("result.json"))?, bytes);
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o700);
    for name in ["comparison.json", "comparison.md"] {
        assert_eq!(
            fs::metadata(output.join(name))?.permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(compare_directories(&input, &input, &output).is_err());
    symlink("absent", input.join(".incomplete"))?;
    assert!(RunReport::read(&input).is_err());
    fs::remove_file(input.join(".incomplete"))?;
    for bad in [
        b"{SECRET".to_vec(),
        b"{\"schema_version\":2}".to_vec(),
        b"{\"rates\":{\"planned_per_second\":1e999}}".to_vec(),
    ] {
        fs::write(input.join("result.json"), bad)?;
        assert!(RunReport::read(&input).is_err());
    }
    fs::File::create(input.join("result.json"))?.set_len(artifacts::RESULT_LIMIT as u64 + 1)?;
    assert!(RunReport::read(&input).is_err());
    let refused = directory.path().join("refused");
    let report = compare_directories(&input, &input, &refused)?;
    assert!(!report.eligible);
    assert!(report.metrics.is_empty());
    assert!(refused.join("comparison.json").is_file());
    assert!(!fs::read_to_string(refused.join("comparison.md"))?.contains("SECRET"));
    Ok(())
}

fn churn() -> Result<RunReport, Box<dyn std::error::Error>> {
    let mut run = fixture()?;
    run.config.scenario = ScenarioConfig::Churn {
        accounts: 1,
        rate_per_second: 1,
    };
    run.dataset.account_count = 1;
    run.dataset.pair_count = None;
    run.dataset.body_bytes = None;
    run.counters = CounterReport {
        planned: 1,
        dispatched: 1,
        dispatched_in_window: 1,
        connection_attempts: 1,
        login_succeeded: 1,
        login_in_window: 1,
        closed_cleanly: 1,
        ..CounterReport::default()
    };
    for kind in validation::KINDS {
        let mut h = LatencyHistogram::new(Duration::from_secs(20))?;
        if !matches!(
            kind,
            LatencyKind::MessageScheduleToReceive
                | LatencyKind::MessageWriteStartToReceive
                | LatencyKind::MessageWriteDuration
        ) {
            h.record(Duration::from_micros(100))?;
        }
        run.latencies.insert(kind, h.report());
    }
    run.rates = test_rates(&run, run.counters.clone(), 1000);
    phases(&mut run);
    Ok(run)
}
#[test]
fn compare_churn_preserves_login_close_and_latency_populations() -> TestResult {
    let run = churn()?;
    let report = compare_runs(&run, &run);
    assert!(report.eligible, "{:?}", report.refusals);
    let mut bad = run.clone();
    bad.counters.closed_cleanly = 0;
    assert!(!compare_runs(&run, &bad).eligible);
    let mut bad = run.clone();
    bad.phases[5].counters.login_in_window = 0;
    assert!(!compare_runs(&run, &bad).eligible);
    Ok(())
}
#[test]
fn compare_delta_uses_each_original_distribution_without_merging() -> TestResult {
    let a = messages()?;
    let mut b = a.clone();
    let mut h = LatencyHistogram::new(Duration::from_secs(20))?;
    h.record(Duration::from_micros(150))?;
    b.latencies
        .insert(LatencyKind::MessageScheduleToReceive, h.report());
    let report = compare_runs(&a, &b);
    assert!(report.eligible);
    let metric = report
        .metrics
        .iter()
        .find(|m| {
            m.name
                == MetricKind::Latency {
                    kind: LatencyKind::MessageScheduleToReceive,
                    quantile: "p95".into(),
                }
        })
        .ok_or("latency")?;
    assert_eq!(
        (
            metric.baseline,
            metric.candidate,
            metric.absolute_delta,
            metric.percent_delta
        ),
        (Some(100.0), Some(150.0), Some(50.0), Some(50.0))
    );
    let mut zero = ComparisonReport::empty();
    add_metric(
        &mut zero,
        MetricKind::Count("zero".into()),
        Unit::Operations,
        Some(0.0),
        Some(0.0),
    );
    assert_eq!(zero.metrics[0].absolute_delta, Some(0.0));
    assert_eq!(zero.metrics[0].percent_delta, None);
    Ok(())
}
#[test]
fn compare_forged_phase_totals_warmup_and_histogram_shape_are_refused() -> TestResult {
    let run = messages()?;
    for change in 0..8 {
        let mut bad = run.clone();
        match change {
            0 => {
                bad.phases[5].counters = CounterReport::default();
                bad.phases[5].rates = test_rates(&run, CounterReport::default(), 1000);
            }
            1 => {
                bad.phases[3].counters.write_failed = 1;
            }
            2 => {
                bad.counters.message_body_bytes_write_succeeded = 100;
            }
            3 => {
                bad.counters.max_dispatch_batch_observed = u64::MAX;
            }
            4 => {
                bad.latencies.remove(&LatencyKind::Close);
            }
            5 => {
                bad.latencies
                    .get_mut(&LatencyKind::MessageScheduleToReceive)
                    .ok_or("histogram")?
                    .mean_us = Some(999.0);
            }
            6 => {
                bad.latencies
                    .get_mut(&LatencyKind::MessageScheduleToReceive)
                    .ok_or("histogram")?
                    .p50_us = None;
            }
            _ => {
                bad.latencies
                    .get_mut(&LatencyKind::MessageScheduleToReceive)
                    .ok_or("histogram")?
                    .buckets
                    .push(HistogramBucket {
                        upper_bound_us: 1,
                        count: 1,
                    });
            }
        }
        assert!(!compare_runs(&run, &bad).eligible, "{change}");
    }
    Ok(())
}

#[test]
fn compare_reconstructs_hdr_bounds_ranks_and_raw_extrema() -> TestResult {
    let run = messages()?;
    for change in 0..4 {
        let mut bad = run.clone();
        let h = bad
            .latencies
            .get_mut(&LatencyKind::MessageScheduleToReceive)
            .ok_or("histogram")?;
        match change {
            0 => {
                h.buckets[0].upper_bound_us = 200;
                h.p50_us = Some(200);
                h.p95_us = Some(200);
                h.p99_us = Some(200);
            }
            1 => {
                h.buckets[0].upper_bound_us = u64::MAX;
                h.p50_us = Some(u64::MAX);
                h.p95_us = Some(u64::MAX);
                h.p99_us = Some(u64::MAX);
            }
            2 => {
                h.min_us = Some(99);
                h.sum_us = 99;
                h.mean_us = Some(99.0);
            }
            _ => {
                h.max_us = Some(101);
            }
        }
        let report = compare_runs(&run, &bad);
        assert!(!report.eligible, "{change}");
        assert!(report.metrics.is_empty());
        assert!(
            report
                .refusals
                .iter()
                .any(|r| r.code == ReasonCode::HistogramError)
        );
    }
    let mut three = run.clone();
    three.config.scenario = ScenarioConfig::Messages {
        pairs: 1,
        rate_per_second: 3,
        body_bytes: 4,
    };
    let mut counters = serde_json::to_value(&three.counters)?;
    for value in counters.as_object_mut().ok_or("counters")?.values_mut() {
        if let Some(n) = value.as_u64() {
            *value = json!(n * 3);
        }
    }
    three.counters = serde_json::from_value(counters)?;
    three.rates = test_rates(&three, three.counters.clone(), 1000);
    for (kind, h) in &mut three.latencies {
        if h.count > 0 {
            let mut histogram = LatencyHistogram::new(Duration::from_secs(20))?;
            for us in [10_001, 20_002, 30_003] {
                histogram.record(Duration::from_micros(us))?;
            }
            *h = histogram.report();
        }
        assert!(validation::KINDS.contains(kind));
    }
    phases(&mut three);
    assert!(compare_runs(&three, &three).eligible);
    let mut wrong = three.clone();
    let h = wrong
        .latencies
        .get_mut(&LatencyKind::MessageScheduleToReceive)
        .ok_or("histogram")?;
    h.p50_us = h.p95_us;
    assert!(!compare_runs(&three, &wrong).eligible);
    let mut noncanonical = three.clone();
    let h = noncanonical
        .latencies
        .get_mut(&LatencyKind::MessageScheduleToReceive)
        .ok_or("histogram")?;
    h.buckets[0].upper_bound_us -= 1;
    assert!(!compare_runs(&three, &noncanonical).eligible);
    Ok(())
}
#[test]
fn compare_refuses_every_inapplicable_counter_in_root_and_both_timed_phases() -> TestResult {
    for (run, fields) in [
        (
            messages()?,
            vec![
                "connection_attempts",
                "login_succeeded",
                "login_failed",
                "closed_cleanly",
                "close_failed",
                "login_in_window",
                "login_during_drain",
            ],
        ),
        (
            churn()?,
            vec![
                "write_succeeded",
                "message_body_bytes_write_succeeded",
                "serialized_stanza_bytes_write_succeeded",
                "write_failed",
                "write_cancelled",
                "received_on_time",
                "received_in_window",
                "received_during_drain",
                "late_receipts",
                "duplicates",
                "unknown_ids",
                "wrong_recipient",
                "stale_phase_stanzas",
                "unreceived_timeout",
                "unreceived_connection_closed",
                "unreceived_send_failed",
                "unreceived_cancelled",
                "write_succeeded_in_window",
                "write_succeeded_during_drain",
            ],
        ),
    ] {
        for field in fields {
            for warmup in [false, true] {
                let mut value = serde_json::to_value(&run)?;
                if warmup {
                    value["phases"][3]["counters"][field] = json!(1);
                } else {
                    value["counters"][field] = json!(1);
                    value["phases"][5]["counters"][field] = json!(1);
                }
                let bad = serde_json::from_value(value)?;
                let report = compare_runs(&run, &bad);
                assert!(!report.eligible, "{field}, warmup={warmup}");
                assert!(report.metrics.is_empty());
                assert!(
                    report.refusals.iter().any(|r| r
                        .context
                        .as_ref()
                        .is_some_and(|v| v.contains("invalid timed-phase accounting"))),
                    "{field}, warmup={warmup}"
                );
            }
        }
    }
    Ok(())
}
#[test]
fn compare_checks_generator_occupancy_in_root_and_warmup() -> TestResult {
    for run in [messages()?, churn()?] {
        for (field, value) in [
            (
                "max_dispatch_batch_observed",
                run.config.measurement.max_dispatch_batch + 1,
            ),
            (
                "peak_in_flight",
                run.config.measurement.max_in_flight as u64 + 1,
            ),
            ("peak_connections", run.dataset.account_count + 1),
        ] {
            for warmup in [false, true] {
                let mut json = serde_json::to_value(&run)?;
                if warmup {
                    json["phases"][3]["counters"][field] = json!(value);
                } else {
                    json["counters"][field] = json!(value);
                    json["phases"][5]["counters"][field] = json!(value);
                }
                let bad = serde_json::from_value(json)?;
                let report = compare_runs(&run, &bad);
                assert!(!report.eligible, "{field}, warmup={warmup}");
                assert!(report.metrics.is_empty());
                assert!(report.refusals.iter().any(|r| {
                    r.context
                        .as_ref()
                        .is_some_and(|v| v.contains("timed phase occupancy"))
                }));
            }
        }
    }
    Ok(())
}
#[test]
fn compare_verifies_each_nonempty_hex_abbreviation_against_declared_full_sha() -> TestResult {
    let mut run = fixture()?;
    build(&mut run, |b| b.revision = "a".repeat(40));
    for length in 1..=40 {
        let mut observed = run.clone();
        observed.target.observed_build =
            Some(BTreeMap::from([("commit".into(), "A".repeat(length))]));
        assert!(
            compare_runs(&run, &observed).eligible,
            "matching length{length}"
        );
        observed
            .target
            .observed_build
            .as_mut()
            .ok_or("build")?
            .insert("commit".into(), "b".repeat(length));
        let report = compare_runs(&run, &observed);
        assert!(!report.eligible, "conflicting length{length}");
        assert!(report.refusals.iter().any(|r| {
            r.context
                .as_ref()
                .is_some_and(|v| v.contains("target.observed_build.commit"))
        }));
        build(&mut observed, |b| {
            b.revision = "arbitrary-nonhex-label".into()
        });
        assert!(compare_runs(&run, &observed).eligible);
    }
    Ok(())
}

fn messages_with_samples(samples: &[u64]) -> Result<RunReport, Box<dyn std::error::Error>> {
    let mut run = messages()?;
    let count = u64::try_from(samples.len())?;
    run.config.scenario = ScenarioConfig::Messages {
        pairs: 1,
        rate_per_second: u32::try_from(count)?,
        body_bytes: 4,
    };
    let mut counters = serde_json::to_value(&run.counters)?;
    for value in counters.as_object_mut().ok_or("counters")?.values_mut() {
        if let Some(n) = value.as_u64() {
            *value = json!(n * count);
        }
    }
    run.counters = serde_json::from_value(counters)?;
    run.rates = test_rates(&run, run.counters.clone(), 1000);
    for h in run.latencies.values_mut().filter(|h| h.count > 0) {
        let mut histogram = LatencyHistogram::new(Duration::from_secs(20))?;
        for value in samples {
            histogram.record(Duration::from_micros(*value))?;
        }
        *h = histogram.report();
    }
    phases(&mut run);
    Ok(run)
}
#[test]
fn compare_histogram_sum_must_include_actual_declared_extrema() -> TestResult {
    for samples in [
        &[10_001][..],
        &[10_001, 10_002][..],
        &[10_001, 10_002, 10_003][..],
        &[10_001, 20_002][..],
        &[10_001, 10_001][..],
    ] {
        let run = messages_with_samples(samples)?;
        assert!(
            compare_runs(&run, &run).eligible,
            "valid samples {samples:?}"
        );
    }
    for (samples, max, sum) in [
        (&[10_001][..], 10_002, 10_001),
        (&[10_001, 10_002][..], 10_002, 20_002),
        (&[10_001, 10_002, 10_003][..], 10_003, 30_003),
        (&[10_001, 20_002][..], 20_002, 30_002),
    ] {
        let run = messages_with_samples(samples)?;
        let mut bad = run.clone();
        let h = bad
            .latencies
            .get_mut(&LatencyKind::MessageScheduleToReceive)
            .ok_or("histogram")?;
        h.max_us = Some(max);
        h.sum_us = sum;
        h.mean_us = Some(sum as f64 / h.count as f64);
        let report = compare_runs(&run, &bad);
        assert!(
            !report.eligible,
            "impossible samples {samples:?}, max{max}, sum{sum}"
        );
        assert!(report.metrics.is_empty());
        assert!(
            report
                .refusals
                .iter()
                .any(|r| r.code == ReasonCode::HistogramError)
        );
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseBoundary {
    name: PhaseName,
    start_offset_ns: u64,
    end_offset_ns: Option<u64>,
    planned_end_offset_ns: Option<u64>,
}
fn boundary_fixtures() -> Result<BTreeMap<String, Vec<PhaseBoundary>>, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(include_str!("phase_boundaries.json"))?)
}
fn with_actual_boundaries(
    mut run: RunReport,
    boundaries: &[PhaseBoundary],
) -> Result<RunReport, Box<dyn std::error::Error>> {
    let measurement = boundaries
        .iter()
        .find(|p| p.name == PhaseName::Measurement)
        .ok_or("measurement")?;
    let duration = measurement
        .planned_end_offset_ns
        .ok_or("nominal end")?
        .checked_sub(measurement.start_offset_ns)
        .ok_or("duration")?
        / 1_000_000;
    let count = duration.div_ceil(1000);
    match &mut run.config.scenario {
        ScenarioConfig::Messages {
            rate_per_second, ..
        }
        | ScenarioConfig::Churn {
            rate_per_second, ..
        } => *rate_per_second = 1,
        _ => return Err("traffic fixture".into()),
    }
    run.config.measurement.duration_ms = duration;
    let mut counters = serde_json::to_value(&run.counters)?;
    for value in counters.as_object_mut().ok_or("counters")?.values_mut() {
        if let Some(n) = value.as_u64() {
            *value = json!(n * count);
        }
    }
    run.counters = serde_json::from_value(counters)?;
    for h in run.latencies.values_mut() {
        h.count *= count;
        h.sum_us *= count;
        for bucket in &mut h.buckets {
            bucket.count *= count;
        }
    }
    run.rates = test_rates(&run, run.counters.clone(), duration);
    phases(&mut run);
    for (phase, boundary) in run.phases.iter_mut().zip(boundaries) {
        phase.name = boundary.name;
        phase.start_offset_ns = boundary.start_offset_ns;
        phase.end_offset_ns = boundary.end_offset_ns;
        phase.planned_end_offset_ns = boundary.planned_end_offset_ns;
    }
    Ok(run)
}
#[test]
fn compare_actual_phase_boundaries_accept_late_timed_finish_inside_nominal_drain() -> TestResult {
    let boundaries = boundary_fixtures()?;
    for run in [messages()?, churn()?] {
        let a = with_actual_boundaries(run.clone(), &boundaries["a"])?;
        let b = with_actual_boundaries(run, &boundaries["b"])?;
        for (timed, drain) in [(3, 4), (5, 6)] {
            assert_eq!(
                a.phases[timed].planned_end_offset_ns,
                Some(a.phases[drain].start_offset_ns)
            );
            assert!(a.phases[timed].end_offset_ns.ok_or("end")? > a.phases[drain].start_offset_ns);
            assert!(a.phases[timed].end_offset_ns <= a.phases[drain].end_offset_ns);
        }
        assert_eq!(
            a.phases[3].planned_end_offset_ns,
            Some(a.phases[3].start_offset_ns)
        );
        let report = compare_runs(&a, &b);
        assert!(report.eligible, "{:?}", report.refusals);
        let mut on_time = a.clone();
        for timed in [3, 5] {
            on_time.phases[timed].end_offset_ns = on_time.phases[timed].planned_end_offset_ns;
        }
        assert!(compare_runs(&on_time, &on_time).eligible);
    }
    Ok(())
}
#[test]
fn compare_nominal_drain_exception_rejects_wrong_boundaries_and_other_overlaps() -> TestResult {
    let boundaries = boundary_fixtures()?;
    for run in [messages()?, churn()?] {
        let run = with_actual_boundaries(run, &boundaries["a"])?;
        for (timed, drain) in [(3, 4), (5, 6)] {
            for change in 0..5 {
                let mut bad = run.clone();
                match change {
                    0 => bad.phases[drain].start_offset_ns += 1,
                    1 => {
                        bad.phases[drain].start_offset_ns =
                            bad.phases[timed].end_offset_ns.ok_or("end")? + 1
                    }
                    2 => {
                        bad.phases[timed].end_offset_ns =
                            Some(bad.phases[drain].end_offset_ns.ok_or("end")? + 1)
                    }
                    3 => bad.phases[timed].planned_end_offset_ns = None,
                    _ => bad.phases[drain].name = PhaseName::Drain,
                }
                let report = compare_runs(&run, &bad);
                assert!(!report.eligible, "timed{timed},change{change}");
                assert!(report.refusals.iter().any(|r| {
                    r.context
                        .as_ref()
                        .is_some_and(|v| v.contains("all ten lifecycle phases"))
                }));
            }
        }
        let mut bad = run.clone();
        bad.phases[1].end_offset_ns = Some(bad.phases[2].start_offset_ns + 1);
        assert!(!compare_runs(&run, &bad).eligible);
    }
    let idle = fixture()?;
    assert!(compare_runs(&idle, &idle).eligible);
    for (timed, drain) in [(3, 4), (5, 6)] {
        let mut bad = idle.clone();
        let nominal = bad.phases[timed]
            .planned_end_offset_ns
            .unwrap_or(bad.phases[drain].start_offset_ns);
        bad.phases[timed].planned_end_offset_ns = Some(nominal);
        bad.phases[timed].end_offset_ns = Some(nominal + 1);
        bad.phases[drain].start_offset_ns = nominal;
        assert!(!compare_runs(&idle, &bad).eligible);
    }
    Ok(())
}

#[test]
fn intact_directory_inputs_retain_status_and_unknown_instrumentation_refusals() -> TestResult {
    let directory = tempfile::tempdir()?;
    for (name, status, old) in [
        ("failed", RunStatus::Failed, false),
        ("invalid", RunStatus::Invalid, false),
        ("interrupted", RunStatus::Interrupted, false),
        ("old", RunStatus::Passed, true),
    ] {
        let root = directory.path().join(name);
        let mut run = fixture()?;
        run.status = status;
        if old {
            run.config.instrumentation = None;
        }
        let writer = artifacts::ArtifactWriter::create(&root)?;
        writer.prepare(&mut run, b"", None)?;
        writer.finish(&run)?;
        assert_eq!(RunReport::read(&root)?.status, status);
        let comparison = compare_directories(
            &root,
            &root,
            &directory.path().join(format!("compare-{name}")),
        )?;
        assert!(!comparison.eligible);
        assert!(comparison.metrics.is_empty());
        let required = if old {
            "config.instrumentation"
        } else {
            "status"
        };
        assert!(
            comparison
                .refusals
                .iter()
                .any(|r| r.context.as_deref().is_some_and(|s| s.contains(required)))
        );
    }
    Ok(())
}
