// SPDX-License-Identifier: Apache-2.0

use super::*;
use openmetrics::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn body(cpu: &str, start: &str) -> String {
    format!(
        "process_start_time_seconds {start}\nprocess_cpu_seconds_total {cpu}\nprocess_resident_memory_bytes 1000\nprocess_open_fds 5\n# EOF\n"
    )
}
fn report() -> TelemetryReport {
    TelemetryReport {
        quality: TelemetryStatus::Complete,
        samples_ok: 0,
        samples_failed: 0,
        missed_ticks: 0,
        queue_overflows: 0,
        bytes: 0,
        total_scrape_duration_ms: 0,
        server: ResourceSummary::default(),
        generator: ResourceSummary::default(),
        policy_rejections: Default::default(),
        identity_changes: 0,
        reasons: vec![],
    }
}

#[test]
fn exact_families_escaped_labels_and_missing_values() -> TestResult {
    let snapshot = parse_snapshot(
        "process_cpu_seconds_total_extra 9\nprocess_cpu_seconds_total 2\nlonewolf_build_info{commit=\"abc\",branch=\"comma,quote\\\"slash\\\\\",version=\"1\"} 1\n# EOF\n",
    )?;
    assert_eq!(snapshot.cpu_seconds, Some(2.0));
    assert_eq!(snapshot.process_start, None);
    let build = snapshot.build.ok_or("build")?;
    assert_eq!(build["branch"], "comma,quote\"slash\\");
    for value in ["NaN", "+Inf", "-1", "garbage"] {
        assert_eq!(parse_snapshot(&body(value, "1"))?.cpu_seconds, None);
    }
    let duplicate =
        parse_snapshot("process_cpu_seconds_total 1\nprocess_cpu_seconds_total 2\n# EOF\n")?;
    assert!(duplicate.invalid_samples);
    assert_eq!(duplicate.cpu_seconds, None);
    assert!(parse_snapshot("process_cpu_seconds_total 1\n").is_err());
    assert!(parse_snapshot("lonewolf_build_info{commit=\"bad\\x\"} 1\n# EOF\n").is_err());
    Ok(())
}

#[test]
fn counter_decrease_restart_and_build_identity() -> TestResult {
    let first = parse_snapshot(&body("2", "1"))?;
    let second = parse_snapshot(&body("1", "1"))?;
    let derived = derive_interval(&first, &second);
    assert!(derived.counter_decreased);
    assert_eq!(derived.cpu_seconds, None);
    let restart = parse_snapshot(&body("3", "2"))?;
    assert!(derive_interval(&first, &restart).identity_changed);
    let mut first = first;
    first.build = Some(BTreeMap::from([("commit".into(), "a".into())]));
    let mut second = second;
    second.build = Some(BTreeMap::from([("commit".into(), "b".into())]));
    assert!(derive_interval(&first, &second).identity_changed);
    Ok(())
}
use std::collections::BTreeMap;

#[test]
fn bounded_required_samples_and_policy_reasons() -> TestResult {
    let snapshot = parse_snapshot(
        "lonewolf_c2s_connections_rejected_total{reason=\"max_connections_per_ip\",listener=\"0\"} 5\nlonewolf_c2s_connections_rejected_total{listener=\"1\",reason=\"max_connections_per_ip\"} 7\nlonewolf_c2s_connections_rejected_total{reason=\"secret\"} 42\n# EOF\n",
    )?;
    assert_eq!(snapshot.policy_rejections.len(), 1);
    assert_eq!(snapshot.policy_rejections["max_connections_per_ip"], 12);
    assert!(parse_snapshot(&format!("{}\n# EOF", "x".repeat(BODY_CAPACITY))).is_err());
    Ok(())
}

#[test]
fn full_intervals_cpu_elapsed_rss_populations_and_negative_idle_noise() -> TestResult {
    let mut resources = Resources::default();
    let mut report = report();
    resources.observe(
        parse_snapshot(&body("0", "1"))?,
        (0, 1),
        None,
        true,
        true,
        &mut report,
    );
    resources.observe(
        parse_snapshot(&body("1", "1"))?,
        (9, 11),
        Some((10, 100)),
        false,
        true,
        &mut report,
    );
    let mut sample = parse_snapshot(&body("2", "1"))?;
    sample.rss_bytes = Some(900);
    resources.observe(
        sample.clone(),
        (20, 30),
        Some((10, 100)),
        false,
        true,
        &mut report,
    );
    sample.cpu_seconds = Some(4.0);
    resources.observe(sample, (40, 50), Some((10, 100)), false, true, &mut report);
    let summary = resources.finish(10);
    assert_eq!(summary.rss_mean_bytes.value, Some(900.0));
    assert_eq!(summary.rss_mean_bytes.sample_count, 2);
    assert_eq!(summary.cpu_average_cores.value, Some(2.0 / (20.0 / 1e9)));
    assert_eq!(summary.cpu_average_cores.start_offset_ns, Some(30));
    assert_eq!(
        summary.incremental_rss_per_connection_bytes.value,
        Some(-10.0)
    );
    Ok(())
}

#[test]
fn identity_change_survives_missing_intervening_samples() -> TestResult {
    let mut resources = Resources::default();
    let mut report = report();
    resources.observe(
        parse_snapshot(&body("1", "1"))?,
        (0, 1),
        None,
        true,
        true,
        &mut report,
    );
    resources.observe(
        MetricSnapshot::default(),
        (2, 3),
        None,
        false,
        true,
        &mut report,
    );
    resources.observe(
        parse_snapshot(&body("2", "2"))?,
        (4, 5),
        None,
        false,
        true,
        &mut report,
    );
    assert_eq!(report.identity_changes, 1);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::ServerRestarted)
    );
    Ok(())
}

#[test]
fn output_cap_rolls_back_whole_record_without_growth() {
    let mut raw = Vec::with_capacity(1024);
    let capacity = raw.capacity();
    let sample = Sample {
        scope: "generator",
        scheduled_offset_ns: 0,
        start_offset_ns: 0,
        end_offset_ns: 1,
        phase: PhaseName::Measurement,
        status: "ok",
        error: None,
        bytes: 0,
        duration_ns: 1,
        openmetrics: Some("# EOF\n"),
    };
    assert!(append_raw(&mut raw, 1024, &sample));
    let first = raw.clone();
    assert!(!append_raw(&mut raw, first.len() + 1, &sample));
    assert_eq!(raw, first);
    assert_eq!(raw.capacity(), capacity);
    assert!(raw.ends_with(b"\n"));
}

#[tokio::test]
async fn nonblocking_control_overflow_and_server_failure_keep_generator_samples() -> TestResult {
    let mut sampler = TelemetrySampler::start(
        SamplerConfig {
            endpoint: None,
            timing: MetricsConfig::default(),
        },
        Instant::now(),
        allocate_buffer()?,
    )?;
    for _ in 0..CONTROL_CAPACITY {
        sampler
            .try_notify(PhaseSampleRequest {
                phase: PhaseName::Measurement,
                scheduled_at: Instant::now(),
                window: None,
                achieved_connections: 0,
            })
            .map_err(|_| "unexpected full")?;
    }
    assert!(
        sampler
            .try_notify(PhaseSampleRequest {
                phase: PhaseName::Measurement,
                scheduled_at: Instant::now(),
                window: None,
                achieved_connections: 0
            })
            .is_err()
    );
    sampler.ready().await;
    let (report, raw) = sampler
        .stop(Instant::now() + Duration::from_secs(1))
        .await?;
    assert_eq!(report.quality, TelemetryStatus::Partial);
    assert_eq!(report.queue_overflows, 1);
    assert!(report.samples_ok > 0 && report.samples_failed > 0);
    assert_eq!(raw.capacity(), RAW_CAPACITY);
    assert!(std::str::from_utf8(&raw)?.contains("process_cpu_seconds_total"));
    assert_eq!(
        crate::measurement::MeasurementResult {
            counters: CounterReport::default(),
            latencies: Default::default(),
            reasons: report.reasons
        }
        .status(),
        RunStatus::Passed
    );
    Ok(())
}

#[test]
fn slow_scrapes_skip_ticks_without_catchup_requests() {
    let start = Instant::now();
    let interval = Duration::from_secs(1);
    let mut next = start + interval;
    assert_eq!(
        skip_ticks(&mut next, start + Duration::from_millis(3500), interval),
        3
    );
    assert_eq!(next, start + Duration::from_secs(4));
    assert_eq!(
        skip_ticks(&mut next, start + Duration::from_millis(3500), interval),
        0
    );
}

#[test]
fn nonfinite_derived_cpu_is_unavailable_without_invalidating_workload() -> TestResult {
    let mut resources = Resources::default();
    let mut report = report();
    resources.observe(
        parse_snapshot(&body("0", "1"))?,
        (1, 2),
        Some((0, 10)),
        false,
        true,
        &mut report,
    );
    resources.observe(
        parse_snapshot(&body("1e308", "1"))?,
        (2, 3),
        Some((0, 10)),
        false,
        true,
        &mut report,
    );
    assert_eq!(resources.finish(0).cpu_average_cores.value, None);
    assert_eq!(report.quality, TelemetryStatus::Partial);
    assert!(parse_snapshot("not_an_eof# EOF").is_err());
    Ok(())
}

#[test]
fn body_bound_refuses_the_whole_oversized_append() {
    let mut body = vec![0; BODY_CAPACITY - 2];
    assert_eq!(append_body(&mut body, b"ab"), Ok(()));
    let capacity = body.capacity();
    assert_eq!(append_body(&mut body, b"c"), Err("body_limit"));
    assert_eq!(body.len(), BODY_CAPACITY);
    assert_eq!(body.capacity(), capacity);
}

#[tokio::test]
async fn driver_close_aborts_and_joins_before_returning() -> TestResult {
    use std::sync::atomic::AtomicBool;
    struct Probe(Arc<AtomicBool>);
    impl Drop for Probe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let probe = Probe(dropped.clone());
    let (admit, admitted) = tokio::sync::oneshot::channel();
    let mut driver = Driver(tokio::spawn(async move {
        let _probe = probe;
        let _ = admit.send(());
        std::future::pending::<Result<(), hyper::Error>>().await
    }));
    admitted.await?;
    driver.close().await;
    assert!(dropped.load(Ordering::Acquire));
    assert!(driver.0.is_finished());
    Ok(())
}

#[tokio::test]
async fn ready_boundary_freezes_baseline_before_later_cached_target_setup_scrapes() -> TestResult {
    for available in [true, false] {
        let (completion, completed) = oneshot::channel();
        let mut ready = ReadyBoundary {
            completion: Some(completion),
        };
        let mut server = Resources::default();
        let mut report = report();
        let initial = if available {
            parse_snapshot(&body("0", "1"))?
        } else {
            MetricSnapshot::default()
        };
        ready.observe_server(&mut server, initial, (0, 1), None, &mut report);
        ready.complete();
        completed.await?;
        let mut overlapping = parse_snapshot(&body("1", "1"))?;
        overlapping.rss_bytes = Some(9000);
        ready.observe_server(&mut server, overlapping, (5, 15), None, &mut report);
        let mut plateau = parse_snapshot(&body("2", "1"))?;
        plateau.rss_bytes = Some(2000);
        ready.observe_server(&mut server, plateau, (20, 30), Some((20, 40)), &mut report);
        assert_eq!(
            server.finish(2).incremental_rss_per_connection_bytes.value,
            if available { Some(500.0) } else { None }
        );
    }
    Ok(())
}

#[test]
fn connection_gauge_sums_distinct_listeners_and_rejects_whole_invalid_aggregates() -> TestResult {
    let distinct = parse_snapshot(
        "lonewolf_c2s_connections{listener=\"0\"} 2\nlonewolf_c2s_connections{listener=\"1\"} 3\n# EOF\n",
    )?;
    assert_eq!(distinct.connections, Some(5));
    assert!(!distinct.invalid_samples);
    let exact =
        parse_snapshot("lonewolf_c2s_connections{listener=\"0\"} 18446744073709551615\n# EOF\n")?;
    assert_eq!(exact.connections, Some(u64::MAX));
    for invalid in [
        "lonewolf_c2s_connections{listener=\"0\"} 2\nlonewolf_c2s_connections{listener=\"0\"} 3\n",
        "lonewolf_c2s_connections{listener=\"0\"} 2\nlonewolf_c2s_connections{listener=\"1\"} NaN\n",
        "lonewolf_c2s_connections{listener=\"0\"} 18446744073709551615\nlonewolf_c2s_connections{listener=\"1\"} 1\n",
        "lonewolf_c2s_connections{listener=\"0\"} 2\nlonewolf_c2s_connections{listener=\"1\"} 1.5\n",
        "lonewolf_c2s_connections{listener=\"0\"} 2\nlonewolf_c2s_connections 3\n",
        "lonewolf_c2s_connections{listener=\"0\",unknown=\"1\"} 2\n",
    ] {
        let snapshot = parse_snapshot(&format!("{invalid}# EOF\n"))?;
        assert_eq!(snapshot.connections, None);
        assert!(snapshot.invalid_samples);
    }
    Ok(())
}

#[test]
fn compare_instrumentation_policy_v1_matches_all_collector_limits() {
    for enabled in [false, true] {
        let metadata = instrumentation_metadata(enabled);
        assert_eq!(
            metadata,
            InstrumentationMetadata {
                policy_version: 1,
                server_metrics_enabled: enabled,
                generator_metrics_enabled: true,
                raw_capacity_bytes: 67_108_864,
                control_capacity: 8,
                response_body_limit_bytes: 1_048_576,
                result_limit_bytes: 33_554_432
            }
        );
        assert_eq!(metadata.raw_capacity_bytes, RAW_CAPACITY as u64);
        assert_eq!(metadata.control_capacity, CONTROL_CAPACITY as u64);
        assert_eq!(metadata.response_body_limit_bytes, BODY_CAPACITY as u64);
        assert_eq!(
            metadata.result_limit_bytes,
            crate::report::artifacts::RESULT_LIMIT as u64
        );
    }
}

#[test]
fn compare_instrumentation_body_limit_matches_parser_boundary() -> TestResult {
    let limit = instrumentation_metadata(true).response_body_limit_bytes as usize;
    let mut body = format!("#{}\n# EOF\n", "x".repeat(limit - 8));
    assert_eq!(body.len(), limit);
    parse_snapshot(&body)?;
    body.push('\n');
    assert!(parse_snapshot(&body).is_err());
    Ok(())
}
