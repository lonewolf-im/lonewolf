// SPDX-License-Identifier: Apache-2.0

use super::*;
use serde_json::{Value, json};

fn report_fixture() -> Result<Value, Box<dyn std::error::Error>> {
    let config: RunConfig = toml::from_str(
        "schema_version=1\nenvironment_id='test'\n[target]\nmode='local'\nserver_binary='/secret/binary'\n[scenario]\nkind='idle'",
    )?;
    let system = json!({"os_release":"test", "kernel":null, "arch":"test", "cpu_model":null,
        "logical_cpus":null, "memory_bytes":null, "virtualization":null, "storage_description":null,
        "cpu_affinity":null, "cpu_quota":null});
    let build =
        json!({"revision":"unknown", "profile":"unknown", "toolchain":null, "features":null});
    let rate_limit = json!({"rate_per_second":1, "burst":1});
    let settings = json!({
                "workers":2, "stanza_pool_size_mib":256, "logging_level":"info", "host_extensions":[],
                "storage_backend":"redb", "max_unauthenticated_connections":1, "max_resources_per_account":1,
                "max_directed_presence_recipients_per_resource":1, "max_connections_per_ip":1,
                "max_stanza_bytes":1, "connection_establishment_timeout_secs":10, "authentication_timeout_secs":15,
                "resource_binding_timeout_secs":5, "authentication_retries":2, "resource_binding_retries":5,
                "connection_attempts_per_ip":rate_limit, "incoming_stanzas_per_connection":rate_limit,
                "new_recipients_per_connection":rate_limit, "incoming_xml_per_connection":{"bytes_per_second":1,"burst_bytes":1},
                "offered_auth_mechanisms":["SCRAM-SHA-256"], "tls_min":"1.2", "tls_max":"1.3",
                "empty_roster":true, "offline_storage":false});
    Ok(
        json!({"schema_version":1, "measurement_version":1, "run_id":"test", "status":"passed",
        "reasons":[], "telemetry_status":"unavailable", "started_at_utc":"2026-10-19T00:00:00Z",
        "phases":[], "config":SanitizedConfig::from(&config),
        "driver":{"executable_sha256":null, "package_version":"0.1.0", "revision":"unknown",
            "build_profile":"debug", "build_target":"unknown", "rustc":"unknown", "worker_count":2,
            "scheduler_policy":{"dispatch_quantum_us":1000, "max_dispatch_batch":256, "max_schedule_lag_ms":100},
            "available_parallelism":null, "rlimit_nofile_soft":null, "rlimit_nofile_hard":null,
            "system":system, "sources":{}},
        "target":{"mode":"local", "xmpp_domain":"localhost", "configured_endpoint":null,
            "negotiated_tls":null, "cipher":null, "auth_mechanism":"SCRAM-SHA-256", "resumption":false,
            "cache_primed":false, "observed_scram_iterations":null, "observed_build":null,
            "observed_process_start_time_seconds":null, "local_binary_sha256":null, "declared_build":build},
        "environment":{"schema_version":1, "environment_id":"test", "network_path":"loopback",
            "server":system, "server_build":build, "server_settings":settings},
        "dataset":{"account_jids_sha256":"test", "account_count":100, "pair_count":null,
            "resource_policy":"one", "availability_policy":"available", "body_bytes":null},
        "counters":CounterReport::default(), "rates":RateReport::default(), "latencies":{},
        "telemetry":{"quality":"unavailable", "samples_ok":0, "samples_failed":0, "missed_ticks":0,
            "queue_overflows":0, "bytes":0, "total_scrape_duration_ms":0, "server":ResourceSummary::default(),
            "generator":ResourceSummary::default(), "policy_rejections":{}, "identity_changes":0, "reasons":[]},
        "artifacts":{}}),
    )
}

#[test]
fn complete_report_schema_round_trip_and_nulls() -> Result<(), Box<dyn std::error::Error>> {
    let value = report_fixture()?;
    let mut unsupported = value.clone();
    unsupported["measurement_version"] = json!(2);
    assert!(serde_json::from_value::<RunReport>(unsupported).is_err());
    let report: RunReport = serde_json::from_value(value.clone())?;
    assert_eq!(serde_json::to_value(&report)?, value);
    assert!(value["rates"]["planned_per_second"].is_null());
    assert!(value["environment"]["server_build"]["features"].is_null());
    assert!(value["environment"]["server"]["memory_bytes"].is_null());
    assert!(!serde_json::to_string(&report)?.contains("/secret/binary"));
    let mut declared = value;
    for location in ["target", "environment"] {
        let key = if location == "target" {
            "declared_build"
        } else {
            "server_build"
        };
        declared[location][key]["profile"] = json!("release");
        declared[location][key]["features"] = json!([]);
    }
    let report: RunReport = serde_json::from_value(declared.clone())?;
    assert_eq!(serde_json::to_value(report)?, declared);
    Ok(())
}

#[test]
fn sparse_histogram_units_and_empty_quantiles() -> Result<(), Box<dyn std::error::Error>> {
    let mut histogram = HistogramReport {
        unit: Microseconds::Microseconds,
        significant_figures: 3,
        count: 0,
        min_us: None,
        mean_us: None,
        p50_us: None,
        p95_us: None,
        p99_us: None,
        max_us: None,
        sum_us: 0,
        buckets: Vec::new(),
    };
    let empty = serde_json::to_value(&histogram)?;
    for field in ["min_us", "mean_us", "p50_us", "p95_us", "p99_us", "max_us"] {
        assert!(empty[field].is_null());
    }
    assert_eq!(empty["unit"], "microseconds");
    let mut invalid = empty;
    invalid["significant_figures"] = json!(4);
    assert!(serde_json::from_value::<HistogramReport>(invalid).is_err());
    histogram.count = 2;
    histogram.sum_us = 7;
    histogram.buckets = vec![
        HistogramBucket {
            upper_bound_us: 3,
            count: 1,
        },
        HistogramBucket {
            upper_bound_us: 4,
            count: 1,
        },
    ];
    assert_eq!(
        histogram.buckets.iter().map(|b| b.count).sum::<u64>(),
        histogram.count
    );
    assert_eq!(
        serde_json::from_str::<HistogramReport>(&serde_json::to_string(&histogram)?)?,
        histogram
    );
    Ok(())
}

#[test]
fn statuses_preserve_precedence_and_exit_codes() {
    for (status, code) in [
        (RunStatus::Passed, 0),
        (RunStatus::Failed, 1),
        (RunStatus::Invalid, 2),
        (RunStatus::Interrupted, 130),
    ] {
        assert_eq!(status.exit_code(), code);
    }
    assert_eq!(
        RunStatus::Passed.combine(RunStatus::Failed),
        RunStatus::Failed
    );
    assert_eq!(
        RunStatus::Failed.combine(RunStatus::Interrupted),
        RunStatus::Interrupted
    );
    assert_eq!(
        RunStatus::Interrupted.combine(RunStatus::Invalid),
        RunStatus::Invalid
    );
    assert_eq!(crate::error::BenchError::staged().exit_code(), 2);
}

#[test]
fn fixed_names_unknown_fields_and_nonfinite_values() -> Result<(), Box<dyn std::error::Error>> {
    let mut rates = RateReport::default();
    assert!(serde_json::from_value::<CounterReport>(json!({"invented":1})).is_err());
    assert!(serde_json::from_str::<LatencyKind>("\"per_account_123\"").is_err());
    assert!(serde_json::from_str::<ErrorCategory>("\"arbitrary\"").is_err());
    for number in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        rates.planned_per_second = Some(number);
        assert!(serde_json::to_string(&rates).is_err());
    }
    rates.planned_per_second = Some(1.5);
    assert_eq!(
        serde_json::from_str::<RateReport>(&serde_json::to_string(&rates)?)?,
        rates
    );
    Ok(())
}

#[test]
fn resource_observations_keep_exact_peaks_and_fractional_derivations()
-> Result<(), Box<dyn std::error::Error>> {
    let mut summary = ResourceSummary::default();
    summary.rss_peak_bytes.value = Some(4096);
    summary.open_fds_peak.value = Some(8);
    summary.rss_mean_bytes.value = Some(4095.5);
    summary.open_fds_mean.value = Some(7.5);
    summary.incremental_rss_per_connection_bytes.value = Some(-0.5);
    let value = serde_json::to_value(&summary)?;
    assert_eq!(value["rss_peak_bytes"]["value"], json!(4096));
    assert_eq!(value["rss_mean_bytes"]["value"], json!(4095.5));
    assert_eq!(
        value["incremental_rss_per_connection_bytes"]["value"],
        json!(-0.5)
    );
    assert!(value["cpu_average_cores"]["value"].is_null());
    assert_eq!(
        serde_json::from_value::<ResourceSummary>(value.clone())?,
        summary
    );
    for field in ["rss_peak_bytes", "open_fds_peak"] {
        for number in [json!(1.5), json!(-1)] {
            let mut invalid = value.clone();
            invalid[field]["value"] = number;
            assert!(serde_json::from_value::<ResourceSummary>(invalid).is_err());
        }
    }
    summary.incremental_rss_per_connection_bytes.value = Some(f64::NAN);
    assert!(serde_json::to_value(summary).is_err());
    Ok(())
}
