// SPDX-License-Identifier: Apache-2.0

use crate::support::{C2sSuite, TestResult};

fn sample_value(body: &str, series: &str) -> Option<f64> {
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
}

#[test]
fn metrics_endpoint_reports_build_information() -> TestResult {
    let mut suite = C2sSuite::with_metrics()?;
    let body = suite.wait_for_metric("lonewolf_log_dropped_lines_total 0")?;
    assert_eq!(
        sample_value(
            &body,
            "lonewolf_build_info{version=\"integration-test\",branch=\"test\",commit=\"test\"}"
        ),
        Some(1.0),
        "{body}"
    );
    assert_eq!(
        sample_value(&body, "lonewolf_log_dropped_lines_total"),
        Some(0.0)
    );
    assert!(
        body.lines()
            .any(|line| line == "lonewolf_stanza_pool_chunks{chunk_bytes=\"524288\"} 2"),
        "{body}"
    );
    assert!(body.ends_with("# EOF\n"), "{body}");
    suite.stop()
}

#[test]
fn storage_commits_are_reported_per_store() -> TestResult {
    let mut suite = C2sSuite::with_metrics()?;
    let series = "lonewolf_storage_commit_duration_seconds_count{store=\"primary\"}";
    let before = suite.scrape_metrics()?;
    let before = sample_value(&before, series).ok_or("missing storage commit count")?;
    suite.create_account("alice", "pencil")?;
    let body = suite.scrape_metrics()?;
    let after = sample_value(&body, series).ok_or("missing storage commit count")?;
    assert!(after >= before + 1.0, "{body}");
    assert!(!body.contains("alice"), "{body}");
    suite.stop()
}
