// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn server_metrics_encode_build_logging_and_process_metrics() -> Result<(), fmt::Error> {
    let (writer, _guard) = tracing_appender::non_blocking(std::io::sink());
    let metrics = ServerMetrics::new(
        &BuildInfo {
            version: "1.2.3",
            branch: "main",
            commit: "abc1234",
        },
        writer.error_counter(),
    );
    let mut body = String::new();
    prometheus_client::encoding::text::encode(&mut body, &metrics.into_registry())?;
    assert!(body.lines().any(|line| line
        == "lonewolf_build_info{version=\"1.2.3\",branch=\"main\",commit=\"abc1234\"} 1"));
    assert!(
        body.lines()
            .any(|line| line == "lonewolf_log_dropped_lines_total 0")
    );
    assert!(
        body.lines()
            .any(|line| line.starts_with("process_cpu_seconds_total "))
    );
    Ok(())
}

#[derive(Debug)]
struct AcmeSnapshot(Vec<(String, lonewolf_acme::HostStatus)>);

impl Collector for AcmeSnapshot {
    fn encode(&self, encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        super::acme::encode_hosts(&self.0, encoder)
    }
}

#[test]
fn acme_metrics_use_exact_names_fixed_outcomes_and_omit_unknown_dates() -> Result<(), fmt::Error> {
    use lonewolf_acme::{HostEvent, HostState, HostStatus};
    let mut ready = HostStatus {
        state: HostState::Ready,
        not_after_unix: Some(1_800_001_000),
        next_attempt_unix: Some(1_800_000_500),
        attempts: 46,
        successes: 1,
        failures: [2, 3, 4, 5, 6, 7, 8, 9, 10],
        generation: 2,
        last_event: HostEvent::Installed,
        events: [0; 5],
    };
    let mut registry = Registry::default();
    let pending = HostStatus {
        state: HostState::Pending,
        not_after_unix: None,
        next_attempt_unix: None,
        ..ready.clone()
    };
    ready.state = HostState::Expired;
    registry
        .sub_registry_with_prefix("lonewolf")
        .register_collector(Box::new(AcmeSnapshot(vec![
            (
                "configured.example".into(),
                HostStatus {
                    state: HostState::Ready,
                    ..ready.clone()
                },
            ),
            ("pending.example".into(), pending),
            ("expired.example".into(), ready),
        ])));
    let mut output = String::new();
    prometheus_client::encoding::text::encode(&mut output, &registry)?;
    for sample in [
        "lonewolf_acme_certificate_ready{host=\"configured.example\"} 1",
        "lonewolf_acme_certificate_ready{host=\"pending.example\"} 0",
        "lonewolf_acme_certificate_ready{host=\"expired.example\"} 0",
        "lonewolf_acme_certificate_not_after_seconds{host=\"configured.example\"} 1800001000.0",
        "lonewolf_acme_next_attempt_seconds{host=\"configured.example\"} 1800000500.0",
    ] {
        assert!(output.lines().any(|line| line == sample), "{output}");
    }
    assert!(
        !output.lines().any(|line| (line
            .starts_with("lonewolf_acme_certificate_not_after_seconds{")
            || line.starts_with("lonewolf_acme_next_attempt_seconds{"))
            && line.contains("pending.example")),
        "{output}"
    );
    for (index, outcome) in [
        "success",
        "network",
        "timeout",
        "rate_limited",
        "authorization",
        "protocol",
        "material",
        "account",
        "state",
        "deferred",
    ]
    .iter()
    .enumerate()
    {
        let expected = format!(
            "lonewolf_acme_attempts_total{{host=\"configured.example\",outcome=\"{outcome}\"}} {}",
            index + 1
        );
        assert!(output.lines().any(|line| line == expected), "{output}");
    }
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("lonewolf_acme_attempts_total{"))
            .count(),
        30
    );
    Ok(())
}

#[test]
fn acme_without_managed_hosts_emits_no_series_or_descriptors() -> Result<(), fmt::Error> {
    let mut registry = Registry::default();
    registry.register_collector(Box::new(AcmeSnapshot(Vec::new())));
    let mut output = String::new();
    prometheus_client::encoding::text::encode(&mut output, &registry)?;
    assert_eq!(output, "# EOF\n");
    Ok(())
}
