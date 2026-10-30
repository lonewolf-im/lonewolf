// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::task::{Context, Poll};

use super::*;

fn render(metrics: &Arc<S2sMetrics>) -> Result<String, fmt::Error> {
    let mut root = Registry::default();
    metrics.register(root.sub_registry_with_prefix("lonewolf"));
    let mut output = String::new();
    prometheus_client::encoding::text::encode(&mut output, &root)?;
    assert!(!output.contains("lonewolf_lonewolf_"), "{output}");
    Ok(output)
}

fn assert_sample(output: &str, sample: &str) {
    assert!(
        output.lines().any(|line| line == sample),
        "missing {sample} in {output}"
    );
}

const DIRECTION_LABELS: [&str; 2] = ["inbound", "outbound"];

const CONNECTION_REJECTION_LABELS: [&str; 5] = [
    "connection_attempts_per_ip",
    "attempt_tracking_full",
    "max_inbound_connections",
    "max_connections_per_ip",
    "connection_tracking_full",
];

const AUTH_OUTCOME_LABELS: [&str; 19] = [
    "success",
    "host_unknown",
    "missing_from",
    "invalid_from",
    "no_certificate",
    "certificate_untrusted",
    "certificate_name",
    "certificate_purpose",
    "certificate_expired",
    "tls_failure",
    "no_tls",
    "tls_refused",
    "external_not_offered",
    "invalid_authzid",
    "invalid_mechanism",
    "sasl_failure",
    "unreachable",
    "timeout",
    "protocol",
];

const STREAM_CLOSE_LABELS: [&str; 16] = [
    "stream_end",
    "idle",
    "certificate_expired",
    "shutdown",
    "conflict",
    "improper_addressing",
    "host_unknown",
    "invalid_from",
    "invalid_namespace",
    "unsupported_stanza_type",
    "not_authorized",
    "peer_error",
    "stalled_write",
    "transport_error",
    "internal_error",
    "protocol_error",
];

const INBOUND_LIMIT_LABELS: [&str; 2] = [
    "incoming_stanzas_per_connection",
    "incoming_xml_per_connection",
];

const DNS_OUTCOME_LABELS: [&str; 8] = [
    "srv",
    "fallback",
    "static",
    "literal",
    "no_service",
    "not_found",
    "unavailable",
    "invalid_domain",
];

const LINK_STATE_LABELS: [&str; 3] = ["connecting", "ready", "backoff"];

const ADMISSION_REASON_LABELS: [&str; 5] = [
    "queue_full",
    "link_limit",
    "backoff",
    "unsupported",
    "stopped",
];

const BOUNCE_CONDITION_LABELS: [&str; 3] = [
    "remote_server_not_found",
    "remote_server_timeout",
    "resource_constraint",
];

const DROP_REASON_LABELS: [&str; 4] = [
    "shutdown",
    "connection_lost",
    "not_bounceable",
    "internal_error",
];

#[test]
fn label_values_and_indexes_are_fixed() {
    for (index, value) in Direction::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), DIRECTION_LABELS[index]);
    }
    for (index, value) in ConnectionRejection::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), CONNECTION_REJECTION_LABELS[index]);
    }
    for (index, value) in AuthOutcome::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), AUTH_OUTCOME_LABELS[index]);
    }
    for (index, value) in StreamClose::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), STREAM_CLOSE_LABELS[index]);
    }
    for (index, value) in InboundLimit::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), INBOUND_LIMIT_LABELS[index]);
    }
    for (index, value) in DnsOutcome::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), DNS_OUTCOME_LABELS[index]);
    }
    for (index, value) in LinkState::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), LINK_STATE_LABELS[index]);
    }
    for (index, value) in AdmissionReason::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), ADMISSION_REASON_LABELS[index]);
    }
    for (index, value) in BounceCondition::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), BOUNCE_CONDITION_LABELS[index]);
    }
    for (index, value) in DropReason::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), DROP_REASON_LABELS[index]);
    }
    for (index, kind) in KINDS.into_iter().enumerate() {
        assert_eq!(kind_index(kind), index);
        assert_eq!(kind.as_str(), ["message", "presence", "iq"][index]);
    }
}

fn record_all(metrics: &Arc<S2sMetrics>) -> Vec<ConnectionGauge> {
    let mut guards = Vec::new();
    for direction in Direction::ALL {
        guards.push(metrics.connection_opened(direction));
        guards.push(metrics.stream_opened(direction));
        for outcome in AuthOutcome::ALL {
            metrics.authentication(direction, outcome, Duration::from_millis(500));
        }
        for outcome in StreamClose::ALL {
            metrics.stream_closed(direction, outcome);
        }
        metrics.bytes(direction, 17, 23);
    }
    for listener in 0..2 {
        metrics.connection_accepted(listener);
        for reason in ConnectionRejection::ALL {
            metrics.connection_rejected(listener, reason);
        }
    }
    for kind in KINDS {
        metrics.stanza_received(kind);
        metrics.stanza_sent(kind);
    }
    for limit in InboundLimit::ALL {
        metrics.rate_limited(limit);
    }
    for outcome in DnsOutcome::ALL {
        metrics.dns(outcome);
    }
    for reason in AdmissionReason::ALL {
        metrics.admission_rejected(reason);
    }
    for condition in BounceCondition::ALL {
        metrics.bounced(condition);
    }
    for reason in DropReason::ALL {
        metrics.dropped(reason, 7);
    }
    guards
}

#[test]
fn every_recorder_encodes_exact_samples() -> Result<(), fmt::Error> {
    let metrics = S2sMetrics::new(2);
    let _guards = record_all(&metrics);
    let output = render(&metrics)?;
    for direction in DIRECTION_LABELS {
        for name in ["connections", "streams"] {
            assert_sample(
                &output,
                &format!("lonewolf_s2s_{name}{{direction=\"{direction}\"}} 1"),
            );
        }
        for outcome in AUTH_OUTCOME_LABELS {
            assert_sample(
                &output,
                &format!(
                    "lonewolf_s2s_authentications_total{{direction=\"{direction}\",outcome=\"{outcome}\"}} 1"
                ),
            );
        }
        for outcome in STREAM_CLOSE_LABELS {
            assert_sample(
                &output,
                &format!(
                    "lonewolf_s2s_streams_closed_total{{direction=\"{direction}\",outcome=\"{outcome}\"}} 1"
                ),
            );
        }
        assert_sample(
            &output,
            &format!("lonewolf_s2s_received_bytes_total{{direction=\"{direction}\"}} 17"),
        );
        assert_sample(
            &output,
            &format!("lonewolf_s2s_sent_bytes_total{{direction=\"{direction}\"}} 23"),
        );
        assert_sample(
            &output,
            &format!(
                "lonewolf_s2s_negotiation_duration_seconds_count{{direction=\"{direction}\"}} 19"
            ),
        );
        assert_sample(
            &output,
            &format!(
                "lonewolf_s2s_negotiation_duration_seconds_sum{{direction=\"{direction}\"}} 9.5"
            ),
        );
        for boundary in PHASE_BUCKETS.into_iter().chain([f64::INFINITY]) {
            let boundary_label = if boundary.is_infinite() {
                "+Inf".into()
            } else {
                format!("{boundary:?}")
            };
            let count = if boundary < 0.5 { 0 } else { 19 };
            assert_sample(
                &output,
                &format!(
                    "lonewolf_s2s_negotiation_duration_seconds_bucket{{le=\"{boundary_label}\",direction=\"{direction}\"}} {count}"
                ),
            );
        }
    }
    for listener in 0..2 {
        assert_sample(
            &output,
            &format!("lonewolf_s2s_connections_accepted_total{{listener=\"{listener}\"}} 1"),
        );
        for reason in CONNECTION_REJECTION_LABELS {
            assert_sample(
                &output,
                &format!(
                    "lonewolf_s2s_connections_rejected_total{{listener=\"{listener}\",reason=\"{reason}\"}} 1"
                ),
            );
        }
    }
    for kind in ["message", "presence", "iq"] {
        for name in ["received", "sent"] {
            assert_sample(
                &output,
                &format!("lonewolf_s2s_stanzas_{name}_total{{kind=\"{kind}\"}} 1"),
            );
        }
    }
    for value in INBOUND_LIMIT_LABELS {
        assert_sample(
            &output,
            &format!("lonewolf_s2s_rate_limited_total{{limit=\"{value}\"}} 1"),
        );
    }
    for value in DNS_OUTCOME_LABELS {
        assert_sample(
            &output,
            &format!("lonewolf_s2s_dns_resolutions_total{{outcome=\"{value}\"}} 1"),
        );
    }
    for value in ADMISSION_REASON_LABELS {
        assert_sample(
            &output,
            &format!("lonewolf_s2s_admission_rejections_total{{reason=\"{value}\"}} 1"),
        );
    }
    for value in BOUNCE_CONDITION_LABELS {
        assert_sample(
            &output,
            &format!("lonewolf_s2s_bounces_total{{condition=\"{value}\"}} 1"),
        );
    }
    for value in DROP_REASON_LABELS {
        assert_sample(
            &output,
            &format!("lonewolf_s2s_dropped_stanzas_total{{reason=\"{value}\"}} 7"),
        );
    }
    Ok(())
}

#[test]
fn untouched_counter_families_are_omitted() -> Result<(), fmt::Error> {
    let metrics = S2sMetrics::new(0);
    let output = render(&metrics)?;
    assert!(!output.contains("# TYPE lonewolf_s2s_connections_accepted"));
    assert!(!output.contains("_total"));
    metrics.dropped(DropReason::Shutdown, 0);
    assert_eq!(render(&metrics)?, output);
    metrics.dns(DnsOutcome::Srv);
    let output = render(&metrics)?;
    assert_sample(
        &output,
        "lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1",
    );
    assert!(!output.contains("outcome=\"fallback\""));
    for direction in DIRECTION_LABELS {
        for name in ["connections", "streams"] {
            assert_sample(
                &output,
                &format!("lonewolf_s2s_{name}{{direction=\"{direction}\"}} 0"),
            );
        }
    }
    Ok(())
}

#[test]
fn guards_release_connection_and_stream_counts_on_cancellation() -> Result<(), fmt::Error> {
    let metrics = S2sMetrics::new(0);
    let task_metrics = Arc::clone(&metrics);
    let mut future = Box::pin(async move {
        let _inbound = task_metrics.connection_opened(Direction::Inbound);
        let _outbound = task_metrics.connection_opened(Direction::Outbound);
        let _inbound_stream = task_metrics.stream_opened(Direction::Inbound);
        let _outbound_stream = task_metrics.stream_opened(Direction::Outbound);
        std::future::pending::<()>().await;
    });
    assert_eq!(
        future.as_mut().poll(&mut Context::from_waker(
            futures_util::task::noop_waker_ref()
        )),
        Poll::Pending
    );
    let output = render(&metrics)?;
    for direction in DIRECTION_LABELS {
        for name in ["connections", "streams"] {
            assert_sample(
                &output,
                &format!("lonewolf_s2s_{name}{{direction=\"{direction}\"}} 1"),
            );
        }
    }
    drop(future);
    let output = render(&metrics)?;
    for direction in DIRECTION_LABELS {
        for name in ["connections", "streams"] {
            assert_sample(
                &output,
                &format!("lonewolf_s2s_{name}{{direction=\"{direction}\"}} 0"),
            );
        }
    }
    Ok(())
}

#[derive(Default)]
struct FakeLinks {
    value: AtomicU64,
    snapshots: AtomicU64,
}

impl LinkStats for FakeLinks {
    fn snapshot(&self) -> LinkSnapshot {
        self.snapshots.fetch_add(1, Ordering::Relaxed);
        let value = self.value.load(Ordering::Relaxed);
        LinkSnapshot {
            connecting: value,
            ready: value * 2,
            backoff: value,
            queued_stanzas: value * 3,
            queued_bytes: value * 17,
        }
    }
}

fn assert_link_samples(output: &str, value: u64) {
    for (state, count) in [
        ("connecting", value),
        ("ready", value * 2),
        ("backoff", value),
    ] {
        assert_sample(
            output,
            &format!("lonewolf_s2s_outbound_links{{state=\"{state}\"}} {count}"),
        );
    }
    assert_sample(
        output,
        &format!("lonewolf_s2s_outbound_queued_stanzas {}", value * 3),
    );
    assert_sample(
        output,
        &format!("lonewolf_s2s_outbound_queued_bytes {}", value * 17),
    );
}

#[test]
fn link_gauges_snapshot_at_scrape_time_without_retaining_source() -> Result<(), fmt::Error> {
    let metrics = S2sMetrics::new(0);
    assert_link_samples(&render(&metrics)?, 0);
    let source = Arc::new(FakeLinks::default());
    let erased: Arc<dyn LinkStats> = source.clone();
    metrics.set_link_source(Arc::downgrade(&erased));
    drop(erased);
    assert_eq!(Arc::strong_count(&source), 1);
    source.value.store(1, Ordering::Relaxed);
    assert_link_samples(&render(&metrics)?, 1);
    source.value.store(5, Ordering::Relaxed);
    assert_link_samples(&render(&metrics)?, 5);
    assert_eq!(source.snapshots.load(Ordering::Relaxed), 2);
    assert_eq!(Arc::strong_count(&source), 1);
    let weak_source = Arc::downgrade(&source);
    drop(source);
    assert!(weak_source.upgrade().is_none());
    assert_link_samples(&render(&metrics)?, 0);
    Ok(())
}

#[test]
fn every_family_has_only_its_bounded_labels() -> Result<(), fmt::Error> {
    let metrics = S2sMetrics::new(2);
    let _guards = record_all(&metrics);
    let output = render(&metrics)?;
    let mut families = std::collections::BTreeSet::new();
    for line in output.lines().filter(|line| !line.starts_with('#')) {
        let (sample, _) = line.split_once(' ').ok_or(fmt::Error)?;
        let (name, labels) = if let Some((name, rest)) = sample.split_once('{') {
            (name, rest.strip_suffix('}').ok_or(fmt::Error)?)
        } else {
            (sample, "")
        };
        let expected: &[&str] = match name {
            "lonewolf_s2s_connections"
            | "lonewolf_s2s_streams"
            | "lonewolf_s2s_received_bytes_total"
            | "lonewolf_s2s_sent_bytes_total"
            | "lonewolf_s2s_negotiation_duration_seconds_count"
            | "lonewolf_s2s_negotiation_duration_seconds_sum" => &["direction"],
            "lonewolf_s2s_connections_accepted_total" => &["listener"],
            "lonewolf_s2s_connections_rejected_total" => &["listener", "reason"],
            "lonewolf_s2s_authentications_total" | "lonewolf_s2s_streams_closed_total" => {
                &["direction", "outcome"]
            }
            "lonewolf_s2s_negotiation_duration_seconds_bucket" => &["le", "direction"],
            "lonewolf_s2s_stanzas_received_total" | "lonewolf_s2s_stanzas_sent_total" => &["kind"],
            "lonewolf_s2s_rate_limited_total" => &["limit"],
            "lonewolf_s2s_dns_resolutions_total" => &["outcome"],
            "lonewolf_s2s_admission_rejections_total" | "lonewolf_s2s_dropped_stanzas_total" => {
                &["reason"]
            }
            "lonewolf_s2s_bounces_total" => &["condition"],
            "lonewolf_s2s_outbound_links" => &["state"],
            "lonewolf_s2s_outbound_queued_stanzas" | "lonewolf_s2s_outbound_queued_bytes" => &[],
            _ => panic!("unexpected sample: {line}"),
        };
        families.insert(name);
        let actual: Vec<_> = labels
            .split(',')
            .filter(|label| !label.is_empty())
            .map(|label| label.split_once('=').ok_or(fmt::Error).map(|(key, _)| key))
            .collect::<Result<_, _>>()?;
        assert_eq!(actual, expected, "{line}");
    }
    assert_eq!(families.len(), 21);
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn shutdown_snapshot_uses_rendered_counter_and_link_sources() -> Result<(), fmt::Error> {
    let metrics = S2sMetrics::new(1);
    assert_eq!(
        metrics.shutdown_state(),
        crate::test_support::S2sShutdownState {
            dropped_shutdown: 0,
            dropped_connection_lost: 0,
            queued_stanzas: 0,
            queued_bytes: 0,
        }
    );
    let source = Arc::new(FakeLinks::default());
    let erased: Arc<dyn LinkStats> = source.clone();
    metrics.set_link_source(Arc::downgrade(&erased));
    for value in [0, 2, 5] {
        source.value.store(value, Ordering::Relaxed);
        metrics.dropped(DropReason::Shutdown, value);
        metrics.dropped(DropReason::ConnectionLost, value + 1);
        let state = metrics.shutdown_state();
        let output = render(&metrics)?;
        for (name, count) in [
            (
                "lonewolf_s2s_dropped_stanzas_total{reason=\"shutdown\"}",
                state.dropped_shutdown,
            ),
            (
                "lonewolf_s2s_dropped_stanzas_total{reason=\"connection_lost\"}",
                state.dropped_connection_lost,
            ),
            ("lonewolf_s2s_outbound_queued_stanzas", state.queued_stanzas),
            ("lonewolf_s2s_outbound_queued_bytes", state.queued_bytes),
        ] {
            if count > 0 || !name.contains("dropped") {
                assert_sample(&output, &format!("{name} {count}"));
            }
        }
        assert_eq!(state.queued_stanzas, value * 3);
        assert_eq!(state.queued_bytes, value * 17);
    }
    drop(erased);
    drop(source);
    let state = metrics.shutdown_state();
    assert_eq!(state.dropped_shutdown, 7);
    assert_eq!(state.dropped_connection_lost, 10);
    assert_eq!(state.queued_stanzas, 0);
    assert_eq!(state.queued_bytes, 0);
    assert_link_samples(&render(&metrics)?, 0);
    Ok(())
}
