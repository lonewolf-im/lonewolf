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

const AUTH_OUTCOME_LABELS: [&str; 23] = [
    "success",
    "host_unknown",
    "missing_from",
    "invalid_from",
    "no_certificate",
    "certificate_untrusted",
    "certificate_name",
    "certificate_purpose",
    "certificate_expired",
    "certificate_revoked",
    "revocation_unknown",
    "revocation_stale",
    "revocation_unavailable",
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

const STREAM_CLOSE_LABELS: [&str; 20] = [
    "stream_end",
    "idle",
    "certificate_expired",
    "certificate_revoked",
    "revocation_unknown",
    "revocation_stale",
    "revocation_unavailable",
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

const BOUNCE_CONDITION_LABELS: [&str; 4] = [
    "remote_server_not_found",
    "remote_server_timeout",
    "resource_constraint",
    "policy_violation",
];

const DROP_REASON_LABELS: [&str; 4] = [
    "shutdown",
    "connection_lost",
    "not_bounceable",
    "internal_error",
];

const BIDI_OUTCOME_LABELS: [&str; 3] = ["enabled", "not_offered", "not_requested"];

const BIDI_HANDOFF_LABELS: [&str; 2] = ["inbound_stream", "dialed_link"];

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
    for (index, value) in BidiOutcome::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), BIDI_OUTCOME_LABELS[index]);
    }
    for (index, value) in BidiHandoff::ALL.into_iter().enumerate() {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), BIDI_HANDOFF_LABELS[index]);
    }
    for (index, kind) in KINDS.into_iter().enumerate() {
        assert_eq!(kind_index(kind), index);
        assert_eq!(kind.as_str(), ["message", "presence", "iq"][index]);
    }
}

fn record_all(metrics: &Arc<S2sMetrics>) -> Vec<ConnectionGauge> {
    let mut guards = Vec::new();
    for direction in Direction::ALL {
        guards.push(metrics.connection_opened(direction, TlsMode::StartTls));
        guards.push(metrics.stream_opened(direction));
        guards.push(metrics.bidi_stream_opened(direction));
        for outcome in BidiOutcome::ALL {
            metrics.bidi_negotiated(direction, outcome);
        }
        for outcome in AuthOutcome::ALL {
            metrics.authentication(direction, outcome, Duration::from_millis(500));
        }
        for outcome in StreamClose::ALL {
            metrics.stream_closed(direction, outcome);
        }
        for source in RevocationSource::ALL {
            let verdict = RevocationVerdict {
                source,
                status: RevocationStatus::Good,
                next_update: None,
                refresh_at: None,
                pending: Vec::new(),
                leases: Vec::new(),
                recheckable: false,
            };
            for phase in CheckPhase::ALL {
                metrics.revocation_checked(direction, phase, &verdict);
            }
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
        metrics.bidi_stanza_sent(kind);
        metrics.bidi_stanza_received(kind);
    }
    for target in BidiHandoff::ALL {
        metrics.bidi_handoff(target);
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
    metrics.peer_size_rejected();
    for condition in BounceCondition::ALL {
        metrics.bounced(condition);
    }
    for reason in DropReason::ALL {
        metrics.dropped(reason, 7);
    }
    for outcome in CrlFetchOutcome::ALL {
        metrics.crl_fetched(outcome, Duration::from_millis(100));
    }
    for reason in CrlEviction::ALL {
        metrics.crl_cache_evicted(reason);
    }
    metrics.crl_cache_size(1, 1234);
    guards
}

#[test]
fn every_recorder_encodes_exact_samples() -> Result<(), fmt::Error> {
    let metrics = S2sMetrics::new(2);
    let _guards = record_all(&metrics);
    let output = render(&metrics)?;
    for direction in DIRECTION_LABELS {
        for name in ["connections", "streams", "bidi_streams"] {
            assert_sample(
                &output,
                &format!("lonewolf_s2s_{name}{{direction=\"{direction}\"}} 1"),
            );
        }
        for source in ["file", "fetched"] {
            for phase in ["handshake", "recheck"] {
                assert_sample(
                    &output,
                    &format!(
                        "lonewolf_s2s_revocation_checks_total{{direction=\"{direction}\",source=\"{source}\",phase=\"{phase}\",status=\"good\",reason=\"none\"}} 1"
                    ),
                );
            }
        }
        for outcome in AUTH_OUTCOME_LABELS {
            assert_sample(
                &output,
                &format!(
                    "lonewolf_s2s_authentications_total{{direction=\"{direction}\",outcome=\"{outcome}\"}} 1"
                ),
            );
        }
        for outcome in BIDI_OUTCOME_LABELS {
            assert_sample(
                &output,
                &format!(
                    "lonewolf_s2s_bidi_negotiations_total{{direction=\"{direction}\",outcome=\"{outcome}\"}} 1"
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
                "lonewolf_s2s_negotiation_duration_seconds_count{{direction=\"{direction}\"}} 23"
            ),
        );
        assert_sample(
            &output,
            &format!(
                "lonewolf_s2s_negotiation_duration_seconds_sum{{direction=\"{direction}\"}} 11.5"
            ),
        );
        for boundary in PHASE_BUCKETS.into_iter().chain([f64::INFINITY]) {
            let boundary_label = if boundary.is_infinite() {
                "+Inf".into()
            } else {
                format!("{boundary:?}")
            };
            let count = if boundary < 0.5 { 0 } else { 23 };
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
        for name in [
            "stanzas_received",
            "stanzas_sent",
            "bidi_stanzas_sent",
            "bidi_stanzas_received",
        ] {
            assert_sample(
                &output,
                &format!("lonewolf_s2s_{name}_total{{kind=\"{kind}\"}} 1"),
            );
        }
    }
    for target in BIDI_HANDOFF_LABELS {
        assert_sample(
            &output,
            &format!("lonewolf_s2s_bidi_handoffs_total{{target=\"{target}\"}} 1"),
        );
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
    assert_sample(&output, "lonewolf_s2s_peer_size_rejections_total 1");
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
        for name in ["connections", "streams", "bidi_streams"] {
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
        let _inbound = task_metrics.connection_opened(Direction::Inbound, TlsMode::StartTls);
        let _outbound = task_metrics.connection_opened(Direction::Outbound, TlsMode::StartTls);
        let _inbound_stream = task_metrics.stream_opened(Direction::Inbound);
        let _outbound_stream = task_metrics.stream_opened(Direction::Outbound);
        let _inbound_bidi = task_metrics.bidi_stream_opened(Direction::Inbound);
        let _outbound_bidi = task_metrics.bidi_stream_opened(Direction::Outbound);
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
        for name in ["connections", "streams", "bidi_streams"] {
            assert_sample(
                &output,
                &format!("lonewolf_s2s_{name}{{direction=\"{direction}\"}} 1"),
            );
        }
    }
    drop(future);
    let output = render(&metrics)?;
    for direction in DIRECTION_LABELS {
        for name in ["connections", "streams", "bidi_streams"] {
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
    let _bound = metrics.listener_bound(0, TlsMode::Direct);
    metrics
        .transport_attempt(Direction::Inbound, TlsMode::Direct)
        .complete(AuthOutcome::Success);
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
            | "lonewolf_s2s_bidi_streams"
            | "lonewolf_s2s_received_bytes_total"
            | "lonewolf_s2s_sent_bytes_total"
            | "lonewolf_s2s_negotiation_duration_seconds_count"
            | "lonewolf_s2s_negotiation_duration_seconds_sum" => &["direction"],
            "lonewolf_s2s_listener_info" => &["listener", "tls_mode"],
            "lonewolf_s2s_transport_connections" => &["direction", "tls_mode"],
            "lonewolf_s2s_transport_attempts_total" => &["direction", "tls_mode", "outcome"],
            "lonewolf_s2s_crl_fetches_total" => &["outcome"],
            "lonewolf_s2s_crl_cache_evictions_total" => &["reason"],
            "lonewolf_s2s_crl_fetch_duration_seconds_bucket" => &["le"],
            "lonewolf_s2s_peer_size_rejections_total"
            | "lonewolf_s2s_crl_fetch_duration_seconds_count"
            | "lonewolf_s2s_crl_fetch_duration_seconds_sum"
            | "lonewolf_s2s_crl_cache_entries"
            | "lonewolf_s2s_crl_cache_bytes" => &[],
            "lonewolf_s2s_connections_accepted_total" => &["listener"],
            "lonewolf_s2s_connections_rejected_total" => &["listener", "reason"],
            "lonewolf_s2s_authentications_total"
            | "lonewolf_s2s_streams_closed_total"
            | "lonewolf_s2s_bidi_negotiations_total" => &["direction", "outcome"],
            "lonewolf_s2s_revocation_checks_total" => {
                &["direction", "source", "phase", "status", "reason"]
            }
            "lonewolf_s2s_negotiation_duration_seconds_bucket" => &["le", "direction"],
            "lonewolf_s2s_stanzas_received_total"
            | "lonewolf_s2s_stanzas_sent_total"
            | "lonewolf_s2s_bidi_stanzas_sent_total"
            | "lonewolf_s2s_bidi_stanzas_received_total" => &["kind"],
            "lonewolf_s2s_rate_limited_total" => &["limit"],
            "lonewolf_s2s_dns_resolutions_total" => &["outcome"],
            "lonewolf_s2s_admission_rejections_total" | "lonewolf_s2s_dropped_stanzas_total" => {
                &["reason"]
            }
            "lonewolf_s2s_bounces_total" => &["condition"],
            "lonewolf_s2s_bidi_handoffs_total" => &["target"],
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
    assert_eq!(families.len(), 38);
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
            transport_cancelled: [[0; 2]; 2],
            transport_connections: [[0; 2]; 2],
            connections: [0; 2],
            authentication_protocol: [0; 2],
            streams: [0; 2],
            bidi_streams: [0; 2],
            c2s_connections: 0,
            c2s_unauthenticated: 0,
            router_sessions: 0,
        }
    );
    let stream = metrics.stream_opened(Direction::Inbound);
    let bidi = metrics.bidi_stream_opened(Direction::Outbound);
    assert_eq!(metrics.shutdown_state().streams, [1, 0]);
    assert_eq!(metrics.shutdown_state().bidi_streams, [0, 1]);
    drop(stream);
    drop(bidi);
    assert_eq!(metrics.shutdown_state().streams, [0; 2]);
    assert_eq!(metrics.shutdown_state().bidi_streams, [0; 2]);
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

#[test]
fn revocation_checks_render_only_recorded_source_phase_and_status() -> Result<(), fmt::Error> {
    use crate::s2s::revocation::UnknownReason;

    let metrics = S2sMetrics::new(0);
    assert!(!render(&metrics)?.contains("s2s_revocation_checks"));
    let mut verdict = RevocationVerdict {
        source: RevocationSource::Fetched,
        status: RevocationStatus::Unknown(UnknownReason::BlockedAddress),
        next_update: None,
        refresh_at: None,
        pending: Vec::new(),
        leases: Vec::new(),
        recheckable: false,
    };
    metrics.revocation_checked(Direction::Outbound, CheckPhase::Recheck, &verdict);
    let output = render(&metrics)?;
    assert_sample(
        &output,
        "lonewolf_s2s_revocation_checks_total{direction=\"outbound\",source=\"fetched\",phase=\"recheck\",status=\"unknown\",reason=\"blocked_address\"} 1",
    );
    verdict.source = RevocationSource::File;
    verdict.status = RevocationStatus::Good;
    metrics.revocation_checked(Direction::Inbound, CheckPhase::Handshake, &verdict);
    let output = render(&metrics)?;
    assert_sample(
        &output,
        "lonewolf_s2s_revocation_checks_total{direction=\"inbound\",source=\"file\",phase=\"handshake\",status=\"good\",reason=\"none\"} 1",
    );
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("lonewolf_s2s_revocation_checks_total{"))
            .count(),
        2
    );
    Ok(())
}

#[test]
fn crl_metrics_have_fixed_labels_and_activate_cache_gauges_on_use() -> Result<(), fmt::Error> {
    for (index, (value, label)) in CrlFetchOutcome::ALL
        .into_iter()
        .zip([
            "success",
            "dns_failed",
            "blocked_address",
            "connect_failed",
            "timeout",
            "http_status",
            "too_large",
            "invalid",
            "stale",
            "rollback",
        ])
        .enumerate()
    {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), label);
    }
    for (index, (value, label)) in CrlEviction::ALL
        .into_iter()
        .zip(["unused", "capacity", "stale_expired"])
        .enumerate()
    {
        assert_eq!(value as usize, index);
        assert_eq!(value.as_str(), label);
    }
    let metrics = S2sMetrics::new(0);
    assert!(!render(&metrics)?.contains("lonewolf_s2s_crl_"));
    metrics.crl_fetched(CrlFetchOutcome::Rollback, Duration::from_millis(50));
    metrics.crl_cache_size(1, 1234);
    for reason in CrlEviction::ALL {
        metrics.crl_cache_evicted(reason);
    }
    let output = render(&metrics)?;
    assert_sample(
        &output,
        "lonewolf_s2s_crl_fetches_total{outcome=\"rollback\"} 1",
    );
    assert_sample(&output, "lonewolf_s2s_crl_fetch_duration_seconds_count 1");
    assert_sample(&output, "lonewolf_s2s_crl_cache_entries 1");
    assert_sample(&output, "lonewolf_s2s_crl_cache_bytes 1234");
    for reason in ["unused", "capacity", "stale_expired"] {
        assert_sample(
            &output,
            &format!("lonewolf_s2s_crl_cache_evictions_total{{reason=\"{reason}\"}} 1"),
        );
    }
    Ok(())
}

#[test]
fn only_certificate_invalidations_use_the_reset_close_path() {
    for outcome in StreamClose::ALL {
        assert_eq!(
            outcome.certificate_invalid(),
            matches!(
                outcome,
                StreamClose::CertificateExpired
                    | StreamClose::CertificateRevoked
                    | StreamClose::RevocationUnknown
                    | StreamClose::RevocationStale
                    | StreamClose::RevocationUnavailable
            )
        );
    }
}

#[test]
fn crl_file_metrics_appear_only_after_loads_and_keep_the_last_success() -> Result<(), fmt::Error> {
    let metrics = S2sMetrics::new(0);
    let fresh = render(&metrics)?;
    assert!(!fresh.contains("s2s_crl_file_"));
    for error in CrlLoadError::ALL {
        metrics.crl_file_load_failed(error);
    }
    let failures = render(&metrics)?;
    for reason in ["unreadable", "invalid", "stale"] {
        assert_sample(
            &failures,
            &format!("lonewolf_s2s_crl_file_load_failures_total{{reason=\"{reason}\"}} 1"),
        );
    }
    assert!(!failures.contains("s2s_crl_file_next_update_seconds"));
    metrics.crl_file_loaded(std::time::UNIX_EPOCH + Duration::from_secs(1_800_000_000));
    metrics.crl_file_load_failed(CrlLoadError::Stale);
    let output = render(&metrics)?;
    assert_sample(
        &output,
        "lonewolf_s2s_crl_file_next_update_seconds 1800000000",
    );
    assert_sample(
        &output,
        "lonewolf_s2s_crl_file_load_failures_total{reason=\"stale\"} 2",
    );
    Ok(())
}

#[test]
fn transport_attempts_are_bounded_terminal_once_and_default_cancelled() -> Result<(), fmt::Error> {
    let metrics = S2sMetrics::new(1);
    assert!(!render(&metrics)?.contains("lonewolf_s2s_listener_info"));
    let first = metrics.listener_bound(0, TlsMode::Direct);
    let second = metrics.listener_bound(0, TlsMode::Direct);
    let bound = render(&metrics)?;
    assert_eq!(
        bound
            .lines()
            .filter(|line| line.starts_with("lonewolf_s2s_listener_info{"))
            .count(),
        1
    );
    assert_sample(
        &bound,
        "lonewolf_s2s_listener_info{listener=\"0\",tls_mode=\"direct\"} 1",
    );
    drop(first);
    assert_sample(
        &render(&metrics)?,
        "lonewolf_s2s_listener_info{listener=\"0\",tls_mode=\"direct\"} 1",
    );
    drop(second);
    assert!(!render(&metrics)?.contains("lonewolf_s2s_listener_info"));
    for direction in Direction::ALL {
        for mode in TlsMode::ALL {
            for outcome in AuthOutcome::ALL {
                let mut attempt = metrics.transport_attempt(direction, mode);
                attempt.complete(outcome);
                attempt.complete(AuthOutcome::Success);
                attempt.cancel();
            }
            let attempt = metrics.transport_attempt(direction, mode);
            let unpolled = async move { drop(attempt) };
            drop(unpolled);
        }
    }
    let output = render(&metrics)?;
    assert!(output.contains("# TYPE lonewolf_s2s_transport_attempts counter\n"));
    assert!(!output.contains("lonewolf_s2s_authentications_total"));
    let samples: Vec<_> = output
        .lines()
        .filter(|line| line.starts_with("lonewolf_s2s_transport_attempts_total{"))
        .collect();
    assert_eq!(samples.len(), 2 * 2 * 24);
    for direction in Direction::ALL {
        for mode in TlsMode::ALL {
            for outcome in AuthOutcome::ALL
                .into_iter()
                .map(Some)
                .chain(std::iter::once(None))
            {
                assert_sample(
                    &output,
                    &format!(
                        "lonewolf_s2s_transport_attempts_total{{direction=\"{}\",tls_mode=\"{}\",outcome=\"{}\"}} 1",
                        direction.as_str(),
                        mode.as_str(),
                        outcome.map_or("cancelled", AuthOutcome::as_str)
                    ),
                );
            }
        }
    }
    Ok(())
}

#[test]
fn transport_connection_guards_share_direction_lifetimes_without_affecting_streams()
-> Result<(), fmt::Error> {
    let metrics = S2sMetrics::new(0);
    for direction in Direction::ALL {
        let first = metrics.connection_opened(direction, TlsMode::StartTls);
        let second = metrics.connection_opened(direction, TlsMode::Direct);
        let stream = metrics.stream_opened(direction);
        let bidi = metrics.bidi_stream_opened(direction);
        assert_eq!(
            metrics.connections[direction as usize].load(Ordering::Relaxed),
            2
        );
        for mode in TlsMode::ALL {
            assert_eq!(
                metrics.transport_connections[direction as usize][mode as usize]
                    .load(Ordering::Relaxed),
                1
            );
        }
        drop(first);
        assert_eq!(
            metrics.connections[direction as usize].load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.transport_connections[direction as usize][TlsMode::StartTls as usize]
                .load(Ordering::Relaxed),
            0
        );
        drop(second);
        assert_eq!(
            metrics.connections[direction as usize].load(Ordering::Relaxed),
            0
        );
        for mode in TlsMode::ALL {
            assert_eq!(
                metrics.transport_connections[direction as usize][mode as usize]
                    .load(Ordering::Relaxed),
                0
            );
        }
        assert_eq!(
            metrics.streams[direction as usize].load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.bidi_streams[direction as usize].load(Ordering::Relaxed),
            1
        );
        drop((stream, bidi));
    }
    let output = render(&metrics)?;
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("lonewolf_s2s_transport_connections{"))
            .count(),
        4
    );
    assert!(output.contains("# TYPE lonewolf_s2s_transport_connections gauge\n"));
    Ok(())
}
