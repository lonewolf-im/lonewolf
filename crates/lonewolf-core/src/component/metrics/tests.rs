// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::future::Future;
use std::task::{Context, Poll};

use super::*;

fn render(metrics: &Arc<ComponentMetrics>) -> Result<String, fmt::Error> {
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

fn record_all(metrics: &Arc<ComponentMetrics>) -> Vec<GaugeGuard> {
    let mut guards = Vec::with_capacity(2 * Transport::ALL.len() + 2);
    for listener in 0..2 {
        for transport in Transport::ALL {
            guards.push(metrics.listener_bound(listener, transport));
        }
        metrics.connection_accepted(listener);
        for reason in ConnectionRejection::ALL {
            metrics.connection_rejected(listener, reason);
        }
    }
    guards.push(metrics.connection_opened());
    guards.push(metrics.stream_opened());
    for outcome in AuthOutcome::ALL {
        metrics.authentication(outcome, Duration::from_millis(500));
    }
    for outcome in StreamClose::ALL {
        metrics.stream_closed(outcome);
    }
    for kind in KINDS {
        metrics.stanza_received(kind);
        metrics.stanza_sent(kind);
    }
    metrics.bytes(17, 23);
    for limit in InboundLimit::ALL {
        metrics.rate_limited(limit);
    }
    for reason in AdmissionReason::ALL {
        metrics.admission_rejected(reason);
    }
    metrics.moved(2);
    metrics.bounced(3);
    for reason in DropReason::ALL {
        metrics.dropped(reason, 5);
    }
    guards
}

#[test]
fn enum_labels_match_the_fixed_catalog() {
    assert_eq!(Transport::ALL.map(Transport::as_str), ["none", "direct"]);
    assert_eq!(
        ConnectionRejection::ALL.map(ConnectionRejection::as_str),
        [
            "connection_attempts_per_ip",
            "attempt_tracking_full",
            "max_inbound_connections",
        ]
    );
    assert_eq!(
        AuthOutcome::ALL.map(AuthOutcome::as_str),
        [
            "success",
            "tls_failure",
            "host_unknown",
            "invalid_namespace",
            "not_authorized",
            "conflict",
            "timeout",
            "shutdown",
            "protocol_error",
            "peer_closed",
            "transport_error",
        ]
    );
    assert_eq!(
        StreamClose::ALL.map(StreamClose::as_str),
        [
            "stream_end",
            "shutdown",
            "improper_addressing",
            "invalid_from",
            "invalid_namespace",
            "unsupported_stanza_type",
            "protocol_error",
            "peer_error",
            "transport_error",
            "stalled_write",
            "internal_error",
        ]
    );
    assert_eq!(
        InboundLimit::ALL.map(InboundLimit::as_str),
        [
            "incoming_stanzas_per_connection",
            "incoming_xml_per_connection",
        ]
    );
    assert_eq!(
        AdmissionReason::ALL.map(AdmissionReason::as_str),
        ["not_connected", "queue_full", "stopped",]
    );
    assert_eq!(
        DropReason::ALL.map(DropReason::as_str),
        ["not_bounceable", "shutdown", "invalid",]
    );
    assert_eq!(KINDS.map(StanzaKind::as_str), ["message", "presence", "iq"]);
}

#[test]
fn recording_methods_encode_the_exact_samples_and_histogram() -> Result<(), fmt::Error> {
    let metrics = ComponentMetrics::new(2, 2);
    let _guards = record_all(&metrics);
    let output = render(&metrics)?;
    for sample in [
        "lonewolf_component_domains 2",
        "lonewolf_component_connections 1",
        "lonewolf_component_streams 1",
        "lonewolf_component_received_bytes_total 17",
        "lonewolf_component_sent_bytes_total 23",
        "lonewolf_component_moved_stanzas_total 2",
        "lonewolf_component_bounces_total 3",
        "lonewolf_component_negotiation_duration_seconds_count 11",
        "lonewolf_component_negotiation_duration_seconds_sum 5.5",
    ] {
        assert_sample(&output, sample);
    }
    for listener in 0..2 {
        assert_sample(
            &output,
            &format!("lonewolf_component_connections_accepted_total{{listener=\"{listener}\"}} 1"),
        );
        for mode in ["none", "direct"] {
            assert_sample(
                &output,
                &format!(
                    "lonewolf_component_listener_info{{listener=\"{listener}\",tls_mode=\"{mode}\"}} 1"
                ),
            );
        }
        for reason in [
            "connection_attempts_per_ip",
            "attempt_tracking_full",
            "max_inbound_connections",
        ] {
            assert_sample(
                &output,
                &format!(
                    "lonewolf_component_connections_rejected_total{{listener=\"{listener}\",reason=\"{reason}\"}} 1"
                ),
            );
        }
    }
    for outcome in [
        "success",
        "tls_failure",
        "host_unknown",
        "invalid_namespace",
        "not_authorized",
        "conflict",
        "timeout",
        "shutdown",
        "protocol_error",
        "peer_closed",
        "transport_error",
    ] {
        assert_sample(
            &output,
            &format!("lonewolf_component_authentications_total{{outcome=\"{outcome}\"}} 1"),
        );
    }
    for outcome in [
        "stream_end",
        "shutdown",
        "improper_addressing",
        "invalid_from",
        "invalid_namespace",
        "unsupported_stanza_type",
        "protocol_error",
        "peer_error",
        "transport_error",
        "stalled_write",
        "internal_error",
    ] {
        assert_sample(
            &output,
            &format!("lonewolf_component_streams_closed_total{{outcome=\"{outcome}\"}} 1"),
        );
    }
    for kind in ["message", "presence", "iq"] {
        for direction in ["received", "sent"] {
            assert_sample(
                &output,
                &format!("lonewolf_component_stanzas_{direction}_total{{kind=\"{kind}\"}} 1"),
            );
        }
    }
    for limit in [
        "incoming_stanzas_per_connection",
        "incoming_xml_per_connection",
    ] {
        assert_sample(
            &output,
            &format!("lonewolf_component_rate_limited_total{{limit=\"{limit}\"}} 1"),
        );
    }
    for reason in ["not_connected", "queue_full", "stopped"] {
        assert_sample(
            &output,
            &format!("lonewolf_component_admission_rejections_total{{reason=\"{reason}\"}} 1"),
        );
    }
    for reason in ["not_bounceable", "shutdown", "invalid"] {
        assert_sample(
            &output,
            &format!("lonewolf_component_dropped_stanzas_total{{reason=\"{reason}\"}} 5"),
        );
    }
    for boundary in PHASE_BUCKETS.into_iter().chain([f64::INFINITY]) {
        let label = if boundary.is_infinite() {
            "+Inf".into()
        } else {
            format!("{boundary:?}")
        };
        let count = if boundary < 0.5 { 0 } else { 11 };
        assert_sample(
            &output,
            &format!(
                "lonewolf_component_negotiation_duration_seconds_bucket{{le=\"{label}\"}} {count}"
            ),
        );
    }
    Ok(())
}

#[test]
fn every_family_has_only_its_exact_bounded_labels() -> Result<(), fmt::Error> {
    let metrics = ComponentMetrics::new(2, 2);
    let _guards = record_all(&metrics);
    let output = render(&metrics)?;
    let mut families = BTreeSet::new();
    for line in output.lines().filter(|line| !line.starts_with('#')) {
        let (sample, _) = line.split_once(' ').ok_or(fmt::Error)?;
        let (name, labels) = if let Some((name, rest)) = sample.split_once('{') {
            (name, rest.strip_suffix('}').ok_or(fmt::Error)?)
        } else {
            (sample, "")
        };
        let expected: &[&str] = match name {
            "lonewolf_component_listener_info" => &["listener", "tls_mode"],
            "lonewolf_component_connections_accepted_total" => &["listener"],
            "lonewolf_component_connections_rejected_total" => &["listener", "reason"],
            "lonewolf_component_authentications_total"
            | "lonewolf_component_streams_closed_total" => &["outcome"],
            "lonewolf_component_stanzas_received_total"
            | "lonewolf_component_stanzas_sent_total" => &["kind"],
            "lonewolf_component_rate_limited_total" => &["limit"],
            "lonewolf_component_admission_rejections_total"
            | "lonewolf_component_dropped_stanzas_total" => &["reason"],
            "lonewolf_component_negotiation_duration_seconds_bucket" => &["le"],
            "lonewolf_component_domains"
            | "lonewolf_component_connections"
            | "lonewolf_component_streams"
            | "lonewolf_component_queued_stanzas"
            | "lonewolf_component_queued_bytes"
            | "lonewolf_component_received_bytes_total"
            | "lonewolf_component_sent_bytes_total"
            | "lonewolf_component_moved_stanzas_total"
            | "lonewolf_component_bounces_total"
            | "lonewolf_component_negotiation_duration_seconds_count"
            | "lonewolf_component_negotiation_duration_seconds_sum" => &[],
            _ => panic!("unexpected sample: {line}"),
        };
        let actual: Vec<_> = labels
            .split(',')
            .filter(|label| !label.is_empty())
            .map(|label| label.split_once('=').ok_or(fmt::Error).map(|(key, _)| key))
            .collect::<Result<_, _>>()?;
        assert_eq!(actual, expected, "{line}");
        for label in actual {
            if label == "le" {
                assert_eq!(
                    name,
                    "lonewolf_component_negotiation_duration_seconds_bucket"
                );
            } else {
                assert!(
                    ["listener", "tls_mode", "reason", "outcome", "kind", "limit"].contains(&label)
                );
            }
        }
        families.insert(name);
    }
    assert_eq!(families.len(), 22);
    Ok(())
}

#[test]
fn families_without_samples_are_absent() -> Result<(), fmt::Error> {
    let metrics = ComponentMetrics::new(1, 1);
    metrics.bytes(0, 0);
    metrics.moved(0);
    metrics.bounced(0);
    metrics.dropped(DropReason::Invalid, 0);
    let output = render(&metrics)?;
    for name in [
        "listener_info",
        "connections_accepted",
        "connections_rejected",
        "authentications",
        "negotiation_duration",
        "streams_closed",
        "stanzas_received",
        "stanzas_sent",
        "received_bytes",
        "sent_bytes",
        "rate_limited",
        "admission_rejections",
        "moved_stanzas",
        "bounces",
        "dropped_stanzas",
    ] {
        assert!(
            !output.contains(&format!("lonewolf_component_{name}")),
            "{output}"
        );
    }
    for sample in [
        "lonewolf_component_domains 1",
        "lonewolf_component_connections 0",
        "lonewolf_component_streams 0",
        "lonewolf_component_queued_stanzas 0",
        "lonewolf_component_queued_bytes 0",
    ] {
        assert_sample(&output, sample);
    }
    Ok(())
}

#[test]
fn guards_count_multiple_lifetimes_and_release_each_count() -> Result<(), fmt::Error> {
    let metrics = ComponentMetrics::new(1, 1);
    let first_connection = metrics.connection_opened();
    let second_connection = metrics.connection_opened();
    let first_stream = metrics.stream_opened();
    let second_stream = metrics.stream_opened();
    let first_listener = metrics.listener_bound(0, Transport::Plain);
    let second_listener = metrics.listener_bound(0, Transport::Plain);
    assert_eq!(
        metrics.listeners[0].bound[Transport::Plain as usize].load(Ordering::Relaxed),
        2
    );
    let output = render(&metrics)?;
    assert_sample(&output, "lonewolf_component_connections 2");
    assert_sample(&output, "lonewolf_component_streams 2");
    assert_sample(
        &output,
        "lonewolf_component_listener_info{listener=\"0\",tls_mode=\"none\"} 1",
    );
    drop((first_connection, first_stream, first_listener));
    let output = render(&metrics)?;
    assert_sample(&output, "lonewolf_component_connections 1");
    assert_sample(&output, "lonewolf_component_streams 1");
    assert_sample(
        &output,
        "lonewolf_component_listener_info{listener=\"0\",tls_mode=\"none\"} 1",
    );
    drop((second_connection, second_stream, second_listener));
    let output = render(&metrics)?;
    assert_sample(&output, "lonewolf_component_connections 0");
    assert_sample(&output, "lonewolf_component_streams 0");
    assert!(
        !output.contains("lonewolf_component_listener_info"),
        "{output}"
    );
    Ok(())
}

#[test]
fn cancelling_a_future_releases_all_gauge_guards() -> Result<(), fmt::Error> {
    let metrics = ComponentMetrics::new(1, 1);
    let task_metrics = Arc::clone(&metrics);
    let mut future = Box::pin(async move {
        let _connection = task_metrics.connection_opened();
        let _stream = task_metrics.stream_opened();
        let _listener = task_metrics.listener_bound(0, Transport::DirectTls);
        std::future::pending::<()>().await;
    });
    assert_eq!(
        future.as_mut().poll(&mut Context::from_waker(
            futures_util::task::noop_waker_ref()
        )),
        Poll::Pending
    );
    assert_sample(&render(&metrics)?, "lonewolf_component_connections 1");
    drop(future);
    let output = render(&metrics)?;
    assert_sample(&output, "lonewolf_component_connections 0");
    assert_sample(&output, "lonewolf_component_streams 0");
    assert!(
        !output.contains("lonewolf_component_listener_info"),
        "{output}"
    );
    Ok(())
}

#[derive(Default)]
struct FakeQueues {
    stanzas: AtomicU64,
    bytes: AtomicU64,
    snapshots: AtomicU64,
}

impl QueueStats for FakeQueues {
    fn snapshot(&self) -> QueueSnapshot {
        self.snapshots.fetch_add(1, Ordering::Relaxed);
        QueueSnapshot {
            stanzas: self.stanzas.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

#[test]
fn queue_gauges_read_live_snapshots_without_retaining_the_source() -> Result<(), fmt::Error> {
    let metrics = ComponentMetrics::new(0, 1);
    let output = render(&metrics)?;
    assert_sample(&output, "lonewolf_component_queued_stanzas 0");
    assert_sample(&output, "lonewolf_component_queued_bytes 0");
    let queues = Arc::new(FakeQueues::default());
    let source: Arc<dyn QueueStats> = queues.clone();
    metrics.set_queue_source(Arc::downgrade(&source));
    queues.stanzas.store(3, Ordering::Relaxed);
    queues.bytes.store(17, Ordering::Relaxed);
    let output = render(&metrics)?;
    assert_sample(&output, "lonewolf_component_queued_stanzas 3");
    assert_sample(&output, "lonewolf_component_queued_bytes 17");
    queues.stanzas.store(6, Ordering::Relaxed);
    queues.bytes.store(34, Ordering::Relaxed);
    let output = render(&metrics)?;
    assert_sample(&output, "lonewolf_component_queued_stanzas 6");
    assert_sample(&output, "lonewolf_component_queued_bytes 34");
    assert_eq!(queues.snapshots.load(Ordering::Relaxed), 2);
    drop((source, queues));
    let output = render(&metrics)?;
    assert_sample(&output, "lonewolf_component_queued_stanzas 0");
    assert_sample(&output, "lonewolf_component_queued_bytes 0");
    Ok(())
}

#[test]
fn byte_reader_throttling_records_only_the_xml_rate_limit() -> Result<(), fmt::Error> {
    let metrics = ComponentMetrics::new(0, 1);
    lonewolf_util::rate_limited_reader::RateLimitObserver::on_throttle(metrics.as_ref());
    let output = render(&metrics)?;
    assert_sample(
        &output,
        "lonewolf_component_rate_limited_total{limit=\"incoming_xml_per_connection\"} 1",
    );
    assert!(
        !output.contains("incoming_stanzas_per_connection"),
        "{output}"
    );
    Ok(())
}
