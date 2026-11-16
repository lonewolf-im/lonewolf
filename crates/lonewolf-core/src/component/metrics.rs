// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use lonewolf_xmpp::stanza::StanzaKind;
use parking_lot::RwLock as PlRwLock;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::{
    MetricType, counter::ConstCounter, gauge::ConstGauge, histogram::Histogram,
};
use prometheus_client::registry::{Registry, Unit};

use crate::c2s::PHASE_BUCKETS;

#[derive(Clone, Copy)]
pub(crate) enum Transport {
    Plain,
    DirectTls,
}

impl Transport {
    const ALL: [Self; 2] = [Self::Plain, Self::DirectTls];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "none",
            Self::DirectTls => "direct",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ConnectionRejection {
    ConnectionAttemptsPerIp,
    AttemptTrackingFull,
    MaxInboundConnections,
}

impl ConnectionRejection {
    const ALL: [Self; 3] = [
        Self::ConnectionAttemptsPerIp,
        Self::AttemptTrackingFull,
        Self::MaxInboundConnections,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionAttemptsPerIp => "connection_attempts_per_ip",
            Self::AttemptTrackingFull => "attempt_tracking_full",
            Self::MaxInboundConnections => "max_inbound_connections",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AuthOutcome {
    Success,
    TlsFailure,
    HostUnknown,
    InvalidNamespace,
    NotAuthorized,
    Conflict,
    Timeout,
    Shutdown,
    ProtocolError,
    PeerClosed,
    TransportError,
}

impl AuthOutcome {
    const ALL: [Self; 11] = [
        Self::Success,
        Self::TlsFailure,
        Self::HostUnknown,
        Self::InvalidNamespace,
        Self::NotAuthorized,
        Self::Conflict,
        Self::Timeout,
        Self::Shutdown,
        Self::ProtocolError,
        Self::PeerClosed,
        Self::TransportError,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::TlsFailure => "tls_failure",
            Self::HostUnknown => "host_unknown",
            Self::InvalidNamespace => "invalid_namespace",
            Self::NotAuthorized => "not_authorized",
            Self::Conflict => "conflict",
            Self::Timeout => "timeout",
            Self::Shutdown => "shutdown",
            Self::ProtocolError => "protocol_error",
            Self::PeerClosed => "peer_closed",
            Self::TransportError => "transport_error",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum StreamClose {
    StreamEnd,
    Shutdown,
    ImproperAddressing,
    InvalidFrom,
    InvalidNamespace,
    UnsupportedStanzaType,
    ProtocolError,
    PeerError,
    TransportError,
    StalledWrite,
    InternalError,
}

impl StreamClose {
    const ALL: [Self; 11] = [
        Self::StreamEnd,
        Self::Shutdown,
        Self::ImproperAddressing,
        Self::InvalidFrom,
        Self::InvalidNamespace,
        Self::UnsupportedStanzaType,
        Self::ProtocolError,
        Self::PeerError,
        Self::TransportError,
        Self::StalledWrite,
        Self::InternalError,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::StreamEnd => "stream_end",
            Self::Shutdown => "shutdown",
            Self::ImproperAddressing => "improper_addressing",
            Self::InvalidFrom => "invalid_from",
            Self::InvalidNamespace => "invalid_namespace",
            Self::UnsupportedStanzaType => "unsupported_stanza_type",
            Self::ProtocolError => "protocol_error",
            Self::PeerError => "peer_error",
            Self::TransportError => "transport_error",
            Self::StalledWrite => "stalled_write",
            Self::InternalError => "internal_error",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum InboundLimit {
    IncomingStanzasPerConnection,
    IncomingXmlPerConnection,
}

impl InboundLimit {
    const ALL: [Self; 2] = [
        Self::IncomingStanzasPerConnection,
        Self::IncomingXmlPerConnection,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::IncomingStanzasPerConnection => "incoming_stanzas_per_connection",
            Self::IncomingXmlPerConnection => "incoming_xml_per_connection",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AdmissionReason {
    NotConnected,
    QueueFull,
    Stopped,
}

impl AdmissionReason {
    const ALL: [Self; 3] = [Self::NotConnected, Self::QueueFull, Self::Stopped];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NotConnected => "not_connected",
            Self::QueueFull => "queue_full",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum DropReason {
    NotBounceable,
    Shutdown,
    Invalid,
}

impl DropReason {
    const ALL: [Self; 3] = [Self::NotBounceable, Self::Shutdown, Self::Invalid];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NotBounceable => "not_bounceable",
            Self::Shutdown => "shutdown",
            Self::Invalid => "invalid",
        }
    }
}

const KINDS: [StanzaKind; 3] = [StanzaKind::Message, StanzaKind::Presence, StanzaKind::Iq];

fn kind_index(kind: StanzaKind) -> usize {
    match kind {
        StanzaKind::Message => 0,
        StanzaKind::Presence => 1,
        StanzaKind::Iq => 2,
    }
}

#[derive(Default)]
struct ListenerCounters {
    bound: [AtomicU64; Transport::ALL.len()],
    accepted: AtomicU64,
    rejected: [AtomicU64; ConnectionRejection::ALL.len()],
}

#[derive(Default)]
pub(crate) struct QueueSnapshot {
    pub(crate) stanzas: u64,
    pub(crate) bytes: u64,
}

pub(crate) trait QueueStats: Send + Sync {
    fn snapshot(&self) -> QueueSnapshot;
}

pub(crate) struct ComponentMetrics {
    domains: u64,
    listeners: Box<[ListenerCounters]>,
    connections: AtomicU64,
    authentications: [AtomicU64; AuthOutcome::ALL.len()],
    negotiation_duration: Histogram,
    streams: AtomicU64,
    streams_closed: [AtomicU64; StreamClose::ALL.len()],
    stanzas_received: [AtomicU64; KINDS.len()],
    stanzas_sent: [AtomicU64; KINDS.len()],
    received_bytes: AtomicU64,
    sent_bytes: AtomicU64,
    rate_limited: [AtomicU64; InboundLimit::ALL.len()],
    admission_rejected: [AtomicU64; AdmissionReason::ALL.len()],
    moved: AtomicU64,
    bounces: AtomicU64,
    dropped: [AtomicU64; DropReason::ALL.len()],
    queue_source: PlRwLock<Option<Weak<dyn QueueStats>>>,
}

impl ComponentMetrics {
    #[cfg(feature = "test-support")]
    pub(crate) fn shutdown_state(&self) -> crate::test_support::ComponentShutdownState {
        crate::test_support::ComponentShutdownState {
            connections: self.connections.load(Ordering::Acquire),
            streams: self.streams.load(Ordering::Acquire),
            authentication_success: self.authentications[AuthOutcome::Success as usize]
                .load(Ordering::Relaxed),
            authentication_shutdown: self.authentications[AuthOutcome::Shutdown as usize]
                .load(Ordering::Relaxed),
            authentication_total: self
                .authentications
                .iter()
                .map(|counter| counter.load(Ordering::Relaxed))
                .sum(),
            streams_closed_shutdown: self.streams_closed[StreamClose::Shutdown as usize]
                .load(Ordering::Relaxed),
            streams_closed_total: self
                .streams_closed
                .iter()
                .map(|counter| counter.load(Ordering::Relaxed))
                .sum(),
        }
    }

    pub(crate) fn new(listener_count: usize, domain_count: usize) -> Arc<Self> {
        Arc::new(Self {
            domains: domain_count as u64,
            listeners: (0..listener_count)
                .map(|_| ListenerCounters::default())
                .collect(),
            connections: AtomicU64::new(0),
            authentications: Default::default(),
            negotiation_duration: Histogram::new(PHASE_BUCKETS),
            streams: AtomicU64::new(0),
            streams_closed: Default::default(),
            stanzas_received: Default::default(),
            stanzas_sent: Default::default(),
            received_bytes: AtomicU64::new(0),
            sent_bytes: AtomicU64::new(0),
            rate_limited: Default::default(),
            admission_rejected: Default::default(),
            moved: AtomicU64::new(0),
            bounces: AtomicU64::new(0),
            dropped: Default::default(),
            queue_source: PlRwLock::new(None),
        })
    }

    pub(crate) fn register(self: &Arc<Self>, registry: &mut Registry) {
        registry.register_collector(Box::new(ComponentCollector(Arc::clone(self))));
    }

    pub(crate) fn listener_bound(
        self: &Arc<Self>,
        listener: usize,
        transport: Transport,
    ) -> GaugeGuard {
        self.listeners[listener].bound[transport as usize].fetch_add(1, Ordering::Relaxed);
        GaugeGuard {
            metrics: Arc::clone(self),
            kind: GaugeKind::Listener {
                listener,
                transport,
            },
        }
    }

    pub(crate) fn connection_accepted(&self, listener: usize) {
        self.listeners[listener]
            .accepted
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn connection_rejected(&self, listener: usize, reason: ConnectionRejection) {
        self.listeners[listener].rejected[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn connection_opened(self: &Arc<Self>) -> GaugeGuard {
        self.connections.fetch_add(1, Ordering::Relaxed);
        GaugeGuard {
            metrics: Arc::clone(self),
            kind: GaugeKind::Connection,
        }
    }

    pub(crate) fn authentication(&self, outcome: AuthOutcome, elapsed: Duration) {
        self.authentications[outcome as usize].fetch_add(1, Ordering::Relaxed);
        self.negotiation_duration.observe(elapsed.as_secs_f64());
    }

    pub(crate) fn stream_opened(self: &Arc<Self>) -> GaugeGuard {
        self.streams.fetch_add(1, Ordering::Relaxed);
        GaugeGuard {
            metrics: Arc::clone(self),
            kind: GaugeKind::Stream,
        }
    }

    pub(crate) fn stream_closed(&self, outcome: StreamClose) {
        self.streams_closed[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn stanza_received(&self, kind: StanzaKind) {
        self.stanzas_received[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn stanza_sent(&self, kind: StanzaKind) {
        self.stanzas_sent[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bytes(&self, received: u64, sent: u64) {
        self.received_bytes.fetch_add(received, Ordering::Relaxed);
        self.sent_bytes.fetch_add(sent, Ordering::Relaxed);
    }

    pub(crate) fn rate_limited(&self, limit: InboundLimit) {
        self.rate_limited[limit as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn admission_rejected(&self, reason: AdmissionReason) {
        self.admission_rejected[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn moved(&self, count: u64) {
        self.moved.fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn bounced(&self, count: u64) {
        self.bounces.fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn dropped(&self, reason: DropReason, count: u64) {
        self.dropped[reason as usize].fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn set_queue_source(&self, source: Weak<dyn QueueStats>) {
        *self.queue_source.write() = Some(source);
    }
}

enum GaugeKind {
    Listener {
        listener: usize,
        transport: Transport,
    },
    Connection,
    Stream,
}

#[must_use]
pub(crate) struct GaugeGuard {
    metrics: Arc<ComponentMetrics>,
    kind: GaugeKind,
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        let counter = match self.kind {
            GaugeKind::Listener {
                listener,
                transport,
            } => &self.metrics.listeners[listener].bound[transport as usize],
            GaugeKind::Connection => &self.metrics.connections,
            GaugeKind::Stream => &self.metrics.streams,
        };
        counter.fetch_sub(1, Ordering::Relaxed);
    }
}

impl lonewolf_util::rate_limited_reader::RateLimitObserver for ComponentMetrics {
    fn on_throttle(&self) {
        self.rate_limited(InboundLimit::IncomingXmlPerConnection);
    }
}

struct ComponentCollector(Arc<ComponentMetrics>);

impl fmt::Debug for ComponentCollector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentCollector")
            .finish_non_exhaustive()
    }
}

fn encode_counter<L: EncodeLabelSet>(
    encoder: &mut DescriptorEncoder<'_>,
    name: &str,
    help: &str,
    samples: impl IntoIterator<Item = (L, u64)>,
) -> Result<(), fmt::Error> {
    let mut samples = samples
        .into_iter()
        .filter(|(_, value)| *value != 0)
        .peekable();
    if samples.peek().is_none() {
        return Ok(());
    }
    let mut family = encoder.encode_descriptor(name, help, None, MetricType::Counter)?;
    for (labels, value) in samples {
        ConstCounter::new(value).encode(family.encode_family(&labels)?)?;
    }
    Ok(())
}

impl Collector for ComponentCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        let metrics = &self.0;
        let mut bound = metrics
            .listeners
            .iter()
            .enumerate()
            .flat_map(|(listener, counters)| {
                Transport::ALL.into_iter().filter_map(move |transport| {
                    (counters.bound[transport as usize].load(Ordering::Relaxed) != 0).then_some(
                        ListenerInfoLabels {
                            listener,
                            tls_mode: transport.as_str(),
                        },
                    )
                })
            })
            .peekable();
        if bound.peek().is_some() {
            let mut family = encoder.encode_descriptor(
                "component_listener_info",
                "Bound component listener transport.",
                None,
                MetricType::Gauge,
            )?;
            for labels in bound {
                ConstGauge::new(1u64).encode(family.encode_family(&labels)?)?;
            }
        }
        let source = metrics.queue_source.read().as_ref().and_then(Weak::upgrade);
        let snapshot = source.map_or_else(QueueSnapshot::default, |source| source.snapshot());
        for (name, help, value) in [
            (
                "component_domains",
                "Configured component domains.",
                metrics.domains,
            ),
            (
                "component_connections",
                "Open component TCP connections, including negotiation.",
                metrics.connections.load(Ordering::Relaxed),
            ),
            (
                "component_streams",
                "Authenticated component streams across all domains.",
                metrics.streams.load(Ordering::Relaxed),
            ),
            (
                "component_queued_stanzas",
                "Stanzas queued across all component connections.",
                snapshot.stanzas,
            ),
            (
                "component_queued_bytes",
                "XML bytes queued across all component connections.",
                snapshot.bytes,
            ),
        ] {
            ConstGauge::new(value).encode(encoder.encode_descriptor(
                name,
                help,
                None,
                MetricType::Gauge,
            )?)?;
        }
        encode_counter(
            &mut encoder,
            "component_connections_accepted",
            "Component sockets admitted by the listener.",
            metrics
                .listeners
                .iter()
                .enumerate()
                .map(|(listener, counters)| {
                    (
                        ListenerLabels { listener },
                        counters.accepted.load(Ordering::Relaxed),
                    )
                }),
        )?;
        encode_counter(
            &mut encoder,
            "component_connections_rejected",
            "Component sockets refused by admission.",
            metrics
                .listeners
                .iter()
                .enumerate()
                .flat_map(|(listener, counters)| {
                    ConnectionRejection::ALL.map(|reason| {
                        (
                            RejectedLabels {
                                listener,
                                reason: reason.as_str(),
                            },
                            counters.rejected[reason as usize].load(Ordering::Relaxed),
                        )
                    })
                }),
        )?;
        encode_counter(
            &mut encoder,
            "component_authentications",
            "Component negotiation results, once per admitted connection.",
            AuthOutcome::ALL.map(|outcome| {
                (
                    [("outcome", outcome.as_str())],
                    metrics.authentications[outcome as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        if metrics
            .authentications
            .iter()
            .any(|counter| counter.load(Ordering::Relaxed) != 0)
        {
            metrics
                .negotiation_duration
                .encode(encoder.encode_descriptor(
                    "component_negotiation_duration",
                    "Time from component socket admission to the negotiation result.",
                    Some(&Unit::Seconds),
                    MetricType::Histogram,
                )?)?;
        }
        encode_counter(
            &mut encoder,
            "component_streams_closed",
            "Authenticated component streams by close cause.",
            StreamClose::ALL.map(|outcome| {
                (
                    [("outcome", outcome.as_str())],
                    metrics.streams_closed[outcome as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        for (name, help, counters) in [
            (
                "component_stanzas_received",
                "Validated stanzas accepted from components.",
                &metrics.stanzas_received,
            ),
            (
                "component_stanzas_sent",
                "Stanzas written to components.",
                &metrics.stanzas_sent,
            ),
        ] {
            encode_counter(
                &mut encoder,
                name,
                help,
                KINDS.map(|kind| {
                    (
                        [("kind", kind.as_str())],
                        counters[kind_index(kind)].load(Ordering::Relaxed),
                    )
                }),
            )?;
        }
        for (name, help, counter) in [
            (
                "component_received_bytes",
                "TCP socket bytes received from component connections.",
                &metrics.received_bytes,
            ),
            (
                "component_sent_bytes",
                "TCP socket bytes sent to component connections.",
                &metrics.sent_bytes,
            ),
            (
                "component_moved_stanzas",
                "Queued stanzas moved to another connection of the same domain after a close.",
                &metrics.moved,
            ),
            (
                "component_bounces",
                "Error replies for component stanzas still queued at disconnect.",
                &metrics.bounces,
            ),
        ] {
            let value = counter.load(Ordering::Relaxed);
            if value != 0 {
                ConstCounter::new(value).encode(encoder.encode_descriptor(
                    name,
                    help,
                    None,
                    MetricType::Counter,
                )?)?;
            }
        }
        encode_counter(
            &mut encoder,
            "component_rate_limited",
            "Component read waits caused by rate limits.",
            InboundLimit::ALL.map(|limit| {
                (
                    [("limit", limit.as_str())],
                    metrics.rate_limited[limit as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        encode_counter(
            &mut encoder,
            "component_admission_rejections",
            "Stanzas refused by the selected component connection queue.",
            AdmissionReason::ALL.map(|reason| {
                (
                    [("reason", reason.as_str())],
                    metrics.admission_rejected[reason as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        encode_counter(
            &mut encoder,
            "component_dropped_stanzas",
            "Component stanzas discarded without a reply.",
            DropReason::ALL.map(|reason| {
                (
                    [("reason", reason.as_str())],
                    metrics.dropped[reason as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        Ok(())
    }
}

#[derive(EncodeLabelSet)]
struct ListenerInfoLabels {
    listener: usize,
    tls_mode: &'static str,
}

#[derive(EncodeLabelSet)]
struct ListenerLabels {
    listener: usize,
}

#[derive(EncodeLabelSet)]
struct RejectedLabels {
    listener: usize,
    reason: &'static str,
}

#[cfg(test)]
mod tests;
