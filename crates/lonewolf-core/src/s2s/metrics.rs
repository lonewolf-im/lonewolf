// SPDX-License-Identifier: Apache-2.0

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
pub(crate) enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    const ALL: [Self; 2] = [Self::Inbound, Self::Outbound];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ConnectionRejection {
    ConnectionAttemptsPerIp,
    AttemptTrackingFull,
    MaxInboundConnections,
    MaxConnectionsPerIp,
    ConnectionTrackingFull,
}

impl ConnectionRejection {
    const ALL: [Self; 5] = [
        Self::ConnectionAttemptsPerIp,
        Self::AttemptTrackingFull,
        Self::MaxInboundConnections,
        Self::MaxConnectionsPerIp,
        Self::ConnectionTrackingFull,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionAttemptsPerIp => "connection_attempts_per_ip",
            Self::AttemptTrackingFull => "attempt_tracking_full",
            Self::MaxInboundConnections => "max_inbound_connections",
            Self::MaxConnectionsPerIp => "max_connections_per_ip",
            Self::ConnectionTrackingFull => "connection_tracking_full",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AuthOutcome {
    Success,
    HostUnknown,
    MissingFrom,
    InvalidFrom,
    NoCertificate,
    CertificateUntrusted,
    CertificateName,
    CertificatePurpose,
    CertificateExpired,
    TlsFailure,
    NoTls,
    TlsRefused,
    ExternalNotOffered,
    InvalidAuthzid,
    InvalidMechanism,
    SaslFailure,
    Unreachable,
    Timeout,
    Protocol,
}

impl AuthOutcome {
    const ALL: [Self; 19] = [
        Self::Success,
        Self::HostUnknown,
        Self::MissingFrom,
        Self::InvalidFrom,
        Self::NoCertificate,
        Self::CertificateUntrusted,
        Self::CertificateName,
        Self::CertificatePurpose,
        Self::CertificateExpired,
        Self::TlsFailure,
        Self::NoTls,
        Self::TlsRefused,
        Self::ExternalNotOffered,
        Self::InvalidAuthzid,
        Self::InvalidMechanism,
        Self::SaslFailure,
        Self::Unreachable,
        Self::Timeout,
        Self::Protocol,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::HostUnknown => "host_unknown",
            Self::MissingFrom => "missing_from",
            Self::InvalidFrom => "invalid_from",
            Self::NoCertificate => "no_certificate",
            Self::CertificateUntrusted => "certificate_untrusted",
            Self::CertificateName => "certificate_name",
            Self::CertificatePurpose => "certificate_purpose",
            Self::CertificateExpired => "certificate_expired",
            Self::TlsFailure => "tls_failure",
            Self::NoTls => "no_tls",
            Self::TlsRefused => "tls_refused",
            Self::ExternalNotOffered => "external_not_offered",
            Self::InvalidAuthzid => "invalid_authzid",
            Self::InvalidMechanism => "invalid_mechanism",
            Self::SaslFailure => "sasl_failure",
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::Protocol => "protocol",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum StreamClose {
    StreamEnd,
    Idle,
    CertificateExpired,
    Shutdown,
    Conflict,
    ImproperAddressing,
    HostUnknown,
    InvalidFrom,
    InvalidNamespace,
    UnsupportedStanzaType,
    NotAuthorized,
    PeerError,
    StalledWrite,
    TransportError,
    InternalError,
}

impl StreamClose {
    const ALL: [Self; 15] = [
        Self::StreamEnd,
        Self::Idle,
        Self::CertificateExpired,
        Self::Shutdown,
        Self::Conflict,
        Self::ImproperAddressing,
        Self::HostUnknown,
        Self::InvalidFrom,
        Self::InvalidNamespace,
        Self::UnsupportedStanzaType,
        Self::NotAuthorized,
        Self::PeerError,
        Self::StalledWrite,
        Self::TransportError,
        Self::InternalError,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::StreamEnd => "stream_end",
            Self::Idle => "idle",
            Self::CertificateExpired => "certificate_expired",
            Self::Shutdown => "shutdown",
            Self::Conflict => "conflict",
            Self::ImproperAddressing => "improper_addressing",
            Self::HostUnknown => "host_unknown",
            Self::InvalidFrom => "invalid_from",
            Self::InvalidNamespace => "invalid_namespace",
            Self::UnsupportedStanzaType => "unsupported_stanza_type",
            Self::NotAuthorized => "not_authorized",
            Self::PeerError => "peer_error",
            Self::StalledWrite => "stalled_write",
            Self::TransportError => "transport_error",
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
pub(crate) enum DnsOutcome {
    Srv,
    Fallback,
    Static,
    Literal,
    NoService,
    NotFound,
    Unavailable,
    InvalidDomain,
}

impl DnsOutcome {
    const ALL: [Self; 8] = [
        Self::Srv,
        Self::Fallback,
        Self::Static,
        Self::Literal,
        Self::NoService,
        Self::NotFound,
        Self::Unavailable,
        Self::InvalidDomain,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Srv => "srv",
            Self::Fallback => "fallback",
            Self::Static => "static",
            Self::Literal => "literal",
            Self::NoService => "no_service",
            Self::NotFound => "not_found",
            Self::Unavailable => "unavailable",
            Self::InvalidDomain => "invalid_domain",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum LinkState {
    Connecting,
    Ready,
    Backoff,
}

impl LinkState {
    const ALL: [Self; 3] = [Self::Connecting, Self::Ready, Self::Backoff];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Ready => "ready",
            Self::Backoff => "backoff",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AdmissionReason {
    QueueFull,
    LinkLimit,
    Backoff,
    Unsupported,
    Stopped,
}

impl AdmissionReason {
    const ALL: [Self; 5] = [
        Self::QueueFull,
        Self::LinkLimit,
        Self::Backoff,
        Self::Unsupported,
        Self::Stopped,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::LinkLimit => "link_limit",
            Self::Backoff => "backoff",
            Self::Unsupported => "unsupported",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum BounceCondition {
    RemoteServerNotFound,
    RemoteServerTimeout,
    ResourceConstraint,
}

impl BounceCondition {
    const ALL: [Self; 3] = [
        Self::RemoteServerNotFound,
        Self::RemoteServerTimeout,
        Self::ResourceConstraint,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RemoteServerNotFound => "remote_server_not_found",
            Self::RemoteServerTimeout => "remote_server_timeout",
            Self::ResourceConstraint => "resource_constraint",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum DropReason {
    Shutdown,
    ConnectionLost,
    NotBounceable,
    InternalError,
}

impl DropReason {
    const ALL: [Self; 4] = [
        Self::Shutdown,
        Self::ConnectionLost,
        Self::NotBounceable,
        Self::InternalError,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Shutdown => "shutdown",
            Self::ConnectionLost => "connection_lost",
            Self::NotBounceable => "not_bounceable",
            Self::InternalError => "internal_error",
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
    accepted: AtomicU64,
    rejected: [AtomicU64; ConnectionRejection::ALL.len()],
}

#[derive(Default)]
pub(crate) struct LinkSnapshot {
    pub(crate) connecting: u64,
    pub(crate) ready: u64,
    pub(crate) backoff: u64,
    pub(crate) queued_stanzas: u64,
    pub(crate) queued_bytes: u64,
}

pub(crate) trait LinkStats: Send + Sync {
    fn snapshot(&self) -> LinkSnapshot;
}

pub(crate) struct S2sMetrics {
    connections: [AtomicU64; Direction::ALL.len()],
    listeners: Box<[ListenerCounters]>,
    authentications: [[AtomicU64; AuthOutcome::ALL.len()]; Direction::ALL.len()],
    negotiation_duration: [Histogram; Direction::ALL.len()],
    streams: [AtomicU64; Direction::ALL.len()],
    streams_closed: [[AtomicU64; StreamClose::ALL.len()]; Direction::ALL.len()],
    stanzas_received: [AtomicU64; KINDS.len()],
    stanzas_sent: [AtomicU64; KINDS.len()],
    received_bytes: [AtomicU64; Direction::ALL.len()],
    sent_bytes: [AtomicU64; Direction::ALL.len()],
    rate_limited: [AtomicU64; InboundLimit::ALL.len()],
    dns: [AtomicU64; DnsOutcome::ALL.len()],
    admission_rejected: [AtomicU64; AdmissionReason::ALL.len()],
    bounces: [AtomicU64; BounceCondition::ALL.len()],
    dropped: [AtomicU64; DropReason::ALL.len()],
    link_source: PlRwLock<Option<Weak<dyn LinkStats>>>,
}

impl S2sMetrics {
    pub(crate) fn new(listener_count: usize) -> Arc<Self> {
        Arc::new(Self {
            connections: Default::default(),
            listeners: (0..listener_count)
                .map(|_| ListenerCounters::default())
                .collect(),
            authentications: Default::default(),
            negotiation_duration: std::array::from_fn(|_| Histogram::new(PHASE_BUCKETS)),
            streams: Default::default(),
            streams_closed: Default::default(),
            stanzas_received: Default::default(),
            stanzas_sent: Default::default(),
            received_bytes: Default::default(),
            sent_bytes: Default::default(),
            rate_limited: Default::default(),
            dns: Default::default(),
            admission_rejected: Default::default(),
            bounces: Default::default(),
            dropped: Default::default(),
            link_source: PlRwLock::new(None),
        })
    }

    pub(crate) fn register(self: &Arc<Self>, registry: &mut Registry) {
        registry.register_collector(Box::new(S2sCollector(Arc::clone(self))));
    }

    pub(crate) fn connection_opened(self: &Arc<Self>, direction: Direction) -> ConnectionGauge {
        self.connections[direction as usize].fetch_add(1, Ordering::Relaxed);
        ConnectionGauge {
            metrics: Arc::clone(self),
            direction,
            kind: GaugeKind::Connection,
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

    pub(crate) fn authentication(
        &self,
        direction: Direction,
        outcome: AuthOutcome,
        elapsed: Duration,
    ) {
        self.authentications[direction as usize][outcome as usize].fetch_add(1, Ordering::Relaxed);
        self.negotiation_duration[direction as usize].observe(elapsed.as_secs_f64());
    }

    pub(crate) fn stream_opened(self: &Arc<Self>, direction: Direction) -> ConnectionGauge {
        self.streams[direction as usize].fetch_add(1, Ordering::Relaxed);
        ConnectionGauge {
            metrics: Arc::clone(self),
            direction,
            kind: GaugeKind::Stream,
        }
    }

    pub(crate) fn stream_closed(&self, direction: Direction, outcome: StreamClose) {
        self.streams_closed[direction as usize][outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn stanza_received(&self, kind: StanzaKind) {
        self.stanzas_received[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn stanza_sent(&self, kind: StanzaKind) {
        self.stanzas_sent[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bytes(&self, direction: Direction, received: u64, sent: u64) {
        self.received_bytes[direction as usize].fetch_add(received, Ordering::Relaxed);
        self.sent_bytes[direction as usize].fetch_add(sent, Ordering::Relaxed);
    }

    pub(crate) fn rate_limited(&self, limit: InboundLimit) {
        self.rate_limited[limit as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dns(&self, outcome: DnsOutcome) {
        self.dns[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn admission_rejected(&self, reason: AdmissionReason) {
        self.admission_rejected[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bounced(&self, condition: BounceCondition) {
        self.bounces[condition as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dropped(&self, reason: DropReason, count: u64) {
        self.dropped[reason as usize].fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn set_link_source(&self, source: Weak<dyn LinkStats>) {
        *self.link_source.write() = Some(source);
    }
}

enum GaugeKind {
    Connection,
    Stream,
}

#[must_use]
pub(crate) struct ConnectionGauge {
    metrics: Arc<S2sMetrics>,
    direction: Direction,
    kind: GaugeKind,
}

impl Drop for ConnectionGauge {
    fn drop(&mut self) {
        let counters = match self.kind {
            GaugeKind::Connection => &self.metrics.connections,
            GaugeKind::Stream => &self.metrics.streams,
        };
        counters[self.direction as usize].fetch_sub(1, Ordering::Relaxed);
    }
}

struct S2sCollector(Arc<S2sMetrics>);

impl fmt::Debug for S2sCollector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S2sCollector")
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

impl Collector for S2sCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        let metrics = &self.0;
        for (name, help, counters) in [
            (
                "s2s_connections",
                "Open S2S TCP connections.",
                &metrics.connections,
            ),
            (
                "s2s_streams",
                "Authenticated S2S streams.",
                &metrics.streams,
            ),
        ] {
            let mut family = encoder.encode_descriptor(name, help, None, MetricType::Gauge)?;
            for direction in Direction::ALL {
                ConstGauge::new(counters[direction as usize].load(Ordering::Relaxed))
                    .encode(family.encode_family(&[("direction", direction.as_str())])?)?;
            }
        }
        encode_counter(
            &mut encoder,
            "s2s_connections_accepted",
            "Inbound sockets admitted.",
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
            "s2s_connections_rejected",
            "Inbound sockets refused by admission.",
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
            "s2s_authentications",
            "S2S negotiation results.",
            Direction::ALL.into_iter().flat_map(|direction| {
                AuthOutcome::ALL.map(|outcome| {
                    (
                        [
                            ("direction", direction.as_str()),
                            ("outcome", outcome.as_str()),
                        ],
                        metrics.authentications[direction as usize][outcome as usize]
                            .load(Ordering::Relaxed),
                    )
                })
            }),
        )?;
        let mut family = encoder.encode_descriptor(
            "s2s_negotiation_duration",
            "Active S2S establishment time, excluding DNS and failure cleanup.",
            Some(&Unit::Seconds),
            MetricType::Histogram,
        )?;
        for direction in Direction::ALL {
            metrics.negotiation_duration[direction as usize]
                .encode(family.encode_family(&[("direction", direction.as_str())])?)?;
        }
        encode_counter(
            &mut encoder,
            "s2s_streams_closed",
            "Authenticated S2S streams by close cause.",
            Direction::ALL.into_iter().flat_map(|direction| {
                StreamClose::ALL.map(|outcome| {
                    (
                        [
                            ("direction", direction.as_str()),
                            ("outcome", outcome.as_str()),
                        ],
                        metrics.streams_closed[direction as usize][outcome as usize]
                            .load(Ordering::Relaxed),
                    )
                })
            }),
        )?;
        for (name, help, counters) in [
            (
                "s2s_stanzas_received",
                "Stanzas accepted from inbound streams after address validation.",
                &metrics.stanzas_received,
            ),
            (
                "s2s_stanzas_sent",
                "Stanzas written to outbound streams.",
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
        for (name, help, counters) in [
            (
                "s2s_received_bytes",
                "XML bytes received after TLS.",
                &metrics.received_bytes,
            ),
            (
                "s2s_sent_bytes",
                "XML bytes sent after TLS.",
                &metrics.sent_bytes,
            ),
        ] {
            encode_counter(
                &mut encoder,
                name,
                help,
                Direction::ALL.map(|direction| {
                    (
                        [("direction", direction.as_str())],
                        counters[direction as usize].load(Ordering::Relaxed),
                    )
                }),
            )?;
        }
        encode_counter(
            &mut encoder,
            "s2s_rate_limited",
            "Inbound waits caused by traffic limits.",
            InboundLimit::ALL.map(|value| {
                (
                    [("limit", value.as_str())],
                    metrics.rate_limited[value as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        encode_counter(
            &mut encoder,
            "s2s_dns_resolutions",
            "Outbound endpoint resolution results.",
            DnsOutcome::ALL.map(|value| {
                (
                    [("outcome", value.as_str())],
                    metrics.dns[value as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        encode_counter(
            &mut encoder,
            "s2s_admission_rejections",
            "Remote routing admissions refused synchronously.",
            AdmissionReason::ALL.map(|value| {
                (
                    [("reason", value.as_str())],
                    metrics.admission_rejected[value as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        encode_counter(
            &mut encoder,
            "s2s_bounces",
            "Error replies generated for undeliverable remote stanzas.",
            BounceCondition::ALL.map(|value| {
                (
                    [("condition", value.as_str())],
                    metrics.bounces[value as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        encode_counter(
            &mut encoder,
            "s2s_dropped_stanzas",
            "Stanzas discarded without a bounce.",
            DropReason::ALL.map(|value| {
                (
                    [("reason", value.as_str())],
                    metrics.dropped[value as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        let source = metrics.link_source.read().as_ref().and_then(Weak::upgrade);
        let snapshot = source.map_or_else(LinkSnapshot::default, |source| source.snapshot());
        let mut family = encoder.encode_descriptor(
            "s2s_outbound_links",
            "Outbound link entries by state.",
            None,
            MetricType::Gauge,
        )?;
        for state in LinkState::ALL {
            let value = match state {
                LinkState::Connecting => snapshot.connecting,
                LinkState::Ready => snapshot.ready,
                LinkState::Backoff => snapshot.backoff,
            };
            ConstGauge::new(value).encode(family.encode_family(&[("state", state.as_str())])?)?;
        }
        for (name, help, value) in [
            (
                "s2s_outbound_queued_stanzas",
                "Stanzas queued across outbound links.",
                snapshot.queued_stanzas,
            ),
            (
                "s2s_outbound_queued_bytes",
                "XML bytes queued across outbound links.",
                snapshot.queued_bytes,
            ),
        ] {
            ConstGauge::new(value).encode(encoder.encode_descriptor(
                name,
                help,
                None,
                MetricType::Gauge,
            )?)?;
        }
        Ok(())
    }
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

impl lonewolf_util::rate_limited_reader::RateLimitObserver for S2sMetrics {
    fn on_throttle(&self) {
        self.rate_limited(InboundLimit::IncomingXmlPerConnection);
    }
}
