// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use lonewolf_xmpp::stanza::StanzaKind;
use parking_lot::RwLock as PlRwLock;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::{
    MetricType, counter::ConstCounter, gauge::ConstGauge, histogram::Histogram,
};
use prometheus_client::registry::{Registry, Unit};

use crate::c2s::PHASE_BUCKETS;
use crate::config::TlsMode;
use crate::hosts::revocation::CrlLoadError;

use super::revocation::{CheckPhase, RevocationSource, RevocationStatus, RevocationVerdict};

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
    CertificateRevoked,
    RevocationUnknown,
    RevocationStale,
    RevocationUnavailable,
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
    const ALL: [Self; 23] = [
        Self::Success,
        Self::HostUnknown,
        Self::MissingFrom,
        Self::InvalidFrom,
        Self::NoCertificate,
        Self::CertificateUntrusted,
        Self::CertificateName,
        Self::CertificatePurpose,
        Self::CertificateExpired,
        Self::CertificateRevoked,
        Self::RevocationUnknown,
        Self::RevocationStale,
        Self::RevocationUnavailable,
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
            Self::CertificateRevoked => "certificate_revoked",
            Self::RevocationUnknown => "revocation_unknown",
            Self::RevocationStale => "revocation_stale",
            Self::RevocationUnavailable => "revocation_unavailable",
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
    CertificateRevoked,
    RevocationUnknown,
    RevocationStale,
    RevocationUnavailable,
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
    ProtocolError,
}

impl StreamClose {
    pub(crate) fn certificate_invalid(self) -> bool {
        matches!(
            self,
            Self::CertificateExpired
                | Self::CertificateRevoked
                | Self::RevocationUnknown
                | Self::RevocationStale
                | Self::RevocationUnavailable
        )
    }

    const ALL: [Self; 20] = [
        Self::StreamEnd,
        Self::Idle,
        Self::CertificateExpired,
        Self::CertificateRevoked,
        Self::RevocationUnknown,
        Self::RevocationStale,
        Self::RevocationUnavailable,
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
        Self::ProtocolError,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::StreamEnd => "stream_end",
            Self::Idle => "idle",
            Self::CertificateExpired => "certificate_expired",
            Self::CertificateRevoked => "certificate_revoked",
            Self::RevocationUnknown => "revocation_unknown",
            Self::RevocationStale => "revocation_stale",
            Self::RevocationUnavailable => "revocation_unavailable",
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
            Self::ProtocolError => "protocol_error",
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
    PolicyViolation,
}

impl BounceCondition {
    const ALL: [Self; 4] = [
        Self::RemoteServerNotFound,
        Self::RemoteServerTimeout,
        Self::ResourceConstraint,
        Self::PolicyViolation,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RemoteServerNotFound => "remote_server_not_found",
            Self::RemoteServerTimeout => "remote_server_timeout",
            Self::ResourceConstraint => "resource_constraint",
            Self::PolicyViolation => "policy_violation",
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BidiOutcome {
    Enabled,
    NotOffered,
    NotRequested,
}

impl BidiOutcome {
    const ALL: [Self; 3] = [Self::Enabled, Self::NotOffered, Self::NotRequested];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::NotOffered => "not_offered",
            Self::NotRequested => "not_requested",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BidiHandoff {
    InboundStream,
    DialedLink,
}

impl BidiHandoff {
    const ALL: [Self; 2] = [Self::InboundStream, Self::DialedLink];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InboundStream => "inbound_stream",
            Self::DialedLink => "dialed_link",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CrlFetchOutcome {
    Success,
    DnsFailed,
    BlockedAddress,
    ConnectFailed,
    Timeout,
    HttpStatus,
    TooLarge,
    Invalid,
    Stale,
    Rollback,
}

impl CrlFetchOutcome {
    pub(crate) const ALL: [Self; 10] = [
        Self::Success,
        Self::DnsFailed,
        Self::BlockedAddress,
        Self::ConnectFailed,
        Self::Timeout,
        Self::HttpStatus,
        Self::TooLarge,
        Self::Invalid,
        Self::Stale,
        Self::Rollback,
    ];
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::DnsFailed => "dns_failed",
            Self::BlockedAddress => "blocked_address",
            Self::ConnectFailed => "connect_failed",
            Self::Timeout => "timeout",
            Self::HttpStatus => "http_status",
            Self::TooLarge => "too_large",
            Self::Invalid => "invalid",
            Self::Stale => "stale",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CrlEviction {
    Unused,
    Capacity,
    StaleExpired,
}
impl CrlEviction {
    pub(crate) const ALL: [Self; 3] = [Self::Unused, Self::Capacity, Self::StaleExpired];
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Unused => "unused",
            Self::Capacity => "capacity",
            Self::StaleExpired => "stale_expired",
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
    bound: [AtomicU64; TlsMode::ALL.len()],
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
    transport_connections: [[AtomicU64; TlsMode::ALL.len()]; Direction::ALL.len()],
    transport_attempts:
        [[[AtomicU64; AuthOutcome::ALL.len() + 1]; TlsMode::ALL.len()]; Direction::ALL.len()],
    connections: [AtomicU64; Direction::ALL.len()],
    listeners: Box<[ListenerCounters]>,
    authentications: [[AtomicU64; AuthOutcome::ALL.len()]; Direction::ALL.len()],
    revocation_checks: [[[[AtomicU64; 15]; 2]; 2]; 2],
    negotiation_duration: [Histogram; Direction::ALL.len()],
    streams: [AtomicU64; Direction::ALL.len()],
    streams_closed: [[AtomicU64; StreamClose::ALL.len()]; Direction::ALL.len()],
    stanzas_received: [AtomicU64; KINDS.len()],
    stanzas_sent: [AtomicU64; KINDS.len()],
    #[cfg(feature = "test-support")]
    transport_ends: [AtomicU64; Direction::ALL.len()],
    received_bytes: [AtomicU64; Direction::ALL.len()],
    sent_bytes: [AtomicU64; Direction::ALL.len()],
    rate_limited: [AtomicU64; InboundLimit::ALL.len()],
    dns: [AtomicU64; DnsOutcome::ALL.len()],
    admission_rejected: [AtomicU64; AdmissionReason::ALL.len()],
    peer_size_rejections: AtomicU64,
    bounces: [AtomicU64; BounceCondition::ALL.len()],
    dropped: [AtomicU64; DropReason::ALL.len()],
    bidi_negotiations: [[AtomicU64; BidiOutcome::ALL.len()]; Direction::ALL.len()],
    bidi_streams: [AtomicU64; Direction::ALL.len()],
    bidi_stanzas_sent: [AtomicU64; KINDS.len()],
    bidi_stanzas_received: [AtomicU64; KINDS.len()],
    bidi_handoffs: [AtomicU64; BidiHandoff::ALL.len()],
    crl_file_load_failures: [AtomicU64; 3],
    crl_file_next_update: AtomicU64,
    crl_fetches: [AtomicU64; CrlFetchOutcome::ALL.len()],
    crl_fetch_duration: Histogram,
    crl_cache_active: AtomicBool,
    crl_cache_entries: AtomicU64,
    crl_cache_bytes: AtomicU64,
    crl_cache_evictions: [AtomicU64; CrlEviction::ALL.len()],
    link_source: PlRwLock<Option<Weak<dyn LinkStats>>>,
}

impl S2sMetrics {
    pub(crate) fn new(listener_count: usize) -> Arc<Self> {
        Arc::new(Self {
            transport_connections: Default::default(),
            transport_attempts: Default::default(),
            connections: Default::default(),
            listeners: (0..listener_count)
                .map(|_| ListenerCounters::default())
                .collect(),
            authentications: Default::default(),
            revocation_checks: Default::default(),
            negotiation_duration: std::array::from_fn(|_| Histogram::new(PHASE_BUCKETS)),
            streams: Default::default(),
            streams_closed: Default::default(),
            stanzas_received: Default::default(),
            stanzas_sent: Default::default(),
            #[cfg(feature = "test-support")]
            transport_ends: Default::default(),
            received_bytes: Default::default(),
            sent_bytes: Default::default(),
            rate_limited: Default::default(),
            dns: Default::default(),
            admission_rejected: Default::default(),
            peer_size_rejections: AtomicU64::new(0),
            bounces: Default::default(),
            dropped: Default::default(),
            bidi_negotiations: Default::default(),
            bidi_streams: Default::default(),
            bidi_stanzas_sent: Default::default(),
            bidi_stanzas_received: Default::default(),
            bidi_handoffs: Default::default(),
            crl_file_load_failures: Default::default(),
            crl_file_next_update: AtomicU64::new(0),
            crl_fetches: Default::default(),
            crl_fetch_duration: Histogram::new(PHASE_BUCKETS),
            crl_cache_active: AtomicBool::new(false),
            crl_cache_entries: AtomicU64::new(0),
            crl_cache_bytes: AtomicU64::new(0),
            crl_cache_evictions: Default::default(),
            link_source: PlRwLock::new(None),
        })
    }

    pub(crate) fn register(self: &Arc<Self>, registry: &mut Registry) {
        registry.register_collector(Box::new(S2sCollector(Arc::clone(self))));
    }

    pub(crate) fn crl_file_loaded(&self, next_update: SystemTime) {
        self.crl_file_next_update.store(
            next_update
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn crl_file_load_failed(&self, error: CrlLoadError) {
        self.crl_file_load_failures[error as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn crl_fetched(&self, outcome: CrlFetchOutcome, elapsed: Duration) {
        self.crl_fetches[outcome as usize].fetch_add(1, Ordering::Relaxed);
        self.crl_fetch_duration.observe(elapsed.as_secs_f64());
    }

    pub(crate) fn crl_cache_size(&self, entries: usize, bytes: usize) {
        self.crl_cache_entries
            .store(entries as u64, Ordering::Relaxed);
        self.crl_cache_bytes.store(bytes as u64, Ordering::Relaxed);
        self.crl_cache_active.store(true, Ordering::Release);
    }

    pub(crate) fn crl_cache_evicted(&self, reason: CrlEviction) {
        self.crl_cache_evictions[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn connection_opened(
        self: &Arc<Self>,
        direction: Direction,
        mode: TlsMode,
    ) -> ConnectionGauge {
        self.transport_connections[direction as usize][mode as usize]
            .fetch_add(1, Ordering::Relaxed);
        self.connections[direction as usize].fetch_add(1, Ordering::Relaxed);
        ConnectionGauge {
            metrics: Arc::clone(self),
            direction,
            kind: GaugeKind::Connection(mode),
        }
    }

    pub(crate) fn listener_bound(
        self: &Arc<Self>,
        listener: usize,
        mode: TlsMode,
    ) -> ListenerGauge {
        self.listeners[listener].bound[mode as usize].fetch_add(1, Ordering::Relaxed);
        ListenerGauge {
            metrics: Arc::clone(self),
            listener,
            mode,
        }
    }

    pub(crate) fn transport_attempt(
        self: &Arc<Self>,
        direction: Direction,
        mode: TlsMode,
    ) -> TransportAttempt {
        TransportAttempt {
            metrics: Arc::clone(self),
            direction,
            mode,
            recorded: false,
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

    pub(crate) fn revocation_checked(
        &self,
        direction: Direction,
        phase: CheckPhase,
        verdict: &RevocationVerdict,
    ) {
        self.revocation_checks[direction as usize][verdict.source as usize][phase as usize]
            [verdict.status.index()]
        .fetch_add(1, Ordering::Relaxed);
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

    pub(crate) fn peer_size_rejected(&self) {
        self.peer_size_rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bounced(&self, condition: BounceCondition) {
        self.bounces[condition as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dropped(&self, reason: DropReason, count: u64) {
        self.dropped[reason as usize].fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn bidi_negotiated(&self, direction: Direction, outcome: BidiOutcome) {
        self.bidi_negotiations[direction as usize][outcome as usize]
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bidi_stream_opened(self: &Arc<Self>, direction: Direction) -> ConnectionGauge {
        self.bidi_streams[direction as usize].fetch_add(1, Ordering::Relaxed);
        ConnectionGauge {
            metrics: Arc::clone(self),
            direction,
            kind: GaugeKind::Bidi,
        }
    }

    pub(crate) fn bidi_stanza_sent(&self, kind: StanzaKind) {
        self.bidi_stanzas_sent[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bidi_stanza_received(&self, kind: StanzaKind) {
        self.bidi_stanzas_received[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bidi_handoff(&self, target: BidiHandoff) {
        self.bidi_handoffs[target as usize].fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn transport_end(&self, direction: Direction) {
        self.transport_ends[direction as usize].fetch_add(1, Ordering::Release);
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn shutdown_state(&self) -> crate::test_support::S2sShutdownState {
        let source = self.link_source.read().as_ref().and_then(Weak::upgrade);
        let snapshot = source.map_or_else(LinkSnapshot::default, |source| source.snapshot());
        let transport_ends =
            std::array::from_fn(|direction| self.transport_ends[direction].load(Ordering::Acquire));
        crate::test_support::S2sShutdownState {
            transport_ends,
            received_bytes: std::array::from_fn(|direction| {
                self.received_bytes[direction].load(Ordering::Relaxed)
            }),
            sent_bytes: std::array::from_fn(|direction| {
                self.sent_bytes[direction].load(Ordering::Relaxed)
            }),
            dropped_shutdown: self.dropped[DropReason::Shutdown as usize].load(Ordering::Relaxed),
            dropped_connection_lost: self.dropped[DropReason::ConnectionLost as usize]
                .load(Ordering::Relaxed),
            streams: std::array::from_fn(|direction| {
                self.streams[direction].load(Ordering::Relaxed)
            }),
            bidi_streams: std::array::from_fn(|direction| {
                self.bidi_streams[direction].load(Ordering::Relaxed)
            }),
            c2s_connections: 0,
            c2s_unauthenticated: 0,
            router_sessions: 0,
            queued_stanzas: snapshot.queued_stanzas,
            queued_bytes: snapshot.queued_bytes,
            transport_cancelled: std::array::from_fn(|direction| {
                std::array::from_fn(|mode| {
                    self.transport_attempts[direction][mode][AuthOutcome::ALL.len()]
                        .load(Ordering::Relaxed)
                })
            }),
            transport_connections: std::array::from_fn(|direction| {
                std::array::from_fn(|mode| {
                    self.transport_connections[direction][mode].load(Ordering::Relaxed)
                })
            }),
            connections: std::array::from_fn(|direction| {
                self.connections[direction].load(Ordering::Relaxed)
            }),
            authentication_protocol: std::array::from_fn(|direction| {
                self.authentications[direction][AuthOutcome::Protocol as usize]
                    .load(Ordering::Relaxed)
            }),
        }
    }

    pub(crate) fn set_link_source(&self, source: Weak<dyn LinkStats>) {
        *self.link_source.write() = Some(source);
    }
}

enum GaugeKind {
    Connection(TlsMode),
    Stream,
    Bidi,
}

#[must_use]
pub(crate) struct ConnectionGauge {
    metrics: Arc<S2sMetrics>,
    direction: Direction,
    kind: GaugeKind,
}

impl ConnectionGauge {
    pub(crate) fn tls_mode(&self) -> Option<TlsMode> {
        match self.kind {
            GaugeKind::Connection(mode) => Some(mode),
            _ => None,
        }
    }
}

pub(crate) struct ListenerGauge {
    metrics: Arc<S2sMetrics>,
    listener: usize,
    mode: TlsMode,
}
impl Drop for ListenerGauge {
    fn drop(&mut self) {
        self.metrics.listeners[self.listener].bound[self.mode as usize]
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[must_use]
pub(crate) struct TransportAttempt {
    metrics: Arc<S2sMetrics>,
    direction: Direction,
    mode: TlsMode,
    recorded: bool,
}
impl TransportAttempt {
    pub(crate) fn complete(&mut self, outcome: AuthOutcome) {
        self.record(outcome as usize);
    }
    pub(crate) fn cancel(&mut self) {
        self.record(AuthOutcome::ALL.len());
    }
    fn record(&mut self, outcome: usize) {
        if !self.recorded {
            self.metrics.transport_attempts[self.direction as usize][self.mode as usize][outcome]
                .fetch_add(1, Ordering::Relaxed);
            self.recorded = true;
        }
    }
}
impl Drop for TransportAttempt {
    fn drop(&mut self) {
        self.record(AuthOutcome::ALL.len());
    }
}

impl Drop for ConnectionGauge {
    fn drop(&mut self) {
        let counters = match self.kind {
            GaugeKind::Connection(mode) => {
                self.metrics.transport_connections[self.direction as usize][mode as usize]
                    .fetch_sub(1, Ordering::Relaxed);
                &self.metrics.connections
            }
            GaugeKind::Stream => &self.metrics.streams,
            GaugeKind::Bidi => &self.metrics.bidi_streams,
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
        let mut bound = metrics
            .listeners
            .iter()
            .enumerate()
            .flat_map(|(listener, counters)| {
                TlsMode::ALL.into_iter().filter_map(move |mode| {
                    (counters.bound[mode as usize].load(Ordering::Relaxed) != 0).then_some(
                        ListenerInfoLabels {
                            listener,
                            tls_mode: mode.as_str(),
                        },
                    )
                })
            })
            .peekable();
        if bound.peek().is_some() {
            let mut family = encoder.encode_descriptor(
                "s2s_listener_info",
                "Bound S2S listener transport.",
                None,
                MetricType::Gauge,
            )?;
            for labels in bound {
                ConstGauge::new(1u64).encode(family.encode_family(&labels)?)?;
            }
        }
        let mut family = encoder.encode_descriptor(
            "s2s_transport_connections",
            "Open admitted S2S TCP connections by transport.",
            None,
            MetricType::Gauge,
        )?;
        for direction in Direction::ALL {
            for mode in TlsMode::ALL {
                ConstGauge::new(
                    metrics.transport_connections[direction as usize][mode as usize]
                        .load(Ordering::Relaxed),
                )
                .encode(family.encode_family(&[
                    ("direction", direction.as_str()),
                    ("tls_mode", mode.as_str()),
                ])?)?;
            }
        }
        encode_counter(
            &mut encoder,
            "s2s_transport_attempts",
            "S2S endpoint negotiation results by transport.",
            Direction::ALL.into_iter().flat_map(|direction| {
                TlsMode::ALL.into_iter().flat_map(move |mode| {
                    AuthOutcome::ALL
                        .into_iter()
                        .map(Some)
                        .chain(std::iter::once(None))
                        .enumerate()
                        .map(move |(index, outcome)| {
                            (
                                [
                                    ("direction", direction.as_str()),
                                    ("tls_mode", mode.as_str()),
                                    ("outcome", outcome.map_or("cancelled", AuthOutcome::as_str)),
                                ],
                                metrics.transport_attempts[direction as usize][mode as usize]
                                    [index]
                                    .load(Ordering::Relaxed),
                            )
                        })
                })
            }),
        )?;
        encode_counter(
            &mut encoder,
            "s2s_crl_file_load_failures",
            "S2S CRL file loads that failed.",
            CrlLoadError::ALL.map(|reason| {
                (
                    [("reason", reason.as_str())],
                    metrics.crl_file_load_failures[reason as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        let next_update = metrics.crl_file_next_update.load(Ordering::Relaxed);
        if next_update != 0 {
            ConstGauge::new(next_update).encode(encoder.encode_descriptor(
                "s2s_crl_file_next_update_seconds",
                "Earliest nextUpdate of the last loaded S2S CRL file in Unix seconds.",
                None,
                MetricType::Gauge,
            )?)?;
        }
        encode_counter(
            &mut encoder,
            "s2s_crl_fetches",
            "S2S CRL download attempts by result.",
            CrlFetchOutcome::ALL.map(|outcome| {
                (
                    [("outcome", outcome.as_str())],
                    metrics.crl_fetches[outcome as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
        if metrics
            .crl_fetches
            .iter()
            .any(|count| count.load(Ordering::Relaxed) != 0)
        {
            metrics
                .crl_fetch_duration
                .encode(encoder.encode_descriptor(
                    "s2s_crl_fetch_duration",
                    "S2S CRL download time.",
                    Some(&Unit::Seconds),
                    MetricType::Histogram,
                )?)?;
        }
        if metrics.crl_cache_active.load(Ordering::Acquire) {
            for (name, help, counter) in [
                (
                    "s2s_crl_cache_entries",
                    "URLs tracked by the S2S CRL cache.",
                    &metrics.crl_cache_entries,
                ),
                (
                    "s2s_crl_cache_bytes",
                    "Estimated memory of CRLs held by the S2S CRL cache.",
                    &metrics.crl_cache_bytes,
                ),
            ] {
                ConstGauge::new(counter.load(Ordering::Relaxed))
                    .encode(encoder.encode_descriptor(name, help, None, MetricType::Gauge)?)?;
            }
        }
        encode_counter(
            &mut encoder,
            "s2s_crl_cache_evictions",
            "S2S CRL cache entries removed, by reason.",
            CrlEviction::ALL.map(|reason| {
                (
                    [("reason", reason.as_str())],
                    metrics.crl_cache_evictions[reason as usize].load(Ordering::Relaxed),
                )
            }),
        )?;
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
            (
                "s2s_bidi_streams",
                "Authenticated S2S streams that carry stanzas in both directions.",
                &metrics.bidi_streams,
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
        encode_counter(
            &mut encoder,
            "s2s_bidi_negotiations",
            "Authenticated S2S streams by bidirectional negotiation outcome.",
            Direction::ALL.into_iter().flat_map(|direction| {
                BidiOutcome::ALL.map(|outcome| {
                    (
                        [
                            ("direction", direction.as_str()),
                            ("outcome", outcome.as_str()),
                        ],
                        metrics.bidi_negotiations[direction as usize][outcome as usize]
                            .load(Ordering::Relaxed),
                    )
                })
            }),
        )?;
        encode_counter(
            &mut encoder,
            "s2s_revocation_checks",
            "S2S peer certificate revocation checks.",
            Direction::ALL.into_iter().flat_map(|direction| {
                RevocationSource::ALL.into_iter().flat_map(move |source| {
                    CheckPhase::ALL.into_iter().flat_map(move |phase| {
                        RevocationStatus::ALL.map(|status| {
                            (
                                [
                                    ("direction", direction.as_str()),
                                    ("source", source.as_str()),
                                    ("phase", phase.as_str()),
                                    ("status", status.as_str()),
                                    ("reason", status.reason()),
                                ],
                                metrics.revocation_checks[direction as usize][source as usize]
                                    [phase as usize][status.index()]
                                .load(Ordering::Relaxed),
                            )
                        })
                    })
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
                "Stanzas accepted from remote servers after address validation.",
                &metrics.stanzas_received,
            ),
            (
                "s2s_stanzas_sent",
                "Stanzas written to remote servers.",
                &metrics.stanzas_sent,
            ),
            (
                "s2s_bidi_stanzas_sent",
                "Stanzas sent on inbound bidirectional streams.",
                &metrics.bidi_stanzas_sent,
            ),
            (
                "s2s_bidi_stanzas_received",
                "Stanzas received on outbound bidirectional links.",
                &metrics.bidi_stanzas_received,
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
                "Reported TLS socket read completions, including handshake and record overhead; cancellation or teardown may omit completions.",
                &metrics.received_bytes,
            ),
            (
                "s2s_sent_bytes",
                "Reported TLS socket write completions, including handshake and record overhead; cancellation or teardown may omit completions.",
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
        let rejected = metrics.peer_size_rejections.load(Ordering::Relaxed);
        if rejected != 0 {
            ConstCounter::new(rejected).encode(encoder.encode_descriptor(
                "s2s_peer_size_rejections",
                "Routed stanzas rejected by the peer maximum byte size.",
                None,
                MetricType::Counter,
            )?)?;
        }
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
            "s2s_bidi_handoffs",
            "Outbound link queues moved to an inbound bidirectional stream or to a new dialed link.",
            BidiHandoff::ALL.map(|target| {
                (
                    [("target", target.as_str())],
                    metrics.bidi_handoffs[target as usize].load(Ordering::Relaxed),
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

impl lonewolf_util::rate_limited_reader::RateLimitObserver for S2sMetrics {
    fn on_throttle(&self) {
        self.rate_limited(InboundLimit::IncomingXmlPerConnection);
    }
}
