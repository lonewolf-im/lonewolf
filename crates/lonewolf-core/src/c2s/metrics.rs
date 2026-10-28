// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crossbeam_utils::CachePadded;
use lonewolf_auth::server::Mechanism;
use lonewolf_xmpp::stanza::StanzaKind;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::{
    MetricType, counter::ConstCounter, gauge::ConstGauge, histogram::Histogram,
};
use prometheus_client::registry::{Registry, Unit};

use super::stream::{BindRejection, CloseOutcome, SaslFailure, SaslMechanism, StreamPhase};
use super::unauthenticated_limit::UnauthenticatedLimiter;

pub(crate) const PHASE_BUCKETS: [f64; 13] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0, 30.0,
];
pub(super) const SESSION_BUCKETS: [f64; 13] = [
    1.0, 10.0, 60.0, 300.0, 900.0, 1800.0, 3600.0, 7200.0, 14400.0, 28800.0, 86400.0, 259200.0,
    604800.0,
];
const NEGOTIATION_PHASES: [StreamPhase; 3] = [
    StreamPhase::Establishing,
    StreamPhase::Authenticating,
    StreamPhase::Binding,
];

const KINDS: [StanzaKind; 3] = [StanzaKind::Message, StanzaKind::Presence, StanzaKind::Iq];

fn kind_index(kind: StanzaKind) -> usize {
    match kind {
        StanzaKind::Message => 0,
        StanzaKind::Presence => 1,
        StanzaKind::Iq => 2,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RateLimit {
    IncomingStanzasPerConnection,
    NewRecipientsPerConnection,
}

impl RateLimit {
    pub(super) const ALL: [Self; 2] = [
        Self::IncomingStanzasPerConnection,
        Self::NewRecipientsPerConnection,
    ];

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::IncomingStanzasPerConnection => "incoming_stanzas_per_connection",
            Self::NewRecipientsPerConnection => "new_recipients_per_connection",
        }
    }
}

const MECHANISMS: [Option<SaslMechanism>; 6] = [
    Some(SaslMechanism::External),
    Some(SaslMechanism::Scram(Mechanism::Sha1)),
    Some(SaslMechanism::Scram(Mechanism::Sha1Plus)),
    Some(SaslMechanism::Scram(Mechanism::Sha256)),
    Some(SaslMechanism::Scram(Mechanism::Sha256Plus)),
    None,
];

fn mechanism_index(mechanism: Option<SaslMechanism>) -> usize {
    match mechanism {
        Some(SaslMechanism::External) => 0,
        Some(SaslMechanism::Scram(Mechanism::Sha1)) => 1,
        Some(SaslMechanism::Scram(Mechanism::Sha1Plus)) => 2,
        Some(SaslMechanism::Scram(Mechanism::Sha256)) => 3,
        Some(SaslMechanism::Scram(Mechanism::Sha256Plus)) => 4,
        None => 5,
    }
}

fn mechanism_label(mechanism: Option<SaslMechanism>) -> &'static str {
    mechanism.map_or("none", SaslMechanism::name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RejectReason {
    ConnectionAttemptsPerIp,
    AttemptTrackingFull,
    MaxUnauthenticatedConnections,
    MaxConnectionsPerIp,
    ConnectionTrackingFull,
}

impl RejectReason {
    pub(super) const ALL: [Self; 5] = [
        Self::ConnectionAttemptsPerIp,
        Self::AttemptTrackingFull,
        Self::MaxUnauthenticatedConnections,
        Self::MaxConnectionsPerIp,
        Self::ConnectionTrackingFull,
    ];

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionAttemptsPerIp => "connection_attempts_per_ip",
            Self::AttemptTrackingFull => "attempt_tracking_full",
            Self::MaxUnauthenticatedConnections => "max_unauthenticated_connections",
            Self::MaxConnectionsPerIp => "max_connections_per_ip",
            Self::ConnectionTrackingFull => "connection_tracking_full",
        }
    }
}

struct C2sCounters {
    connections: AtomicU64,
    accepted: AtomicU64,
    rejected: [AtomicU64; RejectReason::ALL.len()],
    /// The last outcome slot counts streams dropped before they reported an outcome.
    closed: [[AtomicU64; CloseOutcome::COUNT + 1]; StreamPhase::ALL.len()],
    panics: AtomicU64,
    authentications: [[AtomicU64; 1 + SaslFailure::ALL.len()]; MECHANISMS.len()],
    bindings: [AtomicU64; 1 + BindRejection::ALL.len()],
    stanzas_received: [AtomicU64; KINDS.len()],
    stanzas_sent: [AtomicU64; KINDS.len()],
    received_bytes: AtomicU64,
    sent_bytes: AtomicU64,
    rate_limited: [AtomicU64; RateLimit::ALL.len()],
}

impl Default for C2sCounters {
    fn default() -> Self {
        Self {
            connections: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            rejected: std::array::from_fn(|_| AtomicU64::new(0)),
            closed: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            panics: AtomicU64::new(0),
            authentications: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            bindings: std::array::from_fn(|_| AtomicU64::new(0)),
            stanzas_received: std::array::from_fn(|_| AtomicU64::new(0)),
            stanzas_sent: std::array::from_fn(|_| AtomicU64::new(0)),
            received_bytes: AtomicU64::new(0),
            sent_bytes: AtomicU64::new(0),
            rate_limited: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

struct WorkerMetrics {
    counters: C2sCounters,
    phase_durations: [Histogram; NEGOTIATION_PHASES.len()],
    session_duration: Histogram,
}

#[derive(Clone)]
pub(super) struct C2sWorkerMetrics(Arc<CachePadded<WorkerMetrics>>);

impl C2sWorkerMetrics {
    pub(super) fn connection_accepted(&self) {
        self.0.counters.accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn connection_rejected(&self, reason: RejectReason) {
        self.0.counters.rejected[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn set_connections(&self, active: usize) {
        self.0
            .counters
            .connections
            .store(u64::try_from(active).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(super) fn connection_closed(&self, phase: StreamPhase, outcome: Option<CloseOutcome>) {
        self.0.counters.closed[phase as usize]
            [outcome.map_or(CloseOutcome::COUNT, CloseOutcome::index)]
        .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn connection_panicked(&self) {
        self.0.counters.panics.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn authentication_succeeded(&self, mechanism: SaslMechanism) {
        self.0.counters.authentications[mechanism_index(Some(mechanism))][0]
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn authentication_failed(
        &self,
        mechanism: Option<SaslMechanism>,
        failure: SaslFailure,
    ) {
        self.0.counters.authentications[mechanism_index(mechanism)][1 + failure as usize]
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn binding_succeeded(&self) {
        self.0.counters.bindings[0].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn binding_rejected(&self, rejection: BindRejection) {
        self.0.counters.bindings[1 + rejection as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn stanza_received(&self, kind: StanzaKind) {
        self.0.counters.stanzas_received[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn stanza_sent(&self, kind: StanzaKind) {
        self.0.counters.stanzas_sent[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn bytes_received(&self, bytes: usize) {
        self.0
            .counters
            .received_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(super) fn bytes_sent(&self, bytes: usize) {
        self.0
            .counters
            .sent_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(super) fn rate_limited(&self, limit: RateLimit) {
        self.0.counters.rate_limited[limit as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Ignores `StreamPhase::Bound`, which has no negotiation duration.
    pub(super) fn phase_completed(&self, phase: StreamPhase, elapsed: Duration) {
        if let Some(histogram) = self.0.phase_durations.get(phase as usize) {
            histogram.observe(elapsed.as_secs_f64());
        }
    }

    pub(super) fn session_ended(&self, duration: Duration) {
        self.0.session_duration.observe(duration.as_secs_f64());
    }

    #[cfg(test)]
    pub(super) fn detached() -> Self {
        C2sMetrics::detached().worker(0, 0)
    }
}

pub(super) struct C2sMetrics {
    listeners: Box<[Box<[C2sWorkerMetrics]>]>,
    phase_durations: [Histogram; NEGOTIATION_PHASES.len()],
    session_duration: Histogram,
    unauthenticated: Arc<UnauthenticatedLimiter>,
}

impl C2sMetrics {
    /// Every worker handle shares the histograms created here.
    pub(super) fn new(
        listeners: usize,
        workers: NonZeroUsize,
        unauthenticated: Arc<UnauthenticatedLimiter>,
    ) -> Arc<Self> {
        let phase_durations = std::array::from_fn(|_| Histogram::new(PHASE_BUCKETS));
        let session_duration = Histogram::new(SESSION_BUCKETS);
        let listeners = (0..listeners)
            .map(|_| {
                (0..workers.get())
                    .map(|_| {
                        C2sWorkerMetrics(Arc::new(CachePadded::new(WorkerMetrics {
                            counters: C2sCounters::default(),
                            phase_durations: phase_durations.clone(),
                            session_duration: session_duration.clone(),
                        })))
                    })
                    .collect()
            })
            .collect();
        Arc::new(Self {
            listeners,
            phase_durations,
            session_duration,
            unauthenticated,
        })
    }

    pub(super) fn worker(&self, listener: usize, worker: usize) -> C2sWorkerMetrics {
        self.listeners[listener][worker].clone()
    }

    pub(super) fn register(self: &Arc<Self>, registry: &mut Registry) {
        registry.register_collector(Box::new(C2sCollector(Arc::clone(self))));
    }

    #[cfg(test)]
    pub(super) fn detached() -> Arc<Self> {
        Self::new(
            1,
            NonZeroUsize::MIN,
            Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN)),
        )
    }

    #[cfg(test)]
    pub(super) fn render(self: &Arc<Self>) -> Result<String, fmt::Error> {
        let mut registry = Registry::default();
        self.register(registry.sub_registry_with_prefix("lonewolf"));
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &registry)?;
        Ok(output)
    }
}

impl fmt::Debug for C2sMetrics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("C2sMetrics").finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct C2sCollector(Arc<C2sMetrics>);

fn sum(workers: &[C2sWorkerMetrics], counter: impl Fn(&C2sCounters) -> &AtomicU64) -> u64 {
    workers.iter().fold(0u64, |total, worker| {
        total.saturating_add(counter(&worker.0.counters).load(Ordering::Relaxed))
    })
}

impl Collector for C2sCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        let metrics = &self.0;
        if !metrics.listeners.is_empty() {
            let mut family = encoder.encode_descriptor(
                "c2s_connections",
                "Client connections currently open, by listener.",
                None,
                MetricType::Gauge,
            )?;
            for (listener, workers) in metrics.listeners.iter().enumerate() {
                ConstGauge::new(sum(workers, |c| &c.connections))
                    .encode(family.encode_family(&ListenerLabels { listener })?)?;
            }
        }
        ConstGauge::new(metrics.unauthenticated.active_count() as u64).encode(
            encoder.encode_descriptor(
                "c2s_unauthenticated_connections",
                "Client connections that have not completed authentication.",
                None,
                MetricType::Gauge,
            )?,
        )?;
        ConstGauge::new(metrics.unauthenticated.limit() as u64).encode(
            encoder.encode_descriptor(
                "c2s_unauthenticated_connections_limit",
                "Maximum number of unauthenticated client connections.",
                None,
                MetricType::Gauge,
            )?,
        )?;
        if !metrics.listeners.is_empty() {
            let mut family = encoder.encode_descriptor(
                "c2s_connections_accepted",
                "Client connections admitted, by listener.",
                None,
                MetricType::Counter,
            )?;
            for (listener, workers) in metrics.listeners.iter().enumerate() {
                ConstCounter::new(sum(workers, |c| &c.accepted))
                    .encode(family.encode_family(&ListenerLabels { listener })?)?;
            }
        }
        if metrics
            .listeners
            .iter()
            .flat_map(|workers| workers.iter())
            .any(|worker| {
                worker
                    .0
                    .counters
                    .rejected
                    .iter()
                    .any(|counter| counter.load(Ordering::Relaxed) != 0)
            })
        {
            let mut family = encoder.encode_descriptor(
                "c2s_connections_rejected",
                "Client connections refused by an admission limit, by listener and reason.",
                None,
                MetricType::Counter,
            )?;
            for (listener, workers) in metrics.listeners.iter().enumerate() {
                for reason in RejectReason::ALL {
                    let value = sum(workers, |c| &c.rejected[reason as usize]);
                    if value != 0 {
                        ConstCounter::new(value).encode(family.encode_family(
                            &RejectedLabels {
                                listener,
                                reason: reason.as_str(),
                            },
                        )?)?;
                    }
                }
            }
        }
        if metrics
            .listeners
            .iter()
            .flat_map(|workers| workers.iter())
            .any(|worker| {
                worker
                    .0
                    .counters
                    .closed
                    .iter()
                    .flatten()
                    .any(|counter| counter.load(Ordering::Relaxed) != 0)
            })
        {
            let mut family = encoder.encode_descriptor(
                "c2s_connections_closed",
                "Admitted client connections that closed, by listener, stream phase and outcome.",
                None,
                MetricType::Counter,
            )?;
            for (listener, workers) in metrics.listeners.iter().enumerate() {
                for phase in StreamPhase::ALL {
                    for index in 0..=CloseOutcome::COUNT {
                        let value = sum(workers, |c| &c.closed[phase as usize][index]);
                        if value != 0 {
                            let outcome = CloseOutcome::ALL
                                .get(index)
                                .map_or("cancelled", |outcome| outcome.as_str());
                            ConstCounter::new(value).encode(family.encode_family(
                                &ClosedLabels {
                                    listener,
                                    phase: phase.as_str(),
                                    outcome,
                                },
                            )?)?;
                        }
                    }
                }
            }
        }
        if !metrics.listeners.is_empty() {
            let mut family = encoder.encode_descriptor(
                "c2s_connection_panics",
                "Client connection tasks that ended with a panic, by listener.",
                None,
                MetricType::Counter,
            )?;
            for (listener, workers) in metrics.listeners.iter().enumerate() {
                ConstCounter::new(sum(workers, |c| &c.panics))
                    .encode(family.encode_family(&ListenerLabels { listener })?)?;
            }
        }
        if metrics
            .listeners
            .iter()
            .flat_map(|workers| workers.iter())
            .any(|worker| {
                worker
                    .0
                    .counters
                    .authentications
                    .iter()
                    .flatten()
                    .any(|counter| counter.load(Ordering::Relaxed) != 0)
            })
        {
            let mut family = encoder.encode_descriptor(
                "c2s_authentications",
                "SASL authentication results, by listener, mechanism and outcome.",
                None,
                MetricType::Counter,
            )?;
            for (listener, workers) in metrics.listeners.iter().enumerate() {
                for mechanism in MECHANISMS {
                    for index in 0..=SaslFailure::ALL.len() {
                        let value = sum(workers, |c| {
                            &c.authentications[mechanism_index(mechanism)][index]
                        });
                        if value != 0 {
                            let outcome = if index == 0 {
                                "success"
                            } else {
                                SaslFailure::ALL[index - 1].as_str()
                            };
                            ConstCounter::new(value).encode(family.encode_family(
                                &AuthenticationLabels {
                                    listener,
                                    mechanism: mechanism_label(mechanism),
                                    outcome,
                                },
                            )?)?;
                        }
                    }
                }
            }
        }
        if metrics
            .listeners
            .iter()
            .flat_map(|workers| workers.iter())
            .any(|worker| {
                worker
                    .0
                    .counters
                    .bindings
                    .iter()
                    .any(|counter| counter.load(Ordering::Relaxed) != 0)
            })
        {
            let mut family = encoder.encode_descriptor(
                "c2s_resource_bindings",
                "Resource binding results, by listener and outcome.",
                None,
                MetricType::Counter,
            )?;
            for (listener, workers) in metrics.listeners.iter().enumerate() {
                for index in 0..=BindRejection::ALL.len() {
                    let value = sum(workers, |c| &c.bindings[index]);
                    if value != 0 {
                        let outcome = if index == 0 {
                            "success"
                        } else {
                            BindRejection::ALL[index - 1].as_str()
                        };
                        ConstCounter::new(value)
                            .encode(family.encode_family(&BindingLabels { listener, outcome })?)?;
                    }
                }
            }
        }
        let mut family = encoder.encode_descriptor(
            "c2s_stanzas_received",
            "Stanzas parsed from client streams, by listener and kind.",
            None,
            MetricType::Counter,
        )?;
        for (listener, workers) in metrics.listeners.iter().enumerate() {
            for kind in KINDS {
                ConstCounter::new(sum(workers, |c| &c.stanzas_received[kind_index(kind)])).encode(
                    family.encode_family(&KindLabels {
                        listener,
                        kind: kind.as_str(),
                    })?,
                )?;
            }
        }
        let mut family = encoder.encode_descriptor(
            "c2s_stanzas_sent",
            "Stanzas written to client streams, by listener and kind.",
            None,
            MetricType::Counter,
        )?;
        for (listener, workers) in metrics.listeners.iter().enumerate() {
            for kind in KINDS {
                ConstCounter::new(sum(workers, |c| &c.stanzas_sent[kind_index(kind)])).encode(
                    family.encode_family(&KindLabels {
                        listener,
                        kind: kind.as_str(),
                    })?,
                )?;
            }
        }
        let mut family = encoder.encode_descriptor(
            "c2s_received",
            "Bytes read from client sockets after STARTTLS, including TLS overhead.",
            Some(&Unit::Bytes),
            MetricType::Counter,
        )?;
        for (listener, workers) in metrics.listeners.iter().enumerate() {
            ConstCounter::new(sum(workers, |c| &c.received_bytes))
                .encode(family.encode_family(&ListenerLabels { listener })?)?;
        }
        let mut family = encoder.encode_descriptor(
            "c2s_sent",
            "Bytes written to client sockets after STARTTLS, including TLS overhead.",
            Some(&Unit::Bytes),
            MetricType::Counter,
        )?;
        for (listener, workers) in metrics.listeners.iter().enumerate() {
            ConstCounter::new(sum(workers, |c| &c.sent_bytes))
                .encode(family.encode_family(&ListenerLabels { listener })?)?;
        }
        let mut family = encoder.encode_descriptor(
            "c2s_rate_limited",
            "Stanzas delayed or rejected by a per-connection rate limit, by listener and limit.",
            None,
            MetricType::Counter,
        )?;
        for (listener, workers) in metrics.listeners.iter().enumerate() {
            for limit in RateLimit::ALL {
                ConstCounter::new(sum(workers, |c| &c.rate_limited[limit as usize])).encode(
                    family.encode_family(&LimitLabels {
                        listener,
                        limit: limit.as_str(),
                    })?,
                )?;
            }
        }
        let mut family = encoder.encode_descriptor(
            "c2s_phase_duration",
            "Time to complete each stream negotiation phase.",
            Some(&Unit::Seconds),
            MetricType::Histogram,
        )?;
        for (phase, histogram) in NEGOTIATION_PHASES.into_iter().zip(&metrics.phase_durations) {
            histogram.encode(family.encode_family(&PhaseLabels {
                phase: phase.as_str(),
            })?)?;
        }
        metrics.session_duration.encode(encoder.encode_descriptor(
            "c2s_session_duration",
            "Lifetime of bound client sessions, from resource binding to close.",
            Some(&Unit::Seconds),
            MetricType::Histogram,
        )?)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ListenerLabels {
    listener: usize,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RejectedLabels {
    listener: usize,
    reason: &'static str,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ClosedLabels {
    listener: usize,
    phase: &'static str,
    outcome: &'static str,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct AuthenticationLabels {
    listener: usize,
    mechanism: &'static str,
    outcome: &'static str,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BindingLabels {
    listener: usize,
    outcome: &'static str,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct KindLabels {
    listener: usize,
    kind: &'static str,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct LimitLabels {
    listener: usize,
    limit: &'static str,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PhaseLabels {
    phase: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_and_limit_indexes_follow_their_order() {
        for (index, kind) in KINDS.into_iter().enumerate() {
            assert_eq!(kind_index(kind), index);
            assert_eq!(kind.as_str(), ["message", "presence", "iq"][index]);
        }
        for (index, limit) in RateLimit::ALL.into_iter().enumerate() {
            assert_eq!(limit as usize, index);
            assert_eq!(
                limit.as_str(),
                [
                    "incoming_stanzas_per_connection",
                    "new_recipients_per_connection"
                ][index]
            );
        }
    }

    #[test]
    fn traffic_counters_are_encoded_for_every_series() -> Result<(), fmt::Error> {
        let metrics = C2sMetrics::detached();
        let empty = metrics.render()?;
        for kind in KINDS {
            for direction in ["received", "sent"] {
                assert!(
                    empty.contains(&format!(
                        "lonewolf_c2s_stanzas_{direction}_total{{listener=\"0\",kind=\"{}\"}} 0\n",
                        kind.as_str()
                    )),
                    "{empty}"
                );
            }
        }
        for direction in ["received", "sent"] {
            assert!(
                empty.contains(&format!(
                    "lonewolf_c2s_{direction}_bytes_total{{listener=\"0\"}} 0\n"
                )),
                "{empty}"
            );
        }
        for limit in RateLimit::ALL {
            assert!(
                empty.contains(&format!(
                    "lonewolf_c2s_rate_limited_total{{listener=\"0\",limit=\"{}\"}} 0\n",
                    limit.as_str()
                )),
                "{empty}"
            );
        }
        let worker = metrics.worker(0, 0);
        worker.stanza_received(StanzaKind::Message);
        worker.stanza_sent(StanzaKind::Iq);
        worker.bytes_received(10);
        worker.bytes_sent(7);
        worker.rate_limited(RateLimit::IncomingStanzasPerConnection);
        let body = metrics.render()?;
        for sample in [
            "lonewolf_c2s_stanzas_received_total{listener=\"0\",kind=\"message\"} 1\n",
            "lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"iq\"} 1\n",
            "lonewolf_c2s_received_bytes_total{listener=\"0\"} 10\n",
            "lonewolf_c2s_sent_bytes_total{listener=\"0\"} 7\n",
            "lonewolf_c2s_rate_limited_total{listener=\"0\",limit=\"incoming_stanzas_per_connection\"} 1\n",
        ] {
            assert!(body.contains(sample), "{body}");
        }
        assert!(
            body.lines()
                .filter(|line| line.starts_with("# HELP "))
                .all(|line| line.ends_with('.')),
            "{body}"
        );
        Ok(())
    }

    #[test]
    fn authentication_and_binding_outcomes_are_encoded_without_zero_series()
    -> Result<(), fmt::Error> {
        let metrics = C2sMetrics::detached();
        let worker = metrics.worker(0, 0);
        let empty = metrics.render()?;
        assert!(!empty.contains("lonewolf_c2s_authentications"));
        assert!(!empty.contains("lonewolf_c2s_resource_bindings"));
        worker.authentication_failed(None, SaslFailure::InvalidMechanism);
        worker.authentication_failed(
            Some(SaslMechanism::Scram(Mechanism::Sha256)),
            SaslFailure::NotAuthorized,
        );
        worker.authentication_succeeded(SaslMechanism::External);
        worker.binding_succeeded();
        worker.binding_rejected(BindRejection::ResourceConstraint);
        let output = metrics.render()?;
        let mut samples: Vec<_> = output
            .lines()
            .filter(|line| {
                line.starts_with("lonewolf_c2s_authentications_total")
                    || line.starts_with("lonewolf_c2s_resource_bindings_total")
            })
            .collect();
        let mut expected = [
            "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"none\",outcome=\"invalid_mechanism\"} 1",
            "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256\",outcome=\"not_authorized\"} 1",
            "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"EXTERNAL\",outcome=\"success\"} 1",
            "lonewolf_c2s_resource_bindings_total{listener=\"0\",outcome=\"success\"} 1",
            "lonewolf_c2s_resource_bindings_total{listener=\"0\",outcome=\"resource_constraint\"} 1",
        ];
        samples.sort_unstable();
        expected.sort_unstable();
        assert_eq!(samples, expected, "{output}");
        assert!(
            output
                .lines()
                .filter(|line| line.starts_with("# HELP "))
                .all(|line| line.ends_with('.')),
            "{output}"
        );
        Ok(())
    }

    #[test]
    fn mechanism_indexes_follow_the_label_order() {
        let expected = [
            "EXTERNAL",
            "SCRAM-SHA-1",
            "SCRAM-SHA-1-PLUS",
            "SCRAM-SHA-256",
            "SCRAM-SHA-256-PLUS",
            "none",
        ];
        for (index, mechanism) in MECHANISMS.into_iter().enumerate() {
            assert_eq!(mechanism_index(mechanism), index);
            assert_eq!(mechanism_label(mechanism), expected[index]);
            assert!(
                MECHANISMS[..index]
                    .iter()
                    .all(|other| mechanism_label(*other) != mechanism_label(mechanism))
            );
        }
    }

    #[test]
    fn failure_and_rejection_indexes_follow_the_all_order() {
        let failures = [
            ("aborted", "aborted"),
            ("incorrect-encoding", "incorrect_encoding"),
            ("invalid-authzid", "invalid_authzid"),
            ("invalid-mechanism", "invalid_mechanism"),
            ("malformed-request", "malformed_request"),
            ("not-authorized", "not_authorized"),
            ("temporary-auth-failure", "temporary_auth_failure"),
        ];
        for (index, failure) in SaslFailure::ALL.into_iter().enumerate() {
            assert_eq!(failure as usize, index);
            assert_eq!((failure.condition(), failure.as_str()), failures[index]);
            for other in &SaslFailure::ALL[..index] {
                assert_ne!(failure.condition(), other.condition());
                assert_ne!(failure.as_str(), other.as_str());
            }
        }
        let rejections = [
            ("modify", "bad-request", "bad_request"),
            ("cancel", "service-unavailable", "service_unavailable"),
            ("wait", "resource-constraint", "resource_constraint"),
        ];
        for (index, rejection) in BindRejection::ALL.into_iter().enumerate() {
            assert_eq!(rejection as usize, index);
            assert_eq!(
                (
                    rejection.error_type(),
                    rejection.condition(),
                    rejection.as_str()
                ),
                rejections[index]
            );
            for other in &BindRejection::ALL[..index] {
                assert_ne!(rejection.condition(), other.condition());
                assert_ne!(rejection.as_str(), other.as_str());
            }
        }
    }

    #[test]
    fn collector_reports_listener_counters_and_omits_zero_outcomes() -> Result<(), fmt::Error> {
        let metrics = C2sMetrics::new(
            2,
            NonZeroUsize::MIN.saturating_add(1),
            Arc::new(UnauthenticatedLimiter::new(
                NonZeroUsize::MIN.saturating_add(2),
            )),
        );
        let worker = metrics.worker(1, 1);
        let empty = metrics.render()?;
        assert!(!empty.contains("# HELP lonewolf_c2s_connections_rejected"));
        assert!(!empty.contains("# HELP lonewolf_c2s_connections_closed"));
        worker.connection_accepted();
        worker.set_connections(2);
        worker.connection_rejected(RejectReason::MaxConnectionsPerIp);
        worker.connection_closed(StreamPhase::Bound, Some(CloseOutcome::StreamEnd));
        worker.connection_closed(StreamPhase::Establishing, None);
        worker.connection_panicked();
        worker.phase_completed(StreamPhase::Establishing, Duration::from_millis(20));
        worker.session_ended(Duration::from_secs(90));
        let output = metrics.render()?;
        for sample in [
            "lonewolf_c2s_connections{listener=\"0\"} 0",
            "lonewolf_c2s_connections{listener=\"1\"} 2",
            "lonewolf_c2s_unauthenticated_connections 0",
            "lonewolf_c2s_unauthenticated_connections_limit 3",
            "lonewolf_c2s_connections_accepted_total{listener=\"1\"} 1",
            "lonewolf_c2s_connections_rejected_total{listener=\"1\",reason=\"max_connections_per_ip\"} 1",
            "lonewolf_c2s_connections_closed_total{listener=\"1\",phase=\"bound\",outcome=\"stream_end\"} 1",
            "lonewolf_c2s_connections_closed_total{listener=\"1\",phase=\"establishing\",outcome=\"cancelled\"} 1",
            "lonewolf_c2s_connection_panics_total{listener=\"1\"} 1",
            "lonewolf_c2s_phase_duration_seconds_count{phase=\"establishing\"} 1",
            "lonewolf_c2s_phase_duration_seconds_count{phase=\"authenticating\"} 0",
            "lonewolf_c2s_session_duration_seconds_count 1",
        ] {
            assert!(output.lines().any(|line| line == sample), "{output}");
        }
        assert_eq!(
            output
                .lines()
                .filter(|line| line.starts_with("lonewolf_c2s_connections_rejected_total"))
                .count(),
            1
        );
        assert_eq!(
            output
                .lines()
                .filter(|line| line.starts_with("lonewolf_c2s_connections_closed_total"))
                .count(),
            2
        );
        assert!(
            output
                .lines()
                .filter(|line| line.starts_with("# HELP "))
                .all(|line| line.ends_with('.')),
            "{output}"
        );
        Ok(())
    }

    #[test]
    fn blocks_of_different_workers_are_summed() -> Result<(), fmt::Error> {
        let metrics = C2sMetrics::new(
            1,
            NonZeroUsize::MIN.saturating_add(1),
            Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN)),
        );
        metrics
            .worker(0, 0)
            .authentication_succeeded(SaslMechanism::External);
        metrics
            .worker(0, 1)
            .authentication_succeeded(SaslMechanism::External);
        metrics
            .worker(0, 0)
            .binding_rejected(BindRejection::BadRequest);
        metrics
            .worker(0, 1)
            .binding_rejected(BindRejection::BadRequest);
        metrics.worker(0, 0).connection_accepted();
        metrics.worker(0, 1).connection_accepted();
        metrics
            .worker(0, 0)
            .phase_completed(StreamPhase::Establishing, Duration::from_millis(1));
        metrics
            .worker(0, 1)
            .phase_completed(StreamPhase::Establishing, Duration::from_millis(2));
        for worker in [metrics.worker(0, 0), metrics.worker(0, 1)] {
            worker.stanza_received(StanzaKind::Message);
            worker.stanza_sent(StanzaKind::Presence);
            worker.bytes_received(4);
            worker.bytes_sent(3);
            worker.rate_limited(RateLimit::NewRecipientsPerConnection);
        }
        let output = metrics.render()?;
        for sample in [
            "lonewolf_c2s_stanzas_received_total{listener=\"0\",kind=\"message\"} 2\n",
            "lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"presence\"} 2\n",
            "lonewolf_c2s_received_bytes_total{listener=\"0\"} 8\n",
            "lonewolf_c2s_sent_bytes_total{listener=\"0\"} 6\n",
            "lonewolf_c2s_rate_limited_total{listener=\"0\",limit=\"new_recipients_per_connection\"} 2\n",
        ] {
            assert!(output.contains(sample), "{output}");
        }
        assert!(output.lines().any(|line| line == "lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"EXTERNAL\",outcome=\"success\"} 2"), "{output}");
        assert!(output.lines().any(|line| line == "lonewolf_c2s_resource_bindings_total{listener=\"0\",outcome=\"bad_request\"} 2"), "{output}");
        assert!(
            output
                .lines()
                .any(|line| line == "lonewolf_c2s_connections_accepted_total{listener=\"0\"} 2"),
            "{output}"
        );
        assert!(
            output.lines().any(|line| line
                == "lonewolf_c2s_phase_duration_seconds_count{phase=\"establishing\"} 2"),
            "{output}"
        );
        Ok(())
    }

    #[test]
    fn bound_phase_has_no_duration() -> Result<(), fmt::Error> {
        let metrics = C2sMetrics::detached();
        let before = metrics.render()?;
        metrics
            .worker(0, 0)
            .phase_completed(StreamPhase::Bound, Duration::from_secs(1));
        assert_eq!(metrics.render()?, before);
        Ok(())
    }

    #[test]
    fn reason_and_phase_indexes_follow_the_all_order() {
        for (index, reason) in RejectReason::ALL.into_iter().enumerate() {
            assert_eq!(reason as usize, index);
        }
        for (index, phase) in StreamPhase::ALL.into_iter().enumerate() {
            assert_eq!(phase as usize, index);
        }
    }

    #[test]
    fn zero_listeners_omit_listener_family_descriptors() -> Result<(), fmt::Error> {
        let metrics = C2sMetrics::new(
            0,
            NonZeroUsize::MIN,
            Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN)),
        );
        let output = metrics.render()?;
        for family in [
            "c2s_connections ",
            "c2s_connections_accepted",
            "c2s_connections_rejected",
            "c2s_connections_closed",
            "c2s_connection_panics",
            "c2s_authentications",
            "c2s_resource_bindings",
        ] {
            assert!(!output.contains(family), "{output}");
        }
        Ok(())
    }
}
