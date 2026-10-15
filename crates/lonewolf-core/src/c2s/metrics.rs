// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crossbeam_utils::CachePadded;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::{
    MetricType, counter::ConstCounter, gauge::ConstGauge, histogram::Histogram,
};
use prometheus_client::registry::{Registry, Unit};

use super::stream::{CloseOutcome, StreamPhase};
use super::unauthenticated_limit::UnauthenticatedLimiter;

pub(super) const PHASE_BUCKETS: [f64; 13] = [
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
}

impl Default for C2sCounters {
    fn default() -> Self {
        Self {
            connections: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            rejected: std::array::from_fn(|_| AtomicU64::new(0)),
            closed: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            panics: AtomicU64::new(0),
        }
    }
}

struct WorkerMetrics {
    counters: C2sCounters,
    phase_durations: [Histogram; NEGOTIATION_PHASES.len()],
    session_duration: Histogram,
}

/// Recording handle for one listener on one worker.
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
struct PhaseLabels {
    phase: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        metrics.worker(0, 0).connection_accepted();
        metrics.worker(0, 1).connection_accepted();
        metrics
            .worker(0, 0)
            .phase_completed(StreamPhase::Establishing, Duration::from_millis(1));
        metrics
            .worker(0, 1)
            .phase_completed(StreamPhase::Establishing, Duration::from_millis(2));
        let output = metrics.render()?;
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
        ] {
            assert!(!output.contains(family), "{output}");
        }
        Ok(())
    }
}
