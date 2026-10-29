// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use async_channel::{Receiver, Sender};
use compio::io::compat::AsyncStream;
use compio::net::TcpStream;
use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Either, Shared, select};
use futures_util::io::{ReadHalf, WriteHalf};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::RoutedStanza;
use parking_lot::Mutex as PlMutex;
use tokio::io::BufReader;
use tokio_util::compat::Compat;

use super::ConnectionSocket;
use super::dns::Resolver;
use super::metrics::{
    AdmissionReason, ConnectionGauge, DropReason, LinkSnapshot, LinkStats, S2sMetrics,
};
use super::stream::traffic::CountingIo;
use super::stream::{S2sReader, S2sWriter};
use crate::config::limits::S2sLimits;
use crate::delivery::{WorkGroup, WorkGuard, WorkHandle};
use crate::hosts::{Hosts, peer_identity::PeerTrust};
use crate::router::RouterHandle;

pub(crate) mod connect;

type ClientTlsTransport =
    CountingIo<futures_rustls::client::TlsStream<Pin<Box<AsyncStream<TcpStream>>>>>;
type ClientTlsInput = BufReader<Compat<ReadHalf<ClientTlsTransport>>>;
type ClientTlsOutput = WriteHalf<ClientTlsTransport>;

pub(crate) struct OutboundStream<A: ChunkAllocator> {
    _socket: ConnectionSocket,
    pub(crate) reader: S2sReader<A, ClientTlsInput>,
    pub(crate) writer: S2sWriter<ClientTlsOutput>,
    pub(crate) valid_until: SystemTime,
    pub(crate) connection_id: u64,
    _connection_gauge: ConnectionGauge,
}

mod bounce;
mod link;
#[cfg(test)]
mod manager_tests;
#[cfg(test)]
pub(crate) mod test_support;
pub(crate) use bounce::bounce;

type Pair = (Box<str>, Box<str>);
type Stop = Shared<BoxFuture<'static, ()>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteFailure {
    NotFound,
    Timeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteError {
    Busy,
    Stopped,
    Backoff(RemoteFailure),
}

pub(crate) struct RemoteRouter<A: ChunkAllocator> {
    inner: Arc<Inner<A>>,
}

impl<A: ChunkAllocator> Clone for RemoteRouter<A> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct Inner<A: ChunkAllocator> {
    hosts: Hosts,
    trust: Arc<PeerTrust>,
    resolver: Arc<Resolver>,
    limits: S2sLimits,
    allocator: A,
    metrics: Arc<S2sMetrics>,
    state: PlMutex<State<A>>,
    work: WorkHandle,
    group: async_lock::Mutex<WorkGroup>,
    stopped: Stop,
}

struct Launch<A: ChunkAllocator> {
    guard: WorkGuard,
    pair: Pair,
    counters: Arc<QueueCounters>,
    receiver: QueueReceiver<A>,
    failures: u32,
}

struct State<A: ChunkAllocator> {
    entries: HashMap<Pair, Entry<A>>,
    stopped: bool,
    stop: Option<oneshot::Sender<()>>,
}

enum Entry<A: ChunkAllocator> {
    Link(LinkHandle<A>),
    Backoff {
        started_at: Instant,
        delay: Duration,
        condition: RemoteFailure,
        failures: u32,
    },
}

struct LinkHandle<A: ChunkAllocator> {
    sender: Sender<Queued<A>>,
    counters: Arc<QueueCounters>,
}

#[derive(Default)]
struct QueueCounters {
    count: AtomicUsize,
    bytes: AtomicUsize,
    ready: AtomicBool,
}

struct QueueReceiver<A: ChunkAllocator>(Receiver<Queued<A>>);

impl<A: ChunkAllocator> std::ops::Deref for QueueReceiver<A> {
    type Target = Receiver<Queued<A>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<A: ChunkAllocator> Drop for QueueReceiver<A> {
    fn drop(&mut self) {
        // The sender can retain buffered stanzas after the receiver is dropped.
        self.0.close();
        while let Ok(queued) = self.0.try_recv() {
            drop(queued);
        }
    }
}

struct Reservation {
    counters: Arc<QueueCounters>,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.counters.count.fetch_sub(1, Ordering::Relaxed);
        self.counters.bytes.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

struct Queued<A: ChunkAllocator> {
    stanza: RoutedStanza<A>,
    reservation: Option<Reservation>,
}

impl<A: ChunkAllocator> Queued<A> {
    fn into_stanza(self) -> RoutedStanza<A> {
        drop(self.reservation);
        self.stanza
    }
}

impl<A: ChunkAllocator> LinkHandle<A> {
    fn enqueue(
        &self,
        stanza: RoutedStanza<A>,
        bytes: usize,
        limits: &S2sLimits,
    ) -> Result<(), RemoteError> {
        self.counters
            .count
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(1)
                    .filter(|sum| *sum <= limits.max_queued_stanzas_per_link.get())
            })
            .map_err(|_| RemoteError::Busy)?;
        if self
            .counters
            .bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes)
                    .filter(|sum| *sum <= limits.max_queued_bytes_per_link.get())
            })
            .is_err()
        {
            self.counters.count.fetch_sub(1, Ordering::Relaxed);
            return Err(RemoteError::Busy);
        }
        let queued = Queued {
            stanza,
            reservation: Some(Reservation {
                counters: Arc::clone(&self.counters),
                bytes,
            }),
        };
        self.sender.try_send(queued).map_err(|_| RemoteError::Busy)
    }
}

impl<A: ChunkAllocator> State<A> {
    fn find(&self, local: &str, remote: &str) -> Option<&Entry<A>> {
        self.entries
            .iter()
            .find(|((l, r), _)| l.as_ref() == local && r.as_ref() == remote)
            .map(|(_, entry)| entry)
    }

    fn retry_count(
        &mut self,
        local: &str,
        remote: &str,
        now: Instant,
        capacity: usize,
    ) -> Result<u32, RemoteError> {
        match self.find(local, remote) {
            Some(Entry::Backoff {
                started_at,
                delay,
                condition,
                failures,
            }) => {
                if now.saturating_duration_since(*started_at) < *delay {
                    return Err(RemoteError::Backoff(*condition));
                }
                return Ok(*failures);
            }
            Some(Entry::Link(_)) => return Ok(0),
            None => {}
        }
        if self.entries.len() >= capacity {
            let candidate = self
                .entries
                .iter()
                .filter_map(|(pair, entry)| {
                    if let Entry::Backoff {
                        started_at, delay, ..
                    } = entry
                    {
                        now.saturating_duration_since(*started_at)
                            .checked_sub(*delay)
                            .map(|overdue| (pair, overdue))
                    } else {
                        None
                    }
                })
                .max_by(|(a, overdue_a), (b, overdue_b)| {
                    overdue_a.cmp(overdue_b).then_with(|| b.cmp(a))
                })
                .map(|(pair, _)| pair.clone());
            let Some(candidate) = candidate else {
                return Err(RemoteError::Busy);
            };
            self.entries.remove(&candidate);
        }
        Ok(0)
    }

    fn owns(&self, pair: &Pair, counters: &Arc<QueueCounters>) -> bool {
        matches!(self.entries.get(pair), Some(Entry::Link(link)) if Arc::ptr_eq(&link.counters, counters))
    }
}

impl<A: ChunkAllocator + Clone> RemoteRouter<A> {
    pub(crate) fn new(
        hosts: Hosts,
        trust: Arc<PeerTrust>,
        resolver: Arc<Resolver>,
        limits: &S2sLimits,
        allocator: A,
        metrics: Arc<S2sMetrics>,
    ) -> Self {
        let group = WorkGroup::new();
        let work = group.handle();
        let (stop, stopped) = oneshot::channel();
        let inner = Arc::new(Inner {
            hosts,
            trust,
            resolver,
            limits: limits.clone(),
            allocator,
            metrics,
            state: PlMutex::new(State {
                entries: HashMap::new(),
                stopped: false,
                stop: Some(stop),
            }),
            work,
            group: async_lock::Mutex::new(group),
            stopped: async move {
                let _ = stopped.await;
            }
            .boxed()
            .shared(),
        });
        let source: Arc<dyn LinkStats> = inner.clone();
        inner.metrics.set_link_source(Arc::downgrade(&source));
        Self { inner }
    }

    pub(crate) fn route(
        &self,
        router: &RouterHandle<A>,
        local: &str,
        remote: &str,
        stanza: RoutedStanza<A>,
    ) -> Result<(), RemoteError> {
        let Some(task) = self.admit(local, remote, stanza)? else {
            return Ok(());
        };
        let inner = Arc::clone(&self.inner);
        let router = router.clone();
        compio::runtime::spawn(task.guard.run(link::run(
            inner,
            router,
            task.pair,
            task.counters,
            task.receiver,
            task.failures,
        )))
        .detach();
        Ok(())
    }

    fn admit(
        &self,
        local: &str,
        remote: &str,
        stanza: RoutedStanza<A>,
    ) -> Result<Option<Launch<A>>, RemoteError> {
        let bytes = stanza_bytes(&stanza);
        let mut state = self.inner.state.lock();
        if state.stopped {
            self.inner
                .metrics
                .admission_rejected(AdmissionReason::Stopped);
            return Err(RemoteError::Stopped);
        }
        let Some(bytes) = bytes else {
            self.inner
                .metrics
                .admission_rejected(AdmissionReason::QueueFull);
            return Err(RemoteError::Busy);
        };
        let failures = match state.retry_count(
            local,
            remote,
            Instant::now(),
            self.inner.limits.max_outbound_links.get(),
        ) {
            Ok(failures) => failures,
            Err(error) => {
                self.inner.metrics.admission_rejected(
                    if matches!(error, RemoteError::Backoff(_)) {
                        AdmissionReason::Backoff
                    } else {
                        AdmissionReason::LinkLimit
                    },
                );
                return Err(error);
            }
        };
        if let Some(Entry::Link(handle)) = state.find(local, remote) {
            return handle
                .enqueue(stanza, bytes, &self.inner.limits)
                .inspect_err(|_| {
                    self.inner
                        .metrics
                        .admission_rejected(AdmissionReason::QueueFull);
                })
                .map(|()| None);
        }
        let (sender, receiver) =
            async_channel::bounded(self.inner.limits.max_queued_stanzas_per_link.get());
        let counters = Arc::new(QueueCounters::default());
        let handle = LinkHandle {
            sender,
            counters: Arc::clone(&counters),
        };
        if let Err(error) = handle.enqueue(stanza, bytes, &self.inner.limits) {
            self.inner
                .metrics
                .admission_rejected(AdmissionReason::QueueFull);
            return Err(error);
        }
        let pair: Pair = (local.into(), remote.into());
        state.entries.insert(pair.clone(), Entry::Link(handle));
        let guard = self.inner.work.start();
        Ok(Some(Launch {
            guard,
            pair,
            counters,
            receiver: QueueReceiver(receiver),
            failures,
        }))
    }

    pub(crate) fn stop(&self) {
        let mut state = self.inner.state.lock();
        state.stopped = true;
        state
            .entries
            .retain(|_, entry| matches!(entry, Entry::Link(_)));
        if let Some(stop) = state.stop.take() {
            let _ = stop.send(());
        }
    }

    pub(crate) async fn join(&self, deadline: Instant) -> io::Result<()> {
        self.stop();
        compio::time::timeout_at(deadline, async {
            self.inner.group.lock().await.drain().await;
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "s2s outbound shutdown timed out"))
    }

    fn register(&self) -> Option<WorkGuard> {
        let state = self.inner.state.lock();
        (!state.stopped).then(|| self.inner.work.start())
    }

    pub(crate) fn bounce(
        &self,
        router: &RouterHandle<A>,
        stanza: RoutedStanza<A>,
        condition: lonewolf_xmpp::stanza::StanzaErrorCondition,
    ) -> Result<(), RemoteError> {
        let Some(guard) = self.register() else {
            self.inner.metrics.dropped(DropReason::Shutdown, 1);
            self.inner
                .metrics
                .admission_rejected(AdmissionReason::Stopped);
            return Err(RemoteError::Stopped);
        };
        let router = router.clone();
        compio::runtime::spawn(guard.run(async move {
            bounce(&router, &stanza, condition).await;
        }))
        .detach();
        Ok(())
    }

    pub(crate) fn unsupported(&self) {
        self.inner
            .metrics
            .admission_rejected(AdmissionReason::Unsupported);
    }
}

impl<A: ChunkAllocator> LinkStats for Inner<A> {
    fn snapshot(&self) -> LinkSnapshot {
        let state = self.state.lock();
        let mut snapshot = LinkSnapshot::default();
        for entry in state.entries.values() {
            match entry {
                Entry::Backoff { .. } => snapshot.backoff += 1,
                Entry::Link(handle) => {
                    if handle.counters.ready.load(Ordering::Relaxed) {
                        snapshot.ready += 1;
                    } else {
                        snapshot.connecting += 1;
                    }
                    snapshot.queued_stanzas += handle.counters.count.load(Ordering::Relaxed) as u64;
                    snapshot.queued_bytes += handle.counters.bytes.load(Ordering::Relaxed) as u64;
                }
            }
        }
        snapshot
    }
}

fn stanza_bytes<A: ChunkAllocator>(stanza: &RoutedStanza<A>) -> Option<usize> {
    struct Counter(usize);
    impl std::fmt::Write for Counter {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            self.0 = self.0.checked_add(value.len()).ok_or(std::fmt::Error)?;
            Ok(())
        }
    }
    let mut counter = Counter(0);
    stanza.resolve().ok()?.write_xml(&mut counter).ok()?;
    Some(counter.0)
}

fn backoff_delay(limits: &S2sLimits, failures: u32, jitter: u16) -> Duration {
    let maximum = u128::from(limits.failure_backoff_max_secs.get()) * 1_000_000_000;
    let initial = u128::from(limits.failure_backoff_initial_secs.get()) * 1_000_000_000;
    let nominal = 1_u128
        .checked_shl(failures.saturating_sub(1))
        .and_then(|factor| initial.checked_mul(factor))
        .unwrap_or(maximum)
        .min(maximum);
    let nanos = (nominal * u128::from(jitter) / 1000).min(maximum);
    Duration::new(
        (nanos / 1_000_000_000) as u64,
        (nanos % 1_000_000_000) as u32,
    )
}

fn jitter() -> u16 {
    draw_jitter(|bytes| graviola::random::fill(bytes).is_ok())
}

fn draw_jitter(mut fill: impl FnMut(&mut [u8]) -> bool) -> u16 {
    const RANGE: u32 = 401;
    const CEILING: u32 = (u16::MAX as u32 + 1) / RANGE * RANGE;
    loop {
        let mut bytes = [0; 2];
        if !fill(&mut bytes) {
            return 1000;
        }
        let value = u32::from(u16::from_ne_bytes(bytes));
        if value < CEILING {
            return 800 + (value % RANGE) as u16;
        }
    }
}

async fn stopping<F: std::future::Future>(stop: Stop, work: F) -> Option<F::Output> {
    match select(stop, std::pin::pin!(work)).await {
        Either::Left(_) => None,
        Either::Right((value, _)) => Some(value),
    }
}

impl<A: ChunkAllocator> Inner<A> {
    fn remove(&self, pair: &Pair, counters: &Arc<QueueCounters>) {
        let mut state = self.state.lock();
        if state.owns(pair, counters) {
            state.entries.remove(pair);
        }
    }

    fn failed(
        &self,
        pair: &Pair,
        counters: &Arc<QueueCounters>,
        failures: u32,
        condition: RemoteFailure,
        now: Instant,
        jitter: u16,
    ) -> bool {
        let mut state = self.state.lock();
        if !state.owns(pair, counters) {
            return false;
        }
        if state.stopped {
            state.entries.remove(pair);
            return false;
        }
        let failures = failures.saturating_add(1);
        state.entries.insert(
            pair.clone(),
            Entry::Backoff {
                started_at: now,
                delay: backoff_delay(&self.limits, failures, jitter),
                condition,
                failures,
            },
        );
        true
    }
}

fn ready(counters: &QueueCounters, failures: &mut u32) {
    *failures = 0;
    counters.ready.store(true, Ordering::Relaxed);
}
