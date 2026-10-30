// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::num::NonZeroUsize;

use lonewolf_util::arena::GlobalChunkAllocator;

use super::*;

type TestResult<T> = Result<T, Box<dyn Error>>;

pub(crate) enum AdmissionState {
    Link,
    Backoff(RemoteFailure),
}

pub(crate) struct Fixture {
    hosts: Hosts,
    remote: RemoteRouter<GlobalChunkAllocator>,
    pair: Pair,
    counters: Arc<QueueCounters>,
    receiver: Option<QueueReceiver<GlobalChunkAllocator>>,
    guard: Option<WorkGuard>,
}

impl Fixture {
    pub(crate) fn new(initial: AdmissionState) -> TestResult<Self> {
        Self::with_capacity(initial, NonZeroUsize::MIN)
    }

    pub(crate) fn with_capacity(
        initial: AdmissionState,
        capacity: NonZeroUsize,
    ) -> TestResult<Self> {
        Self::with_hosts_and_pair(
            initial,
            capacity,
            crate::hosts::test_support::managed_hosts()?,
            ("example.com".into(), "remote.test".into()),
        )
    }

    pub(crate) fn with_hosts_and_pair(
        initial: AdmissionState,
        capacity: NonZeroUsize,
        hosts: Hosts,
        pair: Pair,
    ) -> TestResult<Self> {
        let config = crate::config::Config::default();
        let trust = PeerTrust::load(&config.s2s.tls, hosts.crypto_provider())?;
        let limits = S2sLimits {
            max_queued_stanzas_per_link: capacity,
            ..Default::default()
        };
        let remote = RemoteRouter::new(
            hosts.clone(),
            trust,
            Arc::new(Resolver::new(&config.s2s)?),
            &limits,
            GlobalChunkAllocator,
            S2sMetrics::new(0),
        );
        let counters = Arc::new(QueueCounters::default());
        let (receiver, guard) = {
            let mut state = remote.inner.state.lock();
            match initial {
                AdmissionState::Link => {
                    let (sender, receiver) =
                        async_channel::bounded(limits.max_queued_stanzas_per_link.get());
                    state.entries.insert(
                        pair.clone(),
                        Entry::Link(LinkHandle {
                            sender,
                            counters: Arc::clone(&counters),
                        }),
                    );
                    (
                        Some(QueueReceiver(receiver)),
                        Some(remote.inner.work.start()),
                    )
                }
                AdmissionState::Backoff(condition) => {
                    state.entries.insert(
                        pair.clone(),
                        Entry::Backoff {
                            started_at: Instant::now(),
                            delay: backoff_delay(&limits, 1, 1000),
                            condition,
                            failures: 1,
                        },
                    );
                    (None, None)
                }
            }
        };
        Ok(Self {
            hosts,
            remote,
            pair,
            counters,
            receiver,
            guard,
        })
    }

    pub(crate) fn metrics(&self) -> Arc<S2sMetrics> {
        Arc::clone(&self.remote.inner.metrics)
    }

    pub(crate) fn hosts(&self) -> Hosts {
        self.hosts.clone()
    }

    pub(crate) fn remote(&self) -> RemoteRouter<GlobalChunkAllocator> {
        self.remote.clone()
    }

    pub(crate) fn receive(&self) -> TestResult<Option<RoutedStanza<GlobalChunkAllocator>>> {
        let receiver = self.receiver.as_ref().ok_or("fixture has no link queue")?;
        match receiver.try_recv() {
            Ok(queued) => Ok(Some(queued.into_stanza())),
            Err(async_channel::TryRecvError::Empty) => Ok(None),
            Err(async_channel::TryRecvError::Closed) => Err("fixture queue is closed".into()),
        }
    }

    pub(crate) fn occupancy(&self) -> (usize, usize) {
        (
            self.counters.count.load(Ordering::Relaxed),
            self.counters.bytes.load(Ordering::Relaxed),
        )
    }

    pub(crate) fn snapshot(&self) -> LinkSnapshot {
        self.remote.inner.snapshot()
    }

    fn cleanup(&mut self) {
        self.remote.stop();
        {
            let mut state = self.remote.inner.state.lock();
            if state.owns(&self.pair, &self.counters) {
                state.entries.remove(&self.pair);
            }
        }
        drop(self.receiver.take());
        drop(self.guard.take());
    }

    pub(crate) async fn finish(&mut self, deadline: Instant) -> std::io::Result<()> {
        self.cleanup();
        self.remote.join(deadline).await
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.cleanup();
    }
}
