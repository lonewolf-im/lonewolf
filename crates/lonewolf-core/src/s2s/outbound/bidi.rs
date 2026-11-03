// SPDX-License-Identifier: Apache-2.0

use async_channel::TrySendError;

use super::*;
use crate::s2s::log_domain;
use crate::s2s::metrics::BidiHandoff;

pub(crate) struct BidiRegistration<A: ChunkAllocator + Clone + 'static> {
    inner: Arc<Inner<A>>,
    router: RouterHandle<A>,
    pair: Pair,
    id: u64,
    assigned: Receiver<LinkQueue<A>>,
    released: bool,
}

impl<A: ChunkAllocator + Clone + 'static> RemoteRouter<A> {
    /// Call this only after the peer authenticates for this domain pair.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn register_bidi(
        &self,
        router: &RouterHandle<A>,
        local: &str,
        remote: &str,
    ) -> Option<super::BidiRegistration<A>> {
        if !self.bidirectional() {
            return None;
        }
        let (pair, id, assigned) = {
            let mut state = self.inner.state.lock();
            if state.stopped {
                return None;
            }
            let pair: Pair = (local.into(), remote.into());
            let id = self.inner.next_standby.fetch_add(1, Ordering::Relaxed);
            let (sender, assigned) = async_channel::bounded(1);
            state
                .standby
                .entry(pair.clone())
                .or_default()
                .push(Standby { id, sender });
            if matches!(state.entries.get(&pair), Some(Entry::Backoff { .. })) {
                state.entries.remove(&pair);
            }
            (pair, id, assigned)
        };
        tracing::debug!(local_domain = %log_domain(local), remote_domain = %log_domain(remote), "s2s bidirectional stream registered");
        Some(BidiRegistration {
            inner: Arc::clone(&self.inner),
            router: router.clone(),
            pair,
            id,
            assigned,
            released: false,
        })
    }
}

impl<A: ChunkAllocator> State<A> {
    pub(super) fn offer_standby(
        &self,
        mut queue: LinkQueue<A>,
        metrics: &S2sMetrics,
    ) -> Result<(), LinkQueue<A>> {
        if self.stopped || !self.owns(&queue.pair, &queue.counters) {
            return Err(queue);
        }
        if let Some((pair, standbys)) = self.standby.get_key_value(&queue.pair) {
            for standby in standbys.iter().rev() {
                match standby.sender.try_send(queue) {
                    Ok(()) => {
                        metrics.bidi_handoff(BidiHandoff::InboundStream);
                        tracing::debug!(local_domain = %log_domain(&pair.0), remote_domain = %log_domain(&pair.1), target = "inbound_stream", "s2s link queue handed off");
                        return Ok(());
                    }
                    Err(TrySendError::Full(returned) | TrySendError::Closed(returned)) => {
                        queue = returned;
                    }
                }
            }
        }
        Err(queue)
    }
}

impl<A: ChunkAllocator + Clone + 'static> Inner<A> {
    pub(super) fn offer_standby(&self, queue: LinkQueue<A>) -> Result<(), LinkQueue<A>> {
        self.state.lock().offer_standby(queue, &self.metrics)
    }
}

impl<A: ChunkAllocator + Clone + 'static> BidiRegistration<A> {
    pub(super) fn inner(&self) -> &Inner<A> {
        &self.inner
    }

    pub(crate) async fn assigned(&self) -> Option<LinkQueue<A>> {
        self.assigned.recv().await.ok()
    }

    #[cfg_attr(not(test), expect(dead_code))]
    /// Pass the assigned queue to preserve queued stanzas when this stream ends.
    pub(crate) fn release(mut self, queue: Option<LinkQueue<A>>) {
        self.release_inner(queue);
        self.released = true;
    }

    fn release_inner(&mut self, queue: Option<LinkQueue<A>>) {
        let mut dropped = [None, None];
        let mut launches = [None, None];
        {
            let mut state = self.inner.state.lock();
            if let Some(standbys) = state.standby.get_mut(&self.pair) {
                standbys.retain(|standby| standby.id != self.id);
                if standbys.is_empty() {
                    state.standby.remove(&self.pair);
                }
            }
            let queues = [queue, self.assigned.try_recv().ok()];
            self.assigned.close();
            for (index, queue) in queues.into_iter().enumerate() {
                let Some(queue) = queue else { continue };
                queue.counters.ready.store(false, Ordering::Relaxed);
                let owns = state.owns(&queue.pair, &queue.counters);
                if state.stopped || !owns {
                    if owns {
                        state.entries.remove(&queue.pair);
                    }
                    dropped[index] = Some(queue);
                } else if queue.is_drained() {
                    state.entries.remove(&queue.pair);
                } else if let Err(queue) = state.offer_standby(queue, &self.inner.metrics) {
                    let guard = self.inner.work.start();
                    self.inner.metrics.bidi_handoff(BidiHandoff::DialedLink);
                    tracing::debug!(local_domain = %log_domain(&queue.pair.0), remote_domain = %log_domain(&queue.pair.1), target = "dialed_link", "s2s link queue handed off");
                    launches[index] = Some((guard, queue));
                }
            }
        }
        for mut queue in dropped.into_iter().flatten() {
            link::shutdown_queue(
                &self.inner,
                &queue.receiver,
                &queue.pair,
                &mut queue.current,
            );
        }
        for (guard, queue) in launches.into_iter().flatten() {
            compio::runtime::spawn(guard.run(link::run(
                Arc::clone(&self.inner),
                self.router.clone(),
                queue,
                0,
            )))
            .detach();
        }
    }
}

impl<A: ChunkAllocator + Clone + 'static> Drop for BidiRegistration<A> {
    fn drop(&mut self) {
        if !self.released {
            self.release_inner(None);
        }
    }
}
