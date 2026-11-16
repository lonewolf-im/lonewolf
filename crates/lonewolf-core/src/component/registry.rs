// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{BTreeMap, hash_map::RandomState};
use std::hash::BuildHasher;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use async_channel::{Receiver, Sender, TrySendError};
use lonewolf_auth::component::ComponentSecret;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::RoutedStanza;
use parking_lot::Mutex as PlMutex;

use super::metrics::{AdmissionReason, ComponentMetrics, DropReason, QueueSnapshot, QueueStats};
use crate::config::{ComponentBalancing, ComponentLimits, ComponentsConfig};
use crate::xml_stream::serialized_len;

pub(crate) const NOT_CONNECTED_TEXT: &str =
    "The service at this domain is not connected. Try again later.";

pub(crate) struct ComponentRegistry<A: ChunkAllocator> {
    inner: Arc<Inner<A>>,
}

impl<A: ChunkAllocator> Clone for ComponentRegistry<A> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct Inner<A: ChunkAllocator> {
    slots: BTreeMap<Box<str>, Slot<A>>,
    limits: QueueLimits,
    metrics: Arc<ComponentMetrics>,
    stopped: AtomicBool,
    next_id: AtomicU64,
    random_state: RandomState,
    random_counter: AtomicU64,
}

struct Slot<A: ChunkAllocator> {
    domain: Arc<str>,
    secret: ComponentSecret,
    max_connections: usize,
    balancing: ComponentBalancing,
    attachments: PlMutex<Vec<Attachment<A>>>,
}

struct QueueLimits {
    stanzas: usize,
    bytes: usize,
}

struct Attachment<A: ChunkAllocator> {
    id: u64,
    sender: Sender<Queued<A>>,
    counters: Arc<QueueCounters>,
}

#[derive(Default)]
struct QueueCounters {
    stanzas: AtomicUsize,
    bytes: AtomicUsize,
}

struct Reservation {
    counters: Arc<QueueCounters>,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.counters.stanzas.fetch_sub(1, Ordering::Relaxed);
        self.counters.bytes.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

struct Queued<A: ChunkAllocator> {
    stanza: RoutedStanza<A>,
    reservation: Reservation,
}

impl<A: ChunkAllocator> Queued<A> {
    fn into_parts(self) -> (RoutedStanza<A>, usize) {
        let bytes = self.reservation.bytes;
        drop(self.reservation);
        (self.stanza, bytes)
    }

    fn into_stanza(self) -> RoutedStanza<A> {
        self.into_parts().0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttachError {
    Unknown,
    Conflict,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnqueueError {
    NotConnected,
    Busy,
    Stopped,
}

impl<A: ChunkAllocator + Clone> ComponentRegistry<A> {
    pub(crate) fn new(
        config: &ComponentsConfig,
        secrets: BTreeMap<Box<str>, ComponentSecret>,
        limits: &ComponentLimits,
        metrics: Arc<ComponentMetrics>,
    ) -> Self {
        let slots = secrets
            .into_iter()
            .map(|(domain, secret)| {
                let configured = &config.domains[domain.as_ref()];
                let slot = Slot {
                    domain: Arc::from(domain.as_ref()),
                    secret,
                    max_connections: configured.max_connections.get(),
                    balancing: configured.balancing,
                    attachments: PlMutex::new(Vec::new()),
                };
                (domain, slot)
            })
            .collect();
        let inner = Arc::new(Inner {
            slots,
            limits: QueueLimits {
                stanzas: limits.max_queued_stanzas.get(),
                bytes: limits.max_queued_bytes.get(),
            },
            metrics: Arc::clone(&metrics),
            stopped: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            random_state: RandomState::new(),
            random_counter: AtomicU64::new(0),
        });
        let source: Arc<dyn QueueStats> = inner.clone();
        metrics.set_queue_source(Arc::downgrade(&source));
        Self { inner }
    }

    pub(crate) fn secret(&self, domain: &str) -> Option<&ComponentSecret> {
        self.inner.slots.get(domain).map(|slot| &slot.secret)
    }

    pub(crate) fn attach(&self, domain: &str) -> Result<ComponentLink<A>, AttachError> {
        if self.inner.stopped.load(Ordering::Acquire) {
            return Err(AttachError::Stopped);
        }
        let slot = self.inner.slots.get(domain).ok_or(AttachError::Unknown)?;
        let mut attachments = slot.attachments.lock();
        if self.inner.stopped.load(Ordering::Acquire) {
            return Err(AttachError::Stopped);
        }
        if attachments.len() >= slot.max_connections {
            return Err(AttachError::Conflict);
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = async_channel::bounded(self.inner.limits.stanzas);
        let counters = Arc::new(QueueCounters::default());
        attachments.push(Attachment {
            id,
            sender,
            counters: Arc::clone(&counters),
        });
        Ok(ComponentLink {
            domain: Arc::clone(&slot.domain),
            id,
            receiver: Some(receiver),
            counters,
            registry: self.clone(),
        })
    }

    pub(crate) fn enqueue(
        &self,
        domain: &str,
        stanza: RoutedStanza<A>,
    ) -> Result<(), EnqueueError> {
        self.inner.admit(domain, None, stanza)
    }

    pub(crate) fn reply(
        &self,
        domain: &str,
        connection_id: u64,
        stanza: RoutedStanza<A>,
    ) -> Result<(), EnqueueError> {
        self.inner.admit(domain, Some(connection_id), stanza)
    }

    pub(crate) fn stop(&self) {
        self.inner.stopped.store(true, Ordering::Release);
    }
}

impl<A: ChunkAllocator> Inner<A> {
    fn admit(
        &self,
        domain: &str,
        preferred: Option<u64>,
        stanza: RoutedStanza<A>,
    ) -> Result<(), EnqueueError> {
        let result = (|| {
            if self.stopped.load(Ordering::Acquire) {
                return Err(EnqueueError::Stopped);
            }
            let slot = self.slots.get(domain).ok_or(EnqueueError::NotConnected)?;
            let bytes = serialized_len(&stanza).ok_or(EnqueueError::Busy)?;
            let key = balancing_key(slot.balancing, domain, &stanza).ok_or(EnqueueError::Busy)?;
            let attachments = slot.attachments.lock();
            if self.stopped.load(Ordering::Acquire) {
                return Err(EnqueueError::Stopped);
            }
            let target = preferred
                .and_then(|id| attachments.iter().find(|attachment| attachment.id == id))
                .or_else(|| self.select(&attachments, slot.balancing, key))
                .ok_or(EnqueueError::NotConnected)?;
            target
                .enqueue(stanza, bytes, &self.limits)
                .map_err(|(error, _)| error)
        })();
        if let Err(error) = result {
            self.metrics.admission_rejected(match error {
                EnqueueError::NotConnected => AdmissionReason::NotConnected,
                EnqueueError::Busy => AdmissionReason::QueueFull,
                EnqueueError::Stopped => AdmissionReason::Stopped,
            });
        }
        result
    }

    fn select<'a>(
        &self,
        attachments: &'a [Attachment<A>],
        balancing: ComponentBalancing,
        key: &str,
    ) -> Option<&'a Attachment<A>> {
        if attachments.is_empty() {
            return None;
        }
        if balancing == ComponentBalancing::Random {
            let index = self
                .random_state
                .hash_one(self.random_counter.fetch_add(1, Ordering::Relaxed))
                as usize
                % attachments.len();
            return attachments.get(index);
        }
        attachments.iter().max_by(|first, second| {
            self.random_state
                .hash_one((key, first.id))
                .cmp(&self.random_state.hash_one((key, second.id)))
                .then_with(|| second.id.cmp(&first.id))
        })
    }
}

fn balancing_key<'a, A: ChunkAllocator>(
    balancing: ComponentBalancing,
    domain: &'a str,
    stanza: &'a RoutedStanza<A>,
) -> Option<&'a str> {
    if balancing == ComponentBalancing::Random {
        return Some(domain);
    }
    let view = stanza.resolve().ok()?;
    let jid = match balancing {
        ComponentBalancing::Source | ComponentBalancing::BareSource => view.from().ok()?,
        ComponentBalancing::Destination | ComponentBalancing::BareDestination => view.to().ok()?,
        ComponentBalancing::Random => return Some(domain),
    };
    match jid {
        Some(jid) => Some(match balancing {
            ComponentBalancing::BareSource | ComponentBalancing::BareDestination => {
                jid.bare().as_str()
            }
            _ => jid.as_str(),
        }),
        None if matches!(
            balancing,
            ComponentBalancing::Source | ComponentBalancing::BareSource
        ) =>
        {
            Some(domain)
        }
        None => None,
    }
}

impl<A: ChunkAllocator> Attachment<A> {
    fn enqueue(
        &self,
        stanza: RoutedStanza<A>,
        bytes: usize,
        limits: &QueueLimits,
    ) -> Result<(), (EnqueueError, RoutedStanza<A>)> {
        if self
            .counters
            .bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes)
                    .filter(|total| *total <= limits.bytes)
            })
            .is_err()
        {
            return Err((EnqueueError::Busy, stanza));
        }
        if self
            .counters
            .stanzas
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(1)
            })
            .is_err()
        {
            self.counters.bytes.fetch_sub(bytes, Ordering::Relaxed);
            return Err((EnqueueError::Busy, stanza));
        }
        let queued = Queued {
            stanza,
            reservation: Reservation {
                counters: Arc::clone(&self.counters),
                bytes,
            },
        };
        self.sender.try_send(queued).map_err(|error| match error {
            TrySendError::Full(queued) => (EnqueueError::Busy, queued.into_stanza()),
            TrySendError::Closed(queued) => (EnqueueError::NotConnected, queued.into_stanza()),
        })
    }
}

pub(crate) struct ComponentLink<A: ChunkAllocator> {
    domain: Arc<str>,
    id: u64,
    receiver: Option<Receiver<Queued<A>>>,
    counters: Arc<QueueCounters>,
    registry: ComponentRegistry<A>,
}

pub(crate) struct Detached<A: ChunkAllocator> {
    pub(crate) stranded: Vec<RoutedStanza<A>>,
    pub(crate) moved: u64,
}

impl<A: ChunkAllocator> ComponentLink<A> {
    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) async fn next(&mut self) -> Option<RoutedStanza<A>> {
        self.receiver
            .as_ref()?
            .recv()
            .await
            .ok()
            .map(Queued::into_stanza)
    }

    pub(crate) fn try_next(&mut self) -> Option<RoutedStanza<A>> {
        self.receiver
            .as_ref()?
            .try_recv()
            .ok()
            .map(Queued::into_stanza)
    }

    pub(crate) fn detach(mut self) -> Detached<A> {
        let (detached, _) = self.cleanup(true);
        self.registry.inner.metrics.moved(detached.moved);
        detached
    }

    pub(crate) fn discard(mut self) -> u64 {
        let (_, dropped) = self.cleanup(false);
        self.registry
            .inner
            .metrics
            .dropped(DropReason::Shutdown, dropped);
        dropped
    }

    fn cleanup(&mut self, move_queued: bool) -> (Detached<A>, u64) {
        let inner = Arc::clone(&self.registry.inner);
        let slot = &inner.slots[self.domain()];
        let mut attachments = slot.attachments.lock();
        let mut detached = Detached {
            stranded: Vec::new(),
            moved: 0,
        };
        let Some(receiver) = self.receiver.take() else {
            return (detached, 0);
        };
        if let Some(index) = attachments
            .iter()
            .position(|attachment| attachment.id == self.id)
        {
            attachments.remove(index);
        }
        receiver.close();
        let mut dropped = 0;
        while let Ok(queued) = receiver.try_recv() {
            let (stanza, bytes) = queued.into_parts();
            if !move_queued {
                dropped += 1;
                continue;
            }
            let key = balancing_key(slot.balancing, self.domain(), &stanza);
            let target = key.and_then(|key| inner.select(&attachments, slot.balancing, key));
            let stranded = match target {
                Some(target) => match target.enqueue(stanza, bytes, &inner.limits) {
                    Ok(()) => {
                        detached.moved += 1;
                        continue;
                    }
                    Err((_, stanza)) => stanza,
                },
                None => stanza,
            };
            if detached.stranded.capacity() == 0 {
                detached.stranded.reserve(
                    self.counters
                        .stanzas
                        .load(Ordering::Relaxed)
                        .saturating_add(1),
                );
            }
            detached.stranded.push(stranded);
        }
        (detached, dropped)
    }
}

impl<A: ChunkAllocator> Drop for ComponentLink<A> {
    fn drop(&mut self) {
        if self.receiver.is_none() {
            return;
        }
        let reason = if self.registry.inner.stopped.load(Ordering::Acquire) {
            DropReason::Shutdown
        } else {
            DropReason::NotBounceable
        };
        let (_, dropped) = self.cleanup(false);
        self.registry.inner.metrics.dropped(reason, dropped);
    }
}

impl<A: ChunkAllocator> QueueStats for Inner<A> {
    fn snapshot(&self) -> QueueSnapshot {
        let mut snapshot = QueueSnapshot::default();
        for slot in self.slots.values() {
            for attachment in slot.attachments.lock().iter() {
                snapshot.stanzas += attachment.counters.stanzas.load(Ordering::Relaxed) as u64;
                snapshot.bytes += attachment.counters.bytes.load(Ordering::Relaxed) as u64;
            }
        }
        snapshot
    }
}

#[cfg(test)]
mod tests;
