// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io;
use std::mem;
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use crossbeam_utils::CachePadded;
use futures_channel::oneshot;
use lonewolf_extension::delivery::SessionTag;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{ArenaRead, ChunkAllocator};
#[cfg(test)]
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{PresenceType, StanzaRef, StanzaType};
use parking_lot::Mutex as PlMutex;

use super::registration::{
    Registration, ResourceMatch, SessionHandle, SessionLiveness, release_deferred,
    validate_resource,
};
#[cfg(test)]
use super::shard::DirectedRecipient;
use super::shard::Shard;
#[cfg(test)]
use crate::config::limits::default_max_directed_presence_recipients_per_resource;
use crate::router::{RoutedStanza, RouterError, RouterFailure, RouterState};

// A fixed power of two keeps unrelated accounts apart regardless of worker count and allows masking.
const SHARD_COUNT: usize = 256;

const RESOURCE_QUEUE_CAPACITY: usize = 64;

pub(crate) struct LocalRouter<A: ChunkAllocator> {
    handle: LocalRouterHandle<A>,
    failure: oneshot::Receiver<RouterFailure>,
}

pub(in crate::router) struct LocalRouterHandle<A: ChunkAllocator> {
    pub(super) inner: Arc<Inner<A>>,
}

pub(super) struct Inner<A: ChunkAllocator> {
    pub(super) slots: Box<[CachePadded<Slot<A>>]>,
    hash_state: RandomState,
    lifecycle: PlMutex<Lifecycle>,
    allocator: A,
}

pub(super) struct Slot<A: ChunkAllocator> {
    pub(super) shard: async_lock::Mutex<Shard<A>>,
    pub(super) pending: PlMutex<Vec<PendingCleanup>>,
}

pub(super) struct PendingCleanup {
    pub(super) account: AccountKey,
    pub(super) resource: Box<str>,
    pub(super) token: u64,
}

struct Lifecycle {
    state: RouterState,
    failure: Option<RouterFailure>,
    notify: Option<oneshot::Sender<RouterFailure>>,
}

impl<A: ChunkAllocator + Clone> LocalRouter<A> {
    #[cfg(test)]
    pub(crate) fn new(allocator: A) -> Self {
        Self::with_options(
            allocator,
            default_max_directed_presence_recipients_per_resource(),
        )
    }

    pub(crate) fn with_options(
        allocator: A,
        max_directed_presence_recipients_per_resource: NonZeroUsize,
    ) -> Self {
        let (notify, failure) = oneshot::channel();
        let slots = (0..SHARD_COUNT)
            .map(|_| {
                CachePadded::new(Slot {
                    shard: async_lock::Mutex::new(Shard::with_directed_presence_limit(
                        max_directed_presence_recipients_per_resource,
                    )),
                    pending: PlMutex::new(Vec::new()),
                })
            })
            .collect();
        Self {
            handle: LocalRouterHandle {
                inner: Arc::new(Inner {
                    slots,
                    hash_state: RandomState::new(),
                    lifecycle: PlMutex::new(Lifecycle {
                        state: RouterState::Running,
                        failure: None,
                        notify: Some(notify),
                    }),
                    allocator,
                }),
            },
            failure,
        }
    }

    pub(in crate::router) fn handle(&self) -> LocalRouterHandle<A> {
        self.handle.clone()
    }

    pub(crate) fn state(&self) -> RouterState {
        self.handle.state()
    }

    pub(crate) fn stop(&self) {
        let mut lifecycle = self.handle.inner.lifecycle.lock();
        if lifecycle.state == RouterState::Running {
            lifecycle.state = RouterState::Stopping;
        }
    }

    pub(crate) async fn failure(&mut self) -> RouterFailure {
        let failure = if let RouterState::Failed(failure) = self.state() {
            failure
        } else {
            match (&mut self.failure).await {
                Ok(failure) => failure,
                Err(_) => return std::future::pending().await,
            }
        };
        for slot in &self.handle.inner.slots {
            slot.shard.lock().await.terminate();
        }
        failure
    }

    pub(crate) async fn shutdown(self) -> io::Result<()> {
        self.stop();
        for slot in &self.handle.inner.slots {
            slot.shard.lock().await.terminate();
        }
        match self.handle.inner.lifecycle.lock().failure {
            Some(failure) => Err(io::Error::other(failure)),
            None => Ok(()),
        }
    }
}

impl<A: ChunkAllocator> Drop for Inner<A> {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            slot.shard.get_mut().terminate();
        }
    }
}

impl<A: ChunkAllocator> Drop for LocalRouterHandle<A> {
    fn drop(&mut self) {
        // Waking another task while this thread unwinds aborts the process.
        if std::thread::panicking() {
            mem::forget(Arc::clone(&self.inner));
        }
    }
}

impl<A: ChunkAllocator> Clone for LocalRouterHandle<A> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<A: ChunkAllocator + Clone> LocalRouterHandle<A> {
    pub(in crate::router) fn allocator(&self) -> A {
        self.inner.allocator.clone()
    }

    pub(crate) async fn resource_match(
        &self,
        account: &AccountKey,
        resource: &str,
    ) -> Result<Option<ResourceMatch>, RouterError> {
        self.with_shard(self.shard_index(account.as_str()), |shard| {
            shard.resource_match(account, resource)
        })
        .await
    }

    pub(crate) async fn register(
        &self,
        account: &AccountKey,
        requested: Option<&str>,
        limit: NonZeroUsize,
    ) -> Result<Registration<A>, RouterError> {
        release_deferred();
        if self.state() != RouterState::Running {
            return Err(RouterError::Stopped);
        }
        let requested = requested
            .map(|resource| validate_resource(account, resource, self.allocator()))
            .transpose()?;
        let (outbound, inbound) = async_channel::bounded(RESOURCE_QUEUE_CAPACITY);
        self.with_shard(self.shard_index(account.as_str()), |shard| {
            shard.register(
                account.clone(),
                requested,
                limit,
                outbound,
                inbound,
                self.clone(),
            )
        })
        .await?
    }

    pub(crate) async fn deliver_full(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        self.deliver_full_or_chat_fallback(stanza, false, None)
            .await
    }

    pub(crate) async fn deliver_full_guarded(
        &self,
        stanza: RoutedStanza<A>,
        source: SessionLiveness,
    ) -> Result<(), RouterError> {
        self.deliver_full_or_chat_fallback(stanza, false, Some(source))
            .await
    }

    pub(crate) async fn deliver_message(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        self.deliver_full_or_chat_fallback(stanza, true, None).await
    }

    pub(super) async fn deliver_full_or_chat_fallback(
        &self,
        stanza: RoutedStanza<A>,
        fallback_chat: bool,
        source: Option<SessionLiveness>,
    ) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            self.full_target_shard(&view)?
        };
        self.with_shard(shard, |shard| match &source {
            Some(source) => shard.deliver_with_guard(stanza, fallback_chat, || source.is_alive()),
            None => shard.deliver(stanza, fallback_chat),
        })
        .await?
    }

    pub(crate) async fn deliver_iq_request(
        &self,
        stanza: RoutedStanza<A>,
        subscribed: bool,
        source: Option<SessionLiveness>,
    ) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            self.full_target_shard(&view)?
        };
        self.with_shard(shard, |shard| {
            shard.deliver_iq_request(stanza, subscribed, source)
        })
        .await?
    }

    pub(crate) async fn deliver_bare(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            self.bare_target_shard(&view)?
        };
        self.with_shard(shard, |shard| shard.deliver_bare(stanza, false))
            .await?
    }

    pub(crate) async fn deliver_presence(
        &self,
        stanza: RoutedStanza<A>,
    ) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            self.bare_target_shard(&view)?
        };
        self.with_shard(shard, |shard| shard.deliver_presence(stanza, None))
            .await?
    }

    pub(crate) async fn deliver_presence_guarded(
        &self,
        stanza: RoutedStanza<A>,
        source: SessionLiveness,
    ) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            self.bare_target_shard(&view)?
        };
        self.with_shard(shard, |shard| shard.deliver_presence(stanza, Some(&source)))
            .await?
    }

    pub(crate) async fn deliver_presence_error(
        &self,
        stanza: RoutedStanza<A>,
    ) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            if view.stanza_type() != StanzaType::Presence(PresenceType::Error) {
                return Err(RouterError::InvalidTarget);
            }
            self.bare_target_shard(&view)?
        };
        self.with_shard(shard, |shard| {
            shard.deliver_presence_where(stanza, |session| session.priority.is_some())
        })
        .await?
    }

    pub(crate) async fn deliver_presence_to_tagged(
        &self,
        tag: SessionTag,
        stanza: RoutedStanza<A>,
    ) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            self.bare_target_shard(&view)?
        };
        self.with_shard(shard, |shard| shard.deliver_presence_to_tagged(tag, stanza))
            .await?
    }

    pub(crate) async fn presence_snapshot(
        &self,
        account: &AccountKey,
    ) -> Result<Vec<RoutedStanza<A>>, RouterError> {
        self.with_shard(self.shard_index(account.as_str()), |shard| {
            shard.presence_snapshot(account)
        })
        .await
    }

    pub(crate) async fn withdrawal_snapshot(
        &self,
        account: &AccountKey,
    ) -> Result<Vec<RoutedStanza<A>>, RouterError> {
        self.with_shard(self.shard_index(account.as_str()), |shard| {
            shard.withdrawal_snapshot(account)
        })
        .await
    }

    pub(crate) async fn deliver_to_tagged(
        &self,
        account: &AccountKey,
        tag: SessionTag,
        mut build: impl FnMut(&str) -> Result<RoutedStanza<A>, RouterError> + Send + 'static,
    ) -> Result<(), RouterError> {
        self.with_shard(self.shard_index(account.as_str()), |shard| {
            shard.deliver_to_tagged(account, tag, &mut build)
        })
        .await?
    }

    #[cfg(test)]
    pub(crate) async fn has_directed_grant(
        &self,
        account: &AccountKey,
        resource: &str,
        observer: JidRef<'_>,
    ) -> Result<bool, RouterError> {
        let observer = DirectedRecipient::new(observer);
        self.with_shard(self.shard_index(account.as_str()), |shard| {
            shard.has_directed_grant(account, resource, &observer)
        })
        .await
    }

    pub(crate) async fn probe(
        &self,
        requester: &SessionHandle<A>,
        request: &RoutedStanza<A>,
        subscribed: bool,
    ) -> Result<(), RouterError> {
        let source = request
            .resolve()
            .map_err(|_| RouterError::InvalidTarget)?
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if let Some(unavailable) = self
            .with_shard(self.shard_index(source.bare().as_str()), |shard| {
                shard.probe(requester, request, subscribed)
            })
            .await??
        {
            self.with_shard(requester.shard, |shard| {
                shard.prune_directed(&unavailable, Some(requester.token))
            })
            .await??;
        }
        Ok(())
    }

    pub(crate) async fn retire_account(&self, account: &AccountKey) -> Result<(), RouterError> {
        self.with_shard(self.shard_index(account.as_str()), |shard| {
            shard.retire_account(account)
        })
        .await
    }
}

impl<A: ChunkAllocator> LocalRouterHandle<A> {
    pub(in crate::router) fn state(&self) -> RouterState {
        self.inner.lifecycle.lock().state
    }

    /// The operation must borrow, not own, values whose drop can wake a task.
    pub(super) async fn with_shard<R>(
        &self,
        index: usize,
        operation: impl FnOnce(&mut Shard<A>) -> R,
    ) -> Result<R, RouterError> {
        let mut shard = self.inner.slots[index].shard.lock().await;
        self.run_locked(index, &mut shard, operation)
    }

    pub(super) fn try_with_shard<R>(
        &self,
        index: usize,
        operation: impl FnOnce(&mut Shard<A>) -> R,
    ) -> Option<Result<R, RouterError>> {
        let mut shard = self.inner.slots[index].shard.try_lock()?;
        Some(self.run_locked(index, &mut shard, operation))
    }

    fn run_locked<R>(
        &self,
        index: usize,
        shard: &mut Shard<A>,
        operation: impl FnOnce(&mut Shard<A>) -> R,
    ) -> Result<R, RouterError> {
        if shard.terminated || matches!(self.state(), RouterState::Failed(_)) {
            return Err(RouterError::Stopped);
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            let pending = mem::take(&mut *self.inner.slots[index].pending.lock());
            for cleanup in pending {
                shard.cleanup(&cleanup.account, &cleanup.resource, cleanup.token);
            }
            operation(shard)
        }));
        match result {
            Ok(value) => Ok(value),
            Err(payload) => {
                shard.terminate();
                self.fail(RouterFailure { shard_id: index });
                drop(payload);
                Err(RouterError::Stopped)
            }
        }
    }

    fn fail(&self, failure: RouterFailure) {
        let notify = {
            let mut lifecycle = self.inner.lifecycle.lock();
            let failure = *lifecycle.failure.get_or_insert(failure);
            if lifecycle.state == RouterState::Running {
                lifecycle.state = RouterState::Failed(failure);
                lifecycle.notify.take().map(|notify| (notify, failure))
            } else {
                None
            }
        };
        if let Some((notify, failure)) = notify {
            let _ = notify.send(failure);
        }
    }

    pub(super) fn defer_cleanup(&self, index: usize, cleanup: PendingCleanup) {
        self.inner.slots[index].pending.lock().push(cleanup);
    }

    #[cfg(test)]
    pub(crate) async fn inject_panic(&self, account: &AccountKey) -> Result<(), RouterError> {
        self.with_shard(self.shard_index(account.as_str()), |_| {
            panic!("injected router panic")
        })
        .await
    }

    fn full_target_shard<R: ArenaRead>(
        &self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<usize, RouterError> {
        let to = stanza
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        to.localpart().ok_or(RouterError::InvalidTarget)?;
        to.resourcepart().ok_or(RouterError::InvalidTarget)?;
        Ok(self.shard_index(to.bare().as_str()))
    }

    fn bare_target_shard<R: ArenaRead>(
        &self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<usize, RouterError> {
        let to = stanza
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        to.localpart().ok_or(RouterError::InvalidTarget)?;
        if to.resourcepart().is_some() {
            return Err(RouterError::InvalidTarget);
        }
        Ok(self.shard_index(to.as_str()))
    }

    pub(super) fn shard_index(&self, bare: &str) -> usize {
        self.inner.hash_state.hash_one(bare) as usize & (SHARD_COUNT - 1)
    }
}

#[cfg(test)]
mod supervision_tests;
