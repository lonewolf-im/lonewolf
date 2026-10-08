// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::cell::RefCell;
use std::future::Future;
use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_channel::{Receiver, WeakSender};
use futures_channel::oneshot;
use futures_util::future::Shared;
use lonewolf_extension::delivery::SessionTag;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{JidError, JidRef};
use parking_lot::Mutex as PlMutex;

use super::shard::DirectedRecipient;
use super::shards::{LocalRouterHandle, PendingCleanup};
use crate::router::{RoutedStanza, RouterError};

type Retirement<A> = Shared<oneshot::Receiver<Retired<A>>>;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ResourceMatch {
    pub(crate) token: u64,
}

pub(crate) struct DirectedWithdrawal {
    pub(crate) source_token: u64,
    pub(crate) recipients: Vec<DirectedRecipient>,
}

#[derive(Clone)]
pub(super) struct SharedDirectedWithdrawal(pub(super) Arc<PlMutex<Option<DirectedWithdrawal>>>);

impl SharedDirectedWithdrawal {
    pub(super) fn take(&self) -> Option<DirectedWithdrawal> {
        self.0.lock().take()
    }
}

pub(crate) struct Withdrawal<A: ChunkAllocator> {
    pub(crate) unavailable: Option<RoutedStanza<A>>,
    pub(crate) directed: DirectedWithdrawal,
}

/// Keeps a bound resource registered until this value is dropped.
pub(crate) struct Registration<A: ChunkAllocator> {
    pub(super) account: AccountKey,
    pub(super) resource: Box<str>,
    pub(super) token: u64,
    pub(super) alive: Arc<AtomicBool>,
    /// Defer these values during panic unwinding because dropping them wakes other tasks.
    pub(super) links: mem::ManuallyDrop<Links<A>>,
}

pub(super) struct Links<A: ChunkAllocator> {
    pub(super) retired: Retirement<A>,
    pub(super) inbound: Receiver<RoutedStanza<A>>,
    pub(super) mailbox: WeakSender<RoutedStanza<A>>,
    pub(super) shard: usize,
    pub(super) router: LocalRouterHandle<A>,
}

pub(crate) struct PresenceChange<A: ChunkAllocator> {
    pub(crate) became_available: bool,
    pub(crate) became_eligible: bool,
    pub(crate) became_unavailable: bool,
    /// Write these deliveries before the update's echo to preserve mailbox order.
    pub(crate) preceding: Vec<RoutedStanza<A>>,
    /// Includes sibling presence only when this resource becomes available.
    pub(crate) siblings: Vec<RoutedStanza<A>>,
    pub(crate) directed: DirectedWithdrawal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetireCause {
    Evicted,
    AccountDeleted,
    RouterStopped,
}

pub(crate) struct Retired<A: ChunkAllocator> {
    pub(crate) cause: RetireCause,
    pub(crate) unavailable: Option<RoutedStanza<A>>,
    pub(super) directed: SharedDirectedWithdrawal,
}

impl<A: ChunkAllocator> Clone for Retired<A> {
    fn clone(&self) -> Self {
        Self {
            cause: self.cause,
            unavailable: self.unavailable.clone(),
            directed: self.directed.clone(),
        }
    }
}

impl<A: ChunkAllocator> Registration<A> {
    pub(crate) fn liveness(&self) -> SessionLiveness {
        SessionLiveness(Arc::clone(&self.alive))
    }
    pub(crate) fn account(&self) -> &AccountKey {
        &self.account
    }

    pub(crate) fn resource(&self) -> &str {
        &self.resource
    }

    pub(crate) fn full_jid(&self) -> String {
        format!("{}/{}", self.account.as_str(), self.resource)
    }

    pub(crate) async fn recv(&self) -> Option<RoutedStanza<A>> {
        self.links.inbound.recv().await.ok()
    }

    pub(crate) fn mailbox(&self) -> Mailbox<A> {
        Mailbox(self.links.inbound.clone())
    }

    pub(crate) fn take_queued(&self) -> Vec<RoutedStanza<A>> {
        take_queued(&self.links.inbound)
    }

    /// The returned future does not borrow the registration.
    pub(crate) fn wait_retired(
        &self,
    ) -> impl Future<Output = Result<Retired<A>, RouterError>> + use<A> {
        let retired = self.links.retired.clone();
        async move { retired.await.map_err(|_| RouterError::Stopped) }
    }

    #[cfg(test)]
    pub(crate) async fn end_presence(&self) -> Result<Withdrawal<A>, RouterError>
    where
        A: Clone,
    {
        self.handle().end_presence().await
    }

    #[cfg(test)]
    pub(crate) async fn finish_presence(&self) -> Result<(), RouterError>
    where
        A: Clone,
    {
        self.handle().finish_presence(self.token).await
    }

    pub(crate) fn handle(&self) -> SessionHandle<A>
    where
        A: Clone,
    {
        SessionHandle {
            account: self.account.clone(),
            resource: self.resource.clone(),
            token: self.token,
            shard: self.links.shard,
            retired: self.links.retired.clone(),
            router: self.links.router.clone(),
            liveness: self.liveness(),
            mailbox: self.links.mailbox.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct SessionLiveness(Arc<AtomicBool>);

impl SessionLiveness {
    pub(crate) fn is_alive(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub(crate) struct Mailbox<A: ChunkAllocator>(Receiver<RoutedStanza<A>>);

impl<A: ChunkAllocator> Mailbox<A> {
    pub(crate) fn take_queued(&self) -> Vec<RoutedStanza<A>> {
        take_queued(&self.0)
    }
}

pub(super) fn take_queued<A: ChunkAllocator>(
    inbound: &Receiver<RoutedStanza<A>>,
) -> Vec<RoutedStanza<A>> {
    let mut queued = Vec::new();
    while let Ok(delivery) = inbound.try_recv() {
        queued.push(delivery);
    }
    queued
}

pub(crate) struct SessionHandle<A: ChunkAllocator> {
    account: AccountKey,
    resource: Box<str>,
    pub(super) token: u64,
    pub(super) shard: usize,
    retired: Retirement<A>,
    pub(super) router: LocalRouterHandle<A>,
    pub(super) liveness: SessionLiveness,
    pub(super) mailbox: WeakSender<RoutedStanza<A>>,
}

impl<A: ChunkAllocator + Clone> Clone for SessionHandle<A> {
    fn clone(&self) -> Self {
        Self {
            account: self.account.clone(),
            resource: self.resource.clone(),
            token: self.token,
            shard: self.shard,
            retired: self.retired.clone(),
            router: self.router.clone(),
            liveness: self.liveness.clone(),
            mailbox: self.mailbox.clone(),
        }
    }
}

impl<A: ChunkAllocator> SessionHandle<A> {
    pub(crate) fn matches(&self, jid: JidRef<'_>) -> bool {
        jid.bare().as_str() == self.account.as_str()
            && jid.resourcepart() == Some(self.resource.as_ref())
    }

    pub(crate) async fn end_presence(&self) -> Result<Withdrawal<A>, RouterError> {
        match self
            .router
            .with_shard(self.shard, |shard| {
                shard.end_presence(&self.account, &self.resource, self.token)
            })
            .await?
        {
            Err(RouterError::NotFound) => {
                let retired = self
                    .retired
                    .clone()
                    .await
                    .map_err(|_| RouterError::Stopped)?;
                Ok(Withdrawal {
                    unavailable: retired.unavailable,
                    directed: retired.directed.take().unwrap_or(DirectedWithdrawal {
                        source_token: self.token,
                        recipients: Vec::new(),
                    }),
                })
            }
            result => result,
        }
    }

    pub(crate) async fn finish_presence(&self, token: u64) -> Result<(), RouterError> {
        if token != self.token {
            return Err(RouterError::NotFound);
        }
        self.router
            .with_shard(self.shard, |shard| {
                shard.finish_presence(&self.account, token)
            })
            .await
    }

    pub(crate) async fn replacement_is_available(&self) -> Result<bool, RouterError> {
        self.router
            .with_shard(self.shard, |shard| {
                shard.replacement_is_available(&self.account, &self.resource, self.token)
            })
            .await
    }

    pub(crate) async fn record_directed_presence(
        &self,
        recipient: DirectedRecipient,
        available: bool,
    ) -> Result<(), RouterError> {
        self.router
            .with_shard(self.shard, |shard| {
                shard.record_directed_presence(
                    &self.account,
                    &self.resource,
                    self.token,
                    recipient,
                    available,
                )
            })
            .await?
    }

    pub(crate) async fn tag(&self, tag: SessionTag) -> Result<(), RouterError> {
        self.router
            .with_shard(self.shard, |shard| {
                shard.tag(&self.account, &self.resource, self.token, tag)
            })
            .await?
    }

    pub(crate) async fn set_presence(
        &self,
        priority: Option<i8>,
        stanza: RoutedStanza<A>,
        unavailable: Option<RoutedStanza<A>>,
    ) -> Result<PresenceChange<A>, RouterError> {
        self.router
            .with_shard(self.shard, |shard| {
                shard.presence(
                    &self.account,
                    &self.resource,
                    self.token,
                    priority,
                    stanza,
                    unavailable,
                )
            })
            .await?
    }
}

impl<A: ChunkAllocator + Clone> SessionHandle<A> {
    /// The caller holds the source and recipient account ticket through delivery.
    pub(crate) async fn directed_presence(
        &self,
        stanza: RoutedStanza<A>,
        available: bool,
    ) -> Result<(), RouterError> {
        let (recipient, full) = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            let sender = view
                .from()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            if sender.bare().as_str() != self.account.as_str()
                || sender.resourcepart() != Some(self.resource.as_ref())
            {
                return Err(RouterError::InvalidTarget);
            }
            let to = view
                .to()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            (DirectedRecipient::new(to), to.resourcepart().is_some())
        };
        self.record_directed_presence(recipient, available).await?;
        let delivered = match (full, available) {
            (true, true) => {
                self.router
                    .deliver_full_guarded(stanza, self.liveness.clone())
                    .await
            }
            (true, false) => self.router.deliver_full(stanza).await,
            (false, true) => {
                self.router
                    .deliver_presence_guarded(stanza, self.liveness.clone())
                    .await
            }
            (false, false) => self.router.deliver_presence(stanza).await,
        };
        match delivered {
            Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

struct RegistrationCleanup<A: ChunkAllocator> {
    links: Links<A>,
    account: AccountKey,
    resource: Box<str>,
    token: u64,
}

impl<A: ChunkAllocator> Drop for RegistrationCleanup<A> {
    fn drop(&mut self) {
        if self
            .links
            .router
            .try_with_shard(self.links.shard, |shard| {
                shard.cleanup(&self.account, &self.resource, self.token)
            })
            .is_none()
        {
            self.links.router.defer_cleanup(
                self.links.shard,
                PendingCleanup {
                    account: self.account.clone(),
                    resource: mem::take(&mut self.resource),
                    token: self.token,
                },
            );
        }
    }
}

impl<A: ChunkAllocator> Drop for Registration<A> {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        // SAFETY: `links` is taken exactly once, here, and never touched again.
        let links = unsafe { mem::ManuallyDrop::take(&mut self.links) };
        let cleanup = RegistrationCleanup {
            links,
            account: self.account.clone(),
            resource: mem::take(&mut self.resource),
            token: self.token,
        };
        if std::thread::panicking() {
            // Waking another task while this thread unwinds aborts the process.
            DEFERRED.with(|deferred| deferred.borrow_mut().push(Box::new(cleanup)));
        } else {
            drop(cleanup);
            release_deferred();
        }
    }
}

thread_local! {
    static DEFERRED: RefCell<Vec<Box<dyn Any>>> = const { RefCell::new(Vec::new()) };
}

/// Deferred registration cleanup must run outside panic unwinding.
pub(crate) fn release_deferred() {
    if std::thread::panicking() {
        return;
    }
    let deferred = DEFERRED.with(|deferred| mem::take(&mut *deferred.borrow_mut()));
    drop(deferred);
}

pub(super) fn validate_resource<A: ChunkAllocator>(
    account: &AccountKey,
    input: &str,
    allocator: A,
) -> Result<Box<str>, RouterError> {
    let mut arena =
        Arena::try_new_in(Default::default(), allocator).map_err(|_| RouterError::Unavailable)?;
    let jid = lonewolf_xmpp::jid::Jid::from_parts_in(
        Some(account.username()),
        account.domain(),
        Some(input),
        &mut arena,
    )
    .map_err(|error| match error {
        JidError::AllocationFailed(_) | JidError::AccessFailed(_) => RouterError::Unavailable,
        _ => RouterError::InvalidResource,
    })?;
    jid.resolve(&arena)
        .map_err(|_| RouterError::Unavailable)?
        .resourcepart()
        .ok_or(RouterError::InvalidResource)
        .map(Into::into)
}
