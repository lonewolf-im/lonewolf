// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::cell::RefCell;
use std::collections::{HashMap, hash_map::RandomState};
use std::future::Future;
use std::hash::BuildHasher;
use std::io;
use std::mem;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;
use std::time::Instant;

use async_channel::{Receiver, Sender, TrySendError};
use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Either, Shared, poll_fn, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
use lonewolf_extension::delivery::{SessionTag, SessionTags};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_util::core_dispatcher::{DispatchHandle, Task, WorkerContext};
use lonewolf_xmpp::jid::{JidError, JidRef};
use lonewolf_xmpp::stanza::{MessageType, PresenceType, StanzaType};

use super::{RoutedStanza, RouterError};

const SHARD_QUEUE_CAPACITY: usize = 1_024;
const RESOURCE_QUEUE_CAPACITY: usize = 64;
const SHARD_BATCH_SIZE: usize = 64;

type TaggedStanzaFactory<A> = Box<dyn FnMut(&str) -> Result<RoutedStanza<A>, RouterError> + Send>;
type Retirement<A> = Shared<oneshot::Receiver<Retired<A>>>;
pub(crate) type PresenceBuilder<A> = Box<
    dyn for<'a> FnMut(PresenceSource<'a, A>) -> Result<Option<RoutedStanza<A>>, RouterError> + Send,
>;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DirectedRecipient(Box<str>);

impl DirectedRecipient {
    pub(crate) fn new(jid: JidRef<'_>) -> Self {
        Self(jid.as_str().into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    fn bare(&self) -> &str {
        self.0.split_once('/').map_or(&self.0, |(bare, _)| bare)
    }

    fn matches_prepared(&self, observer: &Self) -> bool {
        self == observer || (!self.0.contains('/') && self.bare() == observer.bare())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PresenceAccess {
    pub(crate) subscribed: bool,
    pub(crate) directed: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct PresenceSource<'a, A: ChunkAllocator> {
    pub(crate) resource: &'a str,
    pub(crate) presence: Option<&'a RoutedStanza<A>>,
    pub(crate) access: PresenceAccess,
}

pub(crate) struct DirectedWithdrawal {
    pub(crate) source_token: u64,
    pub(crate) recipients: Vec<DirectedRecipient>,
}

struct DirectedGrant {
    recipient: DirectedRecipient,
    live: Arc<AtomicBool>,
}

fn take_directed(grants: &mut Vec<DirectedGrant>, token: u64) -> DirectedWithdrawal {
    let recipients = mem::take(grants)
        .into_iter()
        .map(|grant| {
            grant.live.store(false, Ordering::Release);
            grant.recipient
        })
        .collect();
    DirectedWithdrawal {
        source_token: token,
        recipients,
    }
}

#[derive(Clone)]
struct SharedDirectedWithdrawal(Arc<Mutex<Option<DirectedWithdrawal>>>);

impl SharedDirectedWithdrawal {
    fn take(&self) -> Option<DirectedWithdrawal> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

pub(crate) struct Withdrawal<A: ChunkAllocator> {
    pub(crate) unavailable: Option<RoutedStanza<A>>,
    pub(crate) directed: DirectedWithdrawal,
}

pub(crate) struct PresenceDelivery<A: ChunkAllocator> {
    pub(crate) stanza: RoutedStanza<A>,
    source: SessionLiveness,
    target_token: Option<u64>,
    ordinary_access: bool,
    grants: [Option<Arc<AtomicBool>>; 2],
}

pub struct LocalRouter<A: ChunkAllocator> {
    handle: LocalRouterHandle<A>,
    tasks: Vec<Task<()>>,
}

pub(super) struct LocalRouterHandle<A: ChunkAllocator> {
    shards: Arc<[Sender<Command<A>>]>,
    hash_state: RandomState,
    allocator: A,
}

/// Keeps a bound resource registered until this value is dropped.
pub struct Registration<A: ChunkAllocator> {
    account: AccountKey,
    resource: Box<str>,
    token: u64,
    alive: Arc<AtomicBool>,
    /// Everything whose drop signals another task, deferred as a whole while unwinding.
    links: mem::ManuallyDrop<Links<A>>,
}

struct Links<A: ChunkAllocator> {
    _lease: oneshot::Sender<()>,
    retired: Retirement<A>,
    inbound: Receiver<RoutedStanza<A>>,
    shard: Sender<Command<A>>,
    router: LocalRouterHandle<A>,
}

pub(crate) struct PresenceChange<A: ChunkAllocator> {
    pub became_available: bool,
    pub became_eligible: bool,
    pub became_unavailable: bool,
    /// Write these deliveries before the update's echo to preserve mailbox order.
    pub preceding: Vec<RoutedStanza<A>>,
    /// Includes sibling presence only when this resource becomes available.
    pub siblings: Vec<RoutedStanza<A>>,
    pub(crate) directed: DirectedWithdrawal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetireCause {
    Evicted,
    AccountDeleted,
}

pub(crate) struct Retired<A: ChunkAllocator> {
    pub(crate) cause: RetireCause,
    pub(crate) unavailable: Option<RoutedStanza<A>>,
    directed: SharedDirectedWithdrawal,
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

enum Command<A: ChunkAllocator> {
    DirectedPresence {
        account: AccountKey,
        resource: Box<str>,
        token: u64,
        recipient: DirectedRecipient,
        available: bool,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    #[cfg_attr(not(test), allow(dead_code))]
    HasDirectedGrant {
        account: AccountKey,
        resource: Box<str>,
        observer: DirectedRecipient,
        reply: oneshot::Sender<bool>,
    },
    #[cfg_attr(not(test), allow(dead_code))]
    PresenceAccess {
        account: AccountKey,
        resource: Option<Box<str>>,
        observer: DirectedRecipient,
        subscribed: bool,
        build: PresenceBuilder<A>,
        reply: oneshot::Sender<Result<Vec<PresenceDelivery<A>>, RouterError>>,
    },
    #[cfg_attr(not(test), allow(dead_code))]
    AuthorizedDelivery {
        delivery: PresenceDelivery<A>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    Register {
        account: AccountKey,
        requested: Option<Box<str>>,
        limit: NonZeroUsize,
        outbound: Sender<RoutedStanza<A>>,
        inbound: Receiver<RoutedStanza<A>>,
        router: LocalRouterHandle<A>,
        reply: oneshot::Sender<Result<Registration<A>, RouterError>>,
    },
    Deliver {
        stanza: RoutedStanza<A>,
        fallback_chat: bool,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    DeliverBare {
        stanza: RoutedStanza<A>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    DeliverPresence {
        stanza: RoutedStanza<A>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    DeliverPresenceToTagged {
        tag: SessionTag,
        stanza: RoutedStanza<A>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    PresenceSnapshot {
        account: AccountKey,
        reply: oneshot::Sender<Vec<RoutedStanza<A>>>,
    },
    WithdrawalSnapshot {
        account: AccountKey,
        reply: oneshot::Sender<Vec<RoutedStanza<A>>>,
    },
    Tag {
        account: AccountKey,
        resource: Box<str>,
        token: u64,
        tag: SessionTag,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    DeliverToTagged {
        account: AccountKey,
        tag: SessionTag,
        build: TaggedStanzaFactory<A>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    Presence {
        account: AccountKey,
        resource: Box<str>,
        token: u64,
        priority: Option<i8>,
        stanza: RoutedStanza<A>,
        unavailable: Option<RoutedStanza<A>>,
        reply: oneshot::Sender<Result<PresenceChange<A>, RouterError>>,
    },
    EndPresence {
        account: AccountKey,
        resource: Box<str>,
        token: u64,
        reply: oneshot::Sender<Result<Withdrawal<A>, RouterError>>,
    },
    ReplacementAvailable {
        account: AccountKey,
        resource: Box<str>,
        token: u64,
        reply: oneshot::Sender<bool>,
    },
    FinishPresence {
        account: AccountKey,
        token: u64,
        reply: oneshot::Sender<()>,
    },
    RetireAccount {
        account: AccountKey,
        reply: oneshot::Sender<()>,
    },
}

struct RetiredPresence<A: ChunkAllocator> {
    resource: Box<str>,
    stanza: RoutedStanza<A>,
}

struct Session<A: ChunkAllocator> {
    token: u64,
    alive: Arc<AtomicBool>,
    outbound: Sender<RoutedStanza<A>>,
    inbound: Receiver<RoutedStanza<A>>,
    priority: Option<i8>,
    tags: SessionTags,
    presence: Option<RoutedStanza<A>>,
    unavailable: Option<RoutedStanza<A>>,
    directed: Vec<DirectedGrant>,
    retired: oneshot::Sender<Retired<A>>,
}

impl<A: ChunkAllocator> Session<A> {
    fn accepts_bare_message(&self) -> bool {
        self.alive.load(Ordering::Acquire)
            && !self.outbound.is_closed()
            && self.priority.is_some_and(|priority| priority >= 0)
    }
}

struct Shard<A: ChunkAllocator> {
    accounts: HashMap<Box<str>, HashMap<Box<str>, Session<A>>>,
    retiring: HashMap<Box<str>, HashMap<u64, RetiredPresence<A>>>,
    next_token: u64,
    cleanups: FuturesUnordered<BoxFuture<'static, (AccountKey, Box<str>, u64)>>,
}

struct Inbox<A: ChunkAllocator>(Receiver<Command<A>>);

impl<A: ChunkAllocator> Drop for Inbox<A> {
    fn drop(&mut self) {
        self.0.close();
        while self.0.try_recv().is_ok() {}
    }
}

impl<A: ChunkAllocator + Clone> LocalRouter<A> {
    /// Returns an error if a worker cannot accept its shard actor.
    pub async fn start(dispatcher: &DispatchHandle, allocator: A) -> io::Result<Self> {
        let count = dispatcher.worker_count();
        let mut senders = Vec::with_capacity(count);
        let mut tasks = Vec::with_capacity(count);
        for worker in 0..count {
            let (sender, receiver) = async_channel::bounded(SHARD_QUEUE_CAPACITY);
            let receiver = Inbox(receiver);
            let task = dispatcher
                .dispatch_at(worker, move |context| Shard::new().run(receiver, context))
                .await?;
            senders.push(sender);
            tasks.push(task);
        }
        Ok(Self {
            handle: LocalRouterHandle {
                shards: senders.into(),
                hash_state: RandomState::new(),
                allocator,
            },
            tasks,
        })
    }

    pub(super) fn handle(&self) -> LocalRouterHandle<A> {
        self.handle.clone()
    }

    pub async fn shutdown(self) -> io::Result<()> {
        for shard in self.handle.shards.iter() {
            shard.close();
        }
        for task in self.tasks {
            task.await.map_err(io::Error::other)?;
        }
        Ok(())
    }
}

impl<A: ChunkAllocator> Drop for LocalRouterHandle<A> {
    fn drop(&mut self) {
        // Waking another task while this thread unwinds aborts the process.
        if std::thread::panicking() {
            mem::forget(mem::replace(&mut self.shards, Arc::from(Vec::new())));
        }
    }
}

impl<A: ChunkAllocator + Clone> Clone for LocalRouterHandle<A> {
    fn clone(&self) -> Self {
        Self {
            shards: Arc::clone(&self.shards),
            hash_state: self.hash_state.clone(),
            allocator: self.allocator.clone(),
        }
    }
}

impl<A: ChunkAllocator + Clone> LocalRouterHandle<A> {
    pub(super) fn allocator(&self) -> A {
        self.allocator.clone()
    }

    pub(crate) async fn register(
        &self,
        account: &AccountKey,
        requested: Option<&str>,
        limit: NonZeroUsize,
    ) -> Result<Registration<A>, RouterError> {
        release_deferred();
        let requested = requested
            .map(|resource| validate_resource(account, resource, self.allocator.clone()))
            .transpose()?;
        let (reply, result) = oneshot::channel();
        let (outbound, inbound) = async_channel::bounded(RESOURCE_QUEUE_CAPACITY);
        let shard = self.shard(account.as_str()).clone();
        shard
            .send(Command::Register {
                account: account.clone(),
                requested,
                limit,
                outbound,
                inbound,
                router: self.clone(),
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    pub(crate) async fn deliver_full(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        self.deliver_full_or_chat_fallback(stanza, false).await
    }

    pub(crate) async fn deliver_message(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        self.deliver_full_or_chat_fallback(stanza, true).await
    }

    async fn deliver_full_or_chat_fallback(
        &self,
        stanza: RoutedStanza<A>,
        fallback_chat: bool,
    ) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            let to = view
                .to()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            to.resourcepart().ok_or(RouterError::InvalidTarget)?;
            to.localpart().ok_or(RouterError::InvalidTarget)?;
            self.shard_index(to.bare().as_str())
        };
        let (reply, result) = oneshot::channel();
        self.shards[shard]
            .send(Command::Deliver {
                stanza,
                fallback_chat,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    pub(crate) async fn deliver_bare(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            let to = view
                .to()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            to.localpart().ok_or(RouterError::InvalidTarget)?;
            if to.resourcepart().is_some() {
                return Err(RouterError::InvalidTarget);
            }
            self.shard_index(to.as_str())
        };
        let (reply, result) = oneshot::channel();
        self.shards[shard]
            .send(Command::DeliverBare { stanza, reply })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    pub(crate) async fn deliver_presence(
        &self,
        stanza: RoutedStanza<A>,
    ) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            let to = view
                .to()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            to.localpart().ok_or(RouterError::InvalidTarget)?;
            if to.resourcepart().is_some() {
                return Err(RouterError::InvalidTarget);
            }
            self.shard_index(to.as_str())
        };
        let (reply, result) = oneshot::channel();
        self.shards[shard]
            .send(Command::DeliverPresence { stanza, reply })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    pub(crate) async fn deliver_presence_to_tagged(
        &self,
        tag: SessionTag,
        stanza: RoutedStanza<A>,
    ) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            let to = view
                .to()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            to.localpart().ok_or(RouterError::InvalidTarget)?;
            if to.resourcepart().is_some() {
                return Err(RouterError::InvalidTarget);
            }
            self.shard_index(to.as_str())
        };
        let (reply, result) = oneshot::channel();
        self.shards[shard]
            .send(Command::DeliverPresenceToTagged { tag, stanza, reply })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    pub(crate) async fn presence_snapshot(
        &self,
        account: &AccountKey,
    ) -> Result<Vec<RoutedStanza<A>>, RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard(account.as_str())
            .send(Command::PresenceSnapshot {
                account: account.clone(),
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)
    }

    pub(crate) async fn withdrawal_snapshot(
        &self,
        account: &AccountKey,
    ) -> Result<Vec<RoutedStanza<A>>, RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard(account.as_str())
            .send(Command::WithdrawalSnapshot {
                account: account.clone(),
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)
    }

    pub(crate) async fn deliver_to_tagged(
        &self,
        account: &AccountKey,
        tag: SessionTag,
        build: impl FnMut(&str) -> Result<RoutedStanza<A>, RouterError> + Send + 'static,
    ) -> Result<(), RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard(account.as_str())
            .send(Command::DeliverToTagged {
                account: account.clone(),
                tag,
                build: Box::new(build),
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn has_directed_grant(
        &self,
        account: &AccountKey,
        resource: &str,
        observer: JidRef<'_>,
    ) -> Result<bool, RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard(account.as_str())
            .send(Command::HasDirectedGrant {
                account: account.clone(),
                resource: resource.into(),
                observer: DirectedRecipient::new(observer),
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn presence_access(
        &self,
        account: &AccountKey,
        resource: Option<Box<str>>,
        observer: DirectedRecipient,
        subscribed: bool,
        build: PresenceBuilder<A>,
    ) -> Result<Vec<PresenceDelivery<A>>, RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard(account.as_str())
            .send(Command::PresenceAccess {
                account: account.clone(),
                resource,
                observer,
                subscribed,
                build,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn authorized_delivery(
        &self,
        delivery: PresenceDelivery<A>,
    ) -> Result<(), RouterError> {
        let shard = {
            let view = delivery
                .stanza
                .resolve()
                .map_err(|_| RouterError::InvalidTarget)?;
            let to = view
                .to()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            self.shard_index(to.bare().as_str())
        };
        let (reply, result) = oneshot::channel();
        self.shards[shard]
            .send(Command::AuthorizedDelivery { delivery, reply })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    pub(crate) async fn retire_account(&self, account: &AccountKey) -> Result<(), RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard(account.as_str())
            .send(Command::RetireAccount {
                account: account.clone(),
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)
    }
}

impl<A: ChunkAllocator> LocalRouterHandle<A> {
    fn shard(&self, bare: &str) -> &Sender<Command<A>> {
        &self.shards[self.shard_index(bare)]
    }

    fn shard_index(&self, bare: &str) -> usize {
        (self.hash_state.hash_one(bare) as usize) % self.shards.len()
    }
}

impl<A: ChunkAllocator> Registration<A> {
    pub(crate) fn liveness(&self) -> SessionLiveness {
        SessionLiveness(Arc::clone(&self.alive))
    }
    pub fn account(&self) -> &AccountKey {
        &self.account
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn full_jid(&self) -> String {
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

    pub async fn tag(&self, tag: SessionTag) -> Result<(), RouterError> {
        tag_resource(
            &self.links.shard,
            &self.account,
            &self.resource,
            self.token,
            tag,
        )
        .await
    }

    pub(crate) fn handle(&self) -> SessionHandle<A>
    where
        A: Clone,
    {
        SessionHandle {
            account: self.account.clone(),
            resource: self.resource.clone(),
            token: self.token,
            shard: self.links.shard.clone(),
            retired: self.links.retired.clone(),
            router: self.links.router.clone(),
            liveness: self.liveness(),
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

fn take_queued<A: ChunkAllocator>(inbound: &Receiver<RoutedStanza<A>>) -> Vec<RoutedStanza<A>> {
    let mut queued = Vec::new();
    while let Ok(delivery) = inbound.try_recv() {
        queued.push(delivery);
    }
    queued
}

pub(crate) struct SessionHandle<A: ChunkAllocator> {
    account: AccountKey,
    resource: Box<str>,
    token: u64,
    shard: Sender<Command<A>>,
    retired: Retirement<A>,
    router: LocalRouterHandle<A>,
    liveness: SessionLiveness,
}

impl<A: ChunkAllocator + Clone> Clone for SessionHandle<A> {
    fn clone(&self) -> Self {
        Self {
            account: self.account.clone(),
            resource: self.resource.clone(),
            token: self.token,
            shard: self.shard.clone(),
            retired: self.retired.clone(),
            router: self.router.clone(),
            liveness: self.liveness.clone(),
        }
    }
}

impl<A: ChunkAllocator> SessionHandle<A> {
    pub(crate) async fn end_presence(&self) -> Result<Withdrawal<A>, RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard
            .send(Command::EndPresence {
                account: self.account.clone(),
                resource: self.resource.clone(),
                token: self.token,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        match result.await.map_err(|_| RouterError::Stopped)? {
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
        let (reply, result) = oneshot::channel();
        self.shard
            .send(Command::FinishPresence {
                account: self.account.clone(),
                token,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)
    }

    pub(crate) async fn replacement_is_available(&self) -> Result<bool, RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard
            .send(Command::ReplacementAvailable {
                account: self.account.clone(),
                resource: self.resource.clone(),
                token: self.token,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)
    }

    pub(crate) async fn record_directed_presence(
        &self,
        recipient: DirectedRecipient,
        available: bool,
    ) -> Result<(), RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard
            .send(Command::DirectedPresence {
                account: self.account.clone(),
                resource: self.resource.clone(),
                token: self.token,
                recipient,
                available,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    pub(crate) async fn tag(&self, tag: SessionTag) -> Result<(), RouterError> {
        tag_resource(&self.shard, &self.account, &self.resource, self.token, tag).await
    }

    pub(crate) async fn set_presence(
        &self,
        priority: Option<i8>,
        stanza: RoutedStanza<A>,
        unavailable: Option<RoutedStanza<A>>,
    ) -> Result<PresenceChange<A>, RouterError> {
        set_presence(
            &self.shard,
            &self.account,
            &self.resource,
            self.token,
            priority,
            stanza,
            unavailable,
        )
        .await
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
        let delivered = if available {
            self.router
                .authorized_delivery(PresenceDelivery {
                    stanza,
                    source: self.liveness.clone(),
                    target_token: None,
                    ordinary_access: true,
                    grants: [None, None],
                })
                .await
        } else if full {
            self.router.deliver_full(stanza).await
        } else {
            self.router.deliver_presence(stanza).await
        };
        match delivered {
            Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

async fn set_presence<A: ChunkAllocator>(
    shard: &Sender<Command<A>>,
    account: &AccountKey,
    resource: &str,
    token: u64,
    priority: Option<i8>,
    stanza: RoutedStanza<A>,
    unavailable: Option<RoutedStanza<A>>,
) -> Result<PresenceChange<A>, RouterError> {
    let (reply, result) = oneshot::channel();
    shard
        .send(Command::Presence {
            account: account.clone(),
            resource: resource.into(),
            token,
            priority,
            stanza,
            unavailable,
            reply,
        })
        .await
        .map_err(|_| RouterError::Stopped)?;
    result.await.map_err(|_| RouterError::Stopped)?
}

async fn tag_resource<A: ChunkAllocator>(
    shard: &Sender<Command<A>>,
    account: &AccountKey,
    resource: &str,
    token: u64,
    tag: SessionTag,
) -> Result<(), RouterError> {
    let (reply, result) = oneshot::channel();
    shard
        .send(Command::Tag {
            account: account.clone(),
            resource: resource.into(),
            token,
            tag,
            reply,
        })
        .await
        .map_err(|_| RouterError::Stopped)?;
    result.await.map_err(|_| RouterError::Stopped)?
}

impl<A: ChunkAllocator> Drop for Registration<A> {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        // SAFETY: `links` is taken exactly once, here, and never touched again.
        let links = unsafe { mem::ManuallyDrop::take(&mut self.links) };
        if std::thread::panicking() {
            // Waking another task while this thread unwinds aborts the process.
            DEFERRED.with(|deferred| deferred.borrow_mut().push(Box::new(links)));
        } else {
            drop(links);
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

fn validate_resource<A: ChunkAllocator>(
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

impl<A: ChunkAllocator> Shard<A> {
    fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            retiring: HashMap::new(),
            next_token: 0,
            cleanups: FuturesUnordered::new(),
        }
    }

    async fn run(mut self, receiver: Inbox<A>, context: WorkerContext) {
        let mut processed = 0;
        let mut prefer_cleanup = true;
        loop {
            let event = self
                .next_event(&receiver.0, context.shutdown_requested(), prefer_cleanup)
                .await;
            match event {
                Some(Either::Left(command)) => self.command(command),
                Some(Either::Right((account, resource, token))) => {
                    self.remove(account.as_str(), &resource, token, RetireCause::Evicted);
                    self.finish_presence(&account, token);
                }
                None => break,
            }
            prefer_cleanup = !prefer_cleanup;
            processed += 1;
            if processed == SHARD_BATCH_SIZE {
                processed = 0;
                if context.shutdown_requested().now_or_never().is_some() {
                    break;
                }
                yield_to_runtime().await;
            }
        }
    }

    async fn next_event<S: Future<Output = Instant>>(
        &mut self,
        receiver: &Receiver<Command<A>>,
        shutdown: S,
        prefer_cleanup: bool,
    ) -> Option<Either<Command<A>, (AccountKey, Box<str>, u64)>> {
        let work = async {
            if self.cleanups.is_empty() {
                return receiver.recv().await.ok().map(Either::Left);
            }
            let mut receive = pin!(receiver.recv());
            let mut cleanup = pin!(self.cleanups.next());
            if prefer_cleanup {
                match select(cleanup.as_mut(), receive.as_mut()).await {
                    Either::Left((Some(cleanup), _)) => Some(Either::Right(cleanup)),
                    Either::Right((Ok(command), _)) => Some(Either::Left(command)),
                    _ => None,
                }
            } else {
                match select(receive.as_mut(), cleanup.as_mut()).await {
                    Either::Left((Ok(command), _)) => Some(Either::Left(command)),
                    Either::Right((Some(cleanup), _)) => Some(Either::Right(cleanup)),
                    _ => None,
                }
            }
        };
        match select(pin!(shutdown), pin!(work)).await {
            Either::Left(_) => None,
            Either::Right((event, _)) => event,
        }
    }

    fn command(&mut self, command: Command<A>) {
        match command {
            Command::DirectedPresence {
                account,
                resource,
                token,
                recipient,
                available,
                reply,
            } => {
                let result =
                    self.record_directed_presence(&account, &resource, token, recipient, available);
                let _ = reply.send(result);
            }
            Command::HasDirectedGrant {
                account,
                resource,
                observer,
                reply,
            } => {
                let granted = self
                    .accounts
                    .get(account.as_str())
                    .and_then(|sessions| sessions.get(resource.as_ref()))
                    .is_some_and(|session| {
                        session.alive.load(Ordering::Acquire)
                            && !session.outbound.is_closed()
                            && session
                                .directed
                                .iter()
                                .any(|grant| grant.recipient.matches_prepared(&observer))
                    });
                let _ = reply.send(granted);
            }
            Command::PresenceAccess {
                account,
                resource,
                observer,
                subscribed,
                mut build,
                reply,
            } => {
                let result = self.presence_access(
                    &account,
                    resource.as_deref(),
                    &observer,
                    subscribed,
                    &mut build,
                );
                let _ = reply.send(result);
            }
            Command::AuthorizedDelivery { delivery, reply } => {
                let result = self.authorized_delivery(delivery);
                let _ = reply.send(result);
            }
            Command::Register {
                account,
                requested,
                limit,
                outbound,
                inbound,
                router,
                reply,
            } => {
                let result = self.register(account, requested, limit, outbound, inbound, router);
                let _ = reply.send(result);
            }
            Command::Deliver {
                stanza,
                fallback_chat,
                reply,
            } => {
                let result = self.deliver(stanza, fallback_chat);
                let _ = reply.send(result);
            }
            Command::DeliverBare { stanza, reply } => {
                let result = self.deliver_bare(stanza, false);
                let _ = reply.send(result);
            }
            Command::DeliverPresence { stanza, reply } => {
                let result = self.deliver_presence(stanza);
                let _ = reply.send(result);
            }
            Command::DeliverPresenceToTagged { tag, stanza, reply } => {
                let result = self.deliver_presence_to_tagged(tag, stanza);
                let _ = reply.send(result);
            }
            Command::PresenceSnapshot { account, reply } => {
                let _ = reply.send(self.presence_snapshot(&account));
            }
            Command::WithdrawalSnapshot { account, reply } => {
                let _ = reply.send(self.withdrawal_snapshot(&account));
            }
            Command::Tag {
                account,
                resource,
                token,
                tag,
                reply,
            } => {
                let result = self.tag(&account, &resource, token, tag);
                let _ = reply.send(result);
            }
            Command::DeliverToTagged {
                account,
                tag,
                mut build,
                reply,
            } => {
                let result = self.deliver_to_tagged(&account, tag, &mut build);
                let _ = reply.send(result);
            }
            Command::Presence {
                account,
                resource,
                token,
                priority,
                stanza,
                unavailable,
                reply,
            } => {
                let result =
                    self.presence(&account, &resource, token, priority, stanza, unavailable);
                let _ = reply.send(result);
            }
            Command::EndPresence {
                account,
                resource,
                token,
                reply,
            } => {
                let result = self.end_presence(&account, &resource, token);
                let _ = reply.send(result);
            }
            Command::ReplacementAvailable {
                account,
                resource,
                token,
                reply,
            } => {
                let result = self.replacement_is_available(&account, &resource, token);
                let _ = reply.send(result);
            }
            Command::FinishPresence {
                account,
                token,
                reply,
            } => {
                self.finish_presence(&account, token);
                let _ = reply.send(());
            }
            Command::RetireAccount { account, reply } => {
                self.retire_account(&account);
                let _ = reply.send(());
            }
        }
    }

    fn register(
        &mut self,
        account: AccountKey,
        requested: Option<Box<str>>,
        limit: NonZeroUsize,
        outbound: Sender<RoutedStanza<A>>,
        inbound: Receiver<RoutedStanza<A>>,
        router: LocalRouterHandle<A>,
    ) -> Result<Registration<A>, RouterError> {
        let shard = router.shard(account.as_str()).clone();
        if let Some(sessions) = self.accounts.get(account.as_str()) {
            let stale: Vec<_> = sessions
                .iter()
                .filter(|(_, session)| {
                    !session.alive.load(Ordering::Acquire) || session.outbound.is_closed()
                })
                .map(|(resource, session)| (resource.clone(), session.token))
                .collect();
            for (resource, token) in stale {
                self.remove(account.as_str(), &resource, token, RetireCause::Evicted);
            }
        }
        let sessions = self.accounts.entry(account.as_str().into()).or_default();
        if sessions.len() >= limit.get() {
            return Err(RouterError::ResourceLimit);
        }
        let token = self
            .next_token
            .checked_add(1)
            .ok_or(RouterError::Unavailable)?;
        self.next_token = token;
        let resource = match requested {
            Some(resource) if !sessions.contains_key(resource.as_ref()) => resource,
            _ => loop {
                let mut random = [0; 16];
                graviola::random::fill(&mut random).map_err(|_| RouterError::Unavailable)?;
                let candidate = format!("lw-{:032x}", u128::from_be_bytes(random)).into_boxed_str();
                if !sessions.contains_key(candidate.as_ref()) {
                    break candidate;
                }
            },
        };
        let (lease, closed) = oneshot::channel();
        let (retired, retired_reply) = oneshot::channel();
        let alive = Arc::new(AtomicBool::new(true));
        let cleanup_account = account.clone();
        let cleanup_resource = resource.clone();
        self.cleanups.push(
            async move {
                let _ = closed.await;
                (cleanup_account, cleanup_resource, token)
            }
            .boxed(),
        );
        sessions.insert(
            resource.clone(),
            Session {
                token,
                alive: Arc::clone(&alive),
                outbound,
                inbound: inbound.clone(),
                priority: None,
                tags: SessionTags::default(),
                presence: None,
                unavailable: None,
                directed: Vec::new(),
                retired,
            },
        );
        Ok(Registration {
            account,
            resource,
            token,
            alive,
            links: mem::ManuallyDrop::new(Links {
                _lease: lease,
                retired: retired_reply.shared(),
                inbound,
                shard,
                router,
            }),
        })
    }

    fn record_directed_presence(
        &mut self,
        account: &AccountKey,
        resource: &str,
        token: u64,
        recipient: DirectedRecipient,
        available: bool,
    ) -> Result<(), RouterError> {
        let source = self
            .accounts
            .get_mut(account.as_str())
            .and_then(|sessions| sessions.get_mut(resource))
            .ok_or(RouterError::NotFound)?;
        if source.token != token
            || !source.alive.load(Ordering::Acquire)
            || source.outbound.is_closed()
        {
            return Err(RouterError::NotFound);
        }
        if recipient.bare() == account.as_str() {
            return Ok(());
        }
        let known = source
            .directed
            .iter()
            .position(|grant| grant.recipient == recipient);
        match (available, known) {
            (true, None) => source.directed.push(DirectedGrant {
                recipient,
                live: Arc::new(AtomicBool::new(true)),
            }),
            (false, Some(index)) => {
                let grant = source.directed.swap_remove(index);
                grant.live.store(false, Ordering::Release);
            }
            _ => {}
        }
        Ok(())
    }

    fn presence_access(
        &self,
        account: &AccountKey,
        resource: Option<&str>,
        observer: &DirectedRecipient,
        subscribed: bool,
        build: &mut PresenceBuilder<A>,
    ) -> Result<Vec<PresenceDelivery<A>>, RouterError> {
        let mut deliveries = Vec::new();
        let Some(sessions) = self.accounts.get(account.as_str()) else {
            return Ok(deliveries);
        };
        for (name, session) in sessions {
            if resource.is_some_and(|resource| resource != name.as_ref())
                || !session.alive.load(Ordering::Acquire)
                || session.outbound.is_closed()
            {
                continue;
            }
            let mut grants = [None, None];
            for (slot, grant) in grants.iter_mut().zip(
                session
                    .directed
                    .iter()
                    .filter(|grant| grant.recipient.matches_prepared(observer)),
            ) {
                *slot = Some(Arc::clone(&grant.live));
            }
            let access = PresenceAccess {
                subscribed,
                directed: grants.iter().any(Option::is_some),
            };
            let ordinary_access = subscribed || account.as_str() == observer.bare();
            if !ordinary_access && !access.directed {
                continue;
            }
            let Some(stanza) = build(PresenceSource {
                resource: name,
                presence: session.presence.as_ref(),
                access,
            })?
            else {
                continue;
            };
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            let to = view
                .to()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            let to_source =
                to.bare().as_str() == account.as_str() && to.resourcepart() == Some(name.as_ref());
            if !to_source && to.as_str() != observer.as_str() {
                return Err(RouterError::InvalidTarget);
            }
            deliveries.push(PresenceDelivery {
                stanza,
                source: SessionLiveness(Arc::clone(&session.alive)),
                target_token: to_source.then_some(session.token),
                ordinary_access,
                grants,
            });
        }
        Ok(deliveries)
    }

    fn authorized_delivery(&mut self, delivery: PresenceDelivery<A>) -> Result<(), RouterError> {
        let PresenceDelivery {
            stanza,
            source,
            target_token,
            ordinary_access,
            grants,
        } = delivery;
        let valid = || {
            source.is_alive()
                && (ordinary_access
                    || grants
                        .iter()
                        .flatten()
                        .any(|grant| grant.load(Ordering::Acquire)))
        };
        if !valid() {
            return Ok(());
        }
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let full = to.resourcepart().is_some();
        if let Some(token) = target_token
            && self
                .accounts
                .get(to.bare().as_str())
                .and_then(|sessions| {
                    to.resourcepart()
                        .and_then(|resource| sessions.get(resource))
                })
                .is_none_or(|session| session.token != token)
        {
            return Ok(());
        }
        if full {
            self.deliver_with_guard(stanza, false, valid)
        } else {
            if !matches!(view.stanza_type(), StanzaType::Presence(_)) {
                return Err(RouterError::InvalidTarget);
            }
            self.deliver_presence_where_with_guard(
                stanza,
                |session| session.priority.is_some(),
                valid,
            )
        }
    }

    fn prune_directed(&mut self, stanza: &RoutedStanza<A>) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        if view.stanza_type() != StanzaType::Presence(PresenceType::Unavailable) {
            return Ok(());
        }
        let Some(sender) = view.from().map_err(|_| RouterError::InvalidTarget)? else {
            return Ok(());
        };
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let Some(sessions) = self.accounts.get_mut(to.bare().as_str()) else {
            return Ok(());
        };
        for (resource, session) in sessions {
            if to
                .resourcepart()
                .is_some_and(|target| target != resource.as_ref())
                || !session.alive.load(Ordering::Acquire)
            {
                continue;
            }
            session.directed.retain(|grant| {
                let remove = if sender.resourcepart().is_some() {
                    grant.recipient.as_str() == sender.as_str()
                } else {
                    grant.recipient.bare() == sender.as_str()
                };
                if remove {
                    grant.live.store(false, Ordering::Release);
                }
                !remove
            });
        }
        Ok(())
    }

    fn deliver(&mut self, stanza: RoutedStanza<A>, fallback_chat: bool) -> Result<(), RouterError> {
        self.deliver_with_guard(stanza, fallback_chat, || true)
    }

    fn deliver_with_guard(
        &mut self,
        stanza: RoutedStanza<A>,
        fallback_chat: bool,
        valid: impl Fn() -> bool,
    ) -> Result<(), RouterError> {
        self.prune_directed(&stanza)?;
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let account = to.bare();
        let resource = to.resourcepart().ok_or(RouterError::InvalidTarget)?;
        let account = account.as_str();
        let recipient = self
            .accounts
            .get(account)
            .and_then(|sessions| sessions.get(resource));
        let result = recipient.map(|session| {
            let delivery = if !valid() {
                Ok(())
            } else if session.alive.load(Ordering::Acquire) {
                session
                    .outbound
                    .try_send(stanza.clone())
                    .map_err(mailbox_error)
            } else {
                Err(RouterError::NotFound)
            };
            (session.token, delivery)
        });
        if let Some((token, Err(RouterError::NotFound))) = result {
            self.remove(account, resource, token, RetireCause::Evicted);
        }
        match result.map_or(Err(RouterError::NotFound), |(_, result)| result) {
            Err(RouterError::NotFound)
                if fallback_chat
                    && view.stanza_type() == StanzaType::Message(MessageType::Chat) =>
            {
                self.deliver_bare(stanza, true)
            }
            Err(RouterError::NotFound)
                if fallback_chat
                    && view.stanza_type() == StanzaType::Message(MessageType::Normal)
                    && !self.accounts.get(account).is_some_and(|sessions| {
                        sessions.values().any(Session::accepts_bare_message)
                    }) =>
            {
                Err(RouterError::Offline)
            }
            result => result,
        }
    }

    fn deliver_bare(
        &mut self,
        stanza: RoutedStanza<A>,
        allow_full: bool,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let sessions = self
            .accounts
            .get(to.bare().as_str())
            .ok_or(match view.stanza_type() {
                StanzaType::Message(
                    MessageType::Normal | MessageType::Chat | MessageType::Headline,
                ) => RouterError::Offline,
                _ => RouterError::NotFound,
            })?;
        if !allow_full && to.resourcepart().is_some() {
            return Err(RouterError::InvalidTarget);
        }
        match view.stanza_type() {
            StanzaType::Message(MessageType::Normal | MessageType::Chat) => {
                let recipient = sessions
                    .values()
                    .filter(|session| session.accepts_bare_message())
                    .max_by_key(|session| (session.priority, std::cmp::Reverse(session.token)))
                    .ok_or(RouterError::Offline)?;
                enqueue_bare_message(sessions, recipient, stanza)
            }
            StanzaType::Message(MessageType::Headline) => {
                let mut delivered = false;
                let mut busy = false;
                for session in sessions
                    .values()
                    .filter(|session| session.accepts_bare_message())
                {
                    match session.outbound.try_send(stanza.clone()) {
                        Ok(()) => delivered = true,
                        Err(TrySendError::Full(_)) => busy = true,
                        Err(TrySendError::Closed(_)) => {}
                    }
                }
                if delivered {
                    Ok(())
                } else if busy {
                    Err(RouterError::Busy)
                } else {
                    Err(RouterError::Offline)
                }
            }
            _ => Err(RouterError::InvalidTarget),
        }
    }

    fn deliver_presence(&mut self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if to.resourcepart().is_some()
            || !matches!(
                view.stanza_type(),
                StanzaType::Presence(
                    PresenceType::Available
                        | PresenceType::Unavailable
                        | PresenceType::Subscribe
                        | PresenceType::Subscribed
                        | PresenceType::Unsubscribe
                        | PresenceType::Unsubscribed
                )
            )
        {
            return Err(RouterError::InvalidTarget);
        }
        self.deliver_presence_where(stanza, |session| session.priority.is_some())
    }

    fn deliver_presence_to_tagged(
        &mut self,
        tag: SessionTag,
        stanza: RoutedStanza<A>,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if to.resourcepart().is_some() || !matches!(view.stanza_type(), StanzaType::Presence(_)) {
            return Err(RouterError::InvalidTarget);
        }
        match self.deliver_presence_where(stanza, |session| session.tags.contains(tag)) {
            Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn deliver_presence_where(
        &mut self,
        stanza: RoutedStanza<A>,
        select: impl Fn(&Session<A>) -> bool,
    ) -> Result<(), RouterError> {
        self.deliver_presence_where_with_guard(stanza, select, || true)
    }

    fn deliver_presence_where_with_guard(
        &mut self,
        stanza: RoutedStanza<A>,
        select: impl Fn(&Session<A>) -> bool,
        valid: impl Fn() -> bool,
    ) -> Result<(), RouterError> {
        self.prune_directed(&stanza)?;
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let account = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?
            .as_str();
        let sessions = self.accounts.get(account).ok_or(RouterError::NotFound)?;
        let mut delivered = false;
        let mut busy = false;
        let mut failed = Vec::new();
        for (resource, session) in sessions {
            if !select(session) {
                continue;
            }
            if !session.alive.load(Ordering::Acquire) || session.outbound.is_closed() {
                failed.push((resource.clone(), session.token));
                continue;
            }
            if !valid() {
                continue;
            }
            match session.outbound.try_send(stanza.clone()) {
                Ok(()) => delivered = true,
                Err(TrySendError::Full(_)) => {
                    busy = true;
                    failed.push((resource.clone(), session.token));
                }
                Err(TrySendError::Closed(_)) => {
                    failed.push((resource.clone(), session.token));
                }
            }
        }
        for (resource, token) in failed {
            self.remove(account, &resource, token, RetireCause::Evicted);
        }
        if delivered {
            Ok(())
        } else if busy {
            Err(RouterError::Busy)
        } else {
            Err(RouterError::NotFound)
        }
    }

    fn presence_snapshot(&self, account: &AccountKey) -> Vec<RoutedStanza<A>> {
        self.accounts
            .get(account.as_str())
            .into_iter()
            .flat_map(|sessions| sessions.values())
            .filter(|session| session.alive.load(Ordering::Acquire))
            .filter_map(|session| session.presence.clone())
            .collect()
    }

    fn withdrawal_snapshot(&self, account: &AccountKey) -> Vec<RoutedStanza<A>> {
        let mut snapshot = self.presence_snapshot(account);
        if let Some(retiring) = self.retiring.get(account.as_str()) {
            for (token, presence) in retiring {
                let replaced = self
                    .accounts
                    .get(account.as_str())
                    .and_then(|sessions| sessions.get(presence.resource.as_ref()))
                    .is_some_and(|session| {
                        session.token != *token
                            && session.alive.load(Ordering::Acquire)
                            && session.presence.is_some()
                    });
                if !replaced {
                    snapshot.push(presence.stanza.clone());
                }
            }
        }
        snapshot
    }

    fn tag(
        &mut self,
        account: &AccountKey,
        resource: &str,
        token: u64,
        tag: SessionTag,
    ) -> Result<(), RouterError> {
        let session = self
            .accounts
            .get_mut(account.as_str())
            .and_then(|sessions| sessions.get_mut(resource))
            .ok_or(RouterError::NotFound)?;
        if session.token != token || !session.alive.load(Ordering::Acquire) {
            return Err(RouterError::NotFound);
        }
        session.tags.insert(tag);
        Ok(())
    }

    fn deliver_to_tagged(
        &mut self,
        account: &AccountKey,
        tag: SessionTag,
        build: &mut TaggedStanzaFactory<A>,
    ) -> Result<(), RouterError> {
        let Some(sessions) = self.accounts.get(account.as_str()) else {
            return Ok(());
        };
        if sessions.values().all(|session| !session.tags.contains(tag)) {
            return Ok(());
        }
        let max_resource_len = sessions
            .keys()
            .map(|resource| resource.len())
            .max()
            .unwrap_or(0);
        let mut full_jid = String::with_capacity(account.as_str().len() + 1 + max_resource_len);
        let mut deliveries = Vec::with_capacity(sessions.len());
        let mut failed = Vec::new();
        let mut build_error = None;
        for (resource, session) in sessions {
            if !session.tags.contains(tag) {
                continue;
            }
            if !session.alive.load(Ordering::Acquire) || session.outbound.is_closed() {
                failed.push((resource.clone(), session.token));
                continue;
            }
            full_jid.clear();
            full_jid.push_str(account.as_str());
            full_jid.push('/');
            full_jid.push_str(resource);
            let stanza = match build(&full_jid).and_then(|stanza| {
                validate_target(&stanza, &full_jid)?;
                Ok(stanza)
            }) {
                Ok(stanza) => stanza,
                Err(error) => {
                    build_error = Some(error);
                    break;
                }
            };
            deliveries.push((resource.clone(), session.token, stanza));
        }
        if let Some(error) = build_error {
            let failed = sessions
                .iter()
                .filter(|(_, session)| session.tags.contains(tag))
                .map(|(resource, session)| (resource.clone(), session.token))
                .collect::<Vec<_>>();
            for (resource, token) in failed {
                self.remove(account.as_str(), &resource, token, RetireCause::Evicted);
            }
            return Err(error);
        }
        if let Some(sessions) = self.accounts.get(account.as_str()) {
            for (resource, token, stanza) in deliveries {
                let Some(session) = sessions.get(resource.as_ref()) else {
                    continue;
                };
                if session.token == token
                    && (!session.alive.load(Ordering::Acquire)
                        || session.outbound.try_send(stanza).is_err())
                {
                    failed.push((resource, token));
                }
            }
        }
        for (resource, token) in failed {
            self.remove(account.as_str(), &resource, token, RetireCause::Evicted);
        }
        Ok(())
    }

    fn presence(
        &mut self,
        account: &AccountKey,
        resource: &str,
        token: u64,
        priority: Option<i8>,
        stanza: RoutedStanza<A>,
        unavailable: Option<RoutedStanza<A>>,
    ) -> Result<PresenceChange<A>, RouterError> {
        let (change, siblings) = {
            let sessions = self
                .accounts
                .get(account.as_str())
                .ok_or(RouterError::NotFound)?;
            let source = sessions.get(resource).ok_or(RouterError::NotFound)?;
            if source.token != token || !source.alive.load(Ordering::Acquire) {
                return Err(RouterError::NotFound);
            }
            let became_available = priority.is_some() && source.priority.is_none();
            let became_eligible = priority.is_some_and(|priority| priority >= 0)
                && source.priority.is_none_or(|priority| priority < 0);
            let became_unavailable = priority.is_none() && source.priority.is_some();
            let preceding = take_queued(&source.inbound);
            let siblings = if became_available {
                sessions
                    .values()
                    .filter(|session| session.token != token)
                    .filter_map(|session| session.presence.as_ref())
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
            (
                (
                    became_available,
                    became_eligible,
                    became_unavailable,
                    preceding,
                ),
                siblings,
            )
        };

        let mut failed = Vec::new();
        let directed;
        {
            let sessions = self
                .accounts
                .get_mut(account.as_str())
                .ok_or(RouterError::NotFound)?;
            let source = sessions.get_mut(resource).ok_or(RouterError::NotFound)?;
            directed = if priority.is_none() {
                take_directed(&mut source.directed, token)
            } else {
                DirectedWithdrawal {
                    source_token: token,
                    recipients: Vec::new(),
                }
            };
            source.priority = priority;
            source.unavailable = unavailable;
            for (recipient_resource, session) in sessions.iter() {
                if session.token != token
                    && session.alive.load(Ordering::Acquire)
                    && session.priority.is_some()
                    && session.outbound.try_send(stanza.clone()).is_err()
                {
                    failed.push((recipient_resource.clone(), session.token));
                }
            }
            if let Some(source) = sessions.get_mut(resource) {
                source.presence = priority.map(|_| stanza);
            }
        }
        for (recipient_resource, recipient_token) in failed {
            self.remove(
                account.as_str(),
                &recipient_resource,
                recipient_token,
                RetireCause::Evicted,
            );
        }
        let (became_available, became_eligible, became_unavailable, preceding) = change;
        Ok(PresenceChange {
            became_available,
            became_eligible,
            became_unavailable,
            preceding,
            siblings,
            directed,
        })
    }

    fn end_presence(
        &mut self,
        account: &AccountKey,
        resource: &str,
        token: u64,
    ) -> Result<Withdrawal<A>, RouterError> {
        let sessions = self
            .accounts
            .get_mut(account.as_str())
            .ok_or(RouterError::NotFound)?;
        let source = sessions.get_mut(resource).ok_or(RouterError::NotFound)?;
        if source.token != token || !source.alive.load(Ordering::Acquire) {
            return Err(RouterError::NotFound);
        }
        source.alive.store(false, Ordering::Release);
        source.outbound.close();
        source.priority = None;
        let presence = source.presence.take();
        let unavailable = source.unavailable.take();
        let directed = take_directed(&mut source.directed, token);
        if let Some(stanza) = unavailable.as_ref() {
            let mut failed = Vec::new();
            for (recipient_resource, recipient) in sessions.iter() {
                if recipient.token != token
                    && recipient.alive.load(Ordering::Acquire)
                    && recipient.priority.is_some()
                    && recipient.outbound.try_send(stanza.clone()).is_err()
                {
                    failed.push((recipient_resource.clone(), recipient.token));
                }
            }
            for (recipient_resource, recipient_token) in failed {
                self.remove(
                    account.as_str(),
                    &recipient_resource,
                    recipient_token,
                    RetireCause::Evicted,
                );
            }
        }
        if let (Some(stanza), Some(_)) = (presence, unavailable.as_ref()) {
            self.retiring
                .entry(account.as_str().into())
                .or_default()
                .insert(
                    token,
                    RetiredPresence {
                        resource: resource.into(),
                        stanza,
                    },
                );
        }
        Ok(Withdrawal {
            unavailable,
            directed,
        })
    }

    fn finish_presence(&mut self, account: &AccountKey, token: u64) {
        if let Some(retiring) = self.retiring.get_mut(account.as_str()) {
            retiring.remove(&token);
            if retiring.is_empty() {
                self.retiring.remove(account.as_str());
            }
        }
    }

    fn replacement_is_available(&self, account: &AccountKey, resource: &str, token: u64) -> bool {
        self.accounts
            .get(account.as_str())
            .and_then(|sessions| sessions.get(resource))
            .is_some_and(|session| {
                session.token != token
                    && session.alive.load(Ordering::Acquire)
                    && session.priority.is_some()
            })
    }

    fn retire_account(&mut self, account: &AccountKey) {
        let Some(sessions) = self.accounts.get(account.as_str()) else {
            return;
        };
        let bound: Vec<_> = sessions
            .iter()
            .map(|(resource, session)| (resource.clone(), session.token))
            .collect();
        for (resource, token) in bound {
            self.remove(
                account.as_str(),
                &resource,
                token,
                RetireCause::AccountDeleted,
            );
        }
    }

    fn remove(&mut self, account: &str, resource: &str, token: u64, cause: RetireCause) {
        let mut retiring = Vec::new();
        if let Some(sessions) = self.accounts.get_mut(account) {
            let mut pending = Vec::new();
            Self::remove_session(
                sessions,
                resource,
                token,
                cause,
                &mut pending,
                &mut retiring,
            );
            while let Some((resource, token)) = pending.pop() {
                Self::remove_session(
                    sessions,
                    &resource,
                    token,
                    cause,
                    &mut pending,
                    &mut retiring,
                );
            }
            if sessions.is_empty() {
                self.accounts.remove(account);
            }
        }
        for (token, presence) in retiring {
            self.retiring
                .entry(account.into())
                .or_default()
                .insert(token, presence);
        }
    }

    fn remove_session(
        sessions: &mut HashMap<Box<str>, Session<A>>,
        resource: &str,
        token: u64,
        cause: RetireCause,
        pending: &mut Vec<(Box<str>, u64)>,
        retiring: &mut Vec<(u64, RetiredPresence<A>)>,
    ) {
        if sessions
            .get(resource)
            .is_none_or(|session| session.token != token)
        {
            return;
        }
        if let Some(mut session) = sessions.remove(resource) {
            session.alive.store(false, Ordering::Release);
            if let Some(unavailable) = session.unavailable.as_ref() {
                for (recipient_resource, recipient) in sessions.iter() {
                    if recipient.alive.load(Ordering::Acquire)
                        && recipient.priority.is_some()
                        && recipient.outbound.try_send(unavailable.clone()).is_err()
                    {
                        pending.push((recipient_resource.clone(), recipient.token));
                    }
                }
            }
            if let (Some(stanza), Some(_)) = (session.presence, session.unavailable.as_ref()) {
                retiring.push((
                    token,
                    RetiredPresence {
                        resource: resource.into(),
                        stanza,
                    },
                ));
            }
            // Report retirement before closing the mailbox so the stream can observe its cause.
            let _ = session.retired.send(Retired {
                cause,
                unavailable: session.unavailable,
                directed: SharedDirectedWithdrawal(Arc::new(Mutex::new(Some(take_directed(
                    &mut session.directed,
                    token,
                ))))),
            });
            session.outbound.close();
        }
    }
}

fn validate_target<A: ChunkAllocator>(
    stanza: &RoutedStanza<A>,
    expected: &str,
) -> Result<(), RouterError> {
    let target = stanza
        .resolve()
        .map_err(|_| RouterError::InvalidTarget)?
        .to()
        .map_err(|_| RouterError::InvalidTarget)?
        .ok_or(RouterError::InvalidTarget)?;
    if target.as_str() == expected {
        Ok(())
    } else {
        Err(RouterError::InvalidTarget)
    }
}

fn mailbox_error<T>(error: TrySendError<T>) -> RouterError {
    match error {
        TrySendError::Full(_) => RouterError::Busy,
        TrySendError::Closed(_) => RouterError::NotFound,
    }
}

fn enqueue_bare_message<A: ChunkAllocator>(
    sessions: &HashMap<Box<str>, Session<A>>,
    recipient: &Session<A>,
    stanza: RoutedStanza<A>,
) -> Result<(), RouterError> {
    match recipient.outbound.try_send(stanza) {
        Err(TrySendError::Closed(_)) if !sessions.values().any(Session::accepts_bare_message) => {
            Err(RouterError::Offline)
        }
        result => result.map_err(mailbox_error),
    }
}

async fn yield_to_runtime() {
    let mut yielded = false;
    poll_fn(|context| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            context.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    fn test_router(
        sender: async_channel::Sender<super::Command<lonewolf_util::arena::GlobalChunkAllocator>>,
    ) -> super::LocalRouterHandle<lonewolf_util::arena::GlobalChunkAllocator> {
        super::LocalRouterHandle {
            shards: vec![sender].into(),
            hash_state: Default::default(),
            allocator: lonewolf_util::arena::GlobalChunkAllocator,
        }
    }

    use std::error::Error;
    use std::future::pending;

    use compio::runtime::Runtime;
    use lonewolf_util::arena::GlobalChunkAllocator;
    use lonewolf_xmpp::jid::Jid;
    use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
    use lonewolf_xmpp::stanza::{PresenceType, StanzaType};

    use super::*;

    fn account() -> Result<AccountKey, Box<dyn Error>> {
        let mut arena = Arena::try_new(Default::default())?;
        let jid = Jid::parse_in("alice@localhost", &mut arena)?;
        Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
    }

    fn register_command(
        account: &AccountKey,
    ) -> (
        Command<GlobalChunkAllocator>,
        oneshot::Receiver<Result<Registration<GlobalChunkAllocator>, RouterError>>,
    ) {
        let (reply, result) = oneshot::channel();
        let (outbound, inbound) = async_channel::bounded(1);
        let (shard, _) = async_channel::bounded(1);
        (
            Command::Register {
                account: account.clone(),
                requested: None,
                limit: NonZeroUsize::MIN,
                outbound,
                inbound,
                router: test_router(shard),
                reply,
            },
            result,
        )
    }

    async fn routed(xml: &str) -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
        let xml = format!(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>{xml}"
        );
        let mut parser = XmppParser::new(
            xml.as_bytes(),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(4096).ok_or("zero stanza size")?,
                arena: Default::default(),
            },
            GlobalChunkAllocator,
        );
        assert!(matches!(
            parser.next_event().await?,
            Some(StreamEvent::StreamStart { .. })
        ));
        match parser.next_event().await? {
            Some(StreamEvent::Stanza(parsed)) => Ok(RoutedStanza::from_parsed(parsed)),
            _ => Err("expected a stanza".into()),
        }
    }

    #[test]
    fn closing_selected_bare_recipient_rechecks_eligibility_without_retrying_a_sibling()
    -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            for kind in ["normal", "chat"] {
                for eligible_sibling in [false, true] {
                    let mut sessions = HashMap::new();
                    let mut receivers = Vec::new();
                    for (token, resource, priority) in [
                        (1, "selected", Some(1)),
                        (2, "sibling", eligible_sibling.then_some(0)),
                    ] {
                        let (outbound, inbound) = async_channel::bounded(1);
                        let (retired, _) = oneshot::channel();
                        sessions.insert(
                            resource.into(),
                            Session {
                                token,
                                alive: Arc::new(AtomicBool::new(true)),
                                outbound,
                                inbound: inbound.clone(),
                                priority,
                                tags: SessionTags::default(),
                                presence: None,
                                unavailable: None,
                                directed: Vec::new(),
                                retired,
                            },
                        );
                        receivers.push(inbound);
                    }
                    let selected = &sessions["selected"];
                    assert!(selected.accepts_bare_message());
                    receivers[0].close();
                    let stanza =
                        routed(&format!("<message to='alice@localhost' type='{kind}'/>")).await?;
                    assert_eq!(
                        enqueue_bare_message(&sessions, selected, stanza),
                        Err(if eligible_sibling {
                            RouterError::NotFound
                        } else {
                            RouterError::Offline
                        })
                    );
                    assert!(receivers[1].is_empty());
                }
            }
            Ok(())
        })
    }

    #[test]
    fn headline_prefers_success_then_busy_and_keeps_closed_sessions() -> Result<(), Box<dyn Error>>
    {
        Runtime::new()?.block_on(async {
            let account = account()?;
            let mut shard = Shard::<GlobalChunkAllocator>::new();
            let mut sessions = HashMap::new();
            let mut receivers = Vec::new();
            for (token, resource) in [(1, "ready"), (2, "full"), (3, "closed")] {
                let (outbound, inbound) = async_channel::bounded(1);
                let (retired, _) = oneshot::channel();
                sessions.insert(
                    resource.into(),
                    Session {
                        token,
                        alive: Arc::new(AtomicBool::new(true)),
                        outbound,
                        inbound: inbound.clone(),
                        priority: Some(0),
                        tags: SessionTags::default(),
                        presence: None,
                        unavailable: None,
                        directed: Vec::new(),
                        retired,
                    },
                );
                receivers.push(inbound);
            }
            let stanza = routed("<message to='alice@localhost' type='headline'/>").await?;
            assert!(sessions["full"].outbound.try_send(stanza.clone()).is_ok());
            receivers[2].close();
            shard.accounts.insert(account.as_str().into(), sessions);

            assert_eq!(shard.deliver_bare(stanza.clone(), false), Ok(()));
            let delivery = receivers[0].try_recv()?;
            assert_eq!(
                delivery.resolve()?.stanza_type(),
                StanzaType::Message(MessageType::Headline)
            );
            assert_eq!(receivers[1].len(), 1);
            receivers[0].close();
            assert_eq!(
                shard.deliver_bare(stanza.clone(), false),
                Err(RouterError::Busy)
            );
            receivers[1].close();
            assert_eq!(shard.deliver_bare(stanza, false), Err(RouterError::Offline));
            let sessions = &shard.accounts[account.as_str()];
            assert_eq!(sessions.len(), 3);
            assert!(
                sessions
                    .values()
                    .all(|session| session.alive.load(Ordering::Acquire))
            );
            Ok(())
        })
    }

    #[test]
    fn a_registration_dropped_by_a_panic_is_released_afterwards() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let account = account()?;
            let mut shard = Shard::<GlobalChunkAllocator>::new();
            let (command_sender, _commands) = async_channel::bounded(1);
            let limit = NonZeroUsize::new(2).ok_or("zero resource limit")?;
            let (outbound, inbound) = async_channel::bounded(64);
            let desk = shard.register(
                account.clone(),
                Some("desk".into()),
                limit,
                outbound,
                inbound,
                test_router(command_sender.clone()),
            )?;
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _held = desk;
                panic!("deliberate");
            }));
            assert!(caught.is_err());
            assert!(shard.cleanups.next().now_or_never().is_none());

            release_deferred();
            let (cleaned, resource, _) = shard.cleanups.next().await.ok_or("missing cleanup")?;
            assert_eq!(cleaned, account);
            assert_eq!(resource.as_ref(), "desk");
            assert!(shard.cleanups.is_empty());
            Ok(())
        })
    }

    #[test]
    fn full_delivery_removes_stale_session_and_broadcasts_unavailable() -> Result<(), Box<dyn Error>>
    {
        Runtime::new()?.block_on(async {
            let account = account()?;
            let mut shard = Shard::<GlobalChunkAllocator>::new();
            let (command_sender, _) = async_channel::bounded(1);
            let (desk_outbound, desk_inbound) = async_channel::bounded(64);
            let desk = shard.register(
                account.clone(),
                Some("desk".into()),
                NonZeroUsize::new(2).ok_or("zero resource limit")?,
                desk_outbound,
                desk_inbound,
                test_router(command_sender.clone()),
            )?;
            let (phone_outbound, phone_inbound) = async_channel::bounded(64);
            let phone = shard.register(
                account.clone(),
                Some("phone".into()),
                NonZeroUsize::new(2).ok_or("zero resource limit")?,
                phone_outbound,
                phone_inbound,
                test_router(command_sender),
            )?;
            let became_available = shard.presence(
                &account,
                "desk",
                desk.token,
                Some(0),
                routed("<presence from='alice@localhost/desk'/>").await?,
                Some(routed("<presence from='alice@localhost/desk' type='unavailable'/>").await?),
            )?;
            assert!(became_available.became_available);
            assert!(became_available.siblings.is_empty());
            let became_available = shard.presence(
                &account,
                "phone",
                phone.token,
                Some(0),
                routed("<presence from='alice@localhost/phone'/>").await?,
                None,
            )?;
            assert!(became_available.became_available);
            assert_eq!(became_available.siblings.len(), 1);
            if desk.recv().await.is_none() {
                return Err("missing peer presence".into());
            }

            drop(desk);
            assert_eq!(
                shard.deliver(routed("<message to='alice@localhost/desk'/>").await?, false),
                Err(RouterError::NotFound)
            );
            let Some(unavailable) = phone.recv().await else {
                return Err("missing unavailable".into());
            };
            assert_eq!(
                unavailable.resolve()?.stanza_type(),
                StanzaType::Presence(PresenceType::Unavailable)
            );
            assert!(!shard.accounts[account.as_str()].contains_key("desk"));
            Ok(())
        })
    }

    #[test]
    fn ready_cleanups_progress_with_a_full_command_queue() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let account = account()?;
            let mut shard = Shard::<GlobalChunkAllocator>::new();
            let (sender, receiver) = async_channel::bounded(SHARD_BATCH_SIZE);
            for token in 0..SHARD_BATCH_SIZE {
                let (command, _reply) = register_command(&account);
                assert!(sender.try_send(command).is_ok());
                let (lease, closed) = oneshot::channel::<()>();
                let cleanup_account = account.clone();
                shard.cleanups.push(
                    async move {
                        let _ = closed.await;
                        (
                            cleanup_account,
                            format!("resource-{token}").into(),
                            token as u64,
                        )
                    }
                    .boxed(),
                );
                drop(lease);
            }

            let mut cleaned = 0;
            for turn in 0..SHARD_BATCH_SIZE {
                match shard.next_event(&receiver, pending(), turn % 2 == 1).await {
                    Some(Either::Left(_)) => {}
                    Some(Either::Right(_)) => cleaned += 1,
                    None => panic!("queued work ended early"),
                }
            }
            assert_eq!(cleaned, SHARD_BATCH_SIZE / 2);
            assert_eq!(receiver.len(), SHARD_BATCH_SIZE / 2);
            Ok(())
        })
    }

    #[test]
    fn dropping_inbox_closes_and_drains_queued_replies() -> Result<(), Box<dyn Error>> {
        let account = account()?;
        let (sender, receiver) = async_channel::bounded(2);
        let inbox = Inbox(receiver);
        let (first, first_reply) = register_command(&account);
        let (second, second_reply) = register_command(&account);
        assert!(sender.try_send(first).is_ok());
        assert!(sender.try_send(second).is_ok());

        drop(inbox);

        assert!(sender.is_closed());
        assert!(matches!(first_reply.now_or_never(), Some(Err(_))));
        assert!(matches!(second_reply.now_or_never(), Some(Err(_))));
        Ok(())
    }

    #[test]
    fn queued_destination_command_rejects_revoked_and_retired_sources() -> Result<(), Box<dyn Error>>
    {
        Runtime::new()?.block_on(async {
            for retire in [false, true] {
                let alice = account()?;
                let mut arena = Arena::try_new(Default::default())?;
                let bob_jid = Jid::parse_in("bob@localhost/desk", &mut arena)?.resolve(&arena)?;
                let bob = AccountKey::try_from(bob_jid.bare())?;
                let mut source = Shard::<GlobalChunkAllocator>::new();
                let mut destination = Shard::<GlobalChunkAllocator>::new();
                let (commands, inbox) = async_channel::bounded(1);
                let router = test_router(commands);
                let (outbound, inbound) = async_channel::bounded(64);
                let desk = source.register(
                    alice.clone(),
                    Some("desk".into()),
                    NonZeroUsize::MIN,
                    outbound,
                    inbound,
                    router.clone(),
                )?;
                let (outbound, inbound) = async_channel::bounded(64);
                let observer = destination.register(
                    bob,
                    Some("desk".into()),
                    NonZeroUsize::MIN,
                    outbound,
                    inbound,
                    router.clone(),
                )?;
                source.record_directed_presence(
                    &alice,
                    "desk",
                    desk.token,
                    DirectedRecipient::new(bob_jid),
                    true,
                )?;
                let response =
                    routed("<presence from='alice@localhost/desk' to='bob@localhost/desk'/>")
                        .await?;
                let mut builder: PresenceBuilder<GlobalChunkAllocator> =
                    Box::new(move |_| Ok(Some(response.clone())));
                let mut selected = source.presence_access(
                    &alice,
                    Some("desk"),
                    &DirectedRecipient::new(bob_jid),
                    false,
                    &mut builder,
                )?;
                let delivery = selected.pop().ok_or("missing selection")?;
                let mut admitted = pin!(router.authorized_delivery(delivery));
                assert!(futures_util::poll!(admitted.as_mut()).is_pending());
                let command = inbox.recv().await?;
                if retire {
                    let withdrawal = source.end_presence(&alice, "desk", desk.token)?;
                    assert!(withdrawal.unavailable.is_none());
                    let (outbound, inbound) = async_channel::bounded(64);
                    let replacement = source.register(
                        alice.clone(),
                        Some("desk".into()),
                        NonZeroUsize::MIN,
                        outbound,
                        inbound,
                        router.clone(),
                    )?;
                    assert_ne!(replacement.token, desk.token);
                } else {
                    source.record_directed_presence(
                        &alice,
                        "desk",
                        desk.token,
                        DirectedRecipient::new(bob_jid),
                        false,
                    )?;
                    source.record_directed_presence(
                        &alice,
                        "desk",
                        desk.token,
                        DirectedRecipient::new(bob_jid),
                        true,
                    )?;
                }
                destination.command(command);
                admitted.await?;
                assert!(observer.take_queued().is_empty());
            }
            Ok(())
        })
    }

    #[test]
    fn committed_directed_unavailable_survives_source_retirement_and_replacement()
    -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            for evict in [false, true] {
                let alice = account()?;
                let mut arena = Arena::try_new(Default::default())?;
                let bob_jid = Jid::parse_in("bob@localhost/desk", &mut arena)?.resolve(&arena)?;
                let bob = AccountKey::try_from(bob_jid.bare())?;
                let mut source = Shard::<GlobalChunkAllocator>::new();
                let mut destination = Shard::<GlobalChunkAllocator>::new();
                let (commands, inbox) = async_channel::bounded(1);
                let router = test_router(commands);
                let (outbound, inbound) = async_channel::bounded(64);
                let desk = source.register(alice.clone(), Some("desk".into()), NonZeroUsize::MIN, outbound, inbound, router.clone())?;
                let session = desk.handle();
                let (outbound, inbound) = async_channel::bounded(64);
                let observer = destination.register(bob, Some("desk".into()), NonZeroUsize::MIN, outbound, inbound, router.clone())?;
                source.record_directed_presence(&alice, "desk", desk.token, DirectedRecipient::new(bob_jid), true)?;
                let unavailable = routed("<presence from='alice@localhost/desk' to='bob@localhost/desk' type='unavailable'/>").await?;
                let mut pending = pin!(session.directed_presence(unavailable, false));
                assert!(futures_util::poll!(pending.as_mut()).is_pending());
                source.command(inbox.recv().await?);
                assert!(source.accounts[alice.as_str()]["desk"].directed.is_empty());
                assert!(futures_util::poll!(pending.as_mut()).is_pending());
                let delivery = inbox.recv().await?;
                if evict {
                    source.remove(alice.as_str(), "desk", desk.token, RetireCause::Evicted);
                    let retired = desk.wait_retired().await?;
                    assert!(retired.unavailable.is_none());
                    assert!(retired.directed.take().ok_or("missing retired withdrawal")?.recipients.is_empty());
                } else {
                    let withdrawal = source.end_presence(&alice, "desk", desk.token)?;
                    assert!(withdrawal.unavailable.is_none());
                    assert!(withdrawal.directed.recipients.is_empty());
                }
                let (outbound, inbound) = async_channel::bounded(64);
                let replacement = source.register(alice.clone(), Some("desk".into()), NonZeroUsize::MIN, outbound, inbound, router.clone())?;
                assert_ne!(replacement.token, desk.token);
                source.record_directed_presence(&alice, "desk", replacement.token, DirectedRecipient::new(bob_jid), true)?;
                destination.command(delivery);
                pending.await?;
                let delivered = observer.take_queued();
                assert_eq!(delivered.len(), 1);
                assert_eq!(delivered[0].resolve()?.stanza_type(), StanzaType::Presence(PresenceType::Unavailable));
                source.finish_presence(&alice, desk.token);
                let replacement_state = &source.accounts[alice.as_str()]["desk"];
                assert_eq!(replacement_state.token, replacement.token);
                assert_eq!(replacement_state.directed.len(), 1);
                assert!(replacement_state.directed[0].live.load(Ordering::Acquire));
                assert_eq!(replacement_state.directed[0].recipient.as_str(), "bob@localhost/desk");
            }
            Ok(())
        })
    }
}
