// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque, hash_map::RandomState};
use std::future::Future;
use std::hash::BuildHasher;
use std::io;
use std::mem;
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};

use async_channel::{Receiver, Sender, TrySendError, WeakSender};
use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Either, Shared, poll_fn, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
use lonewolf_extension::delivery::{SessionTag, SessionTags};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator};
use lonewolf_util::core_dispatcher::{DispatchHandle, Task, TaskError, WorkerContext};
use lonewolf_xmpp::jid::{JidError, JidRef};
use lonewolf_xmpp::stanza::{IqType, MessageType, PresenceType, StanzaRef, StanzaType};

use super::{RoutedStanza, RouterError, RouterFailure, RouterFailureReason, RouterState};
use crate::config::limits::default_max_directed_presence_recipients_per_resource;

const SHARD_QUEUE_CAPACITY: usize = 1_024;
const RESOURCE_QUEUE_CAPACITY: usize = 64;
const SHARD_BATCH_SIZE: usize = 64;
const LAST_UNAVAILABLE_CAPACITY: usize = 1_024;

type TaggedStanzaFactory<A> = Box<dyn FnMut(&str) -> Result<RoutedStanza<A>, RouterError> + Send>;
type Retirement<A> = Shared<oneshot::Receiver<Retired<A>>>;

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

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ResourceMatch {
    pub(crate) token: u64,
}

pub(crate) struct PresenceSource<'a, A: ChunkAllocator> {
    pub(crate) resource: &'a str,
    pub(crate) presence: Option<&'a RoutedStanza<A>>,
    pub(crate) access: PresenceAccess,
}

pub(crate) struct DirectedWithdrawal {
    pub(crate) source_token: u64,
    pub(crate) recipients: Vec<DirectedRecipient>,
}

fn take_directed(grants: &mut Vec<DirectedRecipient>, token: u64) -> DirectedWithdrawal {
    DirectedWithdrawal {
        source_token: token,
        recipients: mem::take(grants),
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

pub struct LocalRouter<A: ChunkAllocator> {
    handle: LocalRouterHandle<A>,
    tasks: FuturesUnordered<ShardTask>,
    join_error: Option<TaskError>,
}

pub(super) struct LocalRouterHandle<A: ChunkAllocator> {
    shards: Arc<[Sender<Command<A>>]>,
    hash_state: RandomState,
    state: Arc<Mutex<RouterState>>,
    allocator: A,
}

/// Keeps a bound resource registered until this value is dropped.
pub struct Registration<A: ChunkAllocator> {
    account: AccountKey,
    resource: Box<str>,
    token: u64,
    alive: Arc<AtomicBool>,
    /// Defer these values during panic unwinding because dropping them wakes other tasks.
    links: mem::ManuallyDrop<Links<A>>,
}

struct Links<A: ChunkAllocator> {
    _lease: oneshot::Sender<()>,
    retired: Retirement<A>,
    inbound: Receiver<RoutedStanza<A>>,
    mailbox: WeakSender<RoutedStanza<A>>,
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
    RouterStopped,
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
    #[cfg(test)]
    Suspend {
        entered: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    },
    ResourceMatch {
        account: AccountKey,
        resource: Box<str>,
        reply: oneshot::Sender<Option<ResourceMatch>>,
    },
    Probe {
        requester: SessionHandle<A>,
        request: RoutedStanza<A>,
        subscribed: bool,
        reply: oneshot::Sender<Result<Option<RoutedStanza<A>>, RouterError>>,
    },
    DirectedPresence {
        account: AccountKey,
        resource: Box<str>,
        token: u64,
        recipient: DirectedRecipient,
        available: bool,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    #[cfg(test)]
    HasDirectedGrant {
        account: AccountKey,
        resource: Box<str>,
        observer: DirectedRecipient,
        reply: oneshot::Sender<bool>,
    },
    PruneDirected {
        stanza: RoutedStanza<A>,
        token: u64,
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
        source: Option<SessionLiveness>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    DeliverIqRequest {
        stanza: RoutedStanza<A>,
        subscribed: bool,
        source: Option<SessionLiveness>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    DeliverBare {
        stanza: RoutedStanza<A>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    DeliverPresence {
        stanza: RoutedStanza<A>,
        source: Option<SessionLiveness>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    DeliverPresenceError {
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
    directed: Vec<DirectedRecipient>,
    retired: oneshot::Sender<Retired<A>>,
}

impl<A: ChunkAllocator> Session<A> {
    fn accepts_bare_message(&self) -> bool {
        self.alive.load(Ordering::Acquire)
            && !self.outbound.is_closed()
            && self.priority.is_some_and(|priority| priority >= 0)
    }
}

struct LastUnavailable {
    at: SystemTime,
}

struct Shard<A: ChunkAllocator> {
    max_directed_presence_recipients_per_resource: NonZeroUsize,
    last_unavailable: VecDeque<(Box<str>, LastUnavailable)>,
    accounts: HashMap<Box<str>, HashMap<Box<str>, Session<A>>>,
    retiring: HashMap<Box<str>, HashMap<u64, RetiredPresence<A>>>,
    next_token: u64,
    cleanups: FuturesUnordered<BoxFuture<'static, (AccountKey, Box<str>, u64)>>,
}

struct ShardTask {
    shard_id: usize,
    task: Task<()>,
}

impl Future for ShardTask {
    type Output = (usize, Result<(), TaskError>);

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task)
            .poll(context)
            .map(|result| (self.shard_id, result))
    }
}

struct ShardOwner<A: ChunkAllocator> {
    shard: Shard<A>,
    inbox: Inbox<A>,
}

impl<A: ChunkAllocator> Drop for ShardOwner<A> {
    fn drop(&mut self) {
        self.shard.terminate();
        self.inbox.0.close();
        while self.inbox.0.try_recv().is_ok() {}
        release_deferred();
    }
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
        Self::start_with_directed_presence_limit(
            dispatcher,
            allocator,
            default_max_directed_presence_recipients_per_resource(),
        )
        .await
    }

    pub(crate) async fn start_with_directed_presence_limit(
        dispatcher: &DispatchHandle,
        allocator: A,
        max_directed_presence_recipients_per_resource: NonZeroUsize,
    ) -> io::Result<Self> {
        let count = dispatcher.worker_count();
        let mut senders = Vec::with_capacity(count);
        let tasks = FuturesUnordered::new();
        for worker in 0..count {
            let (sender, receiver) = async_channel::bounded(SHARD_QUEUE_CAPACITY);
            let receiver = Inbox(receiver);
            let task = dispatcher
                .dispatch_at(worker, move |context| {
                    Shard::with_directed_presence_limit(
                        max_directed_presence_recipients_per_resource,
                    )
                    .run(receiver, context)
                })
                .await?;
            senders.push(sender);
            tasks.push(ShardTask {
                shard_id: worker,
                task,
            });
        }
        Ok(Self {
            handle: LocalRouterHandle {
                shards: senders.into(),
                hash_state: RandomState::new(),
                state: Arc::new(Mutex::new(RouterState::Running)),
                allocator,
            },
            tasks,
            join_error: None,
        })
    }

    pub(super) fn handle(&self) -> LocalRouterHandle<A> {
        self.handle.clone()
    }

    pub(crate) fn state(&self) -> RouterState {
        self.handle.state()
    }

    pub(crate) fn stop(&self) {
        let mut state = self
            .handle
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *state == RouterState::Running {
            *state = RouterState::Stopping;
        }
    }

    pub(crate) async fn failure(&mut self) -> RouterFailure {
        loop {
            if let RouterState::Failed(failure) = self.state() {
                return failure;
            }
            let Some((shard_id, result)) = self.tasks.next().await else {
                return std::future::pending().await;
            };
            if let Err(error) = result {
                self.join_error.get_or_insert(error);
            }
            let mut state = self
                .handle
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *state == RouterState::Running {
                let reason = match result {
                    Ok(()) => RouterFailureReason::Completed,
                    Err(TaskError::Panicked) => RouterFailureReason::Panicked,
                    Err(TaskError::Cancelled) => RouterFailureReason::Cancelled,
                };
                let failure = RouterFailure { shard_id, reason };
                *state = RouterState::Failed(failure);
                for shard in self.handle.shards.iter() {
                    shard.close();
                }
                return failure;
            }
        }
    }

    pub async fn shutdown(mut self) -> io::Result<()> {
        self.stop();
        for shard in self.handle.shards.iter() {
            shard.close();
        }
        let mut error = match self.state() {
            RouterState::Failed(failure) => Some(io::Error::other(failure)),
            _ => self.join_error.map(io::Error::other),
        };
        while let Some((_, result)) = self.tasks.next().await {
            if let Err(failure) = result {
                error.get_or_insert_with(|| io::Error::other(failure));
            }
        }
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
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
            state: Arc::clone(&self.state),
            allocator: self.allocator.clone(),
        }
    }
}

impl<A: ChunkAllocator + Clone> LocalRouterHandle<A> {
    pub(super) fn state(&self) -> RouterState {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn allocator(&self) -> A {
        self.allocator.clone()
    }

    pub(crate) async fn resource_match(
        &self,
        account: &AccountKey,
        resource: &str,
    ) -> Result<Option<ResourceMatch>, RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard(account.as_str())
            .send(Command::ResourceMatch {
                account: account.clone(),
                resource: resource.into(),
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)
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

    async fn deliver_full_or_chat_fallback(
        &self,
        stanza: RoutedStanza<A>,
        fallback_chat: bool,
        source: Option<SessionLiveness>,
    ) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            self.full_target_shard(&view)?
        };
        let (reply, result) = oneshot::channel();
        self.shards[shard]
            .send(Command::Deliver {
                stanza,
                fallback_chat,
                source,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
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
        let (reply, result) = oneshot::channel();
        self.shards[shard]
            .send(Command::DeliverIqRequest {
                stanza,
                subscribed,
                source,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    pub(crate) async fn deliver_bare(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            self.bare_target_shard(&view)?
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
            self.bare_target_shard(&view)?
        };
        let (reply, result) = oneshot::channel();
        self.shards[shard]
            .send(Command::DeliverPresence {
                stanza,
                source: None,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
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
        let (reply, result) = oneshot::channel();
        self.shards[shard]
            .send(Command::DeliverPresence {
                stanza,
                source: Some(source),
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
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
        let (reply, result) = oneshot::channel();
        self.shards[shard]
            .send(Command::DeliverPresenceError { stanza, reply })
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
            self.bare_target_shard(&view)?
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

    #[cfg(test)]
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
        let (reply, result) = oneshot::channel();
        self.shard(source.bare().as_str())
            .send(Command::Probe {
                requester: requester.clone(),
                request: request.clone(),
                subscribed,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        if let Some(stanza) = result.await.map_err(|_| RouterError::Stopped)?? {
            let (reply, result) = oneshot::channel();
            requester
                .shard
                .send(Command::PruneDirected {
                    stanza,
                    token: requester.token,
                    reply,
                })
                .await
                .map_err(|_| RouterError::Stopped)?;
            result.await.map_err(|_| RouterError::Stopped)??;
        }
        Ok(())
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
    mailbox: WeakSender<RoutedStanza<A>>,
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
    fn terminate(&mut self) {
        for sessions in self.accounts.values() {
            for session in sessions.values() {
                session.alive.store(false, Ordering::Release);
            }
        }
        let directed = SharedDirectedWithdrawal(Arc::new(Mutex::new(None)));
        for (_, sessions) in self.accounts.drain() {
            for (_, session) in sessions {
                let _ = session.retired.send(Retired {
                    cause: RetireCause::RouterStopped,
                    unavailable: None,
                    directed: directed.clone(),
                });
                session.outbound.close();
                while session.inbound.try_recv().is_ok() {}
            }
        }
        self.retiring.clear();
        self.last_unavailable.clear();
        self.cleanups.clear();
    }
}

impl<A: ChunkAllocator + Clone> Shard<A> {
    #[cfg(test)]
    fn new() -> Self {
        Self::with_directed_presence_limit(default_max_directed_presence_recipients_per_resource())
    }

    fn with_directed_presence_limit(
        max_directed_presence_recipients_per_resource: NonZeroUsize,
    ) -> Self {
        Self {
            max_directed_presence_recipients_per_resource,
            last_unavailable: VecDeque::new(),
            accounts: HashMap::new(),
            retiring: HashMap::new(),
            next_token: 0,
            cleanups: FuturesUnordered::new(),
        }
    }

    async fn run(self, inbox: Inbox<A>, context: WorkerContext) {
        let mut owner = ShardOwner { shard: self, inbox };
        let result = AssertUnwindSafe(owner.shard.run_loop(&owner.inbox.0, context))
            .catch_unwind()
            .await;
        drop(owner);
        match result {
            Ok(Ok(())) => {}
            Ok(Err(payload)) | Err(payload) => resume_unwind(payload),
        }
    }

    async fn run_loop(
        &mut self,
        receiver: &Receiver<Command<A>>,
        context: WorkerContext,
    ) -> Result<(), Box<dyn Any + Send>> {
        let mut processed = 0;
        let mut prefer_cleanup = true;
        loop {
            if receiver.is_closed() {
                break;
            }
            let event = self
                .next_event(receiver, context.shutdown_requested(), prefer_cleanup)
                .await;
            if receiver.is_closed() {
                break;
            }
            match event {
                Some(Either::Left(command)) => {
                    #[cfg(test)]
                    if let Command::Suspend { entered, release } = command {
                        let _ = entered.send(());
                        let _ = release.await;
                        continue;
                    }
                    self.command(command)?;
                }
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
        Ok(())
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

    fn command(&mut self, command: Command<A>) -> Result<(), Box<dyn Any + Send>> {
        macro_rules! reply {
            ($sender:expr, $operation:expr) => {{
                // A reply or callback capture can wake tasks when it drops.
                let result = catch_unwind(AssertUnwindSafe(|| $operation))?;
                let _ = $sender.send(result);
            }};
        }
        match command {
            #[cfg(test)]
            Command::Suspend { .. } => unreachable!("suspension belongs to the actor loop"),
            Command::ResourceMatch {
                account,
                resource,
                reply,
            } => {
                reply!(
                    reply,
                    self.accounts
                        .get(account.as_str())
                        .and_then(|sessions| sessions.get(resource.as_ref()))
                        .filter(|session| {
                            session.alive.load(Ordering::Acquire) && !session.outbound.is_closed()
                        })
                        .map(|session| ResourceMatch {
                            token: session.token,
                        })
                );
            }
            Command::DirectedPresence {
                account,
                resource,
                token,
                recipient,
                available,
                reply,
            } => {
                reply!(
                    reply,
                    self.record_directed_presence(&account, &resource, token, recipient, available)
                );
            }
            #[cfg(test)]
            Command::HasDirectedGrant {
                account,
                resource,
                observer,
                reply,
            } => {
                reply!(
                    reply,
                    self.accounts
                        .get(account.as_str())
                        .and_then(|sessions| sessions.get(resource.as_ref()))
                        .is_some_and(|session| {
                            session.alive.load(Ordering::Acquire)
                                && !session.outbound.is_closed()
                                && session
                                    .directed
                                    .iter()
                                    .any(|grant| grant.matches_prepared(&observer))
                        })
                );
            }
            Command::Probe {
                requester,
                request,
                subscribed,
                reply,
            } => {
                reply!(reply, self.probe(&requester, &request, subscribed));
            }
            Command::PruneDirected {
                stanza,
                token,
                reply,
            } => {
                reply!(reply, self.prune_directed(&stanza, Some(token)));
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
                reply!(
                    reply,
                    self.register(account, requested, limit, outbound, inbound, router)
                );
            }
            Command::Deliver {
                stanza,
                fallback_chat,
                source,
                reply,
            } => {
                reply!(
                    reply,
                    match source {
                        Some(source) => {
                            self.deliver_with_guard(stanza, fallback_chat, || source.is_alive())
                        }
                        None => self.deliver(stanza, fallback_chat),
                    }
                );
            }
            Command::DeliverIqRequest {
                stanza,
                subscribed,
                source,
                reply,
            } => {
                reply!(reply, self.deliver_iq_request(stanza, subscribed, source));
            }
            Command::DeliverBare { stanza, reply } => {
                reply!(reply, self.deliver_bare(stanza, false));
            }
            Command::DeliverPresence {
                stanza,
                source,
                reply,
            } => {
                reply!(reply, self.deliver_presence(stanza, source.as_ref()));
            }
            Command::DeliverPresenceError { stanza, reply } => {
                reply!(
                    reply,
                    self.deliver_presence_where(stanza, |session| session.priority.is_some())
                );
            }
            Command::DeliverPresenceToTagged { tag, stanza, reply } => {
                reply!(reply, self.deliver_presence_to_tagged(tag, stanza));
            }
            Command::PresenceSnapshot { account, reply } => {
                reply!(reply, self.presence_snapshot(&account));
            }
            Command::WithdrawalSnapshot { account, reply } => {
                reply!(reply, self.withdrawal_snapshot(&account));
            }
            Command::Tag {
                account,
                resource,
                token,
                tag,
                reply,
            } => {
                reply!(reply, self.tag(&account, &resource, token, tag));
            }
            Command::DeliverToTagged {
                account,
                tag,
                mut build,
                reply,
            } => {
                reply!(reply, self.deliver_to_tagged(&account, tag, &mut build));
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
                reply!(
                    reply,
                    self.presence(&account, &resource, token, priority, stanza, unavailable)
                );
            }
            Command::EndPresence {
                account,
                resource,
                token,
                reply,
            } => {
                reply!(reply, self.end_presence(&account, &resource, token));
            }
            Command::ReplacementAvailable {
                account,
                resource,
                token,
                reply,
            } => {
                reply!(
                    reply,
                    self.replacement_is_available(&account, &resource, token)
                );
            }
            Command::FinishPresence {
                account,
                token,
                reply,
            } => {
                reply!(reply, self.finish_presence(&account, token));
            }
            Command::RetireAccount { account, reply } => {
                reply!(reply, self.retire_account(&account));
            }
        }
        Ok(())
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
        if router.state() != RouterState::Running {
            return Err(RouterError::Stopped);
        }
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
        let mailbox = outbound.downgrade();
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
                mailbox,
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
        let known = source.directed.iter().position(|grant| *grant == recipient);
        match (available, known) {
            (true, None) => {
                if source.directed.len() >= self.max_directed_presence_recipients_per_resource.get()
                {
                    return Err(RouterError::DirectedPresenceLimit);
                }
                source.directed.push(recipient);
            }
            (false, Some(index)) => {
                source.directed.swap_remove(index);
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
        build: &mut impl for<'a> FnMut(
            PresenceSource<'a, A>,
        ) -> Result<Option<RoutedStanza<A>>, RouterError>,
    ) -> Result<Vec<RoutedStanza<A>>, RouterError> {
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
            let access = PresenceAccess {
                subscribed,
                directed: session
                    .directed
                    .iter()
                    .any(|grant| grant.matches_prepared(observer)),
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
            if to.as_str() != observer.as_str() {
                return Err(RouterError::InvalidTarget);
            }
            deliveries.push(stanza);
        }
        Ok(deliveries)
    }

    fn probe(
        &self,
        requester: &SessionHandle<A>,
        request: &RoutedStanza<A>,
        subscribed: bool,
    ) -> Result<Option<RoutedStanza<A>>, RouterError> {
        let view = request.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let observer = view
            .from()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        if !requester.matches(observer)
            || view.stanza_type() != StanzaType::Presence(PresenceType::Probe)
        {
            return Err(RouterError::InvalidTarget);
        }
        let target = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let owner = AccountKey::try_from(target.bare()).map_err(|_| RouterError::InvalidTarget)?;
        let ordinary = subscribed || owner.as_str() == observer.bare().as_str();
        let full = target.resourcepart().is_some();
        let mut build = |source: PresenceSource<'_, A>| {
            if !full && ordinary {
                return source
                    .presence
                    .map(|presence| {
                        super::probe_current(request, presence, requester.router.allocator.clone())
                    })
                    .transpose();
            }
            if source.presence.is_none() && !source.access.directed {
                return Ok(None);
            }
            let from = format!("{}/{}", owner.as_str(), source.resource);
            super::probe_reply(
                request,
                &from,
                PresenceType::Available,
                None,
                requester.router.allocator.clone(),
            )
            .map(Some)
        };
        let mut deliveries = self.presence_access(
            &owner,
            target.resourcepart(),
            &DirectedRecipient::new(observer),
            subscribed,
            &mut build,
        )?;
        let mut unavailable = None;
        if deliveries.is_empty() {
            let (from, kind, at) = if ordinary {
                (
                    target.as_str(),
                    PresenceType::Unavailable,
                    if full {
                        None
                    } else {
                        self.last_unavailable
                            .iter()
                            .find(|(account, _)| account.as_ref() == target.bare().as_str())
                            .map(|(_, value)| value.at)
                    },
                )
            } else {
                (target.bare().as_str(), PresenceType::Unsubscribed, None)
            };
            let stanza =
                super::probe_reply(request, from, kind, at, requester.router.allocator.clone())?;
            if kind == PresenceType::Unavailable {
                unavailable = Some(stanza.clone());
            }
            deliveries.push(stanza);
        }
        if !requester.liveness.is_alive() {
            return Ok(None);
        }
        let Some(sender) = requester.mailbox.upgrade() else {
            return Ok(None);
        };
        for stanza in deliveries {
            match sender.try_send(stanza) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Closed(_)) => return Ok(None),
            }
        }
        Ok(unavailable)
    }

    fn has_available(&self, account: &str) -> bool {
        self.accounts
            .get(account)
            .is_some_and(|sessions| sessions.values().any(|session| session.priority.is_some()))
    }

    fn record_last_unavailable(&mut self, account: &str) {
        if self
            .last_unavailable
            .iter()
            .any(|(known, _)| known.as_ref() == account)
        {
            return;
        }
        if self.last_unavailable.len() == LAST_UNAVAILABLE_CAPACITY {
            self.last_unavailable.pop_front();
        }
        self.last_unavailable.push_back((
            account.into(),
            LastUnavailable {
                at: SystemTime::now(),
            },
        ));
    }

    fn prune_directed(
        &mut self,
        stanza: &RoutedStanza<A>,
        token: Option<u64>,
    ) -> Result<(), RouterError> {
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
                || token.is_some_and(|token| session.token != token)
                || !session.alive.load(Ordering::Acquire)
            {
                continue;
            }
            session.directed.retain(|grant| {
                if sender.resourcepart().is_some() {
                    grant.as_str() != sender.as_str()
                } else {
                    grant.bare() != sender.as_str()
                }
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
        self.prune_directed(&stanza, None)?;
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
            result => result,
        }
    }

    fn deliver_iq_request(
        &mut self,
        stanza: RoutedStanza<A>,
        subscribed: bool,
        source: Option<SessionLiveness>,
    ) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        if !matches!(
            view.stanza_type(),
            StanzaType::Iq(IqType::Get | IqType::Set)
        ) {
            return Err(RouterError::InvalidTarget);
        }
        let observer = view
            .from()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let resource = to.resourcepart().ok_or(RouterError::InvalidTarget)?;
        let session = self
            .accounts
            .get(to.bare().as_str())
            .and_then(|sessions| sessions.get(resource))
            .ok_or(RouterError::NotFound)?;
        if !session.alive.load(Ordering::Acquire) || session.outbound.is_closed() {
            let token = session.token;
            self.remove(to.bare().as_str(), resource, token, RetireCause::Evicted);
            return Err(RouterError::NotFound);
        }
        if !subscribed
            && to.bare() != observer.bare()
            && !session.directed.iter().any(|grant| {
                grant.as_str() == observer.as_str()
                    || (!grant.as_str().contains('/') && grant.as_str() == observer.bare().as_str())
            })
        {
            return Err(RouterError::NotFound);
        }
        self.deliver_with_guard(stanza, false, || {
            source.as_ref().is_none_or(SessionLiveness::is_alive)
        })
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

    fn deliver_presence(
        &mut self,
        stanza: RoutedStanza<A>,
        source: Option<&SessionLiveness>,
    ) -> Result<(), RouterError> {
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
        self.deliver_presence_where_with_guard(
            stanza,
            |session| session.priority.is_some(),
            || source.is_none_or(SessionLiveness::is_alive),
        )
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
        self.prune_directed(&stanza, None)?;
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
        let had_available = self.has_available(account.as_str());
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
        if priority.is_some() {
            self.last_unavailable
                .retain(|(known, _)| known.as_ref() != account.as_str());
        } else if had_available && !self.has_available(account.as_str()) {
            self.record_last_unavailable(account.as_str());
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
        let had_available = self.has_available(account.as_str());
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
        if had_available && !self.has_available(account.as_str()) {
            self.record_last_unavailable(account.as_str());
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
        self.last_unavailable
            .retain(|(known, _)| known.as_ref() != account.as_str());
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
        let had_available = self.has_available(account);
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
        if cause == RetireCause::Evicted && had_available && !self.has_available(account) {
            self.record_last_unavailable(account);
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
            state: Arc::new(Mutex::new(RouterState::Running)),
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
    fn invalid_target_forms_fail_before_command_submission() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let (sender, receiver) = async_channel::bounded(1);
            let router = test_router(sender);
            for target in [
                "",
                " to='localhost'",
                " to='localhost/desk'",
                " to='alice@localhost'",
            ] {
                let xml = format!("<presence type='error'{target}><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>");
                assert_eq!(
                    router
                        .deliver_full_or_chat_fallback(routed(&xml).await?, false, None)
                        .now_or_never(),
                    Some(Err(RouterError::InvalidTarget))
                );
                assert!(receiver.is_empty());
                assert_eq!(
                    router
                        .deliver_iq_request(routed(&xml).await?, false, None)
                        .now_or_never(),
                    Some(Err(RouterError::InvalidTarget))
                );
                assert!(receiver.is_empty());
            }
            for target in [
                "",
                " to='localhost'",
                " to='localhost/desk'",
                " to='alice@localhost/desk'",
            ] {
                let xml = format!("<presence type='error'{target}><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>");
                assert_eq!(
                    router.deliver_bare(routed(&xml).await?).now_or_never(),
                    Some(Err(RouterError::InvalidTarget))
                );
                assert!(receiver.is_empty());
                assert_eq!(
                    router.deliver_presence(routed(&xml).await?).now_or_never(),
                    Some(Err(RouterError::InvalidTarget))
                );
                assert!(receiver.is_empty());
                assert_eq!(
                    router
                        .deliver_presence_error(routed(&xml).await?)
                        .now_or_never(),
                    Some(Err(RouterError::InvalidTarget))
                );
                assert!(receiver.is_empty());
                assert_eq!(
                    router
                        .deliver_presence_to_tagged(SessionTag::Interested, routed(&xml).await?)
                        .now_or_never(),
                    Some(Err(RouterError::InvalidTarget))
                );
                assert!(receiver.is_empty());
            }
            assert_eq!(
                router
                    .deliver_presence_error(routed("<presence to='alice@localhost'/>").await?)
                    .now_or_never(),
                Some(Err(RouterError::InvalidTarget))
            );
            assert!(receiver.is_empty());
            Ok(())
        })
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
    fn full_normal_delivery_linearizes_at_exact_resource_binding_and_disconnect()
    -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            for sibling_priority in [None, Some(-1), Some(0)] {
                for closed in [false, true] {
                    let account = account()?;
                    let mut shard = Shard::<GlobalChunkAllocator>::new();
                    let (commands, _) = async_channel::bounded(1);
                    let limit = NonZeroUsize::new(2).ok_or("zero resource limit")?;
                    let (outbound, inbound) = async_channel::bounded(64);
                    let sibling = shard.register(
                        account.clone(),
                        Some("phone".into()),
                        limit,
                        outbound,
                        inbound,
                        test_router(commands.clone()),
                    )?;
                    shard
                        .accounts
                        .get_mut(account.as_str())
                        .ok_or("missing account")?
                        .get_mut("phone")
                        .ok_or("missing sibling")?
                        .priority = sibling_priority;
                    let stanza =
                        routed("<message to='alice@localhost/desk' type='normal'/>").await?;
                    assert_eq!(
                        shard.deliver(stanza.clone(), true),
                        Err(RouterError::NotFound)
                    );
                    let (outbound, inbound) = async_channel::bounded(64);
                    let desk = shard.register(
                        account.clone(),
                        Some("desk".into()),
                        limit,
                        outbound,
                        inbound,
                        test_router(commands),
                    )?;
                    for priority in [None, Some(-1)] {
                        shard
                            .accounts
                            .get_mut(account.as_str())
                            .ok_or("missing account")?
                            .get_mut("desk")
                            .ok_or("missing resource")?
                            .priority = priority;
                        assert_eq!(shard.deliver(stanza.clone(), true), Ok(()));
                        let delivered = desk.links.inbound.try_recv()?;
                        assert_eq!(
                            delivered.resolve()?.to()?.ok_or("missing target")?.as_str(),
                            "alice@localhost/desk"
                        );
                    }
                    if closed {
                        desk.links.inbound.close();
                    } else {
                        desk.alive.store(false, Ordering::Release);
                    }
                    assert_eq!(
                        shard.deliver(stanza.clone(), true),
                        Err(RouterError::NotFound)
                    );
                    assert_eq!(shard.deliver(stanza, true), Err(RouterError::NotFound));
                    assert!(sibling.take_queued().is_empty());
                    assert!(!shard.accounts[account.as_str()].contains_key("desk"));
                }
            }
            Ok(())
        })
    }

    #[test]
    fn resource_match_ignores_dead_and_closed_sessions() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            for closed in [false, true] {
                let account = account()?;
                let mut shard = Shard::<GlobalChunkAllocator>::new();
                let (commands, _) = async_channel::bounded(1);
                let (outbound, inbound) = async_channel::bounded(64);
                let registration = shard.register(
                    account.clone(),
                    Some("desk".into()),
                    NonZeroUsize::MIN,
                    outbound,
                    inbound,
                    test_router(commands),
                )?;
                if closed {
                    registration.links.inbound.close();
                } else {
                    registration.alive.store(false, Ordering::Release);
                }
                let (reply, result) = oneshot::channel();
                assert!(
                    shard
                        .command(Command::ResourceMatch {
                            account,
                            resource: "desk".into(),
                            reply,
                        })
                        .is_ok()
                );
                assert_eq!(result.await?, None);
            }
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
        for xml in [
            "<message to='alice@localhost/desk'/>",
            "<presence from='bob@localhost/desk' to='alice@localhost/desk' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>",
        ] {
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
                    Some(
                        routed("<presence from='alice@localhost/desk' type='unavailable'/>")
                            .await?,
                    ),
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
                    shard.deliver(routed(xml).await?, false),
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
                assert!(phone.take_queued().is_empty());
                Ok::<_, Box<dyn Error>>(())
            })?;
        }
        Ok(())
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

    fn directed_recipient(text: &str) -> Result<DirectedRecipient, Box<dyn Error>> {
        let mut arena = Arena::try_new(Default::default())?;
        Ok(DirectedRecipient::new(
            Jid::parse_in(text, &mut arena)?.resolve(&arena)?,
        ))
    }

    #[test]
    fn directed_presence_limit_counts_exact_recipients_per_resource() -> Result<(), Box<dyn Error>>
    {
        Runtime::new()?.block_on(async {
            let alice = account()?;
            let mut shard =
                Shard::with_directed_presence_limit(NonZeroUsize::new(2).ok_or("zero limit")?);
            let (commands, _) = async_channel::bounded(1);
            let router = test_router(commands);
            let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
            let phone = register_probe_session(&mut shard, &router, &alice, "phone")?;
            for target in ["bob@localhost", "bob@localhost/desk"] {
                shard.record_directed_presence(
                    &alice,
                    "desk",
                    desk.token,
                    directed_recipient(target)?,
                    true,
                )?;
            }
            shard.record_directed_presence(
                &alice,
                "desk",
                desk.token,
                directed_recipient("bob@localhost")?,
                true,
            )?;
            assert_eq!(
                shard.accounts[alice.as_str()]["desk"].directed[0].as_str(),
                "bob@localhost"
            );
            assert_eq!(shard.accounts[alice.as_str()]["desk"].directed.len(), 2);
            assert_eq!(
                shard.record_directed_presence(
                    &alice,
                    "desk",
                    desk.token,
                    directed_recipient("carol@localhost")?,
                    true
                ),
                Err(RouterError::DirectedPresenceLimit)
            );
            assert_eq!(shard.accounts[alice.as_str()]["desk"].directed.len(), 2);
            shard.record_directed_presence(
                &alice,
                "phone",
                phone.token,
                directed_recipient("carol@localhost")?,
                true,
            )?;
            assert_eq!(shard.accounts[alice.as_str()]["phone"].directed.len(), 1);
            shard.record_directed_presence(
                &alice,
                "desk",
                desk.token,
                directed_recipient("alice@localhost/phone")?,
                true,
            )?;
            shard.record_directed_presence(
                &alice,
                "desk",
                desk.token,
                directed_recipient("unknown@localhost")?,
                false,
            )?;
            assert_eq!(shard.accounts[alice.as_str()]["desk"].directed.len(), 2);
            shard.record_directed_presence(
                &alice,
                "desk",
                desk.token,
                directed_recipient("bob@localhost")?,
                false,
            )?;
            assert!(
                shard.accounts[alice.as_str()]["desk"]
                    .directed
                    .iter()
                    .all(|grant| grant.as_str() != "bob@localhost")
            );
            shard.record_directed_presence(
                &alice,
                "desk",
                desk.token,
                directed_recipient("bob@localhost")?,
                true,
            )?;
            assert_eq!(
                shard.accounts[alice.as_str()]["desk"].directed[1].as_str(),
                "bob@localhost"
            );
            assert_eq!(shard.accounts[alice.as_str()]["desk"].directed.len(), 2);
            Ok(())
        })
    }

    #[test]
    fn recipient_unavailable_releases_directed_presence_limit() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            for sender in ["bob@localhost/desk", "bob@localhost"] {
                let alice = account()?;
                let mut shard =
                    Shard::with_directed_presence_limit(NonZeroUsize::new(2).ok_or("zero limit")?);
                let (commands, _) = async_channel::bounded(1);
                let router = test_router(commands);
                let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
                for target in ["bob@localhost", "bob@localhost/desk"] {
                    shard.record_directed_presence(
                        &alice,
                        "desk",
                        desk.token,
                        directed_recipient(target)?,
                        true,
                    )?;
                }
                shard.prune_directed(
                    &routed(&format!(
                        "<presence from='{sender}' to='alice@localhost/desk' type='unavailable'/>"
                    ))
                    .await?,
                    None,
                )?;
                assert_eq!(
                    shard.accounts[alice.as_str()]["desk"].directed.len(),
                    usize::from(sender.contains('/'))
                );
                if sender.contains('/') {
                    assert_eq!(
                        shard.accounts[alice.as_str()]["desk"].directed[0].as_str(),
                        "bob@localhost"
                    );
                }
                shard.record_directed_presence(
                    &alice,
                    "desk",
                    desk.token,
                    directed_recipient("bob@localhost/desk")?,
                    true,
                )?;
                assert_eq!(
                    shard.accounts[alice.as_str()]["desk"]
                        .directed
                        .last()
                        .ok_or("missing grant")?
                        .as_str(),
                    "bob@localhost/desk"
                );
            }
            Ok(())
        })
    }

    #[test]
    fn directed_presence_limit_resets_on_withdrawal_and_retirement_without_touching_replacements()
    -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            for action in ["unavailable", "disconnect", "evict", "delete", "drop"] {
                let alice = account()?;
                let mut shard = Shard::with_directed_presence_limit(NonZeroUsize::MIN);
                let (commands, _) = async_channel::bounded(1);
                let router = test_router(commands);
                let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
                let token = desk.token;
                shard.record_directed_presence(
                    &alice,
                    "desk",
                    token,
                    directed_recipient("bob@localhost")?,
                    true,
                )?;
                let mut held = Some(desk);
                match action {
                    "unavailable" => {
                        let change = shard.presence(
                            &alice,
                            "desk",
                            token,
                            None,
                            routed("<presence from='alice@localhost/desk' type='unavailable'/>")
                                .await?,
                            None,
                        )?;
                        assert_eq!(change.directed.recipients.len(), 1);
                        assert_eq!(change.directed.recipients[0].as_str(), "bob@localhost");
                        assert!(shard.accounts[alice.as_str()]["desk"].directed.is_empty());
                    }
                    "disconnect" => {
                        let withdrawal = shard.end_presence(&alice, "desk", token)?;
                        assert_eq!(withdrawal.directed.recipients.len(), 1);
                        assert_eq!(withdrawal.directed.recipients[0].as_str(), "bob@localhost");
                        assert!(shard.accounts[alice.as_str()]["desk"].directed.is_empty());
                    }
                    "delete" => shard.retire_account(&alice),
                    "drop" => {
                        drop(held.take());
                        let (owner, resource, old_token) =
                            shard.cleanups.next().await.ok_or("missing cleanup")?;
                        shard.remove(owner.as_str(), &resource, old_token, RetireCause::Evicted);
                    }
                    _ => shard.remove(alice.as_str(), "desk", token, RetireCause::Evicted),
                }
                if !matches!(action, "unavailable" | "disconnect") {
                    assert!(
                        shard
                            .accounts
                            .get(alice.as_str())
                            .is_none_or(|sessions| !sessions.contains_key("desk")),
                        "{action}"
                    );
                }
                let replacement = if action == "unavailable" {
                    held.take().ok_or("missing registration")?
                } else {
                    register_probe_session(&mut shard, &router, &alice, "desk")?
                };
                assert!(shard.accounts[alice.as_str()]["desk"].directed.is_empty());
                shard.record_directed_presence(
                    &alice,
                    "desk",
                    replacement.token,
                    directed_recipient("carol@localhost")?,
                    true,
                )?;
                if action != "unavailable" {
                    assert_ne!(token, replacement.token);
                    assert_eq!(
                        shard.record_directed_presence(
                            &alice,
                            "desk",
                            token,
                            directed_recipient("carol@localhost")?,
                            false
                        ),
                        Err(RouterError::NotFound)
                    );
                    assert!(matches!(
                        shard.end_presence(&alice, "desk", token),
                        Err(RouterError::NotFound)
                    ));
                    shard.remove(alice.as_str(), "desk", token, RetireCause::Evicted);
                    shard.finish_presence(&alice, token);
                }
                let grants = &shard.accounts[alice.as_str()]["desk"].directed;
                assert_eq!(grants.len(), 1);
                assert_eq!(grants[0].as_str(), "carol@localhost");
                assert_eq!(
                    shard.record_directed_presence(
                        &alice,
                        "desk",
                        replacement.token,
                        directed_recipient("dave@localhost")?,
                        true
                    ),
                    Err(RouterError::DirectedPresenceLimit)
                );
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
                assert!(source.command(inbox.recv().await?).is_ok());
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
                assert!(destination.command(delivery).is_ok());
                pending.await?;
                let delivered = observer.take_queued();
                assert_eq!(delivered.len(), 1);
                assert_eq!(delivered[0].resolve()?.stanza_type(), StanzaType::Presence(PresenceType::Unavailable));
                source.finish_presence(&alice, desk.token);
                let replacement_state = &source.accounts[alice.as_str()]["desk"];
                assert_eq!(replacement_state.token, replacement.token);
                assert_eq!(replacement_state.directed.len(), 1);
                assert_eq!(replacement_state.directed[0].as_str(), "bob@localhost/desk");
            }
            Ok(())
        })
    }
    fn register_probe_session(
        shard: &mut Shard<GlobalChunkAllocator>,
        router: &LocalRouterHandle<GlobalChunkAllocator>,
        owner: &AccountKey,
        resource: &str,
    ) -> Result<Registration<GlobalChunkAllocator>, Box<dyn Error>> {
        let (outbound, inbound) = async_channel::bounded(64);
        Ok(shard.register(
            owner.clone(),
            Some(resource.into()),
            NonZeroUsize::new(4).ok_or("zero limit")?,
            outbound,
            inbound,
            router.clone(),
        )?)
    }

    #[test]
    fn queued_iq_admission_rechecks_source_retirement_and_replacement() -> Result<(), Box<dyn Error>>
    {
        Runtime::new()?.block_on(async {
            for kind in ["get", "set", "result", "error"] {
                for action in ["unchanged", "drop", "evict", "replace"] {
                    let alice = account()?;
                    let mut arena = Arena::try_new(Default::default())?;
                    let bob = AccountKey::try_from(
                        Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?
                    )?;
                    let mut source = Shard::<GlobalChunkAllocator>::new();
                    let mut destination = Shard::<GlobalChunkAllocator>::new();
                    let (commands, inbox) = async_channel::bounded(1);
                    let router = test_router(commands);
                    let origin = register_probe_session(&mut source, &router, &alice, "desk")?;
                    let target = register_probe_session(&mut destination, &router, &bob, "phone")?;
                    let token = origin.token;
                    let liveness = origin.liveness();
                    let error = if kind == "error" {
                        "<error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
                    } else {
                        ""
                    };
                    let stanza = routed(&format!(
                        "<iq type='{kind}' from='alice@localhost/desk' to='bob@localhost/phone' id='queued'><query xmlns='urn:test:iq'/>{error}</iq>"
                    )).await?;
                    let mut admission = pin!(async {
                        if matches!(kind, "get" | "set") {
                            router.deliver_iq_request(stanza, true, Some(liveness)).await
                        } else {
                            router.deliver_full_guarded(stanza, liveness).await
                        }
                    });
                    assert!(futures_util::poll!(admission.as_mut()).is_pending());
                    let command = inbox.recv().await?;
                    let mut replacement = None;
                    match action {
                        "drop" => drop(origin),
                        "evict" => {
                            source.remove(alice.as_str(), "desk", token, RetireCause::Evicted);
                        }
                        "replace" => {
                            source.remove(alice.as_str(), "desk", token, RetireCause::Evicted);
                            replacement = Some(register_probe_session(&mut source, &router, &alice, "desk")?);
                            assert_ne!(replacement.as_ref().ok_or("missing replacement")?.token, token);
                        }
                        _ => {}
                    }
                    assert!(destination.command(command).is_ok());
                    admission.await?;
                    assert_eq!(target.take_queued().len(), usize::from(action == "unchanged"), "{kind} {action}");
                    drop(replacement);
                }
            }
            Ok(())
        })
    }

    #[test]
    fn probe_replies_enter_the_requester_mailbox() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let alice = account()?;
            let mut arena = Arena::try_new(Default::default())?;
            let bob = AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;
            let (commands, _) = async_channel::bounded(1);
            let router = test_router(commands);
            let mut shard = Shard::<GlobalChunkAllocator>::new();
            let observer = register_probe_session(&mut shard, &router, &bob, "desk")?;
            let request = routed("<presence from='bob@localhost/desk' to='alice@localhost' type='probe' id='none'/>").await?;
            let unavailable = shard.probe(&observer.handle(), &request, true)?.ok_or("missing unavailable")?;
            assert_eq!(unavailable.resolve()?.stanza_type(), StanzaType::Presence(PresenceType::Unavailable));
            let replies = observer.take_queued();
            assert_eq!(replies.len(), 1);
            let view = replies[0].resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Unavailable));
            assert_eq!(view.from()?.ok_or("missing source")?.as_str(), "alice@localhost");
            assert_eq!(view.to()?.ok_or("missing target")?.as_str(), "bob@localhost/desk");
            assert_eq!(view.id()?, Some("none"));
            assert!(view.child("delay", "urn:xmpp:delay")?.is_none());

            let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
            shard.presence(&alice, "desk", desk.token, Some(0), routed("<presence from='alice@localhost/desk' id='p'><status>here</status></presence>").await?, None)?;
            let request = routed("<presence from='bob@localhost/desk' to='alice@localhost' type='probe' id='bare'/>").await?;
            assert!(shard.probe(&observer.handle(), &request, true)?.is_none());
            let replies = observer.take_queued();
            assert_eq!(replies.len(), 1);
            let view = replies[0].resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Available));
            assert_eq!(view.from()?.ok_or("missing source")?.as_str(), "alice@localhost/desk");
            assert_eq!(view.to()?.ok_or("missing target")?.as_str(), "bob@localhost/desk");
            assert_eq!(view.child("status", "jabber:client")?.ok_or("missing status")?.text()?, Some("here"));

            let request = routed("<presence from='bob@localhost/desk' to='alice@localhost/desk' type='probe' id='full'/>").await?;
            assert!(shard.probe(&observer.handle(), &request, true)?.is_none());
            let replies = observer.take_queued();
            assert_eq!(replies.len(), 1);
            let view = replies[0].resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Available));
            assert_eq!(view.from()?.ok_or("missing source")?.as_str(), "alice@localhost/desk");
            assert_eq!(view.to()?.ok_or("missing target")?.as_str(), "bob@localhost/desk");
            assert_eq!(view.id()?, Some("full"));
            assert!(view.children()?.next().is_none());

            let request = routed("<presence from='bob@localhost/desk' to='alice@localhost' type='probe' id='denied'/>").await?;
            assert!(shard.probe(&observer.handle(), &request, false)?.is_none());
            let replies = observer.take_queued();
            assert_eq!(replies.len(), 1);
            let view = replies[0].resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Unsubscribed));
            assert_eq!(view.from()?.ok_or("missing source")?.as_str(), "alice@localhost");
            assert_eq!(view.to()?.ok_or("missing target")?.as_str(), "bob@localhost/desk");
            assert_eq!(view.id()?, Some("denied"));
            Ok(())
        })
    }

    #[test]
    fn probe_reply_never_reaches_an_ended_requester_or_its_replacement()
    -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            for action in ["end", "evict", "drop", "closed_only"] {
                let alice = account()?;
                let mut arena = Arena::try_new(Default::default())?;
                let bob = AccountKey::try_from(
                    Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?,
                )?;
                let (commands, _) = async_channel::bounded(1);
                let router = test_router(commands);
                let mut source = Shard::<GlobalChunkAllocator>::new();
                let mut destination = Shard::<GlobalChunkAllocator>::new();
                let desk = register_probe_session(&mut source, &router, &alice, "desk")?;
                source.presence(
                    &alice,
                    "desk",
                    desk.token,
                    Some(0),
                    routed("<presence from='alice@localhost/desk'/>").await?,
                    None,
                )?;
                let observer = register_probe_session(&mut destination, &router, &bob, "desk")?;
                let old = observer.handle();
                let old_mailbox = observer.mailbox();
                let replacement = match action {
                    "end" => {
                        destination.end_presence(&bob, "desk", old.token)?;
                        Some(register_probe_session(
                            &mut destination,
                            &router,
                            &bob,
                            "desk",
                        )?)
                    }
                    "evict" => {
                        destination.remove(bob.as_str(), "desk", old.token, RetireCause::Evicted);
                        Some(register_probe_session(
                            &mut destination,
                            &router,
                            &bob,
                            "desk",
                        )?)
                    }
                    "drop" => {
                        drop(observer);
                        None
                    }
                    _ => {
                        observer.links.inbound.close();
                        None
                    }
                };
                assert_eq!(old.liveness.is_alive(), action == "closed_only");
                let request = routed(
                    "<presence from='bob@localhost/desk' to='alice@localhost' type='probe'/>",
                )
                .await?;
                assert!(source.probe(&old, &request, true)?.is_none());
                assert!(old_mailbox.take_queued().is_empty());
                if let Some(replacement) = replacement {
                    assert_eq!(replacement.resource(), "desk");
                    assert_ne!(replacement.token, old.token);
                    assert!(replacement.take_queued().is_empty());
                }
            }
            Ok(())
        })
    }

    #[test]
    fn probe_reads_grants_when_it_runs() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let alice = account()?;
            let mut arena = Arena::try_new(Default::default())?;
            let bob = AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;
            let (commands, _) = async_channel::bounded(1);
            let router = test_router(commands);
            let mut shard = Shard::<GlobalChunkAllocator>::new();
            let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
            let observer = register_probe_session(&mut shard, &router, &bob, "desk")?;
            let request = routed("<presence from='bob@localhost/desk' to='alice@localhost' type='probe' id='directed'/>").await?;
            for available in [true, false] {
                shard.record_directed_presence(&alice, "desk", desk.token, directed_recipient("bob@localhost/desk")?, available)?;
                assert!(shard.probe(&observer.handle(), &request, false)?.is_none());
                let replies = observer.take_queued();
                assert_eq!(replies.len(), 1);
                let view = replies[0].resolve()?;
                let (kind, from) = if available {
                    (PresenceType::Available, "alice@localhost/desk")
                } else {
                    (PresenceType::Unsubscribed, "alice@localhost")
                };
                assert_eq!(view.stanza_type(), StanzaType::Presence(kind));
                assert_eq!(view.from()?.ok_or("missing source")?.as_str(), from);
                assert_eq!(view.to()?.ok_or("missing target")?.as_str(), "bob@localhost/desk");
                assert_eq!(view.id()?, Some("directed"));
                assert!(view.children()?.next().is_none());
            }
            Ok(())
        })
    }

    #[test]
    fn requester_prune_is_limited_to_its_generation() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let mut arena = Arena::try_new(Default::default())?;
            let bob =
                AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;
            let (commands, _) = async_channel::bounded(1);
            let router = test_router(commands);
            let mut shard = Shard::<GlobalChunkAllocator>::new();
            let observer = register_probe_session(&mut shard, &router, &bob, "desk")?;
            shard.record_directed_presence(
                &bob,
                "desk",
                observer.token,
                directed_recipient("alice@localhost")?,
                true,
            )?;
            let stanza = routed(
                "<presence from='alice@localhost' to='bob@localhost/desk' type='unavailable'/>",
            )
            .await?;
            shard.prune_directed(&stanza, Some(observer.token + 1))?;
            assert_eq!(shard.accounts[bob.as_str()]["desk"].directed.len(), 1);
            shard.prune_directed(&stanza, Some(observer.token))?;
            assert!(shard.accounts[bob.as_str()]["desk"].directed.is_empty());
            Ok(())
        })
    }

    #[test]
    fn full_probe_mailbox_preserves_the_requester_and_unavailable_prune()
    -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let alice = account()?;
            let mut arena = Arena::try_new(Default::default())?;
            let bob =
                AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;
            let (commands, _) = async_channel::bounded(1);
            let router = test_router(commands);
            let mut shard = Shard::<GlobalChunkAllocator>::new();
            let (outbound, inbound) = async_channel::bounded(1);
            let observer = shard.register(
                bob.clone(),
                Some("desk".into()),
                NonZeroUsize::MIN,
                outbound,
                inbound,
                router.clone(),
            )?;
            let queued = routed(
                "<presence from='carol@localhost/desk' to='bob@localhost/desk' id='queued'/>",
            )
            .await?;
            shard.accounts[bob.as_str()]["desk"]
                .outbound
                .try_send(queued)?;
            shard.record_directed_presence(
                &bob,
                "desk",
                observer.token,
                directed_recipient("alice@localhost")?,
                true,
            )?;
            let request =
                routed("<presence from='bob@localhost/desk' to='alice@localhost' type='probe'/>")
                    .await?;
            let unavailable = shard
                .probe(&observer.handle(), &request, true)?
                .ok_or("missing unavailable prune")?;
            shard.prune_directed(&unavailable, Some(observer.token + 1))?;
            assert_eq!(shard.accounts[bob.as_str()]["desk"].directed.len(), 1);
            shard.prune_directed(&unavailable, Some(observer.token))?;
            assert!(shard.accounts[bob.as_str()]["desk"].directed.is_empty());
            let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
            let phone = register_probe_session(&mut shard, &router, &alice, "phone")?;
            for session in [&desk, &phone] {
                shard.presence(
                    &alice,
                    session.resource(),
                    session.token,
                    Some(0),
                    routed(&format!("<presence from='{}'/>", session.full_jid())).await?,
                    None,
                )?;
            }
            assert!(shard.probe(&observer.handle(), &request, true)?.is_none());
            assert!(observer.liveness().is_alive());
            assert!(!observer.links.inbound.is_closed());
            let queued = observer.take_queued();
            assert_eq!(queued.len(), 1);
            assert_eq!(queued[0].resolve()?.id()?, Some("queued"));
            assert!(shard.probe(&observer.handle(), &request, true)?.is_none());
            assert_eq!(observer.take_queued().len(), 1);
            Ok(())
        })
    }

    #[test]
    fn probe_unavailable_cache_is_bounded_and_does_not_invent_history() -> Result<(), Box<dyn Error>>
    {
        Runtime::new()?.block_on(async {
            let alice = account()?;
            let mut arena = Arena::try_new(Default::default())?;
            let bob = AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;
            let (commands, _) = async_channel::bounded(1);
            let router = test_router(commands);
            let mut shard = Shard::<GlobalChunkAllocator>::new();
            let observer = register_probe_session(&mut shard, &router, &bob, "desk")?;
            let request = routed("<presence from='bob@localhost/desk' to='alice@localhost' type='probe' id='offline'/>").await?;
            shard.probe(&observer.handle(), &request, true)?;
            let first = observer.take_queued().pop().ok_or("missing reply")?;
            assert!(first.resolve()?.children()?.next().is_none());
            let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
            let phone = register_probe_session(&mut shard, &router, &alice, "phone")?;
            let available = routed("<presence from='alice@localhost/desk'/>").await?;
            let unavailable = routed("<presence from='alice@localhost/desk' type='unavailable'/>").await?;
            shard.presence(&alice, "desk", desk.token, Some(0), available.clone(), Some(unavailable.clone()))?;
            shard.presence(&alice, "phone", phone.token, Some(0), available.clone(), Some(unavailable.clone()))?;
            shard.end_presence(&alice, "desk", desk.token)?;
            assert!(shard.last_unavailable.is_empty());
            shard.end_presence(&alice, "phone", phone.token)?;
            let at = shard.last_unavailable[0].1.at;
            shard.probe(&observer.handle(), &request, true)?;
            let offline = observer.take_queued().pop().ok_or("missing reply")?;
            assert!(offline.resolve()?.child("delay", "urn:xmpp:delay")?.is_some());
            shard.record_last_unavailable(alice.as_str());
            assert_eq!(shard.last_unavailable[0].1.at, at);
            for index in 0..LAST_UNAVAILABLE_CAPACITY { shard.record_last_unavailable(&format!("user{index}@localhost")); }
            assert_eq!(shard.last_unavailable.len(), LAST_UNAVAILABLE_CAPACITY);
            shard.probe(&observer.handle(), &request, true)?;
            let evicted = observer.take_queued().pop().ok_or("missing reply")?;
            assert!(evicted.resolve()?.child("delay", "urn:xmpp:delay")?.is_none());
            shard.record_last_unavailable(alice.as_str());
            let replacement = register_probe_session(&mut shard, &router, &alice, "desk")?;
            shard.presence(&alice, "desk", replacement.token, Some(0), available.clone(), Some(unavailable))?;
            assert!(!shard.last_unavailable.iter().any(|(known, _)| known.as_ref() == alice.as_str()));
            drop(replacement);
            shard.remove(alice.as_str(), "desk", shard.accounts[alice.as_str()]["desk"].token, RetireCause::Evicted);
            assert!(shard.last_unavailable.iter().any(|(known, _)| known.as_ref() == alice.as_str()));
            shard.retire_account(&alice);
            assert!(!shard.last_unavailable.iter().any(|(known, _)| known.as_ref() == alice.as_str()));
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "local/supervision_tests.rs"]
mod supervision_tests;
