// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, hash_map::RandomState};
use std::future::Future;
use std::hash::BuildHasher;
use std::io;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Instant;

use async_channel::{Receiver, Sender, TrySendError};
use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Either, Shared, poll_fn, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_util::core_dispatcher::{DispatchHandle, Task, WorkerContext};
use lonewolf_xmpp::jid::JidError;
use lonewolf_xmpp::stanza::{MessageType, PresenceType, StanzaType};

use super::{RoutedStanza, RouterError};

const SHARD_QUEUE_CAPACITY: usize = 1_024;
const RESOURCE_QUEUE_CAPACITY: usize = 64;
const SHARD_BATCH_SIZE: usize = 64;

type RosterPushFactory<A> = Box<dyn FnMut(&str) -> Result<RoutedStanza<A>, RouterError> + Send>;
type Retirement<A> = Shared<oneshot::Receiver<Option<RoutedStanza<A>>>>;

/// Owns one account shard on each core worker.
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
    _lease: oneshot::Sender<()>,
    retired: Retirement<A>,
    inbound: Receiver<ResourceDelivery<A>>,
    shard: Sender<Command<A>>,
}

pub(crate) enum ResourceDelivery<A: ChunkAllocator> {
    Routed(RoutedStanza<A>),
    Presence {
        stanzas: Vec<RoutedStanza<A>>,
        replay_pending: bool,
    },
}

pub(crate) struct PresenceChange {
    pub became_available: bool,
    pub became_unavailable: bool,
}

enum Command<A: ChunkAllocator> {
    Register {
        account: AccountKey,
        requested: Option<Box<str>>,
        limit: NonZeroUsize,
        outbound: Sender<ResourceDelivery<A>>,
        inbound: Receiver<ResourceDelivery<A>>,
        shard: Sender<Command<A>>,
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
    DeliverPresenceToInterested {
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
    MarkRosterInterested {
        account: AccountKey,
        resource: Box<str>,
        token: u64,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    DeliverRosterPush {
        account: AccountKey,
        build: RosterPushFactory<A>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    Presence {
        account: AccountKey,
        resource: Box<str>,
        token: u64,
        priority: Option<i8>,
        stanza: RoutedStanza<A>,
        unavailable: Option<RoutedStanza<A>>,
        reply: oneshot::Sender<Result<PresenceChange, RouterError>>,
    },
    EndPresence {
        account: AccountKey,
        resource: Box<str>,
        token: u64,
        reply: oneshot::Sender<Result<Option<RoutedStanza<A>>, RouterError>>,
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
}

struct RetiredPresence<A: ChunkAllocator> {
    resource: Box<str>,
    stanza: RoutedStanza<A>,
}

struct Session<A: ChunkAllocator> {
    token: u64,
    alive: Arc<AtomicBool>,
    outbound: Sender<ResourceDelivery<A>>,
    priority: Option<i8>,
    roster_interested: bool,
    presence: Option<RoutedStanza<A>>,
    unavailable: Option<RoutedStanza<A>>,
    retired: oneshot::Sender<Option<RoutedStanza<A>>>,
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
    /// Starts one shard actor per dispatcher worker.
    ///
    /// # Errors
    ///
    /// Returns a dispatcher error if a worker cannot accept its actor.
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

    /// Stops admission and waits for every shard actor.
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
                shard: shard.clone(),
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

    pub(crate) async fn deliver_presence_to_interested(
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
            .send(Command::DeliverPresenceToInterested { stanza, reply })
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

    pub(crate) async fn deliver_roster_push(
        &self,
        account: &AccountKey,
        build: impl FnMut(&str) -> Result<RoutedStanza<A>, RouterError> + Send + 'static,
    ) -> Result<(), RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard(account.as_str())
            .send(Command::DeliverRosterPush {
                account: account.clone(),
                build: Box::new(build),
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    fn shard(&self, bare: &str) -> &Sender<Command<A>> {
        &self.shards[self.shard_index(bare)]
    }

    fn shard_index(&self, bare: &str) -> usize {
        (self.hash_state.hash_one(bare) as usize) % self.shards.len()
    }
}

impl<A: ChunkAllocator> Registration<A> {
    pub fn account(&self) -> &AccountKey {
        &self.account
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn full_jid(&self) -> String {
        format!("{}/{}", self.account.as_str(), self.resource)
    }

    pub(crate) async fn recv(&self) -> Option<ResourceDelivery<A>> {
        self.inbound.recv().await.ok()
    }

    pub(crate) async fn wait_retired(&self) -> Result<Option<RoutedStanza<A>>, RouterError> {
        self.retired.clone().await.map_err(|_| RouterError::Stopped)
    }

    pub(crate) async fn set_presence(
        &self,
        priority: Option<i8>,
        stanza: RoutedStanza<A>,
        unavailable: Option<RoutedStanza<A>>,
    ) -> Result<PresenceChange, RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard
            .send(Command::Presence {
                account: self.account.clone(),
                resource: self.resource.clone(),
                token: self.token,
                priority,
                stanza,
                unavailable,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    pub(crate) async fn end_presence(&self) -> Result<Option<RoutedStanza<A>>, RouterError> {
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
            Ok(unavailable) => Ok(unavailable),
            Err(RouterError::NotFound) => self.wait_retired().await,
            Err(error) => Err(error),
        }
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

    pub(crate) async fn finish_presence(&self) -> Result<(), RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard
            .send(Command::FinishPresence {
                account: self.account.clone(),
                token: self.token,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)
    }

    /// Marks this bound resource as a roster push recipient.
    pub async fn mark_roster_interested(&self) -> Result<(), RouterError> {
        let (reply, result) = oneshot::channel();
        self.shard
            .send(Command::MarkRosterInterested {
                account: self.account.clone(),
                resource: self.resource.clone(),
                token: self.token,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }
}

impl<A: ChunkAllocator> Drop for Registration<A> {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
    }
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
                    self.remove(account.as_str(), &resource, token);
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
            Command::Register {
                account,
                requested,
                limit,
                outbound,
                inbound,
                shard,
                reply,
            } => {
                let result = self.register(account, requested, limit, outbound, inbound, shard);
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
            Command::DeliverPresenceToInterested { stanza, reply } => {
                let result = self.deliver_presence_to_interested(stanza);
                let _ = reply.send(result);
            }
            Command::PresenceSnapshot { account, reply } => {
                let _ = reply.send(self.presence_snapshot(&account));
            }
            Command::WithdrawalSnapshot { account, reply } => {
                let _ = reply.send(self.withdrawal_snapshot(&account));
            }
            Command::MarkRosterInterested {
                account,
                resource,
                token,
                reply,
            } => {
                let result = self.mark_roster_interested(&account, &resource, token);
                let _ = reply.send(result);
            }
            Command::DeliverRosterPush {
                account,
                mut build,
                reply,
            } => {
                let result = self.deliver_roster_push(&account, &mut build);
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
        }
    }

    fn register(
        &mut self,
        account: AccountKey,
        requested: Option<Box<str>>,
        limit: NonZeroUsize,
        outbound: Sender<ResourceDelivery<A>>,
        inbound: Receiver<ResourceDelivery<A>>,
        shard: Sender<Command<A>>,
    ) -> Result<Registration<A>, RouterError> {
        if let Some(sessions) = self.accounts.get(account.as_str()) {
            let stale: Vec<_> = sessions
                .iter()
                .filter(|(_, session)| {
                    !session.alive.load(Ordering::Acquire) || session.outbound.is_closed()
                })
                .map(|(resource, session)| (resource.clone(), session.token))
                .collect();
            for (resource, token) in stale {
                self.remove(account.as_str(), &resource, token);
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
                priority: None,
                roster_interested: false,
                presence: None,
                unavailable: None,
                retired,
            },
        );
        Ok(Registration {
            account,
            resource,
            token,
            alive,
            _lease: lease,
            retired: retired_reply.shared(),
            inbound,
            shard,
        })
    }

    fn deliver(&mut self, stanza: RoutedStanza<A>, fallback_chat: bool) -> Result<(), RouterError> {
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
            let delivery = if session.alive.load(Ordering::Acquire) {
                session
                    .outbound
                    .try_send(ResourceDelivery::Routed(stanza.clone()))
                    .map_err(mailbox_error)
            } else {
                Err(RouterError::NotFound)
            };
            (session.token, delivery)
        });
        if let Some((token, Err(RouterError::NotFound))) = result {
            self.remove(account, resource, token);
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
            .ok_or(RouterError::NotFound)?;
        if !allow_full && to.resourcepart().is_some() {
            return Err(RouterError::InvalidTarget);
        }
        match view.stanza_type() {
            StanzaType::Message(MessageType::Normal | MessageType::Chat) => {
                let recipient = sessions
                    .values()
                    .filter(|session| {
                        session.alive.load(Ordering::Acquire)
                            && session.priority.is_some_and(|priority| priority >= 0)
                    })
                    .max_by_key(|session| (session.priority, std::cmp::Reverse(session.token)))
                    .ok_or(RouterError::NotFound)?;
                recipient
                    .outbound
                    .try_send(ResourceDelivery::Routed(stanza))
                    .map_err(mailbox_error)
            }
            StanzaType::Message(MessageType::Headline) => {
                let mut delivered = false;
                let mut busy = false;
                for session in sessions.values().filter(|session| {
                    session.alive.load(Ordering::Acquire)
                        && session.priority.is_some_and(|priority| priority >= 0)
                }) {
                    match session
                        .outbound
                        .try_send(ResourceDelivery::Routed(stanza.clone()))
                    {
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
                    Err(RouterError::NotFound)
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

    fn deliver_presence_to_interested(
        &mut self,
        stanza: RoutedStanza<A>,
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
                    PresenceType::Subscribe
                        | PresenceType::Subscribed
                        | PresenceType::Unsubscribe
                        | PresenceType::Unsubscribed
                )
            )
        {
            return Err(RouterError::InvalidTarget);
        }
        match self.deliver_presence_where(stanza, |session| session.roster_interested) {
            Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn deliver_presence_where(
        &mut self,
        stanza: RoutedStanza<A>,
        select: impl Fn(&Session<A>) -> bool,
    ) -> Result<(), RouterError> {
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
            match session
                .outbound
                .try_send(ResourceDelivery::Routed(stanza.clone()))
            {
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
            self.remove(account, &resource, token);
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

    fn mark_roster_interested(
        &mut self,
        account: &AccountKey,
        resource: &str,
        token: u64,
    ) -> Result<(), RouterError> {
        let session = self
            .accounts
            .get_mut(account.as_str())
            .and_then(|sessions| sessions.get_mut(resource))
            .ok_or(RouterError::NotFound)?;
        if session.token != token || !session.alive.load(Ordering::Acquire) {
            return Err(RouterError::NotFound);
        }
        session.roster_interested = true;
        Ok(())
    }

    fn deliver_roster_push(
        &mut self,
        account: &AccountKey,
        build: &mut RosterPushFactory<A>,
    ) -> Result<(), RouterError> {
        let Some(sessions) = self.accounts.get(account.as_str()) else {
            return Ok(());
        };
        if sessions.values().all(|session| !session.roster_interested) {
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
            if !session.roster_interested {
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
                validate_roster_push_target(&stanza, &full_jid)?;
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
                .filter(|(_, session)| session.roster_interested)
                .map(|(resource, session)| (resource.clone(), session.token))
                .collect::<Vec<_>>();
            for (resource, token) in failed {
                self.remove(account.as_str(), &resource, token);
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
                        || session
                            .outbound
                            .try_send(ResourceDelivery::Routed(stanza))
                            .is_err())
                {
                    failed.push((resource, token));
                }
            }
        }
        for (resource, token) in failed {
            self.remove(account.as_str(), &resource, token);
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
    ) -> Result<PresenceChange, RouterError> {
        let (change, mut stanzas) = {
            let sessions = self
                .accounts
                .get(account.as_str())
                .ok_or(RouterError::NotFound)?;
            let source = sessions.get(resource).ok_or(RouterError::NotFound)?;
            if source.token != token || !source.alive.load(Ordering::Acquire) {
                return Err(RouterError::NotFound);
            }
            let change = PresenceChange {
                became_available: priority.is_some() && source.priority.is_none(),
                became_unavailable: priority.is_none() && source.priority.is_some(),
            };
            let stanzas = if change.became_available {
                sessions
                    .values()
                    .filter(|session| session.token != token)
                    .filter_map(|session| session.presence.as_ref())
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
            (change, stanzas)
        };

        stanzas.push(stanza.clone());
        let delivery = ResourceDelivery::Presence {
            stanzas,
            replay_pending: change.became_available,
        };
        let source = self
            .accounts
            .get(account.as_str())
            .and_then(|sessions| sessions.get(resource))
            .ok_or(RouterError::NotFound)?;
        if let Err(error) = source.outbound.try_send(delivery).map_err(mailbox_error) {
            self.remove(account.as_str(), resource, token);
            return Err(error);
        }

        let mut failed = Vec::new();
        {
            let sessions = self
                .accounts
                .get_mut(account.as_str())
                .ok_or(RouterError::NotFound)?;
            let source = sessions.get_mut(resource).ok_or(RouterError::NotFound)?;
            source.priority = priority;
            source.unavailable = unavailable;
            for (recipient_resource, session) in sessions.iter() {
                if session.token != token
                    && session.alive.load(Ordering::Acquire)
                    && session.priority.is_some()
                    && session
                        .outbound
                        .try_send(ResourceDelivery::Routed(stanza.clone()))
                        .is_err()
                {
                    failed.push((recipient_resource.clone(), session.token));
                }
            }
            if let Some(source) = sessions.get_mut(resource) {
                source.presence = priority.map(|_| stanza);
            }
        }
        for (recipient_resource, recipient_token) in failed {
            self.remove(account.as_str(), &recipient_resource, recipient_token);
        }
        Ok(change)
    }

    fn end_presence(
        &mut self,
        account: &AccountKey,
        resource: &str,
        token: u64,
    ) -> Result<Option<RoutedStanza<A>>, RouterError> {
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
        if let Some(stanza) = unavailable.as_ref() {
            let mut failed = Vec::new();
            for (recipient_resource, recipient) in sessions.iter() {
                if recipient.token != token
                    && recipient.alive.load(Ordering::Acquire)
                    && recipient.priority.is_some()
                    && recipient
                        .outbound
                        .try_send(ResourceDelivery::Routed(stanza.clone()))
                        .is_err()
                {
                    failed.push((recipient_resource.clone(), recipient.token));
                }
            }
            for (recipient_resource, recipient_token) in failed {
                self.remove(account.as_str(), &recipient_resource, recipient_token);
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
        Ok(unavailable)
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

    fn remove(&mut self, account: &str, resource: &str, token: u64) {
        let mut retiring = Vec::new();
        if let Some(sessions) = self.accounts.get_mut(account) {
            let mut pending = Vec::new();
            Self::remove_session(sessions, resource, token, &mut pending, &mut retiring);
            while let Some((resource, token)) = pending.pop() {
                Self::remove_session(sessions, &resource, token, &mut pending, &mut retiring);
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
        pending: &mut Vec<(Box<str>, u64)>,
        retiring: &mut Vec<(u64, RetiredPresence<A>)>,
    ) {
        if sessions
            .get(resource)
            .is_none_or(|session| session.token != token)
        {
            return;
        }
        if let Some(session) = sessions.remove(resource) {
            session.alive.store(false, Ordering::Release);
            session.outbound.close();
            if let Some(unavailable) = session.unavailable.as_ref() {
                for (recipient_resource, recipient) in sessions.iter() {
                    if recipient.alive.load(Ordering::Acquire)
                        && recipient.priority.is_some()
                        && recipient
                            .outbound
                            .try_send(ResourceDelivery::Routed(unavailable.clone()))
                            .is_err()
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
            let _ = session.retired.send(session.unavailable);
        }
    }
}

fn validate_roster_push_target<A: ChunkAllocator>(
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
                shard,
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
                        priority: Some(0),
                        roster_interested: false,
                        presence: None,
                        unavailable: None,
                        retired,
                    },
                );
                receivers.push(inbound);
            }
            let stanza = routed("<message to='alice@localhost' type='headline'/>").await?;
            assert!(
                sessions["full"]
                    .outbound
                    .try_send(ResourceDelivery::Routed(stanza.clone()))
                    .is_ok()
            );
            receivers[2].close();
            shard.accounts.insert(account.as_str().into(), sessions);

            assert_eq!(shard.deliver_bare(stanza.clone(), false), Ok(()));
            let ResourceDelivery::Routed(delivery) = receivers[0].try_recv()? else {
                return Err("unexpected presence batch".into());
            };
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
            assert_eq!(
                shard.deliver_bare(stanza, false),
                Err(RouterError::NotFound)
            );
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
                command_sender.clone(),
            )?;
            let (phone_outbound, phone_inbound) = async_channel::bounded(64);
            let phone = shard.register(
                account.clone(),
                Some("phone".into()),
                NonZeroUsize::new(2).ok_or("zero resource limit")?,
                phone_outbound,
                phone_inbound,
                command_sender,
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
            let Some(ResourceDelivery::Presence { stanzas, .. }) = desk.recv().await else {
                return Err("missing desk presence batch".into());
            };
            assert_eq!(stanzas.len(), 1);
            let became_available = shard.presence(
                &account,
                "phone",
                phone.token,
                Some(0),
                routed("<presence from='alice@localhost/phone'/>").await?,
                None,
            )?;
            assert!(became_available.became_available);
            let Some(ResourceDelivery::Presence { stanzas, .. }) = phone.recv().await else {
                return Err("missing phone presence batch".into());
            };
            assert_eq!(stanzas.len(), 2);
            let Some(ResourceDelivery::Routed(_)) = desk.recv().await else {
                return Err("missing peer presence".into());
            };

            drop(desk);
            assert_eq!(
                shard.deliver(routed("<message to='alice@localhost/desk'/>").await?, false),
                Err(RouterError::NotFound)
            );
            let Some(ResourceDelivery::Routed(unavailable)) = phone.recv().await else {
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
}
