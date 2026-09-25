// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, hash_map::RandomState};
use std::fmt;
use std::hash::BuildHasher;
use std::io;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

use async_channel::{Receiver, Sender, TrySendError};
use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Either, poll_fn, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator, HandleError, SharedArena};
use lonewolf_util::core_dispatcher::{DispatchHandle, Task, WorkerContext};
use lonewolf_xmpp::jid::JidError;
use lonewolf_xmpp::parser::Parsed;
use lonewolf_xmpp::stanza::{Stanza, StanzaRef};

use crate::hosts::Hosts;

const SHARD_QUEUE_CAPACITY: usize = 256;
const RESOURCE_QUEUE_CAPACITY: usize = 16;
const SHARD_BATCH_SIZE: usize = 64;

/// Owns one account shard on each core worker.
pub struct Router<A: ChunkAllocator> {
    handle: RouterHandle<A>,
    tasks: Vec<Task<()>>,
}

/// Sends account operations to the shard selected by bare JID.
pub struct RouterHandle<A: ChunkAllocator> {
    hosts: Hosts,
    shards: Arc<[Sender<Command<A>>]>,
    hash_state: RandomState,
}

/// Keeps a bound resource registered until this value is dropped.
pub struct Registration<A: ChunkAllocator> {
    account: AccountKey,
    resource: Box<str>,
    alive: Arc<AtomicBool>,
    _lease: oneshot::Sender<()>,
    inbound: Receiver<RoutedStanza<A>>,
}

/// Retains the parsed stanza and its immutable arena across workers.
pub struct RoutedStanza<A: ChunkAllocator> {
    stanza: Stanza,
    arena: SharedArena<A>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterError {
    InvalidTarget,
    RemoteUnsupported,
    InvalidResource,
    ResourceLimit,
    NotFound,
    Busy,
    Unavailable,
    Stopped,
}

enum Command<A: ChunkAllocator> {
    Register {
        account: AccountKey,
        requested: Option<Box<str>>,
        limit: NonZeroUsize,
        outbound: Sender<RoutedStanza<A>>,
        inbound: Receiver<RoutedStanza<A>>,
        reply: oneshot::Sender<Result<Registration<A>, RouterError>>,
    },
    Deliver {
        stanza: RoutedStanza<A>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
}

struct Session<A: ChunkAllocator> {
    token: u64,
    alive: Arc<AtomicBool>,
    outbound: Sender<RoutedStanza<A>>,
}

struct Shard<A: ChunkAllocator> {
    accounts: HashMap<Box<str>, HashMap<Box<str>, Session<A>>>,
    next_token: u64,
    cleanups: FuturesUnordered<BoxFuture<'static, (AccountKey, Box<str>, u64)>>,
}

impl<A: ChunkAllocator> Router<A> {
    /// Starts the shard actors on the core dispatcher.
    ///
    /// # Errors
    ///
    /// Returns a dispatcher error if a worker cannot accept its actor.
    pub async fn start(hosts: Hosts, dispatcher: &DispatchHandle) -> io::Result<Self> {
        let count = dispatcher.worker_count();
        let mut senders = Vec::with_capacity(count);
        let mut tasks = Vec::with_capacity(count);
        for worker in 0..count {
            let (sender, receiver) = async_channel::bounded(SHARD_QUEUE_CAPACITY);
            let task = dispatcher
                .dispatch_at(worker, move |context| Shard::new().run(receiver, context))
                .await?;
            senders.push(sender);
            tasks.push(task);
        }
        Ok(Self {
            handle: RouterHandle {
                hosts,
                shards: senders.into(),
                hash_state: RandomState::new(),
            },
            tasks,
        })
    }

    pub fn handle(&self) -> RouterHandle<A> {
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

impl<A: ChunkAllocator> Clone for RouterHandle<A> {
    fn clone(&self) -> Self {
        Self {
            hosts: self.hosts.clone(),
            shards: Arc::clone(&self.shards),
            hash_state: self.hash_state.clone(),
        }
    }
}

impl<A: ChunkAllocator> RouterHandle<A> {
    /// Applies the incoming listener's limit to resources on all listeners.
    pub async fn register(
        &self,
        account: &AccountKey,
        requested: Option<&str>,
        limit: NonZeroUsize,
    ) -> Result<Registration<A>, RouterError> {
        if !self.hosts.is_local_host(account.domain()) {
            return Err(RouterError::RemoteUnsupported);
        }
        let requested = requested
            .map(|resource| validate_resource(account, resource))
            .transpose()?;
        let (reply, result) = oneshot::channel();
        let (outbound, inbound) = async_channel::bounded(RESOURCE_QUEUE_CAPACITY);
        self.shard(account.as_str())
            .send(Command::Register {
                account: account.clone(),
                requested,
                limit,
                outbound,
                inbound,
                reply,
            })
            .await
            .map_err(|_| RouterError::Stopped)?;
        result.await.map_err(|_| RouterError::Stopped)?
    }

    /// Enqueues a stanza for a connected full JID without waiting for socket I/O.
    pub async fn route_full(&self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        let shard = {
            let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
            let to = view
                .to()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            if !self.hosts.is_local_host(to.domainpart()) {
                return Err(RouterError::RemoteUnsupported);
            }
            to.resourcepart().ok_or(RouterError::InvalidTarget)?;
            to.localpart().ok_or(RouterError::InvalidTarget)?;
            self.shard_index(to.bare().as_str())
        };
        let (reply, result) = oneshot::channel();
        self.shards[shard]
            .send(Command::Deliver { stanza, reply })
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

    pub async fn recv(&self) -> Option<RoutedStanza<A>> {
        self.inbound.recv().await.ok()
    }
}

impl<A: ChunkAllocator> Drop for Registration<A> {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
    }
}

impl<A: ChunkAllocator> RoutedStanza<A> {
    pub fn from_parsed(parsed: Parsed<Stanza, A>) -> Self {
        let (stanza, arena) = parsed.into_parts();
        Self {
            stanza,
            arena: arena.freeze(),
        }
    }

    pub fn resolve(&self) -> Result<StanzaRef<'_, SharedArena<A>>, HandleError> {
        self.stanza.resolve(&self.arena)
    }
}

impl<A: ChunkAllocator> Clone for RoutedStanza<A> {
    fn clone(&self) -> Self {
        Self {
            stanza: self.stanza,
            arena: self.arena.clone(),
        }
    }
}

impl fmt::Display for RouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTarget => "destination must be a full user JID",
            Self::RemoteUnsupported => "remote routing is unavailable",
            Self::InvalidResource => "resource identifier is invalid",
            Self::ResourceLimit => "account resource limit reached",
            Self::NotFound => "destination resource is not connected",
            Self::Busy => "destination resource cannot accept a stanza",
            Self::Unavailable => "router cannot register a resource",
            Self::Stopped => "router has stopped",
        })
    }
}

impl std::error::Error for RouterError {}

fn validate_resource(account: &AccountKey, input: &str) -> Result<Box<str>, RouterError> {
    let mut arena = Arena::try_new(Default::default()).map_err(|_| RouterError::Unavailable)?;
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
            next_token: 0,
            cleanups: FuturesUnordered::new(),
        }
    }

    async fn run(mut self, receiver: Receiver<Command<A>>, context: WorkerContext) {
        let mut processed = 0;
        loop {
            let event = if self.cleanups.is_empty() {
                match select(pin!(receiver.recv()), pin!(context.shutdown_requested())).await {
                    Either::Left((Ok(command), _)) => Some(Either::Left(command)),
                    _ => None,
                }
            } else {
                let receive = receiver.recv();
                let cleanup = self.cleanups.next();
                let mut receive = pin!(receive);
                let mut cleanup = pin!(cleanup);
                let work = select(receive.as_mut(), cleanup.as_mut());
                let work = pin!(work);
                match select(work, pin!(context.shutdown_requested())).await {
                    Either::Left((Either::Left((Ok(command), _)), _)) => {
                        Some(Either::Left(command))
                    }
                    Either::Left((Either::Right((Some(cleanup), _)), _)) => {
                        Some(Either::Right(cleanup))
                    }
                    _ => None,
                }
            };
            match event {
                Some(Either::Left(command)) => self.command(command),
                Some(Either::Right((account, resource, token))) => {
                    self.remove(&account, &resource, token);
                }
                None => break,
            }
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

    fn command(&mut self, command: Command<A>) {
        match command {
            Command::Register {
                account,
                requested,
                limit,
                outbound,
                inbound,
                reply,
            } => {
                let result = self.register(account, requested, limit, outbound, inbound);
                let _ = reply.send(result);
            }
            Command::Deliver { stanza, reply } => {
                let result = self.deliver(stanza);
                let _ = reply.send(result);
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
    ) -> Result<Registration<A>, RouterError> {
        let sessions = self.accounts.entry(account.as_str().into()).or_default();
        sessions.retain(|_, session| {
            session.alive.load(Ordering::Acquire) && !session.outbound.is_closed()
        });
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
            _ => {
                let mut candidate = format!("lw-{token:x}").into_boxed_str();
                while sessions.contains_key(candidate.as_ref()) {
                    self.next_token = self
                        .next_token
                        .checked_add(1)
                        .ok_or(RouterError::Unavailable)?;
                    candidate = format!("lw-{:x}", self.next_token).into_boxed_str();
                }
                candidate
            }
        };
        let (lease, closed) = oneshot::channel();
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
            },
        );
        Ok(Registration {
            account,
            resource,
            alive,
            _lease: lease,
            inbound,
        })
    }

    fn deliver(&mut self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let account = to.bare();
        let resource = to.resourcepart().ok_or(RouterError::InvalidTarget)?;
        let account = account.as_str();
        let sessions = self
            .accounts
            .get_mut(account)
            .ok_or(RouterError::NotFound)?;
        let session = sessions.get(resource).ok_or(RouterError::NotFound)?;
        if !session.alive.load(Ordering::Acquire) {
            sessions.remove(resource);
            if sessions.is_empty() {
                self.accounts.remove(account);
            }
            return Err(RouterError::NotFound);
        }
        match session.outbound.try_send(stanza) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(RouterError::Busy),
            Err(TrySendError::Closed(_)) => Err(RouterError::NotFound),
        }
    }

    fn remove(&mut self, account: &AccountKey, resource: &str, token: u64) {
        if let Some(sessions) = self.accounts.get_mut(account.as_str()) {
            if sessions
                .get(resource)
                .is_some_and(|session| session.token == token)
            {
                sessions.remove(resource);
            }
            if sessions.is_empty() {
                self.accounts.remove(account.as_str());
            }
        }
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
