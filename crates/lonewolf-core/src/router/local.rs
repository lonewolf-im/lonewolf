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
use futures_util::future::{BoxFuture, Either, poll_fn, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_util::core_dispatcher::{DispatchHandle, Task, WorkerContext};
use lonewolf_xmpp::jid::JidError;
use lonewolf_xmpp::stanza::{MessageType, StanzaType};

use super::{RoutedStanza, RouterError};

const SHARD_QUEUE_CAPACITY: usize = 1_024;
const RESOURCE_QUEUE_CAPACITY: usize = 64;
const SHARD_BATCH_SIZE: usize = 64;

/// Owns one account shard on each core worker.
pub struct LocalRouter<A: ChunkAllocator> {
    handle: LocalRouterHandle<A>,
    tasks: Vec<Task<()>>,
}

pub(super) struct LocalRouterHandle<A: ChunkAllocator> {
    shards: Arc<[Sender<Command<A>>]>,
    hash_state: RandomState,
}

/// Keeps a bound resource registered until this value is dropped.
pub struct Registration<A: ChunkAllocator> {
    account: AccountKey,
    resource: Box<str>,
    token: u64,
    alive: Arc<AtomicBool>,
    _lease: oneshot::Sender<()>,
    inbound: Receiver<RoutedStanza<A>>,
    shard: Sender<Command<A>>,
}

enum Command<A: ChunkAllocator> {
    Register {
        account: AccountKey,
        requested: Option<Box<str>>,
        limit: NonZeroUsize,
        outbound: Sender<RoutedStanza<A>>,
        inbound: Receiver<RoutedStanza<A>>,
        shard: Sender<Command<A>>,
        reply: oneshot::Sender<Result<Registration<A>, RouterError>>,
    },
    Deliver {
        stanza: RoutedStanza<A>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    DeliverBare {
        stanza: RoutedStanza<A>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
    Presence {
        account: AccountKey,
        resource: Box<str>,
        token: u64,
        priority: Option<i8>,
        stanza: RoutedStanza<A>,
        unavailable: Option<RoutedStanza<A>>,
        reply: oneshot::Sender<Result<(), RouterError>>,
    },
}

struct Session<A: ChunkAllocator> {
    token: u64,
    alive: Arc<AtomicBool>,
    outbound: Sender<RoutedStanza<A>>,
    priority: Option<i8>,
    presence: Option<RoutedStanza<A>>,
    unavailable: Option<RoutedStanza<A>>,
}

struct Shard<A: ChunkAllocator> {
    accounts: HashMap<Box<str>, HashMap<Box<str>, Session<A>>>,
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

impl<A: ChunkAllocator> LocalRouter<A> {
    /// Starts one shard actor per dispatcher worker.
    ///
    /// # Errors
    ///
    /// Returns a dispatcher error if a worker cannot accept its actor.
    pub async fn start(dispatcher: &DispatchHandle) -> io::Result<Self> {
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

impl<A: ChunkAllocator> Clone for LocalRouterHandle<A> {
    fn clone(&self) -> Self {
        Self {
            shards: Arc::clone(&self.shards),
            hash_state: self.hash_state.clone(),
        }
    }
}

impl<A: ChunkAllocator> LocalRouterHandle<A> {
    pub(crate) async fn register(
        &self,
        account: &AccountKey,
        requested: Option<&str>,
        limit: NonZeroUsize,
    ) -> Result<Registration<A>, RouterError> {
        let requested = requested
            .map(|resource| validate_resource(account, resource))
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
            .send(Command::Deliver { stanza, reply })
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

    pub async fn set_presence(
        &self,
        priority: Option<i8>,
        stanza: RoutedStanza<A>,
        unavailable: Option<RoutedStanza<A>>,
    ) -> Result<(), RouterError> {
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
}

impl<A: ChunkAllocator> Drop for Registration<A> {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
    }
}

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
                    self.remove(&account, &resource, token);
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
            Command::Deliver { stanza, reply } => {
                let result = self.deliver(stanza);
                let _ = reply.send(result);
            }
            Command::DeliverBare { stanza, reply } => {
                let result = self.deliver_bare(stanza);
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
        }
    }

    fn register(
        &mut self,
        account: AccountKey,
        requested: Option<Box<str>>,
        limit: NonZeroUsize,
        outbound: Sender<RoutedStanza<A>>,
        inbound: Receiver<RoutedStanza<A>>,
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
                self.remove(&account, &resource, token);
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
                presence: None,
                unavailable: None,
            },
        );
        Ok(Registration {
            account,
            resource,
            token,
            alive,
            _lease: lease,
            inbound,
            shard,
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

    fn deliver_bare(&mut self, stanza: RoutedStanza<A>) -> Result<(), RouterError> {
        let view = stanza.resolve().map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let sessions = self
            .accounts
            .get(to.as_str())
            .ok_or(RouterError::NotFound)?;
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
                match recipient.outbound.try_send(stanza) {
                    Ok(()) => Ok(()),
                    Err(TrySendError::Full(_)) => Err(RouterError::Busy),
                    Err(TrySendError::Closed(_)) => Err(RouterError::NotFound),
                }
            }
            StanzaType::Message(MessageType::Headline) => {
                let mut delivered = false;
                let mut busy = false;
                for session in sessions.values().filter(|session| {
                    session.alive.load(Ordering::Acquire)
                        && session.priority.is_some_and(|priority| priority >= 0)
                }) {
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
                    Err(RouterError::NotFound)
                }
            }
            _ => Err(RouterError::InvalidTarget),
        }
    }

    fn presence(
        &mut self,
        account: &AccountKey,
        resource: &str,
        token: u64,
        priority: Option<i8>,
        stanza: RoutedStanza<A>,
        unavailable: Option<RoutedStanza<A>>,
    ) -> Result<(), RouterError> {
        let sessions = self
            .accounts
            .get_mut(account.as_str())
            .ok_or(RouterError::NotFound)?;
        let source = sessions.get(resource).ok_or(RouterError::NotFound)?;
        if source.token != token || !source.alive.load(Ordering::Acquire) {
            return Err(RouterError::NotFound);
        }
        if priority.is_some() && source.priority.is_none() {
            for session in sessions.values().filter(|session| session.token != token) {
                if let Some(presence) = &session.presence {
                    let _ = source.outbound.try_send(presence.clone());
                }
            }
        }
        for session in sessions.values() {
            if session.alive.load(Ordering::Acquire)
                && (session.priority.is_some() || session.token == token)
            {
                let _ = session.outbound.try_send(stanza.clone());
            }
        }
        let source = sessions.get_mut(resource).ok_or(RouterError::NotFound)?;
        source.priority = priority;
        source.presence = priority.map(|_| stanza);
        source.unavailable = unavailable;
        Ok(())
    }

    fn remove(&mut self, account: &AccountKey, resource: &str, token: u64) {
        if let Some(sessions) = self.accounts.get_mut(account.as_str()) {
            if sessions
                .get(resource)
                .is_some_and(|session| session.token == token)
                && let Some(session) = sessions.remove(resource)
                && let Some(unavailable) = session.unavailable
            {
                for recipient in sessions.values().filter(|session| {
                    session.alive.load(Ordering::Acquire) && session.priority.is_some()
                }) {
                    let _ = recipient.outbound.try_send(unavailable.clone());
                }
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

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::future::pending;

    use compio::runtime::Runtime;
    use lonewolf_util::arena::GlobalChunkAllocator;
    use lonewolf_xmpp::jid::Jid;

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
