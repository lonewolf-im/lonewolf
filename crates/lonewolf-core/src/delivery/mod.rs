// SPDX-License-Identifier: Apache-2.0

use std::future::{Future, poll_fn};
use std::io::Write;
use std::panic::{AssertUnwindSafe, resume_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::task::AtomicWaker;
use lonewolf_extension::blocking::BlockingPresenceChange;
use lonewolf_extension::delivery::{
    BoundResource, CopyFactory, DeliveryError, DeliveryFuture, DeliveryHandle, Failure,
    FailureKind, HandlerError, HostLookup, IqResponseFuture, SessionId, SessionLookup, SessionTag,
    StanzaFactory,
};
use lonewolf_extension::message::MessageHandler;
use lonewolf_extension::{Deliver, Effects, ExtensionFuture};
#[cfg(test)]
use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::OfflineSequence;
use lonewolf_storage::roster::RosterJid;
use lonewolf_storage::{RedbRead, RedbStorage, RedbWrite, StorageError, WriteTransaction};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{IqType, StanzaKind, StanzaType};

use crate::order::{Order, PendingDirectedGrant, Ticket};
use crate::router::iq_requests::{ID_PREFIX, MAX_TIMEOUT};
use crate::router::{
    Admitted, DeliveryScope, Destination, Mailbox, MailboxEntry, Registration, RoutedStanza,
    RouterError, RouterHandle, SessionHandle, StoredRelease,
};
use crate::stages::message::{MessageRecipients, concrete_recipients};

pub(crate) struct WorkGroup {
    state: Arc<WorkState>,
}

#[derive(Clone)]
pub(crate) struct WorkHandle {
    state: Arc<WorkState>,
}

struct WorkState {
    active: AtomicUsize,
    drained: AtomicWaker,
}

pub(crate) struct WorkGuard {
    state: Arc<WorkState>,
}

impl WorkGroup {
    pub(crate) fn handle(&self) -> WorkHandle {
        WorkHandle {
            state: Arc::clone(&self.state),
        }
    }

    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(WorkState {
                active: AtomicUsize::new(0),
                drained: AtomicWaker::new(),
            }),
        }
    }

    pub(crate) fn start(&self) -> WorkGuard {
        self.state.active.fetch_add(1, Ordering::Relaxed);
        WorkGuard {
            state: Arc::clone(&self.state),
        }
    }

    /// Stop admitting work before waiting for this group.
    pub(crate) async fn drain(&mut self) {
        poll_fn(|context| {
            self.state.drained.register(context.waker());
            if self.state.active.load(Ordering::Acquire) == 0 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

impl WorkHandle {
    pub(crate) fn start(&self) -> WorkGuard {
        self.state.active.fetch_add(1, Ordering::Relaxed);
        WorkGuard {
            state: Arc::clone(&self.state),
        }
    }
}

impl WorkGuard {
    pub(crate) async fn run<F: Future>(self, work: F) -> F::Output {
        let result = AssertUnwindSafe(work).catch_unwind().await;
        drop(self);
        match result {
            Ok(value) => value,
            Err(payload) => resume_unwind(payload),
        }
    }
}

impl Drop for WorkGuard {
    fn drop(&mut self) {
        if self.state.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.state.drained.wake();
        }
    }
}

pub(crate) struct RouterDelivery<A: ChunkAllocator> {
    router: RouterHandle<A>,
    allocator: A,
    scope: DeliveryScope,
    /// Server-initiated work has no session to tag.
    session: Option<SessionHandle<A>>,
    received_copies: Option<(AccountKey, Vec<SessionId>)>,
    presence_snapshot: Option<Arc<RedbRead>>,
    local_block: Option<LocalBlock>,
}

struct LocalBlock {
    change: Arc<BlockingPresenceChange>,
    subscribers: Result<Vec<RosterJid>, DeliveryError>,
    base_accounts: usize,
}

impl<A: ChunkAllocator + Clone> RouterDelivery<A> {
    pub(crate) fn router(&self) -> &RouterHandle<A> {
        &self.router
    }

    pub(crate) fn new(
        router: &RouterHandle<A>,
        allocator: &A,
        session: Option<&Registration<A>>,
    ) -> Self {
        Self::with_session(router, allocator, session.map(Registration::handle))
    }

    pub(crate) fn with_session(
        router: &RouterHandle<A>,
        allocator: &A,
        session: Option<SessionHandle<A>>,
    ) -> Self {
        Self {
            router: router.clone(),
            allocator: allocator.clone(),
            scope: DeliveryScope::ComponentAware,
            session,
            received_copies: None,
            presence_snapshot: None,
            local_block: None,
        }
    }

    pub(crate) fn with_scope(mut self, scope: DeliveryScope) -> Self {
        self.scope = scope;
        self
    }

    pub(crate) fn with_presence_snapshot(mut self, snapshot: Option<Arc<RedbRead>>) -> Self {
        self.presence_snapshot = snapshot;
        self
    }

    pub(crate) fn restrict_received_copies(
        &mut self,
        account: &AccountKey,
        targets: Vec<SessionId>,
    ) {
        self.received_copies = Some((account.clone(), targets));
    }

    fn block_snapshot(&self, change: &BlockingPresenceChange) -> Result<&RedbRead, DeliveryError> {
        let session = self.session.as_ref().ok_or(DeliveryError)?;
        if session.account() != change.owner() {
            return Err(DeliveryError);
        }
        self.presence_snapshot.as_deref().ok_or(DeliveryError)
    }
}

/// Dropping this handle does not cancel the detached work.
pub(crate) struct Pending<T> {
    turned: oneshot::Receiver<()>,
    done: oneshot::Receiver<T>,
}

impl<T> Pending<T> {
    pub(crate) fn spawn<F: Future<Output = T> + 'static>(guard: WorkGuard, work: F) -> Self
    where
        T: 'static,
    {
        let (report_turned, turned) = oneshot::channel();
        let (report_done, done) = oneshot::channel();
        compio::runtime::spawn(guard.run(async move {
            let result = work.await;
            let _ = report_turned.send(());
            let _ = report_done.send(result);
        }))
        .detach();
        Self { turned, done }
    }

    /// Deliveries before this cut predate the caller's storage view.
    pub(crate) async fn turned(&mut self) {
        let _ = (&mut self.turned).await;
    }

    pub(crate) async fn finished(self) -> Option<T> {
        self.done.await.ok()
    }
}

/// The callback owns the turned ticket and must hold it through ordered deliveries.
pub(crate) fn after_turn<A, T, F, Fut>(
    guard: WorkGuard,
    mut ticket: Ticket,
    mailbox: Option<Mailbox<A>>,
    work: F,
) -> Pending<T>
where
    A: ChunkAllocator,
    T: 'static,
    F: FnOnce(Vec<MailboxEntry<A>>, Ticket) -> Fut + 'static,
    Fut: Future<Output = T> + 'static,
{
    let (report_turned, turned) = oneshot::channel();
    let (report_done, done) = oneshot::channel();
    compio::runtime::spawn(guard.run(async move {
        ticket.turn().await;
        let _ = report_turned.send(());
        let queued = mailbox.map_or_else(Vec::new, |mailbox| mailbox.take_queued());
        let result = work(queued, ticket).await;
        let _ = report_done.send(result);
    }))
    .detach();
    Pending { turned, done }
}

pub(crate) fn storage_failure(error: StorageError, operation: &'static str) -> Failure {
    Failure {
        kind: FailureKind::Storage(error.kind()),
        operation,
    }
}

pub(crate) fn report_failure(failure: Failure, account: &AccountKey) {
    tracing::error!(
        failure_kind = failure.kind.as_str(),
        operation = failure.operation,
        account_jid = ?account.as_str(),
        "internal operation failed"
    );
}

pub(crate) fn report_handler_failure(error: &HandlerError, account: &AccountKey) {
    if let Some(failure) = error.failure() {
        report_failure(failure, account);
    }
}

pub(crate) enum EffectsIdentity {
    Account(AccountKey),
    Server(Box<str>),
}

pub(crate) fn report_server_failure(failure: Failure, domain: &str) {
    tracing::error!(
        failure_kind = failure.kind.as_str(),
        operation = failure.operation,
        local_domain = domain,
        "internal operation failed"
    );
}

pub(crate) struct EffectsDiagnostics {
    pub(crate) identity: EffectsIdentity,
    pub(crate) commit_operation: &'static str,
    pub(crate) delivery_operation: &'static str,
}

#[derive(Debug)]
pub(crate) enum EffectsError {
    Commit(Failure),
    Delivery(Failure),
}

impl EffectsError {
    pub(crate) const fn failure(&self) -> Failure {
        match self {
            Self::Commit(failure) | Self::Delivery(failure) => *failure,
        }
    }
}

pub(crate) struct StoredDelivery<A: ChunkAllocator> {
    pub(crate) source: Option<AccountKey>,
    pub(crate) recipient: AccountKey,
    pub(crate) sequence: OfflineSequence,
    pub(crate) stanza: RoutedStanza<A>,
    pub(crate) bytes: usize,
    pub(crate) policy: Option<(A, RedbRead)>,
}

pub(crate) struct StoreAdmission {
    pub(crate) admitted: Admitted,
    pub(crate) copies: Option<Vec<SessionId>>,
}

/// A preceding availability snapshot misses this commit, so retry routing after its ticket turns.
pub(crate) fn commit_and_store<A: ChunkAllocator + Clone + 'static>(
    guard: WorkGuard,
    router: RouterHandle<A>,
    transaction: RedbWrite,
    handler: Arc<dyn MessageHandler<A, RedbStorage>>,
    stored: StoredDelivery<A>,
) -> Pending<Result<StoreAdmission, EffectsError>> {
    let (report_turned, turned) = oneshot::channel();
    let (report_done, done) = oneshot::channel();
    compio::runtime::spawn(guard.run(async move {
        let result: Result<StoreAdmission, EffectsError> = async {
            let ((), mut ticket) = router
                .order()
                .fix(
                    stored
                        .source
                        .iter()
                        .filter(|source| *source != &stored.recipient)
                        .cloned()
                        .chain([stored.recipient.clone()])
                        .collect(),
                    transaction.commit(),
                )
                .await
                .map_err(|error| {
                    let failure = storage_failure(error, "offline_store_commit");
                    EffectsError::Commit(failure)
                })?;
            tracing::info!(
                operation = "store",
                outcome = "stored",
                bytes = stored.bytes,
                recipient_jid = ?stored.recipient.as_str(),
                "offline message handled"
            );
            ticket.turn().await;
            let _ = report_turned.send(());
            let copies = if let Some((allocator, snapshot)) = &stored.policy {
                match concrete_recipients(
                    &router,
                    allocator,
                    Some(snapshot),
                    stored.source.as_ref(),
                    Some(&stored.recipient),
                    &stored.stanza,
                )
                .await
                {
                    Ok(MessageRecipients::Allowed(copies)) => copies,
                    Ok(MessageRecipients::Refused(_)) | Err(_) => {
                        return Ok(StoreAdmission {
                            admitted: Admitted::None,
                            copies: Some(Vec::new()),
                        });
                    }
                }
            } else {
                None
            };
            let admitted = match router
                .route_stored_message_to(
                    stored.stanza,
                    StoredRelease {
                        handler,
                        sequence: stored.sequence,
                    },
                    copies.as_deref(),
                )
                .await
            {
                Ok(admitted) => {
                    tracing::info!(
                        operation = "reroute",
                        outcome = "queued",
                        recipient_jid = ?stored.recipient.as_str(),
                        "offline message rerouted"
                    );
                    admitted
                }
                Err(error) => {
                    let reason = match error {
                        RouterError::InvalidTarget => "invalid_target",
                        RouterError::RemoteUnsupported => "remote_unsupported",
                        RouterError::RemoteNotFound => "remote_not_found",
                        RouterError::RemoteTimeout => "remote_timeout",
                        RouterError::InvalidResource => "invalid_resource",
                        RouterError::ResourceLimit => "resource_limit",
                        RouterError::DirectedPresenceLimit => "directed_presence_limit",
                        RouterError::NotFound => "not_found",
                        RouterError::Offline => "offline",
                        RouterError::Busy => "busy",
                        RouterError::Unavailable => "unavailable",
                        RouterError::Stopped => "stopped",
                    };
                    tracing::info!(
                        operation = "reroute",
                        outcome = "retained",
                        reason,
                        recipient_jid = ?stored.recipient.as_str(),
                        "offline message rerouted"
                    );
                    Admitted::None
                }
            };
            Ok(StoreAdmission { admitted, copies })
        }
        .await;
        if let Err(error) = &result {
            report_failure(error.failure(), &stored.recipient);
        }
        let _ = report_done.send(result);
    }))
    .detach();
    Pending { turned, done }
}

pub(crate) trait OrderedEffectsDelivery<A: ChunkAllocator>: DeliveryHandle<A> {
    fn prepare_local_block(
        &mut self,
        _change: &Arc<BlockingPresenceChange>,
        _accounts: &mut Vec<AccountKey>,
    ) -> impl Future<Output = ()> {
        std::future::ready(())
    }

    fn extend_local_block_scope(
        &mut self,
        _pending: Vec<PendingDirectedGrant>,
        _accounts: &mut Vec<AccountKey>,
    ) -> impl Future<Output = ()> {
        std::future::ready(())
    }
}

impl<A: ChunkAllocator + Clone + 'static> OrderedEffectsDelivery<A> for RouterDelivery<A> {
    async fn prepare_local_block(
        &mut self,
        change: &Arc<BlockingPresenceChange>,
        accounts: &mut Vec<AccountKey>,
    ) {
        let base_accounts = accounts.len();
        let subscribers = match self.block_snapshot(change) {
            Ok(snapshot) => self
                .router
                .blocking_subscribers(change.owner(), snapshot)
                .await
                .map_err(|_| DeliveryError),
            Err(error) => Err(error),
        };
        if let Ok(subscribers) = &subscribers {
            self.router
                .extend_blocking_roster_accounts(change, subscribers, accounts);
        }
        self.local_block = Some(LocalBlock {
            change: Arc::clone(change),
            subscribers,
            base_accounts,
        });
    }

    async fn extend_local_block_scope(
        &mut self,
        pending: Vec<PendingDirectedGrant>,
        accounts: &mut Vec<AccountKey>,
    ) {
        if let Some(block) = &mut self.local_block
            && block.subscribers.is_ok()
            && self
                .router
                .extend_blocking_directed_accounts(&block.change, pending, accounts)
                .await
                .is_err()
        {
            accounts.truncate(block.base_accounts);
            block.subscribers = Err(DeliveryError);
        }
    }
}

/// Detached work owns commit and ticket admission even when the caller retires.
/// The caller must write the returned deliveries before its reply.
pub(crate) fn commit_and_deliver<A, D, W>(
    guard: WorkGuard,
    order: Arc<Order>,
    transaction: W,
    effects: Effects<A>,
    mut delivery: D,
    mailbox: Option<Mailbox<A>>,
    diagnostics: EffectsDiagnostics,
) -> Pending<Result<Vec<MailboxEntry<A>>, EffectsError>>
where
    A: ChunkAllocator + Clone + 'static,
    D: OrderedEffectsDelivery<A> + 'static,
    W: WriteTransaction + 'static,
{
    let (report_turned, turned) = oneshot::channel();
    let (report_done, done) = oneshot::channel();
    compio::runtime::spawn(guard.run(async move {
        let result = async {
            let commit_error =
                |error| EffectsError::Commit(storage_failure(error, diagnostics.commit_operation));
            let delivery_error = |_| {
                EffectsError::Delivery(Failure {
                    kind: FailureKind::Delivery,
                    operation: diagnostics.delivery_operation,
                })
            };
            let local_edit = effects.local_blocklist_edit().cloned();
            let mut accounts = effects.accounts;
            let mut ticket = if let Some(change) = &local_edit {
                delivery.prepare_local_block(change, &mut accounts).await;
                order
                    .fix_block(
                        change.owner(),
                        accounts,
                        transaction.commit(),
                        async |pending, accounts| {
                            delivery.extend_local_block_scope(pending, accounts).await;
                        },
                    )
                    .await
                    .map_err(commit_error)?
            } else {
                let ((), ticket) = order
                    .fix(accounts, transaction.commit())
                    .await
                    .map_err(commit_error)?;
                ticket
            };
            ticket.turn().await;
            let _ = report_turned.send(());
            let queued = mailbox.map_or_else(Vec::new, |mailbox| mailbox.take_queued());
            let delivered = (effects.deliver)(&delivery).await;
            drop(ticket);
            delivered.map(|()| queued).map_err(delivery_error)
        }
        .await;
        if let Err(error) = &result {
            match &diagnostics.identity {
                EffectsIdentity::Account(account) => report_failure(error.failure(), account),
                EffectsIdentity::Server(domain) => report_server_failure(error.failure(), domain),
            }
        }
        let _ = report_done.send(result);
    }))
    .detach();
    Pending { turned, done }
}

#[cfg(test)]
pub(crate) mod failure_tests;
#[cfg(test)]
mod tests;

impl<A: ChunkAllocator + Clone> HostLookup for RouterDelivery<A> {
    fn is_local_host(&self, domain: &str) -> bool {
        self.router.is_local_host(domain)
    }

    fn federates(&self, local_domain: &str) -> bool {
        self.router.federates_domain(local_domain)
    }

    fn is_component_domain(&self, domain: &str) -> bool {
        self.scope.allows_components() && self.router.is_component_domain(domain)
    }
}

impl<A: ChunkAllocator + Clone> SessionLookup for RouterDelivery<A> {
    fn resources<'a>(
        &'a self,
        account: &'a AccountKey,
    ) -> ExtensionFuture<'a, Result<Vec<BoundResource>, DeliveryError>> {
        Box::pin(async move {
            self.router
                .account_resources(account)
                .await
                .map_err(|_| DeliveryError)
        })
    }
}

impl<A: ChunkAllocator + Clone + 'static> DeliveryHandle<A> for RouterDelivery<A> {
    fn arena(&self) -> Result<Arena<A>, DeliveryError> {
        Arena::try_new_in(Default::default(), self.allocator.clone()).map_err(|_| DeliveryError)
    }

    fn request_iq<'a>(
        &'a self,
        request: RoutedStanza<A>,
        timeout: Duration,
    ) -> IqResponseFuture<'a, A> {
        Box::pin(async move {
            let view = request.resolve()?;
            if !matches!(
                view.stanza_type(),
                StanzaType::Iq(IqType::Get | IqType::Set)
            ) {
                return Err(DeliveryError);
            }
            let from = view.from()?.ok_or(DeliveryError)?;
            let to = view.to()?.ok_or(DeliveryError)?;
            if self.router.destination(from) != Destination::Server
                || self.router.destination(to) != Destination::Resource
            {
                return Err(DeliveryError);
            }
            let mut pending = self
                .router
                .iq_requests()
                .register(to.as_str())
                .map_err(|_| DeliveryError)?;
            let mut buffer = [0; 26];
            let mut remainder = buffer.as_mut_slice();
            write!(remainder, "{ID_PREFIX}{}", pending.id()).map_err(|_| DeliveryError)?;
            let written = 26 - remainder.len();
            let id = std::str::from_utf8(&buffer[..written]).map_err(|_| DeliveryError)?;
            let mut arena = self.arena()?;
            let stanza = view.to_builder_in(&mut arena)?.id(Some(id))?.build()?;
            drop(request);
            self.router
                .route_full(RoutedStanza::from_parts(stanza, arena))
                .await
                .map_err(|_| DeliveryError)?;
            match compio::time::timeout(timeout.min(MAX_TIMEOUT), pending.response()).await {
                Ok(Some(response)) => Ok(response),
                Ok(None) | Err(_) => Err(DeliveryError),
            }
        })
    }

    fn detach(&self, work: Deliver<A>) -> Result<(), DeliveryError> {
        let guard = self
            .router
            .detached_work()
            .try_start()
            .ok_or(DeliveryError)?;
        let delivery = RouterDelivery {
            router: self.router.clone(),
            allocator: self.allocator.clone(),
            scope: self.scope,
            session: None,
            received_copies: None,
            presence_snapshot: None,
            local_block: None,
        };
        compio::runtime::spawn(async move {
            if work(&delivery).await.is_err() {
                tracing::error!(
                    failure_kind = "delivery",
                    operation = "detached_work",
                    "internal operation failed"
                );
            }
            drop(guard);
        })
        .detach();
        Ok(())
    }

    fn tag_session<'a>(&'a self, tag: SessionTag) -> DeliveryFuture<'a> {
        Box::pin(async move {
            match &self.session {
                Some(session) => session.tag(tag).await.map_err(|_| DeliveryError),
                None => Err(DeliveryError),
            }
        })
    }

    fn to_available<'a>(&'a self, stanza: RoutedStanza<A>) -> DeliveryFuture<'a> {
        Box::pin(async move {
            self.router
                .route_generated_presence(self.presence_snapshot.as_deref(), stanza, None, None)
                .await
                .map_err(|_| DeliveryError)
        })
    }

    fn to_remote<'a>(&'a self, stanza: RoutedStanza<A>) -> DeliveryFuture<'a> {
        Box::pin(async move {
            if let Some(snapshot) = self.presence_snapshot.as_deref()
                && stanza.resolve()?.kind() == StanzaKind::Presence
                && !self
                    .router
                    .presence_allowed(Some(snapshot), &stanza)
                    .await
                    .map_err(|_| DeliveryError)?
            {
                return Ok(());
            }
            let component = self.scope.allows_components()
                && stanza
                    .resolve()
                    .ok()
                    .and_then(|view| view.to().ok().flatten())
                    .is_some_and(|to| self.router.is_component_domain(to.domainpart()));
            if component {
                self.router
                    .route_to_component_or_bounce(stanza)
                    .await
                    .map_err(|_| DeliveryError)
            } else {
                self.router
                    .route_remote_or_bounce(stanza)
                    .map_err(|_| DeliveryError)
            }
        })
    }

    fn to_tagged<'a>(&'a self, tag: SessionTag, stanza: RoutedStanza<A>) -> DeliveryFuture<'a> {
        Box::pin(async move {
            if let Some(snapshot) = self.presence_snapshot.as_deref() {
                self.router
                    .route_generated_presence(Some(snapshot), stanza, Some(tag), None)
                    .await
            } else {
                self.router.route_presence_to_tagged(tag, stanza).await
            }
            .map_err(|_| DeliveryError)
        })
    }

    fn push_to_tagged<'a>(
        &'a self,
        account: &'a AccountKey,
        tag: SessionTag,
        mut build: StanzaFactory<A>,
    ) -> DeliveryFuture<'a> {
        let allocator = self.allocator.clone();
        Box::pin(async move {
            self.router
                .route_to_tagged(account, tag, move |to| {
                    let mut arena = Arena::try_new_in(Default::default(), allocator.clone())
                        .map_err(|_| RouterError::Unavailable)?;
                    let to =
                        Jid::parse_in(to, &mut arena).map_err(|_| RouterError::InvalidTarget)?;
                    let stanza = build(to, &mut arena).map_err(|_| RouterError::Unavailable)?;
                    Ok(RoutedStanza::from_parts(stanza, arena))
                })
                .await
                .map_err(|_| DeliveryError)
        })
    }

    fn copy_to_tagged<'a>(
        &'a self,
        account: &'a AccountKey,
        tag: SessionTag,
        holders: &'a [SessionId],
        build: CopyFactory<'a, A>,
    ) -> DeliveryFuture<'a> {
        Box::pin(async move {
            let targets = self.received_copies.as_ref().and_then(|(owner, targets)| {
                (tag == SessionTag::Carbons && owner == account).then_some(targets.as_slice())
            });
            self.router
                .copy_to_tagged_for(account, tag, holders, targets, build)
                .await
                .map_err(|_| DeliveryError)
        })
    }

    fn retire_tagged<'a>(&'a self, account: &'a AccountKey, tag: SessionTag) -> DeliveryFuture<'a> {
        Box::pin(async move {
            self.router
                .retire_tagged(account, tag)
                .await
                .map_err(|_| DeliveryError)
        })
    }

    fn current_presence<'a>(&'a self, from: &'a AccountKey, to: &'a str) -> DeliveryFuture<'a> {
        Box::pin(async move {
            self.router
                .route_current_presence(from, to, self.scope, self.presence_snapshot.as_deref())
                .await
                .map_err(|_| DeliveryError)
        })
    }

    fn unavailable_presence<'a>(&'a self, from: &'a AccountKey, to: &'a str) -> DeliveryFuture<'a> {
        Box::pin(async move {
            self.router
                .route_unavailable_presence(from, to, self.scope, self.presence_snapshot.as_deref())
                .await
                .map_err(|_| DeliveryError)
        })
    }

    fn blocking_presence<'a>(&'a self, change: &'a BlockingPresenceChange) -> DeliveryFuture<'a> {
        Box::pin(async move {
            let before = self.block_snapshot(change)?;
            let subscribers = match &self.local_block {
                Some(block) if std::ptr::eq(block.change.as_ref(), change) => {
                    Some(block.subscribers.as_deref().map_err(|_| DeliveryError)?)
                }
                Some(_) => return Err(DeliveryError),
                None => None,
            };
            self.router
                .route_blocking_presence(change, before, self.scope, subscribers)
                .await
                .map_err(|_| DeliveryError)
        })
    }
}
