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
use lonewolf_extension::delivery::{
    BoundResource, CopyFactory, Delivery, DeliveryError, DeliveryFuture, Failure, FailureKind,
    HandlerError, HostLookup, IqResponseFuture, SessionId, SessionLookup, SessionTag,
    StanzaFactory,
};
use lonewolf_extension::message::MessageHandler;
use lonewolf_extension::{Deliver, Effects, ExtensionFuture};
#[cfg(test)]
use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::OfflineSequence;
use lonewolf_storage::{RedbStorage, RedbWrite, StorageError, WriteTransaction};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{IqType, StanzaType};

use crate::order::{Order, Ticket};
use crate::router::iq_requests::{ID_PREFIX, MAX_TIMEOUT};
use crate::router::{
    Admitted, Destination, Mailbox, MailboxEntry, Registration, RoutedStanza, RouterError,
    RouterHandle, SessionHandle, StoredRelease,
};

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
    /// The requesting resource; server-initiated work has none and cannot tag a session.
    session: Option<SessionHandle<A>>,
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
        Self {
            router: router.clone(),
            allocator: allocator.clone(),
            session: session.map(Registration::handle),
        }
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
    pub(crate) recipient: AccountKey,
    pub(crate) sequence: OfflineSequence,
    pub(crate) stanza: RoutedStanza<A>,
    pub(crate) bytes: usize,
}

/// A preceding availability snapshot misses this commit, so retry routing after its ticket turns.
pub(crate) fn commit_and_store<A: ChunkAllocator + Clone + 'static>(
    guard: WorkGuard,
    router: RouterHandle<A>,
    transaction: RedbWrite,
    handler: Arc<dyn MessageHandler<A, RedbStorage>>,
    stored: StoredDelivery<A>,
) -> Pending<Result<Admitted, EffectsError>> {
    let (report_turned, turned) = oneshot::channel();
    let (report_done, done) = oneshot::channel();
    compio::runtime::spawn(guard.run(async move {
        let result: Result<Admitted, EffectsError> = async {
            let ((), mut ticket) = router
                .order()
                .fix(vec![stored.recipient.clone()], transaction.commit())
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
            let admitted = match router
                .route_stored_message(
                    stored.stanza,
                    StoredRelease {
                        handler,
                        sequence: stored.sequence,
                    },
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
            Ok(admitted)
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

/// Detached work owns commit and ticket admission even when the caller retires.
/// The caller must write the returned deliveries before its reply.
pub(crate) fn commit_and_deliver<A, D, W>(
    guard: WorkGuard,
    order: Arc<Order>,
    transaction: W,
    Effects { accounts, deliver }: Effects<A>,
    delivery: D,
    mailbox: Option<Mailbox<A>>,
    diagnostics: EffectsDiagnostics,
) -> Pending<Result<Vec<MailboxEntry<A>>, EffectsError>>
where
    A: ChunkAllocator + Clone + 'static,
    D: Delivery<A> + 'static,
    W: WriteTransaction + 'static,
{
    let (report_turned, turned) = oneshot::channel();
    let (report_done, done) = oneshot::channel();
    compio::runtime::spawn(guard.run(async move {
        let result = async {
            let ((), mut ticket) =
                order
                    .fix(accounts, transaction.commit())
                    .await
                    .map_err(|error| {
                        let failure = storage_failure(error, diagnostics.commit_operation);
                        EffectsError::Commit(failure)
                    })?;
            ticket.turn().await;
            let _ = report_turned.send(());
            let queued = mailbox.map_or_else(Vec::new, |mailbox| mailbox.take_queued());
            let delivered = deliver(&delivery).await;
            drop(ticket);
            delivered.map(|()| queued).map_err(|_| {
                let failure = Failure {
                    kind: FailureKind::Delivery,
                    operation: diagnostics.delivery_operation,
                };
                EffectsError::Delivery(failure)
            })
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

impl<A: ChunkAllocator + Clone + 'static> Delivery<A> for RouterDelivery<A> {
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
            session: None,
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
            match self.router.route_presence(stanza).await {
                Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
                Err(_) => Err(DeliveryError),
            }
        })
    }

    fn to_remote<'a>(&'a self, stanza: RoutedStanza<A>) -> DeliveryFuture<'a> {
        Box::pin(async move {
            self.router
                .route_remote_or_bounce(stanza)
                .map_err(|_| DeliveryError)
        })
    }

    fn to_tagged<'a>(&'a self, tag: SessionTag, stanza: RoutedStanza<A>) -> DeliveryFuture<'a> {
        Box::pin(async move {
            self.router
                .route_presence_to_tagged(tag, stanza)
                .await
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
            self.router
                .copy_to_tagged(account, tag, holders, build)
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

    fn current_presence<'a>(
        &'a self,
        from: &'a AccountKey,
        to: &'a AccountKey,
    ) -> DeliveryFuture<'a> {
        Box::pin(async move {
            self.router
                .route_current_presence(from, to)
                .await
                .map_err(|_| DeliveryError)
        })
    }

    fn unavailable_presence<'a>(
        &'a self,
        from: &'a AccountKey,
        to: &'a AccountKey,
    ) -> DeliveryFuture<'a> {
        Box::pin(async move {
            self.router
                .route_unavailable_presence(from, to)
                .await
                .map_err(|_| DeliveryError)
        })
    }
}
