// SPDX-License-Identifier: Apache-2.0

use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, resume_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::task::AtomicWaker;
use lonewolf_extension::Effects;
use lonewolf_extension::delivery::{
    Delivery, DeliveryError, DeliveryFuture, HandlerError, HostLookup, SessionTag, StanzaFactory,
};
use lonewolf_extension::message::MessageHandler;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::OfflineSequence;
use lonewolf_storage::{RedbStorage, RedbWrite, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::StanzaErrorCondition;

use crate::order::{Order, Ticket};
use crate::router::{
    Mailbox, Registration, RoutedStanza, RouterError, RouterHandle, SessionHandle,
};

pub(crate) struct WorkGroup {
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

/// Detached work holds the ticket, so a stalled caller cannot block later deliveries.
pub(crate) fn after_turn<A, T, F, Fut>(
    guard: WorkGuard,
    mut ticket: Ticket,
    mailbox: Option<Mailbox<A>>,
    work: F,
) -> Pending<T>
where
    A: ChunkAllocator,
    T: 'static,
    F: FnOnce(Vec<RoutedStanza<A>>) -> Fut + 'static,
    Fut: Future<Output = T> + 'static,
{
    let (report_turned, turned) = oneshot::channel();
    let (report_done, done) = oneshot::channel();
    compio::runtime::spawn(guard.run(async move {
        ticket.turn().await;
        let _ = report_turned.send(());
        let queued = mailbox.map_or_else(Vec::new, |mailbox| mailbox.take_queued());
        let result = work(queued).await;
        drop(ticket);
        let _ = report_done.send(result);
    }))
    .detach();
    Pending { turned, done }
}

#[derive(Debug)]
pub(crate) enum EffectsError {
    Commit,
    Delivery,
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
    storage: RedbStorage,
    transaction: RedbWrite,
    handler: Arc<dyn MessageHandler<A, RedbStorage>>,
    stored: StoredDelivery<A>,
) -> Pending<Result<(), EffectsError>> {
    let (report_turned, turned) = oneshot::channel();
    let (report_done, done) = oneshot::channel();
    compio::runtime::spawn(guard.run(async move {
        let result = async {
            let ((), mut ticket) = router
                .order()
                .fix(vec![stored.recipient.clone()], transaction.commit())
                .await
                .map_err(|_| EffectsError::Commit)?;
            tracing::info!(
                operation = "store",
                outcome = "stored",
                bytes = stored.bytes,
                recipient_jid = ?stored.recipient.as_str(),
                "offline message handled"
            );
            ticket.turn().await;
            let _ = report_turned.send(());
            match router.route_message(stored.stanza).await {
                Ok(()) => {
                    tracing::info!(
                        operation = "reroute",
                        outcome = "queued",
                        recipient_jid = ?stored.recipient.as_str(),
                        "offline message rerouted"
                    );
                    let acknowledged: Result<(), HandlerError> = async {
                        let mut transaction = storage
                            .begin_write()
                            .await
                            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                        handler
                            .acknowledge_one(&stored.recipient, stored.sequence, &mut transaction)
                            .await?;
                        transaction
                            .commit()
                            .await
                            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                        tracing::info!(
                            operation = "acknowledge_live",
                            outcome = "committed",
                            recipient_jid = ?stored.recipient.as_str(),
                            "offline message acknowledgement handled"
                        );
                        Ok(())
                    }
                    .await;
                    if let Err(error) = acknowledged {
                        tracing::error!(error = ?error, "offline message acknowledgement failed");
                    }
                }
                Err(error) => {
                    let reason = match error {
                        RouterError::InvalidTarget => "invalid_target",
                        RouterError::RemoteUnsupported => "remote_unsupported",
                        RouterError::InvalidResource => "invalid_resource",
                        RouterError::ResourceLimit => "resource_limit",
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
                }
            }
            // Keep account recreation behind this acknowledgement.
            drop(ticket);
            Ok(())
        }
        .await;
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
) -> Pending<Result<Vec<RoutedStanza<A>>, EffectsError>>
where
    A: ChunkAllocator + Clone + 'static,
    D: Delivery<A> + 'static,
    W: WriteTransaction + 'static,
{
    let (report_turned, turned) = oneshot::channel();
    let (report_done, done) = oneshot::channel();
    compio::runtime::spawn(guard.run(async move {
        let result = async {
            let ((), mut ticket) = order
                .fix(accounts, transaction.commit())
                .await
                .map_err(|_| EffectsError::Commit)?;
            ticket.turn().await;
            let _ = report_turned.send(());
            let queued = mailbox.map_or_else(Vec::new, |mailbox| mailbox.take_queued());
            let delivered = deliver(&delivery).await;
            drop(ticket);
            delivered
                .map(|()| queued)
                .map_err(|_| EffectsError::Delivery)
        }
        .await;
        let _ = report_done.send(result);
    }))
    .detach();
    Pending { turned, done }
}

#[cfg(test)]
mod tests;

impl<A: ChunkAllocator + Clone> HostLookup for RouterDelivery<A> {
    fn is_local_host(&self, domain: &str) -> bool {
        self.router.is_local_host(domain)
    }
}

impl<A: ChunkAllocator + Clone> Delivery<A> for RouterDelivery<A> {
    fn arena(&self) -> Result<Arena<A>, DeliveryError> {
        Arena::try_new_in(Default::default(), self.allocator.clone()).map_err(|_| DeliveryError)
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
