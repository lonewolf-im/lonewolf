// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::sync::Arc;

use futures_channel::oneshot;
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
    /// Deliveries before this cut predate the caller's storage view.
    pub(crate) async fn turned(&mut self) {
        let _ = (&mut self.turned).await;
    }

    /// The work's result, or `None` when its task ended without reporting.
    pub(crate) async fn finished(self) -> Option<T> {
        self.done.await.ok()
    }
}

/// Detached work holds the ticket, so a stalled caller cannot block later deliveries.
pub(crate) fn after_turn<A, T, F, Fut>(
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
    compio::runtime::spawn(async move {
        ticket.turn().await;
        let _ = report_turned.send(());
        let queued = mailbox.map_or_else(Vec::new, |mailbox| mailbox.take_queued());
        let result = work(queued).await;
        drop(ticket);
        let _ = report_done.send(result);
    })
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
    router: RouterHandle<A>,
    storage: RedbStorage,
    transaction: RedbWrite,
    handler: Arc<dyn MessageHandler<A, RedbStorage>>,
    stored: StoredDelivery<A>,
) -> Pending<Result<(), EffectsError>> {
    let (report_turned, turned) = oneshot::channel();
    let (report_done, done) = oneshot::channel();
    compio::runtime::spawn(async move {
        let result = async {
            let ((), mut ticket) = router
                .order()
                .fix(vec![stored.recipient.clone()], transaction.commit())
                .await
                .map_err(|_| EffectsError::Commit)?;
            tracing::debug!(
                outcome = "stored",
                bytes = stored.bytes,
                "offline message handled"
            );
            ticket.turn().await;
            let _ = report_turned.send(());
            if router.route_message(stored.stanza).await.is_ok() {
                tracing::debug!(
                    outcome = "delivered_live",
                    bytes = stored.bytes,
                    "offline message handled"
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
                    Ok(())
                }
                .await;
                if let Err(error) = acknowledged {
                    tracing::error!(error = ?error, "offline message acknowledgement failed");
                }
            }
            // Keep account recreation behind this acknowledgement.
            drop(ticket);
            Ok(())
        }
        .await;
        let _ = report_done.send(result);
    })
    .detach();
    Pending { turned, done }
}

/// Detached work owns commit and ticket admission even when the caller retires.
/// The caller must write the returned deliveries before its reply.
pub(crate) fn commit_and_deliver<A, D, W>(
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
    compio::runtime::spawn(async move {
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
    })
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
