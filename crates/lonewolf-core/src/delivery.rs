// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::sync::Arc;

use futures_channel::oneshot;
use lonewolf_extension::Deliver;
use lonewolf_extension::delivery::{
    Delivery, DeliveryError, DeliveryFuture, HostLookup, SessionTag, StanzaFactory,
};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;

use crate::order::{Order, Ticket};
use crate::router::{
    Mailbox, Registration, RoutedStanza, RouterError, RouterHandle, SessionHandle,
};

/// Performs handler deliveries through the router, for a bound resource or for the
/// server itself when no session is involved.
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

    /// Runs committed deliveries. Should they fail partway, every session of the accounts
    /// they addressed is evicted, so no client keeps a view that may have missed a change.
    pub(crate) async fn deliver_or_evict(
        &self,
        accounts: &[AccountKey],
        deliver: Deliver<A>,
    ) -> Result<(), DeliveryError> {
        let result = deliver(self).await;
        if result.is_err() {
            tracing::error!(accounts = accounts.len(), "committed deliveries failed");
            for account in accounts {
                let _ = self.router.evict_account(account).await;
            }
        }
        result
    }
}

/// Work that runs on a task of its own once a ticket turns. Dropping the handle does
/// not stop it, so a session retired meanwhile cannot lose what the ticket ordered.
pub(crate) struct Pending<T> {
    turned: oneshot::Receiver<()>,
    done: oneshot::Receiver<T>,
}

impl<T> Pending<T> {
    /// Resolves when the ticket has turned, which is the cut for the caller's mailbox:
    /// everything delivered before it predates the caller's view of storage.
    pub(crate) async fn turned(&mut self) {
        let _ = (&mut self.turned).await;
    }

    /// The work's result, or `None` when its task ended without reporting.
    pub(crate) async fn finished(self) -> Option<T> {
        self.done.await.ok()
    }
}

/// Runs `work` on its own task once `ticket` turns, handing it whatever `mailbox` still
/// holds at that moment, and releases the ticket when the work is done. The caller
/// never holds the ticket, so nothing it does, including a stalled write, can keep the
/// account's line from moving.
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

/// Why a committed change's effects did not run to completion.
pub(crate) enum EffectsError {
    /// The commit failed, so there was nothing to deliver.
    Commit,
    /// The deliveries failed partway and the addressed sessions were evicted.
    Delivery,
}

/// Commits a change with its ticket admitted under the same lock, runs its effects once
/// the ticket turns, and reports the deliveries queued for the caller at that moment,
/// which the caller writes ahead of its reply. Everything from the commit on runs on a
/// task of its own, so a caller retired meanwhile cannot drop what it committed.
pub(crate) fn commit_and_deliver<A, C, E>(
    order: Arc<Order>,
    accounts: Vec<AccountKey>,
    commit: C,
    deliver: Deliver<A>,
    delivery: RouterDelivery<A>,
    mailbox: Option<Mailbox<A>>,
) -> Pending<Result<Vec<RoutedStanza<A>>, EffectsError>>
where
    A: ChunkAllocator + Clone + 'static,
    C: Future<Output = Result<(), E>> + 'static,
{
    let (report_turned, turned) = oneshot::channel();
    let (report_done, done) = oneshot::channel();
    compio::runtime::spawn(async move {
        let result = async {
            let ((), mut ticket) = order
                .fix(accounts.clone(), commit)
                .await
                .map_err(|_| EffectsError::Commit)?;
            ticket.turn().await;
            let _ = report_turned.send(());
            let queued = mailbox.map_or_else(Vec::new, |mailbox| mailbox.take_queued());
            let delivered = delivery.deliver_or_evict(&accounts, deliver).await;
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

    fn tag_session<'a>(&'a self, tag: SessionTag, since: u64) -> DeliveryFuture<'a> {
        Box::pin(async move {
            match &self.session {
                Some(session) => session.tag(tag, since).await.map_err(|_| DeliveryError),
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
