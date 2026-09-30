// SPDX-License-Identifier: Apache-2.0

use futures_channel::oneshot;
use lonewolf_extension::Deliver;
use lonewolf_extension::delivery::{
    Delivery, DeliveryError, DeliveryFuture, HostLookup, SessionTag, StanzaFactory,
};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;

use crate::order::Ticket;
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
}

/// Committed effects running on a task of their own; dropping it does not stop them.
pub(crate) struct Committed<A: ChunkAllocator> {
    turned: oneshot::Receiver<()>,
    done: oneshot::Receiver<Result<Vec<RoutedStanza<A>>, DeliveryError>>,
}

impl<A: ChunkAllocator> Committed<A> {
    /// Resolves when the ticket has turned, which is the cut for the caller's mailbox:
    /// everything delivered before it predates the caller's view of storage.
    pub(crate) async fn turned(&mut self) {
        let _ = (&mut self.turned).await;
    }

    /// The deliveries still queued for the caller when the ticket turned, once the
    /// effects have run; the caller writes them ahead of its own reply.
    pub(crate) async fn finished(self) -> Result<Vec<RoutedStanza<A>>, DeliveryError> {
        self.done.await.unwrap_or(Err(DeliveryError))
    }
}

/// Runs `deliver` once `ticket` turns, on a task of its own, so a caller that is
/// cancelled after its commit cannot lose the deliveries the commit promised.
pub(crate) fn deliver_committed<A, D>(
    mut ticket: Ticket,
    deliver: Deliver<A>,
    delivery: D,
    mailbox: Option<Mailbox<A>>,
) -> Committed<A>
where
    A: ChunkAllocator + Clone + 'static,
    D: Delivery<A> + 'static,
{
    let (report_turned, turned) = oneshot::channel();
    let (report_done, done) = oneshot::channel();
    compio::runtime::spawn(async move {
        ticket.turn().await;
        let _ = report_turned.send(());
        let queued = mailbox.map_or_else(Vec::new, |mailbox| mailbox.take_queued());
        let result = deliver(&delivery).await.map(|()| queued);
        drop(ticket);
        let _ = report_done.send(result);
    })
    .detach();
    Committed { turned, done }
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
