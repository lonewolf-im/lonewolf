// SPDX-License-Identifier: Apache-2.0

use std::future::Future;

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
    Mailbox, Registration, ResourceDelivery, RoutedStanza, RouterError, RouterHandle, SessionHandle,
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

/// Runs `deliver` once `ticket` turns, on a task of its own, so a caller that is
/// cancelled after its commit cannot lose the deliveries the commit promised. The
/// returned future reports the outcome and may be dropped without stopping the work.
///
/// When the ticket turns, everything already in `mailbox` came from earlier commits
/// and predates the caller's view of storage. It is taken out before the effects run
/// and returned, so the caller writes it ahead of its own reply.
pub(crate) fn deliver_committed<A: ChunkAllocator + Clone + 'static>(
    mut ticket: Ticket,
    deliver: Deliver<A>,
    delivery: RouterDelivery<A>,
    mailbox: Option<Mailbox<A>>,
) -> impl Future<Output = Result<Vec<ResourceDelivery<A>>, DeliveryError>> {
    let (done, completed) = oneshot::channel();
    compio::runtime::spawn(async move {
        ticket.turn().await;
        let queued = mailbox.map_or_else(Vec::new, |mailbox| mailbox.take_queued());
        let result = deliver(&delivery).await.map(|()| queued);
        drop(ticket);
        let _ = done.send(result);
    })
    .detach();
    async move { completed.await.unwrap_or(Err(DeliveryError)) }
}

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
