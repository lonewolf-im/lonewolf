// SPDX-License-Identifier: Apache-2.0

use std::pin::pin;
use std::sync::Arc;

use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::Shared;
use lonewolf_extension::message::{Backlog, MessageHandler};
use lonewolf_extension::presence::{PresenceAudience, PresenceHandler};
use lonewolf_storage::roster::PendingPage;
use lonewolf_storage::{RedbRead, RedbStorage};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{PresenceType, Stanza, StanzaNamespace, StanzaType};

use super::{BoundSession, CloseOutcome, Outbox, OutboxWriter};
use crate::delivery::{Pending, WorkHandle};
use crate::router::local::AvailabilityChange;
use crate::router::{MailboxEntry, Registration, RoutedStanza, RouterHandle, SessionHandle};
use crate::stages::Stage;
use crate::stages::service::ServicePresenceLease;

mod update;
mod withdrawal;

#[derive(Default)]
pub(super) struct ResourcePresence {
    pub(super) priority: Option<i8>,
    service_lease: Option<Arc<ServicePresenceLease>>,
    service_pending: Option<Shared<oneshot::Receiver<()>>>,
}

impl ResourcePresence {
    pub(super) async fn start_service<A: ChunkAllocator + Clone, W: OutboxWriter<A>>(
        &mut self,
        source: &str,
        router: &RouterHandle<A>,
        registration: &Registration<A>,
        outbox: &mut Outbox<'_, A, W>,
    ) -> Result<Option<(Arc<ServicePresenceLease>, oneshot::Sender<()>)>, CloseOutcome> {
        if self.service_lease.is_none()
            && let Some(gate) = router.service_presence_gate(source)
        {
            self.service_lease = Some(Arc::new(
                outbox
                    .drain_until(registration, pin!(gate.acquire()))
                    .await?,
            ));
        }
        Ok(self.service_lease.as_ref().map(|lease| {
            let (completion, completed) = oneshot::channel();
            self.service_pending = Some(completed.shared());
            (Arc::clone(lease), completion)
        }))
    }
}

pub(super) struct PresenceContext<A: ChunkAllocator> {
    pub(super) session: SessionHandle<A>,
    pub(super) router: RouterHandle<A>,
    pub(super) storage: RedbStorage,
    pub(super) allocator: A,
    pub(super) work: WorkHandle,
}

impl<A: ChunkAllocator + Clone> PresenceContext<A> {
    fn capture(registration: &Registration<A>, stage: &Stage<'_, A>) -> Self {
        Self {
            session: registration.handle(),
            router: stage.router.clone(),
            storage: stage.storage.clone(),
            allocator: stage.allocator.clone(),
            work: stage.work.clone(),
        }
    }

    fn stage(&self) -> Stage<'_, A> {
        Stage {
            router: &self.router,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        }
    }
}

impl<A: ChunkAllocator + Clone, W: OutboxWriter<A>> BoundSession<'_, A, W> {
    pub(super) async fn end_presence(&mut self) -> Result<(), CloseOutcome> {
        let context = PresenceContext::capture(
            &self.registration,
            &Stage {
                router: &self.router,
                storage: &self.storage,
                allocator: &self.allocator,
                work: &self.work,
            },
        );
        let presence = std::mem::take(&mut self.presence);
        let fallback = self.unavailable_notice()?;
        Pending::spawn(self.outbox.work.start(), context.end(presence, fallback))
            .finished()
            .await
            .ok_or(CloseOutcome::InternalError)?
    }

    fn unavailable_notice(&self) -> Result<RoutedStanza<A>, CloseOutcome> {
        let mut arena = Arena::try_new_in(Default::default(), self.allocator.clone())?;
        let account = self.registration.account();
        let from = Jid::from_trusted_parts_in(
            Some(account.username()),
            account.domain(),
            Some(self.registration.resource()),
            &mut arena,
        )?;
        let stanza = Stanza::builder_in(
            StanzaType::Presence(PresenceType::Unavailable),
            StanzaNamespace::Client,
            &mut arena,
        )
        .from(Some(from))?
        .build()?;
        Ok(RoutedStanza::from_parts(stanza, arena))
    }
}

pub(super) struct PresenceWork<A: ChunkAllocator> {
    pub(super) context: PresenceContext<A>,
    pub(super) service_presence: Option<Arc<ServicePresenceLease>>,
    pub(super) completion: Option<oneshot::Sender<()>>,
    pub(super) priority: Option<i8>,
    pub(super) routed: RoutedStanza<A>,
    pub(super) unavailable: Option<RoutedStanza<A>>,
    pub(super) audience: Option<PresenceAudience>,
    pub(super) backlog: Option<Backlog>,
    pub(super) snapshot: Option<RedbRead>,
}

pub(super) struct AvailabilityHandlers<A: ChunkAllocator> {
    pub(super) presence: Option<Arc<dyn PresenceHandler<A, RedbStorage>>>,
    pub(super) messages: Option<Arc<dyn MessageHandler<A, RedbStorage>>>,
}

pub(super) struct PresenceOutcome<A: ChunkAllocator> {
    pub(super) availability: AvailabilityChange,
    pub(super) preceding: Vec<MailboxEntry<A>>,
    pub(super) siblings: Vec<RoutedStanza<A>>,
    pub(super) echo: RoutedStanza<A>,
    pub(super) replay: Vec<crate::router::PresenceDelivery<A>>,
    pub(super) requests: Option<PendingPage>,
    pub(super) backlog: Option<Backlog>,
}
