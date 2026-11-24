// SPDX-License-Identifier: Apache-2.0

use std::{mem, sync::Arc};

use futures_channel::oneshot;
use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::observer::{SessionChange, SessionEvent};
use lonewolf_extension::presence::{PresenceAudience, PresenceRequestType, PresenceUpdate};
use lonewolf_storage::roster::{PendingPage, RosterJid};
use lonewolf_storage::{RedbRead, Storage};
use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::Parsed;
use lonewolf_xmpp::stanza::{
    CLIENT_NAMESPACE, PresenceType, Stanza, StanzaErrorCondition, StanzaNamespace, StanzaRef,
    StanzaType,
};

use super::super::{BoundSession, CloseOutcome, OutboxWriter, close_storage_failure};
use super::withdrawal::WithdrawalDelivery;
use super::{AvailabilityHandlers, PresenceContext, PresenceOutcome, PresenceWork};
use crate::c2s::metrics::{C2sWorkerMetrics, ReplayKind, ReplayOutcome};
use crate::delivery::{Pending, after_turn, report_handler_failure};
use crate::order::Ticket;
use crate::router::local::AvailabilityChange;
use crate::router::{MailboxEntry, Registration, RoutedStanza, RouterError};
use crate::stages::service::ServicePresenceLease;
use crate::stages::{Stage, observe, policy};

impl<A: ChunkAllocator + Clone, W: OutboxWriter<A>> BoundSession<'_, A, W> {
    pub(in super::super) async fn handle_availability(
        &mut self,
        parsed: Parsed<Stanza, A>,
        available: bool,
    ) -> Result<(), CloseOutcome> {
        let priority = if available {
            let stanza = parsed.value().resolve(parsed.arena())?;
            match presence_priority(&stanza) {
                Ok(priority) => Some(priority),
                Err(condition) => {
                    let routed = self.stamp(parsed)?;
                    return self.reply_error(&routed, condition);
                }
            }
        } else {
            None
        };
        let (source, mut arena) = parsed.into_parts();
        let (stamped, from, to) = self.stamp_in(source, &mut arena, true)?;
        let service = self
            .presence
            .start_service(
                from.resolve(&arena)?.as_str(),
                &self.router,
                &self.registration,
                &mut self.outbox,
            )
            .await?;
        let unavailable = if available {
            Some(
                Stanza::builder_in(
                    StanzaType::Presence(PresenceType::Unavailable),
                    StanzaNamespace::Client,
                    &mut arena,
                )
                .from(Some(from))?
                .to(to)?
                .build()?,
            )
        } else {
            None
        };
        let change = AvailabilityChange::between(self.presence.priority, priority);
        let kind = if available {
            PresenceRequestType::Available
        } else {
            PresenceRequestType::Unavailable
        };
        let handlers = AvailabilityHandlers {
            presence: self
                .router
                .presence_handlers(self.registration.account().domain())
                .and_then(|handlers| handlers.find_shared(kind)),
            messages: self
                .router
                .message_handler(self.registration.account().domain())
                .cloned(),
        };
        let stage = Stage {
            router: &self.router,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        };
        let request = AvailabilityRequest {
            stamped,
            from,
            arena,
            unavailable,
            change,
        };
        let metrics = self.outbox.metrics.clone();
        let registration = &self.registration;
        let prepare = request.prepare(&stage, registration, &handlers, &metrics, service);
        let mut pending = match self.outbox.drain_until(registration, prepare).await?? {
            Preparation::Admitted(pending) => pending,
            Preparation::Rejected(routed, error) => {
                return self.reply_rejection_with_text(
                    &routed,
                    error.condition(),
                    None,
                    error.text(),
                );
            }
        };
        #[cfg(feature = "test-support")]
        if !available {
            crate::test_support::stream_event(
                &registration.full_jid(),
                crate::test_support::StreamProbeEvent::UnavailablePresenceAdmitted,
            );
        }
        self.outbox
            .drain_until(&self.registration, pending.turned())
            .await?;
        let outcome = pending
            .finished()
            .await
            .ok_or(CloseOutcome::InternalError)??;
        self.presence.priority = outcome.availability.current;
        let transition = outcome.availability.transition();
        let echo = (!self
            .router
            .session_observers(self.registration.account().domain())
            .is_empty())
        .then(|| outcome.echo.clone());
        self.outbox.queue_presence(
            outcome,
            handlers,
            &self.router,
            self.registration.resource(),
        );
        if let Some(echo) = echo {
            let account = self.registration.account();
            let mut arena = Arena::try_new_in(Default::default(), self.allocator.clone())?;
            let session = Jid::from_trusted_parts_in(
                Some(account.username()),
                account.domain(),
                Some(self.registration.resource()),
                &mut arena,
            )?;
            let delivery = self.delivery();
            self.outbox
                .drain_until(
                    &self.registration,
                    observe::session(
                        &stage,
                        &delivery,
                        SessionChange {
                            session: session.resolve(&arena)?,
                            event: SessionEvent::Presence {
                                transition,
                                stanza: &echo,
                            },
                        },
                    ),
                )
                .await?;
        }
        Ok(())
    }
}

struct AvailabilityRequest<A: ChunkAllocator> {
    stamped: Stanza,
    from: Jid,
    arena: Arena<A>,
    unavailable: Option<Stanza>,
    change: AvailabilityChange,
}

enum Preparation<A: ChunkAllocator> {
    Rejected(RoutedStanza<A>, HandlerError),
    Admitted(Pending<Result<PresenceOutcome<A>, CloseOutcome>>),
}

impl<A: ChunkAllocator + Clone> AvailabilityRequest<A> {
    async fn prepare(
        self,
        stage: &Stage<'_, A>,
        registration: &Registration<A>,
        handlers: &AvailabilityHandlers<A>,
        metrics: &C2sWorkerMetrics,
        service: Option<(Arc<ServicePresenceLease>, oneshot::Sender<()>)>,
    ) -> Result<Preparation<A>, CloseOutcome> {
        let Self {
            mut stamped,
            from,
            mut arena,
            unavailable,
            change,
        } = self;
        let priority = change.current;
        let available = priority.is_some();
        let decorations = stage
            .router
            .presence_decorations(registration.account().domain());
        let decorate = available && !decorations.is_empty();
        let backlog_reader = handlers
            .messages
            .as_deref()
            .filter(|_| change.became_eligible());
        let router = stage.router;
        let storage = stage.storage;
        let explicit = router.has_explicit_policy();
        let needs_snapshot = handlers.presence.is_some()
            || backlog_reader.is_some()
            || decorate
            || (!available && explicit);
        let (result, ticket, snapshot) = if needs_snapshot {
            let owner = registration.account();
            let (transaction, ticket) = router
                .order()
                .fix(vec![owner.clone()], storage.begin_read())
                .await
                .map_err(|error| {
                    close_storage_failure(error, "presence_snapshot_begin_read", owner)
                })?;
            let sender = from.resolve(&arena)?;
            let mut result = async {
                let audience = match handlers.presence.as_deref() {
                    Some(handler) => {
                        handler
                            .audience(
                                PresenceUpdate {
                                    sender,
                                    transition: change.transition(),
                                },
                                &transaction,
                            )
                            .await?
                    }
                    None => None,
                };
                if let Some(page) = audience
                    .as_ref()
                    .and_then(|audience| audience.pending.as_ref())
                {
                    metrics.replay_page_read(ReplayKind::SubscriptionRequest, page.byte_len());
                }
                let backlog = match backlog_reader {
                    Some(handler) => {
                        handler
                            .backlog(owner, &transaction)
                            .await?
                            .inspect(|backlog| {
                                metrics.replay_page_read(
                                    ReplayKind::OfflineMessage,
                                    backlog.page.byte_len(),
                                );
                            })
                    }
                    None => None,
                };
                Ok((audience, backlog))
            }
            .await;
            if let Ok((Some(audience), _)) = &mut result {
                let sender = from.resolve(&arena)?;
                policy::filter_audience(
                    router,
                    &transaction,
                    stage.allocator,
                    owner,
                    sender,
                    StanzaType::Presence(if available {
                        PresenceType::Available
                    } else {
                        PresenceType::Unavailable
                    }),
                    audience,
                )
                .await
                .map_err(|_| CloseOutcome::InternalError)?;
                if let Some(page) = &audience.pending {
                    metrics.replay_records(
                        ReplayKind::SubscriptionRequest,
                        ReplayOutcome::Blocked,
                        page.read_len() - page.len(),
                    );
                }
            }
            if decorate {
                let mut children = Vec::with_capacity(decorations.len());
                for (extension, name, namespace, handler) in decorations {
                    match handler.decorate(owner, &transaction, &mut arena).await {
                        Ok(Some(element)) => {
                            let child = element.resolve(&arena)?;
                            if child.name() == *name && child.namespace() == *namespace {
                                children.push((*name, *namespace, element));
                            } else {
                                tracing::error!(
                                    extension,
                                    operation = "presence_decoration",
                                    outcome = "misnamed",
                                    "internal operation failed"
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(error) => report_handler_failure(&error, owner),
                    }
                }
                if !children.is_empty() {
                    let mut builder = stamped.derive_in(&mut arena)?;
                    for (name, namespace, element) in children {
                        builder = builder.remove_children(name, namespace)?.child(element)?;
                    }
                    stamped = builder.build()?;
                }
            }
            (result, ticket, explicit.then_some(transaction))
        } else {
            let ((), ticket) = router
                .order()
                .fix(vec![registration.account().clone()], async {
                    Ok::<_, CloseOutcome>(())
                })
                .await?;
            (Ok((None, None)), ticket, None)
        };
        let (audience, backlog) = match result {
            Ok(result) => result,
            Err(error) => {
                drop(ticket);
                report_handler_failure(&error, registration.account());
                return Ok(Preparation::Rejected(
                    RoutedStanza::from_parts(stamped, arena),
                    error,
                ));
            }
        };
        let (routed, unavailable) = match unavailable {
            Some(unavailable) => {
                let (routed, unavailable) =
                    RoutedStanza::from_parts_pair(stamped, unavailable, arena);
                (routed, Some(unavailable))
            }
            None => (RoutedStanza::from_parts(stamped, arena), None),
        };
        let (service_presence, completion) = service.unzip();
        let work = PresenceWork {
            context: PresenceContext::capture(registration, stage),
            service_presence,
            completion,
            priority,
            routed,
            unavailable,
            audience,
            backlog,
            snapshot,
        };
        Ok(Preparation::Admitted(after_turn(
            stage.work.start(),
            ticket,
            None,
            move |_: Vec<MailboxEntry<A>>, ticket| work.run(ticket),
        )))
    }
}

impl<A: ChunkAllocator + Clone> PresenceWork<A> {
    pub(in super::super) async fn run(
        self,
        ticket: Ticket,
    ) -> Result<PresenceOutcome<A>, CloseOutcome> {
        let PresenceWork {
            context,
            service_presence,
            completion,
            priority,
            routed,
            unavailable,
            mut audience,
            backlog,
            snapshot,
        } = self;
        let session = &context.session;
        let router = &context.router;
        let account = session.account();
        let change = session
            .set_presence(priority, routed.clone(), unavailable)
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        let backlog = if change.availability.became_eligible() {
            backlog
        } else {
            None
        };
        let mut replay = Vec::new();
        let mut requests = None;
        let mut probes = Vec::new();
        if change.availability.became_available()
            && let Some(audience) = audience.as_mut()
        {
            // The ticket keeps subscription revocation behind these deliveries.
            let observer = routed
                .resolve()?
                .from()?
                .ok_or(CloseOutcome::InternalError)?;
            for contact in &audience.contacts {
                let presence = router
                    .current_presence(contact, observer, snapshot.as_ref())
                    .await
                    .map_err(|_| CloseOutcome::InternalError)?;
                replay.extend(presence);
            }
            requests = audience.pending.take();
            probes = mem::take(&mut audience.probes);
            tracing::info!(
                contact_count = audience.contacts.len(),
                replay_count = replay.len(),
                pending_page_count = requests.as_ref().map_or(0, PendingPage::len),
                subscriber_count = audience.subscribers.len(),
                owner_jid = ?account.as_str(),
                "initial presence prepared"
            );
        }
        let published = if priority.is_some() {
            let result = context
                .publish_available(&routed, audience, probes, snapshot.as_ref())
                .await;
            drop(ticket);
            result
        } else {
            let subscribers = audience
                .filter(|audience| {
                    change.availability.became_unavailable() && !audience.subscribers.is_empty()
                })
                .map(|audience| audience.subscribers);
            WithdrawalDelivery {
                notice: &routed,
                directed: &change.directed,
                snapshot: snapshot.as_ref(),
            }
            .deliver(&context.stage(), Some(ticket), subscribers, None)
            .await
        };
        drop(service_presence);
        drop(completion);
        published?;
        Ok(PresenceOutcome {
            availability: change.availability,
            preceding: change.preceding,
            siblings: change.siblings,
            echo: routed,
            replay,
            requests,
            backlog,
        })
    }
}

impl<A: ChunkAllocator + Clone> PresenceContext<A> {
    async fn publish_available(
        &self,
        routed: &RoutedStanza<A>,
        audience: Option<PresenceAudience>,
        probes: Vec<RosterJid>,
        snapshot: Option<&RedbRead>,
    ) -> Result<(), CloseOutcome> {
        if let Some(audience) = audience
            && !audience.subscribers.is_empty()
        {
            let subscribers = &audience.subscribers;
            self.router
                .broadcast_presence(routed, subscribers, snapshot, Some(self.session.liveness()))
                .await
                .map_err(|_| CloseOutcome::InternalError)?;
            self.router
                .broadcast_component_presence(routed, subscribers, Some(self.session.liveness()))
                .map_err(|_| CloseOutcome::InternalError)?;
        }
        let federated = self.router.federation_enabled();
        for contact in probes {
            if !self.session.liveness().is_alive() {
                break;
            }
            if self.router.is_local_host(contact.domain()) {
                continue;
            }
            let component = self.router.is_component_domain(contact.domain());
            if !component && !federated {
                continue;
            }
            let mut arena = Arena::try_new_in(Default::default(), self.allocator.clone())?;
            let to = Jid::parse_in(contact.as_str(), &mut arena)?;
            let from = Jid::parse_in(self.session.account().as_str(), &mut arena)?;
            let stanza = Stanza::builder_in(
                StanzaType::Presence(PresenceType::Probe),
                StanzaNamespace::Client,
                &mut arena,
            )
            .from(Some(from))?
            .to(Some(to))?
            .build()?;
            let stanza = RoutedStanza::from_parts(stanza, arena);
            if component {
                match self.router.route_to_component(stanza) {
                    Ok(()) | Err(RouterError::Offline | RouterError::Busy) => {}
                    Err(_) => return Err(CloseOutcome::InternalError),
                }
            } else if let Err(RouterError::Stopped) = self.router.route_remote_or_bounce(stanza) {
                return Err(CloseOutcome::InternalError);
            }
        }
        Ok(())
    }
}

fn presence_priority<R: ArenaRead>(stanza: &StanzaRef<'_, R>) -> Result<i8, StanzaErrorCondition> {
    let mut priority = None;
    for child in stanza
        .children()
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
    {
        let child = child.map_err(|_| StanzaErrorCondition::InternalServerError)?;
        if child.name() != "priority" || child.namespace() != CLIENT_NAMESPACE {
            continue;
        }
        if priority.is_some()
            || child
                .attributes()
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .next()
                .transpose()
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .is_some()
        {
            return Err(StanzaErrorCondition::BadRequest);
        }
        let text = child
            .text()
            .map_err(|_| StanzaErrorCondition::InternalServerError)?
            .ok_or(StanzaErrorCondition::BadRequest)?;
        priority = Some(
            text.trim()
                .parse::<i8>()
                .map_err(|_| StanzaErrorCondition::BadRequest)?,
        );
    }
    Ok(priority.unwrap_or(0))
}
