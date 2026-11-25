// SPDX-License-Identifier: Apache-2.0

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::mem;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
#[cfg(test)]
use std::time::Instant;

use futures_channel::oneshot;
use futures_util::future::{Either, join, select};
#[cfg(test)]
use lonewolf_extension::Effects;
use lonewolf_extension::delivery::HandlerError;
#[cfg(test)]
use lonewolf_extension::delivery::{Failure, FailureKind};
#[cfg(test)]
use lonewolf_extension::discovery::Discovery;
#[cfg(test)]
use lonewolf_extension::iq::{IqDestinationRule, IqHandler, IqReply, IqRequestType, IqScope};
use lonewolf_extension::iq::{
    IqError, IqErrorPayload, IqRequest, SessionIqHandler, SessionIqReply, XmlSpace,
};
use lonewolf_extension::message::{Backlog, MessageHandler};
#[cfg(test)]
use lonewolf_extension::message::{StoreOutcome, UndeliverableMessage};
use lonewolf_extension::observer::{
    MessageEvent, MessageOutcome, MessageRole, SessionChange, SessionEvent,
};
use lonewolf_extension::policy::{Direction, Verdict};
#[cfg(test)]
use lonewolf_extension::presence::{PresenceAudience, PresenceUpdate};
use lonewolf_extension::presence::{PresenceHandler, PresenceRequestType};
#[cfg(test)]
use lonewolf_extension::presence::{PresenceRequest, PresenceSend};
use lonewolf_storage::account::{AccountError, AccountKey, AccountReads};
use lonewolf_storage::offline::OfflineSequence;
use lonewolf_storage::roster::{PendingPage, RosterJid};
use lonewolf_storage::{RedbRead, RedbStorage, RedbWrite, Storage, StorageError, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, ArenaRead, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{Jid, JidError, JidRef};
use lonewolf_xmpp::parser::{ParseError, Parsed, ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{
    ApplicationCondition, BuildError, Element, IqType, MessageType, PresenceType, RejectedStanza,
    Stanza, StanzaErrorCondition, StanzaNamespace, StanzaRef, StanzaType, XML_NAMESPACE,
};

#[cfg(test)]
use lonewolf_xmpp::stanza::CLIENT_NAMESPACE;

use super::bind::Bound;
use super::outcome::CloseOutcome;
use super::recipient_rate::RecipientLimiter;
use super::session::{Session, Writer};
use crate::c2s::iq;
use crate::c2s::metrics::{C2sWorkerMetrics, ReplayKind, ReplayOutcome};
#[cfg(test)]
use crate::delivery::after_turn;
#[cfg(test)]
use crate::delivery::{EffectsDiagnostics, commit_and_deliver};
use crate::delivery::{
    Pending, RouterDelivery, WorkGroup, WorkHandle, report_failure, report_handler_failure,
    storage_failure,
};
use crate::order::Ticket;
use crate::router::local::SessionLiveness;
use crate::router::{
    Destination, MailboxEntry, Registration, ResourceMatch, RoutedStanza, RouterError,
    RouterHandle, ServiceRoute, SessionHandle,
};

use crate::stages::ingress::Origin;
use crate::stages::ingress::iq::{AnswerStanzas, IqAnswer, IqDisposition, IqInput};
#[cfg(test)]
use crate::stages::ingress::iq::{Diagnostics, GetWork, ResourceAuthorization, ResourceIqWork};
use crate::stages::ingress::message::{MessageDisposition, Reply};
use crate::stages::ingress::presence::ProbeAuthorization;
#[cfg(test)]
use crate::stages::iq::require_iq_account;
use crate::stages::service::{self, ServiceOutcome, ServicePresenceLease};
use crate::stages::{Stage, archive, ingress, observe, policy};

mod link;
mod output;
mod presence;
mod replay;
mod subscription;
mod transport;

use link::{Incoming, LinkWriter};
use output::{Outgoing, OutputSequence, Release};
use presence::ResourcePresence;
#[cfg(test)]
use presence::{PresenceContext, PresenceWork};
use replay::ReplayPolicy;
use transport::Transport;

const STORED_STANZA_STREAM_HEADER: &[u8] =
    b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>";

struct BoundSession<'w, A: ChunkAllocator, W = Writer> {
    registration: Registration<A>,
    router: RouterHandle<A>,
    storage: RedbStorage,
    allocator: A,
    work: WorkHandle,
    presence: ResourcePresence,
    recipients: RecipientLimiter,
    incoming: async_channel::Receiver<Incoming<A>>,
    outbox: Outbox<'w, A, W>,
}

struct Outbox<'w, A: ChunkAllocator, W = Writer> {
    queue: VecDeque<Output<A>>,
    writer: W,
    written: OutputSequence,
    releases: VecDeque<(OutputSequence, Release<A>)>,
    allocator: A,
    account: AccountKey,
    storage: RedbStorage,
    liveness: SessionLiveness,
    acknowledgement: Option<ReplayAcknowledgement>,
    selective_acknowledgement: Option<compio::runtime::JoinHandle<()>>,
    messages: Option<MessageRelease>,
    metrics: C2sWorkerMetrics,
    work: &'w WorkGroup,
}

struct ReplayAcknowledgement {
    through: Rc<Cell<OfflineSequence>>,
    task: compio::runtime::JoinHandle<()>,
    #[cfg(test)]
    entered: futures_channel::oneshot::Receiver<()>,
}

struct MessageRelease {
    pending: Rc<RefCell<Vec<OfflineSequence>>>,
    task: compio::runtime::JoinHandle<()>,
}

enum Output<A: ChunkAllocator> {
    Delivered(MailboxEntry<A>),
    Routed(RoutedStanza<A>),
    Presence(crate::router::PresenceDelivery<A>),
    Owned {
        stanza: Stanza,
        arena: Arena<A>,
    },
    /// Each page stays unparsed until it is written, which bounds replay memory.
    Requests {
        page: PendingPage,
        resource: Box<str>,
        handler: Arc<dyn PresenceHandler<A, RedbStorage>>,
        router: RouterHandle<A>,
    },
    Offline {
        backlog: Backlog,
        handler: Arc<dyn MessageHandler<A, RedbStorage>>,
        policy: Option<ReplayPolicy<A>>,
    },
}

enum ServiceAdmission<A: ChunkAllocator> {
    Refused(Verdict, RoutedStanza<A>),
    Directed(RoutedStanza<A>, ServiceRoute<A>),
    Dispatched(Pending<Result<Option<Reply<A>>, crate::stages::StageFailure>>),
}

enum StoredKind<'a> {
    Subscription(&'a RosterJid),
    Message,
}

enum StoredRecordError {
    InvalidContent,
    ReplayFailure,
}

impl From<ParseError> for StoredRecordError {
    fn from(error: ParseError) -> Self {
        if error.is_transport_error() {
            return Self::ReplayFailure;
        }
        match error {
            ParseError::Build(BuildError::Allocation(_) | BuildError::Access(_))
            | ParseError::Build(BuildError::Jid(
                JidError::AllocationFailed(_) | JidError::AccessFailed(_),
            ))
            | ParseError::ParserFailed => Self::ReplayFailure,
            _ => Self::InvalidContent,
        }
    }
}

impl From<HandleError> for StoredRecordError {
    fn from(_: HandleError) -> Self {
        Self::ReplayFailure
    }
}

impl From<StoredRecordError> for CloseOutcome {
    fn from(_: StoredRecordError) -> Self {
        Self::InternalError
    }
}

fn close_storage_failure(
    error: StorageError,
    operation: &'static str,
    account: &AccountKey,
) -> CloseOutcome {
    report_failure(storage_failure(error, operation), account);
    CloseOutcome::InternalError
}

trait OutboxWriter<A: ChunkAllocator> {
    /// The caller must flush buffered output.
    async fn write(&mut self, output: Outgoing<A>) -> Result<(), CloseOutcome>;

    /// `through` is the last stanza sequence the writer must flush.
    async fn flush(&mut self, through: OutputSequence) -> Result<(), CloseOutcome>;
}

impl<A: ChunkAllocator> OutboxWriter<A> for Writer {
    async fn write(&mut self, output: Outgoing<A>) -> Result<(), CloseOutcome> {
        match output {
            Outgoing::Routed(stanza) => Writer::write_routed(self, &stanza).await,
            Outgoing::Owned { stanza, arena } => {
                let stanza = stanza.resolve(&arena)?;
                Writer::write_stanza(self, &stanza).await
            }
        }
    }

    async fn flush(&mut self, _through: OutputSequence) -> Result<(), CloseOutcome> {
        Writer::flush(self).await
    }
}

pub(super) async fn bound_stream<A: ChunkAllocator + Clone>(
    bound: Bound<A>,
    work: &mut WorkGroup,
    recipients: RecipientLimiter,
    metrics: C2sWorkerMetrics,
) -> CloseOutcome {
    let Bound {
        session:
            Session {
                reader,
                writer,
                close,
                ..
            },
        monitor,
        registration,
        router,
        storage,
        allocator,
        resource_requested: _,
    } = bound;
    let (link, incoming, transport_link) = link::link();
    #[cfg(feature = "test-support")]
    let transport_link = transport_link.for_stream(registration.full_jid());
    let watch = link.watch();
    let shutdown = close.shutdown.clone();
    let mut transport = Transport {
        reader,
        writer,
        close,
        monitor,
        link: transport_link,
    };
    {
        let serve = async {
            let outbox = Outbox {
                queue: VecDeque::new(),
                writer: link,
                written: OutputSequence::default(),
                releases: VecDeque::new(),
                allocator: allocator.clone(),
                account: registration.account().clone(),
                storage: storage.clone(),
                liveness: registration.liveness(),
                acknowledgement: None,
                selective_acknowledgement: None,
                messages: None,
                metrics,
                work: &*work,
            };
            let mut session = BoundSession {
                registration,
                router,
                storage,
                allocator,
                work: work.handle(),
                presence: ResourcePresence::default(),
                recipients,
                incoming,
                outbox,
            };
            let stopped = {
                // Retirement takes precedence over shutdown, link failure, and session completion.
                let retired = pin!(session.registration.wait_retired());
                let shutdown = pin!(shutdown);
                let failed = pin!(watch.failed());
                let running = pin!(session.run());
                match select(
                    retired,
                    pin!(select(shutdown, pin!(select(failed, running)))),
                )
                .await
                {
                    Either::Left((retired, _)) => {
                        Either::Left(retired.map(|retired| retired.cause))
                    }
                    Either::Right((Either::Left(_), _)) => {
                        Either::Right(CloseOutcome::SystemShutdown)
                    }
                    Either::Right((Either::Right((Either::Left((outcome, _)), _)), _))
                    | Either::Right((Either::Right((Either::Right((outcome, _)), _)), _)) => {
                        Either::Right(outcome)
                    }
                }
            };
            session.outbox.writer.stop();
            let outcome = match stopped {
                Either::Right(outcome) => outcome,
                Either::Left(Ok(cause)) => cause.into(),
                Either::Left(Err(_)) => CloseOutcome::InternalError,
            };
            let ended = session.end().await;
            let outcome = ended.map_or(CloseOutcome::InternalError, |()| outcome);
            let BoundSession {
                registration,
                outbox,
                ..
            } = session;
            drop(registration);
            let Outbox {
                writer: link,
                acknowledgement,
                selective_acknowledgement,
                messages,
                ..
            } = outbox;
            work.drain().await;
            drop((acknowledgement, selective_acknowledgement, messages));
            link.close(outcome).await;
        };
        let ((), outcome) = join(serve, transport.run()).await;
        outcome
    }
}

impl<A: ChunkAllocator + Clone> BoundSession<'_, A, LinkWriter<A>> {
    async fn run(&mut self) -> CloseOutcome {
        if let Err(outcome) = self.announce_bound().await {
            return outcome;
        }
        let mut prefer_outbound = true;
        loop {
            let selected = {
                let receive = pin!(self.registration.recv());
                let incoming = pin!(self.incoming.recv());
                if prefer_outbound {
                    match select(receive, incoming).await {
                        Either::Left((delivery, _)) => Either::Right(delivery),
                        Either::Right((incoming, _)) => Either::Left(incoming),
                    }
                } else {
                    match select(incoming, receive).await {
                        Either::Left((incoming, _)) => Either::Left(incoming),
                        Either::Right((delivery, _)) => Either::Right(delivery),
                    }
                }
            };
            prefer_outbound = !prefer_outbound;
            match selected {
                Either::Right(Some(delivery)) => {
                    if let Err(outcome) = self
                        .outbox
                        .drain_mailbox(&self.registration, delivery)
                        .await
                    {
                        break outcome;
                    }
                }
                Either::Right(None) | Either::Left(Err(_)) => break CloseOutcome::InternalError,
                Either::Left(Ok(Incoming::Stanza(parsed))) => {
                    let handled = self.handle_stanza(parsed).await;
                    let flushed = self.outbox.flush().await;
                    if let Err(outcome) = handled.and(flushed) {
                        break outcome;
                    }
                    self.outbox.writer.accept();
                }
                Either::Left(Ok(Incoming::Rejected(parsed))) => {
                    let handled = self.handle_rejected(parsed);
                    let flushed = self.outbox.flush().await;
                    if let Err(outcome) = handled.and(flushed) {
                        break outcome;
                    }
                    self.outbox.writer.accept();
                }
                Either::Left(Ok(Incoming::Ended(outcome))) => break outcome,
            }
        }
    }
}

impl<A: ChunkAllocator + Clone, W: OutboxWriter<A>> BoundSession<'_, A, W> {
    async fn announce_bound(&mut self) -> Result<(), CloseOutcome> {
        let account = self.registration.account();
        if self.router.session_observers(account.domain()).is_empty() {
            return Ok(());
        }
        let mut arena = Arena::try_new_in(Default::default(), self.allocator.clone())?;
        let session = Jid::from_trusted_parts_in(
            Some(account.username()),
            account.domain(),
            Some(self.registration.resource()),
            &mut arena,
        )?;
        let stage = Stage {
            router: &self.router,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        };
        let delivery = self.delivery();
        self.outbox
            .drain_until(
                &self.registration,
                observe::session(
                    &stage,
                    &delivery,
                    SessionChange {
                        session: session.resolve(&arena)?,
                        event: SessionEvent::Bound,
                    },
                ),
            )
            .await
    }

    async fn end(&mut self) -> Result<(), CloseOutcome> {
        self.end_presence().await?;
        let account = self.registration.account();
        if !self.router.session_observers(account.domain()).is_empty() {
            let mut arena = Arena::try_new_in(Default::default(), self.allocator.clone())?;
            let session = Jid::from_trusted_parts_in(
                Some(account.username()),
                account.domain(),
                Some(self.registration.resource()),
                &mut arena,
            )?;
            let stage = Stage {
                router: &self.router,
                storage: &self.storage,
                allocator: &self.allocator,
                work: &self.work,
            };
            let delivery = RouterDelivery::new(&self.router, &self.allocator, None);
            observe::session(
                &stage,
                &delivery,
                SessionChange {
                    session: session.resolve(&arena)?,
                    event: SessionEvent::Ended,
                },
            )
            .await;
        }
        Ok(())
    }

    fn handle_rejected(&mut self, parsed: Parsed<RejectedStanza, A>) -> Result<(), CloseOutcome> {
        let (rejected, mut arena) = parsed.into_parts();
        if rejected.namespace() != StanzaNamespace::Client {
            return Err(CloseOutcome::InvalidNamespace);
        }
        if !rejected.can_reply() {
            return Ok(());
        }
        let account = self.registration.account();
        let authenticated = Jid::from_trusted_parts_in(
            Some(account.username()),
            account.domain(),
            Some(self.registration.resource()),
            &mut arena,
        )?;
        let server = Jid::from_trusted_parts_in(None, account.domain(), None, &mut arena)?;
        let reply = rejected.error_in(authenticated, server, &mut arena)?;
        self.outbox.push(Output::Owned {
            stanza: reply,
            arena,
        });
        Ok(())
    }

    async fn handle_stanza(&mut self, parsed: Parsed<Stanza, A>) -> Result<(), CloseOutcome> {
        let stanza = parsed.value().resolve(parsed.arena())?;
        if stanza.namespace() != StanzaNamespace::Client {
            return Err(CloseOutcome::InvalidNamespace);
        }
        let parsed = if matches!(stanza.stanza_type(), StanzaType::Iq(_)) {
            let Some(parsed) = self.admit_iq(parsed)? else {
                return Ok(());
            };
            parsed
        } else {
            parsed
        };
        let stanza = parsed.value().resolve(parsed.arena())?;
        let target = stanza.to()?;
        if let StanzaType::Presence(kind) = stanza.stanza_type()
            && let Some(kind) = PresenceRequestType::from_subscription_stanza(kind)
            && target.is_some_and(|to| self.router.is_component_domain(to.domainpart()))
            && self
                .router
                .presence_handlers(self.registration.account().domain())
                .and_then(|handlers| handlers.find(kind))
                .is_some()
        {
            return self.handle_subscription(parsed, kind).await;
        }
        let service = target.and_then(|to| self.router.service(to.domainpart()).cloned());
        if let Some(route) = service {
            return self.handle_service(parsed, route).await;
        }
        match stanza.stanza_type() {
            StanzaType::Iq(_) => self.handle_iq(parsed).await,
            StanzaType::Presence(kind) => {
                let directed = stanza.to()?.is_some();
                self.handle_presence(parsed, kind, directed).await
            }
            StanzaType::Message(kind) => self.handle_message(parsed, kind).await,
        }
    }

    async fn handle_service(
        &mut self,
        parsed: Parsed<Stanza, A>,
        route: ServiceRoute<A>,
    ) -> Result<(), CloseOutcome> {
        let routed = self.stamp(parsed)?;
        let liveness = self.registration.liveness();
        let account = self.registration.account();
        let kind = routed.resolve()?.stanza_type();
        let is_message = matches!(kind, StanzaType::Message(_));
        let directed = matches!(
            kind,
            StanzaType::Presence(PresenceType::Available | PresenceType::Unavailable)
        );
        let archive_needed = is_message && self.router.archive_handler(account.domain()).is_some();
        let prepared = self
            .outbox
            .drain_until(&self.registration, async {
                let stage = Stage {
                    router: &self.router,
                    storage: &self.storage,
                    allocator: &self.allocator,
                    work: &self.work,
                };
                let view = routed.resolve()?;
                let peer = view.to()?.ok_or(CloseOutcome::InternalError)?;
                let checks = [policy::Check {
                    account,
                    direction: Direction::Outbound,
                    peer,
                }];
                let ordered = ingress::checks::fix_explicit_snapshot(
                    stage.router,
                    stage.storage,
                    Some(account),
                    None,
                )
                .await?;
                let (verdict, mut admission) = if let Some((snapshot, ticket)) = ordered {
                    (
                        policy::evaluate_in(stage.router, &snapshot, view.stanza_type(), &checks)
                            .await?,
                        Some(ticket),
                    )
                } else {
                    (
                        policy::evaluate(&stage, view.stanza_type(), &checks).await?,
                        None,
                    )
                };
                if verdict != Verdict::Allow {
                    return Ok(ServiceAdmission::Refused(verdict, routed));
                }
                if let Some(ticket) = &mut admission {
                    ticket.turn().await;
                }
                if !liveness.is_alive() {
                    return Ok(ServiceAdmission::Refused(Verdict::Drop, routed));
                }
                if directed {
                    return Ok(ServiceAdmission::Directed(routed, route));
                }
                let archived = if archive_needed {
                    archive::archive_addressed(&stage, routed, Some(account), None, Some(&liveness))
                        .await?
                } else {
                    archive::ArchiveStep::Accepted(archive::Archived {
                        stanza: routed,
                        sent: None,
                        received: None,
                    })
                };
                let archive::Archived { stanza, sent, .. } = match archived {
                    archive::ArchiveStep::Accepted(archived) => archived,
                    archive::ArchiveStep::Rejected {
                        stanza,
                        condition,
                        text,
                    } => {
                        return Ok(ServiceAdmission::Refused(
                            Verdict::Reject {
                                condition,
                                application: None,
                                text: Some(text),
                            },
                            stanza,
                        ));
                    }
                };
                if !liveness.is_alive() {
                    return Ok(ServiceAdmission::Refused(Verdict::Drop, stanza));
                }
                let observer = (is_message
                    && !self.router.message_observers(account.domain()).is_empty())
                .then(|| self.registration.handle());
                let work = ServiceWork {
                    router: self.router.clone(),
                    storage: self.storage.clone(),
                    allocator: self.allocator.clone(),
                    work: self.work.clone(),
                    observer,
                    archived: sent,
                    stanza,
                    route,
                };
                let pending = Pending::spawn(self.work.start(), work.run());
                drop(admission);
                Ok::<_, CloseOutcome>(ServiceAdmission::Dispatched(pending))
            })
            .await??;
        match prepared {
            ServiceAdmission::Refused(Verdict::OutboundBlocked, stanza) => {
                self.reply_outbound_blocked(&stanza)
            }
            ServiceAdmission::Refused(
                Verdict::Reject {
                    condition,
                    application,
                    text,
                },
                stanza,
            ) => self.reply_rejection_with_text(
                &stanza,
                condition,
                application,
                text.unwrap_or_else(|| condition.default_text()),
            ),
            ServiceAdmission::Refused(Verdict::Drop | Verdict::Allow, _) => Ok(()),
            ServiceAdmission::Directed(routed, route) => {
                self.handle_directed_service(routed, route, liveness).await
            }
            ServiceAdmission::Dispatched(pending) => {
                let reply = self
                    .outbox
                    .drain_until(&self.registration, pending.finished())
                    .await?
                    .ok_or(CloseOutcome::InternalError)??;
                match reply {
                    Some(reply) => self.reply_from_ingress(reply),
                    None => Ok(()),
                }
            }
        }
    }

    async fn handle_directed_service(
        &mut self,
        routed: RoutedStanza<A>,
        route: ServiceRoute<A>,
        liveness: SessionLiveness,
    ) -> Result<(), CloseOutcome> {
        let account = self.registration.account();
        let policy_account = policy::Selection::Explicit
            .configured(&self.router, account.domain())
            .then(|| account.clone());
        let from = routed
            .resolve()?
            .from()?
            .ok_or(CloseOutcome::InternalError)?;
        let (lease, completion) = self
            .presence
            .start_service(
                from.as_str(),
                &self.router,
                &self.registration,
                &mut self.outbox,
            )
            .await?
            .ok_or(CloseOutcome::InternalError)?;
        let work = DirectedServiceWork {
            session: self.registration.handle(),
            liveness,
            policy_account,
            router: self.router.clone(),
            storage: self.storage.clone(),
            allocator: self.allocator.clone(),
            work: self.work.clone(),
            lease,
            completion,
            stanza: routed.clone(),
            route,
        };
        let pending = Pending::spawn(self.work.start(), work.run());
        let outcome = match self
            .outbox
            .drain_until(&self.registration, pending.finished())
            .await?
            .ok_or(CloseOutcome::InternalError)?
        {
            Ok(DirectedServiceOutcome::Dispatched(outcome)) => outcome,
            Ok(DirectedServiceOutcome::Blocked) => return self.reply_outbound_blocked(&routed),
            Err(RouterError::DirectedPresenceLimit) => {
                tracing::warn!(
                    account_jid = ?self.registration.account().as_str(),
                    stanza_kind = "presence",
                    outcome = "directed_presence_limit",
                    "directed presence rejected"
                );
                return self.reply_error(&routed, StanzaErrorCondition::ResourceConstraint);
            }
            Err(_) => return Err(CloseOutcome::InternalError),
        };
        match outcome {
            ServiceOutcome::Rejected {
                stanza,
                condition,
                text,
            } => self.reply_rejection_with_text(&stanza, condition, None, text),
            ServiceOutcome::Handled => Ok(()),
        }
    }

    fn admit_iq(
        &mut self,
        parsed: Parsed<Stanza, A>,
    ) -> Result<Option<Parsed<Stanza, A>>, CloseOutcome> {
        let stanza = parsed.value().resolve(parsed.arena())?;
        let error = if self.admit_recipient(&stanza)? {
            crate::stages::iq::destination_error(
                &self.router,
                Some(self.registration.account()),
                &stanza,
            )?
        } else {
            Some(HandlerError::described(StanzaErrorCondition::PolicyViolation,
                lonewolf_xmpp::stanza::StanzaErrorText::Static("Too many distinct recipients were contacted. Wait before contacting additional recipients.")).into())
        };
        let Some(error) = error else {
            return Ok(Some(parsed));
        };
        let (request, mut arena) = parsed.into_parts();
        let account = self.registration.account();
        let sender = Jid::from_trusted_parts_in(
            Some(account.username()),
            account.domain(),
            Some(self.registration.resource()),
            &mut arena,
        )?;
        self.queue_iq_error(request, sender, arena, error)?;
        Ok(None)
    }

    /// Committed handler effects outlive this session.
    async fn handle_iq(&mut self, parsed: Parsed<Stanza, A>) -> Result<(), CloseOutcome> {
        let (request, mut arena) = parsed.into_parts();
        let route = iq::route(&request, &mut arena, &self.registration, &self.router)?;
        let stage = Stage {
            router: &self.router,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        };
        let origin = Origin::Session(&self.registration);
        let disposition = self
            .outbox
            .drain_until(
                &self.registration,
                ingress::iq::handle(
                    &stage,
                    &origin,
                    IqInput::Owned {
                        request,
                        arena,
                        sender: route.sender,
                    },
                    route.destination,
                    route.kind,
                ),
            )
            .await??;
        if route.kind == IqType::Get && matches!(&disposition, IqDisposition::Ordered(_)) {
            #[cfg(feature = "test-support")]
            crate::test_support::stream_event(
                &self.registration.full_jid(),
                crate::test_support::StreamProbeEvent::IqGetAdmitted,
            );
        }
        self.complete_iq(disposition).await
    }

    async fn complete_iq(&mut self, disposition: IqDisposition<A>) -> Result<(), CloseOutcome> {
        match disposition {
            IqDisposition::Done => Ok(()),
            IqDisposition::OutboundBlocked(IqInput::Owned {
                request,
                mut arena,
                sender,
            }) => {
                let stanza = iq::outbound_blocked_reply(&request, &mut arena, sender)?;
                self.outbox.push(Output::Owned { stanza, arena });
                Ok(())
            }
            IqDisposition::OutboundBlocked(IqInput::Routed(stanza)) => {
                self.reply_outbound_blocked(&stanza)
            }
            IqDisposition::PolicyRejected {
                input: IqInput::Owned {
                    request, mut arena, ..
                },
                condition,
                application,
                text,
            } => {
                let stanza = request
                    .error_reply_described_in(&mut arena, condition, application, text)?
                    .to(None)?
                    .build()?;
                self.outbox.push(Output::Owned { stanza, arena });
                Ok(())
            }
            IqDisposition::PolicyRejected { .. } => Err(CloseOutcome::InternalError),
            IqDisposition::Unavailable {
                input: IqInput::Owned {
                    request, mut arena, ..
                },
                condition,
                response,
                ..
            } => {
                let stanza = iq::error_reply(&request, &mut arena, condition, None)?;
                self.outbox.push(Output::Owned { stanza, arena });
                drop(response);
                Ok(())
            }
            IqDisposition::Unavailable {
                input: IqInput::Routed(stanza),
                condition,
                kind: ingress::iq::UnavailableKind::Resource,
                ..
            } => self.reply_error(&stanza, condition),
            IqDisposition::Unavailable {
                input: IqInput::Routed(stanza),
                condition,
                kind: ingress::iq::UnavailableKind::Remote,
                ..
            } => {
                let mut arena = Arena::try_new_in(Default::default(), self.allocator.clone())?;
                let request = stanza.resolve()?.clone_in(&mut arena)?;
                let reply = iq::error_reply(&request, &mut arena, condition, None)?;
                self.outbox.push(Output::Owned {
                    stanza: reply,
                    arena,
                });
                Ok(())
            }
            IqDisposition::Unavailable { .. } => Err(CloseOutcome::InternalError),
            IqDisposition::SessionIq {
                handler,
                request,
                arena,
                sender,
                response,
            } => {
                self.handle_session_iq(request, sender, arena, response, handler)
                    .await
            }
            IqDisposition::Answer(answer) => self.queue_iq_answer(answer),
            IqDisposition::Ordered(mut pending) => {
                self.outbox
                    .drain_until(&self.registration, pending.turned())
                    .await?;
                let completed = pending
                    .finished()
                    .await
                    .ok_or(CloseOutcome::InternalError)??;
                self.outbox.delivered(completed.queued);
                self.queue_iq_answer(completed.answer)
            }
        }
    }

    fn queue_iq_answer(&mut self, answer: IqAnswer<A>) -> Result<(), CloseOutcome> {
        let origin = Origin::Session(&self.registration);
        match ingress::iq::render_answer(&origin, &self.allocator, answer)? {
            AnswerStanzas::One { stanza, arena } => {
                self.outbox.push(Output::Owned { stanza, arena })
            }
            AnswerStanzas::Shared(stanzas) => self.outbox.routed(stanzas),
        }
        Ok(())
    }

    async fn handle_session_iq(
        &mut self,
        request: Stanza,
        sender: Jid,
        arena: Arena<A>,
        mut response: Arena<A>,
        handler: Arc<dyn SessionIqHandler<A>>,
    ) -> Result<(), CloseOutcome> {
        let reply = {
            let sender = sender.resolve(&arena)?;
            let stanza = request.resolve(&arena)?;
            let target = stanza.to()?.unwrap_or_else(|| sender.bare());
            let discovery = self
                .router
                .discovery(target.domainpart())
                .ok_or(CloseOutcome::InternalError)?;
            let payload = stanza
                .children()?
                .next()
                .transpose()?
                .ok_or(CloseOutcome::InternalError)?;
            let delivery = self.delivery();
            handler.set(
                IqRequest {
                    sender,
                    target,
                    discovery,
                    sessions: &delivery,
                    requester: None,
                    lang: stanza.lang()?,
                    space: stanza
                        .attribute("space", XML_NAMESPACE)?
                        .map(XmlSpace::from_attribute),
                    payload,
                },
                &mut response,
            )
        };
        let reply = match reply {
            Ok(SessionIqReply { payload, change }) => {
                if let Some(change) = change {
                    match self.registration.handle().change_tag(change).await {
                        Ok(preceding) => self.outbox.delivered(preceding),
                        Err(RouterError::NotFound) => {
                            tracing::debug!(
                                account_jid = ?self.registration.account().as_str(),
                                operation = "session_iq",
                                outcome = "session_retired",
                                "session IQ tag change skipped"
                            );
                            return self.queue_iq_reply(
                                request,
                                sender,
                                arena,
                                response,
                                Err(IqError::without_payload(
                                    StanzaErrorCondition::InternalServerError.into(),
                                )),
                                Vec::new(),
                            );
                        }
                        Err(_) => return Err(CloseOutcome::InternalError),
                    }
                }
                Ok(payload)
            }
            Err(error) => {
                report_handler_failure(error.handler_error(), self.registration.account());
                Err(error)
            }
        };
        self.queue_iq_reply(request, sender, arena, response, reply, Vec::new())
    }

    #[cfg(test)]
    async fn handle_iq_get(
        &mut self,
        request: Stanza,
        sender: Jid,
        arena: Arena<A>,
        response: Arena<A>,
        handler: Arc<dyn IqHandler<A, RedbStorage>>,
        target_account: Option<AccountKey>,
    ) -> Result<(), CloseOutcome> {
        let stage = Stage {
            router: &self.router,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        };
        let origin = Origin::Session(&self.registration);
        let answer = IqAnswer {
            request,
            arena,
            sender: Some(sender),
            response,
            reply: Ok(None),
            results: Vec::new(),
        };
        let disposition = self
            .outbox
            .drain_until(
                &self.registration,
                ingress::iq::prepare_get(&stage, &origin, answer, handler, target_account),
            )
            .await??;
        #[cfg(feature = "test-support")]
        crate::test_support::stream_event(
            &self.registration.full_jid(),
            crate::test_support::StreamProbeEvent::IqGetAdmitted,
        );
        self.complete_iq(disposition).await
    }

    #[cfg(test)]
    async fn handle_iq_set(
        &mut self,
        request: Stanza,
        sender: Jid,
        arena: Arena<A>,
        response: Arena<A>,
        handler: Arc<dyn IqHandler<A, RedbStorage>>,
        target_account: Option<AccountKey>,
    ) -> Result<(), CloseOutcome> {
        let stage = Stage {
            router: &self.router,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        };
        let origin = Origin::Session(&self.registration);
        let answer = IqAnswer {
            request,
            arena,
            sender: Some(sender),
            response,
            reply: Ok(None),
            results: Vec::new(),
        };
        let disposition = self
            .outbox
            .drain_until(
                &self.registration,
                ingress::iq::prepare_set(&stage, &origin, answer, handler, target_account),
            )
            .await??;
        self.complete_iq(disposition).await
    }

    fn queue_iq_error(
        &mut self,
        request: Stanza,
        sender: Jid,
        mut arena: Arena<A>,
        error: IqError,
    ) -> Result<(), CloseOutcome> {
        let (stanza, arena) = match error.payload() {
            IqErrorPayload::Include => {
                let stanza = request
                    .error_reply_described_in(
                        &mut arena,
                        error.condition(),
                        None,
                        error.handler_error().text(),
                    )?
                    .to(Some(sender))?
                    .build()?;
                (stanza, arena)
            }
            IqErrorPayload::Omit => {
                let mut response = Arena::try_new_in(Default::default(), self.allocator.clone())?;
                let stanza = iq::error_reply_omitting_payload(
                    &request.resolve(&arena)?,
                    sender.resolve(&arena)?,
                    error.condition(),
                    error.handler_error().text(),
                    &mut response,
                )?;
                (stanza, response)
            }
        };
        self.outbox.push(Output::Owned { stanza, arena });
        Ok(())
    }

    fn queue_iq_reply(
        &mut self,
        request: Stanza,
        sender: Jid,
        arena: Arena<A>,
        response: Arena<A>,
        reply: Result<Option<Element>, IqError>,
        results: Vec<Stanza>,
    ) -> Result<(), CloseOutcome> {
        self.queue_iq_answer(IqAnswer {
            request,
            arena,
            sender: Some(sender),
            response,
            reply,
            results,
        })
    }

    async fn handle_presence(
        &mut self,
        parsed: Parsed<Stanza, A>,
        kind: PresenceType,
        directed: bool,
    ) -> Result<(), CloseOutcome> {
        if directed {
            return match (PresenceRequestType::from_subscription_stanza(kind), kind) {
                (Some(kind), _) => self.handle_subscription(parsed, kind).await,
                (None, PresenceType::Available | PresenceType::Unavailable) => {
                    self.handle_directed(parsed, kind == PresenceType::Available)
                        .await
                }
                (None, PresenceType::Probe) => self.handle_probe(parsed).await,
                (None, PresenceType::Error) => {
                    let routed = self.stamp(parsed)?;
                    self.outbox
                        .drain_until(&self.registration, async {
                            let (verdict, admission) = explicit_presence_policy(
                                &self.router,
                                &self.storage,
                                &self.registration,
                                &routed,
                            )
                            .await?;
                            let liveness = self.registration.liveness();
                            if verdict != Verdict::Allow || !liveness.is_alive() {
                                return Ok(());
                            }
                            if self.router.federation_enabled()
                                && self.router.destination(
                                    routed.resolve()?.to()?.ok_or(CloseOutcome::InternalError)?,
                                ) == Destination::Remote
                            {
                                let _ = self.router.route_remote_or_bounce(routed);
                                return Ok(());
                            }
                            match self
                                .router
                                .route_addressed_presence_error(
                                    routed,
                                    Some(liveness),
                                    admission.as_ref().map(|(snapshot, _)| snapshot),
                                )
                                .await
                            {
                                Ok(())
                                | Err(
                                    RouterError::NotFound
                                    | RouterError::Busy
                                    | RouterError::InvalidTarget
                                    | RouterError::RemoteUnsupported,
                                ) => Ok(()),
                                Err(_) => Err(CloseOutcome::InternalError),
                            }
                        })
                        .await?
                }
                (None, _) => Ok(()),
            };
        }
        match kind {
            PresenceType::Available | PresenceType::Unavailable => {
                self.handle_availability(parsed, kind == PresenceType::Available)
                    .await
            }
            _ => Ok(()),
        }
    }

    async fn directed_presence_fallback(
        &mut self,
        routed: &RoutedStanza<A>,
        destination: Destination,
    ) -> Result<(), CloseOutcome> {
        let verdict = self
            .outbox
            .drain_until(&self.registration, async {
                explicit_presence_policy(&self.router, &self.storage, &self.registration, routed)
                    .await
                    .map(|(verdict, _admission)| verdict)
            })
            .await??;
        match verdict {
            Verdict::Allow if destination == Destination::Remote => {
                self.reply_error(routed, StanzaErrorCondition::RemoteServerNotFound)
            }
            Verdict::OutboundBlocked => self.reply_outbound_blocked(routed),
            Verdict::Allow | Verdict::Drop | Verdict::Reject { .. } => Ok(()),
        }
    }

    async fn handle_probe(&mut self, parsed: Parsed<Stanza, A>) -> Result<(), CloseOutcome> {
        let routed = self.stamp(parsed)?;
        if !self.admit_routed(&routed)? {
            return Ok(());
        }
        let target = {
            let view = routed.resolve()?;
            let to = view.to()?.ok_or(CloseOutcome::InternalError)?;
            match self.router.destination(to) {
                Destination::Account | Destination::Resource => {
                    Some(AccountKey::try_from(to.bare()).map_err(|_| CloseOutcome::InternalError)?)
                }
                Destination::Remote if self.router.federation_enabled() => None,
                destination => return self.directed_presence_fallback(&routed, destination).await,
            }
        };
        let session = self.registration.handle();
        let liveness = self.registration.liveness();
        let router = self.router.clone();
        let storage = self.storage.clone();
        let account = self.registration.account().clone();
        let pending = Pending::spawn(self.outbox.work.start(), async move {
            let local = target.is_some();
            let grant = match ingress::presence::authorize_probe(
                router.clone(),
                storage,
                Some(account),
                target,
                &routed,
                false,
            )
            .await?
            {
                ProbeAuthorization::Granted(grant) => grant,
                ProbeAuthorization::OutboundBlocked => return Ok::<_, CloseOutcome>(Some(routed)),
                ProbeAuthorization::Denied => return Ok(None),
            };
            if !liveness.is_alive() {
                return Ok(None);
            }
            let result = if local {
                router
                    .probe_presence(&session, &routed, grant.subscribed, grant.snapshot.as_ref())
                    .await
            } else {
                match router.route_remote_or_bounce(routed) {
                    Err(RouterError::Stopped) => Err(RouterError::Stopped),
                    _ => Ok(()),
                }
            };
            drop(grant.ticket);
            result
                .map(|()| None)
                .map_err(|_| CloseOutcome::InternalError)
        });
        let blocked = self
            .outbox
            .drain_until(&self.registration, pending.finished())
            .await?
            .ok_or(CloseOutcome::InternalError)?
            .map_err(|_| CloseOutcome::InternalError)?;
        if let Some(routed) = blocked {
            self.reply_outbound_blocked(&routed)?;
        }
        Ok(())
    }

    async fn handle_directed(
        &mut self,
        parsed: Parsed<Stanza, A>,
        available: bool,
    ) -> Result<(), CloseOutcome> {
        let routed = self.stamp(parsed)?;
        if !self.admit_routed(&routed)? {
            return Ok(());
        }
        let (target, full) = {
            let view = routed.resolve()?;
            let to = view.to()?.ok_or(CloseOutcome::InternalError)?;
            match self.router.destination(to) {
                Destination::Account | Destination::Resource => (
                    Some(AccountKey::try_from(to.bare()).map_err(|_| CloseOutcome::InternalError)?),
                    (available && to.is_full()).then(|| Box::from(to.as_str())),
                ),
                Destination::Remote if self.router.federation_enabled() => (None, None),
                destination => return self.directed_presence_fallback(&routed, destination).await,
            }
        };
        let session = self.registration.handle();
        let liveness = self.registration.liveness();
        let router = self.router.clone();
        let storage = self.storage.clone();
        let account = self.registration.account().clone();
        let directed = routed.clone();
        let pending = Pending::spawn(self.outbox.work.start(), async move {
            let remote = target.is_none();
            let peer = target.as_ref().filter(|target| *target != &account);
            let policies = target.as_ref() != Some(&account)
                && (!router.policies(account.domain()).is_empty()
                    || peer.is_some_and(|target| !router.policies(target.domain()).is_empty()));
            let read = async {
                if policies {
                    storage.begin_read().await.map(Some).map_err(|error| {
                        close_storage_failure(error, "directed_presence_begin_read", &account);
                        RouterError::Unavailable
                    })
                } else {
                    Ok(None)
                }
            };
            let (snapshot, mut ticket) = match peer {
                Some(target) if available => {
                    router
                        .order()
                        .fix_directed_grant(account.clone(), target.clone(), full, read)
                        .await?
                }
                target => {
                    let mut accounts = vec![account.clone()];
                    accounts.extend(target.cloned());
                    router.order().fix(accounts, read).await?
                }
            };
            if let Some(snapshot) = snapshot.as_ref() {
                let view = directed.resolve().map_err(|_| RouterError::InvalidTarget)?;
                let verdict = ingress::checks::check_from(
                    &router,
                    &storage,
                    Some(&account),
                    target.as_ref(),
                    &view,
                    None,
                    ingress::checks::Snapshot::Ordered(snapshot),
                )
                .await
                .map_err(|_| RouterError::Unavailable)?;
                if verdict != Verdict::Allow {
                    return Ok(verdict);
                }
            }
            ticket.turn().await;
            if !liveness.is_alive() {
                return Ok(Verdict::Drop);
            }
            if !remote {
                let allowed = router
                    .presence_recipient_filter(snapshot.as_ref(), &directed)
                    .await?;
                session
                    .directed_presence_filtered(directed, available, allowed.as_deref())
                    .await?;
            } else {
                let to = directed
                    .resolve()
                    .map_err(|_| RouterError::InvalidTarget)?
                    .to()
                    .map_err(|_| RouterError::InvalidTarget)?
                    .ok_or(RouterError::InvalidTarget)?;
                session.record_service_presence(to, available).await?;
                if liveness.is_alive()
                    && matches!(
                        router.route_remote_or_bounce(directed),
                        Err(RouterError::Stopped)
                    )
                {
                    return Err(RouterError::Stopped);
                }
            }
            Ok(Verdict::Allow)
        });
        let result = self
            .outbox
            .drain_until(&self.registration, pending.finished())
            .await?
            .ok_or(CloseOutcome::InternalError)?;
        match result {
            Ok(Verdict::OutboundBlocked) => self.reply_outbound_blocked(&routed),
            Ok(Verdict::Allow | Verdict::Drop | Verdict::Reject { .. }) => Ok(()),
            Err(RouterError::DirectedPresenceLimit) => {
                tracing::warn!(
                    account_jid = ?self.registration.account().as_str(),
                    stanza_kind = "presence",
                    outcome = "directed_presence_limit",
                    "directed presence rejected"
                );
                self.reply_error(&routed, StanzaErrorCondition::ResourceConstraint)
            }
            Err(_) => Err(CloseOutcome::InternalError),
        }
    }

    async fn handle_message(
        &mut self,
        parsed: Parsed<Stanza, A>,
        kind: MessageType,
    ) -> Result<(), CloseOutcome> {
        let routed = self.stamp(parsed)?;
        if !self.admit_routed(&routed)? {
            return Ok(());
        }
        let router = self.router.clone();
        let storage = self.storage.clone();
        let allocator = self.allocator.clone();
        let work = self.work.clone();
        let sender = self.registration.handle();
        let pending = Pending::spawn(self.work.start(), async move {
            let stage = Stage {
                router: &router,
                storage: &storage,
                allocator: &allocator,
                work: &work,
            };
            ingress::message::handle_from(
                &stage,
                Some(&sender),
                routed,
                kind,
                crate::stages::message::MissingRecipientPolicy::Discard,
            )
            .await
        });
        let disposition = self
            .outbox
            .drain_until(&self.registration, pending.finished())
            .await?
            .ok_or(CloseOutcome::InternalError)??;
        match disposition {
            MessageDisposition::Done => Ok(()),
            MessageDisposition::Reply(reply) => self.reply_from_ingress(reply),
        }
    }

    fn reply_from_ingress(&mut self, reply: Reply<A>) -> Result<(), CloseOutcome> {
        match reply {
            Reply::Built(reply) => {
                self.outbox.push(Output::Routed(reply));
                Ok(())
            }
            Reply::Error {
                stanza,
                condition,
                application,
                text,
            } => self.reply_rejection_with_text(&stanza, condition, application, text),
        }
    }

    fn reply_error(
        &mut self,
        source: &RoutedStanza<A>,
        condition: StanzaErrorCondition,
    ) -> Result<(), CloseOutcome> {
        self.reply_rejection(source, condition, None)
    }

    fn reply_rejection(
        &mut self,
        source: &RoutedStanza<A>,
        condition: StanzaErrorCondition,
        application: Option<ApplicationCondition>,
    ) -> Result<(), CloseOutcome> {
        self.reply_rejection_with_text(source, condition, application, condition.default_text())
    }

    fn reply_rejection_with_text(
        &mut self,
        source: &RoutedStanza<A>,
        condition: StanzaErrorCondition,
        application: Option<ApplicationCondition>,
        text: lonewolf_xmpp::stanza::StanzaErrorText,
    ) -> Result<(), CloseOutcome> {
        self.outbox.push(Output::Routed(self.rejection_reply(
            source,
            condition,
            application,
            text,
        )?));
        Ok(())
    }

    fn reply_outbound_blocked(&mut self, source: &RoutedStanza<A>) -> Result<(), CloseOutcome> {
        let reply = ingress::outbound_blocked_reply(&self.allocator, source)?;
        self.outbox.push(Output::Routed(reply));
        Ok(())
    }

    fn rejection_reply(
        &self,
        source: &RoutedStanza<A>,
        condition: StanzaErrorCondition,
        application: Option<ApplicationCondition>,
        text: lonewolf_xmpp::stanza::StanzaErrorText,
    ) -> Result<RoutedStanza<A>, CloseOutcome> {
        Ok(ingress::rejection_reply(
            &self.allocator,
            source,
            condition,
            application,
            text,
        )?)
    }

    fn delivery(&self) -> RouterDelivery<A> {
        RouterDelivery::new(&self.router, &self.allocator, Some(&self.registration))
    }

    fn admit_recipient<R: ArenaRead>(
        &mut self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<bool, CloseOutcome> {
        if matches!(
            stanza.stanza_type(),
            StanzaType::Iq(IqType::Result | IqType::Error)
                | StanzaType::Message(MessageType::Error)
                | StanzaType::Presence(PresenceType::Error)
        ) {
            return Ok(true);
        }
        let Some(to) = stanza.to()? else {
            return Ok(true);
        };
        let destination = self.router.destination(to);
        if matches!(
            destination,
            Destination::Server | Destination::ServerResource | Destination::Service
        ) || to.bare().as_str() == self.registration.account().as_str()
            || self
                .recipients
                .admit(to.bare().as_str(), crate::clock::now())
        {
            return Ok(true);
        }
        tracing::debug!(
            outcome = "rejected",
            reason = "recipient_rate",
            "stanza rejected"
        );
        Ok(false)
    }

    fn admit_routed(&mut self, routed: &RoutedStanza<A>) -> Result<bool, CloseOutcome> {
        let view = routed.resolve()?;
        if self.admit_recipient(&view)? {
            return Ok(true);
        }
        if !matches!(
            view.stanza_type(),
            StanzaType::Presence(
                PresenceType::Available | PresenceType::Unavailable | PresenceType::Probe
            )
        ) {
            self.reply_rejection_with_text(routed, StanzaErrorCondition::PolicyViolation, None,
                lonewolf_xmpp::stanza::StanzaErrorText::Static("Too many distinct recipients were contacted. Wait before contacting additional recipients."))?;
        }
        Ok(false)
    }

    fn stamp(&self, parsed: Parsed<Stanza, A>) -> Result<RoutedStanza<A>, CloseOutcome> {
        let (stanza, mut arena) = parsed.into_parts();
        let needs_to = stanza.resolve(&arena)?.to()?.is_none();
        let (stanza, _, _) = self.stamp_in(stanza, &mut arena, needs_to)?;
        Ok(RoutedStanza::from_parts(stanza, arena))
    }

    fn stamp_in(
        &self,
        stanza: Stanza,
        arena: &mut Arena<A>,
        needs_to: bool,
    ) -> Result<(Stanza, Jid, Option<Jid>), CloseOutcome> {
        let account = self.registration.account();
        let from = Jid::from_trusted_parts_in(
            Some(account.username()),
            account.domain(),
            Some(self.registration.resource()),
            arena,
        )?;
        let to = needs_to
            .then(|| {
                Jid::from_trusted_parts_in(Some(account.username()), account.domain(), None, arena)
            })
            .transpose()?;
        let mut builder = stanza.derive_in(arena)?.from(Some(from))?;
        if let Some(to) = to {
            builder = builder.to(Some(to))?;
        }
        Ok((builder.build()?, from, to))
    }
}

impl<A: ChunkAllocator + Clone, W: OutboxWriter<A>> Outbox<'_, A, W> {
    fn push(&mut self, output: Output<A>) {
        self.queue.push_back(output);
    }

    fn routed(&mut self, stanzas: impl IntoIterator<Item = RoutedStanza<A>>) {
        self.queue.extend(stanzas.into_iter().map(Output::Routed));
    }

    fn delivered(&mut self, entries: impl IntoIterator<Item = MailboxEntry<A>>) {
        self.queue
            .extend(entries.into_iter().map(Output::Delivered));
    }

    async fn drain_mailbox(
        &mut self,
        registration: &Registration<A>,
        first: MailboxEntry<A>,
    ) -> Result<(), CloseOutcome> {
        self.push(Output::Delivered(first));
        self.delivered(registration.take_queued());
        self.flush().await
    }

    /// Drain while work is pending to avoid evicting a client that keeps reading.
    /// Poll `until` first to leave deliveries after its cut in the mailbox.
    /// Local work must transfer or drop shared guards before it returns.
    async fn drain_until<F: Future>(
        &mut self,
        registration: &Registration<A>,
        until: F,
    ) -> Result<F::Output, CloseOutcome> {
        let mut until = pin!(until);
        loop {
            let event = {
                let receive = pin!(registration.recv());
                match select(until.as_mut(), receive).await {
                    Either::Left((output, _)) => Either::Left(output),
                    Either::Right((delivery, _)) => Either::Right(delivery),
                }
            };
            match event {
                Either::Left(output) => return Ok(output),
                Either::Right(Some(delivery)) => {
                    self.push(Output::Delivered(delivery));
                    self.delivered(registration.take_queued());
                    let mut flush = pin!(self.flush());
                    match select(until.as_mut(), flush.as_mut()).await {
                        Either::Left((output, flush)) => {
                            flush.await?;
                            return Ok(output);
                        }
                        Either::Right((flushed, _)) => flushed?,
                    }
                }
                Either::Right(None) => return Err(CloseOutcome::InternalError),
            }
        }
    }

    async fn flush(&mut self) -> Result<(), CloseOutcome> {
        let flushed = self.write_queue().await;
        if flushed.is_err() {
            // Failed writes may not have reached the client, so their copies stay stored.
            self.releases.clear();
        }
        flushed
    }

    #[expect(clippy::cognitive_complexity)]
    async fn write_queue(&mut self) -> Result<(), CloseOutcome> {
        if self.queue.is_empty() {
            return Ok(());
        }
        let mut offline_replay = false;
        let mut messages_written = 0usize;
        let mut messages_skipped = 0usize;
        let mut pending_count = 0usize;
        while let Some(output) = self.queue.pop_front() {
            match output {
                Output::Delivered(entry) => {
                    self.written = self.written.next();
                    self.writer.write(Outgoing::Routed(entry.stanza)).await?;
                    if let Some(release) = entry.release {
                        self.releases.push_back((
                            self.written,
                            Release::Message {
                                handler: release.handler,
                                sequence: release.sequence,
                            },
                        ));
                    }
                }
                Output::Routed(stanza) => {
                    self.written = self.written.next();
                    self.writer.write(Outgoing::Routed(stanza)).await?;
                }
                Output::Presence(delivery) => {
                    if self.liveness.is_alive() && delivery.is_current() {
                        self.written = self.written.next();
                        self.writer.write(Outgoing::Routed(delivery.stanza)).await?;
                    }
                }
                Output::Owned { stanza, arena } => {
                    self.written = self.written.next();
                    self.writer.write(Outgoing::Owned { stanza, arena }).await?;
                }
                Output::Requests {
                    mut page,
                    resource,
                    handler,
                    router,
                } => {
                    let kind = ReplayKind::SubscriptionRequest;
                    'pages: loop {
                        for (sender, bytes) in page.iter() {
                            if !self.liveness.is_alive() {
                                break 'pages;
                            }
                            let stanza = self
                                .parse_stored(bytes, StoredKind::Subscription(sender))
                                .await?;
                            self.written = self.written.next();
                            self.writer.write(Outgoing::Routed(stanza)).await?;
                            pending_count += 1;
                            self.metrics
                                .replay_records(kind, ReplayOutcome::Delivered, 1);
                        }
                        if page.is_complete() {
                            break;
                        }
                        let Some(after) = page.resume_after().cloned() else {
                            break;
                        };
                        let transaction = self.storage.begin_read().await.map_err(|error| {
                            close_storage_failure(error, "pending_replay_begin_read", &self.account)
                        })?;
                        if !self.liveness.is_alive() {
                            tracing::debug!(
                                operation = "replay",
                                outcome = "stale_session",
                                owner_jid = ?self.account.as_str(),
                                "pending replay stopped"
                            );
                            break;
                        }
                        page = handler
                            .pending_page(&self.account, &after, &transaction, page)
                            .await
                            .map_err(|error| {
                                report_handler_failure(&error, &self.account);
                                CloseOutcome::InternalError
                            })?;
                        self.metrics.replay_page_read(kind, page.byte_len());
                        policy::filter_pending(
                            &router,
                            &transaction,
                            &self.allocator,
                            (&self.account, Some(&resource)),
                            StanzaType::Presence(PresenceType::Available),
                            &mut page,
                        )
                        .await
                        .map_err(|_| CloseOutcome::InternalError)?;
                        drop(transaction);
                        self.metrics.replay_records(
                            kind,
                            ReplayOutcome::Blocked,
                            page.read_len() - page.len(),
                        );
                    }
                }
                Output::Offline {
                    backlog,
                    handler,
                    policy,
                } => {
                    offline_replay = true;
                    let counts = self.write_offline(backlog, handler, policy).await?;
                    messages_written += counts.written;
                    messages_skipped += counts.skipped;
                }
            }
        }
        self.writer.flush(self.written).await?;
        if pending_count != 0 {
            tracing::info!(
                operation = "replay",
                outcome = "flushed",
                pending_count,
                owner_jid = ?self.account.as_str(),
                "pending subscriptions flushed"
            );
        }
        if offline_replay {
            tracing::info!(
                operation = "replay",
                outcome = "flushed",
                messages_written,
                messages_skipped,
                owner_jid = ?self.account.as_str(),
                "offline replay flushed"
            );
        }
        self.release_through(self.written);
        Ok(())
    }

    fn release_through(&mut self, flushed: OutputSequence) {
        let mut backlog: Option<(Arc<dyn MessageHandler<A, RedbStorage>>, OfflineSequence)> = None;
        let mut messages = Vec::new();
        let mut message_handler = None;
        while let Some((sequence, _)) = self.releases.front() {
            if *sequence > flushed {
                break;
            }
            let Some((_, release)) = self.releases.pop_front() else {
                break;
            };
            match release {
                Release::Message { handler, sequence } => {
                    messages.push(sequence);
                    message_handler = Some(handler);
                }
                Release::BacklogMessages { handler, sequences } => {
                    self.release_replay_sequences(handler, sequences);
                }
                Release::Backlog { handler, through } => {
                    let through = backlog
                        .as_ref()
                        .map_or(through, |(_, previous)| (*previous).max(through));
                    backlog = Some((handler, through));
                }
            }
        }
        if let Some((handler, through)) = backlog {
            self.acknowledge(handler, through);
        }
        if let Some(handler) = message_handler {
            self.release_messages(handler, messages);
        }
    }

    fn release_messages(
        &mut self,
        handler: Arc<dyn MessageHandler<A, RedbStorage>>,
        sequences: Vec<OfflineSequence>,
    ) {
        let pending = if let Some(messages) = &self.messages {
            messages.pending.borrow_mut().extend(sequences);
            if !messages.task.is_finished() {
                return;
            }
            messages.pending.clone()
        } else {
            Rc::new(RefCell::new(sequences))
        };
        let batch = pending.clone();
        let storage = self.storage.clone();
        let account = self.account.clone();
        let liveness = self.liveness.clone();
        let task = compio::runtime::spawn(self.work.start().run(async move {
            if let Err(error) =
                acknowledge_messages(&storage, &account, &liveness, &*handler, &batch).await
            {
                report_handler_failure(&error, &account);
            }
        }));
        self.messages = Some(MessageRelease { pending, task });
    }

    fn acknowledge(
        &mut self,
        handler: Arc<dyn MessageHandler<A, RedbStorage>>,
        through: OfflineSequence,
    ) {
        if let Some(pending) = &self.acknowledgement {
            pending.through.set(pending.through.get().max(through));
            if !pending.task.is_finished() {
                return;
            }
        }
        let watermark = self
            .acknowledgement
            .take()
            .map_or_else(|| Rc::new(Cell::new(through)), |pending| pending.through);
        let through = watermark.clone();
        let storage = self.storage.clone();
        let account = self.account.clone();
        let liveness = self.liveness.clone();
        #[cfg(test)]
        let (report_entered, entered) = futures_channel::oneshot::channel();
        let task = compio::runtime::spawn(self.work.start().run(async move {
            #[cfg(test)]
            let _ = report_entered.send(());
            let result =
                acknowledge_backlog(&storage, &account, &liveness, &*handler, &through).await;
            if let Err(error) = result {
                report_handler_failure(&error, &account);
            }
        }));
        self.acknowledgement = Some(ReplayAcknowledgement {
            through: watermark,
            task,
            #[cfg(test)]
            entered,
        });
    }

    async fn parse_stored(
        &self,
        stanza_bytes: &[u8],
        kind: StoredKind<'_>,
    ) -> Result<RoutedStanza<A>, StoredRecordError> {
        let max_stanza_bytes =
            NonZeroUsize::new(stanza_bytes.len()).ok_or(StoredRecordError::InvalidContent)?;
        let input = tokio::io::AsyncReadExt::chain(STORED_STANZA_STREAM_HEADER, stanza_bytes);
        let mut parser = XmppParser::new(
            input,
            ParserConfig {
                max_stanza_bytes,
                arena: ArenaConfig::default(),
            },
            self.allocator.clone(),
        );
        if !matches!(
            parser.next_event().await?,
            Some(StreamEvent::StreamStart { .. })
        ) {
            return Err(StoredRecordError::InvalidContent);
        }
        let parsed = match parser.next_event().await? {
            Some(StreamEvent::Stanza(parsed)) => parsed,
            _ => return Err(StoredRecordError::InvalidContent),
        };
        let (stanza, arena) = parsed.into_parts();
        if matches!(kind, StoredKind::Message) {
            use tokio::io::AsyncBufReadExt;
            let mut remainder = parser.into_inner();
            loop {
                let bytes = remainder
                    .fill_buf()
                    .await
                    .map_err(|_| StoredRecordError::ReplayFailure)?;
                if bytes.is_empty() {
                    break;
                }
                if bytes
                    .iter()
                    .any(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
                {
                    return Err(StoredRecordError::InvalidContent);
                }
                let consumed = bytes.len();
                remainder.consume(consumed);
            }
        }
        {
            let stanza = stanza.resolve(&arena)?;
            let valid_kind = match kind {
                StoredKind::Subscription(sender) => {
                    stanza.stanza_type() == StanzaType::Presence(PresenceType::Subscribe)
                        && stanza
                            .from()?
                            .is_some_and(|from| from.as_str() == sender.as_str())
                        && stanza
                            .to()?
                            .is_some_and(|to| to.as_str() == self.account.as_str())
                }
                StoredKind::Message => {
                    matches!(
                        stanza.stanza_type(),
                        StanzaType::Message(MessageType::Normal | MessageType::Chat)
                    ) && stanza
                        .to()?
                        .is_some_and(|to| to.bare().as_str() == self.account.as_str())
                }
            };
            if stanza.namespace() != StanzaNamespace::Client || !valid_kind {
                return Err(StoredRecordError::InvalidContent);
            }
        }
        Ok(RoutedStanza::from_parts(stanza, arena))
    }
}

async fn acknowledge_messages<A: ChunkAllocator>(
    storage: &RedbStorage,
    account: &AccountKey,
    liveness: &SessionLiveness,
    handler: &dyn MessageHandler<A, RedbStorage>,
    pending: &RefCell<Vec<OfflineSequence>>,
) -> Result<(), HandlerError> {
    while !pending.borrow().is_empty() {
        let mut transaction =
            storage
                .begin_write()
                .await
                .map_err(|error| HandlerError::Internal {
                    condition: StanzaErrorCondition::InternalServerError,
                    failure: storage_failure(error, "offline_acknowledge_one_begin_write"),
                })?;
        // Check after writer admission so account recreation cannot reset these sequences.
        if !liveness.is_alive() {
            tracing::info!(
                operation = "acknowledge_one",
                outcome = "skipped_stale_session",
                recipient_jid = ?account.as_str(),
                "offline message acknowledgement handled"
            );
            return Ok(());
        }
        let batch = mem::take(&mut *pending.borrow_mut());
        for sequence in batch {
            handler
                .acknowledge_one(account, sequence, &mut transaction)
                .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| HandlerError::Internal {
                condition: StanzaErrorCondition::InternalServerError,
                failure: storage_failure(error, "offline_acknowledge_one_commit"),
            })?;
        tracing::info!(
            operation = "acknowledge_one",
            outcome = "committed",
            recipient_jid = ?account.as_str(),
            "offline message acknowledgement handled"
        );
    }
    Ok(())
}

async fn acknowledge_backlog<A: ChunkAllocator>(
    storage: &RedbStorage,
    account: &AccountKey,
    liveness: &SessionLiveness,
    handler: &dyn MessageHandler<A, RedbStorage>,
    watermark: &Cell<OfflineSequence>,
) -> Result<(), HandlerError> {
    loop {
        let mut transaction =
            storage
                .begin_write()
                .await
                .map_err(|error| HandlerError::Internal {
                    condition: StanzaErrorCondition::InternalServerError,
                    failure: storage_failure(error, "offline_acknowledge_replay_begin_write"),
                })?;
        // Check after writer admission so account recreation cannot reset these sequences.
        if !liveness.is_alive() {
            tracing::info!(
                operation = "acknowledge_replay",
                outcome = "skipped_stale_session",
                owner_jid = ?account.as_str(),
                "offline backlog acknowledgement handled"
            );
            return Ok(());
        }
        let through = watermark.get();
        handler
            .acknowledge(account, through, &mut transaction)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|error| HandlerError::Internal {
                condition: StanzaErrorCondition::InternalServerError,
                failure: storage_failure(error, "offline_acknowledge_replay_commit"),
            })?;
        tracing::info!(
            operation = "acknowledge_replay",
            outcome = "committed",
            owner_jid = ?account.as_str(),
            "offline backlog acknowledgement handled"
        );
        if watermark.get() <= through {
            return Ok(());
        }
    }
}

struct ServiceWork<A: ChunkAllocator> {
    router: RouterHandle<A>,
    storage: RedbStorage,
    allocator: A,
    work: WorkHandle,
    observer: Option<SessionHandle<A>>,
    archived: Option<lonewolf_extension::archive::ArchiveId>,
    stanza: RoutedStanza<A>,
    route: ServiceRoute<A>,
}

impl<A: ChunkAllocator + Clone + 'static> ServiceWork<A> {
    async fn run(self) -> Result<Option<Reply<A>>, crate::stages::StageFailure> {
        let stage = Stage {
            router: &self.router,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        };
        let observed = self.observer.map(|session| (session, self.stanza.clone()));
        let outcome = service::dispatch(&stage, &self.route, self.stanza).await?;
        if let Some((sender, observed)) = observed {
            let id = sender.session_id();
            let account = sender.account().clone();
            let delivery =
                RouterDelivery::with_session(stage.router, stage.allocator, Some(sender));
            let rejection = match &outcome {
                ServiceOutcome::Rejected {
                    stanza,
                    condition,
                    text,
                } => Some(ingress::rejection_reply(
                    stage.allocator,
                    stanza,
                    *condition,
                    None,
                    *text,
                )?),
                ServiceOutcome::Handled => None,
            };
            observe::message(
                &stage,
                &delivery,
                MessageEvent {
                    account: &account,
                    role: MessageRole::Sent,
                    stanza: &observed,
                    outcome: MessageOutcome::from(&outcome),
                    archived: self.archived,
                    holders: std::slice::from_ref(&id),
                    rejection: rejection.as_ref(),
                },
            )
            .await;
            return Ok(rejection.map(Reply::Built));
        }
        Ok(match outcome {
            ServiceOutcome::Rejected {
                stanza,
                condition,
                text,
            } => Some(Reply::Error {
                stanza,
                condition,
                application: None,
                text,
            }),
            ServiceOutcome::Handled => None,
        })
    }
}

struct DirectedServiceWork<A: ChunkAllocator> {
    session: SessionHandle<A>,
    liveness: SessionLiveness,
    policy_account: Option<AccountKey>,
    router: RouterHandle<A>,
    storage: RedbStorage,
    allocator: A,
    work: WorkHandle,
    lease: Arc<ServicePresenceLease>,
    completion: oneshot::Sender<()>,
    stanza: RoutedStanza<A>,
    route: ServiceRoute<A>,
}

enum DirectedServiceOutcome<A: ChunkAllocator> {
    Dispatched(ServiceOutcome<A>),
    Blocked,
}

impl<A: ChunkAllocator + Clone> DirectedServiceWork<A> {
    async fn run(self) -> Result<DirectedServiceOutcome<A>, RouterError> {
        if !self.liveness.is_alive() {
            return Ok(DirectedServiceOutcome::Dispatched(ServiceOutcome::Handled));
        }
        let view = self
            .stanza
            .resolve()
            .map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let available = view.stanza_type() == StanzaType::Presence(PresenceType::Available);
        let ordered = ingress::checks::fix_explicit_snapshot(
            &self.router,
            &self.storage,
            self.policy_account.as_ref(),
            None,
        )
        .await
        .map_err(|_| RouterError::Unavailable)?;
        let admission = if let Some((snapshot, mut ticket)) = ordered {
            let verdict = ingress::checks::check_selected(
                (&self.router, &self.storage),
                self.policy_account.as_ref(),
                None,
                &view,
                None,
                ingress::checks::Snapshot::Ordered(&snapshot),
                policy::Selection::Explicit,
            )
            .await
            .map_err(|_| RouterError::Unavailable)?;
            drop(snapshot);
            match verdict {
                Verdict::Allow => {
                    ticket.turn().await;
                    Some(ticket)
                }
                Verdict::OutboundBlocked => return Ok(DirectedServiceOutcome::Blocked),
                Verdict::Drop | Verdict::Reject { .. } => {
                    return Ok(DirectedServiceOutcome::Dispatched(ServiceOutcome::Handled));
                }
            }
        } else {
            None
        };
        if !self.liveness.is_alive() {
            return Ok(DirectedServiceOutcome::Dispatched(ServiceOutcome::Handled));
        }
        self.session.record_service_presence(to, available).await?;
        drop(admission);
        if !self.liveness.is_alive() {
            return Ok(DirectedServiceOutcome::Dispatched(ServiceOutcome::Handled));
        }
        let stage = Stage {
            router: &self.router,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        };
        let result = service::dispatch(&stage, &self.route, self.stanza)
            .await
            .map(DirectedServiceOutcome::Dispatched)
            .map_err(|_| RouterError::Unavailable);
        drop(self.lease);
        let _ = self.completion.send(());
        result
    }
}

async fn explicit_presence_policy<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    storage: &RedbStorage,
    registration: &Registration<A>,
    stanza: &RoutedStanza<A>,
) -> Result<(Verdict, Option<(RedbRead, Ticket)>), CloseOutcome> {
    let view = stanza.resolve()?;
    let to = view.to()?.ok_or(CloseOutcome::InternalError)?;
    let sender = Some(registration.account());
    let parties = ingress::checks::parties_for(router, sender, to, view.kind())?;
    let Some((snapshot, mut ticket)) =
        ingress::checks::fix_explicit_snapshot(router, storage, sender, parties.recipient.as_ref())
            .await?
    else {
        return Ok((Verdict::Allow, None));
    };
    let verdict = ingress::checks::check_selected(
        (router, storage),
        sender,
        parties.recipient.as_ref(),
        &view,
        None,
        ingress::checks::Snapshot::Ordered(&snapshot),
        policy::Selection::Explicit,
    )
    .await?;
    if verdict != Verdict::Allow {
        return Ok((verdict, None));
    }
    ticket.turn().await;
    Ok((verdict, Some((snapshot, ticket))))
}

fn presence_addresses<A: ChunkAllocator>(
    stanza: &RoutedStanza<A>,
) -> Result<(JidRef<'_>, JidRef<'_>), CloseOutcome> {
    let view = stanza.resolve()?;
    let sender = view.from()?.ok_or(CloseOutcome::InternalError)?;
    let target = view.to()?.ok_or(CloseOutcome::InternalError)?;
    Ok((sender, target))
}

async fn subscription_target<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    transaction: &RedbWrite,
    target: JidRef<'_>,
) -> Result<Option<ResourceMatch>, CloseOutcome> {
    let (Ok(account), Some(resource)) =
        (AccountKey::try_from(target.bare()), target.resourcepart())
    else {
        return Ok(None);
    };
    if transaction
        .account(&account)
        .await
        .map_err(|error| {
            if let AccountError::Storage(error) = error {
                report_failure(
                    storage_failure(error, "presence_subscription_account_read"),
                    &account,
                );
            }
            CloseOutcome::InternalError
        })?
        .is_none()
    {
        return Ok(None);
    }
    router
        .resource_match(&account, resource)
        .await
        .map_err(|_| CloseOutcome::InternalError)
}

#[cfg(test)]
mod preparation_tests;
#[cfg(test)]
mod service_tests;
#[cfg(test)]
mod tests;
