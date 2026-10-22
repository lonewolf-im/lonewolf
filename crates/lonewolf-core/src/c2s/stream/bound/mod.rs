// SPDX-License-Identifier: Apache-2.0

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::mem;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;
#[cfg(test)]
use std::time::SystemTime;

use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::{Either, Shared, join, select};
use lonewolf_extension::Effects;
use lonewolf_extension::delivery::{Failure, FailureKind, HandlerError};
use lonewolf_extension::discovery::Discovery;
use lonewolf_extension::iq::{
    IqDestinationRule, IqError, IqErrorPayload, IqHandler, IqReply, IqRequest, IqRequestType,
    IqScope, Requester, XmlSpace,
};
use lonewolf_extension::message::{Backlog, MessageHandler};
#[cfg(test)]
use lonewolf_extension::message::{StoreOutcome, UndeliverableMessage};
use lonewolf_extension::observer::{
    MessageEvent, MessageOutcome, MessageRole, SessionChange, SessionEvent,
};
use lonewolf_extension::policy::{Direction, Verdict};
use lonewolf_extension::presence::{
    PresenceAudience, PresenceRequest, PresenceRequestType, PresenceSend, PresenceTransition,
    PresenceUpdate,
};
use lonewolf_storage::account::{AccountError, AccountKey, AccountReads};
use lonewolf_storage::offline::OfflineSequence;
use lonewolf_storage::roster::{PendingSubscription, RosterJid};
use lonewolf_storage::{RedbRead, RedbStorage, RedbWrite, Storage, StorageError, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, ArenaRead, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{Jid, JidError, JidRef};
use lonewolf_xmpp::parser::{ParseError, Parsed, ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{
    ApplicationCondition, BuildError, CLIENT_NAMESPACE, Element, IqType, MessageType, PresenceType,
    RejectedStanza, Stanza, StanzaErrorCondition, StanzaNamespace, StanzaRef, StanzaType,
    XML_NAMESPACE,
};

use super::bind::Bound;
use super::outcome::CloseOutcome;
use super::recipient_rate::RecipientLimiter;
use super::session::{Session, Writer};
use crate::c2s::iq;
use crate::delivery::{
    EffectsDiagnostics, Pending, RouterDelivery, WorkGroup, WorkHandle, after_turn,
    commit_and_deliver, report_failure, report_handler_failure, storage_failure,
};
use crate::order::Ticket;
use crate::router::local::{DirectedWithdrawal, PresenceChange, SessionLiveness};
use crate::router::{
    Destination, MailboxEntry, Registration, ResourceMatch, RoutedStanza, RouterError,
    RouterHandle, ServiceRoute, SessionHandle,
};

use crate::stages::message::{self, DeliveryOutcome};
use crate::stages::service::{self, ServiceOutcome, ServicePresenceLease};
use crate::stages::{Stage, archive, observe, policy};

mod link;
mod output;
mod transport;

use link::{Incoming, LinkWriter};
use output::{Outgoing, OutputSequence, Release};
use transport::Transport;

const STORED_STANZA_STREAM_HEADER: &[u8] =
    b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>";

struct BoundSession<'w, A: ChunkAllocator, W = Writer> {
    registration: Registration<A>,
    router: RouterHandle<A>,
    storage: RedbStorage,
    allocator: A,
    work: WorkHandle,
    service_presence: Option<Arc<ServicePresenceLease>>,
    service_pending: Option<Shared<oneshot::Receiver<()>>>,
    recipients: RecipientLimiter,
    available: bool,
    priority: Option<i8>,
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
    messages: Option<MessageRelease>,
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
    Owned {
        stanza: Stanza,
        arena: Arena<A>,
    },
    /// Requests stay unparsed to bound backlog memory.
    Requests(Vec<PendingSubscription>),
    Offline {
        backlog: Backlog,
        handler: Arc<dyn MessageHandler<A, RedbStorage>>,
    },
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
) -> CloseOutcome {
    let Bound {
        session: Session {
            reader,
            writer,
            close,
        },
        monitor,
        registration,
        router,
        storage,
        allocator,
        resource_requested: _,
    } = bound;
    let (link, incoming, transport_link) = link::link();
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
                messages: None,
                work: &*work,
            };
            let mut session = BoundSession {
                registration,
                router,
                storage,
                allocator,
                work: work.handle(),
                service_presence: None,
                service_pending: None,
                recipients,
                available: false,
                priority: None,
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
                messages,
                ..
            } = outbox;
            work.drain().await;
            drop((acknowledgement, messages));
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
        let work = TerminalPresenceWork {
            session: self.registration.handle(),
            router: self.router.clone(),
            storage: self.storage.clone(),
            allocator: self.allocator.clone(),
            work: self.work.clone(),
            service_presence: self.service_presence.take(),
            service_pending: self.service_pending.take(),
            account: self.registration.account().clone(),
            fallback: self.unavailable_notice()?,
        };
        Pending::spawn(self.outbox.work.start(), work.run())
            .finished()
            .await
            .ok_or(CloseOutcome::InternalError)??;
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
        let service = stanza
            .to()?
            .and_then(|to| self.router.service(to.domainpart()).cloned());
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
        let verdict = {
            let view = routed.resolve()?;
            let peer = view.to()?.ok_or(CloseOutcome::InternalError)?;
            let checks = [policy::Check {
                account: self.registration.account(),
                direction: Direction::Outbound,
                peer,
            }];
            let stage = Stage {
                router: &self.router,
                storage: &self.storage,
                allocator: &self.allocator,
                work: &self.work,
            };
            self.outbox
                .drain_until(
                    &self.registration,
                    policy::evaluate(&stage, view.stanza_type(), &checks),
                )
                .await??
        };
        match verdict {
            Verdict::Allow => {}
            Verdict::Reject {
                condition,
                application,
                text,
            } => {
                return self.reply_rejection_with_text(
                    &routed,
                    condition,
                    application,
                    text.unwrap_or_else(|| condition.default_text()),
                );
            }
            Verdict::Drop => return Ok(()),
        }
        let mut sent = None;
        let is_message = matches!(routed.resolve()?.stanza_type(), StanzaType::Message(_));
        let routed = if is_message
            && self
                .router
                .archive_handler(self.registration.account().domain())
                .is_some()
        {
            let stage = Stage {
                router: &self.router,
                storage: &self.storage,
                allocator: &self.allocator,
                work: &self.work,
            };
            match self
                .outbox
                .drain_until(
                    &self.registration,
                    archive::archive(&stage, routed, Some(self.registration.account()), None),
                )
                .await??
            {
                archive::ArchiveStep::Accepted(archived) => {
                    sent = archived.sent;
                    archived.stanza
                }
                archive::ArchiveStep::Rejected {
                    stanza,
                    condition,
                    text,
                } => {
                    return self.reply_rejection_with_text(&stanza, condition, None, text);
                }
            }
        } else {
            routed
        };
        let observed = if is_message
            && !self
                .router
                .message_observers(self.registration.account().domain())
                .is_empty()
        {
            Some(routed.clone())
        } else {
            None
        };
        let presence = {
            let view = routed.resolve()?;
            matches!(
                view.stanza_type(),
                StanzaType::Presence(PresenceType::Available | PresenceType::Unavailable)
            )
        };
        let outcome = if presence {
            if self.service_presence.is_none() {
                let from = routed
                    .resolve()?
                    .from()?
                    .ok_or(CloseOutcome::InternalError)?;
                let gate = self
                    .router
                    .service_presence_gate(from.as_str())
                    .ok_or(CloseOutcome::InternalError)?;
                let lease = self
                    .outbox
                    .drain_until(&self.registration, gate.acquire())
                    .await?;
                self.service_presence = Some(Arc::new(lease));
            }
            let (completion, completed) = oneshot::channel();
            self.service_pending = Some(completed.shared());
            let work = DirectedServiceWork {
                session: self.registration.handle(),
                router: self.router.clone(),
                storage: self.storage.clone(),
                allocator: self.allocator.clone(),
                work: self.work.clone(),
                lease: self
                    .service_presence
                    .as_ref()
                    .cloned()
                    .ok_or(CloseOutcome::InternalError)?,
                completion,
                stanza: routed.clone(),
                route,
            };
            let pending = Pending::spawn(self.work.start(), work.run());
            match self
                .outbox
                .drain_until(&self.registration, pending.finished())
                .await?
                .ok_or(CloseOutcome::InternalError)?
            {
                Ok(outcome) => outcome,
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
            }
        } else {
            let stage = Stage {
                router: &self.router,
                storage: &self.storage,
                allocator: &self.allocator,
                work: &self.work,
            };
            self.outbox
                .drain_until(
                    &self.registration,
                    service::dispatch(&stage, &route, routed),
                )
                .await??
        };
        if let Some(observed) = observed {
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
                    observe::message(
                        &stage,
                        &delivery,
                        MessageEvent {
                            account: self.registration.account(),
                            role: MessageRole::Sent,
                            stanza: &observed,
                            outcome: MessageOutcome::from(&outcome),
                            archived: sent,
                        },
                    ),
                )
                .await?;
        }
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
            self.iq_destination_error(&stanza)?
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

    fn iq_destination_error(
        &self,
        stanza: &StanzaRef<'_, Arena<A>>,
    ) -> Result<Option<IqError>, CloseOutcome> {
        let kind = match stanza.stanza_type() {
            StanzaType::Iq(IqType::Get) => IqRequestType::Get,
            StanzaType::Iq(IqType::Set) => IqRequestType::Set,
            _ => return Ok(None),
        };
        let payload = stanza
            .children()?
            .next()
            .transpose()?
            .ok_or(CloseOutcome::InternalError)?;
        let source_domain = self.registration.account().domain();
        let target = stanza.to()?;
        let target_domain = target.map_or(source_domain, |to| to.domainpart());
        let mut rejected = false;
        for domain in [
            Some(source_domain),
            (target_domain != source_domain).then_some(target_domain),
        ]
        .into_iter()
        .flatten()
        {
            let rule = self.router.iq_handlers(domain).and_then(|registry| {
                registry.destination_rule(kind, payload.namespace(), payload.name())
            });
            rejected |= match rule {
                Some(IqDestinationRule::SenderBare) => {
                    target.is_some_and(|to| to.as_str() != self.registration.account().as_str())
                }
                None => false,
            };
        }
        Ok(rejected.then(|| IqError::without_payload(HandlerError::described(StanzaErrorCondition::Forbidden,
            lonewolf_xmpp::stanza::StanzaErrorText::Static("This operation requires an omitted destination or your authenticated bare JID without a resource.")))))
    }

    /// Committed handler effects outlive this session.
    async fn handle_iq(&mut self, parsed: Parsed<Stanza, A>) -> Result<(), CloseOutcome> {
        let (request, mut arena) = parsed.into_parts();
        let route = iq::route(&request, &mut arena, &self.registration, &self.router)?;
        let verdict = {
            let view = request.resolve(&arena)?;
            match view.to()? {
                Some(to)
                    if matches!(
                        route.destination,
                        Destination::Resource | Destination::Account
                    ) && to.bare().as_str() != self.registration.account().as_str()
                        && (!self
                            .router
                            .policies(self.registration.account().domain())
                            .is_empty()
                            || !self.router.policies(to.domainpart()).is_empty()) =>
                {
                    let recipient = AccountKey::try_from(to.bare())?;
                    let checks = [
                        policy::Check {
                            account: self.registration.account(),
                            direction: Direction::Outbound,
                            peer: to,
                        },
                        policy::Check {
                            account: &recipient,
                            direction: Direction::Inbound,
                            peer: route.sender.resolve(&arena)?,
                        },
                    ];
                    let stage = Stage {
                        router: &self.router,
                        storage: &self.storage,
                        allocator: &self.allocator,
                        work: &self.work,
                    };
                    self.outbox
                        .drain_until(
                            &self.registration,
                            policy::evaluate(&stage, view.stanza_type(), &checks),
                        )
                        .await??
                }
                _ => Verdict::Allow,
            }
        };
        match verdict {
            Verdict::Allow => {}
            Verdict::Reject {
                condition,
                application,
                text,
            } => {
                let reply = request
                    .error_reply_described_in(
                        &mut arena,
                        condition,
                        application,
                        text.unwrap_or_else(|| condition.default_text()),
                    )?
                    .to(None)?
                    .build()?;
                self.outbox.push(Output::Owned {
                    stanza: reply,
                    arena,
                });
                return Ok(());
            }
            Verdict::Drop => return Ok(()),
        }
        if matches!(
            route.destination,
            Destination::Resource | Destination::ServerResource
        ) {
            let routed = request
                .derive_in(&mut arena)?
                .from(Some(route.sender))?
                .build()?;
            return self
                .route_resource_iq(RoutedStanza::from_parts(routed, arena), route.kind)
                .await;
        }
        let Some(kind) = route.request_type() else {
            if route.destination == Destination::Server {
                let id = request
                    .resolve(&arena)?
                    .id()?
                    .filter(|id| id.starts_with(crate::router::iq_requests::ID_PREFIX))
                    .map(Box::<str>::from);
                if let Some(id) = id {
                    let routed = request
                        .derive_in(&mut arena)?
                        .from(Some(route.sender))?
                        .build()?;
                    let sender_text = Box::<str>::from(route.sender.resolve(&arena)?.as_str());
                    self.router.iq_requests().complete(
                        &id,
                        &sender_text,
                        RoutedStanza::from_parts(routed, arena),
                    );
                }
            }
            return Ok(());
        };
        let response = Arena::try_new_in(Default::default(), self.allocator.clone())?;
        let (handler, target_account) = {
            let sender = route.sender.resolve(&arena)?;
            let stanza = request.resolve(&arena)?;
            let target = stanza.to()?.unwrap_or_else(|| sender.bare());
            let payload = stanza
                .children()?
                .next()
                .transpose()?
                .ok_or(CloseOutcome::InternalError)?;
            let scope = match route.destination {
                Destination::Account => Some(IqScope::Account),
                Destination::Server => Some(IqScope::Server),
                Destination::Resource
                | Destination::ServerResource
                | Destination::Service
                | Destination::Remote => None,
            };
            let handler = scope.and_then(|scope| {
                self.router.iq_handlers(target.domainpart())?.find(
                    scope,
                    kind,
                    payload.namespace(),
                    payload.name(),
                )
            });
            let target_account = match scope {
                Some(IqScope::Account) => Some(AccountKey::try_from(target.bare())?),
                Some(IqScope::Server) | None => None,
            };
            (handler.map(Arc::clone), target_account)
        };
        let Some(handler) = handler else {
            let condition = if route.destination == Destination::Remote {
                StanzaErrorCondition::RemoteServerNotFound
            } else {
                StanzaErrorCondition::ServiceUnavailable
            };
            let reply = iq::error_reply(&request, &mut arena, condition, None)?;
            self.outbox.push(Output::Owned {
                stanza: reply,
                arena,
            });
            return Ok(());
        };
        match kind {
            IqRequestType::Get => {
                self.handle_iq_get(
                    request,
                    route.sender,
                    arena,
                    response,
                    handler,
                    target_account,
                )
                .await
            }
            IqRequestType::Set => {
                self.handle_iq_set(
                    request,
                    route.sender,
                    arena,
                    response,
                    handler,
                    target_account,
                )
                .await
            }
        }
    }

    async fn route_resource_iq(
        &mut self,
        routed: RoutedStanza<A>,
        kind: IqType,
    ) -> Result<(), CloseOutcome> {
        let target = {
            let to = routed.resolve()?.to()?.ok_or(CloseOutcome::InternalError)?;
            if to.localpart().is_none() {
                return if matches!(kind, IqType::Get | IqType::Set) {
                    self.reply_error(&routed, StanzaErrorCondition::ServiceUnavailable)
                } else {
                    Ok(())
                };
            }
            AccountKey::try_from(to.bare())?
        };
        let request = matches!(kind, IqType::Get | IqType::Set);
        let work = ResourceIqWork {
            source: self.registration.account().clone(),
            liveness: self.registration.liveness(),
            router: self.router.clone(),
            storage: self.storage.clone(),
            target,
            request,
            stanza: routed.clone(),
        };
        let pending = Pending::spawn(self.outbox.work.start(), work.run());
        let result = self
            .outbox
            .drain_until(&self.registration, pending.finished())
            .await?
            .ok_or(CloseOutcome::InternalError)?;
        match result {
            Ok(()) => Ok(()),
            Err(error) if !request => {
                tracing::debug!(stanza_kind = "iq", outcome = ?error, "IQ response delivery failed");
                Ok(())
            }
            Err(RouterError::Busy | RouterError::ResourceLimit) => {
                self.reply_error(&routed, StanzaErrorCondition::ResourceConstraint)
            }
            Err(RouterError::Unavailable | RouterError::Stopped) => {
                Err(CloseOutcome::InternalError)
            }
            Err(_) => self.reply_error(&routed, StanzaErrorCondition::ServiceUnavailable),
        }
    }

    async fn handle_iq_get(
        &mut self,
        request: Stanza,
        sender: Jid,
        arena: Arena<A>,
        response: Arena<A>,
        handler: Arc<dyn IqHandler<A, RedbStorage>>,
        target_account: Option<AccountKey>,
    ) -> Result<(), CloseOutcome> {
        let registration = &self.registration;
        let storage = &self.storage;
        let router = &self.router;
        let work_group = self.outbox.work;
        let delivery = self.delivery();
        let discovery = {
            let sender = sender.resolve(&arena)?;
            let stanza = request.resolve(&arena)?;
            let target = stanza.to()?.unwrap_or_else(|| sender.bare());
            Arc::clone(
                router
                    .discovery(target.domainpart())
                    .ok_or(CloseOutcome::InternalError)?,
            )
        };
        let prepare = async {
            let (transaction, ticket) = Arc::clone(router.order())
                .fix(
                    target_account.iter().cloned().collect(),
                    storage.begin_read(),
                )
                .await
                .map_err(|error| {
                    close_storage_failure(error, "iq_get_begin_read", registration.account())
                })?;
            let work = GetWork {
                account: registration.account().clone(),
                target_account,
                transaction,
                handler,
                discovery,
                arena,
                request,
                sender,
                response,
                delivery,
            };
            Ok::<_, CloseOutcome>(after_turn(
                work_group.start(),
                ticket,
                Some(registration.mailbox()),
                move |queued, ticket| async move {
                    let result = work.run(queued).await;
                    drop(ticket);
                    result
                },
            ))
        };
        let mut pending = self.outbox.drain_until(registration, prepare).await??;
        self.outbox
            .drain_until(&self.registration, pending.turned())
            .await?;
        let outcome = pending
            .finished()
            .await
            .ok_or(CloseOutcome::InternalError)??;
        self.outbox.delivered(outcome.queued);
        self.queue_iq_reply(
            request,
            sender,
            outcome.arena,
            outcome.response,
            outcome.reply,
            outcome.results,
        )
    }

    async fn handle_iq_set(
        &mut self,
        request: Stanza,
        sender: Jid,
        arena: Arena<A>,
        mut response: Arena<A>,
        handler: Arc<dyn IqHandler<A, RedbStorage>>,
        target_account: Option<AccountKey>,
    ) -> Result<(), CloseOutcome> {
        let registration = &self.registration;
        let storage = &self.storage;
        let router = &self.router;
        let work = self.outbox.work;
        let delivery = self.delivery();
        let discovery = {
            let sender = sender.resolve(&arena)?;
            let stanza = request.resolve(&arena)?;
            let target = stanza.to()?.unwrap_or_else(|| sender.bare());
            Arc::clone(
                router
                    .discovery(target.domainpart())
                    .ok_or(CloseOutcome::InternalError)?,
            )
        };
        let prepare = async {
            let mut transaction = storage.begin_write().await.map_err(|error| {
                close_storage_failure(error, "iq_set_begin_write", registration.account())
            })?;
            let reply = match require_iq_account(&transaction, target_account.as_ref()).await {
                Err(error) => Err(error.into()),
                Ok(()) => {
                    let sender = sender.resolve(&arena)?;
                    let stanza = request.resolve(&arena)?;
                    let target = stanza.to()?.unwrap_or_else(|| sender.bare());
                    let payload = stanza
                        .children()?
                        .next()
                        .transpose()?
                        .ok_or(CloseOutcome::InternalError)?;
                    handler
                        .set(
                            IqRequest {
                                sender,
                                target,
                                discovery: &discovery,
                                sessions: &delivery,
                                requester: None,
                                lang: stanza.lang()?,
                                space: stanza
                                    .attribute("space", XML_NAMESPACE)?
                                    .map(XmlSpace::from_attribute),
                                payload,
                            },
                            &mut transaction,
                            &delivery,
                            &mut response,
                        )
                        .await
                }
            };
            Ok::<_, CloseOutcome>(match reply {
                Ok(IqReply {
                    payload,
                    effects,
                    results,
                }) => Ok((
                    payload,
                    results,
                    commit_and_deliver(
                        work.start(),
                        Arc::clone(router.order()),
                        transaction,
                        effects,
                        delivery,
                        Some(registration.mailbox()),
                        EffectsDiagnostics {
                            account: registration.account().clone(),
                            commit_operation: "iq_set_commit",
                            delivery_operation: "iq_set_effects",
                        },
                    ),
                )),
                Err(error) => {
                    drop(transaction);
                    report_handler_failure(error.handler_error(), registration.account());
                    Err(error)
                }
            })
        };
        let prepared = self.outbox.drain_until(registration, prepare).await??;
        let (reply, results) = match prepared {
            Ok((payload, results, mut committed)) => {
                self.outbox
                    .drain_until(registration, committed.turned())
                    .await?;
                let queued = committed
                    .finished()
                    .await
                    .ok_or(CloseOutcome::InternalError)?
                    .map_err(|_| CloseOutcome::InternalError)?;
                self.outbox.delivered(queued);
                (Ok(payload), results)
            }
            Err(error) => (Err(error), Vec::new()),
        };
        self.queue_iq_reply(request, sender, arena, response, reply, results)
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
        mut arena: Arena<A>,
        mut response: Arena<A>,
        reply: Result<Option<Element>, IqError>,
        mut results: Vec<Stanza>,
    ) -> Result<(), CloseOutcome> {
        match reply {
            Err(error) => self.queue_iq_error(request, sender, arena, error)?,
            Ok(payload) => {
                let sender_ref = sender.resolve(&arena)?;
                for result in &results {
                    if result.resolve(&response)?.to()?.map(|to| to.as_str())
                        != Some(sender_ref.as_str())
                    {
                        tracing::error!(
                            account_jid = ?self.registration.account().as_str(),
                            operation = "iq_results",
                            outcome = "misaddressed",
                            "internal operation failed"
                        );
                        let reply = iq::error_reply(
                            &request,
                            &mut arena,
                            StanzaErrorCondition::InternalServerError,
                            Some(sender),
                        )?;
                        self.outbox.push(Output::Owned {
                            stanza: reply,
                            arena,
                        });
                        return Ok(());
                    }
                }
                let reply = {
                    let sender = sender.resolve(&arena)?;
                    let stanza = request.resolve(&arena)?;
                    iq::result_reply(&stanza, sender, payload, &mut response)?
                };
                if results.is_empty() {
                    self.outbox.push(Output::Owned {
                        stanza: reply,
                        arena: response,
                    });
                } else {
                    results.push(reply);
                    self.outbox
                        .routed(RoutedStanza::from_parts_shared(results, response));
                }
            }
        }
        Ok(())
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
                    match self.router.route_presence_error(routed).await {
                        Ok(())
                        | Err(
                            RouterError::NotFound
                            | RouterError::Busy
                            | RouterError::InvalidTarget
                            | RouterError::RemoteUnsupported,
                        ) => Ok(()),
                        Err(_) => Err(CloseOutcome::InternalError),
                    }
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

    async fn handle_probe(&mut self, parsed: Parsed<Stanza, A>) -> Result<(), CloseOutcome> {
        let routed = self.stamp(parsed)?;
        if !self.admit_routed(&routed)? {
            return Ok(());
        }
        let target = {
            let view = routed.resolve()?;
            let to = view.to()?.ok_or(CloseOutcome::InternalError)?;
            match self.router.destination(to) {
                Destination::Account | Destination::Resource => {}
                Destination::Remote => {
                    return self.reply_error(&routed, StanzaErrorCondition::RemoteServerNotFound);
                }
                _ => return Ok(()),
            }
            AccountKey::try_from(to.bare()).map_err(|_| CloseOutcome::InternalError)?
        };
        let session = self.registration.handle();
        let router = self.router.clone();
        let storage = self.storage.clone();
        let account = self.registration.account().clone();
        let pending = Pending::spawn(self.outbox.work.start(), async move {
            let mut accounts = vec![account];
            if accounts[0] != target {
                accounts.push(target.clone());
            }
            let (transaction, mut ticket) = router
                .order()
                .fix(accounts, storage.begin_read())
                .await
                .map_err(|error| {
                    report_failure(storage_failure(error, "presence_probe_begin_read"), &target);
                    RouterError::Unavailable
                })?;
            let observer = routed
                .resolve()
                .map_err(|_| RouterError::InvalidTarget)?
                .from()
                .map_err(|_| RouterError::InvalidTarget)?
                .ok_or(RouterError::InvalidTarget)?;
            let subscribed = match router
                .presence_handlers(target.domain())
                .and_then(|handlers| handlers.find(PresenceRequestType::Probe))
            {
                Some(handler) => handler
                    .visibility(&target, observer, &transaction)
                    .await
                    .map_err(|error| {
                        report_handler_failure(&error, &target);
                        RouterError::Unavailable
                    })?,
                None => false,
            };
            if observer.bare().as_str() != target.as_str()
                && (!router.policies(observer.domainpart()).is_empty()
                    || !router.policies(target.domain()).is_empty())
            {
                let prober = AccountKey::try_from(observer.bare())
                    .map_err(|_| RouterError::InvalidTarget)?;
                let peer = routed
                    .resolve()
                    .map_err(|_| RouterError::InvalidTarget)?
                    .to()
                    .map_err(|_| RouterError::InvalidTarget)?
                    .ok_or(RouterError::InvalidTarget)?;
                let checks = [
                    policy::Check {
                        account: &prober,
                        direction: Direction::Outbound,
                        peer,
                    },
                    policy::Check {
                        account: &target,
                        direction: Direction::Inbound,
                        peer: observer,
                    },
                ];
                if policy::evaluate_in(
                    &router,
                    &transaction,
                    StanzaType::Presence(PresenceType::Probe),
                    &checks,
                )
                .await
                .map_err(|_| RouterError::Unavailable)?
                    != Verdict::Allow
                {
                    return Ok(());
                }
            }
            ticket.turn().await;
            router.probe_presence(&session, &routed, subscribed).await
        });
        self.outbox
            .drain_until(&self.registration, pending.finished())
            .await?
            .ok_or(CloseOutcome::InternalError)?
            .map_err(|_| CloseOutcome::InternalError)
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
        let target = {
            let view = routed.resolve()?;
            let to = view.to()?.ok_or(CloseOutcome::InternalError)?;
            match self.router.destination(to) {
                Destination::Account | Destination::Resource => {}
                Destination::Remote => {
                    return self.reply_error(&routed, StanzaErrorCondition::RemoteServerNotFound);
                }
                _ => return Ok(()),
            }
            AccountKey::try_from(to.bare()).map_err(|_| CloseOutcome::InternalError)?
        };
        if &target != self.registration.account() {
            let stage = Stage {
                router: &self.router,
                storage: &self.storage,
                allocator: &self.allocator,
                work: &self.work,
            };
            let view = routed.resolve()?;
            let checks = [
                policy::Check {
                    account: self.registration.account(),
                    direction: Direction::Outbound,
                    peer: view.to()?.ok_or(CloseOutcome::InternalError)?,
                },
                policy::Check {
                    account: &target,
                    direction: Direction::Inbound,
                    peer: view.from()?.ok_or(CloseOutcome::InternalError)?,
                },
            ];
            if self
                .outbox
                .drain_until(
                    &self.registration,
                    policy::evaluate(&stage, view.stanza_type(), &checks),
                )
                .await??
                != Verdict::Allow
            {
                return Ok(());
            }
        }
        let session = self.registration.handle();
        let router = self.router.clone();
        let account = self.registration.account().clone();
        let directed = routed.clone();
        let pending = Pending::spawn(self.outbox.work.start(), async move {
            let mut accounts = vec![account];
            if accounts[0] != target {
                accounts.push(target);
            }
            let ((), mut ticket) = router
                .order()
                .fix(accounts, async { Ok::<_, RouterError>(()) })
                .await?;
            ticket.turn().await;
            session.directed_presence(directed, available).await
        });
        let result = self
            .outbox
            .drain_until(&self.registration, pending.finished())
            .await?
            .ok_or(CloseOutcome::InternalError)?;
        match result {
            Ok(()) => Ok(()),
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
        let stage = Stage {
            router: &self.router,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        };
        let verdict = {
            let view = routed.resolve()?;
            let to = view.to()?.ok_or(CloseOutcome::InternalError)?;
            let from = view.from()?.ok_or(CloseOutcome::InternalError)?;
            let sender = self.registration.account();
            let local_recipient = matches!(
                self.router.destination(to),
                Destination::Account | Destination::Resource
            );
            if to.bare().as_str() == sender.as_str()
                || (self.router.policies(sender.domain()).is_empty()
                    && (!local_recipient || self.router.policies(to.domainpart()).is_empty()))
            {
                Verdict::Allow
            } else {
                let recipient = if local_recipient {
                    Some(AccountKey::try_from(to.bare())?)
                } else {
                    None
                };
                let checks = [
                    policy::Check {
                        account: sender,
                        direction: Direction::Outbound,
                        peer: to,
                    },
                    policy::Check {
                        account: recipient.as_ref().unwrap_or(sender),
                        direction: Direction::Inbound,
                        peer: from,
                    },
                ];
                let checks = &checks[..if recipient.is_some() { 2 } else { 1 }];
                self.outbox
                    .drain_until(
                        &self.registration,
                        policy::evaluate(&stage, view.stanza_type(), checks),
                    )
                    .await??
            }
        };
        match verdict {
            Verdict::Allow => {}
            Verdict::Reject {
                condition,
                application,
                text,
            } => {
                return self.reply_rejection_with_text(
                    &routed,
                    condition,
                    application,
                    text.unwrap_or_else(|| condition.default_text()),
                );
            }
            Verdict::Drop => return Ok(()),
        }
        let archived = {
            let view = routed.resolve()?;
            let to = view.to()?.ok_or(CloseOutcome::InternalError)?;
            let local_recipient = matches!(
                self.router.destination(to),
                Destination::Account | Destination::Resource
            );
            let archive_needed = self
                .router
                .archive_handler(self.registration.account().domain())
                .is_some()
                || (local_recipient && self.router.archive_handler(to.domainpart()).is_some());
            if archive_needed {
                let recipient = if local_recipient {
                    Some(AccountKey::try_from(to.bare())?)
                } else {
                    None
                };
                self.outbox
                    .drain_until(
                        &self.registration,
                        archive::archive(
                            &stage,
                            routed,
                            Some(self.registration.account()),
                            recipient.as_ref(),
                        ),
                    )
                    .await??
            } else {
                archive::ArchiveStep::Accepted(archive::Archived {
                    stanza: routed,
                    sent: None,
                    received: None,
                })
            }
        };
        let archive::Archived {
            stanza: routed,
            sent,
            received,
        } = match archived {
            archive::ArchiveStep::Accepted(archived) => archived,
            archive::ArchiveStep::Rejected {
                stanza,
                condition,
                text,
            } => {
                return self.reply_rejection_with_text(&stanza, condition, None, text);
            }
        };
        let observed = {
            let view = routed.resolve()?;
            let to = view.to()?.ok_or(CloseOutcome::InternalError)?;
            let local_recipient = matches!(
                self.router.destination(to),
                Destination::Account | Destination::Resource
            );
            if !self
                .router
                .message_observers(self.registration.account().domain())
                .is_empty()
                || (local_recipient && !self.router.message_observers(to.domainpart()).is_empty())
            {
                let recipient = if local_recipient {
                    Some(AccountKey::try_from(to.bare())?)
                } else {
                    None
                };
                Some((routed.clone(), recipient))
            } else {
                None
            }
        };
        let outcome = self
            .outbox
            .drain_until(&self.registration, message::deliver(&stage, routed, kind))
            .await??;
        if let Some((observed, recipient)) = observed {
            let delivery = self.delivery();
            self.outbox
                .drain_until(&self.registration, async {
                    let outcome = MessageOutcome::from(&outcome);
                    observe::message(
                        &stage,
                        &delivery,
                        MessageEvent {
                            account: self.registration.account(),
                            role: MessageRole::Sent,
                            stanza: &observed,
                            outcome,
                            archived: sent,
                        },
                    )
                    .await;
                    if matches!(outcome, MessageOutcome::Routed | MessageOutcome::Stored)
                        && let Some(recipient) = recipient.as_ref()
                    {
                        observe::message(
                            &stage,
                            &delivery,
                            MessageEvent {
                                account: recipient,
                                role: MessageRole::Received,
                                stanza: &observed,
                                outcome,
                                archived: received,
                            },
                        )
                        .await;
                    }
                })
                .await?;
        }
        match outcome {
            DeliveryOutcome::Rejected {
                stanza,
                condition,
                text,
            } => self.reply_rejection_with_text(&stanza, condition, None, text),
            DeliveryOutcome::Routed | DeliveryOutcome::Stored | DeliveryOutcome::Discarded => {
                Ok(())
            }
        }
    }

    async fn handle_availability(
        &mut self,
        parsed: Parsed<Stanza, A>,
        available: bool,
    ) -> Result<(), CloseOutcome> {
        let completion = self.service_presence.as_ref().map(|_| {
            let (completion, completed) = oneshot::channel();
            self.service_pending = Some(completed.shared());
            completion
        });
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
        let (mut stamped, from, to) = self.stamp_in(source, &mut arena, true)?;
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
        let (kind, transition) = match (available, self.available) {
            (true, false) => (PresenceRequestType::Available, PresenceTransition::Initial),
            (true, true) => (PresenceRequestType::Available, PresenceTransition::Update),
            (false, _) => (
                PresenceRequestType::Unavailable,
                PresenceTransition::Unavailable,
            ),
        };
        let candidate = priority.is_some_and(|priority| priority >= 0)
            && self.priority.is_none_or(|priority| priority < 0);
        let presence_handler = self
            .router
            .presence_handlers(self.registration.account().domain())
            .and_then(|handlers| handlers.find(kind));
        let message_handler = self
            .router
            .message_handler(self.registration.account().domain())
            .cloned();
        let decorations = self
            .router
            .presence_decorations(self.registration.account().domain());
        let decorate = available && !decorations.is_empty();
        let registration = &self.registration;
        let router = &self.router;
        let storage = &self.storage;
        let work_group = self.outbox.work;
        let prepare = async {
            let (result, ticket) = if presence_handler.is_some()
                || (candidate && message_handler.is_some())
                || decorate
            {
                let owner = registration.account();
                let (transaction, ticket) = Arc::clone(router.order())
                    .fix(vec![owner.clone()], storage.begin_read())
                    .await
                    .map_err(|error| {
                        close_storage_failure(error, "presence_snapshot_begin_read", owner)
                    })?;
                let sender = from.resolve(&arena)?;
                let mut result = async {
                    let audience = match presence_handler {
                        Some(handler) => {
                            handler
                                .audience(PresenceUpdate { sender, transition }, &transaction)
                                .await?
                        }
                        None => None,
                    };
                    let backlog = match message_handler.as_ref().filter(|_| candidate) {
                        Some(handler) => handler.backlog(owner, &transaction).await?,
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
                        &self.allocator,
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
                drop(transaction);
                (result, ticket)
            } else {
                let ((), ticket) = router
                    .order()
                    .fix(vec![registration.account().clone()], async {
                        Ok::<_, CloseOutcome>(())
                    })
                    .await?;
                (Ok((None, None)), ticket)
            };
            let (audience, backlog) = match result {
                Ok(result) => result,
                Err(error) => {
                    drop(ticket);
                    report_handler_failure(&error, registration.account());
                    return Ok::<_, CloseOutcome>(Err((
                        RoutedStanza::from_parts(stamped, arena),
                        error,
                    )));
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
            let work = PresenceWork {
                session: registration.handle(),
                router: router.clone(),
                storage: storage.clone(),
                allocator: self.allocator.clone(),
                work: self.work.clone(),
                service_presence: self.service_presence.clone(),
                completion,
                account: registration.account().clone(),
                priority,
                available,
                routed,
                unavailable,
                audience,
                backlog,
            };
            Ok(Ok(after_turn(
                work_group.start(),
                ticket,
                None,
                move |_: Vec<MailboxEntry<A>>, ticket| work.run(ticket),
            )))
        };
        let mut pending = match self.outbox.drain_until(registration, prepare).await?? {
            Ok(pending) => pending,
            Err((routed, error)) => {
                return self.reply_rejection_with_text(
                    &routed,
                    error.condition(),
                    None,
                    error.text(),
                );
            }
        };
        self.outbox
            .drain_until(&self.registration, pending.turned())
            .await?;
        let outcome = pending
            .finished()
            .await
            .ok_or(CloseOutcome::InternalError)??;
        self.available = priority.is_some();
        self.priority = priority;
        // The router's mailbox cut keeps earlier sibling updates ahead of this echo.
        self.outbox.delivered(outcome.change.preceding);
        self.outbox.routed(outcome.change.siblings);
        let echo = (!self
            .router
            .session_observers(self.registration.account().domain())
            .is_empty())
        .then(|| outcome.echo.clone());
        self.outbox.push(Output::Routed(outcome.echo));
        self.outbox.routed(outcome.replay);
        if !outcome.requests.is_empty() {
            self.outbox.push(Output::Requests(outcome.requests));
        }
        if let Some(backlog) = outcome.backlog
            && let Some(handler) = message_handler
        {
            self.outbox.push(Output::Offline { backlog, handler });
        }
        if let Some(echo) = echo {
            let account = self.registration.account();
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

    async fn handle_subscription(
        &mut self,
        parsed: Parsed<Stanza, A>,
        kind: PresenceRequestType,
    ) -> Result<(), CloseOutcome> {
        let remote = {
            let stanza = parsed.value().resolve(parsed.arena())?;
            let target = stanza.to()?.ok_or(CloseOutcome::InternalError)?;
            self.router.destination(target) == Destination::Remote
        };
        let (source, mut arena) = parsed.into_parts();
        let (source, sender, _) = self.stamp_in(source, &mut arena, false)?;
        let routed = source
            .derive_in(&mut arena)?
            .from(Some(sender.bare()))?
            .bare_to()
            .build()?;
        let (source, routed) = RoutedStanza::from_parts_pair(source, routed, arena);
        if !self.admit_routed(&source)? {
            return Ok(());
        }
        let sender_host = self
            .router
            .presence_handlers(self.registration.account().domain())
            .and_then(|handlers| handlers.find(kind));
        if sender_host.is_none() && !remote {
            return Ok(());
        }

        let (policy_sender, policy_target) = presence_addresses(&routed)?;
        let account = self.registration.account();
        let policy_applies = policy_target.as_str() != account.as_str();
        let outbound_policy = policy_applies && !self.router.policies(account.domain()).is_empty();
        let inbound_policy = policy_applies
            && self.router.destination(policy_target) == Destination::Account
            && !self.router.policies(policy_target.domainpart()).is_empty();
        let policy_snapshot = if outbound_policy || inbound_policy {
            let read = async {
                self.storage.begin_read().await.map_err(|error| {
                    close_storage_failure(error, "presence_subscription_begin_read", account)
                })
            };
            Some(self.outbox.drain_until(&self.registration, read).await??)
        } else {
            None
        };
        if outbound_policy && let Some(snapshot) = policy_snapshot.as_ref() {
            let checks = [policy::Check {
                account,
                direction: Direction::Outbound,
                peer: policy_target,
            }];
            if self
                .outbox
                .drain_until(
                    &self.registration,
                    policy::evaluate_in(
                        &self.router,
                        snapshot,
                        routed.resolve()?.stanza_type(),
                        &checks,
                    ),
                )
                .await??
                != Verdict::Allow
            {
                return Ok(());
            }
        }
        if let Some(sender_host) = sender_host {
            let authorized = {
                let (sender, target) = presence_addresses(&source)?;
                let account = self.registration.account();
                let authorize = async {
                    let result = sender_host
                        .authorize(PresenceRequest {
                            kind,
                            sender,
                            target,
                            stanza: &source,
                        })
                        .await;
                    if let Err(error) = &result {
                        report_handler_failure(error, account);
                    }
                    result
                };
                self.outbox
                    .drain_until(&self.registration, authorize)
                    .await?
            };
            if let Err(error) = authorized {
                return self.reply_rejection_with_text(
                    &source,
                    error.condition(),
                    None,
                    error.text(),
                );
            }
        }
        if sender_host.is_none() {
            drop(policy_snapshot);
            return self.reply_error(&source, StanzaErrorCondition::RemoteServerNotFound);
        }
        let registration = &self.registration;
        let storage = &self.storage;
        let router = &self.router;
        let work = self.outbox.work;
        let delivery = self.delivery();
        let prepare = async {
            let (sender, target) = presence_addresses(&routed)?;
            let mut transaction = storage.begin_write().await.map_err(|error| {
                close_storage_failure(
                    error,
                    "presence_subscription_begin_write",
                    registration.account(),
                )
            })?;
            let sent = match sender_host {
                Some(sender_host) => {
                    let (sender, target) = presence_addresses(&source)?;
                    sender_host
                        .send(
                            PresenceRequest {
                                kind,
                                sender,
                                target,
                                stanza: &source,
                            },
                            &mut transaction,
                            &delivery,
                        )
                        .await
                }
                None => Ok(PresenceSend::Continue),
            };
            let effects = match sent {
                Ok(PresenceSend::Handled(effects)) => {
                    drop(policy_snapshot);
                    Ok(effects)
                }
                Ok(PresenceSend::Continue) => {
                    if inbound_policy && let Some(snapshot) = policy_snapshot.as_ref() {
                        let recipient = AccountKey::try_from(policy_target)?;
                        let checks = [policy::Check {
                            account: &recipient,
                            direction: Direction::Inbound,
                            peer: policy_sender,
                        }];
                        if policy::evaluate_in(
                            router,
                            snapshot,
                            routed.resolve()?.stanza_type(),
                            &checks,
                        )
                        .await?
                            != Verdict::Allow
                        {
                            return Ok::<_, CloseOutcome>(None);
                        }
                    }
                    drop(policy_snapshot);
                    if remote {
                        return Ok(Some(Err(HandlerError::Stanza(
                            StanzaErrorCondition::RemoteServerNotFound,
                        ))));
                    }
                    let (_, original_target) = presence_addresses(&source)?;
                    if kind != PresenceRequestType::Subscribe
                        && router.is_local_host(original_target.domainpart())
                        && original_target.resourcepart().is_some()
                        && subscription_target(router, &transaction, original_target)
                            .await?
                            .is_none()
                    {
                        return Ok(None);
                    }
                    match router
                        .presence_handlers(target.domainpart())
                        .and_then(|handlers| handlers.find(kind))
                    {
                        Some(target_host) => {
                            target_host
                                .receive(
                                    PresenceRequest {
                                        kind,
                                        sender,
                                        target,
                                        stanza: &routed,
                                    },
                                    &mut transaction,
                                    &delivery,
                                )
                                .await
                        }
                        None => Err(HandlerError::Stanza(
                            StanzaErrorCondition::ServiceUnavailable,
                        )),
                    }
                }
                Err(error) => {
                    drop(policy_snapshot);
                    Err(error)
                }
            };
            Ok(Some(match effects {
                Ok(effects) => Ok(commit_and_deliver(
                    work.start(),
                    Arc::clone(router.order()),
                    transaction,
                    effects,
                    delivery,
                    Some(registration.mailbox()),
                    EffectsDiagnostics {
                        account: registration.account().clone(),
                        commit_operation: "presence_subscription_commit",
                        delivery_operation: "presence_subscription_effects",
                    },
                )),
                Err(error) => {
                    drop(transaction);
                    report_handler_failure(&error, registration.account());
                    Err(error)
                }
            }))
        };
        match self.outbox.drain_until(registration, prepare).await?? {
            None => Ok(()),
            Some(Ok(mut committed)) => {
                self.outbox
                    .drain_until(registration, committed.turned())
                    .await?;
                let queued = committed
                    .finished()
                    .await
                    .ok_or(CloseOutcome::InternalError)?
                    .map_err(|_| CloseOutcome::InternalError)?;
                self.outbox.delivered(queued);
                Ok(())
            }
            Some(Err(error)) => {
                self.reply_rejection_with_text(&source, error.condition(), None, error.text())
            }
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
        let mut arena = Arena::try_new_in(Default::default(), self.allocator.clone())?;
        let source = source.resolve()?.clone_in(&mut arena)?;
        let reply = source
            .error_reply_described_in(&mut arena, condition, application, text)?
            .build()?;
        self.outbox.push(Output::Owned {
            stanza: reply,
            arena,
        });
        Ok(())
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
            || self.recipients.admit(to.bare().as_str(), Instant::now())
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
                Output::Owned { stanza, arena } => {
                    self.written = self.written.next();
                    self.writer.write(Outgoing::Owned { stanza, arena }).await?;
                }
                Output::Requests(requests) => {
                    for subscription in requests {
                        let stanza = self
                            .parse_stored(
                                &subscription.stanza,
                                StoredKind::Subscription(&subscription.sender),
                            )
                            .await?;
                        self.written = self.written.next();
                        self.writer.write(Outgoing::Routed(stanza)).await?;
                        pending_count += 1;
                    }
                }
                Output::Offline { backlog, handler } => {
                    offline_replay = true;
                    for message in backlog.messages {
                        match self
                            .parse_stored(&message.stanza, StoredKind::Message)
                            .await
                        {
                            Ok(stanza) => {
                                self.written = self.written.next();
                                self.writer.write(Outgoing::Routed(stanza)).await?;
                                messages_written += 1;
                            }
                            Err(StoredRecordError::InvalidContent) => {
                                messages_skipped += 1;
                                tracing::error!(
                                    sequence = message.sequence.get(),
                                    "stored offline message rejected"
                                );
                            }
                            Err(StoredRecordError::ReplayFailure) => {
                                return Err(CloseOutcome::InternalError);
                            }
                        }
                    }
                    self.releases.push_back((
                        self.written,
                        Release::Backlog {
                            handler,
                            through: backlog.through,
                        },
                    ));
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
    loop {
        let mut transaction =
            storage
                .begin_write()
                .await
                .map_err(|error| HandlerError::Internal {
                    condition: StanzaErrorCondition::InternalServerError,
                    failure: storage_failure(error, "offline_acknowledge_live_begin_write"),
                })?;
        // Check after writer admission so account recreation cannot reset these sequences.
        if !liveness.is_alive() {
            tracing::info!(
                operation = "acknowledge_live",
                outcome = "skipped_stale_session",
                recipient_jid = ?account.as_str(),
                "offline message acknowledgement handled"
            );
            return Ok(());
        }
        let batch = mem::take(&mut *pending.borrow_mut());
        if batch.is_empty() {
            return Ok(());
        }
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
                failure: storage_failure(error, "offline_acknowledge_live_commit"),
            })?;
        tracing::info!(
            operation = "acknowledge_live",
            outcome = "committed",
            recipient_jid = ?account.as_str(),
            "offline message acknowledgement handled"
        );
    }
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

#[derive(Clone, Copy)]
enum IqTarget {
    Server,
    Present,
    Missing,
}

async fn iq_target(
    transaction: &impl AccountReads,
    target: Option<&AccountKey>,
) -> Result<IqTarget, HandlerError> {
    let Some(target) = target else {
        return Ok(IqTarget::Server);
    };
    match transaction.account(target).await {
        Ok(Some(_)) => Ok(IqTarget::Present),
        Ok(None) => Ok(IqTarget::Missing),
        Err(AccountError::Storage(error)) => Err(HandlerError::Internal {
            condition: StanzaErrorCondition::InternalServerError,
            failure: storage_failure(error, "iq_account_read"),
        }),
        Err(_) => Err(StanzaErrorCondition::InternalServerError.into()),
    }
}

async fn require_iq_account(
    transaction: &impl AccountReads,
    target: Option<&AccountKey>,
) -> Result<(), HandlerError> {
    match iq_target(transaction, target).await? {
        IqTarget::Missing => Err(StanzaErrorCondition::ServiceUnavailable.into()),
        IqTarget::Server | IqTarget::Present => Ok(()),
    }
}

async fn iq_requester<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    account: &AccountKey,
    sender: JidRef<'_>,
    transaction: &RedbRead,
) -> Result<Requester, HandlerError> {
    if sender.bare().as_str() == account.as_str() {
        return Ok(Requester::Owner);
    }
    let Some(handler) = router
        .presence_handlers(account.domain())
        .and_then(|handlers| handlers.find(PresenceRequestType::Available))
    else {
        return Ok(Requester::Other);
    };
    Ok(if handler.visibility(account, sender, transaction).await? {
        Requester::PresenceAuthorized
    } else {
        Requester::Other
    })
}

struct GetWork<A: ChunkAllocator> {
    account: AccountKey,
    target_account: Option<AccountKey>,
    transaction: RedbRead,
    handler: Arc<dyn IqHandler<A, RedbStorage>>,
    discovery: Arc<Discovery>,
    arena: Arena<A>,
    request: Stanza,
    sender: Jid,
    response: Arena<A>,
    delivery: RouterDelivery<A>,
}

struct GetOutcome<A: ChunkAllocator> {
    arena: Arena<A>,
    response: Arena<A>,
    reply: Result<Option<Element>, IqError>,
    results: Vec<Stanza>,
    /// Write these deliveries before the reply to preserve mailbox order.
    queued: Vec<MailboxEntry<A>>,
}

impl<A: ChunkAllocator + Clone> GetWork<A> {
    async fn run(self, queued: Vec<MailboxEntry<A>>) -> Result<GetOutcome<A>, CloseOutcome> {
        let GetWork {
            account,
            target_account,
            transaction,
            handler,
            discovery,
            arena,
            request,
            sender,
            mut response,
            delivery,
        } = self;
        let reply = match iq_target(&transaction, target_account.as_ref()).await {
            Err(error) => Err(error.into()),
            Ok(iq_target) => {
                let sender = sender.resolve(&arena)?;
                let stanza = request.resolve(&arena)?;
                let target = stanza.to()?.unwrap_or_else(|| sender.bare());
                let payload = stanza
                    .children()?
                    .next()
                    .transpose()?
                    .ok_or(CloseOutcome::InternalError)?;
                let requester = match iq_target {
                    IqTarget::Server => Ok(None),
                    IqTarget::Present => {
                        let account = target_account.as_ref().ok_or(CloseOutcome::InternalError)?;
                        iq_requester(delivery.router(), account, sender, &transaction)
                            .await
                            .map(Some)
                    }
                    IqTarget::Missing => {
                        let account = target_account.as_ref().ok_or(CloseOutcome::InternalError)?;
                        Ok(Some(if sender.bare().as_str() == account.as_str() {
                            Requester::Owner
                        } else {
                            Requester::Other
                        }))
                    }
                };
                match requester {
                    Err(error) => Err(error.into()),
                    Ok(requester) => {
                        let iq_request = IqRequest {
                            sender,
                            target,
                            discovery: &discovery,
                            sessions: &delivery,
                            requester,
                            lang: stanza.lang()?,
                            space: stanza
                                .attribute("space", XML_NAMESPACE)?
                                .map(XmlSpace::from_attribute),
                            payload,
                        };
                        match iq_target {
                            IqTarget::Missing => handler
                                .get_missing_account(iq_request, &mut response)
                                .map(|payload| IqReply::new(payload, Effects::none())),
                            IqTarget::Server | IqTarget::Present => {
                                handler.get(iq_request, &transaction, &mut response).await
                            }
                        }
                    }
                }
            }
        };
        drop(transaction);
        let (reply, results) = match reply {
            Ok(IqReply {
                payload,
                effects,
                results,
            }) => {
                (effects.deliver)(&delivery).await.map_err(|_| {
                    report_failure(
                        Failure {
                            kind: FailureKind::Delivery,
                            operation: "iq_get_effects",
                        },
                        &account,
                    );
                    CloseOutcome::InternalError
                })?;
                (Ok(payload), results)
            }
            Err(error) => {
                report_handler_failure(error.handler_error(), &account);
                (Err(error), Vec::new())
            }
        };
        Ok(GetOutcome {
            arena,
            response,
            reply,
            results,
            queued,
        })
    }
}

struct DirectedServiceWork<A: ChunkAllocator> {
    session: SessionHandle<A>,
    router: RouterHandle<A>,
    storage: RedbStorage,
    allocator: A,
    work: WorkHandle,
    lease: Arc<ServicePresenceLease>,
    completion: oneshot::Sender<()>,
    stanza: RoutedStanza<A>,
    route: ServiceRoute<A>,
}

impl<A: ChunkAllocator + Clone> DirectedServiceWork<A> {
    async fn run(self) -> Result<ServiceOutcome<A>, RouterError> {
        let view = self
            .stanza
            .resolve()
            .map_err(|_| RouterError::InvalidTarget)?;
        let to = view
            .to()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let available = view.stanza_type() == StanzaType::Presence(PresenceType::Available);
        self.session.record_service_presence(to, available).await?;
        let stage = Stage {
            router: &self.router,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        };
        let result = service::dispatch(&stage, &self.route, self.stanza)
            .await
            .map_err(|_| RouterError::Unavailable);
        drop(self.lease);
        let _ = self.completion.send(());
        result
    }
}

struct TerminalPresenceWork<A: ChunkAllocator> {
    session: SessionHandle<A>,
    router: RouterHandle<A>,
    storage: RedbStorage,
    allocator: A,
    work: WorkHandle,
    service_presence: Option<Arc<ServicePresenceLease>>,
    service_pending: Option<Shared<oneshot::Receiver<()>>>,
    account: AccountKey,
    fallback: RoutedStanza<A>,
}

impl<A: ChunkAllocator + Clone> TerminalPresenceWork<A> {
    async fn run(self) -> Result<(), CloseOutcome> {
        let stage = Stage {
            router: &self.router,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        };
        let withdrawal = self
            .session
            .end_presence()
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        let notice = withdrawal.unavailable.as_ref().unwrap_or(&self.fallback);
        let mut covered = Vec::new();
        let mut ticket = None;
        let broadcast = if withdrawal.unavailable.is_some() {
            async {
                let handler = self
                    .router
                    .presence_handlers(self.account.domain())
                    .and_then(|handlers| handlers.find(PresenceRequestType::Unavailable));
                let (transaction, admitted) = self
                    .router
                    .order()
                    .fix(vec![self.account.clone()], async {
                        match handler {
                            Some(_) => self.storage.begin_read().await.map(Some).map_err(|error| {
                                close_storage_failure(
                                    error,
                                    "presence_terminal_begin_read",
                                    &self.account,
                                )
                            }),
                            None => Ok(None),
                        }
                    })
                    .await?;
                ticket = Some(admitted);
                let mut audience = match (handler, transaction.as_ref()) {
                    (Some(handler), Some(transaction)) => {
                        let view = notice.resolve()?;
                        let sender = view.from()?.ok_or(CloseOutcome::InternalError)?;
                        handler
                            .audience(
                                PresenceUpdate {
                                    sender,
                                    transition: PresenceTransition::Unavailable,
                                },
                                transaction,
                            )
                            .await
                            .map_err(|error| {
                                report_handler_failure(&error, &self.account);
                                CloseOutcome::InternalError
                            })?
                    }
                    _ => None,
                };
                if let (Some(audience), Some(transaction)) =
                    (audience.as_mut(), transaction.as_ref())
                {
                    let view = notice.resolve()?;
                    let sender = view.from()?.ok_or(CloseOutcome::InternalError)?;
                    policy::filter_audience(
                        &self.router,
                        transaction,
                        &self.allocator,
                        &self.account,
                        sender,
                        StanzaType::Presence(PresenceType::Unavailable),
                        audience,
                    )
                    .await
                    .map_err(|_| CloseOutcome::InternalError)?;
                }
                if let Some(ticket) = ticket.as_mut() {
                    ticket.turn().await;
                }
                if let Some(audience) = audience {
                    if !self
                        .session
                        .replacement_is_available()
                        .await
                        .map_err(|_| CloseOutcome::InternalError)?
                    {
                        self.router
                            .broadcast_presence(notice, &audience.subscribers)
                            .await
                            .map_err(|_| CloseOutcome::InternalError)?;
                    }
                    covered = audience.subscribers;
                }
                Ok(())
            }
            .await
        } else {
            Ok(())
        };
        if let Some(ticket) = ticket.as_mut() {
            ticket.turn().await;
        }
        let local = send_local_withdrawal(&stage, notice, &withdrawal.directed, &covered).await;
        let finished = self
            .session
            .finish_presence(withdrawal.directed.source_token)
            .await
            .map_err(|_| CloseOutcome::InternalError);
        drop(ticket);
        if let Some(pending) = self.service_pending {
            let _ = pending.await;
        }
        let services =
            send_service_withdrawal(&stage, notice, &withdrawal.directed, &covered).await;
        drop(self.service_presence);
        broadcast.and(local).and(finished).and(services)
    }
}

fn withdrawal_recipients<'a>(
    withdrawal: &'a DirectedWithdrawal,
    covered: &'a [RosterJid],
) -> impl Iterator<Item = &'a str> + Clone {
    withdrawal
        .recipients
        .iter()
        .map(|recipient| recipient.as_str())
        .filter(|recipient| {
            !covered
                .iter()
                .any(|subscriber| subscriber.as_str() == *recipient)
        })
}

async fn send_local_withdrawal<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    notice: &RoutedStanza<A>,
    withdrawal: &DirectedWithdrawal,
    covered: &[RosterJid],
) -> Result<(), CloseOutcome> {
    stage
        .router
        .send_directed(
            notice,
            withdrawal_recipients(withdrawal, covered)
                .filter(|recipient| stage.router.service(domain_of(recipient)).is_none()),
        )
        .await
        .map_err(|_| CloseOutcome::InternalError)
}

async fn send_service_withdrawal<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    notice: &RoutedStanza<A>,
    withdrawal: &DirectedWithdrawal,
    covered: &[RosterJid],
) -> Result<(), CloseOutcome> {
    for recipient in withdrawal_recipients(withdrawal, covered) {
        if let Some(route) = stage.router.service(domain_of(recipient)) {
            let mut arena = Arena::try_new_in(Default::default(), stage.allocator.clone())?;
            let target = Jid::parse_in(recipient, &mut arena)?;
            let stanza = notice
                .resolve()?
                .to_builder_in(&mut arena)?
                .to(Some(target))?
                .build()?;
            service::dispatch(stage, route, RoutedStanza::from_parts(stanza, arena)).await?;
        }
    }
    Ok(())
}

fn domain_of(jid: &str) -> &str {
    let bare = jid.split_once('/').map_or(jid, |(bare, _)| bare);
    bare.split_once('@').map_or(bare, |(_, domain)| domain)
}

struct PresenceWork<A: ChunkAllocator> {
    session: SessionHandle<A>,
    router: RouterHandle<A>,
    storage: RedbStorage,
    allocator: A,
    work: WorkHandle,
    service_presence: Option<Arc<ServicePresenceLease>>,
    completion: Option<oneshot::Sender<()>>,
    account: AccountKey,
    priority: Option<i8>,
    available: bool,
    routed: RoutedStanza<A>,
    unavailable: Option<RoutedStanza<A>>,
    audience: Option<PresenceAudience>,
    backlog: Option<Backlog>,
}

struct PresenceOutcome<A: ChunkAllocator> {
    change: PresenceChange<A>,
    echo: RoutedStanza<A>,
    replay: Vec<RoutedStanza<A>>,
    requests: Vec<PendingSubscription>,
    backlog: Option<Backlog>,
}

impl<A: ChunkAllocator + Clone> PresenceWork<A> {
    async fn run(self, ticket: Ticket) -> Result<PresenceOutcome<A>, CloseOutcome> {
        let PresenceWork {
            session,
            router,
            storage,
            allocator,
            work,
            service_presence,
            completion,
            account,
            priority,
            available,
            routed,
            unavailable,
            mut audience,
            backlog,
        } = self;
        let mut change = session
            .set_presence(priority, routed.clone(), unavailable)
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        let backlog = if change.became_eligible {
            backlog
        } else {
            None
        };
        let mut replay = Vec::new();
        let mut requests = Vec::new();
        if change.became_available
            && let Some(audience) = audience.as_mut()
        {
            // The ticket keeps subscription revocation behind these deliveries.
            for contact in &audience.contacts {
                let presence = router
                    .current_presence(contact, &account)
                    .await
                    .map_err(|_| CloseOutcome::InternalError)?;
                replay.extend(presence);
            }
            requests = mem::take(&mut audience.pending);
            tracing::info!(
                contact_count = audience.contacts.len(),
                replay_count = replay.len(),
                pending_count = requests.len(),
                subscriber_count = audience.subscribers.len(),
                owner_jid = ?account.as_str(),
                "initial presence prepared"
            );
        }
        let mut covered = Vec::new();
        let broadcast = if let Some(audience) = audience
            && (available || change.became_unavailable)
            && !audience.subscribers.is_empty()
        {
            router
                .broadcast_presence(&routed, &audience.subscribers)
                .await
                .map(|()| covered = audience.subscribers)
                .map_err(|_| CloseOutcome::InternalError)
        } else {
            Ok(())
        };
        let stage = Stage {
            router: &router,
            storage: &storage,
            allocator: &allocator,
            work: &work,
        };
        let local = if !available {
            send_local_withdrawal(&stage, &routed, &change.directed, &covered).await
        } else {
            Ok(())
        };
        drop(ticket);
        let services = if !available {
            send_service_withdrawal(&stage, &routed, &change.directed, &covered).await
        } else {
            Ok(())
        };
        change.directed.recipients.clear();
        drop(service_presence);
        drop(completion);
        broadcast.and(local).and(services)?;
        Ok(PresenceOutcome {
            change,
            echo: routed,
            replay,
            requests,
            backlog,
        })
    }
}

fn presence_addresses<A: ChunkAllocator>(
    stanza: &RoutedStanza<A>,
) -> Result<(JidRef<'_>, JidRef<'_>), CloseOutcome> {
    let view = stanza.resolve()?;
    let sender = view.from()?.ok_or(CloseOutcome::InternalError)?;
    let target = view.to()?.ok_or(CloseOutcome::InternalError)?;
    Ok((sender, target))
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

struct ResourceIqWork<A: ChunkAllocator> {
    source: AccountKey,
    liveness: SessionLiveness,
    router: RouterHandle<A>,
    storage: RedbStorage,
    target: AccountKey,
    request: bool,
    stanza: RoutedStanza<A>,
}

impl<A: ChunkAllocator + Clone> ResourceIqWork<A> {
    async fn run(self) -> Result<(), RouterError> {
        let (subscribed, ticket) = self.authorize().await?;
        self.admit(subscribed, ticket).await
    }

    async fn authorize(&self) -> Result<(bool, Ticket), RouterError> {
        let mut accounts = vec![self.source.clone()];
        if self.source != self.target {
            accounts.push(self.target.clone());
        }
        if !self.request {
            let ((), ticket) = self
                .router
                .order()
                .fix(accounts, async { Ok::<_, RouterError>(()) })
                .await?;
            return Ok((false, ticket));
        }
        let (transaction, ticket) = self
            .router
            .order()
            .fix(accounts, self.storage.begin_read())
            .await
            .map_err(|error| {
                report_failure(
                    storage_failure(error, "resource_iq_begin_read"),
                    &self.target,
                );
                RouterError::Unavailable
            })?;
        let observer = self
            .stanza
            .resolve()
            .map_err(|_| RouterError::InvalidTarget)?
            .from()
            .map_err(|_| RouterError::InvalidTarget)?
            .ok_or(RouterError::InvalidTarget)?;
        let subscribed = match self
            .router
            .presence_handlers(self.target.domain())
            .and_then(|handlers| handlers.find(PresenceRequestType::Available))
        {
            Some(handler) => handler
                .visibility(&self.target, observer, &transaction)
                .await
                .map_err(|error| {
                    report_handler_failure(&error, &self.target);
                    RouterError::Unavailable
                })?,
            None => false,
        };
        Ok((subscribed, ticket))
    }

    async fn admit(self, subscribed: bool, mut ticket: Ticket) -> Result<(), RouterError> {
        ticket.turn().await;
        if !self.liveness.is_alive() {
            return Ok(());
        }
        if self.request {
            self.router
                .route_iq_request_guarded(self.stanza, subscribed, Some(self.liveness))
                .await
        } else {
            self.router
                .route_full_guarded(self.stanza, self.liveness)
                .await
        }
    }
}

#[cfg(test)]
mod preparation_tests;
#[cfg(test)]
mod service_tests;
#[cfg(test)]
mod tests;
