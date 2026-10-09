// SPDX-License-Identifier: Apache-2.0

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::mem;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::SystemTime;

use futures_util::future::{Either, join, select};
use lonewolf_extension::delivery::{Failure, FailureKind, HandlerError};
use lonewolf_extension::iq::{IqHandler, IqReply, IqRequest, IqRequestType, IqScope};
use lonewolf_extension::message::{Backlog, MessageHandler, StoreOutcome, UndeliverableMessage};
use lonewolf_extension::presence::{
    PresenceAudience, PresenceRequest, PresenceRequestType, PresenceTransition, PresenceUpdate,
};
use lonewolf_storage::account::{AccountError, AccountKey, AccountReads};
use lonewolf_storage::offline::OfflineSequence;
use lonewolf_storage::roster::{PendingSubscription, RosterJid};
use lonewolf_storage::{RedbRead, RedbStorage, RedbWrite, Storage, StorageError, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, ArenaRead, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{Jid, JidError, JidRef};
use lonewolf_xmpp::parser::{ParseError, Parsed, ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{
    BuildError, CLIENT_NAMESPACE, Element, IqType, MessageType, PresenceType, RejectedStanza,
    Stanza, StanzaErrorCondition, StanzaNamespace, StanzaRef, StanzaType,
};

use super::bind::Bound;
use super::outcome::CloseOutcome;
use super::session::{Session, Writer};
use crate::c2s::iq;
use crate::delivery::{
    EffectsDiagnostics, Pending, RouterDelivery, StoredDelivery, WorkGroup, after_turn,
    commit_and_deliver, commit_and_store, report_failure, report_handler_failure, storage_failure,
};
use crate::order::Ticket;
use crate::router::local::{DirectedWithdrawal, PresenceChange, RetireCause, SessionLiveness};
use crate::router::{
    MailboxEntry, Registration, ResourceMatch, RoutedStanza, RouterError, RouterHandle,
    SessionHandle,
};

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
    /// Parse each request at write time to keep large backlogs out of memory.
    Requests(Vec<PendingSubscription>),
    Offline {
        backlog: Backlog,
        handler: Arc<dyn MessageHandler<A, RedbStorage>>,
    },
}

enum StorePreparation<A: ChunkAllocator> {
    Rejected {
        stanza: RoutedStanza<A>,
        error: HandlerError,
    },
    Discarded,
    Committed(Pending<Result<(), crate::delivery::EffectsError>>),
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

    /// Flushes every stanza written so far; `through` is the sequence of the last one.
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
                Either::Left(Ok(RetireCause::AccountDeleted)) => CloseOutcome::AccountDeleted,
                Either::Left(_) => CloseOutcome::InternalError,
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
    async fn end(&mut self) -> Result<(), CloseOutcome> {
        let work = TerminalPresenceWork {
            session: self.registration.handle(),
            router: self.router.clone(),
            storage: self.storage.clone(),
            account: self.registration.account().clone(),
            fallback: self.unavailable_notice()?,
        };
        Pending::spawn(self.outbox.work.start(), work.run())
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
        let reply = rejected.error_in(authenticated, &mut arena)?;
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
        match stanza.stanza_type() {
            StanzaType::Iq(_) => self.handle_iq(parsed).await,
            StanzaType::Presence(kind) => {
                let directed = stanza.to()?.is_some();
                self.handle_presence(parsed, kind, directed).await
            }
            StanzaType::Message(kind) => self.handle_message(parsed, kind).await,
        }
    }

    /// Committed handler effects outlive this session.
    async fn handle_iq(&mut self, parsed: Parsed<Stanza, A>) -> Result<(), CloseOutcome> {
        let (request, mut arena) = parsed.into_parts();
        let route = iq::route(&request, &mut arena, &self.registration, &self.router)?;
        if route.destination == iq::IqDestination::FullResource {
            let routed = request
                .derive_in(&mut arena)?
                .from(Some(route.sender))?
                .build()?;
            return self
                .route_resource_iq(RoutedStanza::from_parts(routed, arena), route.kind)
                .await;
        }
        let Some(kind) = route.request_type() else {
            return Ok(());
        };
        let response = Arena::try_new_in(Default::default(), self.allocator.clone())?;
        let (handler, accounts) = {
            let sender = route.sender.resolve(&arena)?;
            let stanza = request.resolve(&arena)?;
            let target = stanza.to()?.unwrap_or_else(|| sender.bare());
            let payload = stanza
                .children()?
                .next()
                .transpose()?
                .ok_or(CloseOutcome::InternalError)?;
            let scope = match route.destination {
                iq::IqDestination::Account => Some(IqScope::Account),
                iq::IqDestination::Server => Some(IqScope::Server),
                iq::IqDestination::FullResource | iq::IqDestination::Remote => None,
            };
            let handler = scope.and_then(|scope| {
                self.router.iq_handlers(target.domainpart())?.find(
                    scope,
                    kind,
                    payload.namespace(),
                    payload.name(),
                )
            });
            let accounts = match scope {
                Some(IqScope::Account) => vec![AccountKey::try_from(target.bare())?],
                Some(IqScope::Server) | None => Vec::new(),
            };
            (handler.map(Arc::clone), accounts)
        };
        let Some(handler) = handler else {
            let reply = iq::error_reply(
                &request,
                &mut arena,
                StanzaErrorCondition::ServiceUnavailable,
                None,
            )?;
            self.outbox.push(Output::Owned {
                stanza: reply,
                arena,
            });
            return Ok(());
        };
        match kind {
            IqRequestType::Get => {
                self.handle_iq_get(request, route.sender, arena, response, handler, accounts)
                    .await
            }
            IqRequestType::Set => {
                self.handle_iq_set(request, route.sender, arena, response, handler)
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
        accounts: Vec<AccountKey>,
    ) -> Result<(), CloseOutcome> {
        let registration = &self.registration;
        let storage = &self.storage;
        let router = &self.router;
        let work_group = self.outbox.work;
        let delivery = self.delivery();
        let prepare = async {
            let (transaction, ticket) = Arc::clone(router.order())
                .fix(accounts, storage.begin_read())
                .await
                .map_err(|error| {
                    close_storage_failure(error, "iq_get_begin_read", registration.account())
                })?;
            let work = GetWork {
                account: registration.account().clone(),
                transaction,
                handler,
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
                move |queued| work.run(queued),
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
        )
    }

    async fn handle_iq_set(
        &mut self,
        request: Stanza,
        sender: Jid,
        arena: Arena<A>,
        mut response: Arena<A>,
        handler: Arc<dyn IqHandler<A, RedbStorage>>,
    ) -> Result<(), CloseOutcome> {
        let registration = &self.registration;
        let storage = &self.storage;
        let router = &self.router;
        let work = self.outbox.work;
        let delivery = self.delivery();
        let prepare = async {
            let mut transaction = storage.begin_write().await.map_err(|error| {
                close_storage_failure(error, "iq_set_begin_write", registration.account())
            })?;
            let reply = {
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
                            payload,
                        },
                        &mut transaction,
                        &delivery,
                        &mut response,
                    )
                    .await
            };
            Ok::<_, CloseOutcome>(match reply {
                Ok(IqReply { payload, effects }) => Ok((
                    payload,
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
                    report_handler_failure(&error, registration.account());
                    Err(error)
                }
            })
        };
        let prepared = self.outbox.drain_until(registration, prepare).await??;
        let reply = match prepared {
            Ok((payload, mut committed)) => {
                self.outbox
                    .drain_until(registration, committed.turned())
                    .await?;
                let queued = committed
                    .finished()
                    .await
                    .ok_or(CloseOutcome::InternalError)?
                    .map_err(|_| CloseOutcome::InternalError)?;
                self.outbox.delivered(queued);
                Ok(payload)
            }
            Err(error) => Err(error),
        };
        self.queue_iq_reply(request, sender, arena, response, reply)
    }

    fn queue_iq_reply(
        &mut self,
        request: Stanza,
        sender: Jid,
        mut arena: Arena<A>,
        mut response: Arena<A>,
        reply: Result<Option<Element>, HandlerError>,
    ) -> Result<(), CloseOutcome> {
        match reply {
            Err(error) => {
                let reply = iq::error_reply(&request, &mut arena, error.condition(), Some(sender))?;
                self.outbox.push(Output::Owned {
                    stanza: reply,
                    arena,
                });
            }
            Ok(payload) => {
                let reply = {
                    let sender = sender.resolve(&arena)?;
                    let stanza = request.resolve(&arena)?;
                    iq::result_reply(&stanza, sender, payload, &mut response)?
                };
                self.outbox.push(Output::Owned {
                    stanza: reply,
                    arena: response,
                });
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
        let target = {
            let view = routed.resolve()?;
            let to = view.to()?.ok_or(CloseOutcome::InternalError)?;
            if !self.router.is_local_host(to.domainpart()) || to.localpart().is_none() {
                return Ok(());
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
        let target = {
            let view = routed.resolve()?;
            let to = view.to()?.ok_or(CloseOutcome::InternalError)?;
            if !self.router.is_local_host(to.domainpart()) || to.localpart().is_none() {
                return Ok(());
            }
            AccountKey::try_from(to.bare()).map_err(|_| CloseOutcome::InternalError)?
        };
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
        let bare = routed
            .resolve()?
            .to()?
            .ok_or(CloseOutcome::InternalError)?
            .resourcepart()
            .is_none();
        if bare && kind == MessageType::Error {
            return Ok(());
        }
        if bare && kind == MessageType::Groupchat {
            return self.reply_error(&routed, StanzaErrorCondition::ServiceUnavailable);
        }
        if let Err(error) = self.router.route_message(routed.clone()).await {
            if kind == MessageType::Error
                || (bare && kind == MessageType::Headline && error == RouterError::NotFound)
                || (kind == MessageType::Headline && error == RouterError::Offline)
            {
                return Ok(());
            }
            if error == RouterError::Offline
                && matches!(kind, MessageType::Normal | MessageType::Chat)
            {
                return self.store_message(routed).await;
            }
            let condition = match error {
                RouterError::Busy
                | RouterError::ResourceLimit
                | RouterError::DirectedPresenceLimit => StanzaErrorCondition::ResourceConstraint,
                RouterError::InvalidTarget | RouterError::InvalidResource => {
                    StanzaErrorCondition::BadRequest
                }
                RouterError::NotFound | RouterError::Offline | RouterError::RemoteUnsupported => {
                    StanzaErrorCondition::ServiceUnavailable
                }
                RouterError::Unavailable | RouterError::Stopped => {
                    return Err(CloseOutcome::InternalError);
                }
            };
            self.reply_error(&routed, condition)?;
        }
        Ok(())
    }

    async fn store_message(&mut self, routed: RoutedStanza<A>) -> Result<(), CloseOutcome> {
        let recipient = AccountKey::try_from(
            routed
                .resolve()?
                .to()?
                .ok_or(CloseOutcome::InternalError)?
                .bare(),
        )
        .map_err(|_| CloseOutcome::InternalError)?;
        let Some(handler) = self.router.message_handler(recipient.domain()).cloned() else {
            tracing::info!(
                operation = "store",
                outcome = "rejected",
                reason = "missing_handler",
                recipient_jid = ?recipient.as_str(),
                "offline message policy decided"
            );
            return self.reply_error(&routed, StanzaErrorCondition::ServiceUnavailable);
        };
        let bytes = if tracing::enabled!(tracing::Level::INFO) {
            stanza_bytes(&routed)?
        } else {
            0
        };
        let registration = &self.registration;
        let storage = &self.storage;
        let router = &self.router;
        let allocator = &self.allocator;
        let work = self.outbox.work;
        let prepare = async {
            let mut transaction = storage.begin_write().await.map_err(|error| {
                close_storage_failure(error, "offline_store_begin_write", &recipient)
            })?;
            let mut scratch = Arena::try_new_in(ArenaConfig::default(), allocator.clone())?;
            let outcome = handler
                .store(
                    UndeliverableMessage {
                        recipient: &recipient,
                        stanza: &routed,
                        received_at: SystemTime::now(),
                    },
                    &mut transaction,
                    &mut scratch,
                )
                .await;
            drop(scratch);
            Ok::<_, CloseOutcome>(match outcome {
                Err(error) => {
                    drop(transaction);
                    report_handler_failure(&error, &recipient);
                    StorePreparation::Rejected {
                        stanza: routed,
                        error,
                    }
                }
                Ok(StoreOutcome::Discarded) => {
                    drop(transaction);
                    StorePreparation::Discarded
                }
                Ok(StoreOutcome::Stored(sequence)) => {
                    StorePreparation::Committed(commit_and_store(
                        work.start(),
                        router.clone(),
                        transaction,
                        handler,
                        StoredDelivery {
                            recipient,
                            sequence,
                            stanza: routed,
                            bytes,
                        },
                    ))
                }
            })
        };
        match self.outbox.drain_until(registration, prepare).await?? {
            StorePreparation::Rejected { stanza, error } => {
                self.reply_error(&stanza, error.condition())
            }
            StorePreparation::Discarded => Ok(()),
            StorePreparation::Committed(pending) => self
                .outbox
                .drain_until(registration, pending.finished())
                .await?
                .ok_or(CloseOutcome::InternalError)?
                .map_err(|_| CloseOutcome::InternalError),
        }
    }

    async fn handle_availability(
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
        let registration = &self.registration;
        let router = &self.router;
        let storage = &self.storage;
        let work_group = self.outbox.work;
        let prepare = async {
            let (result, ticket) =
                if presence_handler.is_some() || (candidate && message_handler.is_some()) {
                    let owner = registration.account();
                    let (transaction, ticket) = Arc::clone(router.order())
                        .fix(vec![owner.clone()], storage.begin_read())
                        .await
                        .map_err(|error| {
                            close_storage_failure(error, "presence_snapshot_begin_read", owner)
                        })?;
                    let sender = from.resolve(&arena)?;
                    let result = async {
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
                move |_: Vec<MailboxEntry<A>>| work.run(),
            )))
        };
        let mut pending = match self.outbox.drain_until(registration, prepare).await?? {
            Ok(pending) => pending,
            Err((routed, error)) => return self.reply_error(&routed, error.condition()),
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
        Ok(())
    }

    async fn handle_subscription(
        &mut self,
        parsed: Parsed<Stanza, A>,
        kind: PresenceRequestType,
    ) -> Result<(), CloseOutcome> {
        let Some(sender_host) = self
            .router
            .presence_handlers(self.registration.account().domain())
            .and_then(|handlers| handlers.find(kind))
        else {
            return Ok(());
        };
        let (source, mut arena) = parsed.into_parts();
        let (source, sender, _) = self.stamp_in(source, &mut arena, false)?;
        let routed = source
            .derive_in(&mut arena)?
            .from(Some(sender.bare()))?
            .bare_to()
            .build()?;
        let (source, routed) = RoutedStanza::from_parts_pair(source, routed, arena);
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
            return self.reply_error(&source, error.condition());
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
            let (_, original_target) = presence_addresses(&source)?;
            if kind != PresenceRequestType::Subscribe
                && router.is_local_host(original_target.domainpart())
                && original_target.resourcepart().is_some()
                && subscription_target(router, &transaction, original_target)
                    .await?
                    .is_none()
            {
                drop(transaction);
                return Ok::<_, CloseOutcome>(None);
            }
            let effects = match router
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
            Some(Err(error)) => self.reply_error(&source, error.condition()),
        }
    }

    fn reply_error(
        &mut self,
        source: &RoutedStanza<A>,
        condition: StanzaErrorCondition,
    ) -> Result<(), CloseOutcome> {
        let mut arena = Arena::try_new_in(Default::default(), self.allocator.clone())?;
        let source = source.resolve()?.clone_in(&mut arena)?;
        let reply = source.error_reply_in(&mut arena, condition)?.build()?;
        self.outbox.push(Output::Owned {
            stanza: reply,
            arena,
        });
        Ok(())
    }

    fn delivery(&self) -> RouterDelivery<A> {
        RouterDelivery::new(&self.router, &self.allocator, Some(&self.registration))
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

struct GetWork<A: ChunkAllocator> {
    account: AccountKey,
    transaction: RedbRead,
    handler: Arc<dyn IqHandler<A, RedbStorage>>,
    arena: Arena<A>,
    request: Stanza,
    sender: Jid,
    response: Arena<A>,
    delivery: RouterDelivery<A>,
}

struct GetOutcome<A: ChunkAllocator> {
    arena: Arena<A>,
    response: Arena<A>,
    reply: Result<Option<Element>, HandlerError>,
    /// Deliveries still queued when the ticket turned, written ahead of the reply.
    queued: Vec<MailboxEntry<A>>,
}

impl<A: ChunkAllocator + Clone> GetWork<A> {
    async fn run(self, queued: Vec<MailboxEntry<A>>) -> Result<GetOutcome<A>, CloseOutcome> {
        let GetWork {
            account,
            transaction,
            handler,
            arena,
            request,
            sender,
            mut response,
            delivery,
        } = self;
        let reply = {
            let sender = sender.resolve(&arena)?;
            let stanza = request.resolve(&arena)?;
            let target = stanza.to()?.unwrap_or_else(|| sender.bare());
            let payload = stanza
                .children()?
                .next()
                .transpose()?
                .ok_or(CloseOutcome::InternalError)?;
            let iq_request = IqRequest {
                sender,
                target,
                payload,
            };
            handler.get(iq_request, &transaction, &mut response).await
        };
        drop(transaction);
        let reply = match reply {
            Ok(IqReply { payload, effects }) => {
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
                Ok(payload)
            }
            Err(error) => {
                report_handler_failure(&error, &account);
                Err(error)
            }
        };
        Ok(GetOutcome {
            arena,
            response,
            reply,
            queued,
        })
    }
}

struct TerminalPresenceWork<A: ChunkAllocator> {
    session: SessionHandle<A>,
    router: RouterHandle<A>,
    storage: RedbStorage,
    account: AccountKey,
    fallback: RoutedStanza<A>,
}

impl<A: ChunkAllocator + Clone> TerminalPresenceWork<A> {
    async fn run(self) -> Result<(), CloseOutcome> {
        let withdrawal = self
            .session
            .end_presence()
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        if withdrawal.unavailable.is_none() {
            let directed =
                send_withdrawal(&self.router, &self.fallback, &withdrawal.directed, &[]).await;
            let finished = self
                .session
                .finish_presence(withdrawal.directed.source_token)
                .await
                .map_err(|_| CloseOutcome::InternalError);
            return directed.and(finished);
        }
        let notice = withdrawal.unavailable.as_ref().unwrap_or(&self.fallback);
        let mut covered = Vec::new();
        let mut ticket = None;
        let broadcast = async {
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
            let audience = match (handler, transaction.as_ref()) {
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
        .await;
        if let Some(ticket) = ticket.as_mut() {
            ticket.turn().await;
        }
        let directed = send_withdrawal(&self.router, notice, &withdrawal.directed, &covered).await;
        let finished = self
            .session
            .finish_presence(withdrawal.directed.source_token)
            .await
            .map_err(|_| CloseOutcome::InternalError);
        broadcast.and(directed).and(finished)
    }
}

async fn send_withdrawal<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    notice: &RoutedStanza<A>,
    withdrawal: &DirectedWithdrawal,
    covered: &[RosterJid],
) -> Result<(), CloseOutcome> {
    let recipients = withdrawal
        .recipients
        .iter()
        .map(|recipient| recipient.as_str())
        .filter(|recipient| {
            !covered
                .iter()
                .any(|subscriber| subscriber.as_str() == *recipient)
        });
    router
        .send_directed(notice, recipients)
        .await
        .map_err(|_| CloseOutcome::InternalError)
}

struct PresenceWork<A: ChunkAllocator> {
    session: SessionHandle<A>,
    router: RouterHandle<A>,
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
    async fn run(self) -> Result<PresenceOutcome<A>, CloseOutcome> {
        let PresenceWork {
            session,
            router,
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
        let directed = if !available {
            send_withdrawal(&router, &routed, &change.directed, &covered).await
        } else {
            Ok(())
        };
        change.directed.recipients.clear();
        broadcast.and(directed)?;
        Ok(PresenceOutcome {
            change,
            echo: routed,
            replay,
            requests,
            backlog,
        })
    }
}

fn stanza_bytes<A: ChunkAllocator>(stanza: &RoutedStanza<A>) -> Result<usize, CloseOutcome> {
    struct Counter(usize);
    impl std::fmt::Write for Counter {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            self.0 = self.0.checked_add(text.len()).ok_or(std::fmt::Error)?;
            Ok(())
        }
    }
    let mut counter = Counter(0);
    stanza
        .resolve()?
        .write_xml(&mut counter)
        .map_err(|_| CloseOutcome::InternalError)?;
    Ok(counter.0)
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
mod tests;
