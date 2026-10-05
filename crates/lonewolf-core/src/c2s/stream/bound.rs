// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::collections::VecDeque;
use std::future::Future;
use std::mem;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::SystemTime;

use futures_util::future::{Either, select};
use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::iq::{IqHandler, IqReply, IqRequest, IqRequestType, IqScope};
use lonewolf_extension::message::{Backlog, MessageHandler, StoreOutcome, UndeliverableMessage};
use lonewolf_extension::presence::{
    PresenceAudience, PresenceRequest, PresenceRequestType, PresenceTransition, PresenceUpdate,
};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::OfflineSequence;
use lonewolf_storage::roster::{PendingSubscription, RosterJid};
use lonewolf_storage::{RedbRead, RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, ArenaRead, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{Jid, JidError, JidRef};
use lonewolf_xmpp::parser::{ParseError, Parsed, ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{
    BuildError, CLIENT_NAMESPACE, Element, IqType, MessageType, PresenceType, RejectedStanza,
    Stanza, StanzaErrorCondition, StanzaNamespace, StanzaRef, StanzaType,
};

use super::bind::Bound;
use super::certificate::CertificateMonitor;
use super::close;
use super::outcome::CloseOutcome;
use super::session::{Reader, Session, Writer, namespace_error, peer_stream_error};
use crate::c2s::iq;
use crate::delivery::{
    Pending, RouterDelivery, StoredDelivery, WorkGroup, after_turn, commit_and_deliver,
    commit_and_store,
};
use crate::router::local::{DirectedWithdrawal, PresenceChange, RetireCause, SessionLiveness};
use crate::router::{Registration, RoutedStanza, RouterError, RouterHandle, SessionHandle};

const STORED_STANZA_STREAM_HEADER: &[u8] =
    b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>";

/// The parser stays outside this state so stanza handling preserves a pending read.
struct BoundSession<'w, A: ChunkAllocator> {
    registration: Registration<A>,
    router: RouterHandle<A>,
    storage: RedbStorage,
    allocator: A,
    available: bool,
    priority: Option<i8>,
    outbox: Outbox<'w, A>,
}

struct Outbox<'w, A: ChunkAllocator, W = Writer> {
    queue: VecDeque<Output<A>>,
    writer: W,
    allocator: A,
    account: AccountKey,
    storage: RedbStorage,
    liveness: SessionLiveness,
    acknowledgement: Option<ReplayAcknowledgement>,
    work: &'w WorkGroup,
    certificate: Option<&'w CertificateMonitor>,
}

struct ReplayAcknowledgement {
    through: Rc<Cell<OfflineSequence>>,
    task: compio::runtime::JoinHandle<()>,
    #[cfg(test)]
    entered: futures_channel::oneshot::Receiver<()>,
}

enum Output<A: ChunkAllocator> {
    Routed(RoutedStanza<A>),
    Owned {
        stanzas: Vec<Stanza>,
        arena: Arena<A>,
    },
    /// Parse each request at write time to keep large backlogs out of memory.
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

trait OutboxWriter {
    async fn write_stanza<R: ArenaRead>(
        &mut self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<(), CloseOutcome>;

    async fn flush(&mut self) -> Result<(), CloseOutcome>;

    async fn write_routed<A: ChunkAllocator>(
        &mut self,
        stanza: &RoutedStanza<A>,
    ) -> Result<(), CloseOutcome> {
        self.write_stanza(&stanza.resolve()?).await
    }
}

impl OutboxWriter for Writer {
    async fn write_stanza<R: ArenaRead>(
        &mut self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<(), CloseOutcome> {
        Writer::write_stanza(self, stanza).await
    }

    async fn flush(&mut self) -> Result<(), CloseOutcome> {
        Writer::flush(self).await
    }

    async fn write_routed<A: ChunkAllocator>(
        &mut self,
        stanza: &RoutedStanza<A>,
    ) -> Result<(), CloseOutcome> {
        Writer::write_routed(self, stanza).await
    }
}

pub(super) async fn bound_stream<A: ChunkAllocator + Clone>(
    bound: Bound<A>,
    work: &mut WorkGroup,
) -> CloseOutcome {
    let Bound {
        session: Session {
            mut reader,
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
    let outbox = Outbox {
        queue: VecDeque::new(),
        writer,
        allocator: allocator.clone(),
        account: registration.account().clone(),
        storage: storage.clone(),
        liveness: registration.liveness(),
        acknowledgement: None,
        work,
        certificate: monitor.as_ref(),
    };
    let mut session = BoundSession {
        registration,
        router,
        storage,
        allocator,
        available: false,
        priority: None,
        outbox,
    };
    let stopped = {
        let retired = pin!(session.registration.wait_retired());
        match select(
            retired,
            pin!(close.interrupt(async {
                let operation = async { Ok(session.run(&mut reader).await) };
                match &monitor {
                    Some(monitor) => monitor.interrupt(operation).await,
                    None => operation.await,
                }
            })),
        )
        .await
        {
            Either::Left((retired, _)) => Either::Left(retired.map(|retired| retired.cause)),
            Either::Right((outcome, _)) => Either::Right(outcome.unwrap_or_else(|outcome| outcome)),
        }
    };
    let outcome = match stopped {
        Either::Right(outcome) => outcome,
        Either::Left(Ok(RetireCause::AccountDeleted)) => CloseOutcome::AccountDeleted,
        Either::Left(_) => CloseOutcome::InternalError,
    };
    let deadline = close.deadline();
    let (mut writer, acknowledgement, outcome) = close
        .cleanup(deadline, async {
            let ended = session.end().await;
            let outcome = ended.map_or(CloseOutcome::InternalError, |()| outcome);
            let BoundSession {
                registration,
                outbox,
                ..
            } = session;
            drop(registration);
            let Outbox {
                writer,
                acknowledgement,
                ..
            } = outbox;
            (writer, acknowledgement, outcome)
        })
        .await;
    close.cleanup(deadline, work.drain()).await;
    drop(acknowledgement);
    close::finish(&mut reader, &mut writer, outcome.into(), &close, deadline).await
}

impl<A: ChunkAllocator + Clone> BoundSession<'_, A> {
    async fn run(&mut self, reader: &mut Reader<A>) -> CloseOutcome {
        let mut prefer_outbound = true;
        'stream: loop {
            if let Err(outcome) = self.outbox.check_certificate() {
                break outcome;
            }
            let mut next = pin!(reader.next_event());
            let event = loop {
                let selected = {
                    let receive = pin!(self.registration.recv());
                    if prefer_outbound {
                        match select(receive, next.as_mut()).await {
                            Either::Left((stanza, _)) => Either::Right(stanza),
                            Either::Right((event, _)) => Either::Left(event),
                        }
                    } else {
                        match select(next.as_mut(), receive).await {
                            Either::Left((event, _)) => Either::Left(event),
                            Either::Right((stanza, _)) => Either::Right(stanza),
                        }
                    }
                };
                prefer_outbound = !prefer_outbound;
                match selected {
                    Either::Left(event) => break event,
                    Either::Right(Some(delivery)) => {
                        if let Err(outcome) = self
                            .outbox
                            .drain_mailbox(&self.registration, delivery)
                            .await
                        {
                            break 'stream outcome;
                        }
                    }
                    Either::Right(None) => break 'stream CloseOutcome::InternalError,
                }
            };
            if let Err(outcome) = self.outbox.check_certificate() {
                break outcome;
            }
            match event {
                Ok(Some(StreamEvent::StreamEnd) | None) => break CloseOutcome::StreamEnd,
                Ok(Some(StreamEvent::Stanza(parsed))) => {
                    let handled = self.handle_stanza(parsed).await;
                    let flushed = self.outbox.flush().await;
                    if let Err(outcome) = handled.and(flushed) {
                        break outcome;
                    }
                }
                Ok(Some(StreamEvent::RejectedStanza(parsed))) => {
                    let handled = self.handle_rejected(parsed);
                    let flushed = self.outbox.flush().await;
                    if let Err(outcome) = handled.and(flushed) {
                        break outcome;
                    }
                }
                Ok(Some(event)) => {
                    match peer_stream_error(&event) {
                        Ok(Some(condition)) => break CloseOutcome::PeerError(condition),
                        Err(outcome) => break outcome,
                        Ok(None) => {}
                    }
                    let outcome =
                        namespace_error(&event).unwrap_or(CloseOutcome::UnsupportedStanzaType);
                    break outcome;
                }
                Err(outcome) => break outcome,
            }
        }
    }

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
            stanzas: vec![reply],
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
            StanzaType::Iq(IqType::Get | IqType::Set) => self.handle_iq(parsed).await,
            StanzaType::Iq(IqType::Result | IqType::Error) => Ok(()),
            StanzaType::Presence(kind) => {
                let directed = stanza.to()?.is_some();
                self.handle_presence(parsed, kind, directed).await
            }
            StanzaType::Message(kind) => self.handle_message(parsed, kind).await,
        }
    }

    /// Detached work owns commit and delivery, so retiring this session cannot cancel them.
    async fn handle_iq(&mut self, parsed: Parsed<Stanza, A>) -> Result<(), CloseOutcome> {
        let (request, mut arena) = parsed.into_parts();
        let route = iq::route(&request, &mut arena, &self.registration)?;
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
            let handler = route.scope.and_then(|scope| {
                self.router.iq_handlers(target.domainpart())?.find(
                    scope,
                    route.kind,
                    payload.namespace(),
                    payload.name(),
                )
            });
            let accounts = match route.scope {
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
                stanzas: vec![reply],
                arena,
            });
            return Ok(());
        };
        match route.kind {
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

    async fn handle_iq_get(
        &mut self,
        request: Stanza,
        sender: Jid,
        arena: Arena<A>,
        response: Arena<A>,
        handler: Arc<dyn IqHandler<A, RedbStorage>>,
        accounts: Vec<AccountKey>,
    ) -> Result<(), CloseOutcome> {
        let (transaction, ticket) = Arc::clone(self.router.order())
            .fix(accounts, self.storage.begin_read())
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        let work = GetWork {
            transaction,
            handler,
            arena,
            request,
            sender,
            response,
            delivery: self.delivery(),
        };
        let mut pending = after_turn(
            self.outbox.work.start(),
            ticket,
            Some(self.registration.mailbox()),
            move |queued| work.run(queued),
        );
        self.outbox
            .drain_until(&self.registration, pending.turned())
            .await?;
        let outcome = pending
            .finished()
            .await
            .ok_or(CloseOutcome::InternalError)??;
        self.outbox.routed(outcome.queued);
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
        let mut transaction = self
            .storage
            .begin_write()
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        let delivery = self.delivery();
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
            handler
                .set(iq_request, &mut transaction, &delivery, &mut response)
                .await
        };
        let reply = match reply {
            Ok(IqReply { payload, effects }) => {
                let mut committed = commit_and_deliver(
                    self.outbox.work.start(),
                    Arc::clone(self.router.order()),
                    transaction,
                    effects,
                    delivery,
                    Some(self.registration.mailbox()),
                );
                self.outbox
                    .drain_until(&self.registration, committed.turned())
                    .await?;
                let queued = committed
                    .finished()
                    .await
                    .ok_or(CloseOutcome::InternalError)?
                    .map_err(|_| CloseOutcome::InternalError)?;
                self.outbox.routed(queued);
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
            Err(HandlerError::Stanza(condition)) => {
                let reply = iq::error_reply(&request, &mut arena, condition, Some(sender))?;
                self.outbox.push(Output::Owned {
                    stanzas: vec![reply],
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
                    stanzas: vec![reply],
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
                .map_err(|_| RouterError::Unavailable)?;
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
                    .map_err(|_| RouterError::Unavailable)?,
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
            session.directed_presence(routed, available).await
        });
        self.outbox
            .drain_until(&self.registration, pending.finished())
            .await?
            .ok_or(CloseOutcome::InternalError)?
            .map_err(|_| CloseOutcome::InternalError)
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
            return self
                .reply_error(&routed, StanzaErrorCondition::ServiceUnavailable)
                .await;
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
                RouterError::Busy | RouterError::ResourceLimit => {
                    StanzaErrorCondition::ResourceConstraint
                }
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
            self.reply_error(&routed, condition).await?;
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
            return self
                .reply_error(&routed, StanzaErrorCondition::ServiceUnavailable)
                .await;
        };
        let bytes = if tracing::enabled!(tracing::Level::INFO) {
            stanza_bytes(&routed)?
        } else {
            0
        };
        let mut transaction = self
            .storage
            .begin_write()
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        let mut scratch = Arena::try_new_in(ArenaConfig::default(), self.allocator.clone())?;
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
        match outcome {
            Err(HandlerError::Stanza(condition)) => {
                drop(transaction);
                self.reply_error(&routed, condition).await
            }
            Ok(StoreOutcome::Discarded) => {
                drop(transaction);
                Ok(())
            }
            Ok(StoreOutcome::Stored(sequence)) => {
                let pending = commit_and_store(
                    self.outbox.work.start(),
                    self.router.clone(),
                    self.storage.clone(),
                    transaction,
                    handler,
                    StoredDelivery {
                        recipient,
                        sequence,
                        stanza: routed,
                        bytes,
                    },
                );
                self.outbox
                    .drain_until(&self.registration, pending.finished())
                    .await?
                    .ok_or(CloseOutcome::InternalError)?
                    .map_err(|_| CloseOutcome::InternalError)
            }
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
                    return self.reply_error(&routed, condition).await;
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
        let (result, ticket) =
            if presence_handler.is_some() || (candidate && message_handler.is_some()) {
                let owner = self.registration.account();
                let (transaction, ticket) = Arc::clone(self.router.order())
                    .fix(vec![owner.clone()], self.storage.begin_read())
                    .await
                    .map_err(|_| CloseOutcome::InternalError)?;
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
                (result, ticket)
            } else {
                let ((), ticket) = self
                    .router
                    .order()
                    .fix(vec![self.registration.account().clone()], async {
                        Ok::<_, CloseOutcome>(())
                    })
                    .await?;
                (Ok((None, None)), ticket)
            };
        let (audience, backlog) = match result {
            Ok(result) => result,
            Err(condition) => {
                let routed = RoutedStanza::from_parts(stamped, arena);
                return self.reply_error(&routed, condition).await;
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
            session: self.registration.handle(),
            router: self.router.clone(),
            account: self.registration.account().clone(),
            priority,
            available,
            routed,
            unavailable,
            audience,
            backlog,
        };
        let mut pending = after_turn(
            self.outbox.work.start(),
            ticket,
            None,
            move |_: Vec<RoutedStanza<A>>| work.run(),
        );
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
        self.outbox.routed(outcome.change.preceding);
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

    /// Authorizes on the sender's host, then applies on the target's host.
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
            sender_host
                .authorize(PresenceRequest {
                    kind,
                    sender,
                    target,
                    stanza: &source,
                })
                .await
        };
        if let Err(condition) = authorized {
            return self.reply_error(&source, condition).await;
        }
        let received = {
            let (sender, target) = presence_addresses(&routed)?;
            match self
                .router
                .presence_handlers(target.domainpart())
                .and_then(|handlers| handlers.find(kind))
            {
                Some(target_host) => {
                    let mut transaction = self
                        .storage
                        .begin_write()
                        .await
                        .map_err(|_| CloseOutcome::InternalError)?;
                    let delivery = self.delivery();
                    let effects = target_host
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
                        .await;
                    match effects {
                        Ok(effects) => Ok(commit_and_deliver(
                            self.outbox.work.start(),
                            Arc::clone(self.router.order()),
                            transaction,
                            effects,
                            delivery,
                            Some(self.registration.mailbox()),
                        )),
                        Err(error) => Err(error),
                    }
                }
                None => Err(HandlerError::Stanza(
                    StanzaErrorCondition::ServiceUnavailable,
                )),
            }
        };
        match received {
            Ok(mut committed) => {
                self.outbox
                    .drain_until(&self.registration, committed.turned())
                    .await?;
                let queued = committed
                    .finished()
                    .await
                    .ok_or(CloseOutcome::InternalError)?
                    .map_err(|_| CloseOutcome::InternalError)?;
                self.outbox.routed(queued);
                Ok(())
            }
            Err(HandlerError::Stanza(condition)) => self.reply_error(&source, condition).await,
        }
    }

    async fn reply_error(
        &mut self,
        source: &RoutedStanza<A>,
        condition: StanzaErrorCondition,
    ) -> Result<(), CloseOutcome> {
        let mut arena = Arena::try_new_in(Default::default(), self.allocator.clone())?;
        let source = source.resolve()?.clone_in(&mut arena)?;
        let reply = source.error_reply_in(&mut arena, condition)?.build()?;
        self.outbox.push(Output::Owned {
            stanzas: vec![reply],
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

impl<A: ChunkAllocator + Clone, W: OutboxWriter> Outbox<'_, A, W> {
    fn check_certificate(&self) -> Result<(), CloseOutcome> {
        self.certificate.map_or(Ok(()), CertificateMonitor::check)
    }
    fn push(&mut self, output: Output<A>) {
        self.queue.push_back(output);
    }

    fn routed(&mut self, stanzas: impl IntoIterator<Item = RoutedStanza<A>>) {
        self.queue.extend(stanzas.into_iter().map(Output::Routed));
    }

    async fn drain_mailbox(
        &mut self,
        registration: &Registration<A>,
        first: RoutedStanza<A>,
    ) -> Result<(), CloseOutcome> {
        self.push(Output::Routed(first));
        self.routed(registration.take_queued());
        self.flush().await
    }

    /// Drain while work is pending to avoid evicting a client that keeps reading.
    /// Poll `until` first to leave deliveries after its cut in the mailbox.
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
                    self.drain_mailbox(registration, delivery).await?;
                }
                Either::Right(None) => return Err(CloseOutcome::InternalError),
            }
        }
    }

    async fn flush(&mut self) -> Result<(), CloseOutcome> {
        if self.queue.is_empty() {
            return Ok(());
        }
        let mut acknowledgement: Option<(
            Arc<dyn MessageHandler<A, RedbStorage>>,
            OfflineSequence,
        )> = None;
        let mut offline_replay = false;
        let mut messages_written = 0usize;
        let mut messages_skipped = 0usize;
        let mut pending_count = 0usize;
        while let Some(output) = self.queue.pop_front() {
            match output {
                Output::Routed(stanza) => {
                    self.check_certificate()?;
                    self.writer.write_routed(&stanza).await?;
                }
                Output::Owned { stanzas, arena } => {
                    for stanza in &stanzas {
                        let stanza = stanza.resolve(&arena)?;
                        self.check_certificate()?;
                        self.writer.write_stanza(&stanza).await?;
                    }
                }
                Output::Requests(requests) => {
                    for subscription in requests {
                        let stanza = self
                            .parse_stored(
                                &subscription.stanza,
                                StoredKind::Subscription(&subscription.sender),
                            )
                            .await?;
                        self.check_certificate()?;
                        self.writer.write_routed(&stanza).await?;
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
                                self.check_certificate()?;
                                self.writer.write_routed(&stanza).await?;
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
                    let through = acknowledgement
                        .as_ref()
                        .map_or(backlog.through, |(_, through)| {
                            (*through).max(backlog.through)
                        });
                    acknowledgement = Some((handler, through));
                }
            }
        }
        self.check_certificate()?;
        self.writer.flush().await?;
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
        if let Some((handler, through)) = acknowledgement {
            self.acknowledge(handler, through);
        }
        Ok(())
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
                tracing::error!(error = ?error, "offline backlog acknowledgement failed");
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

async fn acknowledge_backlog<A: ChunkAllocator>(
    storage: &RedbStorage,
    account: &AccountKey,
    liveness: &SessionLiveness,
    handler: &dyn MessageHandler<A, RedbStorage>,
    watermark: &Cell<OfflineSequence>,
) -> Result<(), HandlerError> {
    loop {
        let mut transaction = storage
            .begin_write()
            .await
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
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
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
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
    queued: Vec<RoutedStanza<A>>,
}

impl<A: ChunkAllocator + Clone> GetWork<A> {
    async fn run(self, queued: Vec<RoutedStanza<A>>) -> Result<GetOutcome<A>, CloseOutcome> {
        let GetWork {
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
                (effects.deliver)(&delivery)
                    .await
                    .map_err(|_| CloseOutcome::InternalError)?;
                Ok(payload)
            }
            Err(error) => Err(error),
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
                        Some(_) => self
                            .storage
                            .begin_read()
                            .await
                            .map(Some)
                            .map_err(|_| CloseOutcome::InternalError),
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
                        .map_err(|_| CloseOutcome::InternalError)?
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

#[cfg(test)]
mod tests;
