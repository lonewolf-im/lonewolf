// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::future::Future;
use std::mem;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::Arc;

use futures_util::future::{Either, select};
use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::iq::{IqHandler, IqReply, IqRequest, IqRequestType, IqScope};
use lonewolf_extension::presence::{
    PresenceAudience, PresenceRequest, PresenceRequestType, PresenceTransition, PresenceUpdate,
};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::PendingSubscription;
use lonewolf_storage::{RedbRead, RedbStorage, Storage};
use lonewolf_util::arena::{Arena, ArenaConfig, ArenaRead, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidRef};
use lonewolf_xmpp::parser::{Parsed, ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{
    CLIENT_NAMESPACE, Element, IqType, MessageType, PresenceType, Stanza, StanzaErrorCondition,
    StanzaNamespace, StanzaRef, StanzaType,
};
use tokio::io::BufReader;

use super::bind::Bound;
use super::outcome::CloseOutcome;
use super::session::{Reader, Session, Writer, namespace_error};
use crate::c2s::iq;
use crate::delivery::{RouterDelivery, after_turn, commit_and_deliver};
use crate::router::local::{PresenceChange, RetireCause};
use crate::router::{Registration, RoutedStanza, RouterError, RouterHandle, SessionHandle};

const STORED_STANZA_STREAM_HEADER: &[u8] =
    b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>";

/// The bound resource's side of the stream: everything except the parser, which
/// stays outside so a pending read can be kept while stanzas are handled.
struct BoundSession<A: ChunkAllocator> {
    registration: Registration<A>,
    router: RouterHandle<A>,
    storage: RedbStorage,
    allocator: A,
    /// Whether this resource currently has presence, mirroring the router's view.
    available: bool,
    outbox: Outbox<A>,
}

/// The session's output path: everything the client has yet to receive, in order, and
/// the writer that only it uses.
struct Outbox<A: ChunkAllocator> {
    queue: VecDeque<Output<A>>,
    writer: Writer,
    allocator: A,
    account: AccountKey,
}

enum Output<A: ChunkAllocator> {
    Routed(RoutedStanza<A>),
    /// Stanzas built by this session in one arena, written in order.
    Owned {
        stanzas: Vec<Stanza>,
        arena: Arena<A>,
    },
    /// Stored subscription requests, parsed one at a time as they are written so a large
    /// backlog never sits in memory at once.
    Requests(Vec<PendingSubscription>),
}

pub(super) async fn bound_stream<A: ChunkAllocator + Clone>(bound: Bound<A>) -> CloseOutcome {
    let Bound {
        session: Session { mut reader, writer },
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
    };
    let mut session = BoundSession {
        registration,
        router,
        storage,
        allocator,
        available: false,
        outbox,
    };
    let stopped = {
        let retired = pin!(session.registration.wait_retired());
        match select(retired, pin!(session.run(&mut reader))).await {
            Either::Left((retired, _)) => Either::Left(retired.map(|retired| retired.cause)),
            Either::Right((outcome, _)) => Either::Right(outcome),
        }
    };
    let outcome = match stopped {
        Either::Right(outcome) => outcome,
        Either::Left(Ok(RetireCause::AccountDeleted)) => {
            session
                .outbox
                .writer
                .fail(CloseOutcome::AccountDeleted)
                .await
        }
        Either::Left(_) => CloseOutcome::InternalError,
    };
    let ended = session.end().await;
    drop(session);
    ended.map_or(CloseOutcome::InternalError, |()| outcome)
}

impl<A: ChunkAllocator + Clone> BoundSession<A> {
    /// Alternates between client stanzas and router deliveries until the stream ends.
    async fn run(&mut self, reader: &mut Reader<A>) -> CloseOutcome {
        let mut prefer_outbound = true;
        'stream: loop {
            // Cancelling an in-progress parser read can lose buffered XML.
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
            match event {
                Ok(Some(StreamEvent::StreamEnd) | None) => break self.outbox.writer.close().await,
                Ok(Some(StreamEvent::Stanza(parsed))) => {
                    let handled = self.handle_stanza(parsed).await;
                    let flushed = self.outbox.flush().await;
                    if let Err(outcome) = handled.and(flushed) {
                        break self.outbox.writer.fail(outcome).await;
                    }
                }
                Ok(Some(event)) => {
                    let outcome =
                        namespace_error(&event).unwrap_or(CloseOutcome::UnsupportedStanzaType);
                    break self.outbox.writer.fail(outcome).await;
                }
                Err(outcome) => break self.outbox.writer.fail(outcome).await,
            }
        }
    }

    /// Withdraws the resource's presence and broadcasts it to the account's subscribers.
    async fn end(&self) -> Result<(), CloseOutcome> {
        let unavailable = match self.registration.end_presence().await {
            Ok(Some(unavailable)) => unavailable,
            Ok(None) | Err(RouterError::NotFound) => return Ok(()),
            Err(_) => return Err(CloseOutcome::InternalError),
        };
        let handler = self
            .router
            .presence_handlers(self.registration.account().domain())
            .and_then(|handlers| handlers.find(PresenceRequestType::Unavailable));
        let (audience, mut ticket) = match handler {
            None => (None, None),
            Some(handler) => {
                let owner = self.registration.account().clone();
                let fixed = Arc::clone(self.router.order())
                    .fix(vec![owner], self.storage.begin_read())
                    .await;
                let result = match fixed {
                    Ok((transaction, ticket)) => {
                        let view = unavailable.resolve()?;
                        let sender = view.from()?.ok_or(CloseOutcome::InternalError)?;
                        handler
                            .audience(
                                PresenceUpdate {
                                    sender,
                                    transition: PresenceTransition::Unavailable,
                                },
                                &transaction,
                            )
                            .await
                            .map(|audience| (audience, ticket))
                    }
                    Err(_) => Err(StanzaErrorCondition::InternalServerError),
                };
                match result {
                    Ok((audience, ticket)) => (audience, Some(ticket)),
                    Err(_) => {
                        let _ = self.registration.finish_presence().await;
                        return Err(CloseOutcome::InternalError);
                    }
                }
            }
        };
        if let Some(ticket) = ticket.as_mut() {
            ticket.turn().await;
        }
        let result = match &audience {
            None => Ok(()),
            // The ticket keeps replacement updates behind this broadcast until it ends.
            Some(audience) => match self.registration.replacement_is_available().await {
                Ok(true) => Ok(()),
                Ok(false) => self
                    .router
                    .broadcast_presence(&unavailable, &audience.subscribers)
                    .await
                    .map_err(|_| CloseOutcome::InternalError),
                Err(_) => Err(CloseOutcome::InternalError),
            },
        };
        let finished = self
            .registration
            .finish_presence()
            .await
            .map_err(|_| CloseOutcome::InternalError);
        drop(audience);
        drop(ticket);
        result.and(finished)
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

    /// Answers an IQ from one fixed view of storage: a snapshot for a get, a committed
    /// transaction for a set. Everything a ticket orders runs on a task of its own, and so
    /// does a set's commit, so retiring the session cannot lose a change that landed and
    /// a stalled socket holds no account's line. Meanwhile the session drains its mailbox, and it
    /// writes the reply afterwards, behind whatever preceded the ticket's turn.
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
        let mut pending = after_turn(ticket, Some(self.registration.mailbox()), move |queued| {
            work.run(queued)
        });
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

    /// Queues the result, or the error reply, behind whatever the outbox already holds.
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

    /// Directed presence only enters subscription handling; other directed presence is dropped.
    async fn handle_presence(
        &mut self,
        parsed: Parsed<Stanza, A>,
        kind: PresenceType,
        directed: bool,
    ) -> Result<(), CloseOutcome> {
        if directed {
            return match PresenceRequestType::from_subscription_stanza(kind) {
                Some(kind) => self.handle_subscription(parsed, kind).await,
                None => Ok(()),
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
            {
                return Ok(());
            }
            let condition = match error {
                RouterError::Busy | RouterError::ResourceLimit => {
                    StanzaErrorCondition::ResourceConstraint
                }
                RouterError::InvalidTarget | RouterError::InvalidResource => {
                    StanzaErrorCondition::BadRequest
                }
                RouterError::NotFound | RouterError::RemoteUnsupported => {
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
        let (result, ticket) = match self
            .router
            .presence_handlers(self.registration.account().domain())
            .and_then(|handlers| handlers.find(kind))
        {
            None => (Ok(None), None),
            Some(handler) => {
                let owner = self.registration.account().clone();
                let (transaction, ticket) = Arc::clone(self.router.order())
                    .fix(vec![owner], self.storage.begin_read())
                    .await
                    .map_err(|_| CloseOutcome::InternalError)?;
                let sender = from.resolve(&arena)?;
                let result = handler
                    .audience(PresenceUpdate { sender, transition }, &transaction)
                    .await;
                (result, Some(ticket))
            }
        };
        let audience = match result {
            Ok(audience) => audience,
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
        };
        let outcome = match ticket {
            Some(ticket) => {
                let mut pending =
                    after_turn(ticket, None, move |_: Vec<RoutedStanza<A>>| work.run());
                self.outbox
                    .drain_until(&self.registration, pending.turned())
                    .await?;
                pending
                    .finished()
                    .await
                    .ok_or(CloseOutcome::InternalError)??
            }
            None => work.run().await?,
        };
        self.available = priority.is_some();
        // The router takes the cut with the update itself, so without a ticket a
        // sibling's earlier update still lands ahead of this echo.
        self.outbox.routed(outcome.change.preceding);
        self.outbox.routed(outcome.change.siblings);
        self.outbox.push(Output::Routed(outcome.echo));
        self.outbox.routed(outcome.replay);
        if !outcome.requests.is_empty() {
            self.outbox.push(Output::Requests(outcome.requests));
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

    /// Stamps the authenticated full JID as `from` and, when asked, the bare JID as `to`.
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

impl<A: ChunkAllocator + Clone> Outbox<A> {
    fn push(&mut self, output: Output<A>) {
        self.queue.push_back(output);
    }

    fn routed(&mut self, stanzas: impl IntoIterator<Item = RoutedStanza<A>>) {
        self.queue.extend(stanzas.into_iter().map(Output::Routed));
    }

    /// Queues one delivery and everything else the mailbox already holds, then writes
    /// the batch in one go.
    async fn drain_mailbox(
        &mut self,
        registration: &Registration<A>,
        first: RoutedStanza<A>,
    ) -> Result<(), CloseOutcome> {
        self.push(Output::Routed(first));
        self.routed(registration.take_queued());
        self.flush().await
    }

    /// Writes deliveries as they arrive until `until` resolves, so a session waiting for
    /// its turn keeps draining its mailbox. The ticket the request took lives on a task of
    /// its own, so a write that stalls here holds no account's line; a client that stops
    /// reading fills its mailbox and is evicted as usual. `until` is polled first, so
    /// nothing that arrives after it resolves is taken.
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

    /// Writes everything queued, in order, and flushes the socket once.
    async fn flush(&mut self) -> Result<(), CloseOutcome> {
        if self.queue.is_empty() {
            return Ok(());
        }
        while let Some(output) = self.queue.pop_front() {
            match output {
                Output::Routed(stanza) => self.writer.write_routed(&stanza).await?,
                Output::Owned { stanzas, arena } => {
                    for stanza in &stanzas {
                        let stanza = stanza.resolve(&arena)?;
                        self.writer.write_stanza(&stanza).await?;
                    }
                }
                Output::Requests(requests) => {
                    for subscription in requests {
                        let stanza = self.parse_pending_subscription(subscription).await?;
                        self.writer.write_routed(&stanza).await?;
                    }
                }
            }
        }
        self.writer.flush().await
    }

    /// Parses a stored request and checks it still addresses this account from its sender.
    async fn parse_pending_subscription(
        &self,
        subscription: PendingSubscription,
    ) -> Result<RoutedStanza<A>, CloseOutcome> {
        let stanza_bytes = subscription.stanza.as_ref();
        let max_stanza_bytes =
            NonZeroUsize::new(stanza_bytes.len()).ok_or(CloseOutcome::InternalError)?;
        let input = tokio::io::AsyncReadExt::chain(STORED_STANZA_STREAM_HEADER, stanza_bytes);
        let mut parser = XmppParser::new(
            BufReader::new(input),
            ParserConfig {
                max_stanza_bytes,
                arena: ArenaConfig::default(),
            },
            self.allocator.clone(),
        );
        if !matches!(
            parser.next_event().await,
            Ok(Some(StreamEvent::StreamStart { .. }))
        ) {
            return Err(CloseOutcome::InternalError);
        }
        let parsed = match parser.next_event().await {
            Ok(Some(StreamEvent::Stanza(parsed))) => parsed,
            _ => return Err(CloseOutcome::InternalError),
        };
        let (stanza, arena) = parsed.into_parts();
        {
            let stanza = stanza.resolve(&arena)?;
            if stanza.namespace() != StanzaNamespace::Client
                || stanza.stanza_type() != StanzaType::Presence(PresenceType::Subscribe)
                || stanza
                    .from()?
                    .is_none_or(|sender| sender.as_str() != subscription.sender.as_str())
                || stanza
                    .to()?
                    .is_none_or(|target| target.as_str() != self.account.as_str())
            {
                return Err(CloseOutcome::InternalError);
            }
        }
        Ok(RoutedStanza::from_parts(stanza, arena))
    }
}

/// A get from the moment its ticket turns: the handler runs on the snapshot, its effects
/// run, and the reply goes back to the session to write.
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

/// A presence update from the moment its ticket turns: the router applies it and takes
/// the cut, the replay for a newly available resource is gathered, and the subscribers
/// are told.
struct PresenceWork<A: ChunkAllocator> {
    session: SessionHandle<A>,
    router: RouterHandle<A>,
    account: AccountKey,
    priority: Option<i8>,
    available: bool,
    routed: RoutedStanza<A>,
    unavailable: Option<RoutedStanza<A>>,
    audience: Option<PresenceAudience>,
}

struct PresenceOutcome<A: ChunkAllocator> {
    change: PresenceChange<A>,
    echo: RoutedStanza<A>,
    /// The contacts' current presence for a resource that just became available.
    replay: Vec<RoutedStanza<A>>,
    requests: Vec<PendingSubscription>,
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
        } = self;
        let change = session
            .set_presence(priority, routed.clone(), unavailable)
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        let mut replay = Vec::new();
        let mut requests = Vec::new();
        if change.became_available
            && let Some(audience) = audience.as_mut()
        {
            // The ticket is still held, so a contact captured here cannot have revoked the
            // subscription before its presence is written.
            for contact in &audience.contacts {
                let presence = router
                    .current_presence(contact, &account)
                    .await
                    .map_err(|_| CloseOutcome::InternalError)?;
                replay.extend(presence);
            }
            requests = mem::take(&mut audience.pending);
        }
        if let Some(audience) = audience
            && (available || change.became_unavailable)
            && !audience.subscribers.is_empty()
        {
            router
                .broadcast_presence(&routed, &audience.subscribers)
                .await
                .map_err(|_| CloseOutcome::InternalError)?;
        }
        Ok(PresenceOutcome {
            change,
            echo: routed,
            replay,
            requests,
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
