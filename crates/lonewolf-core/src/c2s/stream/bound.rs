// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::mem;
use std::num::NonZeroUsize;
use std::pin::pin;

use futures_util::future::{Either, select};
use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::presence::{
    PresenceRequest, PresenceRequestType, PresenceTransition, PresenceUpdate,
};
use lonewolf_storage::roster::PendingSubscription;
use lonewolf_util::arena::{Arena, ArenaConfig, ArenaRead, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidRef};
use lonewolf_xmpp::parser::{Parsed, ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{
    CLIENT_NAMESPACE, IqType, MessageType, PresenceType, Stanza, StanzaErrorCondition,
    StanzaNamespace, StanzaRef, StanzaType,
};
use tokio::io::BufReader;

use super::bind::Bound;
use super::outcome::CloseOutcome;
use super::session::{Reader, Session, Writer, namespace_error};
use crate::c2s::iq;
use crate::delivery::RouterDelivery;
use crate::router::local::{ResourceDelivery, RetireCause};
use crate::router::{Registration, RoutedStanza, RouterError, RouterHandle};

const STORED_STANZA_STREAM_HEADER: &[u8] =
    b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>";

/// The bound resource's side of the stream: everything except the parser, which
/// stays outside so a pending read can be kept while stanzas are handled.
struct BoundSession<A: ChunkAllocator> {
    writer: Writer,
    registration: Registration<A>,
    router: RouterHandle<A>,
    allocator: A,
    /// Whether this resource currently has presence, mirroring the router's view.
    available: bool,
    pending_replays: VecDeque<Replay<A>>,
}

/// What a resource receives right after its own availability echo.
struct Replay<A: ChunkAllocator> {
    /// The contacts' current presence, captured while the subscription state was locked.
    presences: Vec<RoutedStanza<A>>,
    /// Subscription requests stored while no resource was available.
    requests: Vec<PendingSubscription>,
}

impl<A: ChunkAllocator> Default for Replay<A> {
    fn default() -> Self {
        Self {
            presences: Vec::new(),
            requests: Vec::new(),
        }
    }
}

pub(super) async fn bound_stream<A: ChunkAllocator + Clone>(bound: Bound<A>) -> CloseOutcome {
    let Bound {
        session: Session { mut reader, writer },
        registration,
        router,
        allocator,
        resource_requested: _,
    } = bound;
    let mut session = BoundSession {
        writer,
        registration,
        router,
        allocator,
        available: false,
        pending_replays: VecDeque::new(),
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
            session.writer.fail(CloseOutcome::AccountDeleted).await
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
                        if let Err(outcome) = self.deliver(delivery).await {
                            break 'stream outcome;
                        }
                    }
                    Either::Right(None) => break 'stream CloseOutcome::InternalError,
                }
            };
            match event {
                Ok(Some(StreamEvent::StreamEnd) | None) => break self.writer.close().await,
                Ok(Some(StreamEvent::Stanza(parsed))) => {
                    if let Err(outcome) = self.handle_stanza(parsed).await {
                        break self.writer.fail(outcome).await;
                    }
                }
                Ok(Some(event)) => {
                    let outcome =
                        namespace_error(&event).unwrap_or(CloseOutcome::UnsupportedStanzaType);
                    break self.writer.fail(outcome).await;
                }
                Err(outcome) => break self.writer.fail(outcome).await,
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
        let audience = match handler {
            None => None,
            Some(handler) => {
                let result = {
                    let view = unavailable.resolve()?;
                    let sender = view.from()?.ok_or(CloseOutcome::InternalError)?;
                    handler
                        .audience(PresenceUpdate {
                            sender,
                            transition: PresenceTransition::Unavailable,
                        })
                        .await
                };
                match result {
                    Ok(audience) => audience,
                    Err(_) => {
                        let _ = self.registration.finish_presence().await;
                        return Err(CloseOutcome::InternalError);
                    }
                }
            }
        };
        let result = match &audience {
            None => Ok(()),
            // The audience holds an ordering guard that blocks replacement updates until delivery ends.
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
        result.and(finished)
    }

    async fn deliver(&mut self, delivery: ResourceDelivery<A>) -> Result<(), CloseOutcome> {
        match delivery {
            ResourceDelivery::Routed(stanza) => self.writer.send_routed(&stanza).await,
            ResourceDelivery::Presence {
                stanzas,
                replay_pending,
            } => {
                for stanza in stanzas {
                    self.writer.send_routed(&stanza).await?;
                }
                if replay_pending {
                    let replay = self
                        .pending_replays
                        .pop_front()
                        .ok_or(CloseOutcome::InternalError)?;
                    for stanza in &replay.presences {
                        self.writer.send_routed(stanza).await?;
                    }
                    for subscription in replay.requests {
                        let stanza = self.parse_pending_subscription(subscription).await?;
                        self.writer.send_routed(&stanza).await?;
                    }
                }
                Ok(())
            }
        }
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

    async fn handle_iq(&mut self, parsed: Parsed<Stanza, A>) -> Result<(), CloseOutcome> {
        let (reply, arena) = iq::reply(parsed, &self.registration, &self.router, &self.allocator)
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        let reply = reply.resolve(&arena)?;
        self.writer.send_stanza(&reply).await
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
        let result = match self
            .router
            .presence_handlers(self.registration.account().domain())
            .and_then(|handlers| handlers.find(kind))
        {
            None => Ok(None),
            Some(handler) => {
                let sender = from.resolve(&arena)?;
                handler
                    .audience(PresenceUpdate { sender, transition })
                    .await
            }
        };
        let mut audience = match result {
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
        let broadcast_stanza = audience
            .as_ref()
            .is_some_and(|audience| !audience.subscribers.is_empty())
            .then(|| routed.clone());
        let change = self
            .registration
            .set_presence(priority, routed, unavailable)
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        self.available = priority.is_some();
        if change.became_available {
            // The audience still holds the ordering guard, so a contact captured here
            // cannot have revoked the subscription before its presence is written.
            let mut replay = Replay::default();
            if let Some(audience) = audience.as_mut() {
                for contact in &audience.contacts {
                    let presence = self
                        .router
                        .current_presence(contact, self.registration.account())
                        .await
                        .map_err(|_| CloseOutcome::InternalError)?;
                    replay.presences.extend(presence);
                }
                replay.requests = mem::take(&mut audience.pending);
            }
            self.pending_replays.push_back(replay);
        }
        if let Some(audience) = audience
            && (available || change.became_unavailable)
            && let Some(stanza) = broadcast_stanza
        {
            self.router
                .broadcast_presence(&stanza, &audience.subscribers)
                .await
                .map_err(|_| CloseOutcome::InternalError)?;
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
                    let delivery = self.delivery();
                    target_host
                        .receive(
                            PresenceRequest {
                                kind,
                                sender,
                                target,
                                stanza: &routed,
                            },
                            &delivery,
                        )
                        .await
                }
                None => Err(HandlerError::Stanza(
                    StanzaErrorCondition::ServiceUnavailable,
                )),
            }
        };
        match received {
            Ok(()) => Ok(()),
            Err(HandlerError::Stanza(condition)) => self.reply_error(&source, condition).await,
            Err(HandlerError::Delivery(_)) => Err(CloseOutcome::InternalError),
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
        let reply = reply.resolve(&arena)?;
        self.writer.send_stanza(&reply).await
    }

    fn delivery(&self) -> RouterDelivery<'_, A> {
        RouterDelivery {
            router: &self.router,
            allocator: &self.allocator,
            session: Some(&self.registration),
        }
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
                    .is_none_or(|target| target.as_str() != self.registration.account().as_str())
            {
                return Err(CloseOutcome::InternalError);
            }
        }
        Ok(RoutedStanza::from_parts(stanza, arena))
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
