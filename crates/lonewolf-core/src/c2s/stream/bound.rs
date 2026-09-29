// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::mem;
use std::num::NonZeroUsize;
use std::pin::pin;

use futures_util::future::{Either, select};
use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::presence::{PresenceRequest, PresenceRequestType, PresenceUpdate};
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
use super::session::{Writer, namespace_error};
use crate::c2s::delivery::StreamDelivery;
use crate::c2s::iq;
use crate::router::local::ResourceDelivery;
use crate::router::{Registration, RoutedStanza, RouterError, RouterHandle};

const STORED_STANZA_STREAM_HEADER: &[u8] =
    b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>";

pub(super) async fn bound_stream<A: ChunkAllocator + Clone>(bound: Bound<A>) -> CloseOutcome {
    let Bound {
        mut session,
        registration,
        router,
        allocator,
        resource_requested: _,
    } = bound;
    let mut pending_replays = VecDeque::new();
    let mut prefer_outbound = true;
    let stream = async {
        'stream: loop {
            // Cancelling an in-progress parser read can lose buffered XML.
            let mut next = pin!(session.reader.next_event());
            let event = loop {
                let receive = pin!(registration.recv());
                let selected = if prefer_outbound {
                    match select(receive, next.as_mut()).await {
                        Either::Left((stanza, _)) => Either::Right(stanza),
                        Either::Right((event, _)) => Either::Left(event),
                    }
                } else {
                    match select(next.as_mut(), receive).await {
                        Either::Left((event, _)) => Either::Left(event),
                        Either::Right((stanza, _)) => Either::Right(stanza),
                    }
                };
                prefer_outbound = !prefer_outbound;
                match selected {
                    Either::Left(event) => break event,
                    Either::Right(Some(delivery)) => {
                        if let Err(outcome) = write_resource_delivery(
                            &mut session.writer,
                            delivery,
                            &mut pending_replays,
                            &registration,
                            &allocator,
                        )
                        .await
                        {
                            break 'stream outcome;
                        }
                    }
                    Either::Right(None) => break 'stream CloseOutcome::InternalError,
                }
            };
            match event {
                Ok(Some(StreamEvent::StreamEnd) | None) => break session.writer.close().await,
                Ok(Some(StreamEvent::Stanza(parsed))) => {
                    if let Err(outcome) = handle_bound_stanza(
                        parsed,
                        &mut session.writer,
                        &registration,
                        &router,
                        &allocator,
                        &mut pending_replays,
                    )
                    .await
                    {
                        break session.writer.fail(outcome).await;
                    }
                }
                Ok(Some(event)) => {
                    let outcome =
                        namespace_error(&event).unwrap_or(CloseOutcome::UnsupportedStanzaType);
                    break session.writer.fail(outcome).await;
                }
                Err(outcome) => break session.writer.fail(outcome).await,
            }
        }
    };
    let outcome = match select(pin!(registration.wait_retired()), pin!(stream)).await {
        Either::Left(_) => CloseOutcome::InternalError,
        Either::Right((outcome, _)) => outcome,
    };
    let end = match registration.end_presence().await {
        Ok(Some(unavailable)) => {
            broadcast_ended_presence(&unavailable, &registration, &router).await
        }
        Ok(None) | Err(RouterError::NotFound) => Ok(()),
        Err(_) => Err(CloseOutcome::InternalError),
    };
    drop(registration);
    end.map_or(CloseOutcome::InternalError, |()| outcome)
}

async fn broadcast_ended_presence<A: ChunkAllocator + Clone>(
    unavailable: &RoutedStanza<A>,
    registration: &Registration<A>,
    router: &RouterHandle<A>,
) -> Result<(), CloseOutcome> {
    let handler = router
        .presence_handlers(registration.account().domain())
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
                        available: false,
                    })
                    .await
            };
            match result {
                Ok(audience) => audience,
                Err(_) => {
                    let _ = registration.finish_presence().await;
                    return Err(CloseOutcome::InternalError);
                }
            }
        }
    };
    let result = match &audience {
        None => Ok(()),
        // The audience holds an ordering guard that blocks replacement updates until delivery ends.
        Some(audience) => match registration.replacement_is_available().await {
            Ok(true) => Ok(()),
            Ok(false) => router
                .broadcast_presence(unavailable, &audience.subscribers)
                .await
                .map_err(|_| CloseOutcome::InternalError),
            Err(_) => Err(CloseOutcome::InternalError),
        },
    };
    let finished = registration
        .finish_presence()
        .await
        .map_err(|_| CloseOutcome::InternalError);
    drop(audience);
    result.and(finished)
}

async fn write_resource_delivery<A: ChunkAllocator + Clone>(
    writer: &mut Writer,
    delivery: ResourceDelivery<A>,
    pending_replays: &mut VecDeque<Vec<PendingSubscription>>,
    registration: &Registration<A>,
    allocator: &A,
) -> Result<(), CloseOutcome> {
    match delivery {
        ResourceDelivery::Routed(stanza) => writer.send_routed(&stanza).await,
        ResourceDelivery::Presence {
            stanzas,
            replay_pending,
        } => {
            for stanza in stanzas {
                writer.send_routed(&stanza).await?;
            }
            if replay_pending {
                let pending = pending_replays
                    .pop_front()
                    .ok_or(CloseOutcome::InternalError)?;
                for subscription in pending {
                    let stanza =
                        parse_pending_subscription(subscription, registration, allocator).await?;
                    writer.send_routed(&stanza).await?;
                }
            }
            Ok(())
        }
    }
}

async fn handle_bound_stanza<A: ChunkAllocator + Clone>(
    parsed: Parsed<Stanza, A>,
    writer: &mut Writer,
    registration: &Registration<A>,
    router: &RouterHandle<A>,
    allocator: &A,
    pending_replays: &mut VecDeque<Vec<PendingSubscription>>,
) -> Result<(), CloseOutcome> {
    let stanza = parsed.value().resolve(parsed.arena())?;
    if stanza.namespace() != StanzaNamespace::Client {
        return Err(CloseOutcome::InvalidNamespace);
    }
    match stanza.stanza_type() {
        StanzaType::Iq(IqType::Get | IqType::Set) => {
            let (reply, arena) = iq::reply(parsed, registration, router, allocator)
                .await
                .map_err(|_| CloseOutcome::InternalError)?;
            let reply = reply.resolve(&arena)?;
            writer.send_stanza(&reply).await
        }
        StanzaType::Iq(IqType::Result | IqType::Error) => Ok(()),
        StanzaType::Presence(kind) => {
            let directed = stanza.to()?.is_some();
            if directed {
                return match PresenceRequestType::from_subscription_stanza(kind) {
                    Some(kind) => {
                        handle_subscription_presence(
                            parsed,
                            kind,
                            writer,
                            registration,
                            router,
                            allocator,
                        )
                        .await
                    }
                    None => Ok(()),
                };
            }
            match kind {
                PresenceType::Available | PresenceType::Unavailable => {
                    handle_presence_update(
                        parsed,
                        kind == PresenceType::Available,
                        writer,
                        registration,
                        router,
                        allocator,
                        pending_replays,
                    )
                    .await
                }
                _ => Ok(()),
            }
        }
        StanzaType::Message(kind) => {
            let routed = stamp_client_stanza(parsed, registration)?;
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
                return send_stanza_error(
                    writer,
                    &routed,
                    allocator,
                    StanzaErrorCondition::ServiceUnavailable,
                )
                .await;
            }
            if let Err(error) = router.route_message(routed.clone()).await {
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
                send_stanza_error(writer, &routed, allocator, condition).await?;
            }
            Ok(())
        }
    }
}

async fn handle_presence_update<A: ChunkAllocator + Clone>(
    parsed: Parsed<Stanza, A>,
    available: bool,
    writer: &mut Writer,
    registration: &Registration<A>,
    router: &RouterHandle<A>,
    allocator: &A,
    pending_replays: &mut VecDeque<Vec<PendingSubscription>>,
) -> Result<(), CloseOutcome> {
    let priority = if available {
        let stanza = parsed.value().resolve(parsed.arena())?;
        match presence_priority(&stanza) {
            Ok(priority) => Some(priority),
            Err(condition) => {
                let routed = stamp_client_stanza(parsed, registration)?;
                return send_stanza_error(writer, &routed, allocator, condition).await;
            }
        }
    } else {
        None
    };
    let (source, mut arena) = parsed.into_parts();
    let (stamped, from, to) = stamp_client_stanza_in(source, &mut arena, registration, true)?;
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
    let kind = if available {
        PresenceRequestType::Available
    } else {
        PresenceRequestType::Unavailable
    };
    let result = match router
        .presence_handlers(registration.account().domain())
        .and_then(|handlers| handlers.find(kind))
    {
        None => Ok(None),
        Some(handler) => {
            let sender = from.resolve(&arena)?;
            handler.audience(PresenceUpdate { sender, available }).await
        }
    };
    let mut audience = match result {
        Ok(audience) => audience,
        Err(condition) => {
            let routed = RoutedStanza::from_parts(stamped, arena);
            return send_stanza_error(writer, &routed, allocator, condition).await;
        }
    };
    let (routed, unavailable) = match unavailable {
        Some(unavailable) => {
            let (routed, unavailable) = RoutedStanza::from_parts_pair(stamped, unavailable, arena);
            (routed, Some(unavailable))
        }
        None => (RoutedStanza::from_parts(stamped, arena), None),
    };
    let broadcast_stanza = audience
        .as_ref()
        .is_some_and(|audience| !audience.subscribers.is_empty())
        .then(|| routed.clone());
    let change = registration
        .set_presence(priority, routed, unavailable)
        .await
        .map_err(|_| CloseOutcome::InternalError)?;
    if change.became_available {
        pending_replays.push_back(
            audience
                .as_mut()
                .map(|audience| mem::take(&mut audience.pending))
                .unwrap_or_default(),
        );
    }
    if let Some(audience) = audience
        && (available || change.became_unavailable)
        && let Some(stanza) = broadcast_stanza
    {
        router
            .broadcast_presence(&stanza, &audience.subscribers)
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
    }
    Ok(())
}

async fn handle_subscription_presence<A: ChunkAllocator + Clone>(
    parsed: Parsed<Stanza, A>,
    kind: PresenceRequestType,
    writer: &mut Writer,
    registration: &Registration<A>,
    router: &RouterHandle<A>,
    allocator: &A,
) -> Result<(), CloseOutcome> {
    let Some(sender_host) = router
        .presence_handlers(registration.account().domain())
        .and_then(|handlers| handlers.find(kind))
    else {
        return Ok(());
    };
    let (source, mut arena) = parsed.into_parts();
    let (source, sender, _) = stamp_client_stanza_in(source, &mut arena, registration, false)?;
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
        return send_stanza_error(writer, &source, allocator, condition).await;
    }
    let received = {
        let (sender, target) = presence_addresses(&routed)?;
        match router
            .presence_handlers(target.domainpart())
            .and_then(|handlers| handlers.find(kind))
        {
            Some(target_host) => {
                let delivery = StreamDelivery {
                    router,
                    registration,
                    allocator,
                };
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
        Err(HandlerError::Stanza(condition)) => {
            send_stanza_error(writer, &source, allocator, condition).await
        }
        Err(HandlerError::Delivery(_)) => Err(CloseOutcome::InternalError),
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

fn stamp_client_stanza<A: ChunkAllocator>(
    parsed: Parsed<Stanza, A>,
    registration: &Registration<A>,
) -> Result<RoutedStanza<A>, CloseOutcome> {
    let (stanza, mut arena) = parsed.into_parts();
    let needs_to = stanza.resolve(&arena)?.to()?.is_none();
    let (stanza, _, _) = stamp_client_stanza_in(stanza, &mut arena, registration, needs_to)?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}

/// Stamps the authenticated full JID as `from` and, when asked, the bare JID as `to`.
fn stamp_client_stanza_in<A: ChunkAllocator>(
    stanza: Stanza,
    arena: &mut Arena<A>,
    registration: &Registration<A>,
    needs_to: bool,
) -> Result<(Stanza, Jid, Option<Jid>), CloseOutcome> {
    let account = registration.account();
    let from = Jid::from_trusted_parts_in(
        Some(account.username()),
        account.domain(),
        Some(registration.resource()),
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

async fn parse_pending_subscription<A: ChunkAllocator + Clone>(
    subscription: PendingSubscription,
    registration: &Registration<A>,
    allocator: &A,
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
        allocator.clone(),
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
                .is_none_or(|target| target.as_str() != registration.account().as_str())
        {
            return Err(CloseOutcome::InternalError);
        }
    }
    Ok(RoutedStanza::from_parts(stanza, arena))
}

async fn send_stanza_error<A: ChunkAllocator + Clone>(
    writer: &mut Writer,
    source: &RoutedStanza<A>,
    allocator: &A,
    condition: StanzaErrorCondition,
) -> Result<(), CloseOutcome> {
    let mut arena = Arena::try_new_in(Default::default(), allocator.clone())?;
    let source = source.resolve()?.clone_in(&mut arena)?;
    let reply = source.error_reply_in(&mut arena, condition)?.build()?;
    let reply = reply.resolve(&arena)?;
    writer.send_stanza(&reply).await
}
