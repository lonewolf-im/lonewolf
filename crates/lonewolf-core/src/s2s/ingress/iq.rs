// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::iq::{
    IqDestinationRule, IqError, IqErrorPayload, IqRequestType, Requester,
};
use lonewolf_extension::policy::{Direction, Verdict};
use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{IqType, StanzaErrorCondition, StanzaErrorText};

use super::{InboundPeer, IngressContext, IngressFailure, reply_error};
use crate::delivery::storage_failure;
use crate::router::{Destination, RoutedStanza, RouterError};
use crate::stages::ingress::Origin;
use crate::stages::ingress::iq::{self as ingress_iq, AnswerStanzas, IqDisposition, IqInput};
use crate::stages::iq::{ReplyError, error_reply_omitting_payload, iq_requester};
use crate::stages::{Stage, policy};

impl From<ReplyError> for IngressFailure {
    fn from(_: ReplyError) -> Self {
        Self
    }
}

pub(crate) async fn handle<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    peer: &InboundPeer,
    routed: RoutedStanza<A>,
    kind: IqType,
) -> Result<(), IngressFailure> {
    let origin: Origin<'_, A> = Origin::Remote {
        local: &peer.local,
        remote: &peer.remote,
    };
    let stage = Stage {
        router: &context.router,
        storage: &context.storage,
        allocator: &context.allocator,
        work: &context.work,
    };
    let view = routed.resolve().map_err(|_| IngressFailure)?;
    let target = view
        .to()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let sender = view
        .from()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let destination = context.router.destination(target);
    let request_type = match kind {
        IqType::Get => Some(IqRequestType::Get),
        IqType::Set => Some(IqRequestType::Set),
        _ => None,
    };
    if let Some(kind) = request_type {
        let payload = view
            .children()
            .map_err(|_| IngressFailure)?
            .next()
            .transpose()
            .map_err(|_| IngressFailure)?
            .ok_or(IngressFailure)?;
        if context
            .router
            .iq_handlers(target.domainpart())
            .and_then(|registry| {
                registry.destination_rule(kind, payload.namespace(), payload.name())
            })
            == Some(IqDestinationRule::SenderBare)
        {
            return emit_error(
                context,
                &routed,
                IqError::without_payload(HandlerError::described(
                    StanzaErrorCondition::Forbidden,
                    StanzaErrorText::Static(
                        "This operation requires an omitted destination or your authenticated bare JID without a resource.",
                    ),
                )),
            );
        }
    }
    let account = if matches!(destination, Destination::Account | Destination::Resource) {
        Some(AccountKey::try_from(target.bare()).map_err(|_| IngressFailure)?)
    } else {
        None
    };
    let checks = account.as_ref().map(|account| {
        [policy::Check {
            account,
            direction: Direction::Inbound,
            peer: sender,
        }]
    });
    if destination == Destination::Resource {
        let account = account.as_ref().ok_or(IngressFailure)?;
        let policies = !context.router.policies(account.domain()).is_empty();
        let (transaction, mut ticket) = if request_type.is_some() || policies {
            let (transaction, ticket) = Arc::clone(context.router.order())
                .fix(vec![account.clone()], context.storage.begin_read())
                .await
                .map_err(|error| {
                    origin.report(
                        storage_failure(error, "iq_resource_begin_read"),
                        Some(account),
                    );
                    IngressFailure
                })?;
            (Some(transaction), ticket)
        } else {
            let ((), ticket) = Arc::clone(context.router.order())
                .fix(vec![account.clone()], async { Ok::<_, IngressFailure>(()) })
                .await?;
            (None, ticket)
        };
        if policies {
            let verdict = policy::evaluate_in(
                &context.router,
                transaction.as_ref().ok_or(IngressFailure)?,
                view.stanza_type(),
                checks.as_ref().ok_or(IngressFailure)?,
            )
            .await?;
            if verdict != Verdict::Allow {
                return policy_reply(context, &routed, verdict);
            }
        }
        let subscribed = if request_type.is_some() {
            iq_requester(
                &context.router,
                account,
                sender,
                transaction.as_ref().ok_or(IngressFailure)?,
            )
            .await
            .map_err(|error| {
                if let Some(failure) = error.failure() {
                    origin.report(failure, Some(account));
                }
                IngressFailure
            })? == Requester::PresenceAuthorized
        } else {
            false
        };
        drop(transaction);
        ticket.turn().await;
        let result = if request_type.is_some() {
            context
                .router
                .route_iq_request_guarded(routed.clone(), subscribed, None)
                .await
        } else {
            context.router.route_full(routed.clone()).await
        };
        drop(ticket);
        return match result {
            _ if request_type.is_none() => Ok(()),
            Ok(()) => Ok(()),
            Err(RouterError::Unavailable | RouterError::Stopped) => Err(IngressFailure),
            Err(RouterError::Busy | RouterError::ResourceLimit) => {
                unavailable(context, &routed, StanzaErrorCondition::ResourceConstraint)
            }
            Err(_) => unavailable(context, &routed, StanzaErrorCondition::ServiceUnavailable),
        };
    }
    if let Some(checks) = checks {
        let verdict = policy::evaluate(&stage, view.stanza_type(), &checks).await?;
        if verdict != Verdict::Allow {
            return policy_reply(context, &routed, verdict);
        }
    }
    let Some(kind) = request_type else {
        return Ok(());
    };
    match destination {
        Destination::Account | Destination::Server => {}
        Destination::Remote => return Err(IngressFailure),
        _ => return unavailable(context, &routed, StanzaErrorCondition::ServiceUnavailable),
    }
    let disposition = ingress_iq::handle_request(
        &stage,
        &origin,
        IqInput::Routed(routed),
        destination,
        kind,
        account,
    )
    .await?;
    let answer = match disposition {
        IqDisposition::Unavailable {
            input: IqInput::Routed(routed),
            condition,
            ..
        } => return unavailable(context, &routed, condition),
        IqDisposition::Unavailable { .. } | IqDisposition::SessionIq { .. } => {
            return Err(IngressFailure);
        }
        IqDisposition::Answer(answer) => answer,
        IqDisposition::Ordered(pending) => pending.finished().await.ok_or(IngressFailure)??.answer,
    };
    match ingress_iq::render_answer(&origin, &context.allocator, answer)? {
        AnswerStanzas::One { stanza, arena } => {
            let _ = context
                .router
                .route_remote(RoutedStanza::from_parts(stanza, arena));
        }
        AnswerStanzas::Shared(stanzas) => {
            for stanza in stanzas {
                let _ = context.router.route_remote(stanza);
            }
        }
    }
    Ok(())
}

fn unavailable<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    routed: &RoutedStanza<A>,
    condition: StanzaErrorCondition,
) -> Result<(), IngressFailure> {
    reply_error(context, routed, condition, None, condition.default_text())
}

fn policy_reply<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    routed: &RoutedStanza<A>,
    verdict: Verdict,
) -> Result<(), IngressFailure> {
    match verdict {
        Verdict::Reject {
            condition,
            application,
            text,
        } => reply_error(
            context,
            routed,
            condition,
            application,
            text.unwrap_or_else(|| condition.default_text()),
        ),
        Verdict::Allow | Verdict::Drop => Ok(()),
    }
}

fn emit_error<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    routed: &RoutedStanza<A>,
    error: IqError,
) -> Result<(), IngressFailure> {
    match error.payload() {
        IqErrorPayload::Include => reply_error(
            context,
            routed,
            error.condition(),
            None,
            error.handler_error().text(),
        ),
        IqErrorPayload::Omit => {
            let mut original = Arena::try_new_in(Default::default(), context.allocator.clone())
                .map_err(|_| IngressFailure)?;
            let request = routed
                .resolve()
                .map_err(|_| IngressFailure)?
                .clone_in(&mut original)
                .map_err(|_| IngressFailure)?;
            let view = request.resolve(&original).map_err(|_| IngressFailure)?;
            let mut response = Arena::try_new_in(Default::default(), context.allocator.clone())
                .map_err(|_| IngressFailure)?;
            let reply = error_reply_omitting_payload(
                &view,
                view.from()
                    .map_err(|_| IngressFailure)?
                    .ok_or(IngressFailure)?,
                error.condition(),
                error.handler_error().text(),
                &mut response,
            )?;
            let _ = context
                .router
                .route_remote(RoutedStanza::from_parts(reply, response));
            Ok(())
        }
    }
}
