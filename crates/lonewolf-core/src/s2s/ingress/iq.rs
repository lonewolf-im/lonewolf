// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::Effects;
use lonewolf_extension::delivery::{Failure, FailureKind, HandlerError};
use lonewolf_extension::discovery::Discovery;
use lonewolf_extension::iq::{
    IqDestinationRule, IqError, IqErrorPayload, IqHandler, IqReply, IqRequest, IqRequestType,
    IqScope, Requester, XmlSpace,
};
use lonewolf_extension::policy::{Direction, Verdict};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{RedbRead, RedbStorage, Storage};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{IqType, Stanza, StanzaErrorCondition, StanzaErrorText, XML_NAMESPACE};

use super::{InboundPeer, IngressContext, IngressFailure, reply_error};
use crate::delivery::{
    EffectsDiagnostics, EffectsIdentity, RouterDelivery, after_turn, commit_and_deliver,
    report_failure, report_server_failure, storage_failure,
};
use crate::router::{Destination, RoutedStanza, RouterError};
use crate::stages::iq::{
    IqTarget, ReplyError, error_reply_omitting_payload, iq_requester, iq_target,
    require_iq_account, result_reply,
};
use crate::stages::{Stage, policy};

impl From<ReplyError> for IngressFailure {
    fn from(_: ReplyError) -> Self {
        Self
    }
}

fn report(failure: Failure, account: Option<&AccountKey>, domain: &str) {
    match account {
        Some(account) => report_failure(failure, account),
        None => report_server_failure(failure, domain),
    }
}

fn report_handler(error: &HandlerError, account: Option<&AccountKey>, domain: &str) {
    if let Some(failure) = error.failure() {
        report(failure, account, domain);
    }
}

pub(crate) async fn handle<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    peer: &InboundPeer,
    routed: RoutedStanza<A>,
    kind: IqType,
) -> Result<(), IngressFailure> {
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
                    report_failure(storage_failure(error, "iq_resource_begin_read"), account);
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
                report_handler(&error, Some(account), &peer.local);
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
    let scope = match destination {
        Destination::Account => IqScope::Account,
        Destination::Server => IqScope::Server,
        Destination::Remote => return Err(IngressFailure),
        _ => return unavailable(context, &routed, StanzaErrorCondition::ServiceUnavailable),
    };
    let payload = view
        .children()
        .map_err(|_| IngressFailure)?
        .next()
        .transpose()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let handler = context
        .router
        .iq_handlers(target.domainpart())
        .and_then(|registry| registry.find(scope, kind, payload.namespace(), payload.name()))
        .map(Arc::clone);
    let Some(handler) = handler else {
        return unavailable(context, &routed, StanzaErrorCondition::ServiceUnavailable);
    };
    let discovery = Arc::clone(
        context
            .router
            .discovery(target.domainpart())
            .ok_or(IngressFailure)?,
    );
    let delivery = RouterDelivery::new(&context.router, &context.allocator, None);
    let mut arena = Arena::try_new_in(Default::default(), context.allocator.clone())
        .map_err(|_| IngressFailure)?;
    let request = view.clone_in(&mut arena).map_err(|_| IngressFailure)?;
    let mut response = Arena::try_new_in(Default::default(), context.allocator.clone())
        .map_err(|_| IngressFailure)?;
    let (reply, response) = match kind {
        IqRequestType::Get => {
            let (transaction, ticket) = Arc::clone(context.router.order())
                .fix(
                    account.iter().cloned().collect(),
                    context.storage.begin_read(),
                )
                .await
                .map_err(|error| {
                    report(
                        storage_failure(error, "iq_get_begin_read"),
                        account.as_ref(),
                        &peer.local,
                    );
                    IngressFailure
                })?;
            let work = GetWork {
                request,
                arena,
                account,
                domain: peer.local.clone(),
                transaction,
                handler,
                discovery,
                delivery,
                response,
            };
            let pending = after_turn::<A, _, _, _>(
                context.work.start(),
                ticket,
                None,
                move |_, ticket| async move {
                    let result = work.run().await;
                    drop(ticket);
                    result
                },
            );
            pending.finished().await.ok_or(IngressFailure)??
        }
        IqRequestType::Set => {
            let mut transaction = context.storage.begin_write().await.map_err(|error| {
                report(
                    storage_failure(error, "iq_set_begin_write"),
                    account.as_ref(),
                    &peer.local,
                );
                IngressFailure
            })?;
            let reply = match require_iq_account(&transaction, account.as_ref()).await {
                Err(error) => Err(error.into()),
                Ok(()) => {
                    handler
                        .set(
                            iq_request(&request, &arena, &discovery, &delivery, None)?,
                            &mut transaction,
                            &delivery,
                            &mut response,
                        )
                        .await
                }
            };
            match reply {
                Ok(reply) => {
                    let pending = commit_and_deliver(
                        context.work.start(),
                        Arc::clone(context.router.order()),
                        transaction,
                        reply.effects,
                        delivery,
                        None,
                        EffectsDiagnostics {
                            identity: account.map_or_else(
                                || EffectsIdentity::Server(peer.local.clone()),
                                EffectsIdentity::Account,
                            ),
                            commit_operation: "iq_set_commit",
                            delivery_operation: "iq_set_effects",
                        },
                    );
                    pending
                        .finished()
                        .await
                        .ok_or(IngressFailure)?
                        .map_err(|_| IngressFailure)?;
                    (
                        Ok(IqReply {
                            payload: reply.payload,
                            effects: Effects::none(),
                            results: reply.results,
                        }),
                        response,
                    )
                }
                Err(error) => {
                    drop(transaction);
                    report_handler(error.handler_error(), account.as_ref(), &peer.local);
                    (Err(error), response)
                }
            }
        }
    };
    match reply {
        Err(error) => emit_error(context, &routed, error),
        Ok(reply) => emit_reply(context, &routed, reply, response),
    }
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

fn iq_request<'a, A: ChunkAllocator + Clone>(
    request: &'a Stanza,
    arena: &'a Arena<A>,
    discovery: &'a Discovery,
    delivery: &'a RouterDelivery<A>,
    requester: Option<Requester>,
) -> Result<IqRequest<'a, A>, IngressFailure> {
    let view = request.resolve(arena).map_err(|_| IngressFailure)?;
    Ok(IqRequest {
        sender: view
            .from()
            .map_err(|_| IngressFailure)?
            .ok_or(IngressFailure)?,
        target: view
            .to()
            .map_err(|_| IngressFailure)?
            .ok_or(IngressFailure)?,
        discovery,
        sessions: delivery,
        requester,
        lang: view.lang().map_err(|_| IngressFailure)?,
        space: view
            .attribute("space", XML_NAMESPACE)
            .map_err(|_| IngressFailure)?
            .map(XmlSpace::from_attribute),
        payload: view
            .children()
            .map_err(|_| IngressFailure)?
            .next()
            .transpose()
            .map_err(|_| IngressFailure)?
            .ok_or(IngressFailure)?,
    })
}

struct GetWork<A: ChunkAllocator> {
    request: Stanza,
    arena: Arena<A>,
    account: Option<AccountKey>,
    domain: Box<str>,
    transaction: RedbRead,
    handler: Arc<dyn IqHandler<A, RedbStorage>>,
    discovery: Arc<Discovery>,
    delivery: RouterDelivery<A>,
    response: Arena<A>,
}

impl<A: ChunkAllocator + Clone> GetWork<A> {
    async fn run(mut self) -> Result<(Result<IqReply<A>, IqError>, Arena<A>), IngressFailure> {
        let reply = match iq_target(&self.transaction, self.account.as_ref()).await {
            Err(error) => Err(error.into()),
            Ok(target) => {
                let requester = match target {
                    IqTarget::Server => Ok(None),
                    IqTarget::Missing => Ok(Some(Requester::Other)),
                    IqTarget::Present => iq_requester(
                        self.delivery.router(),
                        self.account.as_ref().ok_or(IngressFailure)?,
                        self.request
                            .resolve(&self.arena)
                            .map_err(|_| IngressFailure)?
                            .from()
                            .map_err(|_| IngressFailure)?
                            .ok_or(IngressFailure)?,
                        &self.transaction,
                    )
                    .await
                    .map(Some),
                };
                match requester {
                    Err(error) => Err(error.into()),
                    Ok(requester) => {
                        let request = iq_request(
                            &self.request,
                            &self.arena,
                            &self.discovery,
                            &self.delivery,
                            requester,
                        )?;
                        match target {
                            IqTarget::Missing => self
                                .handler
                                .get_missing_account(request, &mut self.response)
                                .map(|payload| IqReply::new(payload, Effects::none())),
                            _ => {
                                self.handler
                                    .get(request, &self.transaction, &mut self.response)
                                    .await
                            }
                        }
                    }
                }
            }
        };
        drop(self.transaction);
        let reply = match reply {
            Ok(reply) => {
                (reply.effects.deliver)(&self.delivery).await.map_err(|_| {
                    report(
                        Failure {
                            kind: FailureKind::Delivery,
                            operation: "iq_get_effects",
                        },
                        self.account.as_ref(),
                        &self.domain,
                    );
                    IngressFailure
                })?;
                Ok(IqReply {
                    payload: reply.payload,
                    results: reply.results,
                    effects: Effects::none(),
                })
            }
            Err(error) => {
                report_handler(error.handler_error(), self.account.as_ref(), &self.domain);
                Err(error)
            }
        };
        Ok((reply, self.response))
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

fn emit_reply<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    routed: &RoutedStanza<A>,
    reply: IqReply<A>,
    mut response: Arena<A>,
) -> Result<(), IngressFailure> {
    let view = routed.resolve().map_err(|_| IngressFailure)?;
    let sender = view
        .from()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    if reply.results.iter().any(|result| {
        result
            .resolve(&response)
            .ok()
            .and_then(|view| view.to().ok().flatten())
            .map(|to| to.as_str())
            != Some(sender.as_str())
    }) {
        return unavailable(context, routed, StanzaErrorCondition::InternalServerError);
    }
    let mut original = Arena::try_new_in(Default::default(), context.allocator.clone())
        .map_err(|_| IngressFailure)?;
    let request = view.clone_in(&mut original).map_err(|_| IngressFailure)?;
    let final_reply = result_reply(
        &request.resolve(&original).map_err(|_| IngressFailure)?,
        sender,
        reply.payload,
        &mut response,
    )?;
    if reply.results.is_empty() {
        let _ = context
            .router
            .route_remote(RoutedStanza::from_parts(final_reply, response));
    } else {
        let mut results = reply.results;
        results.push(final_reply);
        for result in RoutedStanza::from_parts_shared(results, response) {
            let _ = context.router.route_remote(result);
        }
    }
    Ok(())
}
